"""Bait TCP listeners: fake FTP, Telnet, SMTP, POP3, MSSQL, MySQL, Redis,
Elasticsearch and MongoDB ports.

Each listener sends the persona's service greeting, records what the
client does for up to ``read_timeout_s`` seconds, sends a fake reply where
the protocol has one, and logs a connection event. A client that connects
and sends nothing is a banner grab; a client that sends a protocol probe
is recorded with its fingerprint.
"""

from __future__ import annotations

import asyncio
import logging
import time
from functools import partial

from ..deception import DecoyPolicy
from ..events import CONNECTION, Event
from .common import EmitFn, flow_detail, payload_signature, preview

log = logging.getLogger("sensor.bait")


class BaitListeners:
    def __init__(self, config: dict, bind_host: str, emit: EmitFn, decoys: DecoyPolicy):
        bait = config["decoys"]["bait"]
        self.services = {int(port): name for port, name in bait["services"].items()}
        self.read_timeout = float(bait["read_timeout_s"])
        self.max_bytes = int(bait["max_bytes"])
        self.max_concurrent = int(bait["max_concurrent"])
        self.bind_host = bind_host
        self._emit = emit
        self._decoys = decoys
        self._servers: list[asyncio.AbstractServer] = []
        self._active = 0
        self.status: dict[int, dict] = {}

    async def start(self) -> None:
        for port, service in sorted(self.services.items()):
            try:
                server = await asyncio.start_server(
                    partial(self._handle, port, service),
                    self.bind_host,
                    port,
                )
            except OSError as exc:
                self.status[port] = {
                    "service": service, "state": "unavailable", "error": str(exc),
                }
                log.warning("Bait %s on port %s not started: %s", service, port, exc)
                continue
            self._servers.append(server)
            self.status[port] = {"service": service, "state": "listening"}
            log.info("Bait %s listening on %s:%s", service, self.bind_host, port)

    async def stop(self) -> None:
        for server in self._servers:
            server.close()
        for server in self._servers:
            try:
                await asyncio.wait_for(server.wait_closed(), timeout=2)
            except (asyncio.TimeoutError, OSError):
                pass
        self._servers.clear()

    async def _handle(
        self,
        port: int,
        service: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        src_ip, src_port = str(peer[0]), int(peer[1])
        started = time.time()

        if self._active >= self.max_concurrent:
            writer.close()
            return
        self._active += 1

        received: list[bytes] = []
        writes = 0
        bytes_out = 0
        graceful = True
        reset = False
        end_reason = "client_closed"
        first_payload = b""
        banner = None

        try:
            banner = self._decoys.service_banner(service, src_ip)
            if banner:
                writer.write(banner)
                await writer.drain()
                writes += 1
                bytes_out += len(banner)

            deadline = started + self.read_timeout
            total = 0
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    end_reason = "timeout"
                    graceful = False
                    break
                try:
                    data = await asyncio.wait_for(reader.read(4096), remaining)
                except asyncio.TimeoutError:
                    end_reason = "timeout"
                    graceful = False
                    break
                except (ConnectionResetError, BrokenPipeError):
                    reset = True
                    graceful = False
                    end_reason = "reset"
                    break

                if not data:
                    break  # the client closed its side

                if not first_payload:
                    first_payload = data
                received.append(data)
                total += len(data)

                reply = self._decoys.service_response(service, src_ip, data)
                if reply:
                    writer.write(reply)
                    await writer.drain()
                    writes += 1
                    bytes_out += len(reply)

                if total >= self.max_bytes:
                    end_reason = "max_bytes"
                    break
        except (ConnectionResetError, BrokenPipeError):
            reset = True
            graceful = False
            end_reason = "reset"
        except Exception:
            log.exception("Bait handler failed for %s:%s", src_ip, port)
            end_reason = "error"
            graceful = False
        finally:
            self._active -= 1
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2)
            except (asyncio.TimeoutError, OSError, ConnectionError):
                pass

        ended = time.time()
        sizes = [len(chunk) for chunk in received]
        signature = payload_signature(first_payload)
        detail = flow_detail(
            started=started,
            ended=ended,
            chunk_sizes=sizes,
            bytes_out=bytes_out,
            writes_out=writes,
            graceful=graceful,
            reset=reset,
            end_reason=end_reason,
            extra={
                "src_port": src_port,
                "banner_sent": banner is not None,
                "signature": signature,
                "payload_preview": preview(first_payload),
            },
        )
        self._emit(Event(
            kind=CONNECTION,
            src_ip=src_ip,
            dst_port=port,
            service=service,
            ts=started,
            detail=detail,
        ))
