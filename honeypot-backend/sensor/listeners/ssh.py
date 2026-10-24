"""SSH decoy built on paramiko.

The decoy presents a persona-specific SSH banner, offers password and
public-key authentication and records every attempt. Authentication never
succeeds and no shell or exec channel is ever granted, so an attacker
cannot run commands on the sensor. After ``max_auth_attempts`` failures
the connection is closed.

paramiko is blocking, so the accept loop and each session run in daemon
threads and report to the engine through its thread-safe ``observe``.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from pathlib import Path

import paramiko

from ..deception import DecoyPolicy
from ..events import CONNECTION, SSH_AUTH, Event
from .common import EmitFn, flow_detail

log = logging.getLogger("sensor.ssh")


def load_or_create_host_key(path: Path) -> paramiko.PKey:
    """Persist the decoy's host key so its fingerprint is stable across runs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return paramiko.RSAKey(filename=str(path))
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(path))
    log.info("Generated SSH decoy host key at %s", path)
    return key


class _DecoyAuthServer(paramiko.ServerInterface):
    def __init__(self, src_ip: str, max_attempts: int, emit: EmitFn):
        self.src_ip = src_ip
        self.max_attempts = max_attempts
        self._emit = emit
        self._lock = threading.Lock()
        self.attempts = 0
        self.usernames: list[str] = []

    @property
    def limit_reached(self) -> bool:
        return self.attempts >= self.max_attempts

    def _record(self, username: str, method: str, secret: str) -> int:
        with self._lock:
            self.attempts += 1
            attempt = self.attempts
            self.usernames.append(username)
        self._emit(Event(
            kind=SSH_AUTH,
            src_ip=self.src_ip,
            dst_port=None,
            service="ssh",
            detail={
                "username": username,
                "method": method,
                "secret_preview": secret[:64],
                "attempt": attempt,
                # The raw attempt is checked against honeytokens, nothing else.
                "raw": f"{username}\n{secret}",
            },
        ))
        return paramiko.AUTH_FAILED

    def check_auth_none(self, username):
        return self._record(username, "none", "")

    def check_auth_password(self, username, password):
        return self._record(username, "password", password)

    def check_auth_publickey(self, username, key):
        fingerprint = key.get_fingerprint().hex()
        return self._record(username, "publickey", fingerprint)

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_request(self, kind, chanid):
        # Refuse every channel: no shell, exec or subsystem is ever offered.
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class SSHDecoy:
    def __init__(
        self,
        config: dict,
        bind_host: str,
        key_path: Path,
        emit: EmitFn,
        decoys: DecoyPolicy,
    ):
        ssh = config["decoys"]["ssh"]
        self.port = int(ssh["port"])
        self.max_attempts = int(ssh["max_auth_attempts"])
        self.session_timeout = float(ssh["session_timeout_s"])
        self.bind_host = bind_host
        self._key_path = key_path
        self._emit = emit
        self._decoys = decoys
        self._host_key: paramiko.PKey | None = None
        self._sock: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.status: dict = {"state": "stopped"}

    def start(self) -> None:
        self._host_key = load_or_create_host_key(self._key_path)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind((self.bind_host, self.port))
        except OSError as exc:
            sock.close()
            self.status = {"state": "unavailable", "error": str(exc)}
            raise
        sock.listen(100)
        sock.settimeout(1.0)
        self._sock = sock
        self._thread = threading.Thread(
            target=self._accept_loop, name="ssh-accept", daemon=True
        )
        self._thread.start()
        self.status = {"state": "listening"}
        log.info("SSH decoy listening on %s:%s", self.bind_host, self.port)

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=5)
        self.status = {"state": "stopped"}

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._serve, args=(conn, addr),
                name=f"ssh-{addr[0]}", daemon=True,
            ).start()

    def _serve(self, conn: socket.socket, addr: tuple) -> None:
        src_ip = str(addr[0])
        started = time.time()
        persona = self._decoys.persona_for(src_ip)
        auth = _DecoyAuthServer(src_ip, self.max_attempts, self._emit)
        transport = None
        end_reason = "client_closed"
        reset = False

        try:
            transport = paramiko.Transport(conn)
            transport.local_version = persona["ssh_banner"]
            transport.add_server_key(self._host_key)
            transport.start_server(server=auth)

            deadline = started + self.session_timeout
            while transport.is_active() and time.time() < deadline:
                if auth.limit_reached:
                    end_reason = "auth_limit"
                    break
                time.sleep(0.2)
            else:
                if time.time() >= deadline:
                    end_reason = "timeout"
        except (paramiko.SSHException, EOFError, ConnectionResetError) as exc:
            reset = isinstance(exc, ConnectionResetError)
            end_reason = f"ssh_error:{type(exc).__name__}"
        except OSError as exc:
            end_reason = f"os_error:{exc.errno}"
        finally:
            client_version = None
            if transport is not None:
                client_version = transport.remote_version or None
                try:
                    transport.close()
                except Exception:
                    pass
            try:
                conn.close()
            except OSError:
                pass

            ended = time.time()
            signature = None
            if client_version and auth.attempts == 0:
                signature = "ssh_client_banner"

            self._emit(Event(
                kind=CONNECTION,
                src_ip=src_ip,
                dst_port=self.port,
                service="ssh",
                ts=started,
                detail=flow_detail(
                    started=started,
                    ended=ended,
                    chunk_sizes=[len(client_version or "")] if client_version else [],
                    bytes_out=len(persona["ssh_banner"]),
                    writes_out=1,
                    graceful=end_reason == "client_closed",
                    reset=reset,
                    end_reason=end_reason,
                    extra={
                        "client_version": client_version,
                        "auth_attempts": auth.attempts,
                        "signature": signature,
                        "src_port": int(addr[1]),
                    },
                ),
            ))
