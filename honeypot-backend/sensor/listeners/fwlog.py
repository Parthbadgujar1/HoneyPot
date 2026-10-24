"""Read dropped packets from the Windows Defender Firewall log.

Bait ports only see scans that complete a TCP handshake with a decoy.
Scans of every other port, and ICMP echo sweeps, are dropped by the
firewall before any listener sees them. With dropped-connection logging
enabled, those drops appear in ``pfirewall.log``; this module turns them
into FW_DROP events so port scans and host discovery across the whole host
can be detected.

Enable logging with scripts/setup_firewall.ps1 (run as Administrator).
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime
from pathlib import Path

from ..events import FW_DROP, Event
from .common import EmitFn

log = logging.getLogger("sensor.fwlog")

FIELDS = (
    "date", "time", "action", "protocol", "src-ip", "dst-ip", "src-port",
    "dst-port", "size", "tcpflags", "tcpsyn", "tcpack", "tcpwin",
    "icmptype", "icmpcode", "info", "path",
)


def parse_line(line: str) -> dict | None:
    """Parse one pfirewall.log line. Returns None for anything that is not a DROP."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    parts = stripped.split()
    if len(parts) < 8:
        return None
    record = dict(zip(FIELDS, parts))

    if record.get("action", "").upper() != "DROP":
        return None

    protocol = record.get("protocol", "").upper()
    src_ip = record.get("src-ip", "")
    try:
        timestamp = datetime.strptime(
            f"{record['date']} {record['time']}", "%Y-%m-%d %H:%M:%S"
        ).timestamp()
    except (KeyError, ValueError):
        timestamp = time.time()

    if protocol == "ICMP":
        try:
            icmp_type = int(record.get("icmptype", "-1"))
        except ValueError:
            return None
        return {
            "src_ip": src_ip,
            "dst_port": None,
            "ts": timestamp,
            "detail": {
                "protocol": "ICMP",
                "icmp_type": icmp_type,
                "dst_ip": record.get("dst-ip", ""),
            },
        }

    if protocol in ("TCP", "UDP"):
        try:
            dst_port = int(record["dst-port"])
        except (KeyError, ValueError):
            return None
        return {
            "src_ip": src_ip,
            "dst_port": dst_port,
            "ts": timestamp,
            "detail": {
                "protocol": protocol,
                "tcp_flags": record.get("tcpflags", ""),
                "dst_ip": record.get("dst-ip", ""),
            },
        }

    return None


class FirewallLogReader:
    def __init__(self, path: Path, emit: EmitFn, own_addresses: set[str], poll_s: float):
        self.path = path
        self.poll_s = poll_s
        self._emit = emit
        self._own = own_addresses
        self._offset: int | None = None
        self.status: dict = {"state": "waiting", "path": str(path)}

    def poll_once(self) -> int:
        """Read new complete lines. Returns the number of events emitted."""
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            self.status = {"state": "waiting", "path": str(self.path),
                           "detail": "log file does not exist yet"}
            return 0
        except OSError as exc:
            self.status = {"state": "error", "path": str(self.path), "error": str(exc)}
            return 0

        if self._offset is None:
            # Start at the end: old drops are history, not live activity.
            self._offset = size
            self.status = {"state": "reading", "path": str(self.path)}
            return 0
        if size < self._offset:
            self._offset = 0  # the log rotated

        if size == self._offset:
            return 0

        try:
            with self.path.open("rb") as handle:
                handle.seek(self._offset)
                data = handle.read(size - self._offset)
        except PermissionError:
            self.status = {
                "state": "error", "path": str(self.path),
                "error": "permission denied: run the sensor as Administrator",
            }
            return 0
        except OSError as exc:
            self.status = {"state": "error", "path": str(self.path), "error": str(exc)}
            return 0

        cut = data.rfind(b"\n")
        if cut == -1:
            return 0  # wait for a complete line
        self._offset += cut + 1

        emitted = 0
        for raw in data[: cut + 1].decode("utf-8", errors="replace").splitlines():
            parsed = parse_line(raw)
            if parsed is None or parsed["src_ip"] in self._own:
                continue
            self._emit(Event(
                kind=FW_DROP,
                src_ip=parsed["src_ip"],
                dst_port=parsed["dst_port"],
                service="-",
                ts=parsed["ts"],
                detail=parsed["detail"],
            ))
            emitted += 1
        return emitted

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                self.poll_once()
            except Exception:
                log.exception("Firewall log poll failed")
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.poll_s)
            except asyncio.TimeoutError:
                pass
