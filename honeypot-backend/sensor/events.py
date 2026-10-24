"""Telemetry event model shared by every listener and log source."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

# One TCP/UDP-level session that reached a decoy listener (or was dropped
# by the host firewall, see FW_DROP). Carries flow statistics for the ML.
CONNECTION = "connection"
# One authentication attempt against the SSH decoy.
SSH_AUTH = "ssh_auth"
# One HTTP request handled by the HTTP decoy.
HTTP = "http_request"
# A packet dropped by Windows Defender Firewall (from pfirewall.log).
FW_DROP = "fw_drop"
EVENT_KINDS = (CONNECTION, SSH_AUTH, HTTP, FW_DROP)


@dataclass
class Event:
    kind: str
    src_ip: str
    dst_port: int | None = None
    service: str = "-"
    ts: float = field(default_factory=time.time)
    detail: dict = field(default_factory=dict)
