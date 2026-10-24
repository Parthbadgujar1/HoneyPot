"""Shared helpers for decoy listeners."""

from __future__ import annotations

from typing import Callable, Iterable

from ..events import Event

EmitFn = Callable[[Event], object]


def payload_signature(data: bytes) -> str | None:
    """Name the protocol fingerprint a client's first bytes reveal."""
    if not data:
        return None
    if data.startswith((b"GET ", b"HEAD ", b"POST ", b"OPTIONS ", b"PUT ", b"CONNECT ")):
        return "http_verb"
    if data.startswith(b"SSH-"):
        return "ssh_banner"
    if len(data) > 1 and data[0] == 0x16 and data[1] == 0x03:
        return "tls_clienthello"
    if data.strip(b"\r\n") == b"":
        return "empty_line"
    if set(data) <= {0}:
        return "null_probe"
    return None


def flow_detail(
    *,
    started: float,
    ended: float,
    chunk_sizes: Iterable[int],
    bytes_out: int,
    writes_out: int,
    graceful: bool,
    reset: bool,
    end_reason: str,
    extra: dict | None = None,
) -> dict:
    """Flow statistics for one TCP session, the input to the ML models.

    Packet counts are estimates from the application layer: the SYN/ACK
    handshake is counted as one packet on each side, and every data chunk
    the decoy read or wrote counts as one packet.
    """
    sizes = [int(size) for size in chunk_sizes]
    detail = {
        "duration_s": round(max(0.0, ended - started), 6),
        "bytes_in": sum(sizes),
        "bytes_out": int(bytes_out),
        "packets_in": len(sizes) + 1,
        "packets_out": int(writes_out) + 1,
        "chunk_sizes": sizes[:200],
        "had_payload": bool(sizes),
        "graceful": bool(graceful),
        "reset": bool(reset),
        "end_reason": end_reason,
        "http_requests": 0,
    }
    if extra:
        detail.update(extra)
    return detail


def preview(data: bytes, limit: int = 200) -> str:
    return data[:limit].decode("utf-8", errors="backslashreplace")
