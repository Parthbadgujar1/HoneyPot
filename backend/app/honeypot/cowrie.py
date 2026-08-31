"""Cowrie JSON log adapter.

Parses Cowrie's JSON logging file format (cowrie.json) into the canonical
RawEvent schema. This is a read-only, safe integration that only consumes
local log files. It never sends traffic to any external system.
"""

import json
import os
from datetime import datetime
from typing import Iterator, Optional

from app.honeypot.base import FileBasedAdapter
from app.schemas.event import RawEvent
from app.telemetry.action_catalog import classify_command_action


class CowrieAdapter(FileBasedAdapter):
    name = "cowrie"
    service = "ssh"

    def __init__(self, log_path: str = ""):
        super().__init__(log_path=log_path, service="ssh")
        self._pos = 0

    def _session_ref(self, rec: dict) -> str:
        return str(rec.get("session", "unknown"))

    def _parse_ts(self, rec: dict) -> datetime:
        raw = rec.get("timestamp")
        if not raw:
            return datetime.utcnow()
        try:
            return datetime.fromisoformat(str(raw).replace("Z", "+00:00").rstrip("Z"))
        except Exception:
            return datetime.utcnow()

    def _to_raw(self, rec: dict) -> RawEvent:
        eventid = rec.get("eventid", "cowrie.unknown")
        session = self._session_ref(rec)
        src = rec.get("src_ip") or rec.get("src")
        service = "ssh"

        common = dict(
            session_id=session,
            source=src,
            destination=rec.get("dst_ip"),
            service=service,
            result="success",
            metadata={
                "src_port": rec.get("src_port"),
                "dst_port": rec.get("dst_port"),
                "protocol": rec.get("protocol", "ssh"),
                "message": rec.get("message"),
                "cowrie_eventid": eventid,
            },
        )

        if eventid == "cowrie.session.connect":
            return RawEvent(
                timestamp=self._parse_ts(rec),
                event_type="connection",
                action="connect",
                **common,
            )
        if eventid == "cowrie.session.closed":
            return RawEvent(
                timestamp=self._parse_ts(rec),
                event_type="session_end",
                action="close",
                **common,
            )
        if eventid == "cowrie.login.failed":
            return RawEvent(
                timestamp=self._parse_ts(rec),
                event_type="authentication_failure",
                action="authentication",
                username=rec.get("username"),
                result="failure",
                metadata={**common["metadata"], "password": rec.get("password")},
                **{k: common[k] for k in ("session_id", "source", "destination", "service")},
            )
        if eventid == "cowrie.command.input":
            cmd = rec.get("input", "")
            return RawEvent(
                timestamp=self._parse_ts(rec),
                event_type="command",
                action=classify_command_action(cmd),
                command=cmd,
                target=cmd.split()[1] if len(cmd.split()) > 1 else None,
                metadata=common["metadata"],
                **{k: common[k] for k in ("session_id", "source", "destination", "service")},
            )
        if eventid == "cowrie.command.failed":
            cmd = rec.get("input", "")
            return RawEvent(
                timestamp=self._parse_ts(rec),
                event_type="command_failure",
                action=classify_command_action(cmd),
                command=cmd,
                result="failure",
                metadata=common["metadata"],
                **{k: common[k] for k in ("session_id", "source", "destination", "service")},
            )
        if eventid in ("cowrie.file.download", "cowrie.file.upload"):
            return RawEvent(
                timestamp=self._parse_ts(rec),
                event_type="file_access",
                action="download" if "download" in eventid else "upload",
                target=rec.get("outfile") or rec.get("url") or rec.get("filename"),
                metadata=common["metadata"],
                **{k: common[k] for k in ("session_id", "source", "destination", "service")},
            )
        # Fallback generic command event
        return RawEvent(
            timestamp=self._parse_ts(rec),
            event_type=eventid.replace("cowrie.", "").replace(".", "_"),
            action=eventid.split(".")[-1],
            message=rec.get("message"),
            **common,
        )

    def read_events(self, _limit: Optional[int] = None) -> Iterator[RawEvent]:
        if not self.log_path or not os.path.exists(self.log_path):
            return
        size = os.path.getsize(self.log_path)
        start = self._pos
        self._pos = size
        if size <= start:
            return
        emitted = 0
        with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(start)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    yield self._to_raw(rec)
                    emitted += 1
                except Exception:
                    # malformed JSON line -> skip, never crash the pipeline
                    continue
                if _limit and emitted >= _limit:
                    return
