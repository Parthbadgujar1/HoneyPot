"""Telemetry pipeline: normalizes raw honeypot events into canonical events,
deduplicates, stores, sessionizes, and feeds the ML pipeline.

Handles malformed events gracefully without crashing the collector.
"""

import hashlib
import json
from datetime import datetime
from typing import Iterable, List, Optional

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.models import HoneypotEvent, HoneypotSession
from app.schemas.event import NormalizedEvent, RawEvent

logger = get_logger("telemetry-pipeline")


def compute_dedup_key(ev: NormalizedEvent) -> str:
    """Deterministic dedup key from the event's identifying fields."""
    payload = json.dumps(
        {
            "ts": ev.timestamp.isoformat(),
            "sess": ev.session_id,
            "src": ev.source,
            "service": ev.service,
            "type": ev.event_type,
            "action": ev.action,
            "target": ev.target,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def normalize(raw: RawEvent) -> NormalizedEvent:
    """Convert a RawEvent into a NormalizedEvent with a stable event_id."""
    return NormalizedEvent(
        event_id=raw.event_id or compute_dedup_key(raw),
        timestamp=raw.timestamp,
        session_id=raw.session_id,
        source=raw.source,
        destination=raw.destination,
        service=raw.service,
        event_type=raw.event_type,
        action=raw.action,
        target=raw.target,
        result=raw.result,
        username=raw.username,
        command=raw.command,
        metadata=raw.metadata or {},
    )


class TelemetryPipeline:
    """Orchestrates ingestion of raw events into the database."""

    def __init__(self, db: Session):
        self.db = db
        self._seen_keys = set()

    def _resolve_session(self, session_ref: Optional[str], ev) -> Optional[str]:
        if not session_ref:
            return None
        sess = (
            self.db.query(HoneypotSession)
            .filter(HoneypotSession.session_ref == session_ref)
            .first()
        )
        if sess:
            return str(sess.id)
        return None

    def ingest_raw(self, raw_events: Iterable[RawEvent]) -> dict:
        stats = {"received": 0, "stored": 0, "duplicates": 0, "malformed": 0}
        for raw in raw_events:
            stats["received"] += 1
            try:
                ev = normalize(raw)
                key = compute_dedup_key(ev)
                if key in self._seen_keys:
                    stats["duplicates"] += 1
                    continue
                self._seen_keys.add(key)

                session_id = self._resolve_session(ev.session_id, ev)
                row = HoneypotEvent(
                    event_ref=ev.session_id,
                    session_id=session_id,
                    timestamp=ev.timestamp,
                    source=ev.source,
                    destination=ev.destination,
                    service=ev.service,
                    event_type=ev.event_type,
                    action=ev.action,
                    target=ev.target,
                    result=ev.result,
                    username=ev.username,
                    command=ev.command,
                    payload=ev.metadata,
                )
                self.db.add(row)
                stats["stored"] += 1
            except Exception as e:
                logger.warning("Malformed event skipped: %s", e)
                stats["malformed"] += 1
        self.db.commit()
        return stats

    def create_or_update_session(self, raw_events: Iterable[RawEvent]) -> List[str]:
        """Group events into sessions and persist session records."""
        events = list(raw_events)
        if not events:
            return []
        sessions = {}
        for ev in events:
            ref = ev.session_id or "unknown"
            sessions.setdefault(ref, []).append(ev)

        result_ids = []
        for ref, evs in sessions.items():
            sess = (
                self.db.query(HoneypotSession)
                .filter(HoneypotSession.session_ref == ref)
                .first()
            )
            evs_sorted = sorted(evs, key=lambda e: e.timestamp)
            start = evs_sorted[0].timestamp
            end = evs_sorted[-1].timestamp
            if sess is None:
                sess = HoneypotSession(
                    session_ref=ref,
                    source=evs_sorted[0].source,
                    destination=evs_sorted[0].destination,
                    service=evs_sorted[0].service or "unknown",
                    start_time=start,
                    end_time=end,
                    duration_seconds=(end - start).total_seconds(),
                    is_active=False,
                )
                self.db.add(sess)
                self.db.flush()
                # link events to this session
                for e_ in self.db.query(HoneypotEvent).filter(
                    HoneypotEvent.event_ref == ref
                ):
                    e_.session_id = str(sess.id)
                result_ids.append(str(sess.id))
            else:
                sess.end_time = end
                sess.start_time = min(sess.start_time or start, start)
                sess.duration_seconds = (sess.end_time - sess.start_time).total_seconds()
                sess.is_active = False
                result_ids.append(str(sess.id))
        self.db.commit()
        return result_ids

    def recount_events(self, session_ids: List[str] = None) -> None:
        q = self.db.query(HoneypotEvent.session_id, HoneypotEvent.session_id).filter(
            HoneypotEvent.session_id.isnot(None)
        )
        if session_ids:
            q = q.filter(HoneypotEvent.session_id.in_(session_ids))
        from sqlalchemy import func

        counts = (
            self.db.query(
                HoneypotEvent.session_id, func.count(HoneypotEvent.id)
            )
            .filter(HoneypotEvent.session_id.isnot(None))
            .group_by(HoneypotEvent.session_id)
            .all()
        )
        for sid, cnt in counts:
            self.db.query(HoneypotSession).filter(HoneypotSession.id == sid).update(
                {"event_count": cnt}
            )
        self.db.commit()
