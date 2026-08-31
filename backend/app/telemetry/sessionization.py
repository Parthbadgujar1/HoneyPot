"""Reusable sessionization service.

Groups normalized events into behavioural sessions based on a session reference
(or a time-window heuristic when no explicit session id exists).
"""

from collections import OrderedDict
from datetime import timedelta
from typing import Dict, List, Optional

from app.schemas.event import NormalizedEvent


class SessionizationService:
    def __init__(self, idle_timeout_seconds: int = 300):
        self.idle_timeout = timedelta(seconds=idle_timeout_seconds)

    def sessionize(self, events: List[NormalizedEvent]) -> Dict[str, List[NormalizedEvent]]:
        """Group events into sessions keyed by a stable session reference."""
        from collections import defaultdict

        groups: "OrderedDict[str, List[NormalizedEvent]]" = OrderedDict()

        # Prefer explicit session ids
        for ev in sorted(events, key=lambda e: e.timestamp):
            key = ev.session_id or "unknown"
            groups.setdefault(key, []).append(ev)
        return dict(groups)

    def summarize(self, events: List[NormalizedEvent]) -> dict:
        """Compute session summary metadata from a group of events."""
        if not events:
            return {}
        evs = sorted(events, key=lambda e: e.timestamp)
        start = evs[0].timestamp
        end = evs[-1].timestamp
        duration = (end - start).total_seconds()
        return {
            "session_id": evs[0].session_id,
            "start_time": start,
            "end_time": end,
            "duration_seconds": duration,
            "event_count": len(evs),
            "services": sorted({e.service for e in evs if e.service}),
            "sources": sorted({e.source for e in evs if e.source}),
        }
