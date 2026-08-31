"""Attack timeline reconstruction.

Transforms raw/normalized events into a human-readable incident timeline where
each entry describes what happened at a given time.
"""

from typing import Dict, List, Optional

from app.models.models import HoneypotEvent
from app.telemetry.action_catalog import (
    action_to_stage,
    is_discovery_action,
    is_sensitive_target,
)


def describe_event(event_type: str, action: Optional[str], target: Optional[str]) -> str:
    """Produce a human-readable description of an event."""
    a = action or ""
    if event_type == "connection":
        return "Connection established"
    if event_type == "session_end":
        return "Session closed"
    if event_type == "authentication_failure":
        return "Authentication failed"
    if event_type == "authentication_success":
        return "Authentication succeeded"
    if event_type == "authentication":
        return f"Authentication attempt ({a})"
    if event_type == "command":
        if a == "directory_listing":
            return "Directory listing"
        if a == "system_discovery":
            return "System discovery"
        if a == "file_search":
            return "File search"
        if a == "file_read":
            return f"File read: {target}" if target else "File read"
        if a == "network_exfil":
            return "Network exfiltration attempt"
        if a == "directory_change":
            return f"Changed directory: {target}" if target else "Directory change"
        return f"Command executed ({a})"
    if event_type == "file_access":
        return f"File access ({a}): {target}" if target else "File access"
    if event_type == "deception_action":
        return f"Decoy action ({a}): {target}" if target else "Decoy action"
    if event_type == "anomaly":
        return f"Anomaly flagged ({a})" if a else "Anomaly flagged"
    if event_type == "classification":
        return f"Behaviour classified: {a}" if a else "Behaviour classified"
    return f"{event_type.replace('_', ' ')} ({a})"


def build_timeline(events: List[HoneypotEvent]) -> List[Dict[str, Optional[str]]]:
    entries = []
    for ev in sorted(events, key=lambda e: e.timestamp):
        entries.append(
            {
                "timestamp": ev.timestamp.isoformat(),
                "event_type": ev.event_type,
                "action": ev.action,
                "target": ev.target,
                "service": ev.service,
                "result": ev.result,
                "stage": action_to_stage(ev.action or ""),
                "description": describe_event(ev.event_type, ev.action, ev.target),
                "event_id": str(ev.id),
                "sensitive": is_sensitive_target(ev.target),
            }
        )
    return entries
