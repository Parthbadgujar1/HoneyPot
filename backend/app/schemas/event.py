from datetime import datetime
from typing import Optional, Dict, Any

from pydantic import BaseModel, Field


class RawEvent(BaseModel):
    """Canonical normalized event schema used across the telemetry pipeline."""

    event_id: Optional[str] = None
    timestamp: datetime
    session_id: Optional[str] = None
    source: Optional[str] = None
    destination: Optional[str] = None
    service: Optional[str] = None
    event_type: str
    action: Optional[str] = None
    target: Optional[str] = None
    result: Optional[str] = None
    username: Optional[str] = None
    command: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class NormalizedEvent(BaseModel):
    event_id: str
    timestamp: datetime
    session_id: Optional[str] = None
    source: Optional[str] = None
    destination: Optional[str] = None
    service: Optional[str] = None
    event_type: str
    action: Optional[str] = None
    target: Optional[str] = None
    result: Optional[str] = None
    username: Optional[str] = None
    command: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
