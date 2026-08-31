from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]


class UserOut(BaseModel):
    id: str
    username: str
    email: Optional[str] = None
    role: str
    is_active: bool
    created_at: Optional[datetime] = None


class DashboardSummary(BaseModel):
    total_sessions: int = 0
    active_sessions: int = 0
    high_risk_sessions: int = 0
    anomalies: int = 0
    total_events: int = 0
    predictions: int = 0
    adaptive_actions: int = 0
