from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import HoneypotEvent
from app.security.auth import get_current_user

router = APIRouter(prefix="/events", tags=["events"])


@router.get("")
def list_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    session_id: Optional[str] = None,
    service: Optional[str] = None,
    event_type: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "timestamp",
    sort_dir: str = "desc",
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    q = db.query(HoneypotEvent)
    if session_id:
        q = q.filter(HoneypotEvent.session_id == session_id)
    if service:
        q = q.filter(HoneypotEvent.service == service)
    if event_type:
        q = q.filter(HoneypotEvent.event_type == event_type)
    if search:
        like = f"%{search}%"
        q = q.filter(HoneypotEvent.action.ilike(like) | HoneypotEvent.command.ilike(like))
    column = getattr(HoneypotEvent, sort_by, HoneypotEvent.timestamp)
    if sort_dir == "asc":
        q = q.order_by(column.asc())
    else:
        q = q.order_by(column.desc())
    total = q.count()
    items = q.offset((page - 1) * page_size).limit(page_size).all()
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [_ser(e) for e in items],
    }


@router.get("/{event_id}")
def get_event(event_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    e = db.get(HoneypotEvent, event_id)
    if not e:
        raise HTTPException(status_code=404, detail="Event not found")
    return _ser(e)


def _ser(e: HoneypotEvent) -> dict:
    return {
        "id": e.id,
        "event_ref": e.event_ref,
        "session_id": e.session_id,
        "timestamp": e.timestamp.isoformat(),
        "source": e.source,
        "destination": e.destination,
        "service": e.service,
        "event_type": e.event_type,
        "action": e.action,
        "target": e.target,
        "result": e.result,
        "username": e.username,
        "command": e.command,
        "metadata": e.payload,
        "is_anomaly": e.is_anomaly,
        "risk_score": e.risk_score,
    }
