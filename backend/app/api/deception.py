from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import DeceptionAction, HoneypotSession
from app.security.auth import get_current_user, require_role

router = APIRouter(prefix="/deception", tags=["deception"])


def _engine(request: Request):
    return request.app.state.deception_engine


@router.get("/actions")
def list_actions(
    session_id: str | None = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    q = db.query(DeceptionAction)
    if session_id:
        q = q.filter(DeceptionAction.session_id == session_id)
    items = q.order_by(DeceptionAction.created_at.desc()).limit(200).all()
    return {
        "items": [
            {
                "id": a.id,
                "session_id": a.session_id,
                "policy_id": a.policy_id,
                "action": a.action,
                "reason": a.reason,
                "status": a.status,
                "result": a.result,
                "rollback_status": a.rollback_status,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in items
        ]
    }


@router.get("/environment")
def environment(
    request: Request,
    user=Depends(get_current_user),
):
    return _engine(request).environment_status()


@router.post("/actions/{action_id}/rollback")
def rollback_action(
    action_id: str,
    request: Request,
    user=Depends(require_role("ADMIN")),
):
    try:
        return _engine(request).rollback(action_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/sessions/{session_id}/evaluate")
def evaluate_session(
    session_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_role("ANALYST")),
):
    if not db.get(HoneypotSession, session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"decision": "ok", "note": "Use POST /sessions/{id}/analyse to run evaluation."}
