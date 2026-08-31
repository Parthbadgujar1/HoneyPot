from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import AuditLog
from app.security.auth import get_current_user, require_role

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
def list_audit(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    action: str | None = None,
    db: Session = Depends(get_db),
    user=Depends(require_role("ANALYST")),
):
    q = db.query(AuditLog)
    if action:
        q = q.filter(AuditLog.action == action)
    total = q.count()
    items = q.order_by(AuditLog.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {
        "total": total,
        "items": [
            {
                "id": a.id,
                "user_id": a.user_id,
                "action": a.action,
                "resource_type": a.resource_type,
                "resource_id": a.resource_id,
                "ip_address": a.ip_address,
                "details": a.details,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in items
        ],
    }
