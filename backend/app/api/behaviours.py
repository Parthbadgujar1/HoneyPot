from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import ClassificationResult, HoneypotSession
from app.security.auth import get_current_user
from app.analytics.service import classification_distribution

router = APIRouter(prefix="/behaviours", tags=["behaviours"])


@router.get("")
def list_behaviours(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    rows = (
        db.query(ClassificationResult)
        .order_by(ClassificationResult.confidence.desc())
        .limit(200)
        .all()
    )
    items = []
    for c in rows:
        sess = db.get(HoneypotSession, c.session_id)
        items.append(
            {
                "session_id": c.session_id,
                "session_ref": sess.session_ref if sess else None,
                "behaviour_class": c.behaviour_class,
                "confidence": c.confidence,
                "probabilities": c.probabilities,
                "model": c.model_name,
                "model_version": c.model_version,
            }
        )
    return {"total": len(items), "items": items, "distribution": classification_distribution(db)}
