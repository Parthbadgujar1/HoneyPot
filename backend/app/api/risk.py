from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import RiskAssessment, HoneypotSession
from app.security.auth import get_current_user
from app.telemetry.action_catalog import BEHAVIOUR_STAGES

router = APIRouter(prefix="/risk", tags=["risk"])


@router.get("")
def list_risk(
    severity: str | None = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    q = db.query(RiskAssessment)
    if severity:
        q = q.filter(RiskAssessment.severity == severity)
    items = q.order_by(RiskAssessment.score.desc()).all()
    result = []
    for r in items:
        sess = db.get(HoneypotSession, r.session_id)
        result.append(
            {
                "session_id": r.session_id,
                "session_ref": sess.session_ref if sess else None,
                "score": r.score,
                "severity": r.severity,
                "contributions": r.contributions,
                "policy_version": r.policy_version,
            }
        )
    return {"total": len(result), "items": result}


@router.get("/stages")
def stages():
    return {"stages": BEHAVIOUR_STAGES}
