from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import AnomalyResult, HoneypotSession
from app.security.auth import get_current_user

router = APIRouter(prefix="/anomalies", tags=["anomalies"])


@router.get("")
def list_anomalies(
    min_score: float = 0.0,
    label: str | None = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    q = db.query(AnomalyResult)
    if label:
        q = q.filter(AnomalyResult.label == label)
    items = q.order_by(AnomalyResult.anomaly_score.desc()).all()
    result = []
    for a in items:
        if (a.anomaly_score or 0) < min_score:
            continue
        sess = db.get(HoneypotSession, a.session_id)
        result.append(
            {
                "id": a.id,
                "session_id": a.session_id,
                "session_ref": sess.session_ref if sess else None,
                "anomaly_score": a.anomaly_score,
                "label": a.label,
                "reasons": a.reasons,
                "contributing_features": a.contributing_features,
                "model": a.model_name,
                "model_version": a.model_version,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
        )
    return {"total": len(result), "items": result}


@router.get("/stats")
def anomaly_stats(db: Session = Depends(get_db), user=Depends(get_current_user)):
    from app.analytics.service import anomaly_distribution

    rows = anomaly_distribution(db)
    total_anomalies = sum(r["count"] for r in rows if r["label"] == "anomaly")
    total = sum(r["count"] for r in rows)
    return {
        "distribution": rows,
        "anomalies": total_anomalies,
        "normal": total - total_anomalies,
    }
