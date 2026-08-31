from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models.models import ModelVersion
from app.security.auth import get_current_user

router = APIRouter(prefix="/system", tags=["system"])
settings = get_settings()


@router.get("/status")
def system_status(request: Request, db: Session = Depends(get_db), user=Depends(get_current_user)):
    active = {
        "classifier": None,
        "anomaly": None,
        "sequence": None,
    }
    for mt in active:
        m = (
            db.query(ModelVersion)
            .filter(ModelVersion.model_type == mt, ModelVersion.is_active.is_(True))
            .first()
        )
        active[mt] = {"version": m.version, "name": m.name} if m else {"status": "not_trained"}
    return {
        "services": {
            "api": "ok",
            "db": "ok",
            "collector": request.app.state.collector.status(),
        },
        "models": active,
        "config": {
            "classifier": settings.ACTIVE_CLASSIFIER,
            "anomaly": settings.ACTIVE_ANOMALY,
            "sequence": settings.ACTIVE_SEQUENCE,
        },
    }


@router.get("/metrics")
def system_metrics(db: Session = Depends(get_db), user=Depends(get_current_user)):
    from app.analytics.service import events_over_time, dashboard_summary

    return {"summary": dashboard_summary(db), "events_over_time": events_over_time(db, "hour")}
