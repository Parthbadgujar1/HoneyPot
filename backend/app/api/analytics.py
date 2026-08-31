from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.analytics import service as analytics
from app.core.database import get_db
from app.security.auth import get_current_user

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/events-over-time")
def events_over_time(bucket: str = "hour", db: Session = Depends(get_db), user=Depends(get_current_user)):
    return analytics.events_over_time(db, bucket)


@router.get("/classification-distribution")
def classification_distribution(db: Session = Depends(get_db), user=Depends(get_current_user)):
    return analytics.classification_distribution(db)


@router.get("/risk-distribution")
def risk_distribution(db: Session = Depends(get_db), user=Depends(get_current_user)):
    return analytics.risk_distribution(db)


@router.get("/service-usage")
def service_usage(db: Session = Depends(get_db), user=Depends(get_current_user)):
    return analytics.service_usage(db)


@router.get("/anomaly-distribution")
def anomaly_distribution(db: Session = Depends(get_db), user=Depends(get_current_user)):
    return analytics.anomaly_distribution(db)


@router.get("/session-durations")
def session_durations(db: Session = Depends(get_db), user=Depends(get_current_user)):
    return analytics.session_duration_distribution(db)


@router.get("/behaviour-transitions")
def behaviour_transitions(db: Session = Depends(get_db), user=Depends(get_current_user)):
    return analytics.behaviour_transitions(db)


@router.get("/adaptive-actions")
def adaptive_actions(db: Session = Depends(get_db), user=Depends(get_current_user)):
    return analytics.adaptive_actions(db)
