"""Analytics queries for the dashboard and analytics pages."""

from typing import Any, Dict, List

from sqlalchemy import func, text
from sqlalchemy.orm import Session

from app.models.models import (
    AnomalyResult,
    BehaviourFeatures,
    ClassificationResult,
    DeceptionAction,
    HoneypotEvent,
    HoneypotSession,
    ModelPrediction,
    RiskAssessment,
)


def events_over_time(db: Session, bucket: str = "hour") -> List[Dict[str, Any]]:
    if bucket == "day":
        expr = "date_trunc('day', timestamp)"
    elif bucket == "minute":
        expr = "date_trunc('minute', timestamp)"
    else:
        expr = "date_trunc('hour', timestamp)"
    rows = db.execute(
        text(
            f"SELECT {expr} AS bucket, count(*) AS n FROM honeypot_events "
            "WHERE timestamp IS NOT NULL GROUP BY 1 ORDER BY 1"
        )
    ).all()
    return [{"bucket": r[0].isoformat(), "count": r[1]} for r in rows]


def classification_distribution(db: Session) -> List[Dict[str, Any]]:
    rows = (
        db.query(ClassificationResult.behaviour_class, func.count(ClassificationResult.id))
        .group_by(ClassificationResult.behaviour_class)
        .all()
    )
    return [{"class": c, "count": n} for c, n in rows]


def risk_distribution(db: Session) -> List[Dict[str, Any]]:
    rows = (
        db.query(RiskAssessment.severity, func.count(RiskAssessment.id))
        .group_by(RiskAssessment.severity)
        .all()
    )
    return [{"severity": s, "count": n} for s, n in rows]


def service_usage(db: Session) -> List[Dict[str, Any]]:
    rows = (
        db.query(HoneypotEvent.service, func.count(HoneypotEvent.id))
        .filter(HoneypotEvent.service.isnot(None))
        .group_by(HoneypotEvent.service)
        .all()
    )
    return [{"service": s, "count": n} for s, n in rows]


def anomaly_distribution(db: Session) -> List[Dict[str, Any]]:
    rows = (
        db.query(AnomalyResult.label, func.count(AnomalyResult.id))
        .group_by(AnomalyResult.label)
        .all()
    )
    return [{"label": l, "count": n} for l, n in rows]


def session_duration_distribution(db: Session, buckets: int = 8) -> List[Dict[str, Any]]:
    durations = [
        r[0]
        for r in db.query(HoneypotSession.duration_seconds)
        .filter(HoneypotSession.duration_seconds.isnot(None))
        .all()
    ]
    if not durations:
        return []
    maxd = max(durations)
    step = max(maxd / buckets, 1)
    hist: Dict[int, int] = {}
    for d in durations:
        b = int(d // step)
        hist[b] = hist.get(b, 0) + 1
    return [
        {
            "bucket": f"{int(b*step)}-{int((b+1)*step)}s",
            "count": hist.get(b, 0),
        }
        for b in sorted(hist)
    ]


def behaviour_transitions(db: Session) -> List[Dict[str, Any]]:
    rows = (
        db.query(ModelPrediction.input_sequence, ModelPrediction.top1_label)
        .filter(ModelPrediction.top1_label.isnot(None))
        .all()
    )
    transitions = {}
    for seq, top1 in rows:
        if not seq:
            continue
        last = seq[-1] if seq else "other_unknown"
        key = (last, top1)
        transitions[key] = transitions.get(key, 0) + 1
    return [
        {"from": a, "to": b, "count": c}
        for (a, b), c in sorted(transitions.items(), key=lambda x: -x[1])
    ]


def adaptive_actions(db: Session) -> List[Dict[str, Any]]:
    rows = (
        db.query(DeceptionAction.policy_id, DeceptionAction.status, func.count(DeceptionAction.id))
        .group_by(DeceptionAction.policy_id, DeceptionAction.status)
        .all()
    )
    return [{"policy_id": p, "status": s, "count": n} for p, s, n in rows]


def dashboard_summary(db: Session) -> Dict[str, Any]:
    sessions_total = db.query(HoneypotSession).count()
    active = db.query(HoneypotSession).filter(HoneypotSession.is_active.is_(True)).count()
    high_risk = (
        db.query(RiskAssessment).filter(RiskAssessment.severity.in_(["HIGH", "CRITICAL"])) .count()
    )
    anomalies = db.query(AnomalyResult).filter(AnomalyResult.label == "anomaly").count()
    events_total = db.query(HoneypotEvent).count()
    predictions = db.query(ModelPrediction).count()
    adaptive_actions_n = db.query(DeceptionAction).count()
    return {
        "total_sessions": sessions_total,
        "active_sessions": active,
        "high_risk_sessions": high_risk,
        "anomalies": anomalies,
        "total_events": events_total,
        "predictions": predictions,
        "adaptive_actions": adaptive_actions_n,
    }
