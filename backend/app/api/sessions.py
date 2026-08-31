from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.logging import get_logger
from app.models.models import (
    AnomalyResult,
    AttackEdge,
    AttackNode,
    BehaviourFeatures,
    ClassificationResult,
    DeceptionAction,
    HoneypotEvent,
    HoneypotSession,
    ModelPrediction,
    RiskAssessment,
    TimelineEvent,
)
from app.security.auth import get_current_user, require_role
from app.services.analysis_service import AnalysisService

router = APIRouter(prefix="/sessions", tags=["sessions"])
logger = get_logger("api-sessions")


@router.get("")
def list_sessions(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    severity: Optional[str] = None,
    service: Optional[str] = None,
    risk_min: Optional[float] = None,
    sort_by: str = "start_time",
    sort_dir: str = "desc",
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    q = db.query(HoneypotSession)
    if service:
        q = q.filter(HoneypotSession.service == service)
    total = q.count()
    items = q.order_by(HoneypotSession.start_time.desc().nullslast()) \
        .offset((page - 1) * page_size).limit(page_size).all()

    result = []
    for s in items:
        risk = (
            db.query(RiskAssessment).filter(RiskAssessment.session_id == s.id).first()
        )
        if severity and (not risk or risk.severity != severity):
            continue
        if risk_min is not None and (not risk or (risk.score or 0) < risk_min):
            continue
        result.append(_summary(s, risk))
    return {"total": len(result), "page": page, "page_size": page_size, "items": result}


def _summary(s, risk):
    return {
        "id": s.id,
        "session_ref": s.session_ref,
        "source": s.source,
        "service": s.service,
        "start_time": s.start_time.isoformat() if s.start_time else None,
        "end_time": s.end_time.isoformat() if s.end_time else None,
        "duration_seconds": s.duration_seconds,
        "event_count": s.event_count,
        "is_active": s.is_active,
        "risk_score": risk.score if risk else None,
        "severity": risk.severity if risk else None,
    }


@router.get("/{session_id}")
def get_session(session_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    s = db.get(HoneypotSession, session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    risk = db.query(RiskAssessment).filter(RiskAssessment.session_id == session_id).first()
    cls = db.query(ClassificationResult).filter(ClassificationResult.session_id == session_id).first()
    an = db.query(AnomalyResult).filter(AnomalyResult.session_id == session_id).first()
    pred = db.query(ModelPrediction).filter(ModelPrediction.session_id == session_id).first()
    features = db.query(BehaviourFeatures).filter(
        BehaviourFeatures.session_id == session_id
    ).first()
    return {
        **_summary(s, risk),
        "classification": _ser_cls(cls),
        "anomaly": _ser_anomaly(an),
        "prediction": _ser_pred(pred),
        "features": features.features_json if features else None,
        "deception_actions": [
            {"id": a.id, "policy_id": a.policy_id, "action": a.action,
             "status": a.status, "rollback_status": a.rollback_status,
             "reason": a.reason, "created_at": a.created_at.isoformat() if a.created_at else None}
            for a in db.query(DeceptionAction).filter(DeceptionAction.session_id == session_id).all()
        ],
    }


@router.post("/{session_id}/analyse")
def analyse(session_id: str, db: Session = Depends(get_db), user=Depends(require_role("ANALYST"))):
    if not db.get(HoneypotSession, session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    service = AnalysisService(db)
    result = service.analyse(session_id, apply_deception=True)
    return {"status": "ok", "analysis": result}


@router.get("/{session_id}/timeline")
def session_timeline(session_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = (
        db.query(TimelineEvent)
        .filter(TimelineEvent.session_id == session_id)
        .order_by(TimelineEvent.timestamp)
        .all()
    )
    return [
        {
            "timestamp": r.timestamp.isoformat(),
            "event_type": r.event_type,
            "action": r.action,
            "description": r.description,
        }
        for r in rows
    ]


@router.get("/{session_id}/graph")
def session_graph(session_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    nodes = db.query(AttackNode).filter(AttackNode.session_id == session_id).all()
    edges = db.query(AttackEdge).filter(AttackEdge.session_id == session_id).all()
    return {
        "nodes": [
            {"data": {"id": n.node_key, "label": n.label, "node_type": n.node_type}}
            for n in nodes
        ],
        "edges": [
            {
                "data": {
                    "id": f"{e.source_key}->{e.target_key}",
                    "source": e.source_key,
                    "target": e.target_key,
                    "edge_type": e.edge_type,
                    "label": e.label,
                }
            }
            for e in edges
        ],
        "stats": {"node_count": len(nodes), "edge_count": len(edges)},
    }


@router.get("/{session_id}/prediction")
def session_prediction(session_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    pred = db.query(ModelPrediction).filter(ModelPrediction.session_id == session_id).first()
    if not pred:
        raise HTTPException(status_code=404, detail="No prediction for session")
    return _ser_pred(pred)


@router.get("/{session_id}/explanation")
def session_explanation(session_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    svc = AnalysisService(db)
    analysis = svc.ml.analyse_session(session_id)
    risk = db.query(RiskAssessment).filter(RiskAssessment.session_id == session_id).first()
    from app.ml.explainability.explainer import explain_classification, explain_risk

    exp = {"classification": None, "risk": None, "anomaly": None}
    cls = analysis.get("classification")
    if cls and cls.get("behaviour_class") and svc.ml.classifier_available():
        exp["classification"] = explain_classification(svc.ml.classifier, cls["behaviour_class"])
    an = analysis.get("anomaly")
    if isinstance(an, dict) and an.get("contributing_features"):
        exp["anomaly"] = {
            "score": an["anomaly_score"],
            "label": an["label"],
            "reasons": an.get("reasons"),
            "contributing_features": an.get("contributing_features"),
        }
    if risk:
        exp["risk"] = explain_risk(
            {
                "contributions": risk.contributions,
                "score": risk.score,
                "severity": risk.severity,
                "policy_version": risk.policy_version,
            }
        )
    else:
        exp["risk"] = {"status": "no_assessment"}
    return exp


def _ser_cls(cls):
    if not cls:
        return None
    return {
        "behaviour_class": cls.behaviour_class,
        "confidence": cls.confidence,
        "probabilities": cls.probabilities,
        "model": cls.model_name,
        "model_version": cls.model_version,
        "feature_version": cls.feature_version,
    }


def _ser_anomaly(an):
    if not an:
        return None
    return {
        "anomaly_score": an.anomaly_score,
        "label": an.label,
        "reasons": an.reasons,
        "contributing_features": an.contributing_features,
        "model": an.model_name,
        "model_version": an.model_version,
    }


def _ser_pred(pred):
    if not pred:
        return None
    return {
        "top1": pred.top1_label,
        "top1_probability": pred.top1_probability,
        "top_predictions": pred.top_predictions,
        "input_sequence": pred.input_sequence,
        "model": pred.model_name,
        "model_version": pred.model_version,
    }
