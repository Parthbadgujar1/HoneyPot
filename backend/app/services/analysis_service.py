"""Orchestrates the full intelligence pipeline for a session:
features -> classification -> anomaly -> prediction -> risk -> timeline ->
graph -> adaptive deception. Returns a comprehensive analysis result."""

from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.deception.engine import DeceptionEngine
from app.graph.engine import build_graph
from app.ml.explainability.explainer import (
    explain_classification,
    explain_risk,
)
from app.models.models import (
    AttackEdge,
    AttackNode,
    HoneypotEvent,
    HoneypotSession,
    RiskAssessment,
    TimelineEvent,
)
from app.risk.engine import RiskEngine, parse_weights
from app.services.ml_service import MLService
from app.timeline.engine import build_timeline

logger = get_logger("analysis-service")


class AnalysisService:
    def __init__(self, db: Session, adapter=None):
        self.db = db
        self.ml = MLService(db)
        self.risk_engine = RiskEngine(weights=parse_weights(None))
        self.deception = DeceptionEngine(db, adapter=adapter)

    def _targets_for_session(self, session_id: str) -> List[str]:
        rows = (
            self.db.query(HoneypotEvent)
            .filter(HoneypotEvent.session_id == session_id)
            .all()
        )
        return [r.target for r in rows if r.target]

    def analyse(self, session_id: str, apply_deception: bool = True) -> Dict[str, Any]:
        analysis = self.ml.analyse_session(session_id)
        analysis["_targets"] = self._targets_for_session(session_id)

        # ----- risk -----
        risk = self.risk_engine.assess(analysis.get("risk_inputs", {}))
        analysis["risk"] = risk
        analysis["_risk_score"] = risk["score"]
        self._persist_risk(session_id, risk)

        # ----- timeline -----
        events = (
            self.db.query(HoneypotEvent)
            .filter(HoneypotEvent.session_id == session_id)
            .order_by(HoneypotEvent.timestamp)
            .all()
        )
        timeline = build_timeline(events)
        analysis["timeline"] = timeline
        self._persist_timeline(session_id, timeline, events)

        # ----- graph -----
        pred = analysis.get("prediction", {})
        predicted = None
        if isinstance(pred, dict) and pred.get("top1"):
            predicted = [
                {
                    "from": pred.get("input_sequence", [None])[-1] if pred.get("input_sequence") else None,
                    "to": pred["top1"],
                    "probability": pred.get("top1_probability", 0.0),
                }
            ]
        graph = build_graph(events, predicted=predicted)
        analysis["graph"] = graph
        self._persist_graph(session_id, events, predicted)

        # ----- explanation -----
        explanation = self._explain(analysis)
        analysis["explanation"] = explanation

        # ----- adaptive deception -----
        if apply_deception:
            decision = self.deception.evaluate(
                session_id, analysis, risk_score=risk["score"]
            )
            analysis["deception"] = decision
        else:
            analysis["deception"] = {"decision": "skipped"}

        return analysis

    def _explain(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        explanation = {"classification": None, "risk": None}
        if self.ml.classifier_available():
            cls = analysis.get("classification", {})
            if cls.get("behaviour_class"):
                explanation["classification"] = explain_classification(
                    self.ml.classifier, cls["behaviour_class"]
                )
        else:
            explanation["classification"] = {"status": "model_not_trained"}
        explanation["risk"] = explain_risk(analysis.get("risk", {}))
        return explanation

    def _persist_risk(self, session_id: str, risk: Dict) -> None:
        self.db.query(RiskAssessment).filter(
            RiskAssessment.session_id == session_id
        ).delete()
        row = RiskAssessment(
            session_id=session_id,
            score=risk.get("score"),
            severity=risk.get("severity"),
            policy_version=risk.get("policy_version"),
            contributions=risk.get("contributions"),
        )
        self.db.add(row)
        self.db.commit()

    def _persist_timeline(self, session_id: str, timeline: List[Dict], events) -> None:
        self.db.query(TimelineEvent).filter(
            TimelineEvent.session_id == session_id
        ).delete()
        for ev in events:
            ts = ev.timestamp
            desc = next(
                (t["description"] for t in timeline if t["event_id"] == str(ev.id)),
                str(ev.action or ev.event_type),
            )
            self.db.add(
                TimelineEvent(
                    session_id=session_id,
                    timestamp=ts,
                    event_type=ev.event_type,
                    action=ev.action,
                    description=desc,
                )
            )
        self.db.commit()

    def _persist_graph(self, session_id: str, events, predicted) -> None:
        self.db.query(AttackEdge).filter(AttackEdge.session_id == session_id).delete()
        self.db.query(AttackNode).filter(AttackNode.session_id == session_id).delete()
        graph = build_graph(events, predicted=predicted)
        # build from the graph payload
        for n in graph["nodes"]:
            data = n["data"]
            self.db.add(
                AttackNode(
                    session_id=session_id,
                    node_key=data["id"],
                    node_type=data.get("node_type", "unknown"),
                    label=data.get("label", data["id"]),
                )
            )
        for e in graph["edges"]:
            data = e["data"]
            self.db.add(
                AttackEdge(
                    session_id=session_id,
                    source_key=data["source"],
                    target_key=data["target"],
                    edge_type=data.get("edge_type", "followed_by"),
                    label=data.get("label", data.get("edge_type", "followed_by")),
                )
            )
        self.db.commit()
