"""ML runtime service.

Loads the active classifier/anomaly/sequence models, applies them to a
session's events, and produces annotated results (classification, anomaly,
prediction, risk inputs). Models are versioned and persisted.
"""

import os
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.honeypot.base import HoneypotAdapter
from app.ml.anomaly.isolation import IsolationForestAnomaly
from app.ml.classification.classifier import (
    BaseClassifier,
    create_classifier,
)
from app.ml.sequence.markov import MarkovSequencePredictor
from app.ml.base import BaseModelWrapper, load_model
from app.models.models import (
    AnomalyResult,
    BehaviourFeatures,
    ClassificationResult,
    HoneypotEvent,
    HoneypotSession,
    ModelPrediction,
    ModelVersion,
)
from app.schemas.event import NormalizedEvent
from app.telemetry.features import (
    BehaviourFeatureExtractor,
    FeatureVectorBuilder,
    StageSequenceBuilder,
    majority_stage,
)

settings = get_settings()
logger = get_logger("ml-service")


class MLService:
    def __init__(self, db: Session):
        self.db = db
        self.feature_extractor = BehaviourFeatureExtractor()
        self.vector_builder = FeatureVectorBuilder()
        self.stage_builder = StageSequenceBuilder()
        self.classifier = self._load_active("classifier", create_classifier)
        self.anomaly = self._load_active("anomaly", lambda n, v: IsolationForestAnomaly(version=v))
        self.sequence = self._load_active(
            "sequence", lambda n, v: MarkovSequencePredictor(version=v)
        )

    def _load_active(self, model_type: str, factory) -> Optional[BaseModelWrapper]:
        version_rec = (
            self.db.query(ModelVersion)
            .filter(ModelVersion.model_type == model_type, ModelVersion.is_active.is_(True))
            .first()
        )
        if version_rec and version_rec.artifact_path and os.path.exists(version_rec.artifact_path):
            try:
                return load_model(version_rec.artifact_path)
            except Exception as e:
                logger.warning("Failed to load %s model %s: %s", model_type, version_rec.version, e)
        return None

    def classifier_available(self) -> bool:
        return self.classifier is not None

    def anomaly_available(self) -> bool:
        return self.anomaly is not None

    def sequence_available(self) -> bool:
        return self.sequence is not None

    def extract_features_for_session(self, session_id: str) -> Dict[str, float]:
        events = self._events_for_session(session_id)
        return self.feature_extractor.extract_features(events)

    def _events_for_session(self, session_id: str) -> List[NormalizedEvent]:
        rows = (
            self.db.query(HoneypotEvent)
            .filter(HoneypotEvent.session_id == session_id)
            .order_by(HoneypotEvent.timestamp)
            .all()
        )
        evs = []
        for r in rows:
            evs.append(
                NormalizedEvent(
                    event_id=str(r.id),
                    timestamp=r.timestamp,
                    session_id=str(r.session_id) if r.session_id else r.session_id,
                    source=r.source,
                    destination=r.destination,
                    service=r.service,
                    event_type=r.event_type,
                    action=r.action,
                    target=r.target,
                    result=r.result,
                    username=r.username,
                    command=r.command,
                    payload=r.payload or {},
                )
            )
        return evs

    def analyse_session(self, session_id: str) -> Dict[str, Any]:
        features = self.extract_features_for_session(session_id)
        events = self._events_for_session(session_id)

        # persist features
        self._persist_features(session_id, features)

        vector = self.vector_builder.build(features)
        result: Dict[str, Any] = {"session_id": session_id, "features": features}

        # classification
        if self.classifier_available():
            cls = self._classify(vector)
            result["classification"] = cls
            self._persist_classification(session_id, cls)
        else:
            result["classification"] = {"status": "model_not_trained"}

        # anomaly
        if self.anomaly_available():
            an = self.anomaly.score_and_explain([vector])
            result["anomaly"] = an
            self._persist_anomaly(session_id, an)
        else:
            result["anomaly"] = {"status": "model_not_trained"}

        # sequence
        if self.sequence_available():
            stages = self.stage_builder.compress(self.stage_builder.build(events))
            pred = self.sequence.predict_next(stages)
            result["prediction"] = pred
            result["stage_sequence"] = stages
            self._persist_prediction(session_id, pred)
        else:
            result["prediction"] = {"status": "model_not_trained"}

        # risk inputs
        result["risk_inputs"] = self._risk_inputs(result)
        return result

    def _risk_inputs(self, result: Dict[str, Any]) -> Dict[str, float]:
        inputs = {}
        an = result.get("anomaly", {})
        cls = result.get("classification", {})
        # anomaly score 0..1, normalize
        an_score = an.get("anomaly_score", 0.0) if isinstance(an, dict) else 0.0
        inputs["anomaly"] = an_score
        # behaviour risk: use confidence/class heuristic
        cl_conf = cls.get("confidence", 0.0) if isinstance(cls, dict) else 0.0
        cls_label = cls.get("behaviour_class", "") if isinstance(cls, dict) else ""
        risky_classes = {"suspicious_execution", "data_collection", "credential_abuse"}
        behaviour = (0.6 if cls_label in risky_classes else 0.3 if cls_label == "resource_access" else 0.15)
        inputs["behaviour"] = behaviour + cl_conf * 0.3 if cl_conf else behaviour
        feats = result.get("features", {})
        seq = result.get("prediction", {})
        top1p = seq.get("top1_probability", 0.0) if isinstance(seq, dict) else 0.0
        inputs["sequence"] = min(1.0, top1p)
        sensitive = feats.get("sensitive_interactions", 0)
        inputs["resource"] = min(1.0, 0.2 + 0.2 * sensitive)
        failed = feats.get("failed_auths", 0)
        inputs["persistence"] = min(1.0, 0.1 + 0.15 * failed)
        return {k: min(max(v, 0.0), 1.0) for k, v in inputs.items()}

    def _classify(self, vector) -> Dict[str, Any]:
        if not self.classifier:
            return {"status": "model_not_trained"}
        probs = self.classifier.predict_proba([vector])
        configured = list(self.classifier.classes)
        # Use the actual classes learned by the fitted estimator.
        model = getattr(self.classifier, "model", None)
        model_classes = list(configured)
        if model is not None and hasattr(model, "classes_"):
            model_classes = [str(c) for c in model.classes_]

        if probs is not None and len(probs) > 0 and len(model_classes) > 0:
            proba = probs[0]
            freq = {}
            for i, c in enumerate(model_classes):
                if i < len(proba):
                    freq[c] = float(proba[i])
            idx = int(proba.argmax())
            label = model_classes[idx] if idx < len(model_classes) else "other_unknown"
            conf = float(proba[idx]) if idx < len(proba) else 0.0
        else:
            label = configured[-1] if configured else "other_unknown"
            conf = 0.0
            freq = {c: 1.0 / len(configured) for c in configured}
        # ensure all configured classes present in the response distribution
        for c in configured:
            freq.setdefault(c, 0.0)
        return {
            "behaviour_class": label,
            "confidence": round(conf, 4),
            "probabilities": {c: round(freq.get(c, 0.0), 4) for c in configured},
            "model": getattr(self.classifier, "name", "unknown"),
            "model_version": self.classifier.version,
            "feature_version": "v1",
        }

    def _persist_features(self, session_id: str, features: Dict[str, float]) -> None:
        self.db.query(BehaviourFeatures).filter(
            BehaviourFeatures.session_id == session_id
        ).delete()
        row = BehaviourFeatures(session_id=session_id, feature_version="v1", **features)
        self.db.add(row)
        self.db.commit()

    def _persist_classification(self, session_id: str, cls: Dict) -> None:
        self.db.query(ClassificationResult).filter(
            ClassificationResult.session_id == session_id
        ).delete()
        row = ClassificationResult(
            session_id=session_id,
            model_name=cls.get("model", "unknown"),
            model_version=cls.get("model_version"),
            behaviour_class=cls.get("behaviour_class", "other_unknown"),
            confidence=cls.get("confidence"),
            probabilities=cls.get("probabilities"),
            feature_version=cls.get("feature_version"),
        )
        self.db.add(row)
        self.db.commit()

    def _persist_anomaly(self, session_id: str, an: Dict) -> None:
        self.db.query(AnomalyResult).filter(
            AnomalyResult.session_id == session_id
        ).delete()
        row = AnomalyResult(
            session_id=session_id,
            model_name="isolation_forest",
            model_version=self.anomaly.version if self.anomaly else None,
            anomaly_score=an.get("anomaly_score"),
            label=an.get("label"),
            contributing_features=an.get("contributing_features"),
            reasons=an.get("reasons"),
        )
        self.db.add(row)
        self.db.commit()

    def _persist_prediction(self, session_id: str, pred: Dict) -> None:
        self.db.query(ModelPrediction).filter(
            ModelPrediction.session_id == session_id
        ).delete()
        row = ModelPrediction(
            session_id=session_id,
            model_name=pred.get("model", "markov"),
            model_version=pred.get("model_version"),
            input_sequence=pred.get("input_sequence"),
            top_predictions=pred.get("top_predictions"),
            top1_label=pred.get("top1"),
            top1_probability=pred.get("top1_probability"),
        )
        self.db.add(row)
        self.db.commit()
