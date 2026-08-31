"""ML training pipeline.

Builds a labelled dataset from the controlled simulator's scenarios, extracts
features, trains classifier/anomaly/sequence models, saves artifacts, and
registers ModelVersion records.
"""

from datetime import datetime
from typing import Dict, List, Optional, Tuple

from sklearn.model_selection import train_test_split
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.honeypot.simulator import SimulatedAttacker
from app.ml.anomaly.isolation import IsolationForestAnomaly
from app.ml.classification.classifier import (
    RandomForestClassifier,
    XGBoostClassifier,
    LogisticRegressionClassifier,
)
from app.ml.sequence.markov import MarkovSequencePredictor
from app.ml.base import BaseModelWrapper
from app.models.models import ModelVersion
from app.schemas.event import RawEvent
from app.telemetry.action_catalog import BEHAVIOUR_STAGES, action_to_stage
from app.telemetry.features import (
    BehaviourFeatureExtractor,
    FeatureVectorBuilder,
    StageSequenceBuilder,
)

settings = get_settings()
logger = get_logger("training")

SCENARIO_LABELS = {
    "auth_attempts": "credential_abuse",
    "discovery": "discovery",
    "resource_enumeration": "discovery",
    "decoy_access": "data_collection",
    "multi_stage": "suspicious_execution",
    "benign": "other_unknown",
}

CLASSIFIER_FACTORIES = {
    "logistic_regression": LogisticRegressionClassifier,
    "random_forest": RandomForestClassifier,
    "xgboost": XGBoostClassifier,
}


def generate_labelled_dataset(
    scenarios: Optional[List[str]] = None,
    sessions_per_scenario: int = 20,
    seed: int = 42,
) -> Tuple[List[Dict[str, float]], List[str], List[List[str]], List[str]]:
    scenarios = scenarios or list(SCENARIO_LABELS.keys())
    attacker = SimulatedAttacker(seed=seed)
    extractor = BehaviourFeatureExtractor()
    stage_builder = StageSequenceBuilder()

    xs: List[Dict[str, float]] = []
    ys: List[str] = []
    sequences: List[List[str]] = []
    seq_y: List[str] = []

    for scenario in scenarios:
        label = SCENARIO_LABELS[scenario]
        start = datetime(2026, 1, 1, 0, 0, 0)
        for i in range(sessions_per_scenario):
            events: List[RawEvent] = attacker.generate(
                scenario, n_sessions=1, start=start
            )
            norm = [_raw_to_norm(e) for e in events]
            features = extractor.extract_features(norm)
            xs.append(features)
            ys.append(label)

            stages = stage_builder.compress(stage_builder.build(norm))
            if len(stages) >= 2:
                sequences.append(stages)
                seq_y.append(label)
            start = start.replace(second=0)
    return xs, ys, sequences, seq_y


def _raw_to_norm(ev: RawEvent):
    from app.telemetry.pipeline import normalize

    return normalize(ev)


def train_classifier(
    model_name: str = "random_forest",
    version: str = "classifier-v1",
    sessions_per_scenario: int = 20,
    seed: int = 42,
) -> Dict:
    if model_name not in CLASSIFIER_FACTORIES:
        raise ValueError(f"Unknown classifier: {model_name}")
    xs, ys, _, _ = generate_labelled_dataset(
        sessions_per_scenario=sessions_per_scenario, seed=seed
    )
    builder = FeatureVectorBuilder()
    X = builder.build_matrix(xs)
    X_train, X_test, y_train, y_test = train_test_split(
        X, ys, test_size=0.2, random_state=seed, stratify=ys
    )
    clf = CLASSIFIER_FACTORIES[model_name](version=version)
    clf._n_train = len(X_train)
    clf.fit(X_train, y_train)
    metrics = clf.evaluate(X_test, y_test)
    path = clf.save(settings.ML_MODELS_DIR)
    logger.info("Trained classifier %s v%s metrics=%s", model_name, version, metrics)
    return {
        "model": model_name,
        "version": version,
        "metrics": metrics,
        "artifact_path": path,
        "feature_version": clf.feature_version,
        "classes": clf.classes,
        "n_sessions": len(X),
    }


def train_anomaly(
    version: str = "isolation-v1",
    sessions_per_scenario: int = 20,
    seed: int = 42,
) -> Dict:
    # Train isolation forest on features from all generated sessions.
    xs, _, _, _ = generate_labelled_dataset(
        sessions_per_scenario=sessions_per_scenario, seed=seed
    )
    builder = FeatureVectorBuilder()
    X = builder.build_matrix(xs)
    model = IsolationForestAnomaly(version=version)
    model.fit(X)
    path = model.save(settings.ML_MODELS_DIR)
    logger.info("Trained anomaly model v%s on %d sessions", version, len(X))
    return {
        "model": "isolation_forest",
        "version": version,
        "artifact_path": path,
        "n_sessions": len(X),
    }


def train_sequence(
    version: str = "markov-v1",
    sessions_per_scenario: int = 20,
    seed: int = 42,
) -> Dict:
    _, _, sequences, _ = generate_labelled_dataset(
        sessions_per_scenario=sessions_per_scenario, seed=seed
    )
    model = MarkovSequencePredictor(version=version)
    model.fit(sequences)
    metrics = model.evaluate(sequences)
    path = model.save(settings.ML_MODELS_DIR)
    logger.info("Trained markov v%s metrics=%s", version, metrics)
    return {
        "model": "markov",
        "version": version,
        "metrics": metrics,
        "artifact_path": path,
        "n_sequences": len(sequences),
    }


def register_model(
    db: Session,
    model_type: str,
    name: str,
    version: str,
    artifact_path: str,
    metrics: Dict,
    activate: bool = True,
) -> ModelVersion:
    existing = (
        db.query(ModelVersion)
        .filter(ModelVersion.model_type == model_type, ModelVersion.version == version)
        .first()
    )
    if existing:
        return existing
    if activate:
        db.query(ModelVersion).filter(ModelVersion.model_type == model_type).update(
            {"is_active": False}
        )
    row = ModelVersion(
        model_type=model_type,
        name=name,
        version=version,
        artifact_path=artifact_path,
        metrics=metrics,
        trained_at=datetime.utcnow(),
        dataset_version=f"sim-{version}",
        is_active=activate,
    )
    db.add(row)
    db.commit()
    return row


def train_all(db: Session, seed: int = 42) -> Dict:
    results = {}
    try:
        # classifier
        clf_res = train_classifier("random_forest", version=f"classifier-v{seed}", seed=seed)
        register_model(
            db, "classifier", "random_forest",
            clf_res["version"], clf_res["artifact_path"], clf_res["metrics"],
        )
        results["classifier"] = clf_res
        # anomaly
        an_res = train_anomaly(version=f"isolation-v{seed}", seed=seed)
        register_model(
            db, "anomaly", "isolation_forest",
            an_res["version"], an_res["artifact_path"], {},
        )
        results["anomaly"] = an_res
        # sequence
        seq_res = train_sequence(version=f"markov-v{seed}", seed=seed)
        register_model(
            db, "sequence", "markov",
            seq_res["version"], seq_res["artifact_path"], seq_res.get("metrics", {}),
        )
        results["sequence"] = seq_res
    except Exception as e:
        logger.error("Training failed: %s", e)
        raise
    return results
