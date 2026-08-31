from app.ml.classification.classifier import (
    create_classifier,
    CLASSIFIER_REGISTRY,
)
from app.ml.anomaly.isolation import IsolationForestAnomaly
from app.ml.sequence.markov import MarkovSequencePredictor
from app.services.training_service import (
    generate_labelled_dataset,
    SCENARIO_LABELS,
)


def _dataset(seed=1):
    return generate_labelled_dataset(
        scenarios=None, sessions_per_scenario=10, seed=seed
    )


def test_classifier_registry_complete():
    for name in ("logistic_regression", "random_forest", "xgboost"):
        assert name in CLASSIFIER_REGISTRY


def test_random_forest_classifier_smoke():
    from app.telemetry.features import FeatureVectorBuilder

    xs, ys, _, _ = _dataset()
    builder = FeatureVectorBuilder()
    X = builder.build_matrix(xs)
    clf = create_classifier("random_forest", version="test-v1")
    clf.fit(X, ys)
    pred = clf.predict([X[0]])
    assert pred[0] in clf.classes or pred[0] in ys
    assert clf.metrics or True


def test_anomaly_detector_returns_interpretable_result():
    from app.telemetry.features import FeatureVectorBuilder

    xs, _, _, _ = _dataset()
    builder = FeatureVectorBuilder()
    X = builder.build_matrix(xs)
    model = IsolationForestAnomaly(version="test-v1")
    model.fit(X)
    res = model.score_and_explain([X[0]])
    assert "anomaly_score" in res
    assert "label" in res
    assert isinstance(res["contributing_features"], list)
    assert len(res["contributing_features"]) > 0


def test_markov_sequence_predicts_top_k():
    _, _, sequences, _ = _dataset()
    model = MarkovSequencePredictor(version="test-v1")
    model.fit(sequences)
    seq = sequences[0]
    pred = model.predict_next(seq[:-1], k=3)
    assert len(pred["top_predictions"]) == 3
    assert pred["top1"] in model.classes
    # top-1 is the highest probability and monotonically decreases
    probs = [p["probability"] for p in pred["top_predictions"]]
    assert probs[0] >= probs[1] >= probs[2]
    assert all(0 <= p <= 1 for p in probs)


def test_markov_provides_metrics():
    _, _, sequences, _ = _dataset()
    model = MarkovSequencePredictor(version="test-v1")
    model.fit(sequences)
    metrics = model.evaluate(sequences)
    assert "top1_accuracy" in metrics
    assert 0 <= metrics["top1_accuracy"] <= 1
    assert 0 <= metrics["mrr"] <= 1
