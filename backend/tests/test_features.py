from app.telemetry.features import (
    BehaviourFeatureExtractor,
    FeatureVectorBuilder,
    StageSequenceBuilder,
    FEATURE_NAMES,
)
from app.telemetry.sessionization import SessionizationService
from app.schemas.event import RawEvent
from app.telemetry.pipeline import normalize, compute_dedup_key


def test_feature_extractor_returns_all_features(sample_session_events):
    extractor = BehaviourFeatureExtractor()
    feats = extractor.extract_features(sample_session_events)
    assert len(feats) == len(FEATURE_NAMES)
    assert feats["failed_auths"] == 1
    assert feats["successful_auths"] == 1
    assert feats["sensitive_interactions"] == 1
    assert feats["discovery_activity"] >= 1


def test_feature_vector_builder_fixed_size():
    builder = FeatureVectorBuilder()
    feats = {name: 1.0 for name in FEATURE_NAMES}
    vec = builder.build(feats)
    assert len(vec) == len(FEATURE_NAMES)
    assert all(isinstance(x, float) for x in vec)


def test_sessionization_groups_by_session(sample_session_events):
    svc = SessionizationService()
    groups = svc.sessionize(sample_session_events)
    assert list(groups.keys()) == ["S1"]
    summary = svc.summarize(sample_session_events)
    assert summary["event_count"] == 7
    assert summary["duration_seconds"] == 7.0


def test_stage_sequence_compression(sample_session_events):
    builder = StageSequenceBuilder()
    stages = builder.build(sample_session_events)
    compressed = builder.compress(stages)
    assert compressed == compressed  # no consecutive duplicates
    for a, b in zip(compressed, compressed[1:]):
        assert a != b


def test_normalize_and_dedup_key():
    from datetime import datetime

    raw = RawEvent(
        timestamp=datetime(2026, 1, 1),
        session_id="S",
        service="ssh",
        event_type="command",
        action="directory_listing",
    )
    norm = normalize(raw)
    assert norm.event_id
    k1 = compute_dedup_key(norm)
    k2 = compute_dedup_key(norm)
    assert k1 == k2
