from app.risk.engine import RiskEngine, parse_weights, severity_for


def test_parse_weights_default():
    w = parse_weights(None)
    assert w["anomaly"] == 0.30
    assert w["behaviour"] == 0.25


def test_parse_weights_custom():
    w = parse_weights("anomaly:0.5,behaviour:0.2,sequence:0.1,resource:0.1,persistence:0.1")
    assert w["anomaly"] == 0.5


def test_risk_severity_thresholds():
    engine = RiskEngine()
    low = engine.assess({"anomaly": 0.1, "behaviour": 0.1, "sequence": 0.1, "resource": 0.1, "persistence": 0.1})
    assert low["severity"] == "LOW"
    assert 0 <= low["score"] <= 100

    high = engine.assess({"anomaly": 0.9, "behaviour": 0.9, "sequence": 0.9, "resource": 0.9, "persistence": 0.9})
    assert high["severity"] == "CRITICAL"
    assert high["score"] > 80

    assert severity_for(85) == "CRITICAL"
    assert severity_for(65) == "HIGH"
    assert severity_for(45) == "MEDIUM"
    assert severity_for(10) == "LOW"


def test_risk_contributions_and_version():
    engine = RiskEngine(version="policy-test-v1")
    res = engine.assess({"anomaly": 1.0, "behaviour": 0.0, "sequence": 0.0, "resource": 0.0, "persistence": 0.0})
    assert res["policy_version"] == "policy-test-v1"
    assert res["contributions"]["anomaly"]["score"] > 0
    assert abs(res["score"] - 30.0) < 0.3  # anomaly weight 0.30 -> 30 points
