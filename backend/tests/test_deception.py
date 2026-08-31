from app.deception.policies import POLICIES, get_policy
from app.honeypot.simulator import SCENARIOS, SimulatedAttacker


def test_policy_registry_complete():
    ids = [p.policy_id for p in POLICIES]
    assert "policy_keep_baseline" in ids
    assert "policy_enable_db_decoy" in ids
    assert "policy_expose_config_decoy" in ids
    assert "policy_enable_resource_decoy" in ids
    assert "policy_change_decoy_content" in ids
    # All policies must be safe and reversible
    for p in POLICIES:
        assert p.safety_level == "safe"
        assert p.rollback_action


def test_get_policy():
    assert get_policy("policy_keep_baseline").policy_id == "policy_keep_baseline"
    assert get_policy("nope") is None


def test_scenario_registry():
    for s in ("auth_attempts", "discovery", "resource_enumeration", "decoy_access",
              "multi_stage", "benign"):
        assert s in SCENARIOS


def test_simulator_reproducible():
    from datetime import datetime

    start = datetime(2026, 1, 1, 0, 0, 0)
    a1 = SimulatedAttacker(seed=7).generate("multi_stage", n_sessions=2, start=start)
    a2 = SimulatedAttacker(seed=7).generate("multi_stage", n_sessions=2, start=start)
    assert len(a1) == len(a2)
    # deterministic seeds produce identical sequences with identical timestamps
    t1 = [e.timestamp for e in a1]
    t2 = [e.timestamp for e in a2]
    assert t1 == t2


def test_simulator_is_local_only():
    a = SimulatedAttacker(seed=1).generate("multi_stage", n_sessions=1)
    for e in a:
        # source is a private lab address, destination is loopback
        assert e.destination in ("127.0.0.1", "")
        assert str(e.source).startswith("10.0.0.")


def test_unknown_scenario_raises():
    a = SimulatedAttacker(seed=1)
    try:
        a.generate("does_not_exist")
        assert False, "should have raised"
    except ValueError:
        pass
