"""Tests for the behaviour model, profile-driven deception, block approval and
the Linux firewall backend."""

from __future__ import annotations

import time
import unittest

from sensor import behaviour
from sensor.behaviour import BehaviourModel
from sensor.deception import MAX_LEVEL, PERSONA_FOR_CLASS
from sensor.engine import DetectionEngine
from sensor.firewall import BlockManager, IptablesBackend, NetshBackend, make_backend
from sensor.tools import train_behaviour

from tests.test_sensor import TempSensor, connection


def finding_for(ip, classification, *, profile=None, behaviour_=None, severity="MEDIUM"):
    return {"src_ip": ip, "classification": classification, "severity": severity, "score": 60,
            "evidence": {"profile": profile or {}, "behaviour": behaviour_ or {}}}


class IptablesTests(unittest.TestCase):
    def test_add_inserts_a_tagged_drop_rule_once(self):
        calls = []

        def runner(args):
            calls.append(args)
            return (1, "") if args[1] == "-C" else (0, "")

        code, _ = IptablesBackend(runner).add("HP-BLOCK-198.51.100.7", "198.51.100.7")
        self.assertEqual(code, 0)
        self.assertEqual(calls[-1][:2], ["iptables", "-I"])
        self.assertIn("198.51.100.7", calls[-1])
        self.assertIn("HP-BLOCK-198.51.100.7", calls[-1])
        self.assertEqual(calls[-1][-2:], ["-j", "DROP"])

    def test_existing_rule_is_not_duplicated_and_ipv6_uses_ip6tables(self):
        calls = []
        backend = IptablesBackend(lambda args: (calls.append(args) or (0, "")))
        backend.add("r", "2001:db8::1")
        self.assertEqual(len(calls), 1)  # only the -C check
        self.assertEqual(calls[0][0], "ip6tables")

    def test_backend_selection(self):
        self.assertIsInstance(make_backend("netsh"), NetshBackend)
        self.assertIsInstance(make_backend("iptables"), IptablesBackend)
        with self.assertRaises(ValueError):
            make_backend("pf")


class ApprovalTests(TempSensor):
    def manager(self):
        self.config["response"]["require_approval"] = True
        manager = BlockManager(self.config, self.store, runner=lambda a: (0, ""),
                               admin_check=lambda: True, protected_extra=set())
        manager.start()
        self.addCleanup(manager.stop)
        return manager

    def high_finding(self, ip):
        return {"src_ip": ip, "classification": "PORT_SCAN", "score": 90}

    def test_automatic_block_waits_for_approval_then_applies(self):
        manager = self.manager()
        decision = manager.consider(self.high_finding("203.0.113.150"))
        self.assertEqual(decision["action"], "approval_requested")
        self.assertEqual(self.store.active_blocks(), [])
        self.assertEqual(len(self.store.blocks_awaiting_approval()), 1)

        # A repeat finding does not queue a second request.
        manager.consider(self.high_finding("203.0.113.150"))
        self.assertEqual(len(self.store.blocks_awaiting_approval()), 1)

        row = manager.approve(decision["block_id"])
        manager.wait_idle()
        self.assertEqual(self.store.get_block(row["id"])["status"], "DRY_RUN")
        self.assertIsNotNone(self.store.get_block(row["id"])["expires"])

    def test_rejected_request_is_closed(self):
        manager = self.manager()
        decision = manager.consider(self.high_finding("203.0.113.151"))
        manager.reject(decision["block_id"])
        self.assertEqual(self.store.get_block(decision["block_id"])["status"], "REJECTED")
        self.assertIsNone(self.store.active_block_for_ip("203.0.113.151"))

    def test_operator_block_counts_as_approval(self):
        manager = self.manager()
        decision = manager.consider(self.high_finding("203.0.113.152"))
        row = manager.block("203.0.113.152", "operator", source="operator")
        self.assertEqual(row["id"], decision["block_id"])
        manager.wait_idle()
        self.assertEqual(self.store.get_block(row["id"])["status"], "DRY_RUN")


class BehaviourModelTests(TempSensor):
    @classmethod
    def setUpClass(cls):
        sessions = train_behaviour.lab_sessions(250, seed=3)
        cls.bundle = behaviour.train(train_behaviour.samples_from(sessions), seed=3)

    def model(self):
        path = self.tmp / "behaviour.joblib"
        behaviour.save(self.bundle, path)
        return BehaviourModel(path, weight=20)

    def test_training_reports_grouped_cross_validation(self):
        metrics = self.bundle["metrics"]
        self.assertIn("GroupKFold", metrics["cv"])
        self.assertEqual(set(metrics["per_class"]), set(behaviour.CLASSES))
        self.assertGreater(metrics["macro_f1"], 0.8)

    def test_missing_bundle_is_reported_not_raised(self):
        model = BehaviourModel(self.tmp / "absent.joblib")
        self.assertFalse(model.loaded)
        self.assertIn("not trained", model.status()["error"])

    def test_slow_scan_missed_by_rules_is_flagged_by_the_model(self):
        engine = DetectionEngine(self.config, self.store, self.models, self.decoys,
                                 self.blocker, behaviour=self.model())
        start = time.time() - 2000
        findings = []
        # One port every 170 s: never four ports in the 60 s scan window, never
        # three in the 5-minute service-discovery window.
        for i, port in enumerate((21, 23, 25, 110, 1433, 6379, 9200, 27017)):
            finding = engine.observe(connection("10.77.0.1", port, ts=start + 170 * i))
            if finding:
                findings.append(finding)
        classes = {f["classification"] for f in findings}
        self.assertIn("ML_BEHAVIOUR_SUSPECTED", classes)
        flagged = next(f for f in findings if f["classification"] == "ML_BEHAVIOUR_SUSPECTED")
        self.assertEqual(flagged["evidence"]["behaviour"]["label"], "RECON_SCAN")
        self.assertEqual(flagged["rule_points"], 0)
        self.assertEqual(flagged["attack"][0]["id"], "T1046")
        self.assertEqual(flagged["decision"]["block"]["action"], "none")

        # The same sequence without the model raises nothing.
        plain = DetectionEngine(self.config, self.store, self.models, self.decoys, self.blocker)
        self.assertFalse(any(plain.observe(connection("10.77.0.2", port, ts=start + 170 * i))
                             for i, port in enumerate((21, 23, 25, 110, 1433, 6379, 9200, 27017))))


class ProfileDeceptionTests(TempSensor):
    def test_ml_only_finding_takes_its_persona_from_the_behaviour_label(self):
        decision = self.decoys.on_finding(finding_for(
            "10.88.0.1", "ML_BEHAVIOUR_SUSPECTED",
            behaviour_={"label": "CREDENTIAL_ATTACK", "confidence": 0.9}))
        self.assertEqual(decision["persona"], PERSONA_FOR_CLASS["SSH_BRUTE_FORCE"])
        self.assertIn("attacker profile", decision["reason"])

    def test_multi_stage_profile_gets_full_engagement(self):
        decision = self.decoys.on_finding(finding_for(
            "10.88.0.2", "PORT_SCAN", profile={"label": "TARGETED_MULTI_STAGE", "confidence": 0.7}))
        self.assertEqual(decision["level"], MAX_LEVEL)

    def test_weak_profile_is_ignored(self):
        decision = self.decoys.on_finding(finding_for(
            "10.88.0.3", "PORT_SCAN", profile={"label": "TARGETED_MULTI_STAGE", "confidence": 0.3}))
        self.assertLess(decision["level"], MAX_LEVEL)

    def test_web_attack_class_has_a_persona(self):
        decision = self.decoys.on_finding(finding_for("10.88.0.4", "SQL_INJECTION"))
        self.assertIn("SQL_INJECTION", decision["reason"])


class LabelTests(TempSensor):
    def test_latest_operator_label_wins_and_events_round_trip(self):
        self.store.add_label("10.99.0.1", "BENIGN")
        self.store.add_label("10.99.0.1", "RECON_SCAN")
        self.assertEqual(self.store.labels(), {"10.99.0.1": "RECON_SCAN"})
        self.engine.observe(connection("10.99.0.1", 21))
        events = self.store.events_for("10.99.0.1")
        self.assertEqual(events[0].dst_port, 21)


if __name__ == "__main__":
    unittest.main()
