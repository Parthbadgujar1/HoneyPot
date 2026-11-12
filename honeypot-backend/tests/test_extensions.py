"""Tests for web-attack detection, redaction, ATT&CK/STIX export, the learning
deception policy and attacker profiling."""

from __future__ import annotations

import json
import random
import time
import unittest

from sensor import mitre
from sensor.deception import PERSONA_FOR_CLASS, PERSONAS, DecoyPolicy
from sensor.events import HTTP, SSH_AUTH, Event
from sensor.policy import FULL_REWARD_EVENTS, PersonaBandit
from sensor.privacy import redact_event
from sensor.profiler import profile
from sensor.webattacks import classify_request

from tests.test_sensor import TempSensor, connection


def web(ip, path, query="", body="", ts=None):
    return Event(HTTP, ip, 8080, "http", ts or time.time(), {
        "method": "GET", "path": path, "query": query, "body_preview": body,
        "user_agent": "t", "status": 200, "raw": f"GET {path}?{query}"})


class SignatureTests(unittest.TestCase):
    def test_each_family_is_recognised(self):
        cases = {
            "SQL_INJECTION": ("/item", "id=1 UNION SELECT user,pass FROM users"),
            "XSS": ("/search", "q=<script>alert(1)</script>"),
            "COMMAND_INJECTION": ("/ping", "host=8.8.8.8;cat /etc/hosts"),
            "PATH_TRAVERSAL": ("/download", "file=../../../etc/passwd"),
            "SSRF_LFI": ("/fetch", "url=http://169.254.169.254/latest"),
        }
        for family, (path, query) in cases.items():
            self.assertIn(family, classify_request(path, query), family)

    def test_double_encoded_attack_is_decoded(self):
        self.assertIn("PATH_TRAVERSAL", classify_request("/f", "p=%252e%252e%252f%252e%252e%252fetc/passwd"))

    def test_ordinary_requests_do_not_match(self):
        for path, query in (("/", ""), ("/search", "q=union station select seat"),
                            ("/products", "page=2&sort=price"), ("/about", "")):
            self.assertEqual(classify_request(path, query), [], (path, query))


class EngineExtensionTests(TempSensor):
    def test_sql_injection_raises_a_finding_with_attack_mapping(self):
        findings = self.observe(web("10.9.0.1", "/item", "id=1' OR 1=1 --"))
        self.assertEqual(findings[0]["classification"], "SQL_INJECTION")
        ids = {t["id"] for t in findings[0]["attack"]}
        self.assertIn("T1190", ids)

    def test_finding_carries_a_profile_with_confidence(self):
        findings = self.observe(web("10.9.0.2", "/item", "id=1 union select 1,2"))
        profile_ = findings[0]["evidence"]["profile"]
        self.assertEqual(profile_["label"], "WEB_EXPLOIT_ATTACKER")
        self.assertGreater(profile_["confidence"], 0.5)

    def test_passwords_are_redacted_before_storage_but_still_match_honeytokens(self):
        self.decoys.http_response("GET", "/.env", "10.9.0.3")
        token = self.store.honeytoken_for_ip("10.9.0.3", "aws_access_key")
        event = Event(SSH_AUTH, "10.9.0.3", None, "ssh", time.time(),
                      {"username": "admin", "method": "password", "secret_preview": token,
                       "raw": f"admin\n{token}"})
        findings = self.observe(event)
        self.assertEqual(findings[0]["classification"], "HONEYTOKEN_REUSE")
        stored = json.dumps(self.store.recent_events(limit=10), default=str)
        self.assertNotIn(token, stored)

    def test_form_password_in_http_body_is_masked(self):
        event = web("10.9.0.4", "/login", body="username=a&password=hunter2")
        event.detail["raw"] = "POST /login\r\n\r\nusername=a&password=hunter2"
        redact_event(event)
        self.assertNotIn("hunter2", json.dumps(event.detail))


class StixTests(unittest.TestCase):
    def test_bundle_is_valid_and_deterministic(self):
        findings = [{"ts": 1_800_000_000.0, "src_ip": "203.0.113.7", "classification": "SSH_BRUTE_FORCE",
                     "severity": "HIGH", "score": 90}]
        a = mitre.stix_bundle(findings, 1_800_000_100.0)
        b = mitre.stix_bundle(findings, 1_800_000_100.0)
        self.assertEqual(a, b)
        kinds = [o["type"] for o in a["objects"]]
        self.assertEqual(kinds.count("indicator"), 1)
        self.assertIn("attack-pattern", kinds)
        indicator = next(o for o in a["objects"] if o["type"] == "indicator")
        self.assertEqual(indicator["pattern"], "[ipv4-addr:value = '203.0.113.7']")
        ids = [o["id"] for o in a["objects"]]
        self.assertEqual(len(ids), len(set(ids)))
        for o in a["objects"]:
            self.assertTrue(o["id"].startswith(o["type"] + "--"))


class BanditTests(unittest.TestCase):
    def test_tries_every_persona_then_prefers_the_rewarded_one(self):
        bandit = PersonaBandit(list(PERSONAS))
        seen = set()
        for _ in range(len(PERSONAS)):
            persona = bandit.choose("PORT_SCAN")
            seen.add(persona)
            bandit.credit("PORT_SCAN", persona, 1.0 if persona == "windows_server" else 0.1)
        self.assertEqual(seen, set(PERSONAS))
        picks = []
        for _ in range(30):
            persona = bandit.choose("PORT_SCAN")
            picks.append(persona)
            bandit.credit("PORT_SCAN", persona, 1.0 if persona == "windows_server" else 0.1)
        self.assertGreater(picks.count("windows_server"), 20)

    def test_exclude_never_returns_the_current_persona(self):
        bandit = PersonaBandit(list(PERSONAS))
        for _ in range(20):
            self.assertNotEqual(bandit.choose("X", exclude="ubuntu_web"), "ubuntu_web")

    def test_feedback_window_rewards_follow_up_events(self):
        bandit = PersonaBandit(list(PERSONAS))
        bandit.started("1.2.3.4", "PORT_SCAN", "legacy_linux", now=100.0)
        for i in range(FULL_REWARD_EVENTS // 2):
            bandit.interaction("1.2.3.4", now=101.0 + i)
        bandit.settle("1.2.3.4")
        row = next(r for r in bandit.table() if r["persona"] == "legacy_linux")
        self.assertAlmostEqual(row["mean_reward"], 0.5)

    def test_policy_uses_bandit_and_records_why(self):
        import tempfile
        from pathlib import Path

        from sensor.store import Store
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "s.sqlite3")
            bandit = PersonaBandit(list(PERSONAS), PERSONA_FOR_CLASS)
            policy = DecoyPolicy(store, bandit=bandit)
            finding = {"src_ip": "10.1.1.1", "classification": "SSH_BRUTE_FORCE", "severity": "HIGH"}
            decision = policy.on_finding(finding, prior_findings=1)
            self.assertIn(decision["persona"], PERSONAS)
            self.assertIn("engagement feedback", decision["reason"])
            store.close()


class ProfilerTests(unittest.TestCase):
    def test_scanner_and_brute_forcer_are_told_apart(self):
        from sensor.events import CONNECTION
        now = time.time()
        scan = [Event(CONNECTION, "a", p, "-", now + i * 0.1, {}) for i, p in enumerate((21, 22, 23, 25, 80, 110))]
        brute = [Event(SSH_AUTH, "b", None, "ssh", now + i, {"username": "root"}) for i in range(9)]
        self.assertEqual(profile(scan)["label"], "AUTOMATED_SCANNER")
        self.assertEqual(profile(brute)["label"], "CREDENTIAL_ATTACKER")

    def test_empty_history_has_no_label(self):
        self.assertIsNone(profile([])["label"])

    def test_confidence_is_a_share_between_0_and_1(self):
        rng = random.Random(1)
        for _ in range(50):
            events = [Event(SSH_AUTH, "c", None, "ssh", i * rng.random(), {}) for i in range(rng.randint(1, 12))]
            c = profile(events)["confidence"]
            self.assertTrue(0.0 <= c <= 1.0)


if __name__ == "__main__":
    unittest.main()
