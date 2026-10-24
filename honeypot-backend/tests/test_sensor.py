"""Tests for the honeypot sensor.

Run from honeypot-backend:

    python -m unittest discover -s tests -v

Unit tests use a temporary SQLite file and a fake firewall runner, so no
rule is ever created on this machine. Integration tests start the bait,
SSH and HTTP decoys on free loopback ports.
"""

from __future__ import annotations

import asyncio
import copy
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from sensor import config as cfgmod  # noqa: E402
from sensor.deception import PERSONAS, DecoyPolicy  # noqa: E402
from sensor.engine import DetectionEngine  # noqa: E402
from sensor.events import CONNECTION, FW_DROP, HTTP, SSH_AUTH, Event  # noqa: E402
from sensor.firewall import BlockError, BlockManager  # noqa: E402
from sensor.listeners.bait import BaitListeners  # noqa: E402
from sensor.listeners.common import payload_signature  # noqa: E402
from sensor.listeners.fwlog import FirewallLogReader, parse_line  # noqa: E402
from sensor.ml import ModelBundle, cic_row, unsw_row  # noqa: E402
from sensor.store import Store  # noqa: E402
from sensor.tools.simulate_probes import _check_target  # noqa: E402


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def base_config(tmp: Path, **overrides) -> dict:
    config = copy.deepcopy(cfgmod.load_config())
    config["db_path"] = str(tmp / "sensor.sqlite3")
    config["ml"]["enabled"] = False
    config["response"]["enforce"] = False
    for dotted, value in overrides.items():
        section, key = dotted.split(".", 1)
        config[section][key] = value
    cfgmod.validate_config(config)
    return config


class Collector:
    def __init__(self):
        self.events: list[Event] = []

    def __call__(self, event: Event):
        self.events.append(event)


def connection(src: str, port: int, *, payload: bool = False, ts: float | None = None,
               service: str = "-") -> Event:
    detail = {"had_payload": payload, "chunk_sizes": [10] if payload else [],
              "duration_s": 0.01, "bytes_in": 10 if payload else 0,
              "bytes_out": 30, "packets_in": 2, "packets_out": 2,
              "graceful": True, "reset": False, "http_requests": 0}
    return Event(kind=CONNECTION, src_ip=src, dst_port=port, service=service,
                 ts=ts or time.time(), detail=detail)


class TempSensor(unittest.TestCase):
    """Base class giving each test its own store, engine and fake firewall."""

    def setUp(self):
        # Keep tests hermetic and fast: no PowerShell or ipconfig calls.
        for target, value in (
            ("sensor.netinfo.default_gateways", set()),
            ("sensor.netinfo.local_addresses", {"127.0.0.1"}),
        ):
            patcher = mock.patch(target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.config = base_config(self.tmp)
        self.store = Store(self.tmp / "sensor.sqlite3")
        self.models = ModelBundle(self.config)
        self.decoys = DecoyPolicy(self.store)
        self.firewall_calls: list[list[str]] = []

        def fake_runner(args):
            self.firewall_calls.append(args)
            return 0, "OK"

        self.blocker = BlockManager(
            self.config, self.store, runner=fake_runner,
            admin_check=lambda: True, protected_extra={"192.168.1.1"},
        )
        self.blocker.start()
        self.engine = DetectionEngine(self.config, self.store, self.models,
                                      self.decoys, self.blocker)

    def tearDown(self):
        self.blocker.stop()
        self.store.close()
        self._tmp.cleanup()

    def observe(self, *events: Event):
        findings = []
        for event in events:
            finding = self.engine.observe(event)
            if finding:
                findings.append(finding)
        return findings


class ConfigTests(unittest.TestCase):
    def test_default_config_validates(self):
        cfgmod.validate_config(cfgmod.load_config())

    def test_duplicate_port_is_rejected(self):
        config = cfgmod.load_config()
        config["decoys"]["bait"]["services"]["2222"] = "ftp"
        with self.assertRaises(ValueError):
            cfgmod.validate_config(config)

    def test_admin_console_must_be_loopback(self):
        config = cfgmod.load_config()
        config["admin"]["host"] = "0.0.0.0"
        with self.assertRaises(ValueError):
            cfgmod.validate_config(config)

    def test_scanner_refuses_remote_targets_without_flag(self):
        with self.assertRaises(SystemExit):
            _check_target("203.0.113.5", allow_remote=False)
        _check_target("127.0.0.1", allow_remote=False)


class StoreTests(TempSensor):
    def test_events_findings_and_sources_round_trip(self):
        self.store.insert_event(connection("198.51.100.4", 21))
        self.store.insert_finding({
            "ts": time.time(), "src_ip": "198.51.100.4",
            "classification": "PORT_SCAN", "severity": "MEDIUM", "score": 50,
            "rule_points": 46, "ml_points": 4, "reasons": ["x"],
            "evidence": {}, "decision": {},
        })
        rows = self.store.recent_events(limit=5, src_ip="198.51.100.4")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["dst_port"], 21)
        findings = self.store.recent_findings(limit=5)
        self.assertEqual(findings[0]["classification"], "PORT_SCAN")
        sources = self.store.source_summary()
        self.assertEqual(sources[0]["top_classification"], "PORT_SCAN")


class EngineRuleTests(TempSensor):
    def test_port_scan_across_bait_ports_is_detected(self):
        now = time.time()
        events = [connection("203.0.113.9", port, ts=now - 5 + i)
                  for i, port in enumerate([21, 23, 25, 110, 1433])]
        findings = self.observe(*events)
        self.assertTrue(any(f["classification"] == "PORT_SCAN" for f in findings))
        scan = next(f for f in findings if f["classification"] == "PORT_SCAN")
        # The finding fires at the fourth port; the fifth is suppressed by cooldown.
        self.assertGreaterEqual(len(scan["evidence"]["PORT_SCAN"]["ports"]), 4)

    def test_single_probe_is_not_a_finding(self):
        self.assertEqual(self.observe(connection("203.0.113.10", 21)), [])

    def test_ordinary_visitor_is_not_flagged(self):
        event = Event(kind=HTTP, src_ip="198.51.100.20", dst_port=8080, service="http",
                      detail={"method": "GET", "path": "/", "raw": "GET / HTTP/1.1"})
        self.assertEqual(self.observe(event), [])

    def test_ssh_brute_force_is_high_severity_and_dry_run_blocked(self):
        events = [
            Event(kind=SSH_AUTH, src_ip="198.51.100.30", dst_port=None, service="ssh",
                  detail={"username": f"user{i % 4}", "method": "password",
                          "secret_preview": "x", "attempt": i, "raw": f"u\np{i}"})
            for i in range(20)
        ]
        findings = self.observe(*events)
        high = [f for f in findings if f["severity"] == "HIGH"]
        self.assertTrue(high, "20 attempts should reach HIGH severity")
        self.assertEqual(high[0]["classification"], "SSH_BRUTE_FORCE")
        block = high[0]["decision"]["block"]
        self.assertEqual(block["action"], "block")
        self.blocker.wait_idle()
        self.assertEqual(self.store.get_block(block["block_id"])["status"], "DRY_RUN")
        self.assertEqual(self.firewall_calls, [], "dry-run must not call netsh")

    def test_honeytoken_reuse_is_detected(self):
        self.store.add_honeytoken("198.51.100.40", "aws_access_key", "AKIATESTTOKEN0000XYZ")
        event = Event(kind=HTTP, src_ip="198.51.100.41", dst_port=8080, service="http",
                      detail={"method": "GET", "path": "/api",
                              "raw": "GET /api HTTP/1.1\nAuthorization: AKIATESTTOKEN0000XYZ"})
        findings = self.observe(event)
        self.assertTrue(any(f["classification"] == "HONEYTOKEN_REUSE" for f in findings))
        reuse = next(f for f in findings if f["classification"] == "HONEYTOKEN_REUSE")
        self.assertEqual(reuse["severity"], "HIGH")

    def test_sensitive_http_paths_are_probing(self):
        paths = ["/", "/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/backup.sql"]
        events = [Event(kind=HTTP, src_ip="203.0.113.50", dst_port=8080, service="http",
                        detail={"method": "GET", "path": p, "raw": ""}) for p in paths]
        findings = self.observe(*events)
        self.assertTrue(any(f["classification"] == "HTTP_ENDPOINT_PROBING" for f in findings))

    def test_banner_fingerprints_are_enumeration(self):
        event = connection("203.0.113.60", 6379, payload=True, service="redis")
        event.detail["signature"] = "http_verb"
        events = [event] + [connection("203.0.113.60", 9200 + i) for i in range(3)]
        findings = self.observe(*events)
        self.assertTrue(any(f["classification"] == "BANNER_ENUMERATION" for f in findings))

    def test_icmp_sweep_is_host_discovery(self):
        events = [Event(kind=FW_DROP, src_ip="203.0.113.70", dst_port=None, service="-",
                        detail={"protocol": "ICMP", "icmp_type": 8}) for _ in range(4)]
        findings = self.observe(*events)
        self.assertTrue(any(f["classification"] == "HOST_DISCOVERY" for f in findings))

    def test_repeated_same_finding_is_suppressed_by_cooldown(self):
        now = time.time()
        first = self.observe(*[connection("203.0.113.80", p, ts=now - 10 + i)
                               for i, p in enumerate([21, 23, 25, 110])])
        second = self.observe(connection("203.0.113.80", 1433, ts=now - 1))
        self.assertTrue(first)
        self.assertEqual(second, [], "same class within cooldown and severity should not repeat")

    def test_loopback_is_never_auto_blocked(self):
        self.config["response"]["enforce"] = True  # even with enforcement on
        decision = self.blocker.consider({
            "src_ip": "127.0.0.1", "classification": "PORT_SCAN", "score": 95,
        })
        self.assertEqual(decision["action"], "skipped")
        self.assertIn("loopback", decision["reason"])


class DeceptionTests(TempSensor):
    def test_persona_changes_are_one_way_for_engaged_attackers(self):
        ssh_finding = {"src_ip": "198.51.100.90", "classification": "SSH_BRUTE_FORCE",
                       "severity": "HIGH"}
        first = self.decoys.on_finding(ssh_finding, prior_findings=1)
        self.assertEqual(first["persona"], "legacy_linux")
        web_finding = {"src_ip": "198.51.100.90", "classification": "HTTP_ENDPOINT_PROBING",
                       "severity": "MEDIUM"}
        second = self.decoys.on_finding(web_finding, prior_findings=2)
        self.assertEqual(second["persona"], "legacy_linux")

    def test_adaptation_is_recorded_with_reason(self):
        self.decoys.on_finding({"src_ip": "198.51.100.91", "classification": "SSH_BRUTE_FORCE",
                                "severity": "HIGH"}, prior_findings=1)
        latest = self.store.latest_decoy_action("198.51.100.91")
        self.assertEqual(latest["persona"], "legacy_linux")
        self.assertIn("SSH_BRUTE_FORCE", latest["reason"])

    def test_env_file_serves_stable_honeytokens(self):
        first = self.decoys.http_response("GET", "/.env", "198.51.100.92")
        second = self.decoys.http_response("GET", "/.env", "198.51.100.92")
        self.assertEqual(first["status"], 200)
        key_line = [l for l in first["body"].splitlines() if l.startswith("AWS_ACCESS_KEY_ID=")][0]
        self.assertEqual(key_line, [l for l in second["body"].splitlines()
                                    if l.startswith("AWS_ACCESS_KEY_ID=")][0])
        issued = self.store.honeytoken_for_ip("198.51.100.92", "aws_access_key")
        self.assertEqual(key_line.split("=", 1)[1], issued)

    def test_root_serves_login_page(self):
        root = self.decoys.http_response("GET", "/", "198.51.100.95")
        self.assertEqual(root["status"], 200)
        self.assertIn("Sign in", root["body"])

    def test_login_post_fails_and_unknown_paths_404(self):
        login = self.decoys.http_response("POST", "/wp-login.php", "198.51.100.93", "log=a&pwd=b")
        self.assertIn("ERROR", login["body"])
        missing = self.decoys.http_response("GET", "/no/such/page", "198.51.100.93")
        self.assertEqual(missing["status"], 404)

    def test_banners_come_from_persona(self):
        banner = self.decoys.service_banner("ftp", "198.51.100.94")
        self.assertTrue(banner.startswith(b"220"))
        self.assertIsNone(self.decoys.service_banner("mongodb", "198.51.100.94"))
        self.assertIn("ubuntu_web", PERSONAS)


class FirewallTests(TempSensor):
    def test_dry_run_never_calls_netsh(self):
        row = self.blocker.block("203.0.113.120", "test", source="operator")
        self.blocker.wait_idle()
        self.assertEqual(self.store.get_block(row["id"])["status"], "DRY_RUN")
        self.assertEqual(self.firewall_calls, [])

    def test_enforce_creates_and_removes_rule(self):
        self.config["response"]["enforce"] = True
        manager = BlockManager(self.config, self.store,
                               runner=lambda args: (self.firewall_calls.append(args) or (0, "OK")),
                               admin_check=lambda: True, protected_extra=set())
        manager.start()
        try:
            row = manager.block("203.0.113.121", "test", source="operator")
            manager.wait_idle()
            self.assertEqual(self.store.get_block(row["id"])["status"], "ACTIVE")
            add = next(c for c in self.firewall_calls if "add" in c)
            self.assertIn("remoteip=203.0.113.121", add)
            self.assertIn("action=block", add)

            manager.unblock("203.0.113.121", source="operator")
            manager.wait_idle()
            self.assertEqual(self.store.get_block(row["id"])["status"], "RELEASED")
            self.assertTrue(any("delete" in c for c in self.firewall_calls))
        finally:
            manager.stop()

    def test_enforce_failure_is_recorded(self):
        self.config["response"]["enforce"] = True
        manager = BlockManager(self.config, self.store,
                               runner=lambda args: (1, "The requested operation requires elevation."),
                               admin_check=lambda: False, protected_extra=set())
        manager.start()
        try:
            row = manager.block("203.0.113.122", "test", source="operator")
            manager.wait_idle()
            stored = self.store.get_block(row["id"])
            self.assertEqual(stored["status"], "FAILED")
            self.assertIn("elevation", stored["error"])
        finally:
            manager.stop()

    def test_protected_addresses_are_refused(self):
        for ip in ["127.0.0.1", "192.168.1.1", "0.0.0.0", "224.0.0.1"]:
            with self.assertRaises(BlockError, msg=ip):
                self.blocker.block(ip, "should not happen")

    def test_invalid_ip_is_refused(self):
        with self.assertRaises(BlockError):
            self.blocker.block("not-an-ip", "x")

    def test_allowlisted_network_is_refused(self):
        self.config["response"]["allowlist"].append("198.18.0.0/15")
        manager = BlockManager(self.config, self.store, runner=lambda a: (0, ""),
                               admin_check=lambda: True, protected_extra=set())
        with self.assertRaises(BlockError):
            manager.block("198.18.5.5", "x")

    def test_expired_blocks_are_released(self):
        row = self.blocker.block("203.0.113.123", "short", source="operator", ttl_minutes=1)
        self.blocker.wait_idle()
        released = self.blocker.expire_due(now=time.time() + 3600)
        self.blocker.wait_idle()
        self.assertEqual(released, ["203.0.113.123"])
        self.assertIsNotNone(self.store.get_block(row["id"])["released"])

    def test_max_active_blocks_is_enforced(self):
        self.config["response"]["max_active_blocks"] = 1
        manager = BlockManager(self.config, self.store, runner=lambda a: (0, ""),
                               admin_check=lambda: True, protected_extra=set())
        manager.block("203.0.113.124", "one")
        with self.assertRaises(BlockError):
            manager.block("203.0.113.125", "two")


class ParserAndLogTests(unittest.TestCase):
    def test_parse_tcp_drop(self):
        line = ("2026-10-24 10:01:02 DROP TCP 203.0.113.9 192.168.1.20 "
                "51000 3389 60 S 1 0 64240 - - - SEND")
        parsed = parse_line(line)
        self.assertEqual(parsed["dst_port"], 3389)
        self.assertEqual(parsed["src_ip"], "203.0.113.9")

    def test_parse_icmp_echo_drop(self):
        line = "2026-10-24 10:01:03 DROP ICMP 203.0.113.9 192.168.1.20 - - 60 - - - - 8 0 - SEND"
        parsed = parse_line(line)
        self.assertEqual(parsed["detail"]["icmp_type"], 8)
        self.assertIsNone(parsed["dst_port"])

    def test_allow_and_comment_lines_are_ignored(self):
        self.assertIsNone(parse_line("#Version: 1.5"))
        self.assertIsNone(parse_line("2026-10-24 10:01:02 ALLOW TCP 1.2.3.4 5.6.7.8 1 80 60"))

    def test_log_reader_emits_only_new_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pfirewall.log"
            path.write_text("#Version: 1.5\n", encoding="utf-8")
            collected = Collector()
            reader = FirewallLogReader(path, collected, own_addresses=set(), poll_s=1)
            reader.poll_once()
            with path.open("a", encoding="utf-8") as handle:
                handle.write("2026-10-24 10:05:00 DROP TCP 203.0.113.9 192.168.1.20 "
                             "1 22 60 S 1 0 0 - - - SEND\n")
            self.assertEqual(reader.poll_once(), 1)
            self.assertEqual(collected.events[0].kind, FW_DROP)


class MLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = ModelBundle(cfgmod.load_config())

    def test_both_models_load(self):
        self.assertEqual(self.bundle.errors, {})
        self.assertIsNotNone(self.bundle.cic)
        self.assertIsNotNone(self.bundle.unsw)
        self.assertEqual(len(self.bundle.cic_features), 78)
        self.assertEqual(len(self.bundle.unsw_features), 42)

    def test_predictions_are_probabilities(self):
        flow = {"src_ip": "203.0.113.5", "dst_port": 21, "service": "ftp", "ts": time.time(),
                "duration_s": 0.0002, "bytes_in": 0, "bytes_out": 40, "packets_in": 1,
                "packets_out": 2, "chunk_sizes": [], "had_payload": False,
                "graceful": False, "reset": False, "http_requests": 0}
        result = self.bundle.predict(flow, recent=[])
        for key in ("cic_portscan", "unsw_recon"):
            self.assertGreaterEqual(result[key], 0.0)
            self.assertLessEqual(result[key], 1.0)
        self.assertGreater(result["cic_feature_coverage"], 0.0)
        self.assertLess(result["cic_feature_coverage"], 1.0)

    def test_feature_rows_cover_schema_names(self):
        flow = {"dst_port": 80, "duration_s": 1.0, "packets_in": 3, "packets_out": 3,
                "bytes_in": 200, "bytes_out": 400, "chunk_sizes": [100, 100]}
        row = cic_row(flow, self.bundle.cic_features)
        self.assertEqual(list(row), self.bundle.cic_features)
        ctx = {"ct_srv_src": 1, "ct_src_ltm": 1, "ct_dst_ltm": 1, "ct_dst_src_ltm": 1,
               "ct_src_dport_ltm": 1, "ct_dst_sport_ltm": 1, "ct_srv_dst": 1,
               "ct_flw_http_mthd": 0}
        self.assertEqual(len(unsw_row(flow, ctx, self.bundle.unsw_features)), 42)

    def test_combined_points_stay_within_weights(self):
        points = self.bundle.combined_points({"cic_portscan": 1.0, "unsw_recon": 1.0})
        self.assertLessEqual(points, self.bundle.cic_weight + self.bundle.unsw_weight)


class SignatureTests(unittest.TestCase):
    def test_protocol_fingerprints(self):
        self.assertEqual(payload_signature(b"GET / HTTP/1.1\r\n"), "http_verb")
        self.assertEqual(payload_signature(b"SSH-2.0-libssh"), "ssh_banner")
        self.assertEqual(payload_signature(b"\x16\x03\x01\x00"), "tls_clienthello")
        self.assertEqual(payload_signature(b"\r\n"), "empty_line")
        self.assertIsNone(payload_signature(b"hello"))


class BaitIntegrationTests(TempSensor):
    def test_banner_grab_is_recorded(self):
        port = free_port()
        config = base_config(self.tmp)
        config["decoys"]["bait"]["services"] = {str(port): "ftp"}
        config["decoys"]["bait"]["read_timeout_s"] = 1
        collected = Collector()
        decoys = DecoyPolicy(self.store)

        async def scenario():
            bait = BaitListeners(config, "127.0.0.1", collected, decoys)
            await bait.start()
            assert bait.status[port]["state"] == "listening", bait.status
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            greeting = await asyncio.wait_for(reader.readline(), 3)
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0.3)
            await bait.stop()
            return greeting

        greeting = asyncio.run(scenario())
        self.assertTrue(greeting.startswith(b"220"))
        self.assertTrue(collected.events, "connection should be recorded")
        event = collected.events[-1]
        self.assertEqual(event.kind, CONNECTION)
        self.assertEqual(event.dst_port, port)
        self.assertFalse(event.detail["had_payload"])

    def test_probe_payload_is_fingerprinted(self):
        port = free_port()
        config = base_config(self.tmp)
        config["decoys"]["bait"]["services"] = {str(port): "redis"}
        config["decoys"]["bait"]["read_timeout_s"] = 2
        collected = Collector()

        async def scenario():
            bait = BaitListeners(config, "127.0.0.1", collected, DecoyPolicy(self.store))
            await bait.start()
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            await writer.drain()
            reply = await asyncio.wait_for(reader.read(200), 3)
            writer.close()
            await asyncio.sleep(0.3)
            await bait.stop()
            return reply

        reply = asyncio.run(scenario())
        self.assertIn(b"NOAUTH", reply)
        self.assertEqual(collected.events[-1].detail["signature"], "http_verb")


class SSHIntegrationTests(TempSensor):
    def test_ssh_decoy_records_auth_attempts_and_never_grants_access(self):
        import paramiko
        from sensor.listeners.ssh import SSHDecoy

        port = free_port()
        config = base_config(self.tmp)
        config["decoys"]["ssh"]["port"] = port
        config["decoys"]["ssh"]["session_timeout_s"] = 20
        collected = Collector()
        decoy = SSHDecoy(config, "127.0.0.1", self.tmp / "host_key", collected,
                         DecoyPolicy(self.store))
        decoy.start()
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            with self.assertRaises(paramiko.AuthenticationException):
                client.connect("127.0.0.1", port=port, username="root",
                               password="toor", allow_agent=False, look_for_keys=False,
                               timeout=5)
            remote_version = client.get_transport() and client.get_transport().remote_version
            client.close()
        finally:
            time.sleep(0.5)
            decoy.stop()

        attempts = [e for e in collected.events if e.kind == SSH_AUTH]
        self.assertTrue(attempts, "password attempt should be recorded")
        self.assertEqual(attempts[0].detail["username"], "root")
        self.assertEqual(attempts[0].detail["secret_preview"], "toor")
        self.assertTrue(remote_version is None or remote_version.startswith("SSH-"))
        self.assertTrue((self.tmp / "host_key").exists())

    def test_ssh_banner_matches_persona(self):
        import paramiko
        from sensor.listeners.ssh import SSHDecoy

        port = free_port()
        config = base_config(self.tmp)
        config["decoys"]["ssh"]["port"] = port
        collected = Collector()
        decoy = SSHDecoy(config, "127.0.0.1", self.tmp / "host_key2", collected,
                         DecoyPolicy(self.store))
        decoy.start()
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=5)
            sock.sendall(b"SSH-2.0-probe\r\n")
            data = sock.recv(256)
            sock.close()
        finally:
            time.sleep(0.3)
            decoy.stop()
        self.assertTrue(data.startswith(PERSONAS["ubuntu_web"]["ssh_banner"].encode()))
        self.assertTrue(paramiko)


class HTTPDecoyTests(TempSensor):
    def test_decoy_serves_fake_env_and_logs_request(self):
        from starlette.testclient import TestClient
        from sensor.listeners.http_decoy import build_app

        collected = Collector()
        app = build_app(self.config, collected, self.decoys)
        client = TestClient(app, client=("198.51.100.200", 50000))
        response = client.get("/.env")
        self.assertEqual(response.status_code, 200)
        self.assertIn("AWS_ACCESS_KEY_ID=AKIA", response.text)
        self.assertEqual(response.headers["server"], PERSONAS["ubuntu_web"]["http_server"])

        login = client.post("/login", data={"username": "admin", "password": "hunter2"})
        self.assertEqual(login.status_code, 401)

        kinds = [e.kind for e in collected.events]
        self.assertIn(HTTP, kinds)
        self.assertIn(CONNECTION, kinds)
        http_events = [e for e in collected.events if e.kind == HTTP]
        self.assertEqual(http_events[0].detail["path"], "/.env")
        self.assertEqual(http_events[0].src_ip, "198.51.100.200")


class IntelTests(TempSensor):
    """Campaign linking, indicator export and redaction."""

    def _auth(self, ip, user, password, ts=None):
        return {"ts": ts or time.time(), "kind": "ssh_auth", "src_ip": ip, "dst_port": None,
                "service": "ssh", "detail": {"username": user, "method": "password",
                                              "secret_preview": password}}

    def _http(self, ip, agent, path="/", ts=None, honeytoken=None):
        detail = {"path": path, "user_agent": agent}
        if honeytoken:
            detail["honeytoken_hits"] = [{"token_sha256": honeytoken, "token_prefix": "AKIA",
                                          "issued_to": "x"}]
        return {"ts": ts or time.time(), "kind": "http_request", "src_ip": ip, "dst_port": 8080,
                "service": "http", "detail": detail}

    def test_shared_password_links_sources_into_one_campaign(self):
        from sensor import intel
        now = time.time()
        rows = [self._auth("198.51.100.1", "root", "Winter2024!", now),
                self._auth("198.51.100.2", "admin", "Winter2024!", now),
                self._auth("198.51.100.3", "guest", "other", now)]
        report_profiles = intel.build_profiles(rows, [])
        edges = intel.link_profiles(report_profiles)
        campaigns, unclustered = intel.build_campaigns(report_profiles, edges)
        self.assertEqual(len(campaigns), 1)
        self.assertEqual(campaigns[0]["members"], ["198.51.100.1", "198.51.100.2"])
        self.assertTrue(any(r["reason"].startswith("same password hash")
                            for r in campaigns[0]["reasons"]))
        self.assertIn("198.51.100.3", unclustered)

    def test_shared_honeytoken_is_a_strong_link(self):
        from sensor import intel
        rows = [self._http("198.51.100.10", "curl", honeytoken="abc123"),
                self._http("198.51.100.11", "wget", honeytoken="abc123")]
        profiles = intel.build_profiles(rows, [])
        campaigns, _ = intel.build_campaigns(profiles, intel.link_profiles(profiles))
        self.assertEqual(campaigns[0]["honeytoken_count"], 1)
        self.assertTrue(any("reused honeytoken" in r["reason"] for r in campaigns[0]["reasons"]))

    def test_generic_user_agent_is_not_used_for_linking(self):
        from sensor import intel
        rows = [self._http(f"198.51.100.{20 + i}", "python-requests/2.31") for i in range(12)]
        profiles = intel.build_profiles(rows, [])
        campaigns, unclustered = intel.build_campaigns(profiles, intel.link_profiles(profiles))
        self.assertEqual(campaigns, [])
        self.assertEqual(len(unclustered), 12)

    def test_unusual_user_agent_links_two_sources(self):
        from sensor import intel
        rows = [self._http("198.51.100.40", "rare-scanner/0.9"),
                self._http("198.51.100.41", "rare-scanner/0.9")]
        profiles = intel.build_profiles(rows, [])
        campaigns, _ = intel.build_campaigns(profiles, intel.link_profiles(profiles))
        self.assertEqual(len(campaigns), 1)

    def test_exports_never_contain_raw_passwords(self):
        from sensor import intel
        secret = "Hunter2-very-secret"
        now = time.time()
        self.store.insert_event(Event(kind=SSH_AUTH, src_ip="198.51.100.50", dst_port=None,
                                      service="ssh", ts=now,
                                      detail={"username": "root", "method": "password",
                                              "secret_preview": secret}))
        self.store.insert_event(Event(kind=SSH_AUTH, src_ip="198.51.100.51", dst_port=None,
                                      service="ssh", ts=now,
                                      detail={"username": "root", "method": "password",
                                              "secret_preview": secret}))
        report = intel.build_report(self.store, days=1)
        csv_text = intel.indicators_csv(report["indicators"])
        import json
        self.assertNotIn(secret, csv_text)
        self.assertNotIn(secret, json.dumps(report, default=str))
        self.assertTrue(any(r["type"] == "password_sha256" for r in report["indicators"]))
        self.assertTrue(csv_text.splitlines()[0].startswith("type,value,first_seen"))

    def test_window_excludes_old_activity(self):
        from sensor import intel
        old = time.time() - 40 * 86400
        self.store.insert_event(Event(kind=SSH_AUTH, src_ip="198.51.100.60", dst_port=None,
                                      service="ssh", ts=old,
                                      detail={"username": "root", "method": "none"}))
        report = intel.build_report(self.store, days=7)
        self.assertEqual(report["sources"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
