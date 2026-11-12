"""Scenario evaluation of the complete detection engine for the project report.

Replays randomized attack and normal-use sessions through the real rule engine,
the real ML models, the deception policy and the block manager. Events have the
same fields the live listeners emit, and time is simulated, so slow attacks do
not take real hours. Everything uses a temporary database and dry-run blocking.
No socket is opened and no firewall rule is created.

    python evaluate_scenarios.py <project root> <output json> [trials]
"""

from __future__ import annotations

import copy
import json
import random
import statistics
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock

ROOT = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2])
TRIALS = int(sys.argv[3]) if len(sys.argv) > 3 else 100
sys.path.insert(0, str(ROOT / "honeypot-backend"))

from sensor import config as cfgmod  # noqa: E402
from sensor.deception import DecoyPolicy  # noqa: E402
from sensor.engine import DetectionEngine  # noqa: E402
from sensor.events import CONNECTION, FW_DROP, HTTP, SSH_AUTH, Event  # noqa: E402
from sensor.firewall import BlockManager  # noqa: E402
from sensor.ml import ModelBundle  # noqa: E402
from sensor.store import Store  # noqa: E402

SERVICES = {21: "ftp", 23: "telnet", 25: "smtp", 110: "pop3", 1433: "mssql", 6379: "redis",
            9200: "elasticsearch", 27017: "mongodb", 2222: "ssh", 8080: "http", 3306: "mysql"}
HTTP_PORT, SSH_PORT = 8080, 2222
SENSITIVE = ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/admin", "/backup.sql",
             "/actuator/health", "/api/v1/users", "/server-status", "/config", "/.aws/credentials"]
ORDINARY = ["/", "/login", "/home", "/robots.txt", "/favicon.ico", "/index.html", "/about",
            "/contact", "/help", "/news", "/products", "/team", "/faq", "/terms", "/privacy"]
USERS = ["root", "admin", "ubuntu", "pi", "oracle"]


def flow(rng, *, payload=False, signature=None, http_requests=0):
    size = rng.randint(20, 400) if payload else 0
    detail = {
        "duration_s": round(rng.uniform(0.002, 0.4), 6), "bytes_in": size,
        "bytes_out": rng.randint(20, 120), "packets_in": 2 if payload else 1, "packets_out": 2,
        "chunk_sizes": [size] if payload else [], "had_payload": payload, "graceful": True,
        "reset": False, "end_reason": "client_closed", "http_requests": http_requests,
    }
    if signature:
        detail["signature"] = signature
    return detail


def connect(rng, ip, port, ts, **kwargs):
    return Event(CONNECTION, ip, port, SERVICES.get(port, "-"), ts, flow(rng, **kwargs))


def web(rng, ip, path, ts, method="GET", body="", query=""):
    raw = f"{method} {path}?{query} HTTP/1.1\r\nuser-agent: scenario\r\n\r\n{body}"
    return [
        Event(HTTP, ip, HTTP_PORT, "http", ts, {"method": method, "path": path, "query": query,
              "body_preview": body, "status": 200, "user_agent": "scenario", "raw": raw}),
        connect(rng, ip, HTTP_PORT, ts, payload=True, http_requests=1),
    ]


def ssh(ip, user, secret, ts):
    return Event(SSH_AUTH, ip, SSH_PORT, "ssh", ts, {
        "username": user, "password": secret, "method": "password", "raw": f"{user}\n{secret}"})


def spaced(rng, count, low, high, start):
    clock = start
    for _ in range(count):
        yield clock
        clock += rng.uniform(low, high)


# Each generator returns the events of one session. `ctx` holds shared objects.

def fast_scan(rng, ip, t, ctx):
    ports = rng.sample(sorted(SERVICES), rng.randint(5, 11))
    return [connect(rng, ip, p, c) for p, c in zip(ports, spaced(rng, len(ports), 0.05, 3, t))]


def firewall_scan(rng, ip, t, ctx):
    count = rng.randint(20, 200)
    ports = rng.sample(range(1, 65535), count)
    return [Event(FW_DROP, ip, p, "-", c, {"protocol": "TCP", "action": "DROP"})
            for p, c in zip(ports, spaced(rng, count, 0.01, 0.5, t))]


def slow_banner(rng, ip, t, ctx):
    ports = rng.sample(sorted(SERVICES), rng.randint(3, 5))
    return [connect(rng, ip, p, c) for p, c in zip(ports, spaced(rng, len(ports), 30, 60, t))]


def fingerprint(rng, ip, t, ctx):
    count = rng.randint(1, 2)
    ports = rng.sample([21, 23, 25, 110, 6379], count)
    return [connect(rng, ip, p, c, payload=True,
                    signature=rng.choice(["http_verb", "tls_clienthello", "ssh_banner"]))
            for p, c in zip(ports, spaced(rng, count, 1, 10, t))]


def ping_sweep(rng, ip, t, ctx):
    count = rng.randint(3, 10)
    return [Event(FW_DROP, ip, None, "-", c, {"protocol": "ICMP", "action": "DROP", "icmp_type": 8})
            for c in spaced(rng, count, 0.5, 5, t)]


def web_probe(rng, ip, t, ctx):
    paths = rng.sample(SENSITIVE, rng.randint(4, 10))
    events = []
    for path, clock in zip(paths, spaced(rng, len(paths), 0.2, 3, t)):
        events += web(rng, ip, path, clock)
    return events


def brute_force(rng, ip, t, ctx):
    users = rng.sample(USERS, rng.randint(1, 5))
    count = rng.randint(5, 15)
    return [ssh(ip, rng.choice(users), f"pass{rng.randint(0, 9999)}", c)
            for c in spaced(rng, count, 1, 8, t)]


def honeytoken_reuse(rng, ip, t, ctx):
    ctx["decoys"].http_response("GET", "/.env", ip)
    token = ctx["store"].honeytoken_for_ip(ip, "aws_access_key")
    events = web(rng, ip, "/.env", t)
    if rng.random() < 0.5:
        events.append(ssh(ip, "admin", token, t + rng.uniform(5, 120)))
    else:
        events += web(rng, ip, "/login", t + rng.uniform(5, 120), "POST", f"key={token}")
    return events


def slow_scan(rng, ip, t, ctx):
    ports = rng.sample(sorted(SERVICES), rng.randint(3, 6))
    return [connect(rng, ip, p, c) for p, c in zip(ports, spaced(rng, len(ports), 200, 280, t))]


def slow_ssh(rng, ip, t, ctx):
    count = rng.randint(4, 8)
    return [ssh(ip, "root", f"pass{rng.randint(0, 9999)}", c) for c in spaced(rng, count, 35, 60, t)]


def single_sensitive(rng, ip, t, ctx):
    return web(rng, ip, rng.choice(SENSITIVE), t)


def visitor(rng, ip, t, ctx):
    paths = rng.sample(ORDINARY[:6], rng.randint(1, 4))
    events = []
    for path, clock in zip(paths, spaced(rng, len(paths), 3, 40, t)):
        events += web(rng, ip, path, clock)
    return events


def typing_errors(rng, ip, t, ctx):
    user = rng.choice(USERS)
    count = rng.randint(1, 3)
    return [ssh(ip, user, f"try{i}", c) for i, c in enumerate(spaced(rng, count, 5, 30, t))]


def health_check(rng, ip, t, ctx):
    port = rng.choice([8080, 6379, 9200])
    return [connect(rng, ip, port, c, payload=True) for c in spaced(rng, 10, 25, 35, t)]


def two_services(rng, ip, t, ctx):
    return [connect(rng, ip, SSH_PORT, t, payload=True),
            *web(rng, ip, "/", t + rng.uniform(5, 60))]


def long_browsing(rng, ip, t, ctx):
    paths = rng.sample(ORDINARY, rng.randint(6, 15))
    events = []
    for path, clock in zip(paths, spaced(rng, len(paths), 5, 15, t)):
        events += web(rng, ip, path, clock)
    return events


def uptime_monitor(rng, ip, t, ctx):
    ports = rng.sample(sorted(SERVICES), rng.randint(4, 6))
    return [connect(rng, ip, p, c, payload=True) for p, c in zip(ports, spaced(rng, len(ports), 0.5, 3, t))]


SQLI = ["id=1' OR '1'='1", "id=1 UNION SELECT user,pass FROM users", "q=x'; DROP TABLE users--",
        "id=1 AND SLEEP(5)", "id=-1 UNION ALL SELECT 1,2,information_schema.tables"]
XSS = ["q=<script>alert(1)</script>", "name=<img src=x onerror=alert(1)>", "u=javascript:alert(1)"]
CMDI = ["host=8.8.8.8;cat /etc/hosts", "ip=127.0.0.1|whoami", "d=$(id)", "x=`uname -a`"]
TRAV = ["file=../../../etc/passwd", "f=..%2f..%2f..%2fwindows/win.ini", "p=....//....//etc/shadow"]
SEARCH = ["q=union station timetable", "q=select a seat", "q=drop in clinic", "q=how to cat proof a house",
          "q=alert settings help", "q=sleep better tips", "q=1 or 2 people", "page=2&sort=price"]


def sql_injection(rng, ip, t, ctx):
    return web(rng, ip, rng.choice(["/item", "/product", "/user"]), t, query=rng.choice(SQLI))


def xss_attack(rng, ip, t, ctx):
    return web(rng, ip, "/search", t, query=rng.choice(XSS))


def cmd_injection(rng, ip, t, ctx):
    return web(rng, ip, "/ping", t, query=rng.choice(CMDI))


def traversal(rng, ip, t, ctx):
    return web(rng, ip, "/download", t, query=rng.choice(TRAV))


def keyword_search(rng, ip, t, ctx):
    events = []
    for q, clock in zip(rng.sample(SEARCH, rng.randint(2, 5)), spaced(rng, 5, 4, 30, t)):
        events += web(rng, ip, "/search", clock, query=q)
    return events


SCENARIOS = [
    ("attack", "TCP scan of decoy ports", fast_scan, ["PORT_SCAN"]),
    ("attack", "Wide scan seen in firewall log", firewall_scan, ["PORT_SCAN"]),
    ("attack", "Slow banner grabbing", slow_banner, ["BANNER_ENUMERATION", "SERVICE_DISCOVERY"]),
    ("attack", "Protocol fingerprint probe", fingerprint, ["BANNER_ENUMERATION"]),
    ("attack", "ICMP ping sweep", ping_sweep, ["HOST_DISCOVERY"]),
    ("attack", "Sensitive web path probing", web_probe, ["HTTP_ENDPOINT_PROBING"]),
    ("attack", "SSH password brute force", brute_force, ["SSH_BRUTE_FORCE"]),
    ("attack", "Honeytoken reuse", honeytoken_reuse, ["HONEYTOKEN_REUSE"]),
    ("attack", "SQL injection request", sql_injection, ["SQL_INJECTION"]),
    ("attack", "Cross-site scripting request", xss_attack, ["XSS"]),
    ("attack", "Command injection request", cmd_injection, ["COMMAND_INJECTION"]),
    ("attack", "Path traversal request", traversal, ["PATH_TRAVERSAL"]),
    ("evasive", "Slow scan (one port per 200-280 s)", slow_scan, ["PORT_SCAN", "SERVICE_DISCOVERY", "BANNER_ENUMERATION"]),
    ("evasive", "Slow SSH guessing (one try per 35-60 s)", slow_ssh, ["SSH_BRUTE_FORCE"]),
    ("evasive", "Single sensitive file request", single_sensitive, ["HTTP_ENDPOINT_PROBING"]),
    ("benign", "Ordinary web visitor", visitor, []),
    ("benign", "SSH login typing errors", typing_errors, []),
    ("benign", "Single-service health check", health_check, []),
    ("benign", "Administrator using two services", two_services, []),
    ("benign", "Long browsing session", long_browsing, []),
    ("benign", "Multi-port uptime monitor", uptime_monitor, []),
    ("benign", "Search text with SQL-like words", keyword_search, []),
]


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp, \
            mock.patch("sensor.netinfo.default_gateways", return_value=set()), \
            mock.patch("sensor.netinfo.local_addresses", return_value={"127.0.0.1"}):
        config = copy.deepcopy(cfgmod.load_config())
        config["db_path"] = str(Path(tmp) / "scenario.sqlite3")
        config["response"]["enforce"] = False
        config["response"]["max_active_blocks"] = 1_000_000
        config["firewall_log"]["enabled"] = True
        store = Store(Path(tmp) / "scenario.sqlite3")
        models = ModelBundle(config)
        decoys = DecoyPolicy(store)
        blocker = BlockManager(config, store, runner=lambda args: (0, "OK"),
                               admin_check=lambda: True)
        blocker.start()
        engine = DetectionEngine(config, store, models, decoys, blocker)
        ctx = {"store": store, "decoys": decoys}

        results, timings = [], []
        address = 0
        base_time = 1_800_000_000.0
        for group, name, generate, expected in SCENARIOS:
            rng = random.Random(f"honeypot-{name}")
            rows = []
            for _ in range(TRIALS):
                address += 1
                ip = f"10.{(address >> 16) & 255}.{(address >> 8) & 255}.{address & 255}"
                base_time += 5000
                events = sorted(generate(rng, ip, base_time, ctx), key=lambda e: e.ts)
                findings, first_index = [], None
                for index, event in enumerate(events, 1):
                    start = time.perf_counter()
                    finding = engine.observe(event)
                    timings.append((time.perf_counter() - start) * 1000)
                    if finding:
                        findings.append(finding)
                        first_index = first_index or index
                best = max(findings, key=lambda f: f["score"]) if findings else None
                rows.append({
                    "events": len(events),
                    "detected": bool(findings),
                    "correct": any(c in (f["techniques"] + [f["classification"]])
                                   for f in findings for c in expected),
                    "severity": best["severity"] if best else None,
                    "classification": best["classification"] if best else None,
                    "score": best["score"] if best else 0,
                    "rule_points": best["rule_points"] if best else 0,
                    "ml_points": best["ml_points"] if best else 0,
                    "first_index": first_index,
                    "seconds": (findings[0]["ts"] - events[0].ts) if findings else None,
                    "blocked": any(f["decision"]["block"].get("action") == "block" for f in findings),
                })
            detected = [r for r in rows if r["detected"]]
            summary = {
                "group": group, "scenario": name, "trials": len(rows),
                "mean_events": statistics.mean(r["events"] for r in rows),
                "detected": len(detected),
                "correct_class": sum(r["correct"] for r in rows),
                "low": sum(r["severity"] == "LOW" for r in rows),
                "medium": sum(r["severity"] == "MEDIUM" for r in rows),
                "high": sum(r["severity"] == "HIGH" for r in rows),
                "blocked": sum(r["blocked"] for r in rows),
                "mean_score": statistics.mean(r["score"] for r in detected) if detected else None,
                "mean_rule_points": statistics.mean(r["rule_points"] for r in detected) if detected else None,
                "mean_ml_points": statistics.mean(r["ml_points"] for r in detected) if detected else None,
                "mean_events_to_detect": statistics.mean(r["first_index"] for r in detected) if detected else None,
                "mean_seconds_to_detect": statistics.mean(r["seconds"] for r in detected) if detected else None,
                "top_classes": sorted({r["classification"] for r in detected}),
            }
            results.append(summary)
            print(f"{group:8} {name:42} detected {len(detected):3}/{len(rows)} "
                  f"H{summary['high']:3} M{summary['medium']:3} L{summary['low']:3} "
                  f"blocked {summary['blocked']:3} ml {summary['mean_ml_points']}", flush=True)
            blocker.wait_idle()

        blocker.stop()
        store.close()

    timings.sort()
    report = {
        "trials_per_scenario": TRIALS,
        "scenarios": results,
        "event_processing_ms": {
            "events": len(timings),
            "mean": statistics.mean(timings),
            "p50": timings[len(timings) // 2],
            "p95": timings[int(len(timings) * 0.95)],
            "p99": timings[int(len(timings) * 0.99)],
        },
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(report["event_processing_ms"])


if __name__ == "__main__":
    main()
