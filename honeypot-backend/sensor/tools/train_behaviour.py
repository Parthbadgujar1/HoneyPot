"""Train the behaviour model on this sensor's own event format.

    python -m sensor.tools.train_behaviour                 # lab scenarios only
    python -m sensor.tools.train_behaviour --db sensor/data/sensor.sqlite3
    python -m sensor.tools.train_behaviour --compare-rules --metrics out.json

Training data comes from two places, both with known labels:

* **Lab scenarios** (``--lab-sessions``): randomised attacker and benign
  sessions written as the same ``Event`` records the listeners emit. The
  label is the scenario that generated the session, so it is ground truth for
  the lab, not a copy of the rule engine. Slow scans and slow password
  guessing are included on purpose: they stay under the rule windows and are
  what the model is for.
* **Operator labels** (``--db``): sources an operator labelled in the console
  (``POST /api/sources/{ip}/label``). Their stored events are used as is.

Each session also contributes prefixes (its first 2, 4, 8 ... events) with the
same label, so the model learns to recognise an attack before it is over.
Cross-validation groups prefixes by session, so a session is never in both
the training and the test fold.

Lab data shows whether the features separate the families. It is not field
data; retrain with labelled real sessions as they accumulate.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

from .. import behaviour
from ..config import load_config, sensor_path
from ..events import CONNECTION, HTTP, SSH_AUTH, Event
from ..webattacks import classify_request

PREFIXES = (2, 4, 8, 16, 32)
SESSION_GAP_S = 900

NORMAL_PATHS = ["/", "/favicon.ico", "/robots.txt", "/login", "/about", "/index.html"]
PROBE_PATHS = ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/admin", "/backup.zip",
               "/config.php", "/api/v1/users", "/server-status", "/actuator/health", "/cgi-bin/test",
               "/.aws/credentials", "/db.sql", "/xmlrpc.php", "/console"]
ATTACK_QUERIES = ["id=1' OR '1'='1", "id=1 UNION SELECT user,pass FROM users", "q=<script>alert(1)</script>",
                  "file=../../../../etc/passwd", "host=127.0.0.1;cat /etc/passwd", "id=1 AND sleep(5)",
                  "url=http://169.254.169.254/latest/meta-data", "page=<img src=x onerror=alert(1)>"]
USERNAMES = ["root", "admin", "ubuntu", "test", "oracle", "pi", "user", "git", "postgres", "support"]
SERVICE_PORTS = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 110: "pop3", 1433: "mssql",
                 2222: "ssh", 3306: "mysql", 6379: "redis", 8080: "http", 9200: "elasticsearch",
                 27017: "mongodb"}


class _Session:
    def __init__(self, rng: random.Random, ip: str):
        self.rng, self.ip = rng, ip
        self.t = rng.uniform(0, 86400)
        self.events: list[Event] = []

    def wait(self, low: float, high: float) -> None:
        self.t += self.rng.uniform(low, high)

    def connect(self, port: int, payload: bool = False) -> None:
        self.events.append(Event(CONNECTION, self.ip, port, SERVICE_PORTS.get(port, "-"), self.t,
                                 {"had_payload": payload}))

    def http(self, path: str, query: str = "", status: int | None = None, body: str = "") -> None:
        status = status or (200 if path in NORMAL_PATHS else 404)
        self.events.append(Event(HTTP, self.ip, 8080, "http", self.t, {
            "method": "POST" if body else "GET", "path": path, "query": query, "status": status,
            "user_agent": "lab", "web_attacks": classify_request(path, query, body)}))

    def ssh(self, username: str, token: bool = False) -> None:
        detail = {"username": username, "method": "password"}
        if token:
            detail["honeytoken_hits"] = [{"token_prefix": "AKIA", "issued_to": "lab"}]
        self.events.append(Event(SSH_AUTH, self.ip, 2222, "ssh", self.t, detail))


def _benign(s: _Session) -> None:
    kind = s.rng.random()
    if kind < 0.5:  # someone opening the web page
        for path in s.rng.sample(NORMAL_PATHS, s.rng.randint(1, 4)):
            s.http(path)
            s.wait(1, 40)
    elif kind < 0.75:  # one client talking to one service
        port = s.rng.choice([25, 110, 21, 8080])
        for _ in range(s.rng.randint(1, 2)):
            s.connect(port, payload=True)
            s.wait(5, 120)
    else:  # a mistyped login or two
        user = s.rng.choice(USERNAMES)
        for _ in range(s.rng.randint(1, 2)):
            s.ssh(user)
            s.wait(3, 30)
        if s.rng.random() < 0.5:
            s.http("/login", status=200)


def _recon(s: _Session) -> None:
    ports = list(SERVICE_PORTS) + [s.rng.randint(1024, 65535) for _ in range(40)]
    style = s.rng.random()
    if style < 0.45:  # fast scan
        for port in s.rng.sample(ports, s.rng.randint(5, 45)):
            s.connect(port)
            s.wait(0.002, 0.3)
    elif style < 0.8:  # slow scan, below the rule windows
        for port in s.rng.sample(ports, s.rng.randint(3, 9)):
            s.connect(port)
            s.wait(25, 180)
    else:  # banner grabbing
        for port in s.rng.sample(list(SERVICE_PORTS), s.rng.randint(3, 7)):
            s.connect(port, payload=s.rng.random() < 0.3)
            s.wait(0.5, 20)


def _credential(s: _Session) -> None:
    users = s.rng.sample(USERNAMES, s.rng.randint(1, 6))
    slow = s.rng.random() < 0.4
    if s.rng.random() < 0.75:
        for _ in range(s.rng.randint(3, 40)):
            s.ssh(s.rng.choice(users))
            s.wait(20, 120) if slow else s.wait(0.3, 4)
    else:  # web login stuffing
        page = s.rng.choice(["/login", "/wp-login.php"])
        for _ in range(s.rng.randint(4, 30)):
            s.http(page, status=200, body=f"log={s.rng.choice(users)}&pwd=<redacted>")
            s.wait(15, 90) if slow else s.wait(0.3, 3)


def _web(s: _Session) -> None:
    for _ in range(s.rng.randint(2, 30)):
        roll = s.rng.random()
        if roll < 0.45:
            s.http(s.rng.choice(["/item", "/search", "/download", "/ping", "/fetch"]),
                   s.rng.choice(ATTACK_QUERIES), status=s.rng.choice([200, 400, 500]))
        elif roll < 0.85:
            s.http(s.rng.choice(PROBE_PATHS))
        else:
            s.http(s.rng.choice(NORMAL_PATHS))
        s.wait(0.1, 8)


def _multi_stage(s: _Session) -> None:
    for port in s.rng.sample(list(SERVICE_PORTS), s.rng.randint(3, 8)):
        s.connect(port)
        s.wait(0.05, 5)
    s.wait(10, 300)
    for path in s.rng.sample(PROBE_PATHS, s.rng.randint(2, 6)):
        s.http(path, status=200 if path in ("/.env", "/.git/config") else 404)
        s.wait(1, 20)
    if s.rng.random() < 0.5:
        s.http("/item", s.rng.choice(ATTACK_QUERIES))
    s.wait(20, 400)
    for i in range(s.rng.randint(1, 6)):
        s.ssh(s.rng.choice(["admin", "svc-backup", "deploy"]), token=i == 0 or s.rng.random() < 0.3)
        s.wait(2, 30)


SCENARIOS = {"BENIGN": _benign, "RECON_SCAN": _recon, "CREDENTIAL_ATTACK": _credential,
             "WEB_ATTACK": _web, "MULTI_STAGE": _multi_stage}
# Benign visitors are the majority on a real network, attacks of each kind fewer.
MIX = {"BENIGN": 0.3, "RECON_SCAN": 0.2, "CREDENTIAL_ATTACK": 0.18, "WEB_ATTACK": 0.18,
       "MULTI_STAGE": 0.14}


def lab_sessions(count: int, seed: int) -> list[tuple[str, str, list[Event]]]:
    rng = random.Random(seed)
    names, weights = zip(*MIX.items())
    out = []
    for i in range(count):
        label = rng.choices(names, weights)[0]
        session = _Session(rng, f"10.{200 + i // 65025}.{(i // 255) % 255}.{i % 255 + 1}")
        SCENARIOS[label](session)
        out.append((label, f"lab-{i}", session.events))
    return out


def labelled_db_sessions(db: Path) -> list[tuple[str, str, list[Event]]]:
    from ..store import Store
    store = Store(db)
    try:
        out = []
        for ip, label in store.labels().items():
            if label not in behaviour.CLASSES:
                continue
            session: list[Event] = []
            for event in store.events_for(ip):
                if session and event.ts - session[-1].ts > SESSION_GAP_S:
                    out.append((label, f"{ip}#{len(out)}", session))
                    session = []
                session.append(event)
            if session:
                out.append((label, f"{ip}#{len(out)}", session))
        return out
    finally:
        store.close()


def samples_from(sessions) -> list[tuple[dict, str, str]]:
    samples = []
    for label, group, events in sessions:
        for k in PREFIXES:
            if k < len(events):
                samples.append((behaviour.features(events[:k]), label, group))
        samples.append((behaviour.features(events), label, group))
    return samples


def rule_engine_detects(sessions) -> list[bool]:
    """Whether the rule engine (no ML) raises any finding for each session."""
    import tempfile
    from unittest import mock

    from ..deception import DecoyPolicy
    from ..engine import DetectionEngine
    from ..firewall import BlockManager
    from ..ml import ModelBundle
    from ..store import Store

    import logging

    config = load_config()
    config["ml"]["enabled"] = False
    config["response"]["block_enabled"] = False
    detected = []
    logging.disable(logging.WARNING)
    with tempfile.TemporaryDirectory() as tmp, \
            mock.patch("sensor.netinfo.default_gateways", return_value=set()), \
            mock.patch("sensor.netinfo.local_addresses", return_value={"127.0.0.1"}):
        store = Store(Path(tmp) / "rules.sqlite3")
        engine = DetectionEngine(config, store, ModelBundle(config), DecoyPolicy(store),
                                 BlockManager(config, store, runner=lambda a: (0, "")))
        for _, _, events in sessions:
            hits = [engine.observe(Event(e.kind, e.src_ip, e.dst_port, e.service, e.ts,
                                         dict(e.detail))) for e in events]
            detected.append(any(hits))
        store.close()
    logging.disable(logging.NOTSET)
    return detected


def compare(sessions, seed: int) -> dict:
    """Session-level detection rate, rules versus the cross-validated model."""
    import numpy as np
    from sklearn.model_selection import GroupKFold, cross_val_predict
    from sklearn.ensemble import RandomForestClassifier

    samples = samples_from(sessions)
    X = np.array([behaviour.vector(f) for f, _, _ in samples])
    y = np.array([label for _, label, _ in samples])
    groups = np.array([g for _, _, g in samples])
    predicted = cross_val_predict(
        RandomForestClassifier(n_estimators=120, min_samples_leaf=2, class_weight="balanced",
                               random_state=seed, n_jobs=1),
        X, y, groups=groups, cv=GroupKFold(n_splits=5))
    # The last sample of each session is the full session.
    final = {}
    for (_, _, group), pred in zip(samples, predicted):
        final[group] = pred
    rules = rule_engine_detects(sessions)
    table: dict = {}
    for (label, group, _), rule_hit in zip(sessions, rules):
        row = table.setdefault(label, {"sessions": 0, "rules": 0, "model": 0})
        row["sessions"] += 1
        row["rules"] += int(rule_hit)
        row["model"] += int(final[group] != "BENIGN")
    for row in table.values():
        n = row["sessions"]
        row["rules_rate"] = round(row.pop("rules") / n, 3)
        row["model_rate"] = round(row.pop("model") / n, 3)
    return {"note": "share of sessions flagged as an attack (for BENIGN: false-positive rate)",
            "by_class": table}


def main(argv: list[str] | None = None) -> int:
    config = load_config()
    parser = argparse.ArgumentParser(description="Train the sensor behaviour model.")
    parser.add_argument("--lab-sessions", type=int, default=600)
    parser.add_argument("--db", type=Path, default=None,
                        help="sensor database with operator-labelled sources")
    parser.add_argument("--out", type=Path, default=sensor_path(config["ml"]["behaviour_model"]))
    parser.add_argument("--metrics", type=Path, default=None, help="also write metrics JSON here")
    parser.add_argument("--compare-rules", action="store_true",
                        help="measure rules vs model detection per class on the lab sessions")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args(argv)

    sessions = lab_sessions(args.lab_sessions, args.seed) if args.lab_sessions else []
    real = labelled_db_sessions(args.db) if args.db else []
    if not sessions and not real:
        print("No training data: give --lab-sessions or a --db with labelled sources.")
        return 1

    bundle = behaviour.train(samples_from(sessions + real), seed=args.seed)
    bundle["data"] = {"lab_sessions": len(sessions), "labelled_sessions": len(real),
                      "db": str(args.db) if args.db else None}
    behaviour.save(bundle, args.out)

    report = {"data": bundle["data"], "metrics": bundle["metrics"], "importance": bundle["importance"]}
    if args.compare_rules and sessions:
        report["rules_vs_model"] = compare(sessions, args.seed)
    m = bundle["metrics"]
    print(f"Saved {args.out}")
    print(f"Samples {m['samples']} from {m['groups']} sessions; CV {m['cv']}")
    if "macro_f1" in m:
        print(f"Accuracy {m['accuracy']}  macro-F1 {m['macro_f1']}  "
              f"benign false-positive rate {m.get('false_positive_rate')}")
        for name, row in m["per_class"].items():
            print(f"  {name:18} P={row['precision']:.3f} R={row['recall']:.3f} F1={row['f1-score']:.3f}")
    if "rules_vs_model" in report:
        print("Session detection rate (rules vs model):")
        for name, row in report["rules_vs_model"]["by_class"].items():
            print(f"  {name:18} rules={row['rules_rate']:.3f} model={row['model_rate']:.3f}")
    if args.metrics:
        args.metrics.parent.mkdir(parents=True, exist_ok=True)
        args.metrics.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
