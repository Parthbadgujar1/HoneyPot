"""Detection engine: behavioural rules + ML scoring + adaptive response.

Every event from a listener passes through ``DetectionEngine.observe``:

1. The event is enriched (ML scores for measured connections, honeytoken
   reuse check for HTTP and SSH input) and stored.
2. Per-IP history is updated and the rules for reconnaissance classes are
   evaluated over sliding windows.
3. Rule points and ML points are combined into a score and severity.
4. A finding is created (subject to a per-IP cooldown), the decoy policy
   adapts, the block decision is taken and the finding is stored.

Rule classes
------------
PORT_SCAN              many distinct destination ports in a short window
SERVICE_DISCOVERY      probes across several well-known service ports
BANNER_ENUMERATION     connects that send nothing (banner grabs) or send
                       protocol fingerprints (HTTP verbs, SSH banners, TLS)
HOST_DISCOVERY         repeated ICMP echo requests seen by the firewall log
HTTP_ENDPOINT_PROBING  requests for known-sensitive or many distinct paths
SSH_BRUTE_FORCE        many SSH authentication attempts in a short window
HONEYTOKEN_REUSE       an attacker used a credential the decoy issued
"""

from __future__ import annotations

import hashlib
import logging
import threading
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field

from .deception import DecoyPolicy
from .events import CONNECTION, FW_DROP, HTTP, SSH_AUTH, Event
from .firewall import BlockManager
from .ml import ModelBundle
from .store import Store

log = logging.getLogger("sensor.engine")

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

# Fields copied from a connection event into the flow record used for ML.
FLOW_FIELDS = (
    "duration_s", "bytes_in", "bytes_out", "packets_in", "packets_out",
    "chunk_sizes", "had_payload", "graceful", "reset", "http_requests",
)

SUSPICIOUS_PATH_PREFIXES = (
    "/.env", "/.git", "/.aws", "/.ssh", "/.docker", "/.svn", "/.htaccess",
    "/wp-", "/xmlrpc.php", "/phpmyadmin", "/pma", "/admin", "/administrator",
    "/backup", "/dump", "/db.", "/config", "/actuator", "/server-status",
    "/cgi-bin", "/solr", "/jenkins", "/manager/html", "/console",
    "/api/v1/users", "/api/users",
)

ML_ONLY_MIN_POINTS = 25
ML_ONLY_MIN_FLOWS = 3


@dataclass
class Rule:
    name: str
    points: int
    reason: str
    evidence: dict = field(default_factory=dict)


def is_suspicious_path(path: str) -> bool:
    lowered = path.lower()
    return any(lowered.startswith(prefix) for prefix in SUSPICIOUS_PATH_PREFIXES)


class DetectionEngine:
    def __init__(
        self,
        config: dict,
        store: Store,
        models: ModelBundle,
        decoys: DecoyPolicy,
        blocker: BlockManager,
    ):
        self.thresholds = config["detection"]
        self.store = store
        self.models = models
        self.decoys = decoys
        self.blocker = blocker

        bait_ports = {int(port) for port in config["decoys"]["bait"]["services"]}
        self.service_ports = bait_ports | {
            int(config["decoys"]["ssh"]["port"]),
            int(config["decoys"]["http"]["port"]),
        }

        self._lock = threading.RLock()
        self._history: dict[str, deque] = defaultdict(lambda: deque(maxlen=2000))
        self._last_finding: dict[str, dict] = {}
        self._finding_count: Counter = Counter()
        self._recent_flows: deque = deque(maxlen=100)
        self._ml_history: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self.stats = Counter()

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def observe(self, event: Event) -> dict | None:
        """Process one event. Never raises: a bad event must not stop decoys."""
        try:
            with self._lock:
                return self._observe(event)
        except Exception:
            self.stats["errors"] += 1
            log.exception("Failed to process %s event from %s", event.kind, event.src_ip)
            return None

    def _observe(self, event: Event) -> dict | None:
        now = event.ts
        self.stats["events"] += 1
        self.stats[f"events.{event.kind}"] += 1

        if event.kind == CONNECTION:
            self._score_flow(event)
        if event.kind in (HTTP, SSH_AUTH):
            self._check_honeytokens(event)

        self.store.insert_event(event)

        history = self._history[event.src_ip]
        history.append(event)
        horizon = now - self.thresholds["history_s"]
        while history and history[0].ts < horizon:
            history.popleft()

        finding = self._evaluate(event.src_ip, now)
        if finding is None:
            return None

        self._finding_count[finding["src_ip"]] += 1
        prior = self._finding_count[finding["src_ip"]]

        decoy = self.decoys.on_finding(finding, prior_findings=prior)
        block = self.blocker.consider(finding)
        finding["decision"] = {"decoy": decoy, "block": block}
        finding["id"] = self.store.insert_finding(finding)
        self.stats["findings"] += 1
        log.warning(
            "%s %s from %s score=%s (%s)",
            finding["severity"], finding["classification"], finding["src_ip"],
            finding["score"], "; ".join(finding["reasons"]),
        )
        return finding

    # ------------------------------------------------------------------
    # Enrichment
    # ------------------------------------------------------------------

    def _score_flow(self, event: Event) -> None:
        flow = {"src_ip": event.src_ip, "dst_port": event.dst_port,
                "service": event.service, "ts": event.ts}
        for name in FLOW_FIELDS:
            flow[name] = event.detail.get(name)

        prediction = None
        if self.models.enabled:
            try:
                prediction = self.models.predict(flow, recent=self._recent_flows)
            except Exception:
                self.stats["ml_errors"] += 1
                log.exception("ML scoring failed for %s", event.src_ip)

        event.detail["ml"] = prediction
        self._recent_flows.append(flow)
        if prediction is not None:
            self._ml_history[event.src_ip].append((event.ts, prediction))

    def _check_honeytokens(self, event: Event) -> None:
        raw = str(event.detail.get("raw", ""))
        if not raw:
            return
        hits = [
            record["token"]
            for record in self.store.all_honeytokens()
            if record["token"] in raw
        ]
        if hits:
            event.detail["honeytoken_hits"] = [
                {
                    "token_prefix": token[:8],
                    "token_sha256": hashlib.sha256(token.encode()).hexdigest()[:16],
                    "issued_to": self._issued_to(token),
                }
                for token in hits
            ]

    def _issued_to(self, token: str) -> str:
        for record in self.store.all_honeytokens():
            if record["token"] == token:
                return record["src_ip"]
        return "unknown"

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    def _rules(self, history: list[Event], now: float) -> list[Rule]:
        t = self.thresholds
        rules: list[Rule] = []

        def within(event: Event, seconds: float) -> bool:
            return now - event.ts <= seconds

        probes = [
            e for e in history
            if e.kind in (CONNECTION, FW_DROP) and e.dst_port
            and within(e, t["window_s"])
        ]
        ports = sorted({e.dst_port for e in probes})
        if len(ports) >= t["scan_min_ports"]:
            extra = len(ports) - t["scan_min_ports"]
            rules.append(Rule(
                "PORT_SCAN",
                min(70, 40 + 3 * extra),
                f"{len(ports)} distinct ports probed within {t['window_s']} seconds",
                {"ports": ports[:50]},
            ))

        service_probes = [
            e for e in history
            if e.kind in (CONNECTION, FW_DROP) and e.dst_port in self.service_ports
            and within(e, 300)
        ]
        service_ports = sorted({e.dst_port for e in service_probes})
        if len(service_ports) >= t["service_discovery_min_ports"]:
            extra = len(service_ports) - t["service_discovery_min_ports"]
            rules.append(Rule(
                "SERVICE_DISCOVERY",
                min(50, 20 + 4 * extra),
                f"probed {len(service_ports)} service ports within 5 minutes",
                {"service_ports": service_ports},
            ))

        silent = [
            e for e in history
            if e.kind == CONNECTION and not e.detail.get("had_payload")
            and e.dst_port in self.service_ports and within(e, 300)
        ]
        fingerprints = [
            e for e in history
            if e.kind == CONNECTION and e.detail.get("signature")
            and within(e, 300)
        ]
        if len(silent) >= t["banner_min_silent"] or fingerprints:
            # Kept below PORT_SCAN for the same probes: a sweep of several
            # ports is a scan, and silent connects are how that scan looks.
            points = min(40, 15 + 3 * len(silent) + 10 * len(fingerprints))
            signatures = sorted({e.detail["signature"] for e in fingerprints})
            reason = f"{len(silent)} banner grabs"
            if signatures:
                reason += f" and protocol fingerprints ({', '.join(signatures)})"
            rules.append(Rule(
                "BANNER_ENUMERATION",
                points,
                reason + " within 5 minutes",
                {"silent_connects": len(silent), "signatures": signatures},
            ))

        icmp = [
            e for e in history
            if e.kind == FW_DROP and e.detail.get("icmp_type") == 8 and within(e, 300)
        ]
        if len(icmp) >= t["icmp_min_echo"]:
            extra = len(icmp) - t["icmp_min_echo"]
            rules.append(Rule(
                "HOST_DISCOVERY",
                min(55, 35 + 3 * extra),
                f"{len(icmp)} ICMP echo requests dropped within 5 minutes",
                {"echo_requests": len(icmp)},
            ))

        http = [e for e in history if e.kind == HTTP and within(e, 120)]
        paths = {e.detail.get("path", "/") for e in http}
        suspicious = sorted(p for p in paths if is_suspicious_path(p))
        if (len(suspicious) >= t["http_suspicious_min"]
                or len(paths) >= t["http_probe_min_paths"]):
            extra = max(0, len(paths) - t["http_probe_min_paths"])
            rules.append(Rule(
                "HTTP_ENDPOINT_PROBING",
                min(65, 25 + 6 * len(suspicious) + 2 * extra),
                f"{len(paths)} distinct paths requested, {len(suspicious)} sensitive "
                "within 2 minutes",
                {"paths": sorted(paths)[:50], "sensitive_paths": suspicious[:50]},
            ))

        auth = [e for e in history if e.kind == SSH_AUTH and within(e, 120)]
        if len(auth) >= t["ssh_bruteforce_min_attempts"]:
            extra = len(auth) - t["ssh_bruteforce_min_attempts"]
            users = sorted({str(e.detail.get("username", "")) for e in auth})
            points = 40 + 3 * extra + (10 if len(users) >= 3 else 0)
            rules.append(Rule(
                "SSH_BRUTE_FORCE",
                min(75, points),
                f"{len(auth)} SSH authentication attempts within 2 minutes "
                f"using {len(users)} username(s)",
                {"attempts": len(auth), "usernames": users[:20]},
            ))

        tokens = [
            e for e in history
            if e.detail.get("honeytoken_hits") and within(e, t["history_s"])
        ]
        if tokens:
            hit = tokens[-1].detail["honeytoken_hits"][0]
            rules.append(Rule(
                "HONEYTOKEN_REUSE",
                80,
                "attacker reused a decoy-issued credential "
                f"(token {hit['token_prefix']}..., issued to {hit['issued_to']})",
                {"hits": [e.detail["honeytoken_hits"] for e in tokens][-5:]},
            ))

        return rules

    def _ml_points(self, ip: str, now: float) -> tuple[int, dict, int]:
        window = self.thresholds["window_s"]
        recent = [
            prediction for ts, prediction in self._ml_history[ip]
            if now - ts <= window and prediction
        ]
        if not recent:
            return 0, {}, 0

        strongest = {
            "cic_portscan": max(
                (p["cic_portscan"] for p in recent if p.get("cic_portscan") is not None),
                default=None,
            ),
            "unsw_recon": max(
                (p["unsw_recon"] for p in recent if p.get("unsw_recon") is not None),
                default=None,
            ),
        }
        points = self.models.combined_points(strongest)
        strong_flows = sum(
            1 for p in recent
            if (p.get("cic_portscan") or 0) >= 0.5
        )
        summary = {
            "cic_portscan": _round(strongest["cic_portscan"]),
            "unsw_recon": _round(strongest["unsw_recon"]),
            "flows_scored": len(recent),
            "cic_feature_coverage": recent[-1].get("cic_feature_coverage"),
            "unsw_feature_coverage": recent[-1].get("unsw_feature_coverage"),
        }
        return points, summary, strong_flows

    # ------------------------------------------------------------------
    # Scoring and finding creation
    # ------------------------------------------------------------------

    def _evaluate(self, ip: str, now: float) -> dict | None:
        history = list(self._history[ip])
        rules = self._rules(history, now)
        ml_points, ml_summary, strong_flows = self._ml_points(ip, now)

        if rules:
            # Each rule is already capped for its own class. Several triggered
            # classes add a little, up to 90, so the most serious combinations
            # can still reach HIGH without ML.
            primary = max(rules, key=lambda rule: rule.points)
            rule_points = min(90, primary.points + 10 * (len(rules) - 1))
            classification = primary.name
        elif ml_points >= ML_ONLY_MIN_POINTS and strong_flows >= ML_ONLY_MIN_FLOWS:
            # The models alone may flag recon, but only with agreement over
            # several flows, because single-flow ML scores are noisy.
            rule_points = 0
            classification = "ML_RECON_SUSPECTED"
        else:
            return None

        score = min(100, rule_points + ml_points)
        severity = self._severity(score)

        last = self._last_finding.get(ip)
        if last and last["classification"] == classification:
            within_cooldown = now - last["ts"] < self.thresholds["finding_cooldown_s"]
            not_escalated = SEVERITY_RANK[severity] <= SEVERITY_RANK[last["severity"]]
            if within_cooldown and not_escalated:
                return None

        self._last_finding[ip] = {
            "ts": now, "classification": classification, "severity": severity,
        }

        reasons = [rule.reason for rule in rules]
        if ml_points:
            reasons.append(
                f"ML score {ml_points} points (CIC PortScan p="
                f"{_round(ml_summary.get('cic_portscan'))}, UNSW recon p="
                f"{_round(ml_summary.get('unsw_recon'))})"
            )
        if not rules:
            reasons.append("behavioural rules did not trigger; ML-only agreement")

        evidence: dict = {"ml": ml_summary}
        for rule in rules:
            evidence[rule.name] = rule.evidence

        return {
            "ts": now,
            "src_ip": ip,
            "classification": classification,
            "severity": severity,
            "score": score,
            "rule_points": rule_points,
            "ml_points": ml_points,
            "reasons": reasons,
            "techniques": [rule.name for rule in rules],
            "evidence": evidence,
        }

    def _severity(self, score: int) -> str:
        if score >= self.thresholds["severity_high_score"]:
            return "HIGH"
        if score >= self.thresholds["severity_medium_score"]:
            return "MEDIUM"
        return "LOW"

    def summary(self) -> dict:
        with self._lock:
            return {
                "events": self.stats["events"],
                "findings": self.stats["findings"],
                "errors": self.stats["errors"],
                "ml_errors": self.stats["ml_errors"],
                "events_by_kind": {
                    key.split(".", 1)[1]: value
                    for key, value in self.stats.items()
                    if key.startswith("events.")
                },
                "tracked_sources": len(self._history),
            }


def _round(value: float | None) -> float | None:
    return None if value is None else round(float(value), 4)
