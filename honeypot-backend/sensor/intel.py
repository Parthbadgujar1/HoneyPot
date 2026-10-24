"""Threat-intelligence views built from sensor telemetry.

Three outputs, all computed from the local SQLite store:

* Attacker profiles: per source IP, the ports, services, usernames,
  password hashes, user agents, paths and honeytokens it used.
* Campaigns: sources linked by behaviour they share. Two sources are linked
  when they reuse the same honeytoken or password, try the same usernames,
  send the same user agent, or probe the same set of ports. Linked sources
  form one campaign. Every link records why it was made, so an analyst can
  check the reasoning.
* Indicators: IPs, usernames, password hashes, user agents, paths and
  honeytoken hashes, ready to share. Passwords are exported as SHA-256
  digests only, never as typed.
"""

from __future__ import annotations

import csv
import hashlib
import io
import time
from collections import defaultdict
from datetime import datetime, timezone

from .store import Store

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

# A user agent shared by more sources than this is treated as generic
# tooling (for example a common library default) and is not used for linking.
MAX_SOURCES_PER_USER_AGENT = 10
USERNAME_JACCARD = 0.5
PORT_JACCARD = 0.6
PORT_MIN_SHARED = 3


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _jaccard(a: set, b: set) -> float:
    union = a | b
    return len(a & b) / len(union) if union else 0.0


def build_profiles(rows: list[dict], findings: list[dict]) -> dict[str, dict]:
    """One profile per source IP, built from events and findings."""
    profiles: dict[str, dict] = {}

    def profile(ip: str) -> dict:
        return profiles.setdefault(ip, {
            "src_ip": ip,
            "first_seen": None,
            "last_seen": None,
            "events": 0,
            "ports": set(),
            "services": set(),
            "usernames": set(),
            "password_hashes": set(),
            "user_agents": set(),
            "paths": set(),
            "honeytokens": set(),
            "classes": set(),
            "max_severity": None,
            "max_score": 0,
        })

    for row in rows:
        item = profile(row["src_ip"])
        item["events"] += 1
        ts = row["ts"]
        item["first_seen"] = ts if item["first_seen"] is None else min(item["first_seen"], ts)
        item["last_seen"] = ts if item["last_seen"] is None else max(item["last_seen"], ts)

        if row["dst_port"] is not None:
            item["ports"].add(int(row["dst_port"]))
        if row["kind"] == "connection" and row["service"] not in (None, "", "-"):
            item["services"].add(str(row["service"]))

        detail = row["detail"] or {}
        if row["kind"] == "ssh_auth":
            if detail.get("username"):
                item["usernames"].add(str(detail["username"])[:64])
            if detail.get("method") == "password" and detail.get("secret_preview"):
                item["password_hashes"].add(digest(str(detail["secret_preview"])))
        if row["kind"] == "http_request":
            if detail.get("path"):
                item["paths"].add(str(detail["path"])[:200])
            if detail.get("user_agent"):
                item["user_agents"].add(str(detail["user_agent"])[:200])
        for hit in detail.get("honeytoken_hits") or []:
            token_hash = hit.get("token_sha256")
            if token_hash:
                item["honeytokens"].add(token_hash)

    for finding in findings:
        item = profiles.get(finding["src_ip"])
        if item is None:
            continue
        item["classes"].add(finding["classification"])
        severity = finding["severity"]
        if item["max_severity"] is None or SEVERITY_RANK[severity] > SEVERITY_RANK[item["max_severity"]]:
            item["max_severity"] = severity
        item["max_score"] = max(item["max_score"], int(finding["score"]))

    return profiles


def link_profiles(profiles: dict[str, dict]) -> dict[tuple[str, str], set[str]]:
    """Return {(ip_a, ip_b): reasons} for every pair that should be linked."""
    edges: dict[tuple[str, str], set[str]] = defaultdict(set)

    def link(a: str, b: str, reason: str) -> None:
        edges[tuple(sorted((a, b)))].add(reason)

    def pairwise(shared_index: dict, label: str) -> None:
        for value, members in shared_index.items():
            members = sorted(members)
            for i, a in enumerate(members):
                for b in members[i + 1:]:
                    link(a, b, f"{label} {str(value)[:60]}")

    honeytoken_index: dict[str, set[str]] = defaultdict(set)
    password_index: dict[str, set[str]] = defaultdict(set)
    user_agent_index: dict[str, set[str]] = defaultdict(set)
    for ip, item in profiles.items():
        for token in item["honeytokens"]:
            honeytoken_index[token].add(ip)
        for password in item["password_hashes"]:
            password_index[password].add(ip)
        for agent in item["user_agents"]:
            user_agent_index[agent].add(ip)

    pairwise(honeytoken_index, "reused honeytoken")
    pairwise({k: v for k, v in password_index.items() if len(v) >= 2},
             "same password hash")
    pairwise({k: v for k, v in user_agent_index.items()
              if 2 <= len(v) <= MAX_SOURCES_PER_USER_AGENT},
             "same user agent")

    ips = sorted(profiles)
    for i, a in enumerate(ips):
        for b in ips[i + 1:]:
            ua, ub = profiles[a]["usernames"], profiles[b]["usernames"]
            shared_users = ua & ub
            if len(shared_users) >= 2 and _jaccard(ua, ub) >= USERNAME_JACCARD:
                link(a, b, f"similar username lists ({len(shared_users)} shared)")

            pa, pb = profiles[a]["ports"], profiles[b]["ports"]
            shared_ports = pa & pb
            if len(shared_ports) >= PORT_MIN_SHARED and _jaccard(pa, pb) >= PORT_JACCARD:
                link(a, b, f"same port set ({len(shared_ports)} shared ports)")

    return edges


def build_campaigns(profiles: dict[str, dict], edges: dict[tuple[str, str], set[str]]) -> tuple[list[dict], list[str]]:
    """Group linked sources into campaigns with union-find."""
    parent = {ip: ip for ip in profiles}

    def find(ip: str) -> str:
        while parent[ip] != ip:
            parent[ip] = parent[parent[ip]]
            ip = parent[ip]
        return ip

    for a, b in edges:
        parent[find(a)] = find(b)

    groups: dict[str, list[str]] = defaultdict(list)
    for ip in profiles:
        groups[find(ip)].append(ip)

    campaigns = []
    unclustered = []
    for members in groups.values():
        if len(members) == 1:
            unclustered.append(members[0])
            continue
        members = sorted(members)
        member_set = set(members)
        reasons: dict[str, int] = defaultdict(int)
        for (a, b), edge_reasons in edges.items():
            if a in member_set and b in member_set:
                for reason in edge_reasons:
                    reasons[reason] += 1

        items = [profiles[ip] for ip in members]
        severities = [i["max_severity"] for i in items if i["max_severity"]]
        first = min(i["first_seen"] for i in items)
        last = max(i["last_seen"] for i in items)
        campaigns.append({
            "members": members,
            "size": len(members),
            "reasons": [
                {"reason": reason, "links": count}
                for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1])
            ],
            "usernames": sorted({u for i in items for u in i["usernames"]})[:50],
            "password_hash_count": len({h for i in items for h in i["password_hashes"]}),
            "honeytoken_count": len({t for i in items for t in i["honeytokens"]}),
            "ports": sorted({p for i in items for p in i["ports"]})[:50],
            "classes": sorted({c for i in items for c in i["classes"]}),
            "max_severity": max(severities, key=SEVERITY_RANK.get) if severities else None,
            "max_score": max(i["max_score"] for i in items),
            "first_seen": _iso(first),
            "last_seen": _iso(last),
        })

    campaigns.sort(key=lambda c: (-c["size"], -c["max_score"]))
    for number, campaign in enumerate(campaigns, start=1):
        campaign["id"] = f"C-{number:03d}"
    return campaigns, sorted(unclustered)


def build_indicators(profiles: dict[str, dict], campaign_of: dict[str, str]) -> list[dict]:
    """Shareable indicators. Passwords and honeytokens appear only as hashes."""
    indicators: dict[tuple[str, str], dict] = {}

    def add(kind: str, value: str, ip: str, item: dict) -> None:
        key = (kind, value)
        record = indicators.setdefault(key, {
            "type": kind,
            "value": value,
            "first_seen": None,
            "last_seen": None,
            "sources": set(),
            "classes": set(),
            "max_severity": None,
        })
        record["sources"].add(ip)
        record["classes"].update(item["classes"])
        if item["max_severity"]:
            current = record["max_severity"]
            if current is None or SEVERITY_RANK[item["max_severity"]] > SEVERITY_RANK[current]:
                record["max_severity"] = item["max_severity"]
        first, last = item["first_seen"], item["last_seen"]
        record["first_seen"] = first if record["first_seen"] is None else min(record["first_seen"], first)
        record["last_seen"] = last if record["last_seen"] is None else max(record["last_seen"], last)

    for ip, item in profiles.items():
        add("ip", ip, ip, item)
        for username in item["usernames"]:
            add("username", username, ip, item)
        for password_hash in item["password_hashes"]:
            add("password_sha256", password_hash, ip, item)
        for agent in item["user_agents"]:
            add("user_agent", agent, ip, item)
        for path in item["paths"]:
            add("http_path", path, ip, item)
        for token_hash in item["honeytokens"]:
            add("honeytoken_sha256", token_hash, ip, item)

    rows = []
    for record in indicators.values():
        sources = sorted(record["sources"])
        campaigns = sorted({campaign_of[ip] for ip in sources if ip in campaign_of})
        rows.append({
            "type": record["type"],
            "value": record["value"],
            "first_seen": _iso(record["first_seen"]),
            "last_seen": _iso(record["last_seen"]),
            "sources": len(sources),
            "source_ips": sources[:50],
            "classes": sorted(record["classes"]),
            "max_severity": record["max_severity"],
            "campaigns": campaigns,
        })
    rows.sort(key=lambda r: (r["type"], -r["sources"], r["value"]))
    return rows


def build_report(store: Store, days: int, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    since = now - days * 86400
    profiles = build_profiles(store.intel_rows(since), store.findings_since(since))
    edges = link_profiles(profiles)
    campaigns, unclustered = build_campaigns(profiles, edges)
    campaign_of = {ip: c["id"] for c in campaigns for ip in c["members"]}
    indicators = build_indicators(profiles, campaign_of)
    return {
        "generated": _iso(now),
        "window_days": days,
        "sources": len(profiles),
        "campaigns": campaigns,
        "unclustered_sources": unclustered,
        "indicators": indicators,
    }


INDICATOR_COLUMNS = [
    "type", "value", "first_seen", "last_seen", "sources", "max_severity",
    "classes", "campaigns",
]


def indicators_csv(indicators: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(INDICATOR_COLUMNS)
    for row in indicators:
        writer.writerow([
            row["type"],
            row["value"],
            row["first_seen"],
            row["last_seen"],
            row["sources"],
            row["max_severity"] or "",
            ";".join(row["classes"]),
            ";".join(row["campaigns"]),
        ])
    return buffer.getvalue()
