"""MITRE ATT&CK mapping and STIX 2.1 export for sensor findings.

Each detection class maps to the ATT&CK techniques it evidences. The mapping
describes what the observed behaviour looks like; it is not proof of a
particular adversary. STIX ids are derived deterministically from the data,
so the same window always exports the same ids.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime, timezone

TECHNIQUES: dict[str, list[tuple[str, str, str]]] = {
    "PORT_SCAN": [("T1046", "Network Service Discovery", "discovery")],
    "SERVICE_DISCOVERY": [("T1046", "Network Service Discovery", "discovery")],
    "BANNER_ENUMERATION": [("T1046", "Network Service Discovery", "discovery"),
                           ("T1592", "Gather Victim Host Information", "reconnaissance")],
    "HOST_DISCOVERY": [("T1595.001", "Active Scanning: Scanning IP Blocks", "reconnaissance")],
    "HTTP_ENDPOINT_PROBING": [("T1595.003", "Active Scanning: Wordlist Scanning", "reconnaissance"),
                              ("T1190", "Exploit Public-Facing Application", "initial-access")],
    "SSH_BRUTE_FORCE": [("T1110", "Brute Force", "credential-access")],
    "HONEYTOKEN_REUSE": [("T1078", "Valid Accounts", "defense-evasion"),
                         ("T1552.001", "Unsecured Credentials: Credentials In Files", "credential-access")],
    "SQL_INJECTION": [("T1190", "Exploit Public-Facing Application", "initial-access")],
    "XSS": [("T1189", "Drive-by Compromise", "initial-access")],
    "COMMAND_INJECTION": [("T1059", "Command and Scripting Interpreter", "execution"),
                          ("T1190", "Exploit Public-Facing Application", "initial-access")],
    "PATH_TRAVERSAL": [("T1083", "File and Directory Discovery", "discovery"),
                       ("T1190", "Exploit Public-Facing Application", "initial-access")],
    "FILE_UPLOAD_ABUSE": [("T1505.003", "Server Software Component: Web Shell", "persistence")],
    "SSRF_LFI": [("T1190", "Exploit Public-Facing Application", "initial-access")],
    "ML_RECON_SUSPECTED": [("T1595", "Active Scanning", "reconnaissance")],
}

_NS = uuid.UUID("5b0a2f2e-6d56-4a0c-9d6a-7c8d1d7a0001")


def techniques_for(classes) -> list[dict]:
    seen, out = set(), []
    for name in classes:
        for tid, title, tactic in TECHNIQUES.get(name, []):
            if tid not in seen:
                seen.add(tid)
                out.append({"id": tid, "name": title, "tactic": tactic})
    return out


def _sid(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(_NS, kind + key)}"


def _stamp(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def stix_bundle(findings: list[dict], now: float) -> dict:
    """STIX 2.1 bundle: identity, one indicator per source IP, attack patterns, relationships."""
    identity_id = _sid("identity", "honeypot-sensor")
    created = _stamp(now)
    objects = [{
        "type": "identity", "spec_version": "2.1", "id": identity_id,
        "created": created, "modified": created, "name": "AI-Adaptive Honeypot Sensor",
        "identity_class": "system",
    }]
    patterns: dict[str, str] = {}
    by_ip: dict[str, list[dict]] = {}
    for finding in findings:
        by_ip.setdefault(finding["src_ip"], []).append(finding)

    for ip, items in sorted(by_ip.items()):
        try:
            kind = "ipv6-addr" if ipaddress.ip_address(ip).version == 6 else "ipv4-addr"
        except ValueError:
            continue
        first = min(f["ts"] for f in items)
        last = max(f["ts"] for f in items)
        classes = sorted({f["classification"] for f in items}
                         | {t for f in items for t in f.get("techniques", [])})
        indicator_id = _sid("indicator", ip)
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": indicator_id,
            "created": _stamp(first), "modified": _stamp(last), "created_by_ref": identity_id,
            "name": f"Honeypot reconnaissance source {ip}",
            "description": "Observed by the honeypot sensor: " + ", ".join(classes),
            "pattern": f"[{kind}:value = '{ip}']", "pattern_type": "stix",
            "valid_from": _stamp(first), "labels": ["honeypot-observed"], "confidence": 60,
        })
        for tech in techniques_for(classes):
            if tech["id"] not in patterns:
                patterns[tech["id"]] = _sid("attack-pattern", tech["id"])
                objects.append({
                    "type": "attack-pattern", "spec_version": "2.1", "id": patterns[tech["id"]],
                    "created": created, "modified": created, "name": tech["name"],
                    "external_references": [{
                        "source_name": "mitre-attack", "external_id": tech["id"],
                        "url": "https://attack.mitre.org/techniques/" + tech["id"].replace(".", "/") + "/"}],
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": tech["tactic"]}],
                })
            objects.append({
                "type": "relationship", "spec_version": "2.1",
                "id": _sid("relationship", ip + tech["id"]), "created": created, "modified": created,
                "relationship_type": "indicates", "source_ref": indicator_id,
                "target_ref": patterns[tech["id"]],
            })
    return {"type": "bundle", "id": _sid("bundle", created), "objects": objects}
