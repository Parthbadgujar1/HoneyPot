"""Attacker profiling from observed behaviour.

Each source gets a behavioural label and a confidence. The labels describe
*how the source behaved* (automated scanning, credential guessing, web
exploitation, manual exploration, targeted multi-stage activity). They are
heuristics over measured features, not identities, and the confidence is the
share of evidence that supports the winning label, never a probability of
attribution.
"""

from __future__ import annotations

from collections import Counter

from .events import CONNECTION, FW_DROP, HTTP, SSH_AUTH, Event

LABELS = ("AUTOMATED_SCANNER", "CREDENTIAL_ATTACKER", "WEB_EXPLOIT_ATTACKER",
          "MANUAL_EXPLORER", "TARGETED_MULTI_STAGE")


def features(history: list[Event]) -> dict:
    if not history:
        return {}
    span = max(1.0, history[-1].ts - history[0].ts)
    kinds = Counter(e.kind for e in history)
    ports = {e.dst_port for e in history if e.kind in (CONNECTION, FW_DROP) and e.dst_port}
    paths = {e.detail.get("path") for e in history if e.kind == HTTP}
    web_attacks = sum(len(e.detail.get("web_attacks", [])) for e in history if e.kind == HTTP)
    tokens = sum(1 for e in history if e.detail.get("honeytoken_hits"))
    services = {e.service for e in history if e.service not in (None, "", "-")}
    return {
        "events": len(history), "span_s": round(span, 1), "rate_per_s": round(len(history) / span, 3),
        "distinct_ports": len(ports), "distinct_paths": len(paths), "ssh_attempts": kinds[SSH_AUTH],
        "web_attack_matches": web_attacks, "honeytoken_hits": tokens, "services": len(services),
    }


def profile(history: list[Event]) -> dict:
    f = features(history)
    if not f:
        return {"label": None, "confidence": 0.0, "features": {}}
    stages = sum([f["distinct_ports"] >= 3, f["ssh_attempts"] >= 3, f["distinct_paths"] >= 3,
                  f["web_attack_matches"] > 0, f["honeytoken_hits"] > 0])
    score = {
        "AUTOMATED_SCANNER": 3.0 * (f["distinct_ports"] >= 4) + 1.0 * (f["rate_per_s"] >= 0.5)
                             + 1.0 * (f["services"] >= 3),
        "CREDENTIAL_ATTACKER": 3.0 * (f["ssh_attempts"] >= 5) + 1.0 * (f["ssh_attempts"] >= 3),
        "WEB_EXPLOIT_ATTACKER": 3.0 * (f["web_attack_matches"] > 0) + 1.5 * (f["distinct_paths"] >= 5),
        "MANUAL_EXPLORER": 1.5 * (f["events"] >= 2) + 1.5 * (f["rate_per_s"] < 0.2)
                           + 1.0 * (f["distinct_paths"] >= 2) - 1.5 * (f["distinct_ports"] >= 4),
        "TARGETED_MULTI_STAGE": 2.0 * (stages >= 3) + 3.0 * (f["honeytoken_hits"] > 0),
    }
    top = max(score, key=score.get)
    positive = sum(max(v, 0) for v in score.values())
    if positive <= 0:
        return {"label": None, "confidence": 0.0, "features": f}
    return {"label": top, "confidence": round(max(score[top], 0) / positive, 2), "features": f,
            "scores": {k: round(v, 1) for k, v in score.items()}}
