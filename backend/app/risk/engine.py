"""Dynamic risk scoring service.

Combines anomaly, behaviour, sequence, resource, and persistence signals into a
0-100 risk score. Weights are configurable and NOT claimed to be optimal.
"""

from typing import Any, Dict, Optional

from app.core.config import get_settings

settings = get_settings()

SEVERITY_THRESHOLDS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (0, "LOW"),
]

DEFAULT_WEIGHTS = {
    "anomaly": 0.30,
    "behaviour": 0.25,
    "sequence": 0.15,
    "resource": 0.15,
    "persistence": 0.15,
}


def parse_weights(raw: Optional[str]) -> Dict[str, float]:
    if not raw:
        return dict(DEFAULT_WEIGHTS)
    weights = dict(DEFAULT_WEIGHTS)
    for part in raw.split(","):
        if ":" in part:
            k, v = part.split(":")
            try:
                weights[k.strip()] = float(v.strip())
            except ValueError:
                continue
    return weights


def severity_for(score: float) -> str:
    for threshold, sev in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return sev
    return "LOW"


class RiskEngine:
    def __init__(self, weights: Optional[Dict[str, float]] = None, version: str = "policy-v1"):
        self.weights = weights or parse_weights(settings.RISK_WEIGHTS)
        self.version = version

    def assess(self, inputs: Dict[str, float]) -> Dict[str, Any]:
        """inputs: dict of normalized 0-1 signals (anomaly, behaviour, sequence,
        resource, persistence)."""
        total_weight = sum(self.weights.values()) or 1.0
        contributions = {}
        score = 0.0
        for key in self.weights:
            val = inputs.get(key, 0.0)
            contrib = (self.weights[key] / total_weight) * 100.0 * val
            contributions[key] = {
                "weight": self.weights[key],
                "signal": round(val, 4),
                "score": round(contrib, 2),
            }
            score += contrib
        score = round(min(max(score, 0.0), 100.0), 1)
        severity = severity_for(score)
        return {
            "score": score,
            "severity": severity,
            "policy_version": self.version,
            "weights": self.weights,
            "contributions": contributions,
        }
