"""Unsupervised anomaly detection.

Isolation Forest is used to compute an anomaly score per session feature vector.
The module returns a label, score, and interpretable contributing signals based
on per-feature deviation from the training distribution.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

import numpy as np

from app.ml.base import BaseModelWrapper
from app.telemetry.features import FEATURE_NAMES


class IsolationForestAnomaly(BaseModelWrapper):
    name = "isolation_forest"
    model_type = "anomaly"
    feature_version = "v1"

    def __init__(self, version: str = "v0", contamination: float = 0.1, **kwargs):
        super().__init__(version=version)
        from sklearn.ensemble import IsolationForest

        self.model = IsolationForest(
            contamination=contamination, random_state=42, n_estimators=150
        )
        self._fit_means: Optional[np.ndarray] = None
        self._fit_stds: Optional[np.ndarray] = None

    def fit(self, X, y=None) -> "IsolationForestAnomaly":
        arr = np.asarray(X, dtype=float)
        self.model.fit(arr)
        self._fit_means = arr.mean(axis=0)
        self._fit_stds = arr.std(axis=0) + 1e-9
        self.trained_at = datetime.utcnow()
        return self

    def anomaly_scores(self, X) -> np.ndarray:
        arr = np.asarray(X, dtype=float)
        # decision_function returns higher = more normal; invert to anomaly.
        return -self.model.decision_function(arr)

    def predict(self, X) -> np.ndarray:
        raw = self.model.predict(np.asarray(X, dtype=float))
        # sklearn: -1 = anomaly, 1 = normal
        return np.where(raw == -1, 1, 0)

    def explain(self, X) -> List[Dict[str, Any]]:
        """Return per-sample contributing features (interpretable deviations)."""
        arr = np.asarray(X, dtype=float)
        scores = self.anomaly_scores(arr)
        labels = self.model.predict(arr)
        results = []
        for i in range(len(arr)):
            row = arr[i]
            zs = (row - self._fit_means) / self._fit_stds
            # top features by absolute z-score
            idxs = np.argsort(-np.abs(zs))[:5]
            contribs = []
            for idx in idxs:
                contribs.append(
                    {
                        "feature": FEATURE_NAMES[idx],
                        "value": float(row[idx]),
                        "deviation": float(zs[idx]),
                    }
                )
            score = float(scores[i])
            results.append(
                {
                    "anomaly_score": score,
                    "label": "anomaly" if labels[i] == -1 else "normal",
                    "contributing_features": contribs,
                    "reasons": _derive_reasons(contribs, labels[i] == -1),
                }
            )
        return results

    def score_and_explain(self, X) -> Dict[str, Any]:
        res = self.explain(X)[0]
        return res


def _derive_reasons(contribs: List[Dict], is_anomaly: bool) -> List[str]:
    reasons = []
    high = [c for c in contribs if abs(c["deviation"]) > 1.5]
    if high:
        names = ", ".join(c["feature"] for c in high[:3])
        reasons.append(f"unusual value in: {names}")
    if any(c["feature"] in ("sensitive_interactions", "failed_auths", "discovery_activity") for c in high):
        reasons.append("high-risk signalling feature deviation")
    if is_anomaly:
        reasons.append("pattern deviates from learned baseline")
    if not reasons:
        reasons.append("within expected range")
    return reasons
