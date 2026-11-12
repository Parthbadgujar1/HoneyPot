"""Behaviour model trained on this sensor's own telemetry.

The two pretrained models in ``ml.py`` were trained on CICFlowMeter and
UNSW-NB15 features the sensor can only partly measure. This model closes
that gap: its features are computed from the same ``Event`` records every
listener emits, so training and live scoring see exactly the same inputs.

Two parts, saved together in one joblib bundle:

* a RandomForest classifier that names the attack family of a source from
  its recent behaviour (``CLASSES``), with a class probability as confidence;
* an IsolationForest fitted on the same vectors, which flags behaviour unlike
  anything in the training data, so unfamiliar activity is not silently
  scored as benign.

Train it with ``python -m sensor.tools.train_behaviour``. Labels come from
operator labels in the sensor database or from the lab scenario generator,
never from the rule engine's own findings, so the model is not just a copy
of the rules. Until a bundle exists the sensor runs without it.
"""

from __future__ import annotations

import logging
import math
import time
from collections import Counter
from pathlib import Path

import joblib
import numpy as np

from .events import CONNECTION, FW_DROP, HTTP, SSH_AUTH, Event

log = logging.getLogger("sensor.behaviour")

BUNDLE_VERSION = 1

CLASSES = ("BENIGN", "RECON_SCAN", "CREDENTIAL_ATTACK", "WEB_ATTACK", "MULTI_STAGE")

FEATURES = (
    "events", "span_s", "rate_per_s", "mean_gap_s", "connections", "fw_drops",
    "silent_connections", "distinct_ports", "services", "http_requests",
    "distinct_paths", "suspicious_paths", "http_error_ratio", "web_attack_matches",
    "web_attack_families", "ssh_attempts", "distinct_usernames", "honeytoken_hits",
    "kinds",
)

SUSPICIOUS_MARKERS = ("/.env", "/.git", "/wp-", "/phpmyadmin", "/admin", "/backup",
                      "/config", "/api/", "/cgi-bin", "/actuator", "/server-status")

# Recompute a source's prediction at most this often; a port scan can emit
# hundreds of events a second and the forest is not free to evaluate.
RESCORE_EVERY_EVENTS = 5
RESCORE_EVERY_S = 5.0


def features(history: list[Event]) -> dict:
    """Behaviour features of one source over its retained history."""
    if not history:
        return {name: 0.0 for name in FEATURES}
    times = sorted(e.ts for e in history)
    span = max(1.0, times[-1] - times[0])
    gaps = [b - a for a, b in zip(times, times[1:])]
    kinds = Counter(e.kind for e in history)
    conns = [e for e in history if e.kind == CONNECTION]
    https = [e for e in history if e.kind == HTTP]
    ssh = [e for e in history if e.kind == SSH_AUTH]
    families = {f for e in https for f in e.detail.get("web_attacks", [])}
    paths = [str(e.detail.get("path", "")).lower() for e in https]
    errors = sum(1 for e in https if int(e.detail.get("status") or 200) >= 400)
    return {
        "events": float(len(history)),
        "span_s": span,
        "rate_per_s": len(history) / span,
        "mean_gap_s": sum(gaps) / len(gaps) if gaps else span,
        "connections": float(len(conns)),
        "fw_drops": float(kinds[FW_DROP]),
        "silent_connections": float(sum(1 for e in conns if not e.detail.get("had_payload"))),
        "distinct_ports": float(len({e.dst_port for e in history
                                     if e.kind in (CONNECTION, FW_DROP) and e.dst_port})),
        "services": float(len({e.service for e in history if e.service not in (None, "", "-")})),
        "http_requests": float(len(https)),
        "distinct_paths": float(len(set(paths))),
        "suspicious_paths": float(sum(1 for p in paths if p.startswith(SUSPICIOUS_MARKERS))),
        "http_error_ratio": errors / len(https) if https else 0.0,
        "web_attack_matches": float(sum(len(e.detail.get("web_attacks", [])) for e in https)),
        "web_attack_families": float(len(families)),
        "ssh_attempts": float(len(ssh)),
        "distinct_usernames": float(len({e.detail.get("username") for e in ssh})),
        "honeytoken_hits": float(sum(1 for e in history if e.detail.get("honeytoken_hits"))),
        "kinds": float(len(kinds)),
    }


def vector(feature_row: dict) -> list[float]:
    # log1p keeps counts and durations on comparable scales for the forest
    # and, more importantly, for the IsolationForest's random splits.
    return [math.log1p(max(0.0, float(feature_row.get(name, 0.0)))) for name in FEATURES]


def train(samples: list[tuple[dict, str, str]], seed: int = 7) -> dict:
    """Fit the classifier and anomaly detector.

    ``samples`` holds (features, label, group) tuples. ``group`` identifies the
    source/session a sample came from: prefixes of one session are grouped so
    cross-validation never tests on a session it also trained on.
    """
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.model_selection import GroupKFold, cross_val_predict

    X = np.array([vector(f) for f, _, _ in samples])
    y = np.array([label for _, label, _ in samples])
    groups = np.array([group for _, _, group in samples])
    labels = [c for c in CLASSES if c in set(y)]

    def classifier():
        return RandomForestClassifier(n_estimators=120, min_samples_leaf=2,
                                      class_weight="balanced", random_state=seed, n_jobs=1)

    metrics: dict = {"samples": int(len(y)), "groups": int(len(set(groups))),
                     "class_counts": {c: int((y == c).sum()) for c in labels}}
    folds = min(5, len(set(groups)))
    if folds >= 3 and len(labels) >= 2:
        predicted = cross_val_predict(classifier(), X, y, groups=groups,
                                      cv=GroupKFold(n_splits=folds))
        report = classification_report(y, predicted, labels=labels, output_dict=True,
                                       zero_division=0)
        metrics.update({
            "cv": f"GroupKFold({folds}) by session",
            "accuracy": round(float(report["accuracy"]), 4),
            "macro_f1": round(float(report["macro avg"]["f1-score"]), 4),
            "per_class": {c: {k: round(float(report[c][k]), 4)
                              for k in ("precision", "recall", "f1-score", "support")}
                          for c in labels},
            "confusion_labels": labels,
            "confusion": confusion_matrix(y, predicted, labels=labels).tolist(),
        })
        if "BENIGN" in labels:
            benign = y == "BENIGN"
            metrics["false_positive_rate"] = round(
                float((predicted[benign] != "BENIGN").mean()) if benign.any() else 0.0, 4)
    else:
        metrics["cv"] = "skipped: need at least 3 sessions and 2 classes"

    model = classifier().fit(X, y)
    isolation = IsolationForest(n_estimators=150, contamination="auto",
                                random_state=seed).fit(X)
    return {
        "version": BUNDLE_VERSION,
        "trained_at": time.time(),
        "features": list(FEATURES),
        "classes": list(model.classes_),
        "classifier": model,
        "isolation": isolation,
        "metrics": metrics,
        "importance": dict(sorted(
            ((name, round(float(w), 4)) for name, w in zip(FEATURES, model.feature_importances_)),
            key=lambda item: -item[1])),
    }


def save(bundle: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)


class BehaviourModel:
    """Loads a trained bundle and scores sources during detection."""

    def __init__(self, path: Path, weight: int = 20, min_confidence: float = 0.6):
        self.path = Path(path)
        self.weight = weight
        self.min_confidence = min_confidence
        self.bundle: dict | None = None
        self.error: str | None = None
        self._cache: dict[str, tuple[float, int, dict]] = {}
        self.reload()

    def reload(self) -> None:
        self._cache.clear()
        if not self.path.exists():
            self.bundle, self.error = None, "not trained yet (run sensor.tools.train_behaviour)"
            return
        try:
            bundle = joblib.load(self.path)
            if bundle.get("version") != BUNDLE_VERSION or bundle.get("features") != list(FEATURES):
                raise ValueError("bundle was trained with a different feature set; retrain it")
            self.bundle, self.error = bundle, None
        except Exception as exc:  # a bad bundle must not stop the sensor
            self.bundle, self.error = None, str(exc)
            log.error("Behaviour model not loaded: %s", exc)

    @property
    def loaded(self) -> bool:
        return self.bundle is not None

    def status(self) -> dict:
        if not self.bundle:
            return {"loaded": False, "path": str(self.path), "error": self.error}
        metrics = self.bundle["metrics"]
        return {
            "loaded": True, "path": str(self.path), "weight": self.weight,
            "trained_at": self.bundle["trained_at"], "classes": self.bundle["classes"],
            "samples": metrics.get("samples"), "macro_f1": metrics.get("macro_f1"),
            "false_positive_rate": metrics.get("false_positive_rate"),
            "data": self.bundle.get("data"),
        }

    def score(self, ip: str, history: list[Event], now: float) -> dict | None:
        """Prediction for one source, cached between rescoring intervals."""
        if not self.bundle or not history:
            return None
        cached = self._cache.get(ip)
        if cached and len(history) - cached[1] < RESCORE_EVERY_EVENTS and now - cached[0] < RESCORE_EVERY_S:
            return cached[2]

        row = np.array([vector(features(history))])
        probabilities = self.bundle["classifier"].predict_proba(row)[0]
        classes = self.bundle["classes"]
        best = int(np.argmax(probabilities))
        label, confidence = classes[best], float(probabilities[best])
        # decision_function < 0 means the vector is outside what training covered.
        decision = float(self.bundle["isolation"].decision_function(row)[0])
        anomalous = decision < 0

        points = 0
        if label != "BENIGN" and confidence >= self.min_confidence:
            points += round(self.weight * 0.75 * confidence)
        if anomalous:
            points += round(self.weight * 0.25)
        result = {
            "label": label,
            "confidence": round(confidence, 3),
            "probabilities": {c: round(float(p), 3) for c, p in zip(classes, probabilities)},
            "anomaly_score": round(-decision, 3),
            "anomalous": anomalous,
            "points": min(points, self.weight),
        }
        self._cache[ip] = (now, len(history), result)
        return result
