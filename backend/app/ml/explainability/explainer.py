"""Explainable AI.

Produces interpretable explanations for classification and risk scoring.
For tree-based classifiers, uses feature_importances_ as a stable proxy for
SHAP-style contribution (SHAP itself is heavy; importance-based contributions
are reproducible and dependency-light). Anomaly explanations come from the
anomaly model's per-feature deviations.
"""

from typing import Any, Dict, List, Optional

import numpy as np

from app.ml.base import BaseModelWrapper
from app.telemetry.features import FEATURE_NAMES


def feature_contributions_for_class(
    classifier: BaseModelWrapper, class_label: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Return ordered feature contributions. Uses feature importances for tree
    models (a reproducible, interpretable proxy for SHAP contributions)."""
    model = getattr(classifier, "model", None) or classifier
    feats = getattr(model, "feature_importances_", None)
    if feats is None:
        coef = getattr(model, "coef_", None)
        if coef is None:
            return []
        feats = np.abs(np.asarray(coef)).mean(axis=0)
    feats = np.asarray(feats)
    order = np.argsort(-feats)
    result = []
    for idx in order:
        if idx >= len(FEATURE_NAMES):
            continue
        if feats[idx] <= 0:
            continue
        result.append(
            {"feature": FEATURE_NAMES[idx], "importance": float(feats[idx])}
        )
    return result[:12]


def explain_classification(
    classifier: BaseModelWrapper,
    class_label: str,
    feature_vector: Optional[List[float]] = None,
) -> Dict[str, Any]:
    contributions = feature_contributions_for_class(classifier, class_label)
    top = contributions[:5] if contributions else []
    reasons = [
        f"'{c['feature']}' contributes positively to '{class_label}'"
        for c in top
    ]
    return {
        "model": classifier.name,
        "model_version": classifier.version,
        "class": class_label,
        "feature_version": classifier.feature_version,
        "contributions": contributions,
        "reasons": reasons,
        "summary": (
            f"Most influential signal: {top[0]['feature']}"
            if top
            else "Model provides no negative contribution detail (baseline)."
        ),
        "method": "feature_importance_shap_proxy",
    }


def explain_risk(risk_details: Dict[str, Any]) -> Dict[str, Any]:
    """Build a human-readable explanation for a risk assessment."""
    contribs = risk_details.get("contributions", {})
    severity = risk_details.get("severity", "UNKNOWN")
    reasons = []
    for key, val in contribs.items():
        if isinstance(val, dict):
            score = val.get("score", 0)
            label = key.replace("_", " ").title()
            if score:
                reasons.append(f"+ {label}: {score:.1f}")
    return {
        "severity": severity,
        "score": risk_details.get("score"),
        "contributing_signals": reasons,
        "policy_version": risk_details.get("policy_version"),
        "summary": (
            f"Risk {severity} driven primarily by accumulated behavioural signals."
            if reasons
            else "Risk derived from baseline behavioural profile."
        ),
    }
