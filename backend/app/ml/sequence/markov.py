"""Sequence prediction baseline using a Markov transition model over behaviour
stages. Given a partial stage sequence it predicts the likely next stage with
top-1/top-3 probabilities.
"""

from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.ml.base import BaseModelWrapper
from app.telemetry.features import CATEGORICAL_STAGES


class MarkovSequencePredictor(BaseModelWrapper):
    name = "markov"
    model_type = "sequence"
    feature_version = "v1"

    def __init__(self, version: str = "v0", smooth: float = 0.1, **kwargs):
        super().__init__(version=version)
        self.smooth = smooth
        self.transitions: Dict[str, Dict[str, float]] = {}
        self.stage_counts: Dict[str, float] = defaultdict(float)
        self.classes = CATEGORICAL_STAGES

    def fit(self, X, y=None) -> "MarkovSequencePredictor":
        """X is a list of stage sequences (list of lists of stage labels)."""
        for seq in X:
            for i in range(len(seq) - 1):
                a, b = seq[i], seq[i + 1]
                self.stage_counts[a] += 1
                self.transitions.setdefault(a, defaultdict(float))
                self.transitions[a][b] += 1
        # optional y (labels) accepted for interface compatibility
        self.trained_at = datetime.utcnow()
        return self

    def _next_probs(self, last_stage: str) -> Dict[str, float]:
        if last_stage not in self.transitions:
            return {c: 1.0 / len(self.classes) for c in self.classes}
        counts = self.transitions[last_stage]
        total = sum(counts.values())
        probs = {}
        for c in self.classes:
            probs[c] = (counts.get(c, 0.0) + self.smooth) / (
                total + self.smooth * len(self.classes)
            )
        # normalize
        s = sum(probs.values())
        return {k: v / s for k, v in probs.items()}

    def predict_next(self, seq: List[str], k: int = 3) -> Dict[str, Any]:
        if not seq:
            last = None
            flat = {}
        else:
            last = seq[-1]
            flat = self._next_probs(last)
            # fall back to global distribution if no transitions for stage
            if last not in self.transitions and self.stage_counts:
                total = sum(self.stage_counts.values())
                flat = {c: self.stage_counts.get(c, 0.0) / total for c in self.classes}
                s = sum(flat.values()) or 1.0
                flat = {c: v / s for c, v in flat.items()}

        ranked = sorted(flat.items(), key=lambda x: -x[1])
        top_k = [{"stage": st, "probability": round(p, 4)} for st, p in ranked[:k]]
        top1 = top_k[0] if top_k else None
        return {
            "input_sequence": seq,
            "top_predictions": top_k,
            "top1": top1["stage"] if top1 else None,
            "top1_probability": top1["probability"] if top1 else 0.0,
            "model": self.name,
            "model_version": self.version,
        }

    def predict(self, X) -> Any:
        return [self.predict_next(seq)["top1"] for seq in X]

    def evaluate(self, sequences: List[List[str]], k: int = 3) -> Dict[str, Any]:
        hits1 = hits3 = 0
        mrr = 0.0
        total = 0
        for seq in sequences:
            if len(seq) < 2:
                continue
            truth = seq[-1]
            hist = seq[:-1]
            pred = self.predict_next(hist, k=k)
            ranked = [p["stage"] for p in pred["top_predictions"]]
            total += 1
            if ranked and ranked[0] == truth:
                hits1 += 1
            if truth in ranked:
                hits3 += 1
                mrr += 1.0 / (ranked.index(truth) + 1)
        top1_acc = hits1 / total if total else 0
        top3_acc = hits3 / total if total else 0
        mrr = mrr / total if total else 0
        self.metrics = {
            "top1_accuracy": top1_acc,
            "top3_accuracy": top3_acc,
            "mrr": mrr,
            "sequences_evaluated": total,
        }
        return self.metrics
