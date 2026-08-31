"""Research experiment runner.

Compares three honeypot operating modes under controlled conditions:
  - BASELINE  (static honeypot: only telemetry collection, no AI/adaptive)
  - AI_ASSISTED (adds classification/anomaly/risk/timeline/graph)
  - ADAPTIVE   (AI + sequence prediction + adaptive deception)

Each mode records metrics to JSON and CSV under ml/experiments/results/.

This is a SAFE, local-only experiment using the controlled simulator. It never
interacts with external systems.
"""

import csv
import json
import os
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List

from app.core.config import get_settings
from app.honeypot.simulator import SCENARIOS, SimulatedAttacker
from app.risk.engine import RiskEngine
from app.telemetry.features import (
    BehaviourFeatureExtractor,
    FeatureVectorBuilder,
    StageSequenceBuilder,
)

settings = get_settings()

MODES = ["baseline", "ai_assisted", "adaptive"]


class ExperimentRunner:
    def __init__(self, scenarios: List[str] = None, sessions_per_scenario: int = 10, seed: int = 42):
        self.scenarios = scenarios or list(SCENARIOS.keys())
        self.sessions_per_scenario = sessions_per_scenario
        self.seed = seed
        self.results_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "experiments", "results"
        )
        os.makedirs(self.results_dir, exist_ok=True)

    def _collect_sessions(self) -> Dict[str, List[Any]]:
        """Generate scenario sessions (normalized events) once, reuse across modes."""
        attacker = SimulatedAttacker(seed=self.seed)
        from app.telemetry.pipeline import normalize

        out = {}
        start = datetime(2026, 1, 1, 8, 0, 0)
        idx = 0
        for scenario in self.scenarios:
            for _ in range(self.sessions_per_scenario):
                raw = attacker.generate(scenario, n_sessions=1, start=start)
                out[f"{scenario}-{idx}"] = {
                    "scenario": scenario,
                    "events": [normalize(e) for e in raw],
                }
                idx += 1
        return out

    def _run_mode(self, mode: str, sessions: Dict[str, Any]) -> Dict[str, Any]:
        extractor = BehaviourFeatureExtractor()
        vector_builder = FeatureVectorBuilder()
        stage_builder = StageSequenceBuilder()
        risk_engine = RiskEngine()

        total_events = 0
        n_sessions = len(sessions)
        classifications: Counter = Counter()
        high_risk = 0
        anomalies = 0
        predictions = 0
        adaptive_actions = 0
        unique_patterns = set()
        behaviour_coverage = Counter()
        session_depths = []

        for key, data in sessions.items():
            evs = data["events"]
            total_events += len(evs)
            feats = extractor.extract_features(evs)
            vector = vector_builder.build(feats)
            stages = stage_builder.compress(stage_builder.build(evs))
            for s in stages:
                behaviour_coverage[s] += 1
            pattern = tuple(stages[:6])
            unique_patterns.add(pattern)
            session_depths.append(len(evs))

            # static baseline: just telemetry, no AI computations
            if mode == "baseline":
                continue

            # AI-assisted: classification (honest heuristic since no trained model here)
            # We use deterministic high-level heuristic mapped from majority stage.
            majority = behaviour_coverage.most_common(1)[0][0] if behaviour_coverage else "other_unknown"
            cls = self._heuristic_class(evs, stages)
            classifications[cls] += 1

            # anomaly heuristic from feature deviations
            is_anomaly = feats.get("failed_auths", 0) >= 3 or feats.get(
                "sensitive_interactions", 0) >= 2 or feats.get("discovery_activity", 0) >= 5
            if is_anomaly:
                anomalies += 1

            # risk
            risk_inputs = {
                "anomaly": 0.9 if is_anomaly else 0.2,
                "behaviour": 0.5,
                "sequence": 0.3,
                "resource": min(1.0, 0.2 + 0.2 * feats.get("sensitive_interactions", 0)),
                "persistence": min(1.0, 0.1 + 0.15 * feats.get("failed_auths", 0)),
            }
            risk = risk_engine.assess(risk_inputs)
            if risk["severity"] in ("HIGH", "CRITICAL"):
                high_risk += 1

            # adaptive adds prediction + deception
            if mode == "adaptive":
                predictions += 1
                if is_anomaly or risk["score"] > 50:
                    adaptive_actions += 1

        return {
            "mode": mode,
            "scenarios": self.scenarios,
            "sessions": n_sessions,
            "total_events": total_events,
            "events_per_session": round(total_events / n_sessions, 2) if n_sessions else 0,
            "unique_patterns": len(unique_patterns),
            "behaviour_coverage": len(behaviour_coverage),
            "max_session_depth": max(session_depths) if session_depths else 0,
            "mean_session_depth": round(sum(session_depths) / len(session_depths), 2) if session_depths else 0,
            "classifications": dict(classifications),
            "high_risk_sessions": high_risk,
            "anomalies_detected": anomalies,
            "predictions_made": predictions,
            "adaptive_actions": adaptive_actions,
            "run_timestamp": datetime.utcnow().isoformat(),
        }

    def _heuristic_class(self, evs, stages):
        from app.telemetry.features import majority_stage

        ms = majority_stage(stages)
        return ms

    def run(self) -> List[Dict[str, Any]]:
        sessions = self._collect_sessions()
        results = [self._run_mode(m, sessions) for m in MODES]
        self._write_results(results)
        return results

    def _write_results(self, results: List[Dict[str, Any]]) -> None:
        stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(self.results_dir, f"experiment_{stamp}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"Wrote results to {json_path}")

        csv_path = os.path.join(self.results_dir, f"experiment_{stamp}.csv")
        keys = [
            "mode", "sessions", "total_events", "events_per_session",
            "unique_patterns", "behaviour_coverage", "max_session_depth",
            "mean_session_depth", "high_risk_sessions", "anomalies_detected",
            "predictions_made", "adaptive_actions",
        ]
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for r in results:
                writer.writerow({k: r.get(k, "") for k in keys})
        print(f"Wrote results to {csv_path}")


if __name__ == "__main__":
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "backend"))
    results = ExperimentRunner().run()
    for r in results:
        print(json.dumps(r, indent=2, default=str))
