"""Feature engineering.

Computes behavioural features from a session's events and builds fixed-size
numeric vectors for ML models. Features are versioned for reproducibility.
"""

import math
from collections import Counter
from typing import Dict, List, Optional

from app.schemas.event import NormalizedEvent
from app.telemetry.action_catalog import (
    action_to_stage,
    is_discovery_action,
    is_sensitive_target,
)

FEATURE_VERSION = "v1"

# Ordered feature vector schema used by all supervised/unsupervised models.
FEATURE_NAMES = [
    "duration_seconds",
    "events_per_minute",
    "mean_inter_event_time",
    "var_inter_event_time",
    "burst_frequency",
    "failed_auths",
    "successful_auths",
    "unique_usernames",
    "auth_ratio",
    "command_count",
    "unique_commands",
    "action_diversity",
    "resource_diversity",
    "repeated_actions",
    "discovery_activity",
    "sensitive_interactions",
    "connection_count",
    "service_diversity",
    "request_frequency",
]

CATEGORICAL_STAGES = [
    "reconnaissance",
    "credential_abuse",
    "discovery",
    "resource_access",
    "suspicious_execution",
    "data_collection",
    "other_unknown",
]


class BehaviourFeatureExtractor:
    def __init__(self, version: str = FEATURE_VERSION):
        self.version = version

    def extract_features(self, events: List[NormalizedEvent]) -> Dict[str, float]:
        evs = sorted(events, key=lambda e: e.timestamp)
        if not evs:
            return {name: 0.0 for name in FEATURE_NAMES}

        start = evs[0].timestamp
        end = evs[-1].timestamp
        duration = max((end - start).total_seconds(), 0.0001)

        times = [e.timestamp for e in evs]
        inter = []
        for a, b in zip(times, times[1:]):
            inter.append((b - a).total_seconds())
        mean_inter = sum(inter) / len(inter) if inter else 0.0
        var_inter = (
            sum((x - mean_inter) ** 2 for x in inter) / len(inter) if inter else 0.0
        )

        total_minutes = duration / 60.0
        events_per_minute = len(evs) / total_minutes if total_minutes > 0 else 0.0

        # burst frequency: consecutive events with very small inter-event gaps
        burst = sum(1 for x in inter if x < 1.0) if inter else 0
        burst_freq = burst / total_minutes if total_minutes > 0 else 0.0

        failed_auths = sum(
            1
            for e in evs
            if e.event_type == "authentication_failure"
            or (e.event_type == "authentication" and e.result == "failure")
        )
        successful_auths = sum(
            1
            for e in evs
            if e.event_type == "authentication_success"
            or (e.event_type == "authentication" and e.result == "success")
        )
        usernames = {
            e.username
            for e in evs
            if e.username and e.event_type in (
                "authentication_failure",
                "authentication_success",
                "authentication",
            )
        }
        auth_total = failed_auths + successful_auths
        auth_ratio = failed_auths / auth_total if auth_total > 0 else 0.0

        commands = [e.command for e in evs if e.command]
        command_count = len(commands)
        unique_commands = len(set(commands))

        actions = [e.action for e in evs if e.action]
        action_diversity = len(set(actions))
        resource_diversity = len({e.target for e in evs if e.target})
        repeated_actions = command_count - (len(set(commands)) if commands else 0)

        discovery_activity = sum(1 for e in evs if is_discovery_action(e.action, e.command))
        sensitive_interactions = sum(1 for e in evs if is_sensitive_target(e.target))

        connection_count = sum(
            1 for e in evs if e.event_type == "connection" or e.action == "connect"
        )
        service_diversity = len({e.service for e in evs if e.service})
        request_frequency = (
            sum(1 for e in evs if e.event_type in ("request", "command"))
        ) / total_minutes if total_minutes > 0 else 0.0

        return {
            "duration_seconds": duration,
            "events_per_minute": events_per_minute,
            "mean_inter_event_time": mean_inter,
            "var_inter_event_time": var_inter,
            "burst_frequency": burst_freq,
            "failed_auths": failed_auths,
            "successful_auths": successful_auths,
            "unique_usernames": len(usernames),
            "auth_ratio": auth_ratio,
            "command_count": command_count,
            "unique_commands": unique_commands,
            "action_diversity": action_diversity,
            "resource_diversity": resource_diversity,
            "repeated_actions": repeated_actions,
            "discovery_activity": discovery_activity,
            "sensitive_interactions": sensitive_interactions,
            "connection_count": connection_count,
            "service_diversity": service_diversity,
            "request_frequency": request_frequency,
        }


class FeatureVectorBuilder:
    """Builds a fixed-size numeric vector from the feature dict for ML."""

    def __init__(self, names: Optional[List[str]] = None):
        self.names = names or FEATURE_NAMES

    def build(self, features: Dict[str, float]) -> List[float]:
        return [float(features.get(name, 0.0)) for name in self.names]

    def build_matrix(self, features_list: List[Dict[str, float]]) -> List[List[float]]:
        return [self.build(f) for f in features_list]


class StageSequenceBuilder:
    """Builds a sequence of behaviour stages from events (for sequence models)."""

    def build(self, events: List[NormalizedEvent]) -> List[str]:
        evs = sorted(events, key=lambda e: e.timestamp)
        seq = []
        for e in evs:
            stage = action_to_stage(e.action or "") or "other_unknown"
            seq.append(stage)
        return seq

    def compress(self, stages: List[str]) -> List[str]:
        """Remove consecutive duplicates to get a compact stage progression."""
        result = []
        for s in stages:
            if not result or result[-1] != s:
                result.append(s)
        return result


def majority_stage(stages: List[str]) -> str:
    if not stages:
        return "other_unknown"
    counts = Counter(stages)
    return counts.most_common(1)[0][0]
