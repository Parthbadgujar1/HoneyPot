"""Adaptive deception engine.

Selects safe, predefined deception policies based on observed behaviour via
deterministic rules, then executes local, reversible, auditable actions.

This engine NEVER attacks, retaliates, or modifies anything outside the local
honeypot. All actions only toggle predefined local decoy configuration.
"""

import threading
import time
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.deception.policies import (
    POLICIES,
    DeceptionPolicyDefinition,
    get_policy,
)
from app.models.models import (
    AdaptiveDecision,
    DeceptionAction,
    DeceptionPolicy,
)
from app.services.audit import write_audit

logger = get_logger("deception-engine")

# Safe, predefined local decoys that can be toggled.
DECOY_REGISTRY = {
    "decoy_database": {
        "name": "Synthetic Database Decoy",
        "target": "db_credentials.conf",
        "description": "Synthetic DB credential artifact presented as a honeypot resource.",
    },
    "decoy_config": {
        "name": "Synthetic Config Decoy",
        "target": "settings.ini",
        "description": "Synthetic configuration artifact.",
    },
    "decoy_resource": {
        "name": "Synthetic Resource Decoy",
        "target": "customer_records.csv",
        "description": "Synthetic sensitive resource.",
    },
    "decoy_content": {
        "name": "Regenerable Decoy Content",
        "target": "keys.pem",
        "description": "Regenerable fake private key artifact.",
    },
}


class DecoyEnvironment:
    """Snapshot of which safe local decoys are currently active."""

    _instance = None

    def __new__(cls):
        # Module-level singleton so all DeceptionEngine instances share state.
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, "_active"):
            self._active: Dict[str, bool] = {k: False for k in DECOY_REGISTRY}
            self._lock = threading.Lock()

    def activate(self, decoy: str) -> bool:
        if decoy not in self._active:
            return False
        with self._lock:
            self._active[decoy] = True
        return True

    def deactivate(self, decoy: str) -> bool:
        if decoy not in self._active:
            return False
        with self._lock:
            self._active[decoy] = False
        return True

    def snapshot(self) -> List[Dict[str, Any]]:
        result = []
        for decoy, active in self._active.items():
            info = dict(DECOY_REGISTRY[decoy])
            info["decoy"] = decoy
            info["active"] = active
            result.append(info)
        return result


class DeceptionEngine:
    def __init__(self, db: Session, adapter=None):
        self.db = db
        self.adapter = adapter  # HoneypotAdapter that can emit controlled telemetry
        self.environment = DecoyEnvironment()
        self._last_action_by_session: Dict[str, float] = {}
        self._seed_policies()

    def _seed_policies(self) -> None:
        for p in POLICIES:
            existing = (
                self.db.query(DeceptionPolicy)
                .filter(DeceptionPolicy.policy_id == p.policy_id)
                .first()
            )
            if not existing:
                self.db.add(
                    DeceptionPolicy(
                        policy_id=p.policy_id,
                        name=p.name,
                        description=p.description,
                        trigger_conditions=p.to_dict().get("trigger_conditions", {}),
                        allowed_actions=p.allowed_actions,
                        safety_level=p.safety_level,
                        rollback_action=p.rollback_action,
                        cooldown_seconds=p.cooldown_seconds,
                        is_enabled=True,
                    )
                )
        self.db.commit()

    def select_policy(self, analysis: Dict[str, Any], risk_score: float = 0.0) -> DeceptionPolicyDefinition:
        """Deterministic rule-based policy selection."""
        features = analysis.get("features", {}) or {}
        classification = analysis.get("classification", {}) or {}
        cls_label = classification.get("behaviour_class", "")
        sens = features.get("sensitive_interactions", 0)
        discovery = features.get("discovery_activity", 0)
        failed = features.get("failed_auths", 0)

        # derive interest target from feature/target evidence
        events_targets = analysis.get("_targets", [])
        interests = [t.lower() for t in events_targets if t]
        interest_db = any("db" in t or "database" in t or "credential" in t for t in interests) or sens > 0
        interest_config = any("config" in t or "ini" in t or "settings" in t for t in interests)
        repeated_discovery = discovery >= 3
        credential_abuse = failed >= 3 or cls_label == "credential_abuse"

        if interest_config and risk_score > 55:
            return get_policy("policy_expose_config_decoy")
        if interest_db and risk_score > 55:
            return get_policy("policy_enable_db_decoy")
        if repeated_discovery and risk_score > 50:
            return get_policy("policy_enable_resource_decoy")
        if credential_abuse and risk_score > 45:
            return get_policy("policy_change_decoy_content")
        return get_policy("policy_keep_baseline")

    def evaluate(self, session_id: str, analysis: Dict[str, Any], risk_score: float = 0.0) -> Dict[str, Any]:
        policy = self.select_policy(analysis, risk_score=risk_score)
        inputs = {
            "session_id": session_id,
            "features": analysis.get("features", {}),
            "classification": analysis.get("classification", {}),
            "anomaly": analysis.get("anomaly", {}),
            "risk_inputs": analysis.get("risk_inputs", {}),
        }

        # cooldown guard
        last = self._last_action_by_session.get(session_id, 0)
        if policy.cooldown_seconds and (time.time() - last) < policy.cooldown_seconds:
            policy = get_policy("policy_keep_baseline")

        decision = {
            "session_id": session_id,
            "policy_id": policy.policy_id,
            "policy_name": policy.name,
            "decision": "adapt" if policy.policy_id != "policy_keep_baseline" else "maintain",
            "selected_policy": policy.to_dict(),
            "inputs": inputs,
            "action": policy.allowed_actions[0] if policy.allowed_actions else "none",
        }
        self._record_decision(decision, session_id)
        self._last_action_by_session[session_id] = time.time()

        if decision["decision"] == "adapt" and policy.decoy:
            self._execute(decision, policy, session_id)
        return decision

    def _execute(
        self, decision: Dict, policy: DeceptionPolicyDefinition, session_id: str
    ) -> None:
        activated = self.environment.activate(policy.decoy or "")
        reason = decision.get("policy_name", "")
        # record deed
        action_row = DeceptionAction(
            session_id=session_id,
            policy_id=policy.policy_id,
            action=policy.allowed_actions[0],
            reason=reason,
            inputs={"decoy": policy.decoy, "target": policy.target},
            status="executed",
            result={"decoy_active": activated, "target": policy.target},
            rollback_status=None,
        )
        self.db.add(action_row)
        self.db.flush()
        decision["action_id"] = str(action_row.id)
        decision["result"] = action_row.result

        # emit controlled telemetry from the decoy becoming available
        emitted = 0
        if self.adapter is not None and activated and hasattr(self.adapter, "emit_adaptive_response"):
            try:
                emitted = self.adapter.emit_adaptive_response(
                    policy.allowed_actions[0], policy.target or ""
                )
            except Exception as e:  # pragma: no cover
                logger.warning("Failed to emit adaptive telemetry: %s", e)

        action_row.result = {**action_row.result, "telemetry_emitted": emitted}
        self.db.add(action_row)
        self.db.commit()
        write_audit(
            self.db,
            action="deception_policy_executed",
            user_id=None,
            resource_type="deception_action",
            resource_id=policy.policy_id,
            details={"session_id": session_id, "policy": policy.policy_id, "action": policy.allowed_actions},
        )

    def _record_decision(self, decision: Dict, session_id: str) -> None:
        row = AdaptiveDecision(
            session_id=session_id,
            policy_id=decision["policy_id"],
            decision=decision["decision"],
            inputs=decision.get("inputs"),
            selected_policy=decision.get("selected_policy"),
            action=decision.get("action"),
        )
        self.db.add(row)
        self.db.commit()

    def rollback(self, action_id: str) -> Dict[str, Any]:
        action_row = (
            self.db.query(DeceptionAction)
            .filter(DeceptionAction.id == action_id)
            .first()
        )
        if not action_row:
            raise ValueError("Deception action not found")
        policy = get_policy(action_row.policy_id)
        decoy = policy.decoy if policy else None
        if decoy:
            self.environment.deactivate(decoy)
        action_row.rollback_status = "rolled_back"
        self.db.add(action_row)
        self.db.commit()
        write_audit(
            self.db,
            action="deception_policy_rolled_back",
            resource_type="deception_action",
            resource_id=action_id,
            details={"decoy": decoy, "policy": action_row.policy_id},
        )
        return {
            "action_id": action_id,
            "policy_id": action_row.policy_id,
            "status": "rolled_back",
            "decoy": decoy,
            "environment": self.environment.snapshot(),
        }

    def environment_status(self) -> Dict[str, Any]:
        return {
            "decoys": self.environment.snapshot(),
            "active_count": sum(1 for d in self.environment.snapshot() if d["active"]),
        }
