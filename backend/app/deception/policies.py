"""Predefined safe deception policies.

Each policy defines trigger conditions, allowed actions, safety level, rollback
action, cooldown, and audit metadata. All actions are local, reversible,
non-destructive, and confined to the honeypot environment.
"""

from typing import Any, Dict, List, Optional


class DeceptionPolicyDefinition:
    def __init__(
        self,
        policy_id: str,
        name: str,
        description: str,
        allowed_actions: List[str],
        rollback_action: str,
        safety_level: str = "safe",
        cooldown_seconds: int = 60,
        decoy: Optional[str] = None,
        target: Optional[str] = None,
        weight: float = 1.0,
    ):
        self.policy_id = policy_id
        self.name = name
        self.description = description
        self.allowed_actions = allowed_actions
        self.rollback_action = rollback_action
        self.safety_level = safety_level
        self.cooldown_seconds = cooldown_seconds
        self.decoy = decoy
        self.target = target
        self.weight = weight

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "description": self.description,
            "allowed_actions": self.allowed_actions,
            "rollback_action": self.rollback_action,
            "safety_level": self.safety_level,
            "cooldown_seconds": self.cooldown_seconds,
            "decoy": self.decoy,
            "target": self.target,
            "weight": self.weight,
        }


POLICIES: List[DeceptionPolicyDefinition] = [
    DeceptionPolicyDefinition(
        policy_id="policy_keep_baseline",
        name="Maintain baseline environment",
        description="Keep the current honeypot configuration unchanged.",
        allowed_actions=["none"],
        rollback_action="none",
        cooldown_seconds=0,
    ),
    DeceptionPolicyDefinition(
        policy_id="policy_enable_db_decoy",
        name="Enable database decoy",
        description="Activate an additional synthetic database decoy resource.",
        allowed_actions=["enable_decoy"],
        rollback_action="disable_decoy",
        decoy="decoy_database",
        target="db_credentials.conf",
        weight=1.4,
    ),
    DeceptionPolicyDefinition(
        policy_id="policy_expose_config_decoy",
        name="Expose configuration decoy",
        description="Expose a controlled fake configuration artifact.",
        allowed_actions=["enable_decoy"],
        rollback_action="disable_decoy",
        decoy="decoy_config",
        target="settings.ini",
        weight=1.3,
    ),
    DeceptionPolicyDefinition(
        policy_id="policy_enable_resource_decoy",
        name="Enable resource decoy",
        description="Enable an additional fake resource directory.",
        allowed_actions=["enable_decoy"],
        rollback_action="disable_decoy",
        decoy="decoy_resource",
        target="customer_records.csv",
        weight=1.2,
    ),
    DeceptionPolicyDefinition(
        policy_id="policy_change_decoy_content",
        name="Change decoy content",
        description="Regenerate decoy content within the isolated environment.",
        allowed_actions=["change_content"],
        rollback_action="restore_content",
        decoy="decoy_content",
        target="keys.pem",
        weight=1.1,
    ),
]


def get_policy(policy_id: str) -> Optional[DeceptionPolicyDefinition]:
    for p in POLICIES:
        if p.policy_id == policy_id:
            return p
    return None
