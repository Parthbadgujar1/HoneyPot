"""Shared behaviour-action mapping helpers used for feature extraction and
timeline/graph construction.

This maps raw event types/commands into high-level categorical labels so that
the ML feature space is stable regardless of the specific honeypot source.
"""

import re

# Behaviour-stage labels used by the classifier and sequence model.
BEHAVIOUR_STAGES = [
    "reconnaissance",
    "credential_abuse",
    "discovery",
    "resource_access",
    "suspicious_execution",
    "data_collection",
    "other_unknown",
]

# Sensitive resource keywords that indicate interaction with decoy-sensitive data.
SENSITIVE_KEYWORDS = [
    "database",
    "db_",
    "config",
    "secret",
    "credential",
    "password",
    "account",
    "key",
    "token",
    "backup",
    "shadow",
    "passwd",
    "financial",
    "customer",
    "employee",
    "production",
    "api_key",
    "admin",
]


DISCOVERY_HINTS = [
    "ls",
    "dir",
    "pwd",
    "find",
    "locate",
    "whoami",
    "id",
    "uname",
    "cat /etc",
    "env",
    "printenv",
    "ifconfig",
    "ip addr",
    "hostname",
    "wget",
    "curl",
]


def classify_command_action(command: str) -> str:
    """Map a shell command string to a normalized action label."""
    cmd = (command or "").strip().lower()
    if not cmd:
        return "other"

    if cmd in ("ls", "dir") or cmd.startswith("ls ") or cmd.startswith("dir "):
        return "directory_listing"
    if cmd.startswith("cd "):
        return "directory_change"
    if cmd in ("pwd", "whoami", "id", "uname", "hostname", "env", "printenv"):
        return "system_discovery"
    if cmd.startswith("cat ") or cmd.startswith("type "):
        return "file_read"
    if cmd.startswith("find ") or cmd.startswith("locate "):
        return "file_search"
    if cmd.startswith("rm ") or cmd.startswith("del "):
        return "file_delete"
    if cmd.startswith("cp ") or cmd.startswith("mv ") or cmd.startswith("copy "):
        return "file_manipulation"
    if cmd.startswith("chmod ") or cmd.startswith("chown "):
        return "file_permission_change"
    if cmd.startswith("mkdir "):
        return "directory_create"
    if cmd.startswith("wget ") or cmd.startswith("curl ") or cmd.startswith("nc "):
        return "network_exfil"
    if cmd.startswith("sudo ") or cmd.startswith("su "):
        return "privilege_escalation"
    if cmd.startswith("ps ") or cmd.startswith("top"):
        return "process_discovery"
    if cmd.startswith("ifconfig") or cmd.startswith("ip "):
        return "network_discovery"
    if "password" in cmd or "passwd" in cmd or "shadow" in cmd:
        return "credential_interaction"
    if cmd.startswith("exit"):
        return "session_exit"
    if cmd.startswith("unzip") or cmd.startswith("tar "):
        return "archive"
    if cmd.startswith("apt ") or cmd.startswith("yum ") or cmd.startswith("pip "):
        return "tool_install"
    return "other_command"


def action_to_stage(action: str) -> str:
    """Map a normalized action label to a behaviour stage."""
    if action in (
        "directory_listing",
        "system_discovery",
        "file_search",
        "network_discovery",
        "process_discovery",
        "directory_change",
    ):
        return "discovery"
    if action in (
        "authentication",
        "credential_attempt",
        "credential_interaction",
        "brute_force",
        "privilege_escalation",
        "account_enumeration",
    ):
        return "credential_abuse"
    if action in (
        "file_read",
        "file_access",
        "resource_access",
        "database_access",
        "config_access",
    ):
        return "resource_access"
    if action in (
        "file_delete",
        "file_manipulation",
        "file_write",
        "command_execution",
        "tool_install",
        "archive",
    ):
        return "suspicious_execution"
    if action in ("network_exfil", "data_exfil", "data_collection", "upload", "download"):
        return "data_collection"
    if action in ("port_scan", "banner_grab", "fingerprint"):
        return "reconnaissance"
    return "other_unknown"


def is_sensitive_target(target: Optional[str]) -> bool:
    if not target:
        return False
    low = target.lower()
    return any(k in low for k in SENSITIVE_KEYWORDS)


def is_discovery_action(action: str, command: Optional[str] = None) -> bool:
    if action in (
        "directory_listing",
        "system_discovery",
        "file_search",
        "network_discovery",
        "process_discovery",
    ):
        return True
    if command:
        return any(h in command.lower() for h in DISCOVERY_HINTS)
    return False


def extract_username_from_attempt(username: Optional[str]) -> Optional[str]:
    if not username:
        return None
    return username.strip()
