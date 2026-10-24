"""Load and validate the sensor configuration."""

from __future__ import annotations

import copy
import ipaddress
import json
import os
from pathlib import Path

SENSOR_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SENSOR_DIR.parents[1]  # HoneyPot/ (holds the ML models)
DEFAULT_CONFIG_PATH = SENSOR_DIR / "config.json"
CONFIG_ENV_VAR = "HONEYPOT_SENSOR_CONFIG"


def _deep_merge(base: dict, override: dict) -> dict:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(path: str | Path | None = None) -> dict:
    """Load defaults, then merge the optional override file on top."""
    config = json.loads(DEFAULT_CONFIG_PATH.read_text(encoding="utf-8"))

    override_path = path or os.getenv(CONFIG_ENV_VAR)
    if override_path:
        override = json.loads(Path(override_path).read_text(encoding="utf-8"))
        config = _deep_merge(config, override)

    validate_config(config)
    return config


def sensor_path(value: str) -> Path:
    """Resolve a path from the config that lives under sensor/ (e.g. data/...)."""
    path = Path(value)
    return path if path.is_absolute() else (SENSOR_DIR / path)


def data_path(config: dict, key: str) -> Path:
    """Resolve a top-level config path that lives under sensor/."""
    return sensor_path(config[key])


def model_path(name: str) -> Path:
    """Resolve an ML model or schema file relative to the project root."""
    path = Path(name)
    return path if path.is_absolute() else (PROJECT_ROOT / path)


def enabled_ports(config: dict) -> dict[int, str]:
    """Map every port a decoy listener will bind to its service name."""
    ports: dict[int, str] = {}
    decoys = config["decoys"]

    if decoys["ssh"]["enabled"]:
        ports[int(decoys["ssh"]["port"])] = "ssh"
    if decoys["http"]["enabled"]:
        ports[int(decoys["http"]["port"])] = "http"
    if decoys["bait"]["enabled"]:
        for port, service in decoys["bait"]["services"].items():
            ports[int(port)] = service
    return ports


def validate_config(config: dict) -> None:
    """Fail fast on configuration mistakes that would silently break decoys."""
    seen: dict[int, str] = {}
    decoys = config["decoys"]

    candidates = []
    if decoys["ssh"]["enabled"]:
        candidates.append(("ssh", int(decoys["ssh"]["port"])))
    if decoys["http"]["enabled"]:
        candidates.append(("http", int(decoys["http"]["port"])))
    if decoys["bait"]["enabled"]:
        candidates.extend(
            (service, int(port))
            for port, service in decoys["bait"]["services"].items()
        )
    if config["admin"]["enabled"]:
        candidates.append(("admin", int(config["admin"]["port"])))

    for name, port in candidates:
        if not 1 <= port <= 65535:
            raise ValueError(f"{name} port {port} is outside 1-65535")
        if port in seen:
            raise ValueError(
                f"Port {port} is assigned to both {seen[port]} and {name}"
            )
        seen[port] = name

    if config["admin"]["enabled"]:
        admin_host = ipaddress.ip_address(config["admin"]["host"])
        if not admin_host.is_loopback:
            raise ValueError(
                "admin.host must be a loopback address (127.0.0.1 or ::1); "
                "the operator console must never listen on the network"
            )

    thresholds = config["detection"]
    if thresholds["severity_medium_score"] >= thresholds["severity_high_score"]:
        raise ValueError("severity_medium_score must be below severity_high_score")

    response = config["response"]
    if not 0 <= response["block_min_score"] <= 100:
        raise ValueError("block_min_score must be between 0 and 100")
