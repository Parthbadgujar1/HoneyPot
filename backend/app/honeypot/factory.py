"""Adapter factory.

Resolves a HoneypotAdapter by name. Keeps the telemetry pipeline decoupled
from concrete honeypot implementations.
"""

from typing import Optional

from app.core.config import get_settings
from app.core.logging import get_logger
from app.honeypot.base import HoneypotAdapter
from app.honeypot.cowrie import CowrieAdapter
from app.honeypot.local import LocalSimulatedHoneypot

settings = get_settings()
logger = get_logger("honeypot-factory")


def get_adapter(name: str = "cowrie", **kwargs) -> HoneypotAdapter:
    name = (name or "cowrie").lower()
    if name == "cowrie":
        return CowrieAdapter(log_path=kwargs.get("log_path") or settings.HONEYPOT_COWRIE_JSONL)
    if name in ("local", "local_simulated", "simulated", "sim"):
        return LocalSimulatedHoneypot(**kwargs)
    raise ValueError(f"Unknown honeypot adapter: {name}")


def default_adapter() -> HoneypotAdapter:
    """Return the adapter selected by HONEYPOT_ADAPTER.

    Defaults to LocalSimulatedHoneypot so the demo works in any isolated
    environment without Docker. Set HONEYPOT_ADAPTER=cowrie (and point
    HONEYPOT_COWRIE_JSONL at live logs) to consume a real Cowrie honeypot.
    Unknown/invalid values fall back to the local simulator rather than
    crashing startup.
    """
    try:
        return get_adapter(settings.HONEYPOT_ADAPTER)
    except ValueError:
        logger.warning(
            "Unknown HONEYPOT_ADAPTER=%r, falling back to local_simulated",
            settings.HONEYPOT_ADAPTER,
        )
        return LocalSimulatedHoneypot()
