"""Adapter factory.

Resolves a HoneypotAdapter by name. Keeps the telemetry pipeline decoupled
from concrete honeypot implementations.
"""

from typing import Optional

from app.core.config import get_settings
from app.honeypot.base import HoneypotAdapter
from app.honeypot.cowrie import CowrieAdapter
from app.honeypot.local import LocalSimulatedHoneypot

settings = get_settings()


def get_adapter(name: str = "cowrie", **kwargs) -> HoneypotAdapter:
    name = (name or "cowrie").lower()
    if name == "cowrie":
        return CowrieAdapter(log_path=kwargs.get("log_path") or settings.HONEYPOT_COWRIE_JSONL)
    if name in ("local", "simulated", "sim"):
        return LocalSimulatedHoneypot(**kwargs)
    raise ValueError(f"Unknown honeypot adapter: {name}")


def default_adapter() -> HoneypotAdapter:
    """Return the default adapter. LocalSimulatedHoneypot generates events
    in-process so the demo works in any isolated environment without Docker."""
    return LocalSimulatedHoneypot()
