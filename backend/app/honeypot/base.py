"""Abstract honeypot adapter interface.

This decouples the telemetry pipeline from any specific honeypot implementation.
An adapter is responsible for exposing the health/state of a honeypot and for
producing normalized events (RawEvent) that flow into the pipeline.
"""

from abc import ABC, abstractmethod
from typing import Iterator, List, Optional

from app.schemas.event import RawEvent


class HoneypotAdapter(ABC):
    """Base class for honeypot integrations."""

    name: str = "base"
    service: str = "unknown"

    @abstractmethod
    def status(self) -> dict:
        """Return health/status information about the honeypot."""

    @abstractmethod
    def start(self) -> None:
        """Start/verify the honeypot."""

    @abstractmethod
    def stop(self) -> None:
        """Stop the honeypot (safe, local only)."""

    @abstractmethod
    def read_events(self) -> Iterator[RawEvent]:
        """Yield normalized events collected since the last call."""

    def availableActions(self) -> List[str]:
        return []


class FileBasedAdapter(HoneypotAdapter):
    """Base class for adapters that read from local log files (safe/read-only)."""

    def __init__(self, log_path: str = "", service: str = "unknown"):
        self.log_path = log_path
        self.service = service
        self._seen_positions: dict = {}

    def status(self) -> dict:
        import os

        exists = os.path.exists(self.log_path)
        return {
            "adapter": self.name,
            "service": self.service,
            "online": exists,
            "log_path": self.log_path,
        }
