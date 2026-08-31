"""Local simulated honeypot adapter.

Generates controlled synthetic telemetry in-process so the full pipeline can be
demonstrated in an isolated environment without requiring Docker/Cowrie.

This is a SAFE, local-only source of events; it never communicates with any
external system. It exposes the same HoneypotAdapter interface as Cowrie, so
the pipeline is agnostic to the source.
"""

from datetime import datetime
from queue import Queue
from typing import Iterator, List, Optional

from app.honeypot.base import HoneypotAdapter
from app.honeypot.simulator import SCENARIOS, SimulatedAttacker
from app.schemas.event import RawEvent


class LocalSimulatedHoneypot(HoneypotAdapter):
    name = "local_simulated"
    service = "ssh"

    def __init__(self, seed: int = 42, queue: Optional[Queue] = None):
        self.seed = seed
        self.queue = queue if queue is not None else Queue()
        self._attacker = SimulatedAttacker(seed=seed)
        self._running = True

    def scenario_names(self) -> List[str]:
        return list(SCENARIOS.keys())

    def status(self) -> dict:
        return {
            "adapter": self.name,
            "service": self.service,
            "online": self._running,
            "mode": "simulated",
            "seed": self.seed,
            "queued_events": self.queue.qsize(),
        }

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    def reset(self, seed: Optional[int] = None) -> None:
        if seed is not None:
            self.seed = seed
        self._attacker = SimulatedAttacker(seed=self.seed)
        self._clear()

    def _clear(self) -> None:
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
            except Exception:
                break

    def emit_scenario(self, scenario: str, n_sessions: int = 3) -> int:
        events = self._attacker.generate(scenario, n_sessions=n_sessions)
        for e in events:
            self.queue.put(e)
        return len(events)

    def emit_adaptive_response(self, action: str, target: str) -> int:
        """Emit events representing the honeypot responding to adaptive policy
        activation (e.g., a new decoy becoming available), producing more
        telemetry for the pipeline to collect."""
        attacker = SimulatedAttacker(seed=self.seed)
        n = self.rng_or_zero()
        session = f"SIM-{self.seed}-ADAPTIVE"
        ts = datetime.utcnow()
        evs = self._build_adaptive_events(session, ts, action, target)
        for e in evs:
            self.queue.put(e)
        return len(evs)

    def _build_adaptive_events(self, session, ts, action, target):
        from app.schemas.event import RawEvent

        base = dict(
            timestamp=ts,
            session_id=session,
            source="10.0.0.100",
            destination="127.0.0.1",
            service="ssh",
            result="success",
        )
        evs = [
            RawEvent(
                **base,
                event_type="deception_action",
                action="decoy_activated",
                target=target,
                metadata={"policy_action": action},
            ),
            RawEvent(
                **base,
                timestamp=ts,
                event_type="connection",
                action="connect",
            ),
            RawEvent(
                **base,
                timestamp=ts,
                event_type="command",
                action="file_read",
                target=target,
                command=f"cat /opt/decoy/{target}",
            ),
        ]
        return evs

    def rng_or_zero(self):
        return 0

    def read_events(self, _limit: Optional[int] = None) -> Iterator[RawEvent]:
        emitted = 0
        while not self.queue.empty():
            item = self.queue.get_nowait()
            yield item
            emitted += 1
            if _limit and emitted >= _limit:
                return
