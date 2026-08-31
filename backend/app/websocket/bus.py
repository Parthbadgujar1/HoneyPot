"""Thread-safe in-memory event bus for WebSocket real-time updates.

Services (including the background telemetry collector) publish events; each
WebSocket subscriber provides an asyncio loop + queue, and the bus forwards
events to it using loop.call_soon_threadsafe.
"""

import asyncio
from collections import deque
from threading import Lock
from typing import Any, Deque, Dict, List


class Subscriber:
    def __init__(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=1000)


class EventBus:
    def __init__(self, max_history: int = 300):
        self._lock = Lock()
        self._subscribers: List[Subscriber] = []
        self._history: Deque[Dict[str, Any]] = deque(maxlen=max_history)

    def subscribe(self, loop: asyncio.AbstractEventLoop) -> Subscriber:
        sub = Subscriber(loop)
        with self._lock:
            self._subscribers.append(sub)
        return sub

    def unsubscribe(self, sub: Subscriber) -> None:
        with self._lock:
            if sub in self._subscribers:
                self._subscribers.remove(sub)

    def publish(self, event: Dict[str, Any]) -> None:
        with self._lock:
            self._history.append(event)
            subs = list(self._subscribers)
        for sub in subs:
            try:
                sub.loop.call_soon_threadsafe(self._put, sub, event)
            except Exception:
                continue

    def _put(self, sub: Subscriber, event: Dict[str, Any]) -> None:
        try:
            sub.queue.put_nowait(event)
        except asyncio.QueueFull:
            try:
                sub.queue.get_nowait()
                sub.queue.put_nowait(event)
            except Exception:
                pass

    def history(self, limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._history)[-limit:]


event_bus = EventBus()


def publish_telemetry(kind: str, data: Dict[str, Any]) -> None:
    event_bus.publish({"kind": kind, "data": data})
