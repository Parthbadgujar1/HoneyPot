"""Feedback-driven deception policy.

The decoy can present several personas. Which one keeps a given kind of
attacker engaged is not known in advance, so the choice is a multi-armed
bandit problem: for each attack class (the context) every persona is an arm,
and the reward is how much the attacker keeps interacting after the persona
was shown.

UCB1 is used because it is deterministic given the history, needs no tuning
beyond one exploration constant, and is easy to explain: pick the persona with
the best average reward plus a bonus for personas tried less often.

Reward = min(1, follow-up events within ``WINDOW_S`` / ``FULL_REWARD_EVENTS``).
It measures continued interaction only. It does not prove that the attacker
was fooled, and the report states that limit.
"""

from __future__ import annotations

import math
import threading
import time

WINDOW_S = 300
FULL_REWARD_EVENTS = 10
EXPLORATION = 0.8
PRIOR_STRENGTH = 2  # pseudo-observations given to the hand-written default persona


class PersonaBandit:
    def __init__(self, personas: list[str], priors: dict[str, str] | None = None,
                 exploration: float = EXPLORATION):
        self.personas = list(personas)
        self.exploration = exploration
        self._lock = threading.Lock()
        # context -> persona -> [count, reward_sum]
        self._stats: dict[str, dict[str, list[float]]] = {}
        self._pending: dict[str, dict] = {}
        self._priors = priors or {}

    def _arms(self, context: str) -> dict[str, list[float]]:
        arms = self._stats.get(context)
        if arms is None:
            arms = {p: [0.0, 0.0] for p in self.personas}
            prior = self._priors.get(context)
            if prior in arms:
                arms[prior] = [float(PRIOR_STRENGTH), 0.5 * PRIOR_STRENGTH]
            self._stats[context] = arms
        return arms

    def choose(self, context: str, exclude: str | None = None) -> str:
        with self._lock:
            arms = self._arms(context)
            candidates = [p for p in self.personas if p != exclude] or self.personas
            total = sum(arms[p][0] for p in self.personas) + 1
            best, best_score = candidates[0], -1.0
            for persona in candidates:
                count, reward = arms[persona]
                if count == 0:
                    return persona
                score = reward / count + self.exploration * math.sqrt(math.log(total) / count)
                if score > best_score:
                    best, best_score = persona, score
            return best

    def credit(self, context: str, persona: str, reward: float) -> None:
        with self._lock:
            arm = self._arms(context)[persona]
            arm[0] += 1
            arm[1] += max(0.0, min(1.0, reward))

    # ------------------------------------------------------------------
    # Live feedback: count what the attacker does after a persona is shown
    # ------------------------------------------------------------------

    def started(self, ip: str, context: str, persona: str, now: float | None = None) -> None:
        self.settle(ip, now)
        with self._lock:
            self._pending[ip] = {"context": context, "persona": persona,
                                 "ts": now or time.time(), "events": 0}

    def interaction(self, ip: str, now: float | None = None) -> None:
        now = now or time.time()
        with self._lock:
            pending = self._pending.get(ip)
            if pending is None:
                return
            expired = now - pending["ts"] > WINDOW_S
            if not expired:
                pending["events"] += 1
                done = pending["events"] >= FULL_REWARD_EVENTS
            else:
                done = True
        if done:
            self.settle(ip, now)

    def settle(self, ip: str, now: float | None = None) -> None:
        with self._lock:
            pending = self._pending.pop(ip, None)
        if pending:
            self.credit(pending["context"], pending["persona"],
                        pending["events"] / FULL_REWARD_EVENTS)

    def table(self) -> list[dict]:
        with self._lock:
            rows = []
            for context, arms in sorted(self._stats.items()):
                for persona, (count, reward) in arms.items():
                    rows.append({"context": context, "persona": persona, "tries": int(count),
                                 "mean_reward": round(reward / count, 3) if count else None})
            return rows
