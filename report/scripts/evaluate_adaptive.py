"""Static versus feedback-learning deception, measured in a simulation.

This is a SIMULATION with an assumed attacker model, not field data. Each
simulated attacker belongs to an attack class and "prefers" one persona: it
keeps interacting with probability P_MATCH per step while the decoy shows its
preferred persona and P_OTHER otherwise. The preference table below is an
assumption chosen so that no single fixed persona suits every class, which is
the situation the learning policy is meant for. Results therefore show whether
the policy can discover a good persona from engagement feedback alone, and how
fast, but they do not prove real attackers behave this way.

Compared policies (same random attackers for each):
* static    - the default persona is always shown
* rotation  - persona rotates round-robin on every repeat, as in the original code
* learning  - UCB1 bandit fed by the engagement reward (the project's policy)
* oracle    - always shows the preferred persona (upper bound)

    python evaluate_adaptive.py <project root> <output json> [episodes] [seeds]
"""

from __future__ import annotations

import json
import random
import statistics
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2])
EPISODES = int(sys.argv[3]) if len(sys.argv) > 3 else 600
SEEDS = int(sys.argv[4]) if len(sys.argv) > 4 else 20
sys.path.insert(0, str(ROOT / "honeypot-backend"))

from sensor.deception import PERSONAS  # noqa: E402
from sensor.policy import FULL_REWARD_EVENTS, PersonaBandit  # noqa: E402

CLASSES = ["PORT_SCAN", "SSH_BRUTE_FORCE", "HTTP_ENDPOINT_PROBING", "SQL_INJECTION"]
PREFERRED = {"PORT_SCAN": "windows_server", "SSH_BRUTE_FORCE": "legacy_linux",
             "HTTP_ENDPOINT_PROBING": "ubuntu_web", "SQL_INJECTION": "windows_server"}
DEFAULT = "ubuntu_web"
P_MATCH, P_OTHER, MAX_STEPS = 0.92, 0.80, 60
NAMES = list(PERSONAS)
ROTATE = {n: NAMES[(i + 1) % len(NAMES)] for i, n in enumerate(NAMES)}


def session(rng, klass, persona_for_step):
    """Number of interactions before the attacker gives up."""
    steps, persona = 0, persona_for_step(0)
    while steps < MAX_STEPS:
        p = P_MATCH if persona == PREFERRED[klass] else P_OTHER
        if rng.random() > p:
            break
        steps += 1
        persona = persona_for_step(steps)
    return steps


def run(policy: str, seed: int) -> list[dict]:
    rng = random.Random(seed)
    bandit = PersonaBandit(NAMES, {}) if policy == "learning" else None
    rows = []
    for episode in range(EPISODES):
        klass = rng.choice(CLASSES)
        if policy == "static":
            chooser = lambda step: DEFAULT
        elif policy == "oracle":
            chooser = lambda step: PREFERRED[klass]
        elif policy == "rotation":
            chooser = lambda step: DEFAULT if step < 3 else NAMES[(NAMES.index(DEFAULT) + 1 + (step - 3) // 5) % len(NAMES)]
        else:
            first = bandit.choose(klass)
            chooser = lambda step, first=first: first
        steps = session(rng, klass, chooser)
        if bandit:
            bandit.credit(klass, chooser(0), steps / FULL_REWARD_EVENTS)
        rows.append({"episode": episode, "class": klass, "steps": steps})
    return rows


def main():
    report = {"episodes": EPISODES, "seeds": SEEDS, "p_match": P_MATCH, "p_other": P_OTHER,
              "max_steps": MAX_STEPS, "preferred": PREFERRED, "default": DEFAULT, "policies": {}}
    for policy in ("static", "rotation", "learning", "oracle"):
        runs = [run(policy, seed) for seed in range(SEEDS)]
        mean_all = [statistics.mean(r["steps"] for r in rows) for rows in runs]
        last = [statistics.mean(r["steps"] for r in rows[-EPISODES // 4:]) for rows in runs]
        first = [statistics.mean(r["steps"] for r in rows[:50]) for rows in runs]
        curve = []
        for start in range(0, EPISODES, 50):
            curve.append(statistics.mean(
                statistics.mean(r["steps"] for r in rows[start:start + 50]) for rows in runs))
        by_class = {c: statistics.mean(
            statistics.mean(r["steps"] for r in rows if r["class"] == c) for rows in runs) for c in CLASSES}
        report["policies"][policy] = {
            "mean_steps": statistics.mean(mean_all), "sd_steps": statistics.pstdev(mean_all),
            "first_50": statistics.mean(first), "last_quarter": statistics.mean(last),
            "curve_per_50": curve, "by_class": by_class,
        }
        print(policy, round(statistics.mean(mean_all), 2), "last quarter", round(statistics.mean(last), 2), flush=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
