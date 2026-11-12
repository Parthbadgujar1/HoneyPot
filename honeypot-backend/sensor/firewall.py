"""Attacker IP blocking through the host firewall.

Backends: Windows Defender Firewall (``netsh advfirewall``) and Linux
``iptables``/``ip6tables``. ``response.backend`` picks one; ``auto`` uses
netsh on Windows and iptables elsewhere.

Safety model
------------
* ``response.enforce`` defaults to false: blocks are recorded and logged
  as DRY_RUN and no firewall rule is created. Set it to true once the
  decisions look right on your network.
* Protected addresses are never blocked: loopback, the allowlist in the
  config, this machine's own addresses and the default gateway.
* Every block has a TTL (``block_ttl_minutes``) and is released
  automatically when it expires. ``0`` disables expiry.
* Rules are created with argument lists, never through a shell.
* With ``response.require_approval`` set, automatic blocks wait as
  AWAITING_APPROVAL until an operator approves or rejects them. Operator
  blocks from the console are applied directly.
"""

from __future__ import annotations

import ctypes
import ipaddress
import logging
import os
import queue
import subprocess
import sys
import threading
import time
from typing import Callable

from . import netinfo
from .store import Store

log = logging.getLogger("sensor.firewall")

class BlockError(ValueError):
    """Raised when a block request is refused for safety reasons."""


def is_admin() -> bool:
    if sys.platform.startswith("win"):
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _run(command: list[str]) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return completed.returncode, (completed.stdout + completed.stderr).strip()


def _run_netsh(args: list[str]) -> tuple[int, str]:
    return _run(["netsh", "advfirewall", "firewall", *args])


class NetshBackend:
    name = "netsh"

    def __init__(self, runner: Callable[[list[str]], tuple[int, str]] | None = None):
        self._run = runner or _run_netsh

    def add(self, rule: str, ip: str) -> tuple[int, str]:
        # Remove any leftover rule with the same name so the add cannot
        # fail with a duplicate-name error.
        self._run(["delete", "rule", f"name={rule}"])
        return self._run([
            "add", "rule", f"name={rule}", "dir=in", "action=block",
            f"remoteip={ip}", "profile=any", "enable=yes",
        ])

    def remove(self, rule: str, ip: str) -> tuple[int, str]:
        return self._run(["delete", "rule", f"name={rule}"])


class IptablesBackend:
    """One DROP rule per address at the top of INPUT, tagged with a comment."""

    name = "iptables"

    def __init__(self, runner: Callable[[list[str]], tuple[int, str]] | None = None):
        self._run = runner or _run

    @staticmethod
    def _spec(rule: str, ip: str) -> tuple[str, list[str]]:
        binary = "ip6tables" if ipaddress.ip_address(ip).version == 6 else "iptables"
        return binary, ["INPUT", "-s", ip, "-m", "comment", "--comment", rule, "-j", "DROP"]

    def add(self, rule: str, ip: str) -> tuple[int, str]:
        binary, spec = self._spec(rule, ip)
        if self._run([binary, "-C", *spec])[0] == 0:
            return 0, "rule already present"
        return self._run([binary, "-I", *spec])

    def remove(self, rule: str, ip: str) -> tuple[int, str]:
        binary, spec = self._spec(rule, ip)
        if self._run([binary, "-C", *spec])[0] != 0:
            return 0, "rule already absent"
        return self._run([binary, "-D", *spec])


def make_backend(name: str, runner=None):
    if name == "auto":
        name = "netsh" if sys.platform.startswith("win") else "iptables"
    if name == "netsh":
        return NetshBackend(runner)
    if name == "iptables":
        return IptablesBackend(runner)
    raise ValueError(f"unknown firewall backend: {name}")


class BlockManager:
    def __init__(
        self,
        config: dict,
        store: Store,
        runner: Callable[[list[str]], tuple[int, str]] | None = None,
        admin_check: Callable[[], bool] = is_admin,
        protected_extra: set[str] | None = None,
    ):
        response = config["response"]
        self.enabled: bool = response["block_enabled"]
        self.enforce: bool = response["enforce"]
        self.block_min_score: int = response["block_min_score"]
        self.block_classes: set[str] = set(response["block_classes"])
        self.ttl_minutes: int = response["block_ttl_minutes"]
        self.max_active: int = response["max_active_blocks"]
        self.rule_prefix: str = response["rule_prefix"]
        self.require_approval: bool = response.get("require_approval", False)

        self._allow_networks = [
            ipaddress.ip_network(cidr, strict=False)
            for cidr in response["allowlist"]
        ]
        self._protected_extra = set(protected_extra or ())
        self._protected: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        self._protected_refreshed = 0.0

        self._store = store
        # ``runner`` predates the backends and always meant netsh arguments.
        self.backend = (NetshBackend(runner) if runner is not None
                        else make_backend(response.get("backend", "auto")))
        self._admin_check = admin_check
        self._lock = threading.RLock()
        self._queue: queue.Queue = queue.Queue()
        self._thread: threading.Thread | None = None
        self.refresh_protected()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @property
    def mode(self) -> str:
        return "enforce" if self.enforce else "dry_run"

    def start(self) -> None:
        if self.enforce and not self._admin_check():
            log.warning(
                "Blocking is set to enforce, but this process is not elevated. "
                "%s will fail; run the sensor elevated (Administrator or root).",
                self.backend.name,
            )
        self._thread = threading.Thread(
            target=self._worker, name="firewall-worker", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        if self._thread is not None:
            self._queue.put(None)
            self._thread.join(timeout=10)
            self._thread = None

    def status(self) -> dict:
        return {
            "enabled": self.enabled,
            "mode": self.mode,
            "enforce": self.enforce,
            "backend": self.backend.name,
            "require_approval": self.require_approval,
            "awaiting_approval": len(self._store.blocks_awaiting_approval()),
            "elevated": self._admin_check(),
            "block_min_score": self.block_min_score,
            "block_classes": sorted(self.block_classes),
            "ttl_minutes": self.ttl_minutes,
            "max_active_blocks": self.max_active,
            "protected_addresses": sorted(str(ip) for ip in self._protected),
            "allowlist": [str(net) for net in self._allow_networks],
        }

    # ------------------------------------------------------------------
    # Decisions
    # ------------------------------------------------------------------

    def refresh_protected(self) -> None:
        """Re-read this machine's addresses and the default gateway.

        Called at startup and periodically, because DHCP can change them.
        """
        addresses = netinfo.local_addresses() | netinfo.default_gateways() | self._protected_extra
        protected = set()
        for address in addresses:
            try:
                protected.add(ipaddress.ip_address(address))
            except ValueError:
                continue
        with self._lock:
            self._protected = protected
            self._protected_refreshed = time.time()

    def protected_refreshed_at(self) -> float:
        return self._protected_refreshed

    def protected_reason(self, ip: str) -> str | None:
        address = ipaddress.ip_address(ip)
        if address.is_unspecified or address.is_multicast:
            return "unspecified or multicast address"
        if address.is_loopback:
            return "loopback address"
        if address in self._protected:
            return "this machine or the default gateway"
        for network in self._allow_networks:
            if address in network:
                return f"allowlisted network {network}"
        return None

    def consider(self, finding: dict) -> dict:
        """Decide whether a finding should result in a block."""
        if not self.enabled:
            return {"action": "none", "reason": "blocking disabled in config"}

        classification = finding["classification"]
        if classification not in self.block_classes:
            return {
                "action": "none",
                "reason": f"{classification} is not a blocking class",
            }
        if finding["score"] < self.block_min_score:
            return {
                "action": "none",
                "reason": (
                    f"score {finding['score']} below block threshold "
                    f"{self.block_min_score}"
                ),
            }

        reason = f"{classification} score {finding['score']}"
        try:
            if self.require_approval:
                row = self.request_approval(finding["src_ip"], reason)
            else:
                row = self.block(finding["src_ip"], reason, source="auto")
        except BlockError as exc:
            return {"action": "skipped", "reason": str(exc)}

        if row["status"] == "AWAITING_APPROVAL":
            return {"action": "approval_requested", "block_id": row["id"],
                    "status": row["status"],
                    "reason": "high-impact action held for operator approval"}
        return {
            "action": "block",
            "mode": self.mode,
            "block_id": row["id"],
            "status": row["status"],
            "expires": row["expires"],
        }

    def _checked(self, ip: str) -> str:
        try:
            normalized = str(ipaddress.ip_address(ip.strip()))
        except ValueError as exc:
            raise BlockError(f"'{ip}' is not a valid IP address") from exc
        protected = self.protected_reason(normalized)
        if protected:
            raise BlockError(f"Refusing to block {normalized}: {protected}")
        return normalized

    def request_approval(self, ip: str, reason: str) -> dict:
        """Record an automatic block that waits for an operator decision."""
        normalized = self._checked(ip)
        with self._lock:
            existing = self._store.active_block_for_ip(normalized)
            if existing:
                return existing
            block_id = self._store.insert_block(
                normalized, "AWAITING_APPROVAL", self.mode, "auto", reason, None
            )
        log.warning("Block of %s awaits approval: %s", normalized, reason)
        return self._store.get_block(block_id)

    def approve(self, block_id: int, ttl_minutes: int | None = None) -> dict:
        with self._lock:
            row = self._store.get_block(block_id)
            if row is None or row["status"] != "AWAITING_APPROVAL":
                raise BlockError("No block awaiting approval with that id")
            self._checked(row["ip"])  # protection may have changed since
            ttl = self.ttl_minutes if ttl_minutes is None else ttl_minutes
            self._store.approve_block(block_id, time.time() + ttl * 60 if ttl > 0 else None)
            self._queue.put(("add", block_id, row["ip"]))
        log.warning("Block of %s approved by operator", row["ip"])
        return self._store.get_block(block_id)

    def reject(self, block_id: int) -> dict:
        with self._lock:
            row = self._store.get_block(block_id)
            if row is None or row["status"] != "AWAITING_APPROVAL":
                raise BlockError("No block awaiting approval with that id")
            self._store.set_block_status(block_id, "REJECTED", released=True)
        log.info("Block of %s rejected by operator", row["ip"])
        return self._store.get_block(block_id)

    def block(
        self,
        ip: str,
        reason: str,
        source: str = "manual",
        ttl_minutes: int | None = None,
    ) -> dict:
        normalized = self._checked(ip)

        ttl = self.ttl_minutes if ttl_minutes is None else ttl_minutes
        if ttl < 0:
            raise BlockError("TTL cannot be negative")

        with self._lock:
            existing = self._store.active_block_for_ip(normalized)
            if existing and existing["status"] == "AWAITING_APPROVAL":
                # An operator blocking the address is an approval.
                return self.approve(existing["id"], ttl_minutes)
            if existing:
                return existing

            active = len(self._store.active_blocks())
            if active >= self.max_active:
                raise BlockError(
                    f"Maximum of {self.max_active} active blocks reached"
                )

            expires_ts = time.time() + ttl * 60 if ttl > 0 else None
            block_id = self._store.insert_block(
                normalized, "PENDING", self.mode, source, reason, expires_ts
            )
            self._queue.put(("add", block_id, normalized))

        log.warning("Block %s (%s) from %s: %s", normalized, self.mode, source, reason)
        return self._store.get_block(block_id)

    def unblock(self, ip: str, source: str = "manual") -> dict | None:
        normalized = str(ipaddress.ip_address(ip.strip()))
        with self._lock:
            existing = self._store.active_block_for_ip(normalized)
            if existing is None:
                return None
            if existing["status"] == "AWAITING_APPROVAL":
                return self.reject(existing["id"])
            self._store.set_block_status(existing["id"], "REMOVING")
            self._queue.put(("remove", existing["id"], normalized))
        log.warning("Unblock %s from %s", normalized, source)
        return self._store.get_block(existing["id"])

    def expire_due(self, now: float | None = None) -> list[str]:
        """Start removal for every block whose TTL has passed."""
        now = time.time() if now is None else now
        released = []
        for block in self._store.blocks_due_for_expiry(now):
            if self.unblock(block["ip"], source="ttl") is not None:
                released.append(block["ip"])
        return released

    def wait_idle(self, timeout: float = 10) -> None:
        """Block until queued firewall work has been processed (tests)."""
        deadline = time.time() + timeout
        while self._queue.unfinished_tasks and time.time() < deadline:
            time.sleep(0.05)

    # ------------------------------------------------------------------
    # Worker thread: the only place that touches the firewall
    # ------------------------------------------------------------------

    def _rule_name(self, ip: str) -> str:
        return f"{self.rule_prefix}-{ip}"

    def _worker(self) -> None:
        while True:
            action = self._queue.get()
            try:
                if action is None:
                    return
                operation, block_id, ip = action
                if operation == "add":
                    self._apply_add(block_id, ip)
                else:
                    self._apply_remove(block_id, ip)
            except Exception as exc:  # keep the worker alive
                log.exception("Firewall worker failed: %s", exc)
            finally:
                self._queue.task_done()

    def _apply_add(self, block_id: int, ip: str) -> None:
        if not self.enforce:
            self._store.set_block_status(block_id, "DRY_RUN")
            log.info("[dry-run] would block %s", ip)
            return

        code, output = self.backend.add(self._rule_name(ip), ip)
        if code == 0:
            self._store.set_block_status(block_id, "ACTIVE")
        else:
            self._store.set_block_status(block_id, "FAILED", error=output[:500])
            log.error("%s could not block %s: %s", self.backend.name, ip, output)

    def _apply_remove(self, block_id: int, ip: str) -> None:
        if not self.enforce:
            self._store.set_block_status(block_id, "RELEASED", released=True)
            log.info("[dry-run] would unblock %s", ip)
            return

        code, output = self.backend.remove(self._rule_name(ip), ip)
        if code == 0:
            self._store.set_block_status(block_id, "RELEASED", released=True)
        else:
            self._store.set_block_status(
                block_id, "RELEASE_FAILED", error=output[:500]
            )
            log.error("%s could not remove the block for %s: %s", self.backend.name, ip, output)
