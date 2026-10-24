"""Run the honeypot sensor: decoys, detection, adaptive response, console.

    cd honeypot-backend
    python -m sensor.main                    # uses sensor/config.json
    python -m sensor.main --config my.json   # override any setting

Components started here, in one asyncio process (the SSH decoy runs its
blocking paramiko work in threads):

* bait TCP listeners and the SSH and HTTP decoys (the attacker-facing side)
* the Windows firewall log reader (optional, see firewall_log in config)
* the operator console on 127.0.0.1 (admin.port)
* a maintenance loop that releases expired firewall blocks
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import os
import secrets
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

import uvicorn

from . import netinfo
from .admin_app import create_admin_app
from .config import data_path, load_config, sensor_path
from .deception import DecoyPolicy
from .engine import DetectionEngine
from .events import Event
from .firewall import BlockManager
from .listeners.bait import BaitListeners
from .listeners.fwlog import FirewallLogReader
from .listeners.http_decoy import build_app as build_http_app
from .listeners.ssh import SSHDecoy
from .ml import ModelBundle
from .store import Store

log = logging.getLogger("sensor")

TOKEN_ENV_VAR = "HONEYPOT_ADMIN_TOKEN"
MAINTENANCE_INTERVAL_S = 30
PROTECTED_REFRESH_S = 600


class _EmbeddedServer(uvicorn.Server):
    """uvicorn server that leaves signal handling to the sensor process."""

    @contextlib.contextmanager
    def capture_signals(self):
        yield


def _bind(host: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
    except OSError:
        sock.close()
        raise
    sock.listen(128)
    sock.setblocking(False)
    return sock


class SensorRuntime:
    def __init__(self, config: dict):
        self.config = config
        self.started_at = time.time()
        self.bind_host: str = config["decoys"]["bind_host"]

        self.store = Store(data_path(config, "db_path"))
        self.models = ModelBundle(config)
        self.decoys = DecoyPolicy(self.store)
        self.blocker = BlockManager(config, self.store)
        self.engine = DetectionEngine(config, self.store, self.models, self.decoys, self.blocker)

        self.admin_token, self.token_created = self._admin_token()
        self.listeners: dict[str, dict] = {}
        self._bait: BaitListeners | None = None
        self._ssh: SSHDecoy | None = None
        self._servers: list[_EmbeddedServer] = []
        self._tasks: list[asyncio.Task] = []
        self._stop: asyncio.Event | None = None

    # ------------------------------------------------------------------
    # Setup helpers
    # ------------------------------------------------------------------

    def _admin_token(self) -> tuple[str, bool]:
        """Return (token, created). The token value is never logged."""
        env_token = os.getenv(TOKEN_ENV_VAR)
        if env_token:
            return env_token.strip(), False

        token_path = sensor_path(self.config["admin"]["token_file"])
        if token_path.exists():
            return token_path.read_text(encoding="utf-8").strip(), False

        token = secrets.token_urlsafe(24)
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(token, encoding="utf-8")
        return token, True

    def emit(self, event: Event) -> None:
        self.engine.observe(event)

    def status(self) -> dict:
        listeners = []
        for name, info in sorted(self.listeners.items()):
            listeners.append({"name": name, **info})
        if self._bait is not None:
            for port, info in sorted(self._bait.status.items()):
                listeners.append({
                    "name": f"bait:{info['service']}",
                    "port": port,
                    "state": info["state"],
                    "error": info.get("error"),
                })
        return {
            "started_at": datetime.fromtimestamp(self.started_at, timezone.utc).isoformat(),
            "uptime_s": round(time.time() - self.started_at, 1),
            "bind_host": self.bind_host,
            "listeners": listeners,
            "models": self.models.status(),
            "firewall": self.blocker.status(),
            "engine": self.engine.summary(),
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        self._stop = asyncio.Event()
        self.blocker.start()
        try:
            await self._start_listeners()
            self._tasks.append(asyncio.create_task(self._maintenance()))
            self._print_banner()
            await self._stop.wait()
        finally:
            await self._shutdown()

    def request_stop(self) -> None:
        if self._stop is not None:
            self._stop.set()

    async def _start_listeners(self) -> None:
        decoys = self.config["decoys"]
        bind = self.bind_host

        if decoys["ssh"]["enabled"]:
            self._ssh = SSHDecoy(
                self.config,
                bind,
                sensor_path(decoys["ssh"]["host_key_file"]),
                self.emit,
                self.decoys,
            )
            try:
                self._ssh.start()
                self.listeners["ssh-decoy"] = {"port": self._ssh.port, "state": "listening"}
            except OSError as exc:
                self.listeners["ssh-decoy"] = {
                    "port": self._ssh.port, "state": "unavailable", "error": str(exc),
                }
                log.error("SSH decoy not started: %s", exc)

        if decoys["http"]["enabled"]:
            port = int(decoys["http"]["port"])
            try:
                sock = _bind(bind, port)
                app = build_http_app(self.config, self.emit, self.decoys)
                self._serve(app, sock)
                self.listeners["http-decoy"] = {"port": port, "state": "listening"}
            except OSError as exc:
                self.listeners["http-decoy"] = {
                    "port": port, "state": "unavailable", "error": str(exc),
                }
                log.error("HTTP decoy not started: %s", exc)

        if decoys["bait"]["enabled"]:
            self._bait = BaitListeners(self.config, bind, self.emit, self.decoys)
            await self._bait.start()

        admin = self.config["admin"]
        if admin["enabled"]:
            port = int(admin["port"])
            try:
                sock = _bind(admin["host"], port)
                self._serve(create_admin_app(self), sock)
                self.listeners["operator-console"] = {
                    "port": port, "state": "listening", "detail": f"http://{admin['host']}:{port}/",
                }
            except OSError as exc:
                self.listeners["operator-console"] = {
                    "port": port, "state": "unavailable", "error": str(exc),
                }
                log.error("Operator console not started: %s", exc)

        firewall_log = self.config["firewall_log"]
        if firewall_log["enabled"]:
            reader = FirewallLogReader(
                Path(firewall_log["path"]),
                self.emit,
                netinfo.local_addresses(),
                float(firewall_log["poll_interval_s"]),
            )
            self._tasks.append(asyncio.create_task(reader.run(self._stop)))
            self.listeners["firewall-log"] = {
                "state": "enabled", "detail": str(firewall_log["path"]),
            }

    def _serve(self, app, sock: socket.socket) -> None:
        server = _EmbeddedServer(uvicorn.Config(
            app,
            log_level="warning",
            access_log=False,
            lifespan="off",
            server_header=False,
            date_header=False,
            timeout_keep_alive=5,
        ))
        self._servers.append(server)
        self._tasks.append(asyncio.create_task(server.serve(sockets=[sock])))

    async def _maintenance(self) -> None:
        while not self._stop.is_set():
            try:
                released = self.blocker.expire_due()
                if released:
                    log.info("Released expired blocks: %s", ", ".join(released))
                if time.time() - self.blocker.protected_refreshed_at() >= PROTECTED_REFRESH_S:
                    self.blocker.refresh_protected()
            except Exception:
                log.exception("Maintenance pass failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=MAINTENANCE_INTERVAL_S)
            except asyncio.TimeoutError:
                pass

    async def _shutdown(self) -> None:
        for server in self._servers:
            server.should_exit = True
        if self._ssh is not None:
            self._ssh.stop()
        if self._bait is not None:
            await self._bait.stop()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self.blocker.stop()
        self.store.close()
        log.info("Sensor stopped")

    def _print_banner(self) -> None:
        print("=" * 72)
        print("AI-adaptive honeypot sensor running")
        for row in self.status()["listeners"]:
            state = row["state"]
            port = row.get("port", "")
            extra = row.get("error") or row.get("detail") or ""
            print(f"  {row['name']:<22} {str(port):>6}  {state:<12} {extra}")
        mode = self.blocker.mode.upper().replace("_", " ")
        print(f"  Firewall blocking: {mode}"
              f"{'' if self.blocker.enabled else ' (disabled)'}")
        print(f"  Models: CIC={'loaded' if self.models.cic is not None else 'missing'}"
              f", UNSW={'loaded' if self.models.unsw is not None else 'missing'}")
        if self.config["admin"]["enabled"]:
            print(f"  Operator console: http://{self.config['admin']['host']}:"
                  f"{self.config['admin']['port']}/")
            if self.token_created:
                print("  Admin token created at "
                      f"{sensor_path(self.config['admin']['token_file'])}")
        print("=" * 72)


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    # Port scanners routinely drop SSH connections mid-banner. paramiko
    # logs each one as an ERROR traceback; the sensor records them itself.
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the honeypot sensor.")
    parser.add_argument("--config", help="path to a JSON config override")
    args = parser.parse_args(argv)

    config = load_config(args.config)
    _configure_logging(config.get("log_level", "INFO"))

    runtime = SensorRuntime(config)
    try:
        asyncio.run(runtime.run())
    except KeyboardInterrupt:
        print("Stopping sensor...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
