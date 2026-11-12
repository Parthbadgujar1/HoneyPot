"""Start the real system in a sandbox, generate activity and take screenshots.

Sandbox: decoys bind to 127.0.0.1 only, blocking is dry-run, the database is a
copy, and the admin token is a temporary test value. Every started process is
stopped at the end, and the live sensor data and firewall are not touched.

    python capture_screens.py <project root> <live folder> <screens folder> <venv python>
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(sys.argv[1]).resolve()
LIVE = Path(sys.argv[2]).resolve()
SHOTS = Path(sys.argv[3]).resolve()
PY = sys.argv[4]
BACKEND = ROOT / "honeypot-backend"
FRONTEND = ROOT / "honeypot-frontend"
OVERRIDE = LIVE / "override.json"
TOKEN = (LIVE / "test_token.txt").read_text().strip()
SHOTS.mkdir(parents=True, exist_ok=True)

ENV = {**os.environ, "HONEYPOT_SENSOR_CONFIG": str(OVERRIDE), "HONEYPOT_ADMIN_TOKEN": TOKEN,
       "PYTHONIOENCODING": "utf-8"}
processes: list[subprocess.Popen] = []


def start(name, command, cwd):
    log = open(LIVE / f"{name}.log", "w", encoding="utf-8")
    process = subprocess.Popen(command, cwd=cwd, env=ENV, stdout=log, stderr=subprocess.STDOUT)
    processes.append(process)
    print("started", name, process.pid, flush=True)


def wait_port(port, seconds=90):
    deadline = time.time() + seconds
    while time.time() < deadline:
        with socket.socket() as probe:
            probe.settimeout(1)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.5)
    raise SystemExit(f"port {port} did not open")


def fetch(url, data=None, headers=None, method=None):
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.read().decode("utf-8", "replace")


def activity():
    """The same kinds of probe the project's own simulator and demo script send."""
    subprocess.run([PY, "-m", "sensor.tools.simulate_probes", "--all", "--config", str(OVERRIDE),
                    "--attempts", "12", "--timeout", "1"], cwd=BACKEND, env=ENV, check=False)
    env_page = fetch("http://127.0.0.1:8080/.env")
    key = re.search(r"AWS_ACCESS_KEY_ID=(\S+)", env_page)
    if key:
        fetch("http://127.0.0.1:8080/login", data=urllib.parse.urlencode(
            {"username": "admin", "password": key.group(1)}).encode(), method="POST")
    fetch("http://127.0.0.1:9100/api/blocks",
          data=json.dumps({"ip": "203.0.113.250", "reason": "demo", "ttl_minutes": 30}).encode(),
          headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    time.sleep(3)


def shoot(page, name, full=False):
    page.screenshot(path=str(SHOTS / f"{name}.png"), full_page=full)
    print("saved", name, flush=True)


def capture():
    with sync_playwright() as play:
        browser = play.chromium.launch(channel="msedge", headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 860}, device_scale_factor=1.5)
        page = context.new_page()

        page.goto("http://127.0.0.1:8080/")
        page.wait_for_timeout(500)
        shoot(page, "decoy_login")
        page.goto("http://127.0.0.1:8080/.env")
        page.wait_for_timeout(500)
        shoot(page, "decoy_env")

        page.goto("http://127.0.0.1:5173/")
        page.wait_for_timeout(6000)
        shoot(page, "dashboard_overview")
        page.locator(".nav-item", has_text="Connection Events").first.click()
        page.wait_for_timeout(2000)
        shoot(page, "dashboard_events")
        page.locator(".nav-item", has_text="Threat Alerts").first.click()
        page.wait_for_timeout(2000)
        shoot(page, "dashboard_alerts")
        rows = page.locator("table tbody tr")
        if rows.count():
            target = rows.filter(has_text="HIGH").first if rows.filter(has_text="HIGH").count() else rows.first
            target.get_by_text("View").first.click()
            page.wait_for_timeout(1800)
            shoot(page, "dashboard_alert_detail")

        console = context.new_page()
        console.goto("http://127.0.0.1:9100/")
        console.wait_for_selector("#tokenInput", state="visible")
        console.fill("#tokenInput", TOKEN)
        console.click("#signInBtn")
        console.wait_for_selector("#app", state="visible")
        console.wait_for_timeout(2500)
        for name, slug in (("overview", "console_overview"), ("alerts", "console_alerts"),
                           ("sources", "console_attackers"), ("intel", "console_intel"),
                           ("blocks", "console_blocks"), ("decoys", "console_decoys"),
                           ("system", "console_system")):
            console.locator(f'.nav-item[data-page="{name}"]').click()
            console.wait_for_timeout(1500)
            shoot(console, slug)
        console.get_by_text("ML models", exact=True).first.scroll_into_view_if_needed()
        console.wait_for_timeout(500)
        shoot(console, "console_models")
        browser.close()


def stop_all():
    for process in processes:
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True)
    print("all processes stopped", flush=True)


try:
    start("sensor", [PY, "-m", "sensor.main", "--config", str(OVERRIDE)], BACKEND)
    wait_port(9100)
    wait_port(8080)
    start("backend", [PY, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000"], BACKEND)
    wait_port(8000)
    start("frontend", ["cmd", "/c", "npm", "run", "dev", "--", "--host", "127.0.0.1", "--port", "5173", "--strictPort"], FRONTEND)
    wait_port(5173)
    activity()
    status = json.loads(fetch("http://127.0.0.1:9100/api/status",
                              headers={"Authorization": f"Bearer {TOKEN}"}))
    (LIVE / "status.json").write_text(json.dumps(status, indent=1), encoding="utf-8")
    capture()
finally:
    stop_all()
