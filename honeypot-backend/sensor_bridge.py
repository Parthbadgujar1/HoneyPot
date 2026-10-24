"""Bridge: serves the sensor's data to the monitoring dashboard.

The dashboard (honeypot-frontend, port 5173) reads from this router under
/sensor. The router reads from the sensor's operator console on
127.0.0.1:9100 and reshapes the responses into the fields the dashboard
expects. The admin token is read on the server and never sent to the
browser. This router is only useful while the sensor is running.
"""

from __future__ import annotations

import os
import zlib
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Query

from sensor.config import load_config, sensor_path

router = APIRouter(prefix="/sensor", tags=["sensor"])

_CONFIG = load_config()
SENSOR_URL = f"http://{_CONFIG['admin']['host']}:{_CONFIG['admin']['port']}"
TOKEN_FILE = sensor_path(_CONFIG["admin"]["token_file"])
SENSOR_LIMIT = 500  # the sensor console's maximum page size


def _token() -> str:
    env_token = os.getenv("HONEYPOT_ADMIN_TOKEN")
    if env_token:
        return env_token.strip()
    try:
        return TOKEN_FILE.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise HTTPException(503, f"Sensor admin token not found at {TOKEN_FILE}") from exc


def _call(method: str, path: str, params: dict | None = None, body: dict | None = None) -> Any:
    try:
        with httpx.Client(base_url=SENSOR_URL, timeout=5) as client:
            response = client.request(
                method,
                path,
                params=params,
                json=body,
                headers={"Authorization": f"Bearer {_token()}"},
            )
    except httpx.HTTPError as exc:
        raise HTTPException(
            503,
            f"Sensor console is not reachable at {SENSOR_URL}. Start the sensor first.",
        ) from exc

    if response.status_code >= 400:
        try:
            detail = response.json().get("detail", response.text)
        except ValueError:
            detail = response.text
        raise HTTPException(response.status_code, detail)
    return response.json()


# ----------------------------------------------------------------------
# Shape mapping: sensor data -> the fields the dashboard reads
# ----------------------------------------------------------------------

def _event_success(event: dict) -> bool:
    detail = event.get("detail") or {}
    kind = event["kind"]
    if kind == "http_request":
        return int(detail.get("status", 200)) < 400
    if kind in ("ssh_auth", "fw_drop"):
        return False
    return bool(detail.get("had_payload"))


def _map_event(event: dict) -> dict:
    return {
        "id": event["id"],
        "source_id": event["src_ip"],
        "destination_port": event["dst_port"] if event["dst_port"] is not None else "—",
        "success": _event_success(event),
        "timestamp": event["time"],
        "received_at": event["time"],
        "kind": event["kind"],
        "service": event["service"],
    }


def _map_alert(finding: dict) -> dict:
    evidence = finding.get("evidence") or {}
    scan_ports = set((evidence.get("PORT_SCAN") or {}).get("ports") or [])
    service_ports = set((evidence.get("SERVICE_DISCOVERY") or {}).get("service_ports") or [])
    ssh_attempts = int((evidence.get("SSH_BRUTE_FORCE") or {}).get("attempts") or 0)
    http_paths = len((evidence.get("HTTP_ENDPOINT_PROBING") or {}).get("paths") or [])
    silent = int((evidence.get("BANNER_ENUMERATION") or {}).get("silent_connects") or 0)

    # The dashboard's "attempts" is the largest count behind this finding.
    attempts = max(ssh_attempts, len(scan_ports), http_paths, silent)
    failure_ratio = min(1.0, silent / attempts) if attempts else 0.0

    return {
        "id": finding["id"],
        "source_id": finding["src_ip"],
        "window_end": finding["time"],
        "attempts_10m": attempts,
        "unique_ports_60s": len(scan_ports),
        "unique_ports_10m": len(scan_ports | service_ports),
        "failure_ratio_10m": round(failure_ratio, 3),
        "score": finding["score"],
        "severity": finding["severity"],
        "status": "ALERT",
        "reasons": finding["reasons"],
        "created_at": finding["time"],
        "classification": finding["classification"],
        "rule_points": finding["rule_points"],
        "ml_points": finding["ml_points"],
        "decision": finding.get("decision") or {},
        "evidence": evidence,
    }


def _alert_for_action(action: dict, findings: list[dict]) -> int | None:
    """Link a decoy action to the latest alert for the same source before it."""
    for finding in findings:  # newest first
        if finding["src_ip"] == action["src_ip"] and finding["time"] <= action["time"]:
            return finding["id"]
    return None


def _action_id(action: dict) -> int:
    """Use the sensor's id; older sensor processes don't send one yet."""
    if action.get("id") is not None:
        return int(action["id"])
    return zlib.crc32(f"{action['src_ip']}|{action['time']}".encode()) % 1_000_000


def _map_action(action: dict, findings: list[dict]) -> dict:
    return {
        "id": _action_id(action),
        "alert_id": _alert_for_action(action, findings),
        "source_id": action["src_ip"],
        "selected_decoy": action["persona"],
        "response_type": "engagement_level",
        "decision_reason": action["reason"],
        "simulated_response": {
            "persona": action["persona"],
            "engagement_level": action["level"],
            "note": "Decoy content served to this source",
        },
        "created_at": action["time"],
    }


def _all_findings() -> list[dict]:
    return _call("GET", "/api/findings", {"limit": SENSOR_LIMIT})["findings"]


# ----------------------------------------------------------------------
# Routes used by the dashboard
# ----------------------------------------------------------------------

@router.get("/health")
def health() -> dict:
    status = _call("GET", "/api/status")
    listeners = status["listeners"]
    return {
        "status": "ok",
        "service": "sensor",
        "mode": status["firewall"]["mode"],
        "listeners_up": sum(1 for item in listeners if item["state"] == "listening"),
        "listeners_total": len(listeners),
    }


@router.get("/events")
def events(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    source_id: str | None = Query(default=None),
) -> dict:
    params: dict = {"limit": min(SENSOR_LIMIT, offset + limit)}
    if source_id:
        params["src_ip"] = source_id
    rows = _call("GET", "/api/events", params)["events"]
    page = rows[offset:offset + limit]
    return {"total": len(rows), "limit": limit, "offset": offset,
            "events": [_map_event(event) for event in page]}


@router.get("/alerts")
def alerts(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    severity: str | None = Query(default=None),
    source_id: str | None = Query(default=None),
) -> dict:
    params: dict = {"limit": SENSOR_LIMIT}
    if severity:
        params["severity"] = severity
    if source_id:
        params["src_ip"] = source_id
    rows = _call("GET", "/api/findings", params)["findings"]
    page = rows[offset:offset + limit]
    return {"total": len(rows), "limit": limit, "offset": offset,
            "alerts": [_map_alert(finding) for finding in page]}


@router.get("/alerts/{alert_id}")
def alert(alert_id: int) -> dict:
    for finding in _all_findings():
        if finding["id"] == alert_id:
            return _map_alert(finding)
    raise HTTPException(404, "Alert not found")


@router.get("/deception-actions")
def deception_actions(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    alert_id: int | None = Query(default=None, ge=1),
) -> dict:
    findings = _all_findings()
    actions = _call("GET", "/api/decoy-actions", {"limit": SENSOR_LIMIT})["actions"]
    mapped = [_map_action(action, findings) for action in actions]
    if alert_id is not None:
        mapped = [item for item in mapped if item["alert_id"] == alert_id]
    page = mapped[offset:offset + limit]
    return {"total": len(mapped), "limit": limit, "offset": offset, "actions": page}


@router.post("/alerts/{alert_id}/deception")
def raise_engagement(alert_id: int) -> dict:
    """Raise the engagement level for the source behind an alert.

    This changes real decoy behaviour: the source gets more fake content
    (more honeytokens and fake files). Nothing is executed on the sensor.
    """
    finding = next((f for f in _all_findings() if f["id"] == alert_id), None)
    if finding is None:
        raise HTTPException(404, "Alert not found")

    source = next(
        (s for s in _call("GET", "/api/sources")["sources"] if s["src_ip"] == finding["src_ip"]),
        None,
    )
    persona = source["persona"] if source else "ubuntu_web"
    reason = f"engagement raised to level 3 from the dashboard (alert #{alert_id})"
    _call("POST", f"/api/decoy/{finding['src_ip']}",
          body={"persona": persona, "level": 3, "reason": reason})

    latest = _call("GET", "/api/decoy-actions", {"limit": 1})["actions"]
    action = _map_action(latest[0], [finding]) if latest else None
    return {
        "action_id": action["id"] if action else None,
        "alert_id": alert_id,
        "source_id": finding["src_ip"],
        "selected_decoy": persona,
        "response_type": "engagement_level",
        "decision_reason": reason,
        "simulated_response": {"persona": persona, "engagement_level": 3,
                               "note": "Decoy content served to this source"},
        "simulation_only": False,
    }
