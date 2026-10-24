"""Operator console: the web interface for every sensor action.

Served on 127.0.0.1 only (see config ``admin.host``). Every API call needs
the admin token as ``Authorization: Bearer <token>``. The token is read from
the HONEYPOT_ADMIN_TOKEN environment variable or the admin token file, and
is created on first start if neither exists.

Attackers reach the decoy URL (the HTTP decoy, port 8080 by default); this
console is never exposed on the network.
"""

from __future__ import annotations

import hmac
import ipaddress
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

from . import intel
from .deception import PERSONAS

if TYPE_CHECKING:
    from .main import SensorRuntime

CONSOLE_HTML = Path(__file__).resolve().parent / "admin" / "index.html"


class BlockRequest(BaseModel):
    ip: str = Field(min_length=3, max_length=45)
    reason: str = Field(default="manual block from operator console", max_length=200)
    ttl_minutes: int | None = Field(default=None, ge=0, le=60 * 24 * 365)


class PersonaRequest(BaseModel):
    persona: str
    level: int = Field(default=2, ge=1, le=3)
    reason: str = Field(default="set by operator", max_length=200)


def create_admin_app(runtime: "SensorRuntime") -> FastAPI:
    app = FastAPI(title="Honeypot operator console", version="1.0.0",
                  docs_url=None, redoc_url=None, openapi_url=None)

    def require_token(request: Request) -> None:
        header = request.headers.get("authorization", "")
        supplied = header[7:] if header.lower().startswith("bearer ") else ""
        if not supplied or not hmac.compare_digest(supplied, runtime.admin_token):
            raise HTTPException(status_code=401, detail="Invalid or missing admin token")

    auth = Depends(require_token)

    @app.get("/", response_class=HTMLResponse)
    def console() -> str:
        return CONSOLE_HTML.read_text(encoding="utf-8")

    @app.get("/api/status", dependencies=[auth])
    def status() -> dict:
        return runtime.status()

    @app.get("/api/findings", dependencies=[auth])
    def findings(
        limit: int = Query(default=100, ge=1, le=500),
        severity: str | None = Query(default=None),
        src_ip: str | None = Query(default=None),
    ) -> dict:
        if severity and severity.upper() not in ("LOW", "MEDIUM", "HIGH"):
            raise HTTPException(status_code=422, detail="severity must be LOW, MEDIUM or HIGH")
        rows = runtime.store.recent_findings(
            limit=limit,
            severity=severity.upper() if severity else None,
            src_ip=src_ip,
        )
        return {"findings": rows}

    @app.get("/api/events", dependencies=[auth])
    def events(
        limit: int = Query(default=100, ge=1, le=500),
        src_ip: str | None = Query(default=None),
        kind: str | None = Query(default=None),
    ) -> dict:
        return {"events": runtime.store.recent_events(limit=limit, src_ip=src_ip, kind=kind)}

    @app.get("/api/sources", dependencies=[auth])
    def sources(limit: int = Query(default=200, ge=1, le=1000)) -> dict:
        rows = runtime.store.source_summary(limit=limit)
        blocked = {block["ip"] for block in runtime.store.active_blocks()}
        for row in rows:
            row["persona"] = runtime.decoys.state_for(row["src_ip"])[0]
            row["engagement_level"] = runtime.decoys.level_for(row["src_ip"])
            row["blocked"] = row["src_ip"] in blocked
        return {"sources": rows}

    @app.get("/api/timeline/{ip}", dependencies=[auth])
    def timeline(ip: str, limit: int = Query(default=200, ge=1, le=1000)) -> dict:
        entries: list[dict] = []
        for event in runtime.store.recent_events(limit=limit, src_ip=ip):
            entries.append({"time": event["time"], "type": "event", "data": event})
        for finding in runtime.store.recent_findings(limit=100, src_ip=ip):
            entries.append({"time": finding["time"], "type": "finding", "data": finding})
        for action in runtime.store.recent_decoy_actions(limit=200):
            if action["src_ip"] == ip:
                entries.append({"time": action["time"], "type": "decoy", "data": action})
        for block in runtime.store.block_history(limit=200):
            if block["ip"] == ip:
                entries.append({"time": block["created"], "type": "block", "data": block})
        entries.sort(key=lambda entry: entry["time"] or "", reverse=True)
        return {"ip": ip, "timeline": entries[:limit]}

    @app.get("/api/blocks", dependencies=[auth])
    def blocks() -> dict:
        return {
            "active": runtime.store.active_blocks(),
            "history": runtime.store.block_history(limit=200),
            "firewall": runtime.blocker.status(),
        }

    @app.post("/api/blocks", dependencies=[auth])
    def block(body: BlockRequest) -> dict:
        try:
            row = runtime.blocker.block(
                body.ip,
                body.reason,
                source="operator",
                ttl_minutes=body.ttl_minutes,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return row

    @app.delete("/api/blocks/{ip}", dependencies=[auth])
    def unblock(ip: str) -> dict:
        try:
            row = runtime.blocker.unblock(ip, source="operator")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if row is None:
            raise HTTPException(status_code=404, detail="No active block for that IP")
        return row

    @app.post("/api/blocks/expire", dependencies=[auth])
    def expire_now() -> dict:
        return {"released": runtime.blocker.expire_due()}

    @app.get("/api/intel/campaigns", dependencies=[auth])
    def campaigns(days: int = Query(default=7, ge=1, le=90)) -> dict:
        report = intel.build_report(runtime.store, days)
        return {
            "generated": report["generated"],
            "window_days": report["window_days"],
            "sources": report["sources"],
            "campaigns": report["campaigns"],
            "unclustered_sources": report["unclustered_sources"],
        }

    @app.get("/api/intel/indicators", dependencies=[auth])
    def indicators(
        days: int = Query(default=7, ge=1, le=90),
        format: str = Query(default="json", pattern="^(json|csv)$"),
    ):
        report = intel.build_report(runtime.store, days)
        if format == "csv":
            return Response(
                content=intel.indicators_csv(report["indicators"]),
                media_type="text/csv",
                headers={"Content-Disposition": 'attachment; filename="honeypot-indicators.csv"'},
            )
        return {
            "generated": report["generated"],
            "window_days": report["window_days"],
            "indicators": report["indicators"],
        }

    @app.get("/api/personas", dependencies=[auth])
    def personas() -> dict:
        return {"personas": PERSONAS}

    @app.get("/api/decoy-actions", dependencies=[auth])
    def decoy_actions(limit: int = Query(default=100, ge=1, le=500)) -> dict:
        return {"actions": runtime.store.recent_decoy_actions(limit=limit)}

    @app.post("/api/decoy/{ip}", dependencies=[auth])
    def set_persona(ip: str, body: PersonaRequest) -> dict:
        if body.persona not in PERSONAS:
            raise HTTPException(status_code=400, detail="Unknown persona")
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid IP address") from exc
        runtime.decoys.set_persona(ip, body.persona, body.level, f"operator: {body.reason}")
        return {"ip": ip, "persona": body.persona, "level": body.level}

    return app
