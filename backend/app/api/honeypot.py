import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models.models import HoneypotEvent, HoneypotSession
from app.security.auth import get_current_user, require_role

router = APIRouter(prefix="/honeypot", tags=["honeypot"])
settings = get_settings()


@router.get("/status")
def honeypot_status(request: Request, user=Depends(get_current_user)):
    adapter = request.app.state.adapter
    collector = request.app.state.collector
    return {
        "adapter": adapter.status(),
        "collector": collector.status(),
        "db": _db_status(request),
        "scenarios": adapter.scenario_names() if hasattr(adapter, "scenario_names") else [],
        "environment": {
            "cowrie_log_path": settings.HONEYPOT_COWRIE_LOG_PATH,
            "poll_interval": settings.HONEYPOT_POLL_INTERVAL,
        },
    }


def _db_status(request: Request) -> dict:
    try:
        db: Session = request.app.state.db_factory()
        db.execute("SELECT 1")
        db.close()
        return {"online": True, "driver": "postgresql"}
    except Exception as e:
        return {"online": False, "error": str(e)}


@router.post("/simulate")
def simulate(
    scenario: str,
    n_sessions: int = 3,
    request: Request = None,
    user=Depends(require_role("RESEARCHER")),
):
    adapter = request.app.state.adapter
    if not hasattr(adapter, "emit_scenario"):
        raise HTTPException(status_code=400, detail="Adapter does not support simulation")
    from app.honeypot.simulator import SCENARIOS

    if scenario not in SCENARIOS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scenario. Choose from {list(SCENARIOS.keys())}",
        )
    emitted = adapter.emit_scenario(scenario, n_sessions=n_sessions)
    # trigger collector to ingest immediately
    request.app.state.collector._run_cycle()
    return {"emitted": emitted, "scenario": scenario, "sessions": n_sessions}


@router.get("/scenarios")
def scenarios(request: Request, user=Depends(get_current_user)):
    from app.honeypot.simulator import SCENARIOS

    return [
        {"id": k, "label": v["label"], "description": v["desc"]}
        for k, v in SCENARIOS.items()
    ]
