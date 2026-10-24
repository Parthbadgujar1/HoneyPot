
from datetime import datetime, timezone

import pandas as pd
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from database import Base, engine, get_db
import models
from recon_detector import detect_reconnaissance
from deception_engine import select_decoy


# --------------------------------------------------
# Database initialization
# --------------------------------------------------

# Creates missing tables. Use migrations for production deployments.
Base.metadata.create_all(bind=engine)


# --------------------------------------------------
# FastAPI application
# --------------------------------------------------

app = FastAPI(
    title="AI-Adaptive Honeypot API",
    version="0.1.0",
    description=(
        "Behavioral reconnaissance detection and simulated "
        "adaptive deception for a controlled laboratory."
    ),
)


# --------------------------------------------------
# Sensor bridge (live decoy data for the dashboard)
# --------------------------------------------------

from sensor_bridge import router as sensor_router  # noqa: E402

app.include_router(sensor_router)


# --------------------------------------------------
# CORS configuration
# --------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Accept", "Content-Type"],
)


# --------------------------------------------------
# Request schemas
# --------------------------------------------------

class ConnectionEventInput(BaseModel):
    source_id: str = Field(min_length=1, max_length=128)
    timestamp: datetime
    destination_port: int = Field(ge=1, le=65535)
    success: bool


class DetectionRequest(BaseModel):
    events: list[ConnectionEventInput] = Field(
        min_length=1,
        max_length=10000,
    )


# --------------------------------------------------
# Helper functions
# --------------------------------------------------

def normalize_datetime(value) -> datetime:
    """
    Convert a datetime, ISO-formatted string, or pandas timestamp
    into a timezone-aware Python datetime.

    Naive timestamps are interpreted as UTC.
    """
    if value is None or pd.isna(value):
        return datetime.now(timezone.utc)

    if isinstance(value, str):
        value = datetime.fromisoformat(
            value.strip().replace("Z", "+00:00")
        )

    if isinstance(value, pd.Timestamp):
        value = value.to_pydatetime()

    if not isinstance(value, datetime):
        raise TypeError(
            f"Expected datetime or ISO timestamp, got "
            f"{type(value).__name__}"
        )

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value


# --------------------------------------------------
# Health endpoints
# --------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "honeypot-detection-api",
    }


@app.get("/db-health")
def db_health(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))

    return {
        "status": "ok",
        "database": "connected",
    }


# --------------------------------------------------
# Behavioral detection endpoint
# --------------------------------------------------

@app.post("/detect")
def detect(
    request: DetectionRequest,
    db: Session = Depends(get_db),
):
    try:
        # Convert request events into the detector's expected format.
        records = [
            event.model_dump()
            for event in request.events
        ]

        events_df = pd.DataFrame(records)

        # Run the existing behavioral reconnaissance detector.
        detections = detect_reconnaissance(events_df)

        if detections is None:
            raise ValueError(
                "The reconnaissance detector returned no result."
            )

        # Validate the detector output before processing alerts.
        required_columns = {
            "source_id",
            "window_end",
            "attempts_10m",
            "unique_ports_60s",
            "unique_ports_10m",
            "failure_ratio_10m",
            "score",
            "severity",
            "status",
            "reasons",
        }

        missing_columns = required_columns - set(detections.columns)

        if missing_columns:
            raise ValueError(
                "Detector output is missing required columns: "
                + ", ".join(sorted(missing_columns))
            )

        # Save all submitted connection events.
        for event in request.events:
            timestamp = normalize_datetime(event.timestamp)

            db.add(
                models.ConnectionEvent(
                    source_id=event.source_id,
                    timestamp=timestamp,
                    destination_port=event.destination_port,
                    success=event.success,
                )
            )

        # Save only rows classified as alerts.
        alerts = []

        for _, result in detections.iterrows():
            status = str(result["status"]).strip().upper()

            if status != "ALERT":
                continue

            # FIX: window_end may be a string, not a datetime.
            window_end = normalize_datetime(result["window_end"])

            reasons = result["reasons"]

            if isinstance(reasons, str):
                reasons = [reasons]
            elif reasons is None or (
                isinstance(reasons, float) and pd.isna(reasons)
            ):
                reasons = []
            else:
                reasons = list(reasons)

            alert = models.DetectionAlert(
                source_id=str(result["source_id"]),
                window_end=window_end,
                attempts_10m=int(result["attempts_10m"]),
                unique_ports_60s=int(result["unique_ports_60s"]),
                unique_ports_10m=int(result["unique_ports_10m"]),
                failure_ratio_10m=float(
                    result["failure_ratio_10m"]
                ),
                score=int(result["score"]),
                severity=str(result["severity"]).upper(),
                status=status,
                reasons=reasons,
            )

            db.add(alert)
            alerts.append(alert)

        # Save events and alerts in one transaction.
        db.commit()

        # Refresh saved alerts so their generated IDs are available.
        for alert in alerts:
            db.refresh(alert)

        return {
            "event_count": len(request.events),
            "source_count": int(events_df["source_id"].nunique()),
            "alert_count": len(alerts),
            "alerts": [
                {
                    "id": alert.id,
                    "source_id": alert.source_id,
                    "window_end": alert.window_end,
                    "score": alert.score,
                    "severity": alert.severity,
                    "status": alert.status,
                    "reasons": alert.reasons,
                }
                for alert in alerts
            ],
        }

    except HTTPException:
        db.rollback()
        raise

    except (ValueError, TypeError, KeyError) as exc:
        db.rollback()
        raise HTTPException(
            status_code=422,
            detail=f"Detection input could not be processed: {exc}",
        ) from exc

    except Exception as exc:
        db.rollback()

        # Print the full error in the backend terminal for debugging.
        import traceback
        traceback.print_exc()

        raise HTTPException(
            status_code=500,
            detail="Detection failed. Check the backend logs.",
        ) from exc


# --------------------------------------------------
# Connection event history
# --------------------------------------------------

@app.get("/events")
def get_events(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    source_id: str | None = Query(default=None, min_length=1),
    db: Session = Depends(get_db),
):
    query = db.query(models.ConnectionEvent)

    if source_id:
        query = query.filter(
            models.ConnectionEvent.source_id == source_id
        )

    total = query.count()

    events = (
        query
        .order_by(
            models.ConnectionEvent.timestamp.desc(),
            models.ConnectionEvent.id.desc(),
        )
        .offset(offset)
        .limit(limit)
        .all()
    )

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": [
            {
                "id": event.id,
                "source_id": event.source_id,
                "timestamp": event.timestamp,
                "destination_port": event.destination_port,
                "success": event.success,
                "received_at": event.received_at,
            }
            for event in events
        ],
    }


# --------------------------------------------------
# Detection alerts
# --------------------------------------------------

@app.get("/alerts")
def get_alerts(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    severity: str | None = Query(default=None),
    source_id: str | None = Query(default=None, min_length=1),
    db: Session = Depends(get_db),
):
    query = db.query(models.DetectionAlert)

    if severity:
        severity = severity.strip().upper()

        if severity not in {"LOW", "MEDIUM", "HIGH"}:
            raise HTTPException(
                status_code=422,
                detail="severity must be LOW, MEDIUM, or HIGH",
            )

        query = query.filter(
            models.DetectionAlert.severity == severity
        )

    if source_id:
        query = query.filter(
            models.DetectionAlert.source_id == source_id
        )

    total = query.count()

    alerts = (
        query
        .order_by(
            models.DetectionAlert.created_at.desc(),
            models.DetectionAlert.id.desc(),
        )
        .offset(offset)
        .limit(limit)
        .all()
    )

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "alerts": [
            {
                "id": alert.id,
                "source_id": alert.source_id,
                "window_end": alert.window_end,
                "attempts_10m": alert.attempts_10m,
                "unique_ports_60s": alert.unique_ports_60s,
                "unique_ports_10m": alert.unique_ports_10m,
                "failure_ratio_10m": alert.failure_ratio_10m,
                "score": alert.score,
                "severity": alert.severity,
                "status": alert.status,
                "reasons": alert.reasons,
                "created_at": alert.created_at,
            }
            for alert in alerts
        ],
    }


@app.get("/alerts/{alert_id}")
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
):
    alert = (
        db.query(models.DetectionAlert)
        .filter(models.DetectionAlert.id == alert_id)
        .first()
    )

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    return {
        "id": alert.id,
        "source_id": alert.source_id,
        "window_end": alert.window_end,
        "attempts_10m": alert.attempts_10m,
        "unique_ports_60s": alert.unique_ports_60s,
        "unique_ports_10m": alert.unique_ports_10m,
        "failure_ratio_10m": alert.failure_ratio_10m,
        "score": alert.score,
        "severity": alert.severity,
        "status": alert.status,
        "reasons": alert.reasons,
        "created_at": alert.created_at,
    }


# --------------------------------------------------
# Adaptive deception endpoint
# --------------------------------------------------

@app.post("/alerts/{alert_id}/deception")
def trigger_deception(
    alert_id: int,
    db: Session = Depends(get_db),
):
    alert = (
        db.query(models.DetectionAlert)
        .filter(models.DetectionAlert.id == alert_id)
        .first()
    )

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    # Select a predefined, simulated decoy response.
    decision = select_decoy(alert)

    action = models.DeceptionAction(
        alert_id=alert.id,
        source_id=alert.source_id,
        selected_decoy=decision["selected_decoy"],
        response_type=decision["response_type"],
        decision_reason=decision["decision_reason"],
        simulated_response=decision["simulated_response"],
    )

    try:
        db.add(action)
        db.commit()
        db.refresh(action)

    except Exception as exc:
        db.rollback()

        import traceback
        traceback.print_exc()

        raise HTTPException(
            status_code=500,
            detail="Could not save deception action.",
        ) from exc

    return {
        "action_id": action.id,
        "alert_id": action.alert_id,
        "source_id": action.source_id,
        "selected_decoy": action.selected_decoy,
        "response_type": action.response_type,
        "decision_reason": action.decision_reason,
        "simulated_response": action.simulated_response,
        "simulation_only": True,
    }

# --------------------------------------------------
# Deception action history
# --------------------------------------------------

@app.get("/deception-actions")
def get_deception_actions(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    alert_id: int | None = Query(default=None, ge=1),
    db: Session = Depends(get_db),
):
    query = db.query(models.DeceptionAction)

    if alert_id is not None:
        query = query.filter(
            models.DeceptionAction.alert_id == alert_id
        )

    total = query.count()

    actions = (
        query
        .order_by(models.DeceptionAction.created_at.desc(),
                  models.DeceptionAction.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "actions": [
            {
                "id": action.id,
                "alert_id": action.alert_id,
                "source_id": action.source_id,
                "selected_decoy": action.selected_decoy,
                "response_type": action.response_type,
                "decision_reason": action.decision_reason,
                "simulated_response": action.simulated_response,
                "created_at": action.created_at,
            }
            for action in actions
        ],
    }
