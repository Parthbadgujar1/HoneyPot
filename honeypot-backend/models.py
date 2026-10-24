from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    JSON,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class ConnectionEvent(Base):
    __tablename__ = "connection_events"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True
    )
    source_id: Mapped[str] = mapped_column(
        String(128), index=True
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )
    destination_port: Mapped[int] = mapped_column(Integer)
    success: Mapped[bool] = mapped_column(Boolean)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class DetectionAlert(Base):
    __tablename__ = "detection_alerts"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True
    )
    source_id: Mapped[str] = mapped_column(
        String(128), index=True
    )
    window_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )
    attempts_10m: Mapped[int] = mapped_column(Integer)
    unique_ports_60s: Mapped[int] = mapped_column(Integer)
    unique_ports_10m: Mapped[int] = mapped_column(Integer)
    failure_ratio_10m: Mapped[float] = mapped_column(Float)
    score: Mapped[int] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16))
    reasons: Mapped[list] = mapped_column(JSON)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class DeceptionAction(Base):
    __tablename__ = "deception_actions"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True
    )

    alert_id: Mapped[int] = mapped_column(
        ForeignKey("detection_alerts.id"), index=True
    )

    source_id: Mapped[str] = mapped_column(
        String(128), index=True
    )

    selected_decoy: Mapped[str] = mapped_column(String(64))
    response_type: Mapped[str] = mapped_column(String(64))
    decision_reason: Mapped[str] = mapped_column(String(500))

    # Records the simulated response, never a real service response.
    simulated_response: Mapped[dict] = mapped_column(JSON)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
