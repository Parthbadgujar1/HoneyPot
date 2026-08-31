import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    String,
    Text,
    Integer,
    Float,
    Boolean,
    DateTime,
    ForeignKey,
    JSON,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, ENUM as PG_ENUM


class Base(DeclarativeBase):
    pass


def gen_uuid() -> str:
    return str(uuid.uuid4())


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=True
    )


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="VIEWER", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class Service(Base, TimestampMixin):
    __tablename__ = "services"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    adapter: Mapped[str] = mapped_column(String(64), default="cowrie")


class HoneypotSession(Base, TimestampMixin):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    session_ref: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    source: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    destination: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    service: Mapped[Optional[str]] = mapped_column(String(32), index=True, nullable=True)
    start_time: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)

    events = relationship("HoneypotEvent", back_populates="session")
    features = relationship("BehaviourFeatures", back_populates="session", uselist=False)
    risk = relationship("RiskAssessment", back_populates="session", uselist=False)


class HoneypotEvent(Base, TimestampMixin):
    __tablename__ = "honeypot_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    event_ref: Mapped[Optional[str]] = mapped_column(String(128), index=True, nullable=True)
    session_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("sessions.id"), index=True, nullable=True
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True, nullable=False)
    source: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    destination: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    service: Mapped[Optional[str]] = mapped_column(String(32), index=True, nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    action: Mapped[Optional[str]] = mapped_column(String(128), index=True, nullable=True)
    target: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    result: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    command: Mapped[Optional[Text]] = mapped_column(Text, nullable=True)
    payload: Mapped[Optional[dict]] = mapped_column("metadata", JSON, nullable=True)
    is_anomaly: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    session = relationship("HoneypotSession", back_populates="events")

    __table_args__ = (
        Index("ix_events_session_timestamp", "session_id", "timestamp"),
    )


class BehaviourFeatures(Base, TimestampMixin):
    __tablename__ = "behaviour_features"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sessions.id"), unique=True, index=True, nullable=False
    )
    feature_version: Mapped[str] = mapped_column(String(32), default="v1")
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    events_per_minute: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    mean_inter_event_time: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    var_inter_event_time: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    burst_frequency: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    failed_auths: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    successful_auths: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    unique_usernames: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    auth_ratio: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    command_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    unique_commands: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    action_diversity: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    resource_diversity: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    repeated_actions: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    discovery_activity: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    sensitive_interactions: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    connection_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    service_diversity: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    request_frequency: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    features_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    session = relationship("HoneypotSession", back_populates="features")


class AnomalyResult(Base, TimestampMixin):
    __tablename__ = "anomaly_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sessions.id"), index=True, nullable=False
    )
    model_name: Mapped[str] = mapped_column(String(64), default="isolation_forest")
    model_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    anomaly_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    label: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    contributing_features: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    reasons: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)


class ClassificationResult(Base, TimestampMixin):
    __tablename__ = "classification_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sessions.id"), index=True, nullable=False
    )
    model_name: Mapped[str] = mapped_column(String(64), default="random_forest")
    model_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    behaviour_class: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    probabilities: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    feature_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)


class RiskAssessment(Base, TimestampMixin):
    __tablename__ = "risk_assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sessions.id"), unique=True, index=True, nullable=False
    )
    score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    policy_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    contributions: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    session = relationship("HoneypotSession", back_populates="risk")


class ModelPrediction(Base, TimestampMixin):
    __tablename__ = "model_predictions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sessions.id"), index=True, nullable=False
    )
    model_name: Mapped[str] = mapped_column(String(64), nullable=False)
    model_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    input_sequence: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    top_predictions: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    top1_label: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    top1_probability: Mapped[Optional[float]] = mapped_column(Float, nullable=True)


class TimelineEvent(Base, TimestampMixin):
    __tablename__ = "timeline_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sessions.id"), index=True, nullable=False
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)


class AttackNode(Base, TimestampMixin):
    __tablename__ = "attack_nodes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sessions.id"), index=True, nullable=False
    )
    node_key: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    node_type: Mapped[str] = mapped_column(String(32), nullable=False)
    label: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    payload: Mapped[Optional[dict]] = mapped_column("metadata", JSON, nullable=True)
    evidence_ids: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    __table_args__ = (
        UniqueConstraint("session_id", "node_key", name="uq_node_session_key"),
    )


class AttackEdge(Base, TimestampMixin):
    __tablename__ = "attack_edges"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sessions.id"), index=True, nullable=False
    )
    source_key: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    target_key: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    edge_type: Mapped[str] = mapped_column(String(32), nullable=False)
    label: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    payload: Mapped[Optional[dict]] = mapped_column("metadata", JSON, nullable=True)
    evidence_ids: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)


class DeceptionPolicy(Base, TimestampMixin):
    __tablename__ = "deception_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    policy_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    trigger_conditions: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    allowed_actions: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    safety_level: Mapped[str] = mapped_column(String(16), default="safe")
    rollback_action: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, default=60)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class DeceptionAction(Base, TimestampMixin):
    __tablename__ = "deception_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sessions.id"), index=True, nullable=False
    )
    policy_id: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    inputs: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="executed")
    result: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    rollback_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)


class AdaptiveDecision(Base, TimestampMixin):
    __tablename__ = "adaptive_decisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sessions.id"), index=True, nullable=False
    )
    policy_id: Mapped[str] = mapped_column(String(64), nullable=False)
    decision: Mapped[str] = mapped_column(String(64), nullable=False)
    inputs: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    selected_policy: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    action: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    result: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    rollback_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)


class ModelVersion(Base, TimestampMixin):
    __tablename__ = "model_versions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    model_type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    features: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    dataset_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    metrics: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    trained_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    artifact_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    __table_args__ = (
        UniqueConstraint("model_type", "version", name="uq_model_type_version"),
    )


class IOCRecord(Base, TimestampMixin):
    __tablename__ = "ioc_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    ioc_type: Mapped[str] = mapped_column(String(32), nullable=False)
    ioc_value: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    source: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    session_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    payload: Mapped[Optional[dict]] = mapped_column("metadata", JSON, nullable=True)


class AuditLog(Base, TimestampMixin):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)


class SystemMetric(Base, TimestampMixin):
    __tablename__ = "system_metrics"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    metric: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    value: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    unit: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
