"""SQLAlchemy 2 ORM models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, ClassVar

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    type_annotation_map: ClassVar[dict[Any, Any]] = {dict[str, Any]: JSONB, list[Any]: JSONB}


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


def _created_at() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = _uuid_pk()
    agent_name: Mapped[str] = mapped_column(String(200))
    user_prompt: Mapped[str] = mapped_column(Text)
    prompt_entities: Mapped[list[Any]] = mapped_column(default=list)
    mode: Mapped[str] = mapped_column(String(16), default="enforce")
    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    api_key_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("api_keys.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = _created_at()


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_session_created", "session_id", "created_at"),
        Index("ix_events_action_created", "action", "created_at"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE")
    )
    kind: Mapped[str] = mapped_column(String(32))  # call | result | manifest
    tool: Mapped[str] = mapped_column(String(300))
    payload: Mapped[dict[str, Any]] = mapped_column(default=dict)
    action: Mapped[str] = mapped_column(String(32))
    enforced_action: Mapped[str] = mapped_column(String(32))
    rule_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    message: Mapped[str] = mapped_column(Text, default="")
    labels: Mapped[dict[str, Any]] = mapped_column(default=dict)
    detectors: Mapped[list[Any]] = mapped_column(default=list)
    edges: Mapped[list[Any]] = mapped_column(default=list)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    stage_timings: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = _created_at()


class Approval(Base):
    __tablename__ = "approvals"
    __table_args__ = (Index("ix_approvals_status", "status"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("events.id", ondelete="CASCADE")
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE")
    )
    tool: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    scope: Mapped[str | None] = mapped_column(String(16), nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = _created_at()


class ToolPin(Base):
    __tablename__ = "tool_pins"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(300), unique=True)
    server: Mapped[str] = mapped_column(String(200))
    description_hash: Mapped[str] = mapped_column(String(64))
    manifest: Mapped[dict[str, Any]] = mapped_column(default=dict)
    pending_manifest: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="pinned")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    flagged_spans: Mapped[list[Any]] = mapped_column(default=list)
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("version"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    version: Mapped[int] = mapped_column(Integer)
    yaml: Mapped[str] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    created_at: Mapped[datetime] = _created_at()


class EvalRun(Base):
    __tablename__ = "eval_runs"

    id: Mapped[uuid.UUID] = _uuid_pk()
    suite: Mapped[str] = mapped_column(String(100))
    config: Mapped[str] = mapped_column(String(100))
    model: Mapped[str] = mapped_column(String(200))
    metrics: Mapped[dict[str, Any]] = mapped_column(default=dict)
    source_file: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = _created_at()


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(200))
    prefix: Mapped[str] = mapped_column(String(16), index=True)
    key_hash: Mapped[str] = mapped_column(String(255))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = _created_at()


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = _uuid_pk()
    email: Mapped[str] = mapped_column(String(320), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="readonly")  # admin | readonly
    created_at: Mapped[datetime] = _created_at()
