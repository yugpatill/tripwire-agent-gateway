"""Persistence of sessions and decisions (Postgres in production)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tripwire.db import models as db

log = structlog.get_logger(__name__)


@dataclass(slots=True)
class EventRecord:
    id: UUID
    session_id: UUID
    kind: str  # call | result
    tool: str
    payload: dict[str, Any]
    action: str
    enforced_action: str
    rule_id: str | None
    message: str
    labels: dict[str, Any]
    detectors: list[Any]
    edges: list[Any]
    latency_ms: float
    stage_timings: dict[str, float]


@dataclass(slots=True)
class SessionRecord:
    id: UUID
    agent_name: str
    user_prompt: str
    prompt_entities: list[str]
    mode: str
    api_key_id: UUID | None = None


class Recorder(Protocol):
    async def record_session(self, rec: SessionRecord) -> None: ...
    async def record_event(self, rec: EventRecord) -> None: ...
    async def add_detector(self, event_id: UUID, detector: dict[str, Any]) -> None:
        """Append a detector result to a recorded event (shadow classifier)."""
        ...


@dataclass
class MemoryRecorder:
    sessions: list[SessionRecord] = field(default_factory=list)
    events: list[EventRecord] = field(default_factory=list)

    async def record_session(self, rec: SessionRecord) -> None:
        self.sessions.append(rec)

    async def record_event(self, rec: EventRecord) -> None:
        self.events.append(rec)

    async def add_detector(self, event_id: UUID, detector: dict[str, Any]) -> None:
        for e in self.events:
            if e.id == event_id:
                e.detectors = [*e.detectors, detector]


class SqlRecorder:
    def __init__(
        self,
        factory: async_sessionmaker[AsyncSession],
        on_event: Callable[[EventRecord], Awaitable[None]] | None = None,
    ) -> None:
        """`on_event`: called after each event is stored (the console's live stream)."""
        self._factory = factory
        self._on_event = on_event

    async def record_session(self, rec: SessionRecord) -> None:
        async with self._factory() as s, s.begin():
            s.add(
                db.Session(
                    id=rec.id,
                    agent_name=rec.agent_name,
                    user_prompt=rec.user_prompt,
                    prompt_entities=rec.prompt_entities,
                    mode=rec.mode,
                    api_key_id=rec.api_key_id,
                )
            )

    async def record_event(self, rec: EventRecord) -> None:
        async with self._factory() as s, s.begin():
            s.add(
                db.Event(
                    id=rec.id,
                    session_id=rec.session_id,
                    kind=rec.kind,
                    tool=rec.tool,
                    payload=rec.payload,
                    action=rec.action,
                    enforced_action=rec.enforced_action,
                    rule_id=rec.rule_id,
                    message=rec.message,
                    labels=rec.labels,
                    detectors=rec.detectors,
                    edges=rec.edges,
                    latency_ms=rec.latency_ms,
                    stage_timings=rec.stage_timings,
                )
            )
        if self._on_event is not None:
            try:
                await self._on_event(rec)
            except Exception as exc:  # the live stream is best effort
                log.warning("recorder.publish_failed", error=repr(exc))

    async def add_detector(self, event_id: UUID, detector: dict[str, Any]) -> None:
        async with self._factory() as s, s.begin():
            row = await s.get(db.Event, event_id, with_for_update=True)
            if row is not None:
                # Reassign (not append) so the JSON column is marked dirty.
                row.detectors = [*row.detectors, detector]
