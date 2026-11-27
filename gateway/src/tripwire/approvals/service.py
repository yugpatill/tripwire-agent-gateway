"""Approvals: held tool calls and tool manifests waiting for an operator.

A held call (`kind="call"`) is created when a policy decision is
`require_approval`. The caller (the MCP proxy) waits up to `timeout_s`
(default 120 s); with no decision by then the approval expires and the call is
denied. An operator approves `once` (this call) or for the `session` (later
calls to the same tool in the same session are allowed without asking).

Tool approvals (`kind="tool_quarantine"` / `"tool_change"`) are created by the
manifest guard for poisoned, shadowing or changed tools. They do not expire on
the 120 s clock; the tool stays hidden until an operator approves it.

Postgres is the source of truth. Every change is also published on an event bus
(Redis pub/sub in production) for the `/v1/stream` WebSocket. Waiters are woken
in-process when the decision lands on the same worker, and otherwise poll the
store once a second, so any worker can decide any approval.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol

import structlog
from pydantic import BaseModel
from sqlalchemy import and_, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tripwire.db import models as db

log = structlog.get_logger(__name__)

ApprovalKind = Literal["call", "tool_quarantine", "tool_change"]
ApprovalStatus = Literal["pending", "approved", "denied", "expired"]
Scope = Literal["once", "session"]
EVENTS_CHANNEL = "tripwire:events"
TOOL_APPROVAL_TTL = timedelta(days=30)
POLL_INTERVAL_S = 1.0


class ApprovalRecord(BaseModel):
    id: uuid.UUID
    kind: ApprovalKind
    tool: str
    session_id: uuid.UUID | None
    event_id: uuid.UUID | None
    status: ApprovalStatus
    scope: Scope | None
    decided_by: str | None
    detail: dict[str, Any]
    expires_at: datetime
    decided_at: datetime | None
    created_at: datetime


def _now() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------- stores


class ApprovalStore(Protocol):
    async def create(
        self,
        kind: ApprovalKind,
        tool: str,
        session_id: uuid.UUID | None,
        event_id: uuid.UUID | None,
        detail: dict[str, Any],
        expires_at: datetime,
    ) -> ApprovalRecord: ...
    async def get(self, approval_id: uuid.UUID) -> ApprovalRecord | None: ...
    async def recent(self, status: ApprovalStatus | None, limit: int) -> list[ApprovalRecord]: ...
    async def finish(
        self,
        approval_id: uuid.UUID,
        status: ApprovalStatus,
        scope: Scope | None,
        decided_by: str,
    ) -> ApprovalRecord | None:
        """Move a *pending* approval to `status`; None if it was not pending."""
        ...

    async def pending_for_tool(self, kind: ApprovalKind, tool: str) -> list[ApprovalRecord]: ...
    async def session_granted(self, session_id: uuid.UUID, tool: str) -> bool: ...


def _from_row(r: db.Approval) -> ApprovalRecord:
    return ApprovalRecord(
        id=r.id,
        kind=r.kind,
        tool=r.tool,
        session_id=r.session_id,
        event_id=r.event_id,
        status=r.status,
        scope=r.scope,
        decided_by=r.decided_by,
        detail=r.detail or {},
        expires_at=r.expires_at,
        decided_at=r.decided_at,
        created_at=r.created_at,
    )


class SqlApprovalStore:
    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = factory

    async def create(
        self,
        kind: ApprovalKind,
        tool: str,
        session_id: uuid.UUID | None,
        event_id: uuid.UUID | None,
        detail: dict[str, Any],
        expires_at: datetime,
    ) -> ApprovalRecord:
        row = db.Approval(
            id=uuid.uuid4(),
            kind=kind,
            tool=tool,
            session_id=session_id,
            event_id=event_id,
            status="pending",
            detail=detail,
            expires_at=expires_at,
        )
        async with self._factory() as s, s.begin():
            s.add(row)
            await s.flush()
            await s.refresh(row)
            return _from_row(row)

    async def get(self, approval_id: uuid.UUID) -> ApprovalRecord | None:
        async with self._factory() as s:
            row = await s.get(db.Approval, approval_id)
            return _from_row(row) if row is not None else None

    async def recent(self, status: ApprovalStatus | None, limit: int) -> list[ApprovalRecord]:
        q = select(db.Approval).order_by(db.Approval.created_at.desc()).limit(limit)
        if status is not None:
            q = q.where(db.Approval.status == status)
        async with self._factory() as s:
            return [_from_row(r) for r in (await s.scalars(q)).all()]

    async def finish(
        self,
        approval_id: uuid.UUID,
        status: ApprovalStatus,
        scope: Scope | None,
        decided_by: str,
    ) -> ApprovalRecord | None:
        async with self._factory() as s, s.begin():
            res = await s.execute(
                update(db.Approval)
                .where(and_(db.Approval.id == approval_id, db.Approval.status == "pending"))
                .values(status=status, scope=scope, decided_by=decided_by, decided_at=_now())
                .returning(db.Approval)
            )
            row = res.scalars().first()
            return _from_row(row) if row is not None else None

    async def pending_for_tool(self, kind: ApprovalKind, tool: str) -> list[ApprovalRecord]:
        q = select(db.Approval).where(
            and_(
                db.Approval.kind == kind, db.Approval.tool == tool, db.Approval.status == "pending"
            )
        )
        async with self._factory() as s:
            return [_from_row(r) for r in (await s.scalars(q)).all()]

    async def session_granted(self, session_id: uuid.UUID, tool: str) -> bool:
        q = (
            select(db.Approval.id)
            .where(
                and_(
                    db.Approval.kind == "call",
                    db.Approval.session_id == session_id,
                    db.Approval.tool == tool,
                    db.Approval.status == "approved",
                    db.Approval.scope == "session",
                )
            )
            .limit(1)
        )
        async with self._factory() as s:
            return (await s.scalar(q)) is not None


@dataclass
class MemoryApprovalStore:
    rows: dict[uuid.UUID, ApprovalRecord] = field(default_factory=dict)

    async def create(
        self,
        kind: ApprovalKind,
        tool: str,
        session_id: uuid.UUID | None,
        event_id: uuid.UUID | None,
        detail: dict[str, Any],
        expires_at: datetime,
    ) -> ApprovalRecord:
        rec = ApprovalRecord(
            id=uuid.uuid4(),
            kind=kind,
            tool=tool,
            session_id=session_id,
            event_id=event_id,
            status="pending",
            scope=None,
            decided_by=None,
            detail=detail,
            expires_at=expires_at,
            decided_at=None,
            created_at=_now(),
        )
        self.rows[rec.id] = rec
        return rec

    async def get(self, approval_id: uuid.UUID) -> ApprovalRecord | None:
        return self.rows.get(approval_id)

    async def recent(self, status: ApprovalStatus | None, limit: int) -> list[ApprovalRecord]:
        rows = [r for r in self.rows.values() if status is None or r.status == status]
        return sorted(rows, key=lambda r: r.created_at, reverse=True)[:limit]

    async def finish(
        self,
        approval_id: uuid.UUID,
        status: ApprovalStatus,
        scope: Scope | None,
        decided_by: str,
    ) -> ApprovalRecord | None:
        rec = self.rows.get(approval_id)
        if rec is None or rec.status != "pending":
            return None
        rec = rec.model_copy(
            update={
                "status": status,
                "scope": scope,
                "decided_by": decided_by,
                "decided_at": _now(),
            }
        )
        self.rows[approval_id] = rec
        return rec

    async def pending_for_tool(self, kind: ApprovalKind, tool: str) -> list[ApprovalRecord]:
        return [
            r
            for r in self.rows.values()
            if r.kind == kind and r.tool == tool and r.status == "pending"
        ]

    async def session_granted(self, session_id: uuid.UUID, tool: str) -> bool:
        return any(
            r.kind == "call"
            and r.session_id == session_id
            and r.tool == tool
            and r.status == "approved"
            and r.scope == "session"
            for r in self.rows.values()
        )


# ---------------------------------------------------------------- event bus


class EventBus(Protocol):
    async def publish(self, event: dict[str, Any]) -> None: ...
    def subscribe(self) -> AsyncIterator[dict[str, Any]]: ...


class MemoryEventBus:
    def __init__(self) -> None:
        self._queues: set[asyncio.Queue[dict[str, Any]]] = set()

    async def publish(self, event: dict[str, Any]) -> None:
        for q in list(self._queues):
            q.put_nowait(event)

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._queues.add(q)
        try:
            while True:
                yield await q.get()
        finally:
            self._queues.discard(q)


class RedisEventBus:
    def __init__(self, redis: Any, channel: str = EVENTS_CHANNEL) -> None:
        self._redis = redis
        self._channel = channel

    async def publish(self, event: dict[str, Any]) -> None:
        await self._redis.publish(self._channel, json.dumps(event, default=str))

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        pubsub = self._redis.pubsub()
        await pubsub.subscribe(self._channel)
        try:
            async for msg in pubsub.listen():
                if msg.get("type") == "message":
                    yield json.loads(msg["data"])
        finally:
            await pubsub.unsubscribe(self._channel)
            await pubsub.aclose()


# ---------------------------------------------------------------- service

ToolDecisionHook = Callable[[ApprovalRecord], Awaitable[None]]


class ApprovalError(Exception):
    """An approval cannot be decided (unknown, already decided, or expired)."""


class ApprovalService:
    def __init__(self, store: ApprovalStore, bus: EventBus, timeout_s: float = 120.0) -> None:
        self.store = store
        self.bus = bus
        self.timeout_s = timeout_s
        self._wakeups: dict[uuid.UUID, asyncio.Event] = {}
        self._tool_hooks: list[ToolDecisionHook] = []

    def on_tool_decision(self, hook: ToolDecisionHook) -> None:
        """Called after an operator decides a tool approval (the manifest guard re-pins)."""
        self._tool_hooks.append(hook)

    async def _publish(self, kind: str, rec: ApprovalRecord) -> None:
        try:
            await self.bus.publish({"type": kind, "approval": rec.model_dump(mode="json")})
        except Exception as exc:  # the stream is best effort; the row is the truth
            log.warning("approvals.publish_failed", error=repr(exc))

    # --- creation

    async def request_call(
        self,
        session_id: uuid.UUID,
        event_id: uuid.UUID,
        tool: str,
        args: dict[str, Any],
        rule_id: str | None,
        message: str,
    ) -> ApprovalRecord:
        rec = await self.store.create(
            "call",
            tool,
            session_id,
            event_id,
            {"args": args, "rule_id": rule_id, "message": message},
            _now() + timedelta(seconds=self.timeout_s),
        )
        log.info("approval.created", approval_id=str(rec.id), tool=tool, rule_id=rule_id)
        await self._publish("approval.created", rec)
        return rec

    async def request_tool(
        self, kind: ApprovalKind, tool: str, detail: dict[str, Any]
    ) -> ApprovalRecord:
        """One pending review per tool and manifest hash; returns the existing one."""
        for rec in await self.store.pending_for_tool(kind, tool):
            if rec.detail.get("hash") == detail.get("hash"):
                return rec
        rec = await self.store.create(kind, tool, None, None, detail, _now() + TOOL_APPROVAL_TTL)
        log.warning("approval.tool_review", approval_id=str(rec.id), tool=tool, kind=kind)
        await self._publish("approval.created", rec)
        return rec

    # --- decisions

    async def get(self, approval_id: uuid.UUID) -> ApprovalRecord | None:
        rec = await self.store.get(approval_id)
        if rec is not None and rec.status == "pending" and rec.expires_at <= _now():
            rec = await self._expire(rec.id) or await self.store.get(approval_id)
        return rec

    async def list_approvals(
        self, status: ApprovalStatus | None = None, limit: int = 100
    ) -> list[ApprovalRecord]:
        rows = await self.store.recent(status, limit)
        out = []
        for r in rows:
            if r.status == "pending" and r.expires_at <= _now():
                r = await self._expire(r.id) or r
                if status == "pending" and r.status != "pending":
                    continue
            out.append(r)
        return out

    async def decide(
        self,
        approval_id: uuid.UUID,
        decision: Literal["approve", "deny"],
        scope: Scope,
        decided_by: str,
    ) -> ApprovalRecord:
        current = await self.get(approval_id)
        if current is None:
            raise ApprovalError("unknown approval")
        if current.status != "pending":
            raise ApprovalError(f"approval is already {current.status}")
        status: ApprovalStatus = "approved" if decision == "approve" else "denied"
        # Session scope only means something for held calls.
        eff_scope: Scope = scope if current.kind == "call" else "once"
        rec = await self.store.finish(approval_id, status, eff_scope, decided_by)
        if rec is None:
            latest = await self.store.get(approval_id)
            raise ApprovalError(f"approval is already {latest.status if latest else 'gone'}")
        log.info(
            "approval.decided",
            approval_id=str(rec.id),
            status=rec.status,
            scope=rec.scope,
            decided_by=decided_by,
        )
        self._wake(rec.id)
        await self._publish("approval.decided", rec)
        if rec.kind != "call":
            for hook in self._tool_hooks:
                await hook(rec)
        return rec

    async def _expire(self, approval_id: uuid.UUID) -> ApprovalRecord | None:
        rec = await self.store.finish(approval_id, "expired", None, "timeout")
        if rec is not None:
            log.info("approval.expired", approval_id=str(rec.id), tool=rec.tool)
            self._wake(rec.id)
            await self._publish("approval.decided", rec)
        return rec

    def _wake(self, approval_id: uuid.UUID) -> None:
        ev = self._wakeups.get(approval_id)
        if ev is not None:
            ev.set()

    async def wait(self, approval_id: uuid.UUID, timeout_s: float | None = None) -> ApprovalStatus:
        """Block until the approval is decided or times out (then it is expired)."""
        deadline = asyncio.get_running_loop().time() + (timeout_s or self.timeout_s)
        ev = self._wakeups.setdefault(approval_id, asyncio.Event())
        try:
            while True:
                rec = await self.store.get(approval_id)
                if rec is None:
                    return "denied"
                if rec.status != "pending":
                    return rec.status
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0 or rec.expires_at <= _now():
                    expired = await self._expire(approval_id)
                    if expired is not None:
                        return "expired"
                    continue  # decided at the last moment: re-read
                try:
                    await asyncio.wait_for(ev.wait(), min(POLL_INTERVAL_S, remaining))
                except TimeoutError:
                    pass
                ev.clear()
        finally:
            self._wakeups.pop(approval_id, None)

    async def session_granted(self, session_id: uuid.UUID, tool: str) -> bool:
        return await self.store.session_granted(session_id, tool)
