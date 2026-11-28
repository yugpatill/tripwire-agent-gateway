"""Console read APIs: events, sessions and traces, metrics.

Readable by any console user (the demo account included), so secrets in stored
payloads and matched values are redacted on the way out. Stored rows keep the
originals (taint tracking needs them).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tripwire.auth.console import ConsoleUser, console_reader
from tripwire.db import models as db
from tripwire.pipeline import secrets
from tripwire.pipeline.detect import redact_secrets_in

router = APIRouter(prefix="/v1", tags=["console"])
Reader = Annotated[ConsoleUser, Depends(console_reader)]
STOPPED = ("block", "require_approval")


def factory(request: Request) -> async_sessionmaker[AsyncSession]:
    f: async_sessionmaker[AsyncSession] = request.app.state.sessionmaker
    return f


Factory = Annotated[async_sessionmaker[AsyncSession], Depends(factory)]


class EventView(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID
    created_at: datetime
    kind: str
    tool: str
    action: str
    enforced_action: str
    rule_id: str | None
    message: str
    latency_ms: float
    labels: dict[str, Any]
    detectors: list[Any]
    payload: dict[str, Any]
    edges: list[Any]
    stage_timings: dict[str, Any]


def event_view(e: db.Event) -> EventView:
    edges = [
        {**edge, "matched_value": secrets.redact(str(edge.get("matched_value", "")))}
        for edge in (e.edges or [])
    ]
    return EventView(
        id=e.id,
        session_id=e.session_id,
        created_at=e.created_at,
        kind=e.kind,
        tool=e.tool,
        action=e.action,
        enforced_action=e.enforced_action,
        rule_id=e.rule_id,
        message=e.message,
        latency_ms=e.latency_ms,
        labels=e.labels or {},
        detectors=e.detectors or [],
        payload=redact_secrets_in(e.payload or {}),
        edges=edges,
        stage_timings=e.stage_timings or {},
    )


class EventPage(BaseModel):
    items: list[EventView]
    next_before: datetime | None


@router.get("/events", response_model=EventPage)
async def list_events(
    _: Reader,
    f: Factory,
    kind: Literal["call", "result"] | None = None,
    action: str | None = Query(None, description="enforced action, e.g. block"),
    tool: str | None = None,
    rule_id: str | None = None,
    session_id: uuid.UUID | None = None,
    before: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> EventPage:
    conds = []
    if kind:
        conds.append(db.Event.kind == kind)
    if action:
        conds.append(db.Event.enforced_action == action)
    if tool:
        conds.append(db.Event.tool.ilike(f"%{tool}%"))
    if rule_id:
        conds.append(db.Event.rule_id == rule_id)
    if session_id:
        conds.append(db.Event.session_id == session_id)
    if before:
        conds.append(db.Event.created_at < before)
    q = select(db.Event).order_by(db.Event.created_at.desc()).limit(limit + 1)
    if conds:
        q = q.where(and_(*conds))
    async with f() as s:
        rows = list((await s.scalars(q)).all())
    more = len(rows) > limit
    rows = rows[:limit]
    return EventPage(
        items=[event_view(r) for r in rows], next_before=rows[-1].created_at if more else None
    )


class SessionView(BaseModel):
    id: uuid.UUID
    agent_name: str
    user_prompt: str
    mode: str
    created_at: datetime
    key_name: str | None
    events: int
    stopped: int
    last_event_at: datetime | None


@router.get("/sessions", response_model=list[SessionView])
async def list_sessions(
    _: Reader,
    f: Factory,
    before: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[SessionView]:
    stats = (
        select(
            db.Event.session_id,
            func.count().label("events"),
            func.count().filter(db.Event.enforced_action.in_(STOPPED)).label("stopped"),
            func.max(db.Event.created_at).label("last"),
        )
        .group_by(db.Event.session_id)
        .subquery()
    )
    q = (
        select(db.Session, db.ApiKey.name, stats.c.events, stats.c.stopped, stats.c.last)
        .join(stats, stats.c.session_id == db.Session.id)
        .outerjoin(db.ApiKey, db.ApiKey.id == db.Session.api_key_id)
        .order_by(stats.c.last.desc())
        .limit(limit)
    )
    if before:
        q = q.where(stats.c.last < before)
    async with f() as s:
        rows = (await s.execute(q)).all()
    return [
        SessionView(
            id=sess.id,
            agent_name=sess.agent_name,
            user_prompt=secrets.redact(sess.user_prompt)[:500],
            mode=sess.mode,
            created_at=sess.created_at,
            key_name=key_name,
            events=events,
            stopped=stopped,
            last_event_at=last,
        )
        for sess, key_name, events, stopped, last in rows
    ]


class Trace(BaseModel):
    session: SessionView
    events: list[EventView]
    edges: list[dict[str, Any]]


@router.get("/sessions/{session_id}/trace", response_model=Trace)
async def session_trace(session_id: uuid.UUID, _: Reader, f: Factory) -> Trace:
    async with f() as s:
        sess = await s.get(db.Session, session_id)
        if sess is None:
            raise HTTPException(404, "Unknown session")
        key = await s.get(db.ApiKey, sess.api_key_id) if sess.api_key_id else None
        rows = list(
            (
                await s.scalars(
                    select(db.Event)
                    .where(db.Event.session_id == session_id)
                    .order_by(db.Event.created_at)
                )
            ).all()
        )
    events = [event_view(r) for r in rows]
    edges = [e for ev in events for e in ev.edges]
    return Trace(
        session=SessionView(
            id=sess.id,
            agent_name=sess.agent_name,
            user_prompt=secrets.redact(sess.user_prompt),
            mode=sess.mode,
            created_at=sess.created_at,
            key_name=key.name if key else None,
            events=len(events),
            stopped=sum(e.enforced_action in STOPPED for e in events),
            last_event_at=events[-1].created_at if events else None,
        ),
        events=events,
        edges=edges,
    )


class Summary(BaseModel):
    hours: int
    totals: dict[str, int]
    sessions: int
    latency_ms: dict[str, float | None]
    series: list[dict[str, Any]]
    top_rules: list[dict[str, Any]]
    recent_stops: list[EventView]


@router.get("/metrics/summary", response_model=Summary)
async def metrics_summary(
    _: Reader, f: Factory, hours: Annotated[int, Query(ge=1, le=24 * 30)] = 24
) -> Summary:
    since = datetime.now(UTC) - timedelta(hours=hours)
    recent = db.Event.created_at >= since
    bucket = func.date_trunc("hour", db.Event.created_at).label("bucket")
    async with f() as s:
        total_rows = (
            await s.execute(
                select(db.Event.enforced_action, func.count())
                .where(recent)
                .group_by(db.Event.enforced_action)
            )
        ).all()
        totals: dict[str, int] = {str(act): int(n) for act, n in total_rows}
        sessions = await s.scalar(
            select(func.count(func.distinct(db.Event.session_id))).where(recent)
        )
        p50, p95 = (
            await s.execute(
                select(
                    func.percentile_cont(0.5).within_group(db.Event.latency_ms),
                    func.percentile_cont(0.95).within_group(db.Event.latency_ms),
                ).where(recent)
            )
        ).one()
        series_rows = (
            await s.execute(
                select(bucket, db.Event.enforced_action, func.count())
                .where(recent)
                .group_by(bucket, db.Event.enforced_action)
                .order_by(bucket)
            )
        ).all()
        rules = (
            await s.execute(
                select(db.Event.rule_id, func.count().label("n"))
                .where(and_(recent, db.Event.rule_id.is_not(None)))
                .group_by(db.Event.rule_id)
                .order_by(func.count().desc())
                .limit(8)
            )
        ).all()
        stops = list(
            (
                await s.scalars(
                    select(db.Event)
                    .where(and_(recent, db.Event.enforced_action.in_(STOPPED)))
                    .order_by(db.Event.created_at.desc())
                    .limit(10)
                )
            ).all()
        )
    by_hour: dict[str, dict[str, Any]] = {}
    for b, act, n in series_rows:
        row = by_hour.setdefault(b.isoformat(), {"hour": b.isoformat()})
        row[act] = n
    return Summary(
        hours=hours,
        totals=totals,
        sessions=int(sessions or 0),
        latency_ms={
            "p50": round(p50, 2) if p50 is not None else None,
            "p95": round(p95, 2) if p95 is not None else None,
        },
        series=list(by_hour.values()),
        top_rules=[{"rule_id": r, "count": int(n)} for r, n in rules],
        recent_stops=[event_view(e) for e in stops],
    )
