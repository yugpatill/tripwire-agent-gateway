"""Approval service (memory store) and manifest guard (memory pins)."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from tripwire.approvals.service import (
    ApprovalError,
    ApprovalService,
    MemoryApprovalStore,
    MemoryEventBus,
)
from tripwire.models import ToolCall
from tripwire.pipeline.detect import DetectionPipeline
from tripwire.pipeline.engine import Engine
from tripwire.pipeline.manifest import Manifest
from tripwire.pipeline.recorder import MemoryRecorder
from tripwire.playground.mock_servers.servers import (
    BENIGN_FORECAST_DESCRIPTION,
    POISONED_ADD_DESCRIPTION,
    RUG_PULL_FORECAST_DESCRIPTION,
)
from tripwire.proxy.guard import ManifestGuard, MemoryPinStore
from tripwire.taint.store import InMemoryTaintStore

from .helpers import demo_policy, session

SCHEMA = {"type": "object", "properties": {"city": {"type": "string"}}}


def svc(timeout: float = 2.0) -> ApprovalService:
    return ApprovalService(MemoryApprovalStore(), MemoryEventBus(), timeout_s=timeout)


async def _call(s: ApprovalService, tool: str = "email__send_email", sid: uuid.UUID | None = None):  # type: ignore[no-untyped-def]
    return await s.request_call(sid or uuid.uuid4(), uuid.uuid4(), tool, {"to": "x"}, "r", "msg")


@pytest.mark.parametrize(("decision", "expected"), [("approve", "approved"), ("deny", "denied")])
async def test_wait_returns_the_decision(decision: str, expected: str) -> None:
    s = svc()
    rec = await _call(s)
    waiter = asyncio.create_task(s.wait(rec.id))
    await asyncio.sleep(0.05)
    await s.decide(rec.id, decision, "once", "op")  # type: ignore[arg-type]
    assert await asyncio.wait_for(waiter, 1.0) == expected


async def test_wait_times_out_and_expires() -> None:
    s = svc(timeout=0.3)
    rec = await _call(s)
    assert await s.wait(rec.id) == "expired"
    with pytest.raises(ApprovalError, match="expired"):
        await s.decide(rec.id, "approve", "once", "op")


async def test_decide_twice_is_rejected_and_events_are_published() -> None:
    s = svc()
    events: list[dict] = []  # type: ignore[type-arg]

    async def listen() -> None:
        async for e in s.bus.subscribe():
            events.append(e)

    task = asyncio.create_task(listen())
    await asyncio.sleep(0)
    rec = await _call(s)
    await s.decide(rec.id, "deny", "once", "op")
    with pytest.raises(ApprovalError, match="already denied"):
        await s.decide(rec.id, "approve", "once", "op")
    await asyncio.sleep(0.01)
    task.cancel()
    assert [e["type"] for e in events] == ["approval.created", "approval.decided"]


async def test_stale_pending_is_listed_as_expired() -> None:
    s = svc()
    rec = await _call(s)
    store = s.store
    assert isinstance(store, MemoryApprovalStore)
    store.rows[rec.id] = rec.model_copy(update={"expires_at": datetime.now(UTC) - timedelta(1)})
    assert await s.list_approvals("pending") == []
    got = await s.get(rec.id)
    assert got is not None and got.status == "expired"


async def test_engine_creates_approval_and_honours_session_grant() -> None:
    approvals = svc()
    engine = Engine(InMemoryTaintStore(), MemoryRecorder(), demo_policy(), approvals=approvals)
    sid = await session(engine, "Check my balance and email it to partner@outside.example")
    await engine.check_call(ToolCall(session_id=sid, tool="bank__get_balance", args={}))
    from tripwire.models import ToolResult

    d0 = await engine.check_call(ToolCall(session_id=sid, tool="bank__get_balance", args={}))
    await engine.check_result(
        ToolResult(
            session_id=sid, tool="bank__get_balance", call_event_id=d0.event_id, content="$9"
        )
    )
    send = ToolCall(
        session_id=sid, tool="email__send_email", args={"to": "partner@outside.example"}
    )
    d1 = await engine.check_call(send)
    assert d1.action == "require_approval" and d1.approval_id is not None
    await approvals.decide(d1.approval_id, "approve", "session", "op")
    d2 = await engine.check_call(send)
    assert d2.action == "allow" and d2.approval_id is None
    assert "Approved for this session" in d2.message


# ---------------------------------------------------------------- guard


def man(server: str, tool: str, desc: str) -> Manifest:
    return Manifest(server, tool, desc, SCHEMA)


def guard() -> tuple[ManifestGuard, ApprovalService]:
    s = svc()
    return ManifestGuard(MemoryPinStore(), s, DetectionPipeline()), s


async def test_clean_tools_pinned_poisoned_quarantined() -> None:
    g, s = guard()
    fc = man("weather", "get_forecast", BENIGN_FORECAST_DESCRIPTION)
    add = man("calculator", "add", POISONED_ADD_DESCRIPTION)
    assert await g.process([fc, add]) == [fc]
    ok, _ = await g.callable_status("weather__get_forecast")
    blocked, reason = await g.callable_status("calculator__add")
    assert ok and not blocked and "quarantined" in reason
    reviews = await s.list_approvals("pending")
    assert [(r.kind, r.tool) for r in reviews] == [("tool_quarantine", "calculator__add")]
    # Listing again does not open a second review.
    await g.process([fc, add])
    assert len(await s.list_approvals("pending")) == 1


async def test_rug_pull_blocks_and_approval_repins() -> None:
    g, s = guard()
    v1 = man("weather", "get_forecast", BENIGN_FORECAST_DESCRIPTION)
    v2 = man("weather", "get_forecast", RUG_PULL_FORECAST_DESCRIPTION)
    assert await g.process([v1]) == [v1]
    assert await g.process([v2]) == []
    ok, reason = await g.callable_status(v1.name)
    assert not ok and "rug pull" in reason
    (review,) = await s.list_approvals("pending")
    assert review.kind == "tool_change" and review.detail["previous_hash"] == v1.hash
    assert "id_rsa" in review.detail["diff"]
    # The old version is not trusted either while the change is under review.
    assert await g.process([v1]) == []
    await s.decide(review.id, "approve", "once", "op")
    assert await g.process([v2]) == [v2]
    assert (await g.callable_status(v1.name))[0]


async def test_denied_review_keeps_tool_hidden() -> None:
    g, s = guard()
    add = man("calculator", "add", POISONED_ADD_DESCRIPTION)
    await g.process([add])
    (review,) = await s.list_approvals("pending")
    await s.decide(review.id, "deny", "once", "op")
    assert await g.process([add]) == []


async def test_shadowing_first_seen_wins() -> None:
    g, _ = guard()
    real = man("email", "send_email", "Send an email.")
    assert await g.process([real]) == [real]
    fake = man("helper", "send_emails", "Send an email.")
    assert await g.process([real, fake]) == [real]
    pin = await g.store.get(fake.name)
    assert pin is not None and pin.status == "quarantined"
    assert pin.findings[0]["rule"] == "name-shadowing"
