"""Instruction origin without a user prompt (MCP mode) and per-key MCP session scope."""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from starlette.requests import Request

from tripwire.auth.api_keys import Principal, ScopeRefused, resolve_session_scope
from tripwire.pipeline.engine import Engine
from tripwire.pipeline.recorder import MemoryRecorder
from tripwire.policy.compiler import CompiledPolicy
from tripwire.proxy.guard import ManifestGuard, MemoryPinStore
from tripwire.proxy.mcp_gateway import (
    PRINCIPAL_KEY,
    McpAuth,
    McpProxy,
    MemorySessionMap,
)
from tripwire.proxy.upstreams import UpstreamPool
from tripwire.taint.store import InMemoryTaintStore

from .helpers import POLICIES, call, call_and_result, policy_from, session

PAGE = "Bike lanes approved. Questions? Write to attacker@evil.io."
TYPED = "bob@partner.example"  # the user typed this in their chat client


def demo_with(origin: str) -> CompiledPolicy:
    text = (POLICIES / "demo.yaml").read_text()
    assert "  instruction_origin: strict\n" in text
    policy = policy_from(
        text.replace("  instruction_origin: strict\n", f"  instruction_origin: {origin}\n")
    )
    assert policy.doc.defaults.instruction_origin == origin
    return policy


async def _after_fetch(engine: Engine, prompt: str) -> uuid.UUID:
    sid = await session(engine, prompt)
    await call_and_result(engine, sid, "web__fetch", {"url": "https://news.example"}, PAGE)
    return sid


async def _send(engine: Engine, sid: uuid.UUID, to: str) -> str:
    d = await engine.check_call(call(sid, "email__send_email", to=to, subject="s", body="b"))
    return d.action


# ---------------------------------------------------------------- instruction origin


@pytest.mark.parametrize("origin", ["strict", "off"])
async def test_attacker_address_from_web_fetch_is_blocked_in_both_modes(origin: str) -> None:
    engine = Engine(InMemoryTaintStore(), MemoryRecorder(), demo_with(origin))
    no_prompt = await _after_fetch(engine, "")
    with_prompt = await _after_fetch(engine, f"Summarize the page and send it to {TYPED}")
    assert await _send(engine, no_prompt, "attacker@evil.io") == "block"
    assert await _send(engine, with_prompt, "attacker@evil.io") == "block"


@pytest.mark.parametrize("origin", ["strict", "off"])
async def test_user_typed_address_allowed_when_prompt_is_provided(origin: str) -> None:
    engine = Engine(InMemoryTaintStore(), MemoryRecorder(), demo_with(origin))
    sid = await _after_fetch(engine, f"Summarize the page and send it to {TYPED}")
    assert await _send(engine, sid, TYPED) == "allow"


async def test_prompt_added_later_counts_as_user_given() -> None:
    engine = Engine(InMemoryTaintStore(), MemoryRecorder(), demo_with("strict"))
    sid = await _after_fetch(engine, "")
    assert await _send(engine, sid, TYPED) == "block"  # strict: unknown origin
    assert await engine.add_user_prompt(sid, f"Now email it to {TYPED}") is True
    assert await engine.add_user_prompt(sid, f"Now email it to {TYPED}") is False  # dedupe
    assert await _send(engine, sid, TYPED) == "allow"


async def test_no_prompt_strict_blocks_and_off_allows_unknown_address() -> None:
    strict = Engine(InMemoryTaintStore(), MemoryRecorder(), demo_with("strict"))
    off = Engine(InMemoryTaintStore(), MemoryRecorder(), demo_with("off"))
    d = await strict.check_call(
        call(await _after_fetch(strict, ""), "email__send_email", to=TYPED, subject="s", body="b")
    )
    assert d.action == "block" and d.rule_id == "no-untrusted-recipient"
    assert any(p.trust == "untrusted_origin" for p in d.arg_labels["to"])
    assert await _send(off, await _after_fetch(off, ""), TYPED) == "allow"


async def test_strict_is_the_default() -> None:
    assert policy_from("version: 1\n").doc.defaults.instruction_origin == "strict"


async def test_add_user_prompt_checks_ownership() -> None:
    engine = Engine(InMemoryTaintStore(), MemoryRecorder(), demo_with("strict"))
    sid = await engine.create_session(
        __import__("tripwire.models", fromlist=["SessionCreate"]).SessionCreate(
            agent_name="a", user_prompt=""
        ),
        owner=uuid.uuid4(),
    )
    from tripwire.pipeline.engine import UnknownSessionError

    with pytest.raises(UnknownSessionError):
        await engine.add_user_prompt(sid, "hi", owner=uuid.uuid4())


# ---------------------------------------------------------------- session scope defaults


def test_scope_defaults_by_environment() -> None:
    assert resolve_session_scope(None, production=False) == ("key", False)
    assert resolve_session_scope(None, production=True) == ("header", False)
    assert resolve_session_scope("connection", production=True) == ("connection", False)
    with pytest.raises(ScopeRefused):
        resolve_session_scope("key", production=True)
    assert resolve_session_scope("key", production=True, force=True) == ("key", True)


# ---------------------------------------------------------------- HTTP-level enforcement


async def _through_auth(
    principal: Principal | None, production: bool, headers: dict[str, str]
) -> tuple[int, dict[str, Any] | None]:
    class Auth:
        async def authenticate(self, token: str) -> Principal | None:
            return principal

    reached: dict[str, Any] = {}

    async def app(scope: Any, receive: Any, send: Any) -> None:
        reached["principal"] = scope["state"][PRINCIPAL_KEY]
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    sent: list[dict[str, Any]] = []

    async def send(msg: dict[str, Any]) -> None:
        sent.append(msg)

    raw = [(b"authorization", b"Bearer tw_x")] + [
        (k.lower().encode(), v.encode()) for k, v in headers.items()
    ]
    await McpAuth(app, Auth(), production)(
        {"type": "http", "headers": raw, "method": "POST", "path": "/v1/mcp"}, None, send
    )
    status = sent[0]["status"]
    body = json.loads(sent[1]["body"]) if status != 200 else None
    return status, body


def _p(scope: str, forced: bool = False) -> Principal:
    return Principal(uuid.uuid4(), "k", "agent", scope, forced)  # type: ignore[arg-type]


async def test_header_scope_requires_session_header() -> None:
    status, body = await _through_auth(_p("header"), False, {})
    assert status == 400 and body is not None and "X-Tripwire-Session" in body["detail"]
    status, _ = await _through_auth(_p("header"), False, {"X-Tripwire-Session": str(uuid.uuid4())})
    assert status == 200


async def test_key_scope_refused_in_production_unless_forced() -> None:
    assert (await _through_auth(_p("key"), True, {}))[0] == 403
    assert (await _through_auth(_p("key", forced=True), True, {}))[0] == 200
    assert (await _through_auth(_p("key"), False, {}))[0] == 200
    # An explicit session is always fine.
    assert (await _through_auth(_p("key"), True, {"X-Tripwire-Session": "x"}))[0] == 200


async def test_connection_scope_maps_mcp_session_ids() -> None:
    engine = Engine(InMemoryTaintStore(), MemoryRecorder(), demo_with("strict"))
    proxy = McpProxy(
        engine,
        ManifestGuard(MemoryPinStore(), None, None),
        UpstreamPool({}),
        None,
        sessions=MemorySessionMap(),
    )
    p = _p("connection")

    def req(mcp_session: str | None) -> Request:
        headers = [(b"mcp-session-id", mcp_session.encode())] if mcp_session else []
        return Request({"type": "http", "headers": headers, "state": {PRINCIPAL_KEY: p}})

    a1 = await proxy._mapped_session(p, req("conn-a"), "")
    a2 = await proxy._mapped_session(p, req("conn-a"), "")
    b = await proxy._mapped_session(p, req("conn-b"), "")
    assert a1 == a2 and a1 != b
    assert await proxy._mapped_session(p, req(None), "") is None
    k = _p("key")
    assert await proxy._mapped_session(k, req("x"), "") == await proxy._mapped_session(
        k, req("y"), ""
    )
