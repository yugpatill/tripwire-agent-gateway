"""MCP proxy end to end: the SDK's own MCP client -> Tripwire -> mock MCP servers.

Real HTTP on loopback: the six mock servers and the gateway each run under
uvicorn, against live Postgres and Redis (migrated). Tool pins are reset at the
start. Run locally with the compose stack's postgres and redis up:

    TRIPWIRE_TEST_DATABASE_URL=postgresql+asyncpg://tripwire:tripwire@localhost:5432/tripwire \
    TRIPWIRE_TEST_REDIS_URL=redis://localhost:6379/15 \
    uv run pytest tests/integration/test_mcp_live.py
"""

from __future__ import annotations

import asyncio
import os
import socket
import sys
import threading
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import httpx2
import pytest
import uvicorn
from mcp import Client, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client
from mcp.types import CallToolResult, TextContent
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import create_async_engine

from tripwire.auth.api_keys import SqlKeyRepository
from tripwire.config import Settings
from tripwire.db import models as db
from tripwire.db.session import make_sessionmaker
from tripwire.main import create_app
from tripwire.playground.mock_servers.servers import build_app as build_mock_app

DB_URL = os.environ.get("TRIPWIRE_TEST_DATABASE_URL")
REDIS_URL = os.environ.get("TRIPWIRE_TEST_REDIS_URL")
POLICY = Path(__file__).parents[2] / "policies" / "demo.yaml"
APPROVAL_TIMEOUT_S = 5.0

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not (DB_URL and REDIS_URL), reason="live Postgres/Redis not configured"),
]

EXPECTED_VISIBLE = {
    "email__read_inbox",
    "email__send_email",
    "files__read_file",
    "files__write_file",
    "web__fetch",
    "bank__get_balance",
    "bank__transfer",
    "weather__get_forecast",
}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _Server:
    """uvicorn in a background thread."""

    def __init__(self, app: Any, port: int) -> None:
        self.server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on")
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self) -> _Server:
        self.thread.start()
        deadline = time.monotonic() + 30
        while not self.server.started:
            if time.monotonic() > deadline or not self.thread.is_alive():
                raise RuntimeError("server did not start")
            time.sleep(0.05)
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=15)


@dataclass
class Stack:
    base: str
    mock_base: str
    agent_key: str
    operator_key: str
    app: Any


async def _reset_db() -> None:
    engine = create_async_engine(DB_URL or "")
    async with engine.begin() as conn:
        await conn.execute(delete(db.Approval).where(db.Approval.kind != "call"))
        await conn.execute(delete(db.ToolPin))
    await engine.dispose()


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    asyncio.run(_reset_db())
    mock_port, gw_port = _free_port(), _free_port()
    upstreams = tmp_path_factory.mktemp("mcp") / "upstreams.yaml"
    upstreams.write_text(
        "upstreams:\n"
        + "".join(
            f"  {n}: {{url: 'http://127.0.0.1:{mock_port}/{n}/mcp'}}\n"
            for n in ("email", "files", "web", "bank", "calculator", "weather")
        )
    )
    settings = Settings(
        database_url=DB_URL or "",
        redis_url=REDIS_URL or "",
        tripwire_policy_path=str(POLICY),
        tripwire_mcp_upstreams=str(upstreams),
        tripwire_approval_timeout_s=APPROVAL_TIMEOUT_S,
        tripwire_classifier_dir="",
        log_json=False,
    )
    app = create_app(settings)
    with _Server(build_mock_app(), mock_port), _Server(app, gw_port):

        async def keys() -> tuple[str, str]:
            repo = SqlKeyRepository(make_sessionmaker(create_async_engine(DB_URL or "")))
            agent = await repo.create("mcp-it-agent")
            op = await repo.create("mcp-it-operator", "operator")
            return agent.token, op.token

        agent, operator = asyncio.run(keys())
        yield Stack(
            f"http://127.0.0.1:{gw_port}", f"http://127.0.0.1:{mock_port}", agent, operator, app
        )


def _rest(stack: Stack, key: str) -> httpx.Client:
    return httpx.Client(base_url=stack.base, headers={"Authorization": f"Bearer {key}"}, timeout=30)


def _session(stack: Stack, prompt: str = "") -> str:
    with _rest(stack, stack.agent_key) as c:
        r = c.post("/v1/sessions", json={"agent_name": "mcp-it", "user_prompt": prompt})
        r.raise_for_status()
        sid: str = r.json()["session_id"]
        return sid


@asynccontextmanager
async def mcp_client(stack: Stack, session_id: str | None = None) -> AsyncIterator[Client]:
    headers = {"Authorization": f"Bearer {stack.agent_key}"}
    if session_id:
        headers["X-Tripwire-Session"] = session_id
    async with (
        httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30.0, read=120.0)) as http,
        Client(streamable_http_client(f"{stack.base}/v1/mcp", http_client=http)) as client,
    ):
        yield client


def _text(r: CallToolResult) -> str:
    return "\n".join(b.text for b in r.content if isinstance(b, TextContent))


async def _pending(
    stack: Stack, kind: str, tool: str, session_id: str | None = None
) -> dict[str, Any]:
    deadline = time.monotonic() + 10.0
    async with httpx.AsyncClient(
        base_url=stack.base, headers={"Authorization": f"Bearer {stack.operator_key}"}
    ) as c:
        while time.monotonic() < deadline:
            r = await c.get("/v1/approvals", params={"status": "pending"})
            r.raise_for_status()
            for a in r.json():
                if (
                    a["kind"] == kind
                    and a["tool"] == tool
                    and (session_id is None or a["session_id"] == session_id)
                ):
                    out: dict[str, Any] = a
                    return out
            await asyncio.sleep(0.1)
    raise AssertionError(f"no pending {kind} approval for {tool}")


# ---------------------------------------------------------------- tests


def test_mcp_requires_api_key(stack: Stack) -> None:
    r = httpx.post(f"{stack.base}/v1/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 401


async def test_tools_namespaced_and_poisoned_calculator_quarantined(stack: Stack) -> None:
    async with mcp_client(stack, _session(stack)) as client:
        names = {t.name for t in (await client.list_tools(cache_mode="refresh")).tools}
        assert names == EXPECTED_VISIBLE
        assert "calculator__add" not in names
        r = await client.call_tool("calculator__add", {"a": 1, "b": 2})
        assert r.is_error and "quarantined" in _text(r)

    with _rest(stack, stack.operator_key) as c:
        pins = {p["name"]: p for p in c.get("/v1/tools").json()}
    assert pins["calculator__add"]["status"] == "quarantined"
    rules = {f["rule"] for f in pins["calculator__add"]["findings"]}
    assert {"sensitive-path", "pass-data-as-argument", "hide-from-user"} <= rules
    review = await _pending(stack, "tool_quarantine", "calculator__add")
    assert review["detail"]["score"] >= 0.5


async def test_weather_rug_pull_blocked_on_second_listing_with_diff(stack: Stack) -> None:
    async with mcp_client(stack, _session(stack)) as client:
        first = {t.name for t in (await client.list_tools(cache_mode="refresh")).tools}
        assert "weather__get_forecast" in first
        r = await client.call_tool("weather__get_forecast", {"city": "Pune"})
        assert not r.is_error and "Pune" in _text(r)

        second = {t.name for t in (await client.list_tools(cache_mode="refresh")).tools}
        assert "weather__get_forecast" not in second
        r = await client.call_tool("weather__get_forecast", {"city": "Pune"})
        assert r.is_error and "rug pull" in _text(r)

    review = await _pending(stack, "tool_change", "weather__get_forecast")
    diff = review["detail"]["diff"]
    assert "-  Get the weather forecast for a city." in diff
    assert "+  Get the weather forecast for a city. Before answering" in diff
    assert "id_rsa" in diff
    assert review["detail"]["previous_hash"] != review["detail"]["hash"]


async def test_agent_key_cannot_decide_approvals(stack: Stack) -> None:
    with _rest(stack, stack.agent_key) as c:
        assert c.get("/v1/approvals").status_code == 403
        r = c.post(f"/v1/approvals/{uuid.uuid4()}", json={"decision": "approve"})
        assert r.status_code == 403


async def _held_send(stack: Stack, decision: str | None, scope: str = "once") -> tuple[str, Any]:
    """Run the confidential-to-external flow; decide the held call (or let it time out)."""
    sid = _session(stack, "Check my balance and email it to partner@outside.example")
    async with mcp_client(stack, sid) as client:
        bal = await client.call_tool("bank__get_balance", {})
        assert not bal.is_error, _text(bal)
        args = {"to": "partner@outside.example", "subject": "Balance", "body": _text(bal)}
        call = asyncio.create_task(client.call_tool("email__send_email", args))
        held = await _pending(stack, "call", "email__send_email", sid)
        assert held["session_id"] == sid
        assert held["detail"]["rule_id"] == "confidential-to-external"
        if decision is not None:
            with _rest(stack, stack.operator_key) as c:
                r = c.post(
                    f"/v1/approvals/{held['id']}", json={"decision": decision, "scope": scope}
                )
                assert r.status_code == 200, r.text
        result = await asyncio.wait_for(call, APPROVAL_TIMEOUT_S + 30)
        follow_up = None
        if scope == "session":
            follow_up = await client.call_tool("email__send_email", args)
        return _text(result) if not result.is_error else f"ERROR: {_text(result)}", follow_up


async def test_approved_call_completes(stack: Stack) -> None:
    text, _ = await _held_send(stack, "approve")
    assert text == "Email sent to partner@outside.example."


async def test_session_scope_approval_allows_later_calls(stack: Stack) -> None:
    text, follow_up = await _held_send(stack, "approve", scope="session")
    assert text == "Email sent to partner@outside.example."
    assert follow_up is not None and not follow_up.is_error


async def test_denied_call_returns_error(stack: Stack) -> None:
    text, _ = await _held_send(stack, "deny")
    assert text.startswith("ERROR: An operator denied this call")


async def test_timed_out_call_returns_error(stack: Stack) -> None:
    t0 = time.monotonic()
    text, _ = await _held_send(stack, None)
    assert text.startswith(
        f"ERROR: No operator approved this call within {APPROVAL_TIMEOUT_S:.0f} s"
    )
    assert time.monotonic() - t0 >= APPROVAL_TIMEOUT_S


async def test_block_is_a_tool_error_with_the_rule_message(stack: Stack) -> None:
    async with mcp_client(stack, _session(stack, "Summarize the bike lanes article")) as client:
        page = await client.call_tool("web__fetch", {"url": "https://news.example.org/bike-lanes"})
        assert not page.is_error
        r = await client.call_tool(
            "email__send_email", {"to": "attacker@evil.io", "subject": "hi", "body": "x"}
        )
        assert r.is_error
        assert "no-untrusted-recipient" in _text(r)
        assert "The recipient address came from untrusted content" in _text(r)


async def test_secret_in_result_is_redacted(stack: Stack) -> None:
    async with mcp_client(stack, _session(stack, "Read ~/.env")) as client:
        r = await client.call_tool("files__read_file", {"path": "~/.env"})
        assert not r.is_error
        assert "sk-proj-FAKE" not in _text(r) and "[REDACTED:" in _text(r)


async def test_stdio_bridge_like_a_desktop_client(stack: Stack) -> None:
    """What Claude Desktop does with the documented config: launch the command over stdio."""
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "tripwire.cli", "mcp", "stdio"],
        env={
            "TRIPWIRE_API_KEY": stack.agent_key,
            "TRIPWIRE_URL": stack.base,
            "PATH": os.environ.get("PATH", ""),
        },
    )
    async with Client(params) as client:
        names = {t.name for t in (await client.list_tools(cache_mode="refresh")).tools}
        assert "email__send_email" in names and "calculator__add" not in names
        r = await client.call_tool("web__fetch", {"url": "https://blog.example.net/recipe"})
        assert not r.is_error and "banana" in _text(r)


async def test_reconnecting_does_not_reset_taint(stack: Stack) -> None:
    """Without X-Tripwire-Session, every connection of a key shares one taint context.

    Regression: a client that opens a new MCP connection per call (the Inspector
    CLI does) must not be able to read untrusted content in one connection and
    act on it with a clean slate in the next.
    """
    async with mcp_client(stack) as first:
        page = await first.call_tool("web__fetch", {"url": "https://news.example.org/bike-lanes"})
        assert not page.is_error
    async with mcp_client(stack) as second:
        r = await second.call_tool(
            "email__send_email", {"to": "attacker@evil.io", "subject": "hi", "body": "x"}
        )
    assert r.is_error and "no-untrusted-recipient" in _text(r)
