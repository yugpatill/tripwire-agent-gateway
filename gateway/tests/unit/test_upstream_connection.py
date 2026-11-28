"""Upstream connections live in a task of their own.

The MCP server runs each request handler in a short-lived anyio task. If the first
use of an upstream opened its SDK client inside that task, the client's cancel
scopes were left open when the handler finished, and anyio failed the request
("exit a cancel scope that isn't the current task's")."""

from __future__ import annotations

from typing import Any

import anyio
import pytest
from mcp.types import TextContent

from tripwire.playground.mock_servers.servers import build_servers
from tripwire.proxy.upstreams import UpstreamPool


def _text(result: Any) -> str:
    return "".join(b.text for b in result.content if isinstance(b, TextContent))


@pytest.fixture
async def pool() -> Any:
    p = UpstreamPool.in_memory(build_servers().servers)
    yield p
    await p.aclose()


async def test_first_call_from_short_lived_anyio_task(pool: UpstreamPool) -> None:
    out: list[str] = []

    async def handler() -> None:
        out.append(_text(await pool.call("bank", "get_balance", {})))

    async with anyio.create_task_group() as tg:  # raised RuntimeError on exit before
        tg.start_soon(handler)
    assert out == ["Balance: $2,450.00"]
    # The connection outlives the task that opened it.
    assert _text(await pool.call("bank", "get_balance", {})) == "Balance: $2,450.00"


async def test_reset_reconnects(pool: UpstreamPool) -> None:
    up = pool.upstreams["calculator"]
    first = await up.client()
    await up.reset()
    second = await up.client()
    assert first is not second
    assert _text(await pool.call("calculator", "add", {"a": 1, "b": 2})) == "3.0"
