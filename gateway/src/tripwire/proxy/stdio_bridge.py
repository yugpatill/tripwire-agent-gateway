"""`tripwire mcp stdio`: Tripwire over stdio for clients that launch a command.

A thin MCP server on stdin/stdout that forwards tools/list and tools/call to a
running gateway's `/v1/mcp`, so the guard, policies, approvals and audit trail
stay in one place. It creates one Tripwire session per process and sends it with
every request (`X-Tripwire-Session`).

Environment: TRIPWIRE_API_KEY (required), TRIPWIRE_URL (default
http://localhost:8000), TRIPWIRE_USER_PROMPT (optional: what the user asked for,
so recipients they named count as trusted), TRIPWIRE_AGENT_NAME.
Nothing is written to stdout except MCP messages; logs go to stderr.
"""

from __future__ import annotations

import os
import sys
from contextlib import AsyncExitStack
from typing import Any
from urllib.parse import quote

import anyio
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
)

from tripwire import __version__
from tripwire.proxy.mcp_gateway import INSTRUCTIONS, PROMPT_HEADER, SESSION_HEADER

# Held calls wait up to the approval timeout (120 s by default) on the gateway.
READ_TIMEOUT_S = 300.0


def _err(msg: str) -> None:
    print(f"tripwire-stdio: {msg}", file=sys.stderr, flush=True)


async def _create_session(base: str, key: str, agent: str, prompt: str) -> str:
    async with httpx2.AsyncClient(base_url=base, timeout=15.0) as http:
        r = await http.post(
            "/v1/sessions",
            json={"agent_name": agent, "user_prompt": prompt},
            headers={"Authorization": f"Bearer {key}"},
        )
        r.raise_for_status()
        sid: str = r.json()["session_id"]
        return sid


async def serve(base: str, key: str, agent: str, prompt: str) -> None:
    session_id = await _create_session(base, key, agent, prompt)
    _err(f"connected to {base}, Tripwire session {session_id}")
    headers = {"Authorization": f"Bearer {key}", SESSION_HEADER: session_id}
    if prompt:
        headers[PROMPT_HEADER] = quote(prompt)
    async with AsyncExitStack() as stack:
        http = await stack.enter_async_context(
            httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30.0, read=READ_TIMEOUT_S))
        )
        upstream = await stack.enter_async_context(
            Client(streamable_http_client(f"{base}/v1/mcp", http_client=http))
        )

        async def list_tools(
            ctx: ServerRequestContext[Any, Any], params: PaginatedRequestParams | None
        ) -> ListToolsResult:
            return await upstream.list_tools(cache_mode="refresh")

        async def call_tool(
            ctx: ServerRequestContext[Any, Any], params: CallToolRequestParams
        ) -> CallToolResult:
            try:
                return await upstream.call_tool(
                    params.name, dict(params.arguments or {}), read_timeout_seconds=READ_TIMEOUT_S
                )
            except Exception as exc:  # gateway unreachable: fail closed, visibly
                _err(f"call failed: {exc!r}")
                return CallToolResult(
                    content=[
                        TextContent(type="text", text="Tripwire gateway unreachable; call denied.")
                    ],
                    is_error=True,
                )

        server: Server[Any] = Server(
            "tripwire",
            version=__version__,
            instructions=INSTRUCTIONS,
            on_list_tools=list_tools,
            on_call_tool=call_tool,
        )
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())


def main() -> int:
    key = os.environ.get("TRIPWIRE_API_KEY", "")
    if not key:
        _err("TRIPWIRE_API_KEY is not set")
        return 2
    base = os.environ.get("TRIPWIRE_URL", "http://localhost:8000").rstrip("/")
    agent = os.environ.get("TRIPWIRE_AGENT_NAME", "mcp-stdio")
    prompt = os.environ.get("TRIPWIRE_USER_PROMPT", "")
    try:
        anyio.run(serve, base, key, agent, prompt)
    except KeyboardInterrupt:
        return 0
    return 0
