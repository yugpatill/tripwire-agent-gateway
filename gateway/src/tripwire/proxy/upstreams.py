"""Upstream MCP servers Tripwire proxies to, from a YAML file.

    upstreams:
      email:   {url: "http://mock-mcp:9100/email/mcp"}
      files:   {command: "uvx", args: ["some-mcp-server"], env: {ROOT: "/data"}}
      search:
        url: "https://mcp.example.com/mcp"
        headers: {Authorization: "Bearer ${SEARCH_TOKEN}"}

Names become the namespace (`email__send_email`), so they may not contain `__`.
`${VAR}` in `headers` and `env` values is read from the gateway's environment.
One SDK `Client` per upstream is opened lazily and kept; a failed upstream is
reconnected on the next request, and its tools disappear from the listing while
it is down.
"""

from __future__ import annotations

import asyncio
import os
import re
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

import httpx2
import structlog
import yaml
from mcp import Client, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client
from mcp.types import CallToolResult, Tool
from pydantic import BaseModel, ConfigDict, Field, model_validator

log = structlog.get_logger(__name__)

_ENV_REF = re.compile(r"\$\{([A-Z0-9_]+)\}")
LIST_TIMEOUT_S = 10.0
CALL_TIMEOUT_S = 60.0
MAX_PAGES = 20


class UpstreamSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _one_transport(self) -> UpstreamSpec:
        if (self.url is None) == (self.command is None):
            raise ValueError("set exactly one of `url` (Streamable HTTP) or `command` (stdio)")
        return self


class UpstreamsFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    upstreams: dict[str, UpstreamSpec] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _names(self) -> UpstreamsFile:
        for name in self.upstreams:
            if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", name) or "__" in name:
                raise ValueError(f"invalid upstream name {name!r}: [a-z0-9_-], no '__'")
        return self


def _expand(value: str) -> str:
    return _ENV_REF.sub(lambda m: os.environ.get(m.group(1), ""), value)


def load_upstreams(path: str | Path) -> dict[str, UpstreamSpec]:
    p = Path(path)
    if not p.is_file():
        log.warning("mcp.upstreams_missing", path=str(p))
        return {}
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return UpstreamsFile.model_validate(data).upstreams


class Upstream:
    def __init__(self, name: str, spec: UpstreamSpec) -> None:
        self.name = name
        self.spec = spec
        self._stack: AsyncExitStack | None = None
        self._client: Client | None = None
        self._lock = asyncio.Lock()

    async def _connect(self) -> Client:
        stack = AsyncExitStack()
        try:
            if self.spec.url is not None:
                http = await stack.enter_async_context(
                    httpx2.AsyncClient(
                        headers={k: _expand(v) for k, v in self.spec.headers.items()},
                        timeout=httpx2.Timeout(30.0, read=300.0),
                    )
                )
                transport = streamable_http_client(self.spec.url, http_client=http)
                client = await stack.enter_async_context(Client(transport))
            else:
                assert self.spec.command is not None
                params = StdioServerParameters(
                    command=self.spec.command,
                    args=self.spec.args,
                    env={k: _expand(v) for k, v in self.spec.env.items()} or None,
                )
                client = await stack.enter_async_context(Client(params))
        except BaseException:
            await stack.aclose()
            raise
        self._stack, self._client = stack, client
        log.info("mcp.upstream_connected", upstream=self.name)
        return client

    async def client(self) -> Client:
        async with self._lock:
            if self._client is None:
                return await self._connect()
            return self._client

    async def reset(self) -> None:
        async with self._lock:
            stack, self._stack, self._client = self._stack, None, None
        if stack is not None:
            try:
                await stack.aclose()
            except Exception as exc:  # a broken connection may fail to close cleanly
                log.debug("mcp.upstream_close_failed", upstream=self.name, error=repr(exc))

    async def list_tools(self) -> list[Tool]:
        """Full, uncached listing (a cached one would hide a rug pull)."""
        for attempt in (1, 2):
            try:
                client = await self.client()
                tools: list[Tool] = []
                cursor: str | None = None
                for _ in range(MAX_PAGES):
                    page = await client.list_tools(cursor=cursor, cache_mode="refresh")
                    tools.extend(page.tools)
                    cursor = page.next_cursor
                    if cursor is None:
                        break
                return tools
            except Exception as exc:
                await self.reset()
                if attempt == 2:
                    raise
                log.info("mcp.upstream_retry", upstream=self.name, error=repr(exc))
        raise AssertionError("unreachable")

    async def call_tool(self, tool: str, args: dict[str, Any]) -> CallToolResult:
        # Calls are not retried: a tool call may have side effects.
        client = await self.client()
        try:
            return await client.call_tool(tool, args, read_timeout_seconds=CALL_TIMEOUT_S)
        except Exception:
            await self.reset()
            raise


class UpstreamPool:
    def __init__(self, specs: dict[str, UpstreamSpec]) -> None:
        self.upstreams = {name: Upstream(name, spec) for name, spec in specs.items()}

    async def list_all(self) -> dict[str, list[Tool]]:
        """Tools per reachable upstream; an unreachable upstream lists nothing."""

        async def one(u: Upstream) -> tuple[str, list[Tool]]:
            try:
                return u.name, await asyncio.wait_for(u.list_tools(), LIST_TIMEOUT_S)
            except Exception as exc:
                log.warning("mcp.upstream_unavailable", upstream=u.name, error=repr(exc))
                return u.name, []

        return dict(await asyncio.gather(*(one(u) for u in self.upstreams.values())))

    async def call(self, server: str, tool: str, args: dict[str, Any]) -> CallToolResult:
        return await self.upstreams[server].call_tool(tool, args)

    async def aclose(self) -> None:
        await asyncio.gather(*(u.reset() for u in self.upstreams.values()))
