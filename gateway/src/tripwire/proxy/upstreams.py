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
    def __init__(self, name: str, spec: UpstreamSpec | None, server: Any = None) -> None:
        """`server`: an in-process MCP server object (SDK in-memory transport), used by
        the playground; otherwise `spec` says how to reach the upstream."""
        if (spec is None) == (server is None):
            raise ValueError("give exactly one of spec or server")
        self.name = name
        self.spec = spec
        self.server = server
        self._client: Client | None = None
        self._owner: asyncio.Task[None] | None = None
        self._stop: asyncio.Event | None = None
        self._lock = asyncio.Lock()

    async def _open(self, stack: AsyncExitStack) -> Client:
        if self.server is not None:
            client: Client = await stack.enter_async_context(Client(self.server))
            return client
        if self.spec is not None and self.spec.url is not None:
            http = await stack.enter_async_context(
                httpx2.AsyncClient(
                    headers={k: _expand(v) for k, v in self.spec.headers.items()},
                    timeout=httpx2.Timeout(30.0, read=300.0),
                )
            )
            transport = streamable_http_client(self.spec.url, http_client=http)
            client = await stack.enter_async_context(Client(transport))
            return client
        assert self.spec is not None and self.spec.command is not None
        params = StdioServerParameters(
            command=self.spec.command,
            args=self.spec.args,
            env={k: _expand(v) for k, v in self.spec.env.items()} or None,
        )
        client = await stack.enter_async_context(Client(params))
        return client

    async def _connect(self) -> Client:
        """Open the connection in a task of its own that also closes it.

        The SDK client holds anyio task groups and cancel scopes, which must be
        entered and exited by the same task. Opening it inside whichever request
        first needed it broke that request's own task group when it finished
        ("exit a cancel scope that isn't the current task's")."""
        ready: asyncio.Future[Client] = asyncio.get_running_loop().create_future()
        stop = asyncio.Event()

        async def own() -> None:
            try:
                async with AsyncExitStack() as stack:
                    ready.set_result(await self._open(stack))
                    await stop.wait()
            except BaseException as exc:
                if not ready.done():
                    ready.set_exception(exc)
                else:  # the connection died or failed to close cleanly
                    log.debug("mcp.upstream_closed", upstream=self.name, error=repr(exc))
                if not isinstance(exc, Exception):
                    raise

        owner = asyncio.create_task(own(), name=f"mcp-upstream-{self.name}")
        try:
            client = await asyncio.shield(ready)
        except BaseException:
            stop.set()
            owner.cancel()
            raise
        self._client, self._owner, self._stop = client, owner, stop
        log.info("mcp.upstream_connected", upstream=self.name)
        return client

    async def client(self) -> Client:
        async with self._lock:
            if self._client is None or (self._owner is not None and self._owner.done()):
                return await self._connect()
            return self._client

    async def reset(self) -> None:
        async with self._lock:
            owner, stop = self._owner, self._stop
            self._client = self._owner = self._stop = None
        if owner is not None and stop is not None:
            stop.set()
            try:
                await asyncio.wait_for(asyncio.shield(owner), 5.0)
            except BaseException as exc:  # a broken connection may fail to close cleanly
                if not isinstance(exc, Exception):
                    raise
                owner.cancel()
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

    @classmethod
    def in_memory(cls, servers: dict[str, Any]) -> UpstreamPool:
        """Upstreams that are MCP server objects in this process (playground runs)."""
        pool = cls({})
        pool.upstreams = {name: Upstream(name, None, server) for name, server in servers.items()}
        return pool

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
