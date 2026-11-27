"""MCP gateway: Tripwire as an MCP server in front of upstream MCP servers.

Agent side: a low-level MCP `Server` (SDK v2) served over Streamable HTTP at
`/v1/mcp` (API key required) and, through `tripwire mcp stdio`, over stdio.
Upstream side: one SDK `Client` per configured server (`upstreams.py`).

- tools/list: every upstream's tools, namespaced `server__tool`, filtered by the
  manifest guard (poisoned, shadowing and changed tools are hidden).
- tools/call: guard check -> `engine.check_call` -> (approval wait) -> upstream
  call -> `engine.check_result` -> redacted content back to the agent.
  `block` and denied approvals become tool errors (`isError: true`) whose text
  the model sees; anything unexpected also fails closed as a tool error.

Session mapping (Tripwire session = taint context):
1. `X-Tripwire-Session: <uuid>`: an existing session owned by the API key
   (the stdio bridge creates one per process). Use this for per-run isolation.
2. otherwise one rolling session per API key, shared by all its connections and
   all gateway workers (Redis), renewed on use and replaced after 1 h idle. The
   MCP connection is deliberately *not* the boundary: a client that reconnects
   between reading untrusted content and acting on it must not get a clean
   taint context. Sharing taint across runs only ever makes decisions stricter.
`X-Tripwire-User-Prompt` (percent-encoded) seeds the session's user prompt, so
recipients the user named are trusted (instruction origin).
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import unquote

import structlog
from mcp import MCPError
from mcp.server import Server, ServerRequestContext
from mcp.server.streamable_http_manager import StreamableHTTPASGIApp, StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import (
    INVALID_PARAMS,
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
)
from starlette.requests import Request
from starlette.types import ASGIApp, Receive, Scope, Send

from tripwire import __version__
from tripwire.approvals.service import ApprovalService
from tripwire.auth.api_keys import ApiKeyAuthenticator, Principal
from tripwire.models import SessionCreate, ToolCall, ToolResult
from tripwire.pipeline.engine import Engine
from tripwire.pipeline.manifest import NAMESPACE_SEP, Manifest
from tripwire.proxy.guard import ManifestGuard
from tripwire.proxy.upstreams import UpstreamPool

log = structlog.get_logger(__name__)

PRINCIPAL_KEY = "tripwire_principal"
SESSION_HEADER = "x-tripwire-session"
PROMPT_HEADER = "x-tripwire-user-prompt"
PROGRESS_EVERY_S = 5.0
INSTRUCTIONS = (
    "Tools are provided through Tripwire, a security gateway. Tool names are "
    "'<server>__<tool>'. Some calls may be blocked or held for human approval; "
    "the tool result then explains why."
)


def _error(text: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], is_error=True)


def _text_of(result: CallToolResult) -> str:
    parts: list[str] = []
    for block in result.content:
        if isinstance(block, TextContent):
            parts.append(block.text)
        else:  # images, audio, embedded resources cannot be vetted: withhold them
            parts.append(f"[{getattr(block, 'type', 'non-text')} content withheld by Tripwire]")
    if result.structured_content is not None and not parts:
        parts.append(json.dumps(result.structured_content, ensure_ascii=False))
    return "\n".join(parts)


SESSION_IDLE_TTL_S = 3600


class SessionMap(Protocol):
    async def get(self, key: str) -> str | None:
        """Current value (renewing its idle TTL), or None."""
        ...

    async def set_if_absent(self, key: str, value: str) -> bool: ...


class MemorySessionMap:
    def __init__(self, ttl_s: float = SESSION_IDLE_TTL_S) -> None:
        self._ttl = ttl_s
        self._d: dict[str, tuple[str, float]] = {}

    async def get(self, key: str) -> str | None:
        hit = self._d.get(key)
        if hit is None or hit[1] < time.monotonic():
            return None
        self._d[key] = (hit[0], time.monotonic() + self._ttl)
        return hit[0]

    async def set_if_absent(self, key: str, value: str) -> bool:
        if await self.get(key) is not None:
            return False
        self._d[key] = (value, time.monotonic() + self._ttl)
        return True


class RedisSessionMap:
    def __init__(self, redis: Any, ttl_s: int = SESSION_IDLE_TTL_S) -> None:
        self._r = redis
        self._ttl = ttl_s

    @staticmethod
    def _k(key: str) -> str:
        return f"tripwire:mcp:session:{key}"

    async def get(self, key: str) -> str | None:
        value = await self._r.getex(self._k(key), ex=self._ttl)
        return str(value) if value is not None else None

    async def set_if_absent(self, key: str, value: str) -> bool:
        return bool(await self._r.set(self._k(key), value, nx=True, ex=self._ttl))


@dataclass(frozen=True, slots=True)
class CallerIdentity:
    principal: Principal
    session_id: uuid.UUID


class McpProxy:
    def __init__(
        self,
        engine: Engine,
        guard: ManifestGuard,
        pool: UpstreamPool,
        approvals: ApprovalService | None,
        approval_timeout_s: float = 120.0,
        sessions: SessionMap | None = None,
    ) -> None:
        self.engine = engine
        self.guard = guard
        self.pool = pool
        self.approvals = approvals
        self.approval_timeout_s = approval_timeout_s
        self.sessions: SessionMap = sessions or MemorySessionMap()
        self._tool_cache: dict[str, Tool] = {}
        self.server: Server[Any] = Server(
            "tripwire",
            version=__version__,
            instructions=INSTRUCTIONS,
            on_list_tools=self._list_tools,
            on_call_tool=self._call_tool,
        )

    # ---------- identity

    async def _identity(self, ctx: ServerRequestContext[Any, Any]) -> CallerIdentity:
        request = ctx.request
        if not isinstance(request, Request):
            raise MCPError(INVALID_PARAMS, "Tripwire MCP requires the HTTP transport")
        principal = request.scope.get("state", {}).get(PRINCIPAL_KEY)
        if not isinstance(principal, Principal):  # the auth wrapper always sets it
            raise MCPError(INVALID_PARAMS, "unauthenticated")
        explicit = request.headers.get(SESSION_HEADER)
        if explicit:
            try:
                return CallerIdentity(principal, uuid.UUID(explicit))
            except ValueError as exc:
                raise MCPError(INVALID_PARAMS, f"invalid {SESSION_HEADER} header") from exc
        key = str(principal.key_id)
        current = await self.sessions.get(key)
        if current is not None:
            return CallerIdentity(principal, uuid.UUID(current))
        prompt = unquote(request.headers.get(PROMPT_HEADER, ""))
        sid = await self.engine.create_session(
            SessionCreate(agent_name=f"mcp:{principal.name}", user_prompt=prompt),
            owner=principal.key_id,
        )
        if not await self.sessions.set_if_absent(key, str(sid)):
            # Another request or worker won the race: join its session.
            winner = await self.sessions.get(key)
            if winner is not None:
                return CallerIdentity(principal, uuid.UUID(winner))
        log.info("mcp.session", session_id=str(sid), key=principal.name)
        return CallerIdentity(principal, sid)

    # ---------- tools/list

    async def list_visible(self) -> list[Tool]:
        listing = await self.pool.list_all()
        originals: dict[str, Tool] = {}
        manifests: list[Manifest] = []
        for server, tools in listing.items():
            for t in tools:
                m = Manifest(server, t.name, t.description or "", dict(t.input_schema))
                originals[m.name] = t
                manifests.append(m)
        visible = await self.guard.process(manifests)
        out = [
            Tool(
                name=m.name,
                title=originals[m.name].title,
                description=m.description,
                input_schema=m.input_schema,
                annotations=originals[m.name].annotations,
            )
            for m in visible
        ]
        self._tool_cache = {t.name: t for t in out}
        return out

    async def _list_tools(
        self, ctx: ServerRequestContext[Any, Any], params: PaginatedRequestParams | None
    ) -> ListToolsResult:
        await self._identity(ctx)
        return ListToolsResult(tools=await self.list_visible())

    # ---------- tools/call

    async def _call_tool(
        self, ctx: ServerRequestContext[Any, Any], params: CallToolRequestParams
    ) -> CallToolResult:
        ident = await self._identity(ctx)
        try:
            return await self.call(ident, params.name, dict(params.arguments or {}), ctx)
        except Exception as exc:  # fail closed, visibly
            log.exception("mcp.call_failed", tool=params.name)
            return _error(f"Tripwire could not complete this call safely ({type(exc).__name__}).")

    async def call(
        self,
        ident: CallerIdentity,
        name: str,
        args: dict[str, Any],
        ctx: ServerRequestContext[Any, Any] | None = None,
    ) -> CallToolResult:
        server, sep, tool = name.partition(NAMESPACE_SEP)
        if not sep or server not in self.pool.upstreams:
            return _error(f"Unknown tool {name}. Tools are named '<server>__<tool>'.")
        ok, reason = await self.guard.callable_status(name)
        if not ok:
            return _error(reason)

        owner = ident.principal.key_id
        decision = await self.engine.check_call(
            ToolCall(session_id=ident.session_id, tool=name, args=args), owner=owner
        )
        if decision.action == "block":
            return _error(
                f"Blocked by Tripwire ({decision.rule_id or 'policy'}): {decision.message}"
            )
        if decision.action == "require_approval":
            outcome = await self._await_approval(decision.approval_id, ctx)
            if outcome != "approved":
                return _error(outcome)
        elif decision.action == "redact" and decision.redacted_args is not None:
            args = decision.redacted_args

        try:
            upstream = await self.pool.call(server, tool, args)
        except Exception as exc:
            log.warning("mcp.upstream_call_failed", tool=name, error=repr(exc))
            return _error(f"Upstream server '{server}' failed: {type(exc).__name__}.")

        checked = await self.engine.check_result(
            ToolResult(
                session_id=ident.session_id,
                tool=name,
                call_event_id=decision.event_id,
                content=_text_of(upstream),
            ),
            owner=owner,
        )
        if checked.decision.action == "block":
            return _error("Tripwire could not vet this tool result, so it was withheld.")
        content = checked.content_redacted
        text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
        return CallToolResult(
            content=[TextContent(type="text", text=text)], is_error=upstream.is_error
        )

    async def _await_approval(
        self, approval_id: uuid.UUID | None, ctx: ServerRequestContext[Any, Any] | None
    ) -> str:
        """'approved', or the error text the agent sees."""
        if approval_id is None or self.approvals is None:
            return "This call needs human approval, but no approval service is configured; denied."
        log.info("mcp.call_held", approval_id=str(approval_id))
        waiter = asyncio.create_task(self.approvals.wait(approval_id, self.approval_timeout_s))
        started = time.monotonic()
        while True:
            done, _ = await asyncio.wait({waiter}, timeout=PROGRESS_EVERY_S)
            if done:
                break
            if ctx is not None:  # keeps clients that reset timeouts on progress waiting
                try:
                    await ctx.session.report_progress(
                        time.monotonic() - started,
                        self.approval_timeout_s,
                        f"Waiting for operator approval {approval_id}",
                    )
                except Exception as exc:
                    log.debug("mcp.progress_failed", error=repr(exc))
        status = waiter.result()
        if status == "approved":
            return "approved"
        if status == "expired":
            return (
                f"No operator approved this call within {self.approval_timeout_s:.0f} s, "
                f"so it was denied (approval {approval_id})."
            )
        return f"An operator denied this call (approval {approval_id})."


# ---------------------------------------------------------------- HTTP mounting


class McpAuth:
    """ASGI wrapper: API key required, principal stored in scope['state']."""

    def __init__(self, app: ASGIApp, authenticator: Any) -> None:
        self.app = app
        self.authenticator = authenticator

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        auth: ApiKeyAuthenticator = (
            self.authenticator() if callable(self.authenticator) else self.authenticator
        )
        header = dict(scope.get("headers") or []).get(b"authorization", b"").decode("latin-1")
        scheme, _, token = header.partition(" ")
        principal: Principal | None = None
        status, detail = 401, "Missing or invalid API key"
        if scheme.lower() == "bearer" and token:
            try:
                principal = await auth.authenticate(token.strip())
            except Exception:
                status, detail = 503, "Auth unavailable"
        if principal is None:
            body = json.dumps({"detail": detail}).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": status,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"www-authenticate", b"Bearer"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        scope.setdefault("state", {})[PRINCIPAL_KEY] = principal
        await self.app(scope, receive, send)


def build_http_app(
    proxy: McpProxy, authenticator: Any, allowed_hosts: list[str], allowed_origins: list[str]
) -> tuple[ASGIApp, StreamableHTTPSessionManager]:
    proxy.server.streamable_http_app(
        streamable_http_path="/v1/mcp",
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
            allowed_origins=allowed_origins,
        ),
    )
    manager = proxy.server.session_manager
    return McpAuth(StreamableHTTPASGIApp(manager), authenticator), manager
