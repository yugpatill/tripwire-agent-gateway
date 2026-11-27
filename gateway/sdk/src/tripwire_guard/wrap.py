"""The guard: run one tool call through Tripwire.

    guard = Guard(agent_name="support-bot", user_prompt=user_message)
    outcome = guard.call("email__send_email", {"to": ..., "body": ...}, send_email)

Each call: `check/call` -> (`block`: not executed) -> (`require_approval`: wait
for an operator) -> run the tool (with redacted arguments if the policy says
`redact`) -> `check/result` -> the redacted result for the model. One guard is
one Tripwire session (one agent run for one user); use a new guard per run.

Fail closed: if Tripwire cannot be reached, the tool is not run; if a result
cannot be vetted, it is withheld.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import threading
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, TypeVar
from uuid import UUID

from tripwire_guard.client import (
    AsyncTripwireClient,
    Decision,
    TripwireClient,
    TripwireError,
    TripwireUnavailable,
)

F = TypeVar("F", bound=Callable[..., Any])
Final = Literal["allowed", "blocked", "denied", "expired", "error", "unavailable"]


@dataclass(slots=True)
class GuardOutcome:
    """What happened to one tool call, and what the model should see."""

    tool: str
    status: Final
    content: str  # text to hand back to the model (redacted)
    is_error: bool
    ran: bool  # the tool function was executed
    decision: Decision | None = None
    suspicious_result: bool = False

    @property
    def blocked(self) -> bool:
        return self.status in ("blocked", "denied", "expired", "unavailable")


class ToolBlocked(TripwireError):
    """Raised by `Guard.tool()` wrappers when a call is not allowed (on_block="raise")."""

    def __init__(self, outcome: GuardOutcome) -> None:
        super().__init__(outcome.content)
        self.outcome = outcome


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def _jsonable(value: Any) -> Any:
    if isinstance(value, (str, dict, list)):
        try:
            json.dumps(value)
            return value
        except (TypeError, ValueError):
            pass
    return _as_text(value)


def _blocked_text(d: Decision) -> str:
    return f"Blocked by Tripwire ({d.rule_id or 'policy'}): {d.message}"


class Guard:
    """Guards tool calls for one agent run (one Tripwire session).

    tool_names: map (or function) from the framework's tool name to the name the
        Tripwire policy uses, e.g. {"send_email": "email__send_email"}.
    approval_timeout: how long to wait for an operator on `require_approval`
        (the gateway expires approvals after its own timeout, 120 s by default).
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        agent_name: str = "tripwire-guard",
        user_prompt: str = "",
        session_id: UUID | str | None = None,
        tool_names: Mapping[str, str] | Callable[[str], str] | None = None,
        approval_timeout: float = 130.0,
        poll_interval: float = 1.0,
        client: TripwireClient | None = None,
        async_client: AsyncTripwireClient | None = None,
    ) -> None:
        self._base_url = base_url
        self._api_key = api_key
        self.agent_name = agent_name
        self._initial_prompt = user_prompt
        self._session_id: UUID | None = UUID(str(session_id)) if session_id else None
        self._tool_names = tool_names
        self.approval_timeout = approval_timeout
        self.poll_interval = poll_interval
        self._client = client
        self._aclient = async_client
        self._lock = threading.Lock()
        self._alock: asyncio.Lock | None = None
        self.outcomes: list[GuardOutcome] = []

    # ---------- plumbing

    @property
    def client(self) -> TripwireClient:
        if self._client is None:
            self._client = TripwireClient(self._base_url, self._api_key)
        return self._client

    @property
    def async_client(self) -> AsyncTripwireClient:
        if self._aclient is None:
            self._aclient = AsyncTripwireClient(self._base_url, self._api_key)
        return self._aclient

    def tripwire_name(self, tool: str) -> str:
        names = self._tool_names
        if names is None:
            return tool
        if callable(names):
            return names(tool)
        return names.get(tool, tool)

    @property
    def session_id(self) -> UUID:
        """The Tripwire session, created on first use."""
        with self._lock:
            if self._session_id is None:
                self._session_id = self.client.create_session(self.agent_name, self._initial_prompt)
            return self._session_id

    async def asession_id(self) -> UUID:
        if self._alock is None:
            self._alock = asyncio.Lock()
        async with self._alock:
            if self._session_id is None:
                self._session_id = await self.async_client.create_session(
                    self.agent_name, self._initial_prompt
                )
            return self._session_id

    def user_turn(self, text: str) -> None:
        """Record a new message from the user (their words, never model output)."""
        self.client.add_prompt(self.session_id, text)

    async def auser_turn(self, text: str) -> None:
        await self.async_client.add_prompt(await self.asession_id(), text)

    def _record(self, outcome: GuardOutcome) -> GuardOutcome:
        self.outcomes.append(outcome)
        return outcome

    # ---------- sync

    def call(self, tool: str, args: dict[str, Any], fn: Callable[..., Any]) -> GuardOutcome:
        """Run `fn(**args)` under Tripwire. Never raises for policy outcomes."""
        name = self.tripwire_name(tool)
        try:
            sid = self.session_id
            decision = self.client.check_call(sid, name, args)
        except TripwireUnavailable as exc:
            return self._record(_unavailable(name, exc))
        early = _pre(name, decision)
        if early is not None:
            return self._record(early)
        if decision.action == "require_approval":
            status = self._wait_sync(decision.approval_id)
            if status != "approved":
                return self._record(_not_approved(name, decision, status))
        run_args = decision.redacted_args if decision.action == "redact" else args
        try:
            raw, failed = fn(**(run_args or {})), False
        except Exception as exc:
            raw, failed = f"Tool error: {type(exc).__name__}: {exc}", True
        try:
            checked = self.client.check_result(sid, name, decision.event_id, _jsonable(raw))
        except TripwireUnavailable as exc:
            return self._record(_unvetted(name, decision, exc))
        return self._record(_post(name, decision, checked, failed))

    def _wait_sync(self, approval_id: UUID | None) -> str:
        if approval_id is None:
            return "denied"
        deadline = time.monotonic() + self.approval_timeout
        while time.monotonic() < deadline:
            try:
                status = self.client.get_approval(approval_id).status
            except TripwireUnavailable:
                status = "pending"
            if status != "pending":
                return status
            time.sleep(self.poll_interval)
        return "expired"

    # ---------- async

    async def acall(
        self, tool: str, args: dict[str, Any], fn: Callable[..., Any | Awaitable[Any]]
    ) -> GuardOutcome:
        """Async `call`; `fn` may be sync or async."""
        name = self.tripwire_name(tool)
        try:
            sid = await self.asession_id()
            decision = await self.async_client.check_call(sid, name, args)
        except TripwireUnavailable as exc:
            return self._record(_unavailable(name, exc))
        early = _pre(name, decision)
        if early is not None:
            return self._record(early)
        if decision.action == "require_approval":
            status = await self._wait_async(decision.approval_id)
            if status != "approved":
                return self._record(_not_approved(name, decision, status))
        run_args = decision.redacted_args if decision.action == "redact" else args
        try:
            raw = fn(**(run_args or {}))
            if inspect.isawaitable(raw):
                raw = await raw
            failed = False
        except Exception as exc:
            raw, failed = f"Tool error: {type(exc).__name__}: {exc}", True
        try:
            checked = await self.async_client.check_result(
                sid, name, decision.event_id, _jsonable(raw)
            )
        except TripwireUnavailable as exc:
            return self._record(_unvetted(name, decision, exc))
        return self._record(_post(name, decision, checked, failed))

    async def _wait_async(self, approval_id: UUID | None) -> str:
        if approval_id is None:
            return "denied"
        deadline = time.monotonic() + self.approval_timeout
        while time.monotonic() < deadline:
            try:
                status = (await self.async_client.get_approval(approval_id)).status
            except TripwireUnavailable:
                status = "pending"
            if status != "pending":
                return status
            await asyncio.sleep(self.poll_interval)
        return "expired"

    # ---------- decorators

    def tool(
        self,
        fn: F,
        name: str | None = None,
        on_block: Literal["raise", "return"] = "return",
    ) -> F:
        """Wrap a tool function (sync or async), keeping its signature and docstring.

        on_block="return": the wrapper returns the explanation text instead of the
        tool's result. on_block="raise": it raises `ToolBlocked`.
        """
        tool_name = name or fn.__name__

        def bind(*args: Any, **kwargs: Any) -> dict[str, Any]:
            bound = inspect.signature(fn).bind(*args, **kwargs)
            bound.apply_defaults()
            return dict(bound.arguments)

        def finish(outcome: GuardOutcome) -> Any:
            if outcome.blocked and on_block == "raise":
                raise ToolBlocked(outcome)
            return outcome.content

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def awrapper(*args: Any, **kwargs: Any) -> Any:
                return finish(await self.acall(tool_name, bind(*args, **kwargs), fn))

            return awrapper  # type: ignore[return-value]

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return finish(self.call(tool_name, bind(*args, **kwargs), fn))

        return wrapper  # type: ignore[return-value]

    def close(self) -> None:
        if self._client is not None:
            self._client.close()

    async def aclose(self) -> None:
        if self._aclient is not None:
            await self._aclient.aclose()


# ---------------------------------------------------------------- outcome helpers


def _unavailable(name: str, exc: Exception) -> GuardOutcome:
    return GuardOutcome(
        name,
        "unavailable",
        f"Tripwire is unavailable, so this call was not executed ({exc}).",
        True,
        False,
    )


def _pre(name: str, d: Decision) -> GuardOutcome | None:
    if d.action == "block":
        return GuardOutcome(name, "blocked", _blocked_text(d), True, False, d)
    return None


def _not_approved(name: str, d: Decision, status: str) -> GuardOutcome:
    if status == "expired":
        text = (
            f"No operator approved this call in time, so it was denied "
            f"(approval {d.approval_id}). Rule {d.rule_id}: {d.message}"
        )
        return GuardOutcome(name, "expired", text, True, False, d)
    text = f"An operator denied this call (approval {d.approval_id}). Rule {d.rule_id}: {d.message}"
    return GuardOutcome(name, "denied", text, True, False, d)


def _unvetted(name: str, d: Decision, exc: Exception) -> GuardOutcome:
    return GuardOutcome(
        name,
        "unavailable",
        f"The tool ran, but Tripwire could not vet its result, so it was withheld ({exc}).",
        True,
        True,
        d,
    )


def _post(name: str, d: Decision, checked: Any, failed: bool) -> GuardOutcome:
    if checked.decision.action == "block":
        return GuardOutcome(
            name, "unavailable", "Tripwire could not vet this result; withheld.", True, True, d
        )
    return GuardOutcome(
        name,
        "error" if failed else "allowed",
        _as_text(checked.content_redacted),
        failed,
        True,
        d,
        checked.suspicious,
    )
