"""LangGraph (`pip install "tripwire-guard[langgraph]"`).

    from langgraph.prebuilt import ToolNode
    guard = Guard(agent_name="researcher", user_prompt=user_message)
    tools = guard_tool_node(guard, ToolNode([fetch_page, send_email]))
    # or: ToolNode([...], wrap_tool_call=w, awrap_tool_call=aw) with
    #     w, aw = tripwire_tool_call_wrappers(guard)

Built on ToolNode's tool-call interceptors (`wrap_tool_call` / `awrap_tool_call`),
so injected state, store and runtime arguments keep working. A blocked call
becomes a `ToolMessage` with `status="error"` and the reason; the tool is not
run. Results are replaced by Tripwire's redacted copy.

Not vetted: tools that return a LangGraph `Command` (state updates) pass through
unchanged after the call itself was allowed.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from langchain_core.messages import ToolMessage
from langchain_core.tools import BaseTool
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.tool_node import ToolCallRequest

from tripwire_guard.wrap import Guard, GuardOutcome

__all__ = ["guard_langchain_tools", "guard_tool_node", "tripwire_tool_call_wrappers"]

Execute = Callable[[ToolCallRequest], Any]
AExecute = Callable[[ToolCallRequest], Awaitable[Any]]


def _content(res: Any) -> Any:
    if isinstance(res, ToolMessage):
        return res.content
    return f"[{type(res).__name__} returned by the tool]"


def _message(call: dict[str, Any], outcome: GuardOutcome, res: Any) -> Any:
    if outcome.ran and res is not None and not isinstance(res, ToolMessage):
        return res  # a Command: passed through (see module docs)
    return ToolMessage(
        content=outcome.content,
        tool_call_id=call["id"],
        name=call["name"],
        status="error" if outcome.is_error else "success",
    )


def tripwire_tool_call_wrappers(
    guard: Guard,
    inner: Callable[[ToolCallRequest, Execute], Any] | None = None,
    ainner: Callable[[ToolCallRequest, AExecute], Awaitable[Any]] | None = None,
) -> tuple[
    Callable[[ToolCallRequest, Execute], Any],
    Callable[[ToolCallRequest, AExecute], Awaitable[Any]],
]:
    """(wrap_tool_call, awrap_tool_call) for a ToolNode. `inner`/`ainner`: existing
    wrappers to run inside the guard (the guard decides first)."""

    def wrap(request: ToolCallRequest, execute: Execute) -> Any:
        call: dict[str, Any] = dict(request.tool_call)
        holder: dict[str, Any] = {}

        def run(**kwargs: Any) -> Any:
            req = request.override(tool_call={**call, "args": kwargs})  # type: ignore[typeddict-item]
            res = inner(req, execute) if inner else execute(req)
            holder["res"] = res
            return _content(res)

        outcome = guard.call(call["name"], dict(call.get("args") or {}), run)
        return _message(call, outcome, holder.get("res"))

    async def awrap(request: ToolCallRequest, execute: AExecute) -> Any:
        call: dict[str, Any] = dict(request.tool_call)
        holder: dict[str, Any] = {}

        async def run(**kwargs: Any) -> Any:
            req = request.override(tool_call={**call, "args": kwargs})  # type: ignore[typeddict-item]
            res = await (ainner(req, execute) if ainner else execute(req))
            holder["res"] = res
            return _content(res)

        outcome = await guard.acall(call["name"], dict(call.get("args") or {}), run)
        return _message(call, outcome, holder.get("res"))

    return wrap, awrap


def guard_tool_node(guard: Guard, node: ToolNode) -> ToolNode:
    """A copy of `node` (same tools and name) with every tool call guarded."""
    wrap, awrap = tripwire_tool_call_wrappers(
        guard, getattr(node, "_wrap_tool_call", None), getattr(node, "_awrap_tool_call", None)
    )
    return ToolNode(
        list(node.tools_by_name.values()),
        name=node.name or "tools",
        wrap_tool_call=wrap,
        awrap_tool_call=awrap,
    )


def guard_langchain_tools(guard: Guard, tools: Sequence[BaseTool | Callable[..., Any]]) -> ToolNode:
    """A guarded ToolNode for a list of LangChain tools (or plain functions)."""
    wrap, awrap = tripwire_tool_call_wrappers(guard)
    return ToolNode(list(tools), wrap_tool_call=wrap, awrap_tool_call=awrap)
