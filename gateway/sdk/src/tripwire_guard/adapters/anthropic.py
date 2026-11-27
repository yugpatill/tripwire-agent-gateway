"""Anthropic tool use (`pip install "tripwire-guard[anthropic]"`).

Tool Runner (recommended):

    guard = Guard(agent_name="assistant", user_prompt=user_message)
    runner = client.beta.messages.tool_runner(
        model="claude-opus-5-5", max_tokens=16000,
        tools=guard_tools(guard, [web__fetch, email__send_email]),
        messages=[{"role": "user", "content": user_message}],
    )
    final = runner.until_done()

A blocked, denied or timed-out call raises the SDK's `ToolError`, so the runner
sends Claude a `tool_result` with `is_error: true` and the reason.

Manual loop: `run_tool_calls(guard, response, {"web__fetch": web__fetch, ...})`
returns the `tool_result` blocks for one assistant message (all of them, for the
next user turn).
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from anthropic import beta_async_tool, beta_tool
from anthropic.lib.tools import ToolError

from tripwire_guard.wrap import Guard, GuardOutcome

__all__ = ["arun_tool_calls", "guard_beta_tool", "guard_tools", "run_tool_calls"]


def _raise_if_blocked(outcome: GuardOutcome) -> str:
    if outcome.is_error:
        raise ToolError(outcome.content)
    return outcome.content


def guard_beta_tool(guard: Guard, fn: Callable[..., Any], **beta_tool_kwargs: Any) -> Any:
    """`@beta_tool` (or `@beta_async_tool`) for `fn`, with every call guarded.

    The schema still comes from `fn`'s signature and docstring.
    """
    name = beta_tool_kwargs.get("name") or fn.__name__
    if inspect.iscoroutinefunction(fn):

        async def acall(**kwargs: Any) -> str:
            return _raise_if_blocked(await guard.acall(name, kwargs, fn))

        _copy_meta(acall, fn)
        return beta_async_tool(acall, **beta_tool_kwargs)

    def call(**kwargs: Any) -> str:
        return _raise_if_blocked(guard.call(name, kwargs, fn))

    _copy_meta(call, fn)
    return beta_tool(call, **beta_tool_kwargs)


def _copy_meta(wrapper: Callable[..., Any], fn: Callable[..., Any]) -> None:
    # Keep fn's name, docstring and signature (the tool schema), but not
    # `__wrapped__`, which would let callers bypass the guard.
    wrapper.__name__ = fn.__name__
    wrapper.__qualname__ = fn.__qualname__
    wrapper.__doc__ = fn.__doc__
    wrapper.__module__ = fn.__module__
    wrapper.__annotations__ = dict(getattr(fn, "__annotations__", {}))
    wrapper.__signature__ = inspect.signature(fn)  # type: ignore[attr-defined]


def guard_tools(guard: Guard, fns: Iterable[Callable[..., Any]]) -> list[Any]:
    """`guard_beta_tool` for each function."""
    return [guard_beta_tool(guard, fn) for fn in fns]


def _blocks(message: Any) -> list[Any]:
    content = message.content if hasattr(message, "content") else message
    return [b for b in content if getattr(b, "type", None) == "tool_use"]


def _result(block: Any, outcome: GuardOutcome) -> dict[str, Any]:
    out: dict[str, Any] = {
        "type": "tool_result",
        "tool_use_id": block.id,
        "content": outcome.content,
    }
    if outcome.is_error:
        out["is_error"] = True
    return out


def _unknown(block: Any) -> dict[str, Any]:
    return {
        "type": "tool_result",
        "tool_use_id": block.id,
        "content": f"Unknown tool {block.name}.",
        "is_error": True,
    }


def run_tool_calls(
    guard: Guard, message: Any, tools: Mapping[str, Callable[..., Any]]
) -> list[dict[str, Any]]:
    """Guarded `tool_result` blocks for every `tool_use` block in `message`."""
    results = []
    for block in _blocks(message):
        fn = tools.get(block.name)
        if fn is None:
            results.append(_unknown(block))
            continue
        results.append(_result(block, guard.call(block.name, dict(block.input), fn)))
    return results


async def arun_tool_calls(
    guard: Guard, message: Any, tools: Mapping[str, Callable[..., Any]]
) -> list[dict[str, Any]]:
    """Async `run_tool_calls`; tools may be sync or async."""
    results = []
    for block in _blocks(message):
        fn = tools.get(block.name)
        if fn is None:
            results.append(_unknown(block))
            continue
        results.append(_result(block, await guard.acall(block.name, dict(block.input), fn)))
    return results
