"""OpenAI Agents SDK (`pip install "tripwire-guard[openai-agents]"`).

    guard = Guard(agent_name="support", user_prompt=user_message)
    safe_agent = guard_agent(guard, agent)
    result = await Runner.run(safe_agent, user_message)

Every `FunctionTool` (including `@function_tool` functions) is replaced by a copy
whose `on_invoke_tool` goes through the guard; the model sees the reason when a
call is blocked. Agents reachable through `handoffs` are guarded too, sharing the
same Tripwire session.

Hosted tools (web search, file search, code interpreter, computer use, hosted
MCP) run on OpenAI's side, where Tripwire cannot intercept them; `guard_agent`
refuses an agent that has them unless `allow_unguarded=True`.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

from agents import Agent, FunctionTool

from tripwire_guard.client import TripwireError
from tripwire_guard.wrap import Guard

__all__ = ["guard_agent", "guard_function_tool"]


def guard_function_tool(guard: Guard, tool: FunctionTool) -> FunctionTool:
    """A copy of `tool` whose invocations are checked by Tripwire."""
    original = tool.on_invoke_tool

    async def on_invoke_tool(ctx: Any, input_json: str) -> Any:
        try:
            args = json.loads(input_json) if input_json else {}
        except json.JSONDecodeError:
            return f"Invalid JSON arguments for {tool.name}."
        if not isinstance(args, dict):
            return f"Arguments for {tool.name} must be a JSON object."

        async def run(**kwargs: Any) -> Any:
            return await original(ctx, json.dumps(kwargs))

        outcome = await guard.acall(tool.name, args, run)
        return outcome.content

    return dataclasses.replace(tool, on_invoke_tool=on_invoke_tool)


def guard_agent(
    guard: Guard,
    agent: Agent[Any],
    *,
    allow_unguarded: bool = False,
    _seen: dict[int, Agent[Any]] | None = None,
) -> Agent[Any]:
    """A clone of `agent` (and of agents it hands off to) with guarded function tools."""
    seen = {} if _seen is None else _seen
    if id(agent) in seen:
        return seen[id(agent)]
    tools: list[Any] = []
    for t in agent.tools:
        if isinstance(t, FunctionTool):
            tools.append(guard_function_tool(guard, t))
        elif allow_unguarded:
            tools.append(t)
        else:
            raise TripwireError(
                f"Agent {agent.name!r} has a hosted tool ({type(t).__name__}) that Tripwire "
                "cannot intercept. Remove it or pass allow_unguarded=True."
            )
    clone = agent.clone(tools=tools)
    seen[id(agent)] = clone
    handoffs: list[Any] = []
    for h in agent.handoffs:
        if isinstance(h, Agent):
            handoffs.append(guard_agent(guard, h, allow_unguarded=allow_unguarded, _seen=seen))
        elif allow_unguarded:
            handoffs.append(h)
        else:
            # A custom Handoff resolves its agent when invoked, so its tools cannot be
            # guarded here. Fail closed.
            raise TripwireError(
                f"Agent {agent.name!r} has a custom {type(h).__name__} handoff whose target "
                "cannot be guarded. Hand off to Agent objects, or pass allow_unguarded=True."
            )
    clone.handoffs = handoffs
    return clone
