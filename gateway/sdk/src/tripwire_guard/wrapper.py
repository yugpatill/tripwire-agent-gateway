"""`wrap(obj, policy_url=..., api_key=...)`: guard tools or an agent, picked by type.

- a list of plain functions (Anthropic Tool Runner): guarded `@beta_tool`s
- a LangGraph `ToolNode` or a list of LangChain tools: a guarded `ToolNode` / tools
- an OpenAI Agents SDK `Agent`: a clone whose function tools are guarded

Pass `guard=` to share one Tripwire session, or the `Guard` keyword arguments
(`agent_name`, `user_prompt`, `tool_names`, ...) to create one. `allow_unguarded`
lets an Agents SDK agent keep hosted tools Tripwire cannot see (off by default).
"""

from __future__ import annotations

from typing import Any

from tripwire_guard.wrap import Guard


def _is_langchain_tool(x: Any) -> bool:
    return any(c.__module__.startswith("langchain_core.tools") for c in type(x).__mro__)


def wrap(
    agent_or_tools: Any,
    policy_url: str | None = None,
    api_key: str | None = None,
    *,
    guard: Guard | None = None,
    allow_unguarded: bool = False,
    **guard_kwargs: Any,
) -> Any:
    g = guard or Guard(base_url=policy_url, api_key=api_key, **guard_kwargs)
    obj = agent_or_tools
    mod = type(obj).__module__
    if mod.startswith("agents.") and hasattr(obj, "clone"):
        from tripwire_guard.adapters.openai_agents import guard_agent

        return guard_agent(g, obj, allow_unguarded=allow_unguarded)
    if mod.startswith("langgraph.") and type(obj).__name__ == "ToolNode":
        from tripwire_guard.adapters.langgraph import guard_tool_node

        return guard_tool_node(g, obj)
    if isinstance(obj, (list, tuple)):
        items = list(obj)
        if items and all(_is_langchain_tool(t) for t in items):
            from tripwire_guard.adapters.langgraph import guard_langchain_tools

            return guard_langchain_tools(g, items)
        if all(callable(t) for t in items):
            from tripwire_guard.adapters.anthropic import guard_tools

            return guard_tools(g, items)
    raise TypeError(
        f"wrap() does not know how to guard {type(obj).__name__}: pass a list of tool "
        "functions, a LangGraph ToolNode or list of LangChain tools, or an OpenAI Agents Agent"
    )
