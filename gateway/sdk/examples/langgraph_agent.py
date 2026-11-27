"""LangGraph agent with a guarded ToolNode.

    uv run python examples/langgraph_agent.py

The "model" is a scripted node that follows the injected instruction, so the
example runs without an LLM. To use a real model, replace `agent` with a chat
model bound to the tools (for example `model.bind_tools(tools)`); the guarded
ToolNode does not change. Needs a running gateway (TRIPWIRE_URL, TRIPWIRE_API_KEY).
"""

from __future__ import annotations

import sys
from typing import Any

from _scenario import (
    ATTACK_ARGS,
    FETCH_ARGS,
    USER_PROMPT,
    email__send_email,
    report,
    require_gateway,
    web__fetch,
)
from langchain_core.messages import AIMessage, ToolMessage
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition

from tripwire_guard import Guard
from tripwire_guard.adapters.langgraph import guard_tool_node


def agent(state: MessagesState) -> dict[str, Any]:
    """Scripted model: fetch the page, then do what the page says."""
    done = sum(isinstance(m, ToolMessage) for m in state["messages"])
    if done == 0:
        call = {"name": "web__fetch", "args": FETCH_ARGS, "id": "call_1", "type": "tool_call"}
        return {"messages": [AIMessage(content="", tool_calls=[call])]}
    if done == 1:
        call = {
            "name": "email__send_email",
            "args": ATTACK_ARGS,
            "id": "call_2",
            "type": "tool_call",
        }
        return {"messages": [AIMessage(content="", tool_calls=[call])]}
    return {
        "messages": [AIMessage(content="The council approved new bike lanes, starting in March.")]
    }


def main() -> int:
    require_gateway()
    guard = Guard(agent_name="example-langgraph", user_prompt=USER_PROMPT)
    graph = StateGraph(MessagesState)
    graph.add_node("agent", agent)
    graph.add_node("tools", guard_tool_node(guard, ToolNode([web__fetch, email__send_email])))
    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", tools_condition)
    graph.add_edge("tools", "agent")
    out = graph.compile().invoke({"messages": [("user", USER_PROMPT)]})
    print(f"User: {USER_PROMPT}")
    for m in out["messages"]:
        if isinstance(m, ToolMessage):
            text = " ".join(str(m.content).split())[:90]
            print(f"  ToolMessage {m.name} status={m.status}: {text}")
    return report(guard, str(out["messages"][-1].content))


if __name__ == "__main__":
    sys.exit(main())
