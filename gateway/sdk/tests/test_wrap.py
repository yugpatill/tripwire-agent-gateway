"""wrap() dispatch and adapter construction (no gateway needed)."""

from __future__ import annotations

import pytest

from tests.scenario import email__send_email, web__fetch
from tripwire_guard import Guard, TripwireError, wrap


def guard() -> Guard:
    return Guard(api_key="tw_test")  # never contacted in these tests


def test_wrap_functions_gives_guarded_beta_tools() -> None:
    pytest.importorskip("anthropic")
    tools = wrap([web__fetch, email__send_email], guard=guard())
    assert [t.name for t in tools] == ["web__fetch", "email__send_email"]
    schema = tools[1].to_dict()["input_schema"]
    assert schema["required"] == ["to", "subject", "body"]
    assert not hasattr(tools[1].func, "__wrapped__")  # no way around the guard


def test_wrap_tool_node_and_langchain_tools() -> None:
    pytest.importorskip("langgraph")
    from langchain_core.tools import StructuredTool
    from langgraph.prebuilt import ToolNode

    node = wrap(ToolNode([web__fetch, email__send_email]), guard=guard())
    assert isinstance(node, ToolNode) and set(node.tools_by_name) == {
        "web__fetch",
        "email__send_email",
    }
    assert node._wrap_tool_call is not None and node._awrap_tool_call is not None
    lc = [StructuredTool.from_function(web__fetch)]
    assert isinstance(wrap(lc, guard=guard()), ToolNode)


def test_wrap_agent_guards_function_tools_and_handoffs() -> None:
    pytest.importorskip("agents")
    from agents import Agent, FunctionTool, function_tool

    helper = Agent(name="helper", tools=[function_tool(email__send_email)])
    agent = Agent(name="main", tools=[function_tool(web__fetch)], handoffs=[helper])
    safe = wrap(agent, guard=guard())
    assert safe is not agent and isinstance(safe.tools[0], FunctionTool)
    assert safe.tools[0].on_invoke_tool is not agent.tools[0].on_invoke_tool
    (h,) = safe.handoffs
    assert h is not helper and h.tools[0].on_invoke_tool is not helper.tools[0].on_invoke_tool


def test_hosted_tools_and_custom_handoffs_are_refused() -> None:
    pytest.importorskip("agents")
    from agents import Agent, WebSearchTool, handoff

    with pytest.raises(TripwireError, match="hosted tool"):
        wrap(Agent(name="a", tools=[WebSearchTool()]), guard=guard())
    with pytest.raises(TripwireError, match="handoff"):
        wrap(Agent(name="a", handoffs=[handoff(Agent(name="b"))]), guard=guard())
    ok = wrap(Agent(name="a", tools=[WebSearchTool()]), guard=guard(), allow_unguarded=True)
    assert ok.name == "a"


def test_wrap_rejects_unknown_objects() -> None:
    with pytest.raises(TypeError):
        wrap(object(), guard=guard())
