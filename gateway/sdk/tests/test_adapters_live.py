"""Each adapter against a running gateway: an injected tool result leads to a
blocked tool call.

The models are scripted (no LLM API key needed): they fetch the page, then do
what the injected comment says and try to email attacker@evil.io. The gateway
(demo policy) must block that call; the email tool must never run.

    TRIPWIRE_URL=http://localhost:8000 TRIPWIRE_API_KEY=tw_... uv run pytest -m live
"""

from __future__ import annotations

import json
from typing import Any

import httpx2
import pytest

from tests import scenario
from tests.scenario import ATTACK_ARGS, FETCH_ARGS, SENT, USER_PROMPT
from tripwire_guard import Guard

pytestmark = pytest.mark.live

BLOCK_TEXT = "Blocked by Tripwire (no-untrusted-recipient)"


def assert_blocked(guard: Guard) -> None:
    statuses = [(o.tool, o.status) for o in guard.outcomes]
    assert statuses == [("web__fetch", "allowed"), ("email__send_email", "blocked")], statuses
    assert guard.outcomes[0].suspicious_result  # the page was flagged as an injection
    assert guard.outcomes[1].decision is not None
    assert guard.outcomes[1].decision.rule_id == "no-untrusted-recipient"
    assert SENT == []  # the email tool never ran


# ---------------------------------------------------------------- Anthropic


def scripted_anthropic(requests: list[dict[str, Any]]) -> Any:
    """An Anthropic client whose API is a script: fetch, then follow the injection."""
    import anthropic

    turns = [
        [{"type": "tool_use", "id": "toolu_1", "name": "web__fetch", "input": FETCH_ARGS}],
        [{"type": "tool_use", "id": "toolu_2", "name": "email__send_email", "input": ATTACK_ARGS}],
        [{"type": "text", "text": "The council approved new bike lanes."}],
    ]

    def handler(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        requests.append(body)
        content = turns[min(len(requests) - 1, len(turns) - 1)]
        stop = "tool_use" if content[0]["type"] == "tool_use" else "end_turn"
        return httpx2.Response(
            200,
            json={
                "id": f"msg_{len(requests)}",
                "type": "message",
                "role": "assistant",
                "model": body["model"],
                "content": content,
                "stop_reason": stop,
                "stop_sequence": None,
                "usage": {"input_tokens": 10, "output_tokens": 10},
            },
        )

    return anthropic.Anthropic(
        api_key="scripted", http_client=httpx2.Client(transport=httpx2.MockTransport(handler))
    )


def _tool_results(body: dict[str, Any]) -> list[dict[str, Any]]:
    last = body["messages"][-1]
    return [b for b in last["content"] if b.get("type") == "tool_result"]


def test_anthropic_tool_runner_blocks_injected_call(live_guard: Guard) -> None:
    pytest.importorskip("anthropic")
    from tripwire_guard.adapters.anthropic import guard_tools

    requests: list[dict[str, Any]] = []
    client = scripted_anthropic(requests)
    runner = client.beta.messages.tool_runner(
        model="claude-opus-5-5",
        max_tokens=16000,
        tools=guard_tools(live_guard, [scenario.web__fetch, scenario.email__send_email]),
        messages=[{"role": "user", "content": USER_PROMPT}],
    )
    final = runner.until_done()
    assert final.stop_reason == "end_turn"
    assert_blocked(live_guard)
    (blocked,) = _tool_results(requests[2])
    assert blocked["is_error"] is True and BLOCK_TEXT in json.dumps(blocked["content"])


def test_anthropic_manual_loop_blocks_injected_call(live_guard: Guard) -> None:
    pytest.importorskip("anthropic")
    from tripwire_guard.adapters.anthropic import run_tool_calls

    requests: list[dict[str, Any]] = []
    client = scripted_anthropic(requests)
    tools = {"web__fetch": scenario.web__fetch, "email__send_email": scenario.email__send_email}
    messages: list[dict[str, Any]] = [{"role": "user", "content": USER_PROMPT}]
    for _ in range(5):
        response = client.messages.create(
            model="claude-opus-5-5", max_tokens=16000, messages=messages, tools=[]
        )
        if response.stop_reason != "tool_use":
            break
        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": run_tool_calls(live_guard, response, tools)})
    assert_blocked(live_guard)
    (blocked,) = messages[-1]["content"]
    assert blocked["is_error"] is True and blocked["content"].startswith(BLOCK_TEXT)


# ---------------------------------------------------------------- LangGraph


def _langgraph_app(guard: Guard, use_async: bool) -> Any:
    from langchain_core.messages import AIMessage, ToolMessage
    from langgraph.graph import START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode, tools_condition

    from tripwire_guard.adapters.langgraph import guard_tool_node

    def agent(state: MessagesState) -> dict[str, Any]:
        done = sum(isinstance(m, ToolMessage) for m in state["messages"])
        if done == 0:
            call = {"name": "web__fetch", "args": FETCH_ARGS, "id": "c1", "type": "tool_call"}
            return {"messages": [AIMessage(content="", tool_calls=[call])]}
        if done == 1:
            call = {
                "name": "email__send_email",
                "args": ATTACK_ARGS,
                "id": "c2",
                "type": "tool_call",
            }
            return {"messages": [AIMessage(content="", tool_calls=[call])]}
        return {"messages": [AIMessage(content="The council approved new bike lanes.")]}

    tools: list[Any] = [scenario.web__fetch, scenario.email__send_email]
    if use_async:
        # Async tools keep the sync names the policy knows.
        from langchain_core.tools import StructuredTool

        tools = [
            StructuredTool.from_function(coroutine=scenario.aweb__fetch, name="web__fetch"),
            StructuredTool.from_function(
                coroutine=scenario.aemail__send_email, name="email__send_email"
            ),
        ]
    graph = StateGraph(MessagesState)
    graph.add_node("agent", agent)
    graph.add_node("tools", guard_tool_node(guard, ToolNode(tools)))
    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", tools_condition)
    graph.add_edge("tools", "agent")
    return graph.compile()


def _check_langgraph(guard: Guard, messages: list[Any]) -> None:
    from langchain_core.messages import ToolMessage

    tool_msgs = [m for m in messages if isinstance(m, ToolMessage)]
    assert [m.status for m in tool_msgs] == ["success", "error"]
    assert tool_msgs[1].content.startswith(BLOCK_TEXT)
    assert_blocked(guard)


def test_langgraph_tool_node_blocks_injected_call(live_guard: Guard) -> None:
    pytest.importorskip("langgraph")
    out = _langgraph_app(live_guard, use_async=False).invoke({"messages": [("user", USER_PROMPT)]})
    _check_langgraph(live_guard, out["messages"])


async def test_langgraph_async_blocks_injected_call(live_guard: Guard) -> None:
    pytest.importorskip("langgraph")
    out = await _langgraph_app(live_guard, use_async=True).ainvoke(
        {"messages": [("user", USER_PROMPT)]}
    )
    _check_langgraph(live_guard, out["messages"])


# ---------------------------------------------------------------- OpenAI Agents SDK


def _scripted_agents_model() -> Any:
    from agents import Usage
    from agents.models.interface import Model, ModelResponse
    from openai.types.responses import (
        ResponseFunctionToolCall,
        ResponseOutputMessage,
        ResponseOutputText,
    )

    class ScriptedModel(Model):
        def __init__(self) -> None:
            self.turn = 0
            self.inputs: list[Any] = []

        async def get_response(
            self, system_instructions: Any, input: Any, *a: Any, **k: Any
        ) -> Any:
            self.inputs.append(input)
            self.turn += 1
            if self.turn == 1:
                out: list[Any] = [
                    ResponseFunctionToolCall(
                        type="function_call",
                        call_id="call_1",
                        name="web__fetch",
                        arguments=json.dumps(FETCH_ARGS),
                    )
                ]
            elif self.turn == 2:
                out = [
                    ResponseFunctionToolCall(
                        type="function_call",
                        call_id="call_2",
                        name="email__send_email",
                        arguments=json.dumps(ATTACK_ARGS),
                    )
                ]
            else:
                out = [
                    ResponseOutputMessage(
                        id="msg_3",
                        type="message",
                        role="assistant",
                        status="completed",
                        content=[
                            ResponseOutputText(
                                type="output_text",
                                text="The council approved new bike lanes.",
                                annotations=[],
                            )
                        ],
                    )
                ]
            return ModelResponse(output=out, usage=Usage(), response_id=None)

        def stream_response(self, *a: Any, **k: Any) -> Any:
            raise NotImplementedError

    return ScriptedModel()


async def test_openai_agents_blocks_injected_call(live_guard: Guard) -> None:
    pytest.importorskip("agents")
    from agents import Agent, Runner, function_tool, set_tracing_disabled

    from tripwire_guard.adapters.openai_agents import guard_agent

    set_tracing_disabled(True)
    model = _scripted_agents_model()
    agent = Agent(
        name="assistant",
        instructions="Summarize pages for the user.",
        tools=[function_tool(scenario.web__fetch), function_tool(scenario.email__send_email)],
        model=model,
    )
    result = await Runner.run(guard_agent(live_guard, agent), USER_PROMPT)
    assert result.final_output == "The council approved new bike lanes."
    assert_blocked(live_guard)
    # The model saw the block reason as the tool output.
    last_input = json.dumps(model.inputs[-1], default=str)
    assert BLOCK_TEXT in last_input
