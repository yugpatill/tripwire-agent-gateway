"""OpenAI Agents SDK agent guarded by Tripwire.

    uv run python examples/openai_agents_agent.py           # scripted model, no API key
    uv run python examples/openai_agents_agent.py --live    # SDK default model, OPENAI_API_KEY

Needs a running gateway (TRIPWIRE_URL, TRIPWIRE_API_KEY) with the demo policy.
"""

from __future__ import annotations

import argparse
import asyncio
import json
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
from agents import Agent, Runner, Usage, function_tool, set_tracing_disabled
from agents.models.interface import Model, ModelResponse
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from tripwire_guard import Guard
from tripwire_guard.adapters.openai_agents import guard_agent


class ScriptedModel(Model):
    """Fetches the page, then follows the injected instruction."""

    def __init__(self) -> None:
        self.turn = 0

    async def get_response(self, *args: Any, **kwargs: Any) -> ModelResponse:
        self.turn += 1
        if self.turn in (1, 2):
            name, call_args = (
                ("web__fetch", FETCH_ARGS)
                if self.turn == 1
                else (
                    "email__send_email",
                    ATTACK_ARGS,
                )
            )
            out: list[Any] = [
                ResponseFunctionToolCall(
                    type="function_call",
                    call_id=f"call_{self.turn}",
                    name=name,
                    arguments=json.dumps(call_args),
                )
            ]
        else:
            text = "The council approved new bike lanes, starting in March."
            out = [
                ResponseOutputMessage(
                    id="msg_final",
                    type="message",
                    role="assistant",
                    status="completed",
                    content=[ResponseOutputText(type="output_text", text=text, annotations=[])],
                )
            ]
        return ModelResponse(output=out, usage=Usage(), response_id=None)

    def stream_response(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="use the SDK's default model")
    a = ap.parse_args()
    require_gateway()
    if not a.live:
        set_tracing_disabled(True)
    guard = Guard(agent_name="example-openai-agents", user_prompt=USER_PROMPT)
    agent = Agent(
        name="assistant",
        instructions="You summarize web pages for the user.",
        tools=[function_tool(web__fetch), function_tool(email__send_email)],
        **({} if a.live else {"model": ScriptedModel()}),
    )
    result = await Runner.run(guard_agent(guard, agent), USER_PROMPT)
    print(f"User: {USER_PROMPT}")
    return report(guard, str(result.final_output))


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
