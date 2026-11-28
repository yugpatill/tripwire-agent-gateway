"""Tripwire as an AgentDojo defense (configuration D).

The gateway is reached over HTTP only (TRIPWIRE_URL, TRIPWIRE_API_KEY); evals never
imports it. Two pipeline elements:

* TripwireSession, right after InitQuery: one Tripwire session per task, with the
  user's task text as the user prompt (so addresses the user named count as theirs).
* TripwireToolsExecutor, in place of AgentDojo's ToolsExecutor: every tool call goes
  to /v1/check/call first. A block or a hold (no operator here, so a hold is a
  denial) becomes a tool error the agent sees, and the tool does not run. An allowed
  call runs, and its output goes to /v1/check/result before the model sees it: the
  model gets the redacted content, or an error if Tripwire withholds it.

Tools are named agentdojo__<function> (policy.yaml).
"""

from __future__ import annotations

import os
from ast import literal_eval
from collections.abc import Sequence
from typing import Any

import httpx
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string

PREFIX = "agentdojo__"
STOP = {"block", "require_approval"}


def _client() -> httpx.Client:
    return httpx.Client(
        base_url=os.environ.get("TRIPWIRE_URL", "http://127.0.0.1:8100"),
        headers={"Authorization": f"Bearer {os.environ['TRIPWIRE_API_KEY']}"},
        timeout=httpx.Timeout(60.0),
        transport=httpx.HTTPTransport(retries=3),
    )


class TripwireSession(BasePipelineElement):
    def __init__(self) -> None:
        self.http = _client()

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(), messages: Sequence[ChatMessage] = [], extra_args: dict = {}) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        r = self.http.post("/v1/sessions", json={"agent_name": "agentdojo", "user_prompt": query})
        r.raise_for_status()
        return query, runtime, env, messages, {**extra_args, "tripwire_session": r.json()["session_id"]}


class TripwireToolsExecutor(BasePipelineElement):
    def __init__(self) -> None:
        self.http = _client()

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        r = self.http.post(path, json=body)
        r.raise_for_status()
        out: dict[str, Any] = r.json()
        return out

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(), messages: Sequence[ChatMessage] = [], extra_args: dict = {}) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args
        sid = extra_args["tripwire_session"]
        names = {t.name for t in runtime.functions.values()}
        results: list[ChatMessage] = []
        for call in messages[-1]["tool_calls"]:
            def reply(content: str, error: str | None = None) -> None:
                results.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string(content)], tool_call_id=call.id, tool_call=call, error=error))

            if call.function not in names:
                reply("", f"Invalid tool {call.function} provided.")
                continue
            for k, v in call.args.items():
                if isinstance(v, str) and is_string_list(v):
                    call.args[k] = literal_eval(v)
            tool = PREFIX + call.function
            d = self._post("/v1/check/call", {"session_id": sid, "tool": tool, "args": dict(call.args)})
            if d["action"] in STOP:
                verb = "blocked" if d["action"] == "block" else "held for approval, and no operator approved it"
                reply("", f"Tripwire {verb} this call ({d.get('rule_id') or 'policy'}): {d.get('message', '')}")
                continue
            args = d.get("redacted_args") or call.args if d["action"] == "redact" else call.args
            output, error = runtime.run_function(env, call.function, dict(args))
            text = tool_result_to_str(output)
            checked = self._post("/v1/check/result", {"session_id": sid, "tool": tool, "call_event_id": d["event_id"], "content": text})
            if checked["decision"]["action"] == "block":
                reply("", "Tripwire could not vet this tool result, so it was withheld.")
                continue
            content = checked.get("content_redacted")
            reply(content if isinstance(content, str) else text, error)
        return query, runtime, env, [*messages, *results], extra_args


def tripwire_pre_elements() -> list[BasePipelineElement]:
    return [TripwireSession()]


def tripwire_tools_elements() -> list[BasePipelineElement]:
    return [TripwireToolsExecutor()]
