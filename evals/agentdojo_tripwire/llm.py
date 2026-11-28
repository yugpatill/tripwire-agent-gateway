"""Claude as an AgentDojo pipeline element, for current models.

AgentDojo 0.1.35's `AnthropicLLM` always sends `temperature` (0.0 by default) and
uses `budget_tokens` for thinking. Claude Haiku 5.5 rejects both with HTTP 400
(non-default sampling parameters; adaptive thinking only). Its request-side
converters also call `MessageParam(...)`, which the anthropic 2.x SDK made a type
alias that cannot be instantiated. This element builds the request as plain dicts,
passes thinking blocks back unchanged (redacted ones included), keeps AgentDojo's
response parser, and calls the Messages API with the model's own defaults:
adaptive thinking, `output_config.effort`, no sampling parameters.

Every response is cached on disk by a hash of the full request, so a rerun with
the same inputs costs nothing, and token usage is accumulated for cost reports.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.anthropic_llm import _anthropic_to_assistant_message
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage
from anthropic import Anthropic
from anthropic.types import Message

# USD per million tokens (input, output), prompts up to 100K tokens.
PRICES = {"claude-haiku-5-5": (0.10, 0.50)}


@dataclass
class Usage:
    calls: int = 0
    cached_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    by_case: dict[str, list[int]] = field(default_factory=dict)  # case -> [in, out]

    def cost(self, model: str) -> float:
        p_in, p_out = PRICES[model]
        return (self.input_tokens * p_in + self.output_tokens * p_out) / 1e6


class ClaudeLLM(BasePipelineElement):
    def __init__(
        self,
        model: str,
        cache_dir: Path,
        effort: str = "low",
        max_tokens: int = 4096,
        client: Anthropic | None = None,
    ) -> None:
        self.model = model
        self.effort = effort
        self.max_tokens = max_tokens
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.client = client or Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"), max_retries=6)
        self.usage = Usage()
        self.case = ""  # set by the runner, for per-case usage

    def _request(self, system: str | None, messages: list[Any], tools: list[Any]) -> dict[str, Any]:
        req: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": messages,
            "tools": tools,
            "output_config": {"effort": self.effort},
        }
        if system:
            req["system"] = system
        return req

    def _create(self, req: dict[str, Any]) -> Message:
        key = hashlib.sha256(json.dumps(req, sort_keys=True, default=str).encode()).hexdigest()
        path = self.cache_dir / f"{key}.json"
        if path.exists():
            self.usage.cached_calls += 1
            return Message.model_validate_json(path.read_text())
        msg = self.client.messages.create(**req)
        path.write_text(msg.model_dump_json())
        self.usage.calls += 1
        self.usage.input_tokens += msg.usage.input_tokens
        self.usage.output_tokens += msg.usage.output_tokens
        tot = self.usage.by_case.setdefault(self.case, [0, 0])
        tot[0] += msg.usage.input_tokens
        tot[1] += msg.usage.output_tokens
        return msg

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        system, conv = conversation_to_anthropic(messages)
        tools = [
            {"name": t.name, "description": t.description, "input_schema": t.parameters.model_json_schema()}
            for t in runtime.functions.values()
        ]
        completion = self._create(self._request(system, conv, tools))
        output = _anthropic_to_assistant_message(completion)
        if output["tool_calls"] is not None:
            output["tool_calls"] = [c for c in output["tool_calls"] if re.match(r"^[a-zA-Z0-9_-]{1,64}$", c.function)]
        return query, runtime, env, [*messages, output], extra_args


def _block(b: dict[str, Any]) -> dict[str, Any]:
    match b["type"]:
        case "text":
            return {"type": "text", "text": b["content"]}
        case "thinking" if b.get("id") is not None:
            return {"type": "thinking", "thinking": b["content"], "signature": b["id"]}
        case "thinking" | "redacted_thinking":
            return {"type": "redacted_thinking", "data": b["content"]}
    raise ValueError(f"unsupported content block {b['type']}")


def _message(m: ChatMessage) -> dict[str, Any]:
    if m["role"] == "user":
        return {"role": "user", "content": [_block(b) for b in m["content"]]}  # type: ignore[arg-type]
    if m["role"] == "tool":
        if m["error"] is not None:
            text = m["error"]
        else:
            text = m["content"][0]["content"] if m["content"] else ""  # type: ignore[index]
        result: dict[str, Any] = {"type": "tool_result", "tool_use_id": m["tool_call_id"], "is_error": m["error"] is not None}
        if text:
            result["content"] = [{"type": "text", "text": text}]
        return {"role": "user", "content": [result]}
    if m["role"] == "assistant":
        blocks = [_block(b) for b in (m["content"] or [])]  # type: ignore[arg-type]
        blocks += [{"type": "tool_use", "id": c.id, "name": c.function, "input": dict(c.args)} for c in (m["tool_calls"] or [])]
        return {"role": "assistant", "content": blocks}
    raise ValueError(f"unsupported role {m['role']}")


def conversation_to_anthropic(messages: Sequence[ChatMessage]) -> tuple[str | None, list[dict[str, Any]]]:
    """System prompt and messages; consecutive user-side messages (tool results) merged."""
    system = None
    rest = list(messages)
    if rest and rest[0]["role"] == "system":
        system = rest[0]["content"][0]["content"]  # type: ignore[index]
        rest = rest[1:]
    out: list[dict[str, Any]] = []
    for m in rest:
        msg = _message(m)
        if out and out[-1]["role"] == "user" and msg["role"] == "user":
            out[-1]["content"] = [*out[-1]["content"], *msg["content"]]
        else:
            out.append(msg)
    return system, out
