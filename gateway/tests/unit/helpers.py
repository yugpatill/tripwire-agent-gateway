from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import UUID

from tripwire.models import SessionCreate, ToolCall, ToolResult
from tripwire.pipeline.engine import Engine
from tripwire.pipeline.recorder import MemoryRecorder
from tripwire.policy.compiler import CompiledPolicy, compile_policy
from tripwire.policy.loader import load_policy_file, parse_policy
from tripwire.taint.store import InMemoryTaintStore

POLICIES = Path(__file__).resolve().parents[2] / "policies"


def demo_policy() -> CompiledPolicy:
    doc, text = load_policy_file(POLICIES / "demo.yaml")
    return compile_policy(doc, text)


def policy_from(text: str) -> CompiledPolicy:
    return compile_policy(parse_policy(text), text)


def make_engine(policy: CompiledPolicy | None = None, mode: str = "enforce") -> Engine:
    return Engine(InMemoryTaintStore(), MemoryRecorder(), policy or demo_policy(), mode)


async def session(engine: Engine, prompt: str, mode: str = "enforce") -> UUID:
    return await engine.create_session(
        SessionCreate(agent_name="test", user_prompt=prompt, mode=mode)  # type: ignore[arg-type]
    )


async def call_and_result(
    engine: Engine, sid: UUID, tool: str, args: dict[str, Any], content: Any
) -> UUID:
    d = await engine.check_call(ToolCall(session_id=sid, tool=tool, args=args))
    await engine.check_result(
        ToolResult(session_id=sid, tool=tool, call_event_id=d.event_id, content=content)
    )
    return d.event_id


def call(sid: UUID, tool: str, **args: Any) -> ToolCall:
    return ToolCall(session_id=sid, tool=tool, args=args)
