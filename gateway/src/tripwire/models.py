"""Core request/response contracts (docs/design.md section 6.1)."""

from __future__ import annotations

from typing import Any, Final, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from tripwire.taint.labels import ConfidentialityT, Provenance, TrustT

Trust = TrustT
Confidentiality = ConfidentialityT
Action = Literal["allow", "block", "redact", "require_approval", "log_only"]
Mode = Literal["enforce", "shadow"]

# Ordering used for comparisons (docs/design.md section 6.1).
TRUST_ORDER: Final[dict[str, int]] = {
    "trusted": 0,
    "untrusted": 1,
    "untrusted_origin": 2,
    "suspicious": 3,
}
CONFIDENTIALITY_ORDER: Final[dict[str, int]] = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "secret": 3,
}
# Precedence when several rules match: first block wins, then require_approval, then redact.
ACTION_PRECEDENCE: Final[dict[str, int]] = {
    "allow": 0,
    "log_only": 1,
    "redact": 2,
    "require_approval": 3,
    "block": 4,
}


def trust_rank(t: Trust) -> int:
    return TRUST_ORDER[t]


def confidentiality_rank(c: Confidentiality) -> int:
    return CONFIDENTIALITY_ORDER[c]


def max_confidentiality(a: Confidentiality, b: Confidentiality) -> Confidentiality:
    return a if CONFIDENTIALITY_ORDER[a] >= CONFIDENTIALITY_ORDER[b] else b


class ToolCall(BaseModel):
    session_id: UUID
    tool: str = Field(description='Namespaced "<server>__<tool>"')
    args: dict[str, Any]


class ToolResult(BaseModel):
    session_id: UUID
    tool: str
    call_event_id: UUID
    content: str | dict[str, Any] | list[Any]


class DetectorResult(BaseModel):
    detector: Literal["heuristic", "classifier", "llm_judge", "secrets", "pii", "manifest"]
    score: float = Field(ge=0.0, le=1.0)
    spans: list[tuple[int, int]]
    reason: str


class Decision(BaseModel):
    event_id: UUID
    action: Action
    rule_id: str | None
    message: str
    arg_labels: dict[str, list[Provenance]]
    detectors: list[DetectorResult]
    redacted_args: dict[str, Any] | None
    latency_ms: float
    approval_id: UUID | None


class DataFlowEdge(BaseModel):
    """A taint edge: a value from `from_event` flowed into `arg` of `to_event`."""

    from_event: UUID
    to_event: UUID
    arg: str
    matched_value: str
    label: Provenance
    match: Literal["exact", "normalized", "entity", "user_prompt", "origin"]


class SessionCreate(BaseModel):
    agent_name: str = Field(min_length=1, max_length=200)
    user_prompt: str = Field(max_length=100_000)
    mode: Mode = "enforce"


class SessionCreated(BaseModel):
    session_id: UUID


class ResultCheck(BaseModel):
    content_redacted: str | dict[str, Any] | list[Any]
    labels: list[Provenance]
    detectors: list[DetectorResult]
    decision: Decision
