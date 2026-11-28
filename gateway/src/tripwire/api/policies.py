"""Console policy APIs: the active policy, deploy, test against recorded traffic,
the JSON Schema for the editor, and the shadow-mode switch."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from tripwire.auth.console import ConsoleUser, console_reader, console_writer
from tripwire.policy.loader import PolicyError
from tripwire.policy.schema import PolicyDocument
from tripwire.policy.service import PolicyService

router = APIRouter(prefix="/v1/policies", tags=["policies"])
Reader = Annotated[ConsoleUser, Depends(console_reader)]
Writer = Annotated[ConsoleUser, Depends(console_writer)]
MAX_POLICY_CHARS = 200_000


def service(request: Request) -> PolicyService:
    s: PolicyService = request.app.state.policies
    return s


Service = Annotated[PolicyService, Depends(service)]


class ActivePolicy(BaseModel):
    version: int
    yaml: str
    created_by: str
    created_at: datetime | None


class PolicyText(BaseModel):
    yaml: str = Field(max_length=MAX_POLICY_CHARS)


class Deployed(BaseModel):
    version: int


class Change(BaseModel):
    event_id: str
    session_id: str
    created_at: datetime
    tool: str
    old_action: str
    old_rule_id: str | None
    new_action: str
    rule_id: str | None


class TestResult(BaseModel):
    replayed: int
    skipped: int  # calls recorded without session facts (before they were stored)
    since_hours: int
    changes: list[Change]


class ModeView(BaseModel):
    mode: Literal["enforce", "shadow"]


def invalid(exc: PolicyError) -> HTTPException:
    return HTTPException(
        422,
        {
            "message": "The policy is not valid.",
            "errors": [
                {"loc": e.loc, "message": e.message, "line": e.line, "column": e.column}
                for e in exc.errors
            ],
        },
    )


@router.get("/active", response_model=ActivePolicy)
async def get_active(_: Reader, s: Service) -> ActivePolicy:
    return ActivePolicy(**await s.active())


@router.put("/active", response_model=Deployed)
async def deploy(body: PolicyText, user: Writer, s: Service) -> Deployed:
    try:
        return Deployed(version=await s.deploy(body.yaml, user.name))
    except PolicyError as exc:
        raise invalid(exc) from exc


@router.post("/test", response_model=TestResult)
async def test_policy(
    body: PolicyText,
    _: Reader,
    s: Service,
    since_hours: Annotated[int, Query(ge=1, le=24 * 30)] = 24 * 7,
) -> TestResult:
    """What the candidate policy would have decided for recorded calls (no rate limits)."""
    try:
        return TestResult(**await s.test(body.yaml, since_hours))
    except PolicyError as exc:
        raise invalid(exc) from exc


@router.get("/schema")
async def schema(_: Reader) -> dict[str, Any]:
    return PolicyDocument.model_json_schema()


@router.get("/mode", response_model=ModeView)
async def get_mode(_: Reader, s: Service) -> ModeView:
    return ModeView(mode=await s.mode())


@router.put("/mode", response_model=ModeView)
async def set_mode(body: ModeView, user: Writer, s: Service) -> ModeView:
    await s.set_mode(body.mode, user.name)
    return ModeView(mode=body.mode)
