"""Approval queue: held tool calls and tool reviews.

Deciding needs an operator key. An agent key may read an approval for a call in
one of its own sessions (to poll it), but can never decide one.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel

from tripwire.approvals.service import (
    ApprovalError,
    ApprovalRecord,
    ApprovalService,
    ApprovalStatus,
)
from tripwire.auth.api_keys import Principal
from tripwire.auth.console import ConsoleUser, console_reader, console_writer
from tripwire.auth.deps import require_api_key

router = APIRouter(prefix="/v1/approvals", tags=["approvals"])


class ApprovalDecision(BaseModel):
    decision: Literal["approve", "deny"]
    scope: Literal["once", "session"] = "once"


def get_approvals(request: Request) -> ApprovalService:
    svc: ApprovalService = request.app.state.approvals
    return svc


@router.get("", response_model=list[ApprovalRecord])
async def list_approvals(
    svc: Annotated[ApprovalService, Depends(get_approvals)],
    _: Annotated[ConsoleUser, Depends(console_reader)],
    status_: Annotated[ApprovalStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[ApprovalRecord]:
    return await svc.list_approvals(status_, limit)


@router.get("/{approval_id}", response_model=ApprovalRecord)
async def get_approval(
    approval_id: uuid.UUID,
    request: Request,
    svc: Annotated[ApprovalService, Depends(get_approvals)],
    principal: Annotated[Principal, Depends(require_api_key)],
) -> ApprovalRecord:
    rec = await svc.get(approval_id)
    if rec is not None and not principal.is_operator:
        session = (
            await request.app.state.engine.store.get_session(rec.session_id)
            if rec.session_id
            else None
        )
        if session is None or session.owner != principal.key_id:
            rec = None  # same answer as unknown: no oracle for other keys' approvals
    if rec is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown approval")
    return rec


@router.post("/{approval_id}", response_model=ApprovalRecord)
async def decide_approval(
    approval_id: uuid.UUID,
    body: ApprovalDecision,
    svc: Annotated[ApprovalService, Depends(get_approvals)],
    user: Annotated[ConsoleUser, Depends(console_writer)],
) -> ApprovalRecord:
    try:
        return await svc.decide(approval_id, body.decision, body.scope, user.name)
    except ApprovalError as exc:
        code = status.HTTP_404_NOT_FOUND if "unknown" in str(exc) else status.HTTP_409_CONFLICT
        raise HTTPException(status_code=code, detail=str(exc)) from exc
