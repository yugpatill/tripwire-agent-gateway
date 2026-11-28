"""Tool pins: what Tripwire has seen from upstream MCP servers (operator only)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from tripwire.approvals.service import ApprovalService
from tripwire.auth.console import ConsoleUser, console_reader, console_writer
from tripwire.proxy.guard import ManifestGuard

router = APIRouter(prefix="/v1/tools", tags=["tools"])


class ToolPinView(BaseModel):
    name: str
    server: str
    status: str
    hash: str
    risk_score: float
    findings: list[dict[str, Any]]
    manifest: dict[str, Any]
    pending_change: dict[str, Any] | None


def get_guard(request: Request) -> ManifestGuard:
    guard: ManifestGuard = request.app.state.guard
    return guard


@router.get("", response_model=list[ToolPinView])
async def list_tools(
    guard: Annotated[ManifestGuard, Depends(get_guard)],
    _: Annotated[ConsoleUser, Depends(console_reader)],
) -> list[ToolPinView]:
    return [
        ToolPinView(
            name=p.name,
            server=p.server,
            status=p.status,
            hash=p.hash,
            risk_score=p.risk_score,
            findings=p.findings,
            manifest=p.manifest,
            pending_change=p.pending_manifest,
        )
        for p in await guard.store.all()
    ]


@router.post("/{name}/approve", response_model=ToolPinView)
async def approve_tool(
    name: str,
    request: Request,
    guard: Annotated[ManifestGuard, Depends(get_guard)],
    user: Annotated[ConsoleUser, Depends(console_writer)],
) -> ToolPinView:
    """Re-pin a quarantined or changed tool after review (also closes its open reviews)."""
    approvals: ApprovalService | None = request.app.state.approvals
    decided = False
    if approvals is not None:
        for kind in ("tool_quarantine", "tool_change"):
            for rec in await approvals.store.pending_for_tool(kind, name):
                await approvals.decide(rec.id, "approve", "once", user.name)
                decided = True
    pin = await guard.store.get(name) if decided else await guard.approve(name)
    if pin is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown tool")
    if pin.status != "pinned":  # a stale review: trust the latest manifest explicitly
        pin = await guard.approve(name)
        assert pin is not None
    return ToolPinView(
        name=pin.name,
        server=pin.server,
        status=pin.status,
        hash=pin.hash,
        risk_score=pin.risk_score,
        findings=pin.findings,
        manifest=pin.manifest,
        pending_change=pin.pending_manifest,
    )
