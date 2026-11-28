"""WebSocket /v1/stream: live approval and tool events for operators.

Authentication: the console session cookie (browsers), or
`Authorization: Bearer <operator key>` on the upgrade request.
"""

from __future__ import annotations

import asyncio
import contextlib

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from tripwire.approvals.service import ApprovalService
from tripwire.auth.console import websocket_user

log = structlog.get_logger(__name__)
router = APIRouter(tags=["stream"])


@router.websocket("/v1/stream")
async def stream(ws: WebSocket) -> None:
    user = await websocket_user(ws)
    if user is None:
        await ws.close(code=status.WS_1008_POLICY_VIOLATION, reason="sign in to the console")
        return
    await ws.accept()
    approvals: ApprovalService = ws.app.state.approvals
    await ws.send_json({"type": "hello", "user": user.name, "role": user.role})

    async def pump() -> None:
        async for event in approvals.bus.subscribe():
            await ws.send_json(event)

    task = asyncio.create_task(pump())
    try:
        while True:  # the client may send pings; anything else is ignored
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task
