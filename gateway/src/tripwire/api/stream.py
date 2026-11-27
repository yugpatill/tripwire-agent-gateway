"""WebSocket /v1/stream: live approval and tool events for operators.

Authentication: `Authorization: Bearer <operator key>` on the upgrade request.
(Browser login for the console arrives with the web app.)
"""

from __future__ import annotations

import asyncio
import contextlib

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from tripwire.approvals.service import ApprovalService
from tripwire.auth.api_keys import ApiKeyAuthenticator

log = structlog.get_logger(__name__)
router = APIRouter(tags=["stream"])


@router.websocket("/v1/stream")
async def stream(ws: WebSocket) -> None:
    scheme, _, token = ws.headers.get("authorization", "").partition(" ")
    auth: ApiKeyAuthenticator = ws.app.state.authenticator
    principal = None
    if scheme.lower() == "bearer" and token:
        with contextlib.suppress(Exception):
            principal = await auth.authenticate(token.strip())
    if principal is None or not principal.is_operator:
        await ws.close(code=status.WS_1008_POLICY_VIOLATION, reason="operator key required")
        return
    await ws.accept()
    approvals: ApprovalService = ws.app.state.approvals
    await ws.send_json({"type": "hello", "operator": principal.name})

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
