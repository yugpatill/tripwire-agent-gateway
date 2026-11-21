"""Decision endpoints used by SDK adapters and the MCP proxy."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from tripwire.api.deps import get_engine
from tripwire.auth.api_keys import Principal
from tripwire.auth.deps import require_api_key
from tripwire.models import Decision, ResultCheck, ToolCall, ToolResult
from tripwire.pipeline.engine import Engine

router = APIRouter(prefix="/v1/check", tags=["check"], dependencies=[Depends(require_api_key)])


@router.post("/call", response_model=Decision)
async def check_call(
    call: ToolCall,
    engine: Annotated[Engine, Depends(get_engine)],
    principal: Annotated[Principal, Depends(require_api_key)],
) -> Decision:
    return await engine.check_call(call, owner=principal.key_id)


@router.post("/result", response_model=ResultCheck)
async def check_result(
    result: ToolResult,
    engine: Annotated[Engine, Depends(get_engine)],
    principal: Annotated[Principal, Depends(require_api_key)],
) -> ResultCheck:
    return await engine.check_result(result, owner=principal.key_id)
