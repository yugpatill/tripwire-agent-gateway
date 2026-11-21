"""Agent sessions."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, status

from tripwire.api.deps import get_engine
from tripwire.auth.api_keys import Principal
from tripwire.auth.deps import require_api_key
from tripwire.models import SessionCreate, SessionCreated
from tripwire.pipeline.engine import Engine

router = APIRouter(prefix="/v1", tags=["sessions"], dependencies=[Depends(require_api_key)])


@router.post("/sessions", response_model=SessionCreated, status_code=status.HTTP_201_CREATED)
async def create_session(
    body: SessionCreate,
    engine: Annotated[Engine, Depends(get_engine)],
    principal: Annotated[Principal, Depends(require_api_key)],
) -> SessionCreated:
    return SessionCreated(session_id=await engine.create_session(body, owner=principal.key_id))
