"""Agent sessions."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from tripwire.api.deps import get_engine
from tripwire.auth.api_keys import Principal
from tripwire.auth.deps import require_api_key
from tripwire.models import SessionCreate, SessionCreated
from tripwire.pipeline.engine import Engine, UnknownSessionError

router = APIRouter(prefix="/v1", tags=["sessions"], dependencies=[Depends(require_api_key)])


@router.post("/sessions", response_model=SessionCreated, status_code=status.HTTP_201_CREATED)
async def create_session(
    body: SessionCreate,
    engine: Annotated[Engine, Depends(get_engine)],
    principal: Annotated[Principal, Depends(require_api_key)],
) -> SessionCreated:
    return SessionCreated(session_id=await engine.create_session(body, owner=principal.key_id))


class UserPrompt(BaseModel):
    text: str = Field(min_length=1, max_length=100_000)


class UserPromptAdded(BaseModel):
    added: bool  # False when this exact prompt was already in the session


@router.post("/sessions/{session_id}/prompts", response_model=UserPromptAdded)
async def add_user_prompt(
    session_id: uuid.UUID,
    body: UserPrompt,
    engine: Annotated[Engine, Depends(get_engine)],
    principal: Annotated[Principal, Depends(require_api_key)],
) -> UserPromptAdded:
    """Add a user turn (multi-turn agents): entities in it count as user-given.

    Call it from the application with the user's own words, never with model output.
    """
    try:
        added = await engine.add_user_prompt(session_id, body.text, owner=principal.key_id)
    except UnknownSessionError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Unknown session"
        ) from exc
    return UserPromptAdded(added=added)
