"""Provenance labels attached to every value seen in a session."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict

TrustT = Literal["trusted", "untrusted", "suspicious", "untrusted_origin"]
ConfidentialityT = Literal["public", "internal", "confidential", "secret"]

USER_SOURCE = "user"
SYSTEM_SOURCE = "system"


class Provenance(BaseModel):
    model_config = ConfigDict(frozen=True)

    source: str  # "user" | "system" | "<server>__<tool>"
    trust: TrustT
    confidentiality: ConfidentialityT
    event_id: UUID


class TaggedValue(BaseModel):
    """A string value observed in the session, with its provenance and match keys."""

    value: str
    normalized: str
    entities: list[str]
    provenance: Provenance
