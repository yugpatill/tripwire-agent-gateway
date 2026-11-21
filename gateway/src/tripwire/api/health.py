"""Liveness and readiness probes."""

from __future__ import annotations

import contextlib
from typing import Literal

from fastapi import APIRouter, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import text

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: Literal["ok"]


class ReadyResponse(BaseModel):
    status: Literal["ok", "degraded"]
    checks: dict[str, bool]


@router.get("/healthz", response_model=HealthResponse)
async def healthz() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get("/readyz", response_model=ReadyResponse)
async def readyz(request: Request, response: Response) -> ReadyResponse:
    checks: dict[str, bool] = {"database": False, "redis": False}
    # Readiness must never raise; any failure just marks the dependency down.
    with contextlib.suppress(Exception):
        async with request.app.state.db_engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = True
    with contextlib.suppress(Exception):
        await request.app.state.redis.ping()
        checks["redis"] = True
    ok = all(checks.values())
    if not ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadyResponse(status="ok" if ok else "degraded", checks=checks)
