"""FastAPI dependencies."""

from __future__ import annotations

from fastapi import Request

from tripwire.pipeline.engine import Engine


def get_engine(request: Request) -> Engine:
    engine: Engine = request.app.state.engine
    return engine
