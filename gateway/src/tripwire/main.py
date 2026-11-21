"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from tripwire import __version__
from tripwire.api import check, health, sessions
from tripwire.config import Settings, get_settings
from tripwire.db.session import make_engine, make_sessionmaker
from tripwire.log_config import configure_logging
from tripwire.pipeline.engine import Engine
from tripwire.pipeline.recorder import SqlRecorder
from tripwire.policy.compiler import CompiledPolicy, compile_policy
from tripwire.policy.loader import PolicyError, load_policy_file
from tripwire.taint.store import RedisTaintStore

log = structlog.get_logger(__name__)


def load_active_policy(path: str) -> CompiledPolicy | None:
    """Load the policy file; on failure return None so every decision fails closed."""
    try:
        doc, text = load_policy_file(path)
    except (OSError, PolicyError) as exc:
        log.error("policy.load_failed", path=path, error=str(exc))
        return None
    policy = compile_policy(doc, text)
    log.info("policy.loaded", path=path, version=policy.version, rules=len(policy.rules))
    return policy


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_json)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = make_engine(settings.database_url)
        app.state.engine = engine
        app.state.sessionmaker = make_sessionmaker(engine)
        app.state.redis = aioredis.Redis.from_url(settings.redis_url, decode_responses=True)
        app.state.engine = Engine(
            store=RedisTaintStore(app.state.redis),
            recorder=SqlRecorder(app.state.sessionmaker),
            policy=load_active_policy(settings.tripwire_policy_path),
            default_mode=settings.tripwire_mode,
        )
        log.info("gateway.startup", version=__version__, mode=settings.tripwire_mode)
        try:
            yield
        finally:
            await app.state.redis.aclose()
            await engine.dispose()
            log.info("gateway.shutdown")

    app = FastAPI(title="Tripwire Gateway", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(health.router)
    app.include_router(sessions.router)
    app.include_router(check.router)
    return app


app = create_app()
