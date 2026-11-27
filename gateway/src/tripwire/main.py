"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from tripwire import __version__
from tripwire.api import approvals, check, health, sessions, stream, tools
from tripwire.approvals.service import ApprovalService, RedisEventBus, SqlApprovalStore
from tripwire.auth.api_keys import ApiKeyAuthenticator, SqlKeyRepository
from tripwire.config import Settings, get_settings
from tripwire.db.session import make_engine, make_sessionmaker
from tripwire.log_config import configure_logging
from tripwire.pipeline.classifier import InjectionClassifier
from tripwire.pipeline.detect import DetectionPipeline
from tripwire.pipeline.engine import Engine
from tripwire.pipeline.llm_judge import AnthropicJudge, Judge
from tripwire.pipeline.pii import PiiDetector
from tripwire.pipeline.recorder import SqlRecorder
from tripwire.policy.compiler import CompiledPolicy, compile_policy
from tripwire.policy.loader import PolicyError, load_policy_file
from tripwire.proxy.guard import ManifestGuard, SqlPinStore
from tripwire.proxy.mcp_gateway import McpProxy, RedisSessionMap, build_http_app
from tripwire.proxy.upstreams import UpstreamPool, load_upstreams
from tripwire.taint.store import RedisTaintStore

log = structlog.get_logger(__name__)


def build_detection(settings: Settings) -> DetectionPipeline:
    classifier = InjectionClassifier(
        settings.tripwire_classifier_dir or None, settings.tripwire_classifier_threads
    )
    judge: Judge | None = None
    if settings.tripwire_llm_judge_enabled:
        if settings.tripwire_llm_judge_model:
            judge = AnthropicJudge(
                settings.tripwire_llm_judge_model,
                settings.anthropic_api_key.get_secret_value(),
                settings.tripwire_llm_judge_timeout_s,
            )
        else:
            log.warning(
                "llm_judge.disabled",
                reason="TRIPWIRE_LLM_JUDGE_ENABLED is set but TRIPWIRE_LLM_JUDGE_MODEL is empty",
                effect="gray-zone content is treated as suspicious",
            )
    pii = None if settings.tripwire_pii_mode == "off" else PiiDetector(settings.tripwire_pii_mode)
    return DetectionPipeline(classifier=classifier, judge=judge, pii=pii)


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
        app.state.db_engine = engine
        app.state.sessionmaker = make_sessionmaker(engine)
        app.state.redis = aioredis.Redis.from_url(settings.redis_url, decode_responses=True)
        app.state.authenticator = ApiKeyAuthenticator(SqlKeyRepository(app.state.sessionmaker))
        app.state.approvals = ApprovalService(
            SqlApprovalStore(app.state.sessionmaker),
            RedisEventBus(app.state.redis),
            timeout_s=settings.tripwire_approval_timeout_s,
        )
        detection = build_detection(settings)
        app.state.engine = Engine(
            store=RedisTaintStore(app.state.redis),
            recorder=SqlRecorder(app.state.sessionmaker),
            policy=load_active_policy(settings.tripwire_policy_path),
            default_mode=settings.tripwire_mode,
            detection=detection,
            approvals=app.state.approvals,
        )
        app.state.guard = ManifestGuard(
            SqlPinStore(app.state.sessionmaker), app.state.approvals, detection
        )
        pool = UpstreamPool(load_upstreams(settings.tripwire_mcp_upstreams))
        app.state.mcp = McpProxy(
            app.state.engine,
            app.state.guard,
            pool,
            app.state.approvals,
            settings.tripwire_approval_timeout_s,
            sessions=RedisSessionMap(app.state.redis),
        )
        app.state.mcp_asgi, manager = build_http_app(
            app.state.mcp,
            app.state.authenticator,
            settings.tripwire_mcp_allowed_hosts,
            settings.tripwire_mcp_allowed_origins,
            production=settings.tripwire_env == "production",
        )
        log.info(
            "gateway.startup",
            version=__version__,
            mode=settings.tripwire_mode,
            mcp_upstreams=sorted(pool.upstreams),
        )
        try:
            async with manager.run():
                yield
        finally:
            await pool.aclose()
            await app.state.engine.drain_shadow()
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
    app.include_router(approvals.router)
    app.include_router(tools.router)
    app.include_router(stream.router)

    class McpEndpoint:
        """ASGI endpoint (a class, so Starlette passes every method through).

        The proxy is built in the lifespan (it needs the engine); routing it here
        keeps it behind the same app, CORS and middleware as the REST API."""

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            await app.state.mcp_asgi(scope, receive, send)

    app.router.routes.append(Route("/v1/mcp", endpoint=McpEndpoint(), include_in_schema=False))
    return app


app = create_app()
