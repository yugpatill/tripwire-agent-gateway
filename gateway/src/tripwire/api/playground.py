"""Public playground API: presets, runs, live streams, replays.

No authentication (the web app's landing page uses it); cost is bounded by the
runner's limits (per-IP hourly limit, global daily cap on real-model runs, steps
and output tokens per run).
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from tripwire.playground.runner import PlaygroundError, PlaygroundRunner, RateLimited
from tripwire.playground.scenarios import CUSTOM_TASKS, MAX_CUSTOM_CHARS, presets
from tripwire.playground.store import replay_variants

log = structlog.get_logger(__name__)
router = APIRouter(prefix="/v1/playground", tags=["playground"])
MAX_REPLAY_GAP_S = 0.6


class CustomAttack(BaseModel):
    task_id: str
    text: str = Field(min_length=1, max_length=MAX_CUSTOM_CHARS)


class RunRequest(BaseModel):
    scenario_id: str | None = None
    custom: CustomAttack | None = None


def get_runner(request: Request) -> PlaygroundRunner:
    runner: PlaygroundRunner = request.app.state.playground
    return runner


def client_ip(request: Request) -> str:
    if request.app.state.settings.playground_trust_forwarded:
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.get("/scenarios")
async def list_scenarios(
    runner: Annotated[PlaygroundRunner, Depends(get_runner)],
) -> dict[str, Any]:
    cfg = runner.config
    return {
        "presets": [{**sc.card(), "replays": replay_variants(sc.id)} for sc in presets().values()],
        "custom_tasks": [
            {"id": t.id, "title": t.title, "task": t.task, "kind": t.kind}
            for t in CUSTOM_TASKS.values()
        ],
        "custom_max_chars": MAX_CUSTOM_CHARS,
        "live": cfg.live_available,
        "model": {"provider": cfg.provider, "name": cfg.model_name} if cfg.live_available else None,
        "limits": {
            "max_steps": cfg.max_steps,
            "max_output_tokens": cfg.max_output_tokens,
            "runs_per_ip_per_hour": cfg.ip_per_hour,
        },
    }


@router.post("/run")
async def start_run(
    body: RunRequest,
    request: Request,
    runner: Annotated[PlaygroundRunner, Depends(get_runner)],
) -> dict[str, Any]:
    custom = body.custom.model_dump() if body.custom else None
    try:
        return await runner.start(body.scenario_id, custom, client_ip(request))
    except RateLimited as exc:
        raise HTTPException(
            status_code=429, detail=str(exc), headers={"Retry-After": "3600"}
        ) from exc
    except PlaygroundError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/runs/{run_id}")
async def get_run(
    run_id: str, runner: Annotated[PlaygroundRunner, Depends(get_runner)]
) -> dict[str, Any]:
    run = await runner.store.get(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Unknown or unfinished run")
    return run


@router.websocket("/runs/{run_id}/stream")
async def stream_run(ws: WebSocket, run_id: str) -> None:
    """Events of a run: stored runs and replays are paced like the original
    (`?pace=0` sends them at once); live runs stream as they happen."""
    await ws.accept()
    runner: PlaygroundRunner = ws.app.state.playground
    pace = ws.query_params.get("pace", "1") != "0"
    try:
        stored = await runner.store.get(run_id)
        if stored is not None:
            last = 0
            for ev in stored.get("events", []):
                if pace:
                    gap = (int(ev.get("t_ms", last)) - last) / 1000
                    await asyncio.sleep(min(max(gap, 0.05), MAX_REPLAY_GAP_S))
                    last = int(ev.get("t_ms", last))
                await ws.send_json(ev)
        else:
            async with asyncio.timeout(600):
                async for ev in runner.events.follow(run_id):
                    await ws.send_json(ev)
        await ws.close()
    except (WebSocketDisconnect, TimeoutError):
        pass
    except Exception as exc:  # never leave a socket hanging
        log.warning("playground.stream_failed", run_id=run_id, error=repr(exc))
        with contextlib.suppress(Exception):
            await ws.close(code=1011)
