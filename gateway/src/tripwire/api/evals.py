"""Evaluation results for the console (GET /v1/evals).

Real numbers come from the `eval_runs` table, which Phase 9's CLI fills from
`evals/results`. Until a run is imported this returns clearly marked placeholder
data (`placeholder: true`), so the page can be built and reviewed; the web app
labels every placeholder number as such.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select

from tripwire.api.console import Factory
from tripwire.auth.console import ConsoleUser, console_reader
from tripwire.db import models as db

router = APIRouter(prefix="/v1", tags=["evals"])

SUITES = ("workspace", "travel", "banking", "slack")
CONFIGS = ("A", "B", "C", "D", "E", "F")


class EvalRunView(BaseModel):
    suite: str
    config: str
    model: str
    metrics: dict[str, Any]
    source_file: str | None
    created_at: datetime | None


class EvalResults(BaseModel):
    placeholder: bool
    note: str
    runs: list[EvalRunView]


def placeholder_runs() -> list[EvalRunView]:
    """Obviously synthetic numbers (round steps), never presented as results."""
    runs = []
    for c_i, config in enumerate(CONFIGS):
        for s_i, suite in enumerate(SUITES):
            asr = round(max(0.0, 0.5 - 0.1 * c_i - 0.01 * s_i), 2)
            utility = round(0.8 - 0.02 * c_i - 0.05 * s_i, 2)
            runs.append(
                EvalRunView(
                    suite=suite,
                    config=config,
                    model="placeholder",
                    metrics={
                        "asr": asr,
                        "utility": utility,
                        "utility_under_attack": round(utility - 0.1, 2),
                        "tasks": 0,
                    },
                    source_file=None,
                    created_at=None,
                )
            )
    return runs


@router.get("/evals", response_model=EvalResults)
async def list_evals(_: Annotated[ConsoleUser, Depends(console_reader)], f: Factory) -> EvalResults:
    async with f() as s:
        rows = list(
            (await s.scalars(select(db.EvalRun).order_by(db.EvalRun.created_at.desc()))).all()
        )
    if not rows:
        return EvalResults(
            placeholder=True,
            note="No evaluation has been imported yet (Phase 9). These numbers are placeholders.",
            runs=placeholder_runs(),
        )
    latest: dict[tuple[str, str], db.EvalRun] = {}
    for r in rows:  # newest first: keep the latest run per suite and config
        latest.setdefault((r.suite, r.config), r)
    return EvalResults(
        placeholder=False,
        note="",
        runs=[
            EvalRunView(
                suite=r.suite,
                config=r.config,
                model=r.model,
                metrics=r.metrics or {},
                source_file=r.source_file,
                created_at=r.created_at,
            )
            for r in sorted(latest.values(), key=lambda r: (r.config, r.suite))
        ],
    )
