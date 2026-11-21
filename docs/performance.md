# Performance

Budgets ([design.md](design.md) section 3): decision pipeline **< 30 ms p95** without the classifier, **< 80 ms p95** with it, on CPU.

## Scaling benchmark: `/v1/check/call` with a heavy session

Script: [`gateway/scripts/bench_scaling.py`](../gateway/scripts/bench_scaling.py)

```bash
docker compose up -d
cd gateway && uv run python scripts/bench_scaling.py --url http://localhost:8000
```

Setup: one session holding **20 prior tool results of 50 KB each** (about 1 MB of prose with emails, URLs and long numbers mixed in, so about 11k entities), then 300 timed `email__send_email` calls with **5 string args** (to, cc, subject, a 120-word body, footer). Half the calls use a recipient taken from the untrusted results (blocked), half the user's own address (allowed). 20 warm-up calls are excluded.

Environment: Apple M3, Docker Desktop (8 vCPU, 4 GB), gateway in the dev container (uvicorn `--reload`, single worker), Postgres 16 and Redis 7.4 in compose. "engine" is the server-side `latency_ms` returned in the decision. "http" is the client round trip.

### Results (2026-11-21)

| Version | engine p50 | engine p95 | http p50 | http p95 |
|---|---|---|---|---|
| Phase 2 baseline | 4.14 ms | **18.69 ms** | 5.74 ms | 20.45 ms |
| + per-session value index cache | 2.11 to 2.22 ms | **2.85 to 3.74 ms** | 3.5 ms | 4.9 to 6.0 ms |

Both are under the 30 ms budget. The baseline was under budget too, but the tail was wide, so it was worth fixing before Phase 3 adds detector stages.

Per-stage breakdown after the change (p50 / p95, from `events.stage_timings`):

| Stage | p50 | p95 |
|---|---|---|
| load_session | 0.11 ms | 0.19 ms |
| propagate | 1.23 ms | 1.37 ms |
| evaluate | 0.01 ms | 0.02 ms |
| persist (Redis call record) | 0.10 ms | 0.25 ms |

The Postgres event insert happens after `persist` and is included in `latency_ms`, but not broken out as its own stage.

### What changed

Profiling showed the baseline spent each call on two things:

1. Re-reading and JSON-parsing about 1 MB of tagged values from Redis (`load_session` was 1.4 / 2.3 ms).
2. Rebuilding the entity-to-values index (about 224k dict operations per call). This, plus allocator churn, made the tail wide (`propagate` was 1.7 / 15.4 ms).

Session values are append-only, so the engine now keeps an in-process LRU (2048 sessions) of a `ValueIndex` per session. On each call it asks Redis only for the list length and fetches just the new entries (`LRANGE start -1`). Redis remains the source of truth, so multiple workers stay correct. Each worker's cache simply catches up.

Not needed yet: substring matching (`_text_match`) is about 1.2 ms per call for 5 args over 1 MB, which is linear in session size. If sessions grow far beyond this (for example 100 results of 500 KB), the next step is an n-gram prefilter or an Aho-Corasick automaton over arg needles.
