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

## Detection pipeline latency (Phase 3)

Script: [`gateway/scripts/bench_detectors.py`](../gateway/scripts/bench_detectors.py). x86 numbers come from the manual [`bench-classifier`](../.github/workflows/bench-classifier.yml) workflow on a GitHub-hosted runner: Intel Xeon 6975P-C, 4 vCPU, AVX-512 VNNI. Inputs are built from the benign corpus (web pages, emails, API JSON, tickets).

Classifier numbers use **untrained probes** (`ml/scripts/latency_probe.py`): real architecture and int8 dynamic quantization, random weights. Latency does not depend on the weights; detection quality does, and is measured in Phase 4.

### Detectors without the classifier (x86, p50 / p95)

| Detector | 2 KB | 50 KB |
|---|---|---|
| heuristics (incl. normalization and decoding) | 1.36 / 1.39 ms | 35 / 36 ms |
| secrets | 0.23 / 0.24 ms | 6.8 / 6.9 ms |
| PII (Presidio, patterns mode) | 2.5 / 2.5 ms | 67 / 99 ms |
| **pipeline without classifier** | **4.8 / 5.3 ms** | **111 / 145 ms** |
| pipeline with classifier, injected input (early exit) | 5.3 / 5.6 ms | 109 / 113 ms |

The heuristics target (< 2 ms on 2 KB) is met.

PII on 50 KB dropped from about 1.35 s (stock Presidio: full spaCy pipeline, libphonenumber matcher, lemma context enhancer) to about 67 ms. See `pipeline/pii.py` for the three changes.

### Classifier alone, untrained int8 probes (p50 / p95)

| Model (int8 size) | Threads | x86 2 KB | x86 50 KB* | Apple M3 2 KB |
|---|---|---|---|---|
| DeBERTa-v3-base (243 MB) | 1 | 944 / 983 ms | 4.07 / 4.13 s | 1076 / 1184 ms |
| DeBERTa-v3-base | 2 | 592 / 620 ms | 2.49 / 2.61 s | 597 / 615 ms |
| DeBERTa-v3-small (172 MB) | 1 | 419 / 432 ms | 1.72 / 1.73 s | 575 / 753 ms |
| DeBERTa-v3-small | 2 | 275 / 278 ms | 1.11 / 1.12 s | 314 / 454 ms |
| DeBERTa-v3-small | 4 | 264 / 274 ms | 1.08 / 1.09 s | |
| DeBERTa-v3-xsmall (87 MB) | 2 | 251 / 255 ms | 1.04 / 1.04 s | |
| DeBERTa-v3-xsmall | 4 | 262 / 269 ms | 1.09 / 1.11 s | |
| MiniLM-L12-H384 (34 MB) | 2 | 76 / 78 ms | 422 / 429 ms | |
| **MiniLM-L6-H384 (23 MB)** | 2 | **39 / 40 ms** | 221 / 222 ms | |

\* 50 KB is about 35 windows. Since the window cap it classifies 8 (first 4 and last 4), plus at most 4 focus windows in the full pipeline. The base rows were measured before the focus cap, so they are 8-window numbers.

**Targets: classifier p95 < 50 ms on 2 KB and < 150 ms on 50 KB. Neither is met by any DeBERTa-v3 size. MiniLM-L6 (a BERT architecture whose attention ONNX Runtime fuses) meets the 2 KB target; nothing measured meets 150 ms on 50 KB with 8 windows (MiniLM-L6 would need 5 or fewer).** Detection quality of MiniLM against DeBERTa is unknown until Phase 4 trains them. A 2 KB input is about 550 tokens; DeBERTa-v3 costs about 0.5 ms per token on 2 x86 threads. Its disentangled relative-position attention dominates at this length: xsmall is barely faster than small despite a quarter of the matmul work, and 4 threads do not help over 2.

What changed in Phase 3 to bound the cost:
- **Early exit**: skip the classifier when heuristics already reach `classifier_threshold`.
- **Window cap**: at most 12 windows per input (first 4, last 4, and up to 4 around the strongest weak signals).
- **`TRIPWIRE_CLASSIFIER_THREADS`**: default 2.

The model decision is in [ml/README.md](../ml/README.md#decision).

### Trained MiniLM-L6 (Phase 4, release `classifier-minilm-l6-v1`)

GitHub-hosted runners are not all the same CPU. Phase 4 runs landed on AMD EPYC 9V74 (Zen 4, AVX-512 VNNI) and AMD EPYC 7763 (Zen 3, AVX2 only), not the Phase 3 Xeon 6975P-C, so artifact and probes were measured in the same job for a fair comparison. 2 threads, p50 / p95:

| CPU | Model | 2 KB | 50 KB (8 windows) | Full pipeline, 2 KB / 50 KB |
|---|---|---|---|---|
| EPYC 9V74 | **MiniLM-L6, trained** | 58–60 / 60–63 ms | 327–334 / 360–370 ms | 66 / 69 ms; 618 / 632 ms |
| EPYC 9V74 | MiniLM-L6, untrained probe | 58 / 61–62 ms | 316–329 / 332–334 ms | |
| EPYC 9V74 | DeBERTa-v3-small, untrained probe | 357–372 / 377–414 ms | 1.49–1.52 / 1.51–1.54 s | |
| EPYC 7763 (AVX2) | MiniLM-L6, trained | 93 / 100 ms | 514 / 518 ms | 101 / 103 ms; 945 / 980 ms |
| Xeon 6975P-C (Phase 3) | MiniLM-L6, untrained probe | 39 / 40 ms | 221 / 222 ms | |

The trained model runs at the same speed as its probe, as expected. The 2 KB target (< 50 ms p95) is met on the Xeon and missed on both EPYCs (63 ms and 100 ms); the 50 KB target (< 150 ms) is missed everywhere. MiniLM-L6 is about 6x faster than DeBERTa-v3-small on the same CPU. The full-pipeline 50 KB figure includes up to 4 focus windows (12 in total) and PII.

### `/v1/check/result` end to end, per detection setting (Phase 4 review)

Measured by the manual [`bench-api`](../.github/workflows/bench-api.yml) workflow ([run](https://github.com/yugpatill/tripwire-agent-gateway/actions/runs/45936464133)): one uvicorn worker, Postgres and Redis as services, the published MiniLM-L6 classifier with 2 threads, script [`gateway/scripts/bench_check_result.py`](../gateway/scripts/bench_check_result.py). Requests are sequential; each uses a fresh session. Runner: AMD EPYC 7763, 4 vCPU, AVX2 only (the slowest CPU seen in the GitHub pool). The server column is the gateway's own `decision.latency_ms` (detection, tagging, Redis, Postgres write); the round trip adds HTTP on loopback.

Server-side p50 / p95:

| Workload | `corroborated` (default) | `either` | `corroborated` + `classifier_shadow` |
|---|---|---|---|
| Phase 3 corpus mix (383 results: 250 benign, 133 attacks) | **4.6 / 8.5 ms** (classifier ran on 6%) | 7.1 / 27.3 ms (72%) | 4.7 / 9.6 ms |
| 2 KB, no heuristic signal | **10.9 / 11.8 ms** (not classified) | 104 / 115 ms | 16.2 / 20.5 ms |
| 2 KB, one weak signal | 102 / 114 ms | 99 / 110 ms | 186 / 212 ms |
| 50 KB, no heuristic signal | **139 / 228 ms** (not classified) | 637 / 727 ms | 179 / 280 ms |
| 50 KB, one weak signal (in the middle) | **366 / 471 ms** (3–4 windows) | 707 / 1115 ms | 727 / 1109 ms |
| 50 KB, realistic mix (several weak signals) | 695 / 868 ms (up to 8 windows) | 924 / 1009 ms | 1125 / 1284 ms |

- **The corroborated rule takes the classifier off the hot path.** On the Phase 3 mix it ran on 6% of results (the ones with a weak signal), and p95 dropped from 27 ms to 8.5 ms, inside the 30 ms budget for the pipeline without classifier. A 2 KB output with no signal costs 11 ms instead of 104 ms, and 50 KB 139 ms instead of 637 ms.
- **A weak signal still costs a classifier pass.** 2 KB with one weak signal is the same in both modes (both windows are classified). At 50 KB, signal-only windows (3–4) halve the cost against `either`, which classifies 8–12.
- **Without the classifier, 50 KB is dominated by PII and heuristics** (about 95 ms and 54 ms p50 on this CPU).
- **The shadow classifier is not free on a small box.** It runs off the request path, but on 4 vCPUs it competes with live requests for CPU: under this back-to-back load it raised p50 by 2% (Phase 3 mix) to 99% (50 KB with a weak signal) and dropped 113 of 648 shadow runs (at most 4 in flight). Enable it on hosts with spare cores or moderate traffic.
- Absolute numbers are from the AVX2 runner; on AVX-512 VNNI runners the classifier is about 1.6x faster (see the trained MiniLM-L6 table above).

### Apple M3 note

PyTorch on macOS uses Accelerate (the AMX coprocessor) and ran DeBERTa-v3-base fp32 at 426 ms per 512 tokens. ONNX Runtime cannot use AMX and took 1,200 ms in fp32 and 573 ms in int8. Linux servers have no AMX, so the x86 runner numbers are the ones to plan with.
