# Tripwire design

Tripwire is an open source security gateway for LLM agents, plus a public attack playground and an operator console.

Author: Yugandhar Patil. License: MIT.

---

## 1. What the system does

Tripwire sits between an AI agent and its tools (MCP servers or SDK tool functions). For every tool definition, tool call and tool result it:

1. Scans MCP tool descriptions for tool poisoning, pins them by hash (rug pull detection), and detects tool shadowing.
2. Runs injection detection on tool outputs: heuristics, then a fine-tuned MiniLM-L6 classifier (int8 ONNX), then an optional LLM judge for the gray zone.
3. Tracks data provenance (taint). Every value is labelled with source, trust and confidentiality. Labels propagate to tool call arguments via value matching, context taint and instruction-origin checks.
4. Evaluates YAML policies against the call and its labels: `allow`, `block`, `redact`, `require_approval`, `log_only`.
5. Redacts secrets and PII.
6. Logs every decision to Postgres, streams it to the dashboard over WebSocket, and emits OpenTelemetry traces and Prometheus metrics.

The web app has a public **Playground** (the same agent run unprotected and protected, side by side, live) and a login-protected **Operator Console** (events, trace graph, approvals, tools, policy editor, evaluations).

## 2. Threat model

**Assets.** The user's confidential data reachable through tools (inbox, files, bank, internal APIs), the integrity of actions the agent takes on the user's behalf (sending email, moving money, writing files), and the agent's tool inventory.

**Trust boundary.** The user's prompt and tools the operator marks `trusted` are inside the boundary. Everything a tool returns from the outside world (web pages, inbound email, documents, third-party MCP servers) is outside it.

**Attacker capabilities considered.**

| Attack | Vector | Primary control |
|---|---|---|
| Indirect prompt injection | Instructions hidden in tool output (web page, email, RAG document) | Detection pipeline marks content `suspicious`; taint labels stop injected values reaching sinks |
| Data exfiltration | Agent tricked into sending confidential data to an attacker-controlled recipient, URL or account | Taint propagation + policy rules on sinks (`label_any`, `context_confidentiality_at_least`, `unless.arg_domain_in`) |
| Tool poisoning | Malicious instructions in an MCP tool's description | Manifest scanner, quarantine |
| Rug pull | A tool's description changes after it was approved | SHA-256 pinning, diff, re-approval |
| Tool shadowing | A tool named like, or referring to, another server's tool | Name similarity and cross-server reference detection |
| Abuse of high-risk actions | Repeated transfers, mass email | Rate limits (`limit`), `require_approval` |

**Out of scope.** Model-level jailbreaks that do not involve tools, compromised trusted tools, paraphrased exfiltration of data that has no detectable link to its source (mitigated only by context rules), and attacks on the gateway host itself. See [limitations.md](limitations.md).

**Failure posture.** Fail closed: any exception inside the decision pipeline results in `block`, never `allow`.

## 3. Engineering principles

1. **Dependency isolation.** Three separate Python projects (`gateway`, `ml`, `evals`) with three separate `uv` lockfiles. They never import each other. They communicate only over HTTP or through files (the ONNX model artifact). AgentDojo, PyTorch and the gateway each get their own resolver, which prevents version conflicts.
2. **Pinned majors.** Major versions in the compatibility matrix change only deliberately, never as a workaround for a resolution failure.
3. **Verify after every dependency change.** `uv lock && uv sync && uv run pytest -q` for Python; `pnpm install && pnpm typecheck && pnpm build` for the web app.
4. **MCP Python SDK v2.** v2 is a breaking rework of v1; v1-style code is not used and the two are never mixed.
5. **Secrets.** `.env` is never committed; `.env.example` documents every variable. API keys come from the environment.
6. **Fail closed** (see threat model).
7. **Typed everywhere.** `mypy --strict` on `gateway/src`; TypeScript `strict: true`.
8. **Latency budgets.** The decision pipeline must stay under 30 ms p95 without the classifier and under 80 ms p95 with it, on CPU, measured by the load test. See [performance.md](performance.md).

## 4. Compatibility matrix

### 4.1 Runtimes

| Runtime | Version | Why |
|---|---|---|
| Python | **3.12.x** (all three Python projects) | Supported by PyTorch, spaCy 3.8, Presidio, onnxruntime, AgentDojo. 3.13/3.14 avoided: some ML wheels lag. |
| Node.js | **22 LTS** | Required by Next.js 16 (Node 20.9+), safest LTS. |
| pnpm | **10.x** | Pinned through `packageManager` in `web/package.json`; CI reads the same field. |
| uv | latest | Python package and project manager. |
| Postgres | **16** | `postgres:16-alpine`. |
| Redis | **7.4** | `redis:7.4-alpine`. |
| Docker Compose | v2 | Local stack. |

Each Python project pins `.python-version` = `3.12` and `requires-python = ">=3.12,<3.13"`.

### 4.2 `gateway/` (runtime service, no PyTorch)

| Package | Constraint | Notes |
|---|---|---|
| fastapi | `>=0.115,<1` | |
| uvicorn[standard] | `>=0.32,<1` | |
| pydantic | `>=2.9,<3` | Pydantic v2 only. |
| pydantic-settings | `>=2.6,<3` | |
| mcp | `>=2.3,<3` | v2 SDK. |
| httpx | `>=0.27,<1` | |
| sqlalchemy[asyncio] | `>=2.0.36,<2.1` | SQLAlchemy 2 style only. |
| asyncpg | `>=0.30,<1` | |
| alembic | `>=1.14,<2` | |
| redis | `>=5.2,<7` | `redis.asyncio`. |
| pyyaml | `>=6.0.2,<7` | |
| onnxruntime | `>=1.20,<2` | CPU inference only. |
| tokenizers | `>=0.20,<1` | Loads the exported tokenizer.json. No `transformers` or `torch` in the gateway. |
| numpy | `>=1.26,<3` | |
| presidio-analyzer, presidio-anonymizer | `>=2.2.355,<3` | spaCy model `en_core_web_sm` (not `lg`) to keep the image small. |
| spacy | `>=3.8,<3.9` | `en_core_web_sm` installed in the Dockerfile. |
| rapidfuzz | `>=3.10,<4` | Shadowing name similarity. |
| anthropic | `>=0.40` | Provider SDK for the demo agent and optional LLM judge. |
| openai | `>=1.55` | Alternative provider for the demo agent. |
| structlog | `>=24.4` | |
| prometheus-client | `>=0.21,<1` | |
| opentelemetry-sdk, -exporter-otlp, -instrumentation-fastapi | same release, `>=1.28` / matching `0.49b` | Added in one resolve so they share a release. |
| slowapi | `>=0.1.9` | Rate limiting. |
| pyjwt | `>=2.10,<3` | Console auth. |
| argon2-cffi | latest | Password and API key hashing. |

Dev: `pytest`, `pytest-asyncio`, `pytest-cov`, `mypy`, `ruff`, `locust`, `testcontainers[postgres,redis]`.

The SDK adapter package (`tripwire-guard`, in `gateway/sdk/`) keeps heavy frameworks in optional extras: `[langgraph]` adds `langgraph>=0.2`, `[openai-agents]` adds `openai-agents`.

### 4.3 `ml/` (training only, never deployed)

| Package | Constraint |
|---|---|
| torch | `>=2.5,<3` (CPU wheel locally; CUDA wheel on Colab/Kaggle) |
| transformers | `>=4.46,<5` |
| datasets | `>=3.1` |
| accelerate | `>=1.1` |
| scikit-learn | `>=1.5` |
| optimum[onnxruntime] | latest compatible with the transformers pin |
| onnx | `>=1.17` |
| evaluate, pandas, matplotlib | latest |

Default classifier (decided in milestone 4, full table in [ml/README.md](../ml/README.md#results-phase-4-2026-11-26)): **`sentence-transformers/all-MiniLM-L6-v2` fine-tuned**, int8 ONNX 23 MB, release `classifier-minilm-l6-v1`. **Experimental**, not published: **`microsoft/deberta-v3-small`** fine-tuned (172 MB), intended as an opt-in "accurate" mode (selected with `TRIPWIRE_CLASSIFIER_DIR` or the image build args `CLASSIFIER_URL`/`CLASSIFIER_SHA256`) once its int8 export is fixed; today dynamic int8 quantization changes its probabilities by up to 0.98. DeBERTa-v3-base was dropped in Phase 3 (620 ms p95 on 2 KB).

| int8 artifact | Size | test F1 | test_ood recall (held-out role markers) | test FPR | Phase 3 corpus FPR / recall | x86 p95, 2 threads, 2 KB / 50 KB (EPYC 9V74) |
|---|---|---|---|---|---|---|
| MiniLM-L6 (default) | 23 MB | 0.981 | 0.994 | 0.1% | 6.8% / 73.7% | 60–63 ms / 360–370 ms |
| DeBERTa-v3-small (experimental) | 172 MB | 0.981 | 0.987 | 1.07% | 11.6% / 85.7% | 377–414 ms / 1.51–1.54 s (probe) |
| Prompt Guard 2 22M (zero-shot) | not evaluated (gated access not granted) | | | | | 255 ms / 1.04 s (xsmall probe, Phase 3 Xeon) |

Decision rule, set before training: MiniLM-L6 is the default if its test_ood recall is within 5 points of DeBERTa-v3-small at the same FPR. It is 0.7 points *higher*, at a lower FPR, so MiniLM-L6 is the default. Known gaps: human-written injections (deepset recall 43% vs 77%), a 6.8% false-positive rate on realistic tool outputs (raw HTML, terse JSON fields, imperative docs), and DeBERTa's int8 accuracy loss. The classifier score is calibrated so the artifact's threshold maps to 0.5, the default `suspicious_threshold`. Since Phase 4 the gateway combines detectors with the **corroborated** rule by default (`detection.combine`): a classifier hit counts only alongside a heuristic signal, and the classifier runs only on weak-signal results (see [detection.md](detection.md)).

Output contract: `ml/artifacts/injection-<model>/` containing `model.int8.onnx`, `tokenizer.json`, `config.json` (with `max_length`, `threshold`, `labels`) and `metrics.json`. The gateway reads only this folder (path from `TRIPWIRE_CLASSIFIER_DIR`, default `/app/models/injection-classifier`). The default model's folder is published as a GitHub Release asset, and the Docker build downloads it and verifies its SHA-256.

### 4.4 `evals/` (benchmarks, never deployed)

| Package | Constraint | Notes |
|---|---|---|
| agentdojo | latest, exact version pinned in `uv.lock` | Has its own provider/pydantic pins, so it lives alone. |
| httpx | whatever agentdojo allows | Talks to the gateway at `TRIPWIRE_URL`. |
| pyyaml, pandas, matplotlib, tabulate | latest | Custom MCP suite and result tables. |

Evals never import `gateway`; they call `POST /v1/check/call` and `POST /v1/check/result` over HTTP.

### 4.5 `web/` (Next.js app)

| Package | Constraint | Notes |
|---|---|---|
| next | `^16` (latest 16.x patch) | App Router, Turbopack. |
| react, react-dom | `^19.2` | Matched to Next 16. |
| typescript | `^5.6` | |
| tailwindcss + @tailwindcss/turbopack | `^4` | No `tailwind.config.js`; v4 CSS config. Uses the `@tailwindcss/turbopack` loader configured in `next.config.ts`, as generated by the Next 16.4 starter. |
| shadcn (CLI) | latest | Components copied into `components/ui`. |
| @xyflow/react | `^12` | React Flow (not the old `reactflow` package). |
| recharts | `^3` | React 19 compatible (not Recharts 2). |
| @monaco-editor/react + monaco-yaml | `^4.7` / latest | Policy editor, client side only. |
| @tanstack/react-query | `^5` | Server state. |
| zod | `^3.23` or `^4` | Matches what the shadcn form uses. |
| lucide-react, next-themes, sonner | latest | Icons, dark mode default, toasts. |
| openapi-typescript + openapi-fetch | latest | Typed API client generated from the gateway's OpenAPI JSON. |
| motion | `^11` or later | Block animation in the playground. |

React 19 peer-dependency warnings are resolved explicitly, never with `--force` or `--legacy-peer-deps`.

### 4.6 Third-party models and data (classifier, milestone 4)

| Item | License | How it is used |
|---|---|---|
| `nreimers/MiniLM-L6-H384-uncased` | MIT | Candidate base for the default classifier (fine-tuned; weights published) |
| `sentence-transformers/all-MiniLM-L6-v2` | Apache-2.0 | Candidate base for the default classifier (fine-tuned; weights published) |
| `microsoft/deberta-v3-small` | MIT | Base for the experimental accurate classifier (fine-tuned; not published until its int8 export is fixed) |
| `meta-llama/Llama-Prompt-Guard-2-22M` | **Llama 4 Community License** (gated on Hugging Face) | Zero-shot baseline, **evaluation only** (not yet run: access must be granted to the account that runs the notebook). Weights and converted ONNX copies are never committed, published or shipped in the image, which keeps the license's redistribution duties (copy of the agreement, "Built with Llama" notice, NOTICE file, "Llama" prefix for derived model names) from applying. Only our metrics are published. Use remains subject to Meta's Acceptable Use Policy. |
| `deepset/prompt-injections` | Apache-2.0 | Training and evaluation data |
| `databricks/databricks-dolly-15k` | CC BY-SA 3.0 | Benign carriers and imperative hard negatives |
| `rajpurkar/squad_v2` | CC BY-SA 4.0 | Wikipedia paragraphs as benign web-page carriers |

## 5. Repository layout

```
README.md  LICENSE  .env.example  docker-compose.yml  Makefile
.github/workflows/   gateway.yml (ruff, mypy, pytest, image budget)  web.yml (typecheck, lint, build)
gateway/
  pyproject.toml  uv.lock  .python-version  Dockerfile
  alembic/  policies/{default,demo}.yaml  scripts/
  src/tripwire/
    main.py  config.py  cli.py  models.py
    api/          routers: sessions, check, approvals, policies, tools, metrics, evals, playground, stream, mcp
    auth/         agent API keys
    proxy/        MCP gateway (server facing the agent, clients to upstreams), upstream registry
    pipeline/     engine (stages, timing, fail closed), normalize, heuristics, classifier, llm_judge, secrets, pii, manifest
    taint/        labels, store (Redis), propagate, entities
    policy/       schema, loader, compiler, evaluate, replay, cli
    approvals/  db/  telemetry/
    playground/   agent, scenarios/, environment, mock_servers/, runner
  sdk/            tripwire-guard (client, wrap, adapters for a raw tool-use loop, LangGraph, OpenAI Agents)
  tests/          unit/  integration/  fixtures/
ml/      scripts/{build_dataset,train,evaluate,export_onnx}.py  notebooks/  artifacts/
evals/   agentdojo_tripwire/{element,run}.py  mcp_suite/  adaptive/  load/  results/
web/     app/(public)  app/(console)/console/*  app/login  components/  lib/api/
docs/    design, architecture, threat model, policy reference, onboarding guide, deployment, performance, limitations
deploy/helm/tripwire/
```

## 6. Core contracts

### 6.1 Models (`models.py`, `taint/labels.py`)

```python
Trust = Literal["trusted", "untrusted", "suspicious", "untrusted_origin"]
Confidentiality = Literal["public", "internal", "confidential", "secret"]
Action = Literal["allow", "block", "redact", "require_approval", "log_only"]

class Provenance(BaseModel):
    source: str               # "user" | "system" | "<server>__<tool>"
    trust: Trust
    confidentiality: Confidentiality
    event_id: UUID

class ToolCall(BaseModel):
    session_id: UUID
    tool: str                 # namespaced "<server>__<tool>"
    args: dict[str, Any]

class ToolResult(BaseModel):
    session_id: UUID
    tool: str
    call_event_id: UUID
    content: str | dict[str, Any] | list[Any]

class DetectorResult(BaseModel):
    detector: Literal["heuristic","classifier","llm_judge","secrets","pii","manifest"]
    score: float              # 0..1
    spans: list[tuple[int, int]]
    reason: str

class Decision(BaseModel):
    event_id: UUID
    action: Action
    rule_id: str | None
    message: str
    arg_labels: dict[str, list[Provenance]]
    detectors: list[DetectorResult]
    redacted_args: dict[str, Any] | None
    latency_ms: float
    approval_id: UUID | None
```

Orderings: trust `trusted < untrusted < untrusted_origin < suspicious`; confidentiality `public < internal < confidential < secret`.

### 6.2 HTTP API (all under `/v1`; OpenAPI exported to `web/lib/api/`)

| Method | Path | Request | Response |
|---|---|---|---|
| POST | /sessions | `{agent_name, user_prompt, mode: "enforce"\|"shadow"}` | `{session_id}` (stores prompt entities for instruction origin) |
| POST | /sessions/{id}/prompts | `{text}` | `{added}`: adds a user turn (multi-turn agents, SDK) |
| POST | /check/call | `ToolCall` | `Decision` |
| POST | /check/result | `ToolResult` | `{content_redacted, labels, detectors, decision}` |
| POST | /mcp | MCP Streamable HTTP (agent key) | MCP protocol (proxy mode); see [mcp.md](mcp.md) |
| GET | /sessions | filters | paginated list |
| GET | /sessions/{id}/trace | | ordered events with labels and data-flow edges `[{from_event, to_event, arg, matched_value, label}]` |
| GET | /approvals | `?status=pending` (operator key) | list (kinds `call`, `tool_quarantine`, `tool_change`) |
| GET | /approvals/{id} | operator key, or the agent key that owns the session | approval |
| POST | /approvals/{id} | `{decision: "approve"\|"deny", scope: "once"\|"session"}` (operator key) | updated approval; 409 if already decided or expired |
| GET | /policies/active | | `{version, yaml}` |
| PUT | /policies/active | `{yaml}` | validated new version, or 422 with line/column errors |
| POST | /policies/test | `{yaml, since_hours}` | `[{event_id, old_action, new_action, rule_id}]` |
| GET | /tools | (operator key) | tools with pin status, risk score, findings, pending change |
| POST | /tools/{name}/approve | (operator key) | re-pin the latest manifest after review |
| GET | /metrics/summary | | counts by action, top rules, latency percentiles |
| GET | /evals | | eval runs imported from `evals/results` |
| POST | /playground/run | `{scenario_id}` or `{custom: {...}}` | `{run_id, unprotected_session_id, protected_session_id}` |
| GET | /playground/runs/{run_id} | | stored run for replay |
| WS | /stream | operator key in `Authorization` (Phase 5); session and console channels with browser auth come with the web app | JSON events `{type, approval}` (`approval.created`, `approval.decided`) |
| GET | /healthz, /readyz, /metrics (Prometheus) | | |

**Auth.** Agents send `Authorization: Bearer tw_<prefix>_<secret>`; keys are argon2id-hashed in `api_keys`, created with `tripwire keys create --name <agent> [--role operator]`, and a session is bound to the key that created it. Keys have a role: `agent` keys use sessions, checks and `/mcp`; `operator` keys can also decide approvals and review tools, so an agent can never approve its own held calls. Keys also have an MCP session scope (`key` | `connection` | `header`, [mcp.md](mcp.md#sessions)); `TRIPWIRE_ENV=production` makes `header` the default and refuses `key` unless forced. The console uses a JWT in an httpOnly cookie. Playground endpoints are public but rate limited (5 runs per IP per hour, 200 per day globally) and capped to a cheap model.

### 6.3 Policy YAML schema

```yaml
version: 1
defaults:
  unknown_tool: require_approval     # allow | block | require_approval
  on_engine_error: block             # block | require_approval (never allow)
  classifier_threshold: 0.85
  suspicious_threshold: 0.5
  instruction_origin: strict         # strict | off: sessions with no known user prompt (MCP)
  no_prompt_action: require_approval # require_approval | block: a block caused only by that
detection:
  combine: corroborated              # corroborated | either (see docs/detection.md)
  classifier_shadow: false           # true: classify every result in the background, log only
tools:
  <server>__<tool>:                  # exact name or glob
    trust: trusted | untrusted
    confidentiality: public | internal | confidential | secret
    confidentiality_by_path: { "<glob>": <level> }    # optional, applies to a `path` arg
    sink: true | false
    risk: low | medium | high
rules:
  - id: <slug>
    when:                     # all present keys must match
      tool: <name or glob>
      sink: true
      risk: high
      arg: <arg name>
      label_any: [<trust values>]
      context_confidentiality_at_least: <level>
      session_has: suspicious
    unless:
      arg_domain_in: ["@company.com", "api.company.com"]
    limit: { max_calls: <int>, per: session }
    action: <Action>
    message: "<human readable reason shown in UI>"
```

Rules evaluate in file order; the first `block` wins, then `require_approval`, then `redact`, else `allow`. In shadow mode the computed action is stored but `log_only` is enforced. Test coverage per condition: [policy-test-coverage.md](policy-test-coverage.md).

## 7. Milestones

| # | Milestone | Exit criteria |
|---|---|---|
| 1 | Skeleton and infra: repo layout, compose stack, CI, FastAPI app factory, schema migration, Next.js shell | `docker compose up` starts everything; `/healthz` ok; CI green |
| 2 | Policy engine and taint tracking | Untrusted recipient from a fetched page is blocked by `no-untrusted-recipient`; the user's own recipient is allowed; 40+ unit tests |
| 3 | Detection pipeline: normalization, heuristics, secrets, Presidio PII, ONNX classifier wrapper, gated LLM judge | Detector unit tests; heuristics < 2 ms and classifier < 50 ms p95 on a 2 KB input; classifier < 150 ms p95 on 50 KB; runtime image < 700 MB with the classifier |
| 4 | Classifier training (`ml/`): dataset with held-out attack family, MiniLM-L6 and DeBERTa-v3-small fine-tunes (Prompt Guard 2 22M zero-shot as a reference), threshold at 1% FPR, int8 ONNX export | Artifact folder loads in the gateway; `metrics.json` published; accuracy vs latency reported per model; default published as a release asset and baked into the image |
| 5 | MCP proxy (SDK v2), manifest security, approvals | Namespaced tools; poisoned tool quarantined; rug pull blocked; approval granted via API completes the held call; denied or timed-out approval is an error to the client (integration tests with the SDK client, manual check with the MCP Inspector: [mcp.md](mcp.md)) |
| 6 | `tripwire-guard` SDK adapters ([gateway/sdk](../gateway/sdk/README.md)): Anthropic tool use (Tool Runner and manual loop), LangGraph (ToolNode interceptors), OpenAI Agents SDK (function tools, handoffs), each an optional extra | Examples run end to end against a local gateway; per adapter, an injected tool result leads to a blocked tool call (CI: `sdk` workflow against a real gateway) |
| 7 | Playground backend: 6 preset scenarios, dual run, custom attacks, cost controls. **Each run uses its own Tripwire session** (`POST /v1/sessions` with the scenario's user prompt, then `X-Tripwire-Session` on every MCP request or the session id on every check), so taint and user-prompt entities never cross between runs or visitors | Every preset succeeds unprotected and is stopped protected, verified automatically |
| 8 | Web app: playground, console (overview, events, traces, approvals, tools, policy editor, evals), auth | `pnpm build` passes; Lighthouse ≥ 90 on `/` |
| 9 | Evaluations: AgentDojo defense element, MCP suite, adaptive attacker, load test | Results table with real numbers, README updated from it |
| 10 | Observability, production images, Helm, deployment, docs | Fresh clone to running stack in under 10 minutes from the README |

## 8. Environment variables

See [`.env.example`](../.env.example). Gateway: `DATABASE_URL`, `REDIS_URL`, `TRIPWIRE_POLICY_PATH`, `TRIPWIRE_CLASSIFIER_DIR`, `TRIPWIRE_ENV`, `TRIPWIRE_MCP_UPSTREAMS`, `TRIPWIRE_APPROVAL_TIMEOUT_S`, `TRIPWIRE_MCP_ALLOWED_HOSTS`, `TRIPWIRE_MCP_ALLOWED_ORIGINS`, `TRIPWIRE_LLM_JUDGE_ENABLED`, `TRIPWIRE_MODE`, `JWT_SECRET`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `DEMO_READONLY_PASSWORD`, `CORS_ORIGINS`, `PLAYGROUND_PROVIDER`, `PLAYGROUND_MODEL`, `PLAYGROUND_DAILY_RUN_CAP`, provider API keys, `OTEL_EXPORTER_OTLP_ENDPOINT`. Web: `NEXT_PUBLIC_API_URL`, `NEXT_PUBLIC_WS_URL`. Evals: `TRIPWIRE_URL`, `TRIPWIRE_API_KEY`.

## 9. Integration pitfalls

1. **MCP SDK v1 vs v2.** `pip install mcp` installs v2; v1-era `FastMCP` examples may not apply.
2. **AgentDojo pins** stay in `evals/` only.
3. **No PyTorch in the gateway image.** Inference uses `onnxruntime` + `tokenizers` only, keeping the image small and free of CUDA wheels.
4. **Presidio + spaCy.** Configure the NLP engine with `en_core_web_sm` explicitly, or Presidio downloads `en_core_web_lg` at runtime.
5. **OpenTelemetry** core and instrumentation packages are versioned in lockstep; add them together.
6. **Recharts 2 / `reactflow`** are not used; `recharts@^3` and `@xyflow/react@^12` are.
7. **Monaco in Next.js** loads client side only (`dynamic(..., { ssr: false })`).
8. **Tailwind v4** has no `tailwind.config.js`; the theme lives in `globals.css`.
9. **WebSockets on Vercel.** The web app only connects to the gateway's socket; the socket server is never hosted on Vercel.
10. **Async everywhere in the gateway.** No sync DB or Redis calls in request handlers.

## 10. Definition of done

1. All milestone exit criteria pass.
2. The live playground works for all 6 presets and custom attacks.
3. The README results table has real AgentDojo, MCP suite, adaptive and latency numbers.
4. Classifier `metrics.json` is published.
5. A 3-minute demo video script exists in `docs/demo-script.md`.
6. [limitations.md](limitations.md) honestly lists what Tripwire cannot stop (paraphrased exfiltration, attacks within trusted tools, model-level jailbreaks).
