# Tripwire

Open source security gateway for LLM agents: stops prompt injection, tool poisoning and data exfiltration between an agent and its tools.

> **Status: work in progress.** Phase 1 of 10 (skeleton and infrastructure) is complete; nothing here is production ready yet.

## Quickstart

```bash
cp .env.example .env
docker compose up --build
curl localhost:8000/healthz   # {"status":"ok"}
docker compose exec gateway tripwire keys create --name my-agent   # prints a tw_... key once
open http://localhost:3000
```

## Layout

| Path | What |
|---|---|
| `gateway/` | FastAPI gateway (Python 3.12, uv) |
| `web/` | Next.js 16 playground + operator console |
| `ml/` | Injection classifier training (separate env) |
| `evals/` | AgentDojo + MCP benchmarks (separate env) |

License: MIT.
