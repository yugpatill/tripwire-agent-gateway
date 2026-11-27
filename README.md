# Tripwire

Open source security gateway for LLM agents: stops prompt injection, tool poisoning and data exfiltration between an agent and its tools.

> **Status: work in progress.** Phases 1–5 of 10 are complete (infrastructure, policy engine and taint tracking, detection pipeline, injection classifier, MCP proxy with approvals). Nothing here is production ready yet.

## Quickstart

```bash
cp .env.example .env
docker compose up --build
curl localhost:8000/healthz   # {"status":"ok"}
docker compose exec gateway tripwire keys create --name my-agent   # prints a tw_... key once
open http://localhost:3000
```

Use Tripwire as an MCP server: point any MCP client at `http://localhost:8000/v1/mcp` with `Authorization: Bearer tw_...`, or launch `tripwire mcp stdio` from Claude Desktop. Configs, approvals and the tool review flow: [docs/mcp.md](docs/mcp.md).

Docs: [design](docs/design.md) · [MCP proxy](docs/mcp.md) · [detection](docs/detection.md) · [performance](docs/performance.md) · [limitations](docs/limitations.md) · [deployment](docs/deployment.md)

## Layout

| Path | What |
|---|---|
| `gateway/` | FastAPI gateway (Python 3.12, uv) |
| `web/` | Next.js 16 playground + operator console |
| `ml/` | Injection classifier training (separate env) |
| `evals/` | AgentDojo + MCP benchmarks (separate env) |

License: MIT.
