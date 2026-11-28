#!/usr/bin/env bash
# A throwaway gateway for the MCP suite: its own database (tripwire_eval) and Redis
# index on the compose Postgres/Redis, the compose mock MCP servers, port 8100.
# Leaves the demo database alone. EVAL_POLICY overrides the policy file. Usage, from evals/:
#   bash mcp_suite/local_stack.sh [classifier_dir] [command ...]
# The command (default: the MCP suite) runs from evals/ with TRIPWIRE_URL,
# TRIPWIRE_API_KEY and MOCK_URL set.
set -euo pipefail
cd "$(dirname "$0")/../.."
CLASSIFIER="${1:-$PWD/ml/artifacts/injection-minilm-l6}"
shift || true
CMD=("$@")
[ ${#CMD[@]} -eq 0 ] && CMD=(uv run python mcp_suite/run.py)
docker compose up -d postgres redis mock-mcp >/dev/null
docker compose exec -T postgres psql -U tripwire -d postgres -qc "DROP DATABASE IF EXISTS tripwire_eval WITH (FORCE);" -c "CREATE DATABASE tripwire_eval OWNER tripwire;"
docker compose exec -T redis redis-cli -n 5 FLUSHDB >/dev/null
cat > /tmp/tripwire-eval-upstreams.yaml <<'EOF'
upstreams:
  email: {url: "http://127.0.0.1:9100/email/mcp"}
  files: {url: "http://127.0.0.1:9100/files/mcp"}
  web: {url: "http://127.0.0.1:9100/web/mcp"}
  bank: {url: "http://127.0.0.1:9100/bank/mcp"}
  calculator: {url: "http://127.0.0.1:9100/calculator/mcp"}
  weather: {url: "http://127.0.0.1:9100/weather/mcp"}
EOF
export DATABASE_URL=postgresql+asyncpg://tripwire:tripwire@127.0.0.1:5432/tripwire_eval
export REDIS_URL=redis://127.0.0.1:6379/5
export TRIPWIRE_POLICY_PATH="${EVAL_POLICY:-$PWD/gateway/policies/demo.yaml}"
export TRIPWIRE_CLASSIFIER_DIR="$CLASSIFIER"
export TRIPWIRE_MCP_UPSTREAMS=/tmp/tripwire-eval-upstreams.yaml
export TRIPWIRE_APPROVAL_TIMEOUT_S=2
export TRIPWIRE_ENV=development
cd gateway
uv run alembic upgrade head >/dev/null
KEY=$(uv run tripwire keys create --name mcp-suite | grep -oE 'tw_[A-Za-z0-9_-]+')
uv run uvicorn tripwire.main:app --host 127.0.0.1 --port 8100 --log-level warning > /tmp/tripwire-eval-gateway.log 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT
for _ in $(seq 1 60); do curl -fs http://127.0.0.1:8100/readyz >/dev/null && break; sleep 1; done
cd ../evals
TRIPWIRE_URL=http://127.0.0.1:8100 TRIPWIRE_API_KEY="$KEY" MOCK_URL=http://127.0.0.1:9100 "${CMD[@]}"
