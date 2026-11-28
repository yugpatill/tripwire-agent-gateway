SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help dev down logs test test-gateway test-web lint migrate openapi eval load

help: ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n", $$1, $$2}'

dev: ## start the full local stack
	docker compose up --build

down: ## stop the stack
	docker compose down

logs: ## follow gateway logs
	docker compose logs -f gateway

test: test-gateway test-web ## run all tests and checks

test-gateway: ## ruff + mypy + pytest for the gateway
	cd gateway && uv sync && uv run ruff check . && uv run ruff format --check . && uv run mypy src && uv run pytest -q

test-web: ## typecheck, lint, build the web app
	cd web && pnpm install --frozen-lockfile && pnpm typecheck && pnpm lint && pnpm build

lint: ## format + autofix
	cd gateway && uv run ruff format . && uv run ruff check --fix .

migrate: ## apply DB migrations inside the running gateway container
	docker compose exec gateway alembic upgrade head

openapi: ## export gateway OpenAPI schema for the web client
	cd gateway && uv run tripwire openapi > ../web/lib/api/openapi.json
	cd web && pnpm api:generate

eval: ## run benchmarks (Phase 9)
	@echo "evals are implemented in Phase 9" && exit 1

load: ## run load test (Phase 9)
	@echo "load test is implemented in Phase 9" && exit 1
