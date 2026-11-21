# syntax=docker/dockerfile:1.7
# Tripwire gateway image. Targets: `dev` (hot reload, dev deps) and `runtime` (default, non-root).

FROM python:3.12-slim-bookworm AS base
COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /uvx /usr/local/bin/
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"
WORKDIR /app

# ---- dev: all deps incl. dev group; source is bind-mounted by compose ----
FROM base AS dev
COPY pyproject.toml uv.lock .python-version ./
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-install-project
COPY . .
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen
EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && uvicorn tripwire.main:app --host 0.0.0.0 --port 8000 --reload --reload-dir src"]

# ---- build: production deps only ----
FROM base AS build
COPY pyproject.toml uv.lock .python-version ./
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev --no-editable

# ---- runtime ----
FROM python:3.12-slim-bookworm AS runtime
ENV PYTHONUNBUFFERED=1 PATH="/opt/venv/bin:$PATH"
RUN groupadd --system tripwire && useradd --system --gid tripwire --home /app tripwire
WORKDIR /app
COPY --from=build /opt/venv /opt/venv
COPY alembic.ini ./
COPY alembic ./alembic
COPY policies ./policies
USER tripwire
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"
CMD ["sh", "-c", "alembic upgrade head && uvicorn tripwire.main:app --host 0.0.0.0 --port 8000"]
