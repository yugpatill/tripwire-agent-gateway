# syntax=docker/dockerfile:1.7
# Tripwire gateway image. Targets: `dev` (hot reload, dev deps) and `runtime` (default, non-root).

# Default injection classifier: GitHub Release asset, verified by SHA-256 (ml/README.md).
# Override both build args to bake in another artifact, e.g. DeBERTa-v3-small.
ARG CLASSIFIER_URL=https://github.com/yugpatill/tripwire-agent-gateway/releases/download/classifier-minilm-l6-v1/injection-minilm-l6-v1.tar.gz
ARG CLASSIFIER_SHA256=e6a757991957c35f268ea998c40aa9a6ff22cea80bca224ad53f4e54c5fca719

# ---- classifier: download, verify and unpack the artifact folder ----
FROM python:3.12-slim-bookworm AS classifier
ARG CLASSIFIER_URL
ARG CLASSIFIER_SHA256
ADD --checksum=sha256:${CLASSIFIER_SHA256} ${CLASSIFIER_URL} /tmp/classifier.tar.gz
RUN mkdir -p /models/injection-classifier \
 && tar -xzf /tmp/classifier.tar.gz -C /models/injection-classifier --strip-components=1 \
 && for f in model.int8.onnx tokenizer.json config.json; do \
      test -s "/models/injection-classifier/$f" || { echo "classifier artifact missing $f" >&2; exit 1; }; \
    done

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
COPY --from=classifier /models/injection-classifier /app/models/injection-classifier
ENV TRIPWIRE_CLASSIFIER_DIR=/app/models/injection-classifier
EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && uvicorn tripwire.main:app --host 0.0.0.0 --port 8000 --reload --reload-dir src"]

# ---- build: production deps only ----
FROM base AS build
COPY pyproject.toml uv.lock .python-version ./
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev --no-editable
# Strip debug symbols from Python extension modules (~180 MB, mostly spaCy/thinc).
# Vendored *.libs folders are left alone.
RUN apt-get update && apt-get install -y --no-install-recommends binutils \
 && find /opt/venv -type f \( -name "*.cpython-*.so" -o -name "*.abi3.so" \) \
      -exec strip --strip-unneeded {} + \
 && apt-get purge -y binutils && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
# Runtime-only trims (~70 MB): bundled test suites, pip/setuptools, and the
# phonenumbers geocoding database (Presidio parses numbers, never geocodes them).
RUN cd /opt/venv/lib/python3.12/site-packages \
 && find . -type d \( -name tests -o -name test \) -prune -exec rm -rf {} + \
 && rm -rf pip pip-* setuptools setuptools-* phonenumbers/geodata

# ---- runtime ----
FROM python:3.12-slim-bookworm AS runtime
ENV PYTHONUNBUFFERED=1 PATH="/opt/venv/bin:$PATH"
RUN groupadd --system tripwire && useradd --system --gid tripwire --home /app tripwire
WORKDIR /app
COPY --from=build /opt/venv /opt/venv
COPY alembic.ini ./
COPY alembic ./alembic
COPY policies ./policies
COPY mcp ./mcp
COPY --from=classifier /models/injection-classifier /app/models/injection-classifier
ENV TRIPWIRE_CLASSIFIER_DIR=/app/models/injection-classifier
USER tripwire
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"
CMD ["sh", "-c", "alembic upgrade head && uvicorn tripwire.main:app --host 0.0.0.0 --port 8000"]
