# Deployment

Full deployment guide (Vercel web, Railway/Fly.io gateway, Helm chart) is written in Phase 10. This file tracks deployment constraints decided so far.

## Gateway runtime image

- Built from `gateway/Dockerfile`, target `runtime`: multi-stage, `python:3.12-slim-bookworm`, non-root user `tripwire`, production dependencies only (no PyTorch, no dev tools).
- **Size budget: 900 MB.** Enforced in CI (`.github/workflows/gateway.yml`, job `image`); the build fails above it. CI gates on the larger of `docker image inspect .Size` and the unpacked filesystem size (`du -sxb /` inside the image), because the reported size differs by storage driver (containerd snapshotter reports compressed bytes).

| Date | Phase | Size | Notes |
|---|---|---|---|
| 2026-11-21 | 1 | 242 MB unpacked (336 MB in `docker image ls` on Docker Desktop, 71 MB compressed) | FastAPI, SQLAlchemy/asyncpg, Alembic, redis, structlog. No ML or NLP deps yet. |

Expected growth: Phase 3 adds onnxruntime, tokenizers, Presidio and spaCy `en_core_web_sm`; Phase 4 adds the int8 ONNX classifier (~200 MB for deberta-v3-base). Re-measure after each and update this table.

```bash
docker build --target runtime -t tripwire-gateway gateway
docker image inspect tripwire-gateway --format '{{.Size}}'
```
