# Deployment

Full deployment guide (Vercel web, Railway/Fly.io gateway, Helm chart) is written in Phase 10. This file tracks deployment constraints decided so far.

## Gateway runtime image

- Built from `gateway/Dockerfile`, target `runtime`: multi-stage, `python:3.12-slim-bookworm`, non-root user `tripwire`, production dependencies only (no PyTorch, no dev tools).
- **Size budget: 900 MB.** Enforced in CI (`.github/workflows/gateway.yml`, job `image`); the build fails above it. CI gates on the larger of `docker image inspect .Size` and the unpacked filesystem size (`du -sxb /` inside the image), because the reported size differs by storage driver (containerd snapshotter reports compressed bytes).

| Date | Phase | Size | Notes |
|---|---|---|---|
| 2026-11-21 | 1 | 242 MB unpacked (336 MB in `docker image ls` on Docker Desktop, 71 MB compressed) | FastAPI, SQLAlchemy/asyncpg, Alembic, redis, structlog. No ML or NLP deps yet. |
| 2026-11-21 | 3 | 694 MB unpacked, before trimming | + onnxruntime, tokenizers, numpy, Presidio, spaCy + `en_core_web_sm` |
| 2026-11-21 | 3 | **460 MB** unpacked (674 MB in `docker image ls`) | Debug symbols stripped from extension modules (−184 MB); bundled test suites, pip/setuptools and phonenumbers geodata removed (−68 MB); + provider SDK for the LLM judge |
| 2026-11-21 | 3 | **641 MB** unpacked, with the classifier | + DeBERTa-v3-small int8 ONNX (172 MB). With DeBERTa-v3-base (243 MB) it would be about 712 MB. |
| 2026-11-27 | 4 | **502 MB** unpacked on x86 CI (484 MB arm64; 187 MB compressed) | + default classifier MiniLM-L6 int8 (23 MB) baked in from the `classifier-minilm-l6-v1` release asset. With the opt-in DeBERTa-v3-small instead: about 650 MB. |

Target: under **700 MB** with the classifier (the CI hard limit stays 900 MB): met.

**How the classifier gets into the image.** A `classifier` build stage downloads the release tarball named by the `CLASSIFIER_URL` build arg, verifies it against `CLASSIFIER_SHA256` (`ADD --checksum`, so a changed or tampered asset fails the build) and unpacks it to `/app/models/injection-classifier`, which `TRIPWIRE_CLASSIFIER_DIR` points to. The defaults pin `classifier-minilm-l6-v1`. To bake in another artifact:

```bash
docker build --target runtime --build-arg CLASSIFIER_URL=<tarball URL> --build-arg CLASSIFIER_SHA256=<sha256> -t tripwire-gateway gateway/
```

Or mount an artifact folder and set `TRIPWIRE_CLASSIFIER_DIR` to it at run time. The tarball must contain one top-level folder with `model.int8.onnx`, `tokenizer.json` and `config.json`.

The image makes no outbound calls at startup or while serving: spaCy's model is installed from a locked wheel, and the Public Suffix List used by Presidio comes from tldextract's bundled snapshot (verified with `--network none`).

```bash
docker build --target runtime -t tripwire-gateway gateway
docker image inspect tripwire-gateway --format '{{.Size}}'
```
