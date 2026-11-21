# syntax=docker/dockerfile:1.7
FROM node:22-alpine AS base
RUN npm install -g pnpm@10.34.9
WORKDIR /app

# ---- dev: source bind-mounted by compose ----
FROM base AS dev
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN --mount=type=cache,target=/root/.local/share/pnpm/store pnpm install --frozen-lockfile
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
EXPOSE 3000
CMD ["pnpm", "dev", "--hostname", "0.0.0.0", "--port", "3000"]
