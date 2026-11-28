# Web app: playground and operator console

`web/` is a Next.js 16 app (App Router, Cache Components, Turbopack). It talks to the gateway only through the typed client generated from the gateway's OpenAPI schema (`make openapi` writes `web/lib/api/openapi.json` and `schema.d.ts`).

| Route | Who | What |
|---|---|---|
| `/` | public | Hero, the six preset scenarios, a custom attack dialog |
| `/run/{run_id}` | public | Split view (unprotected / protected), streamed over `WS /v1/playground/runs/{id}/stream`, blocked cards with the "Why?" taint path, environment after the run, permalink and replay. Replays: `replay-<scenario>`, `-scripted`, `-live` |
| `/login` | public | Console sign-in, with a one-click read-only demo account |
| `/console` | console users | Overview: counts by action, decisions per hour, latency p50/p95, top rules, recent stops |
| `/console/events` | console users | All decisions, filterable (kind, action, tool, rule), live updates, a drawer with labels, detectors and arguments |
| `/console/traces` | console users | Sessions, and per session a graph of calls and results with the data-flow edges between them |
| `/console/approvals` | console users; deciding needs an admin | Live queue with countdowns: approve once, approve for the session, deny; tool reviews with the side-by-side manifest diff; optional sound and browser notifications |
| `/console/tools` | console users; approving needs an admin | Every pinned tool with status, risk score, findings marked in the description, the diff of a changed tool |
| `/console/policy` | console users; deploying and shadow mode need an admin | YAML editor with schema validation and completion, "Test against last 7 days", deploy, shadow-mode switch |
| `/console/evals` | console users | Results table, attack success rate by config, utility vs attack success. **Placeholder data until Phase 9** (labelled on the page) |

Colors: only red (block), amber (held, redacted, changed) and green (allowed, pinned) carry action meaning. Taint labels: orange untrusted, red suspicious, purple confidential.

## Sign-in

`POST /v1/auth/login` sets an httpOnly `tripwire_session` cookie (HS256 JWT, 12 hours, `Secure` in production; 10 attempts per IP per 10 minutes). Two console users:

- the admin from `ADMIN_EMAIL` / `ADMIN_PASSWORD`;
- `demo` (password `demo` outside production, `DEMO_READONLY_PASSWORD` in production): read-only. It sees everything (stored secrets are redacted in every console response) and can edit and test a policy, but every change (approvals, tool approval, deploy, shadow mode) returns 403.

Operator API keys work on the same endpoints as an admin (`Authorization: Bearer`). Set a long random `JWT_SECRET` (32+ bytes); production refuses the placeholder.

## Policy versions and the editor

The active policy lives in the `policies` table:

- On start, the newest active row wins. With none, the file policy (`TRIPWIRE_POLICY_PATH`) is stored as a version. While no one has deployed from the console, edits to the file still apply on restart (a new version is stored); once a console deploy exists, the database wins.
- `PUT /v1/policies/active` validates the YAML (422 with line and column per error, shown in the editor and as markers), stores version N+1, swaps it into the engine and publishes `policy.updated`; other gateway workers reload it.
- `POST /v1/policies/test?since_hours=168` replays recorded tool calls of the last 7 days (playground runs excluded, at most 5,000 calls) against the candidate and lists the calls whose action would change. Each call event stores the session facts the rules saw (`context_confidentiality`, `session_suspicious`), so the replay uses the same labels and facts. Rate limits are not replayed, and calls recorded before these facts were stored are left out (counted as `skipped`).
- `GET /v1/policies/schema` is the JSON Schema of the policy model, used by the editor (monaco-yaml).
- `GET/PUT /v1/policies/mode`: shadow mode for all agents (decisions logged, `log_only` enforced), stored in Redis and announced with `mode.updated`. `TRIPWIRE_MODE` is the default when it has never been set. A session created with `mode: shadow` stays in shadow either way.

## Live updates

`WS /v1/stream` (session cookie or operator key) carries `event.recorded`, `approval.created`, `approval.decided`, `policy.updated` and `mode.updated`. The client reconnects with backoff and the pages refetch what changed.

## Evaluations

`GET /v1/evals` returns the newest run per suite and config from `eval_runs`. Until Phase 9 imports results it returns `placeholder: true` with obviously synthetic numbers; the page shows a "Placeholder data: not results" banner and marks every chart and the table.

## Checks

- `pnpm typecheck`, `pnpm lint`, `pnpm build` (CI `web` workflow).
- Lighthouse (mobile defaults) on `/` against `pnpm build && pnpm start`, 2026-11-27: performance 100, accessibility 100, best practices 100, SEO 100. The header's console link is not prefetched, which keeps the console's chart and editor code off the landing page.
- `gateway/tests/integration/test_console_auth_live.py` and `test_policies_live.py`: sign-in, the read-only demo account, redaction, policy validation, test, deploy, shadow mode, evals placeholder.

## Notes

- Monaco runs only in the browser (`next/dynamic` with `ssr: false`) and is bundled (no CDN), with its editor and YAML workers built by Turbopack. `monaco-editor` is pinned to `~0.52.2`: `monaco-yaml` 5.5 does not work with 0.55 (its YAML worker requests fail) or 0.58 (new package export map).
