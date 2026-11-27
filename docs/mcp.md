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

Tripwire's taint tracking needs to know which calls belong to one agent run, for one end user. A request carrying `X-Tripwire-Session: <uuid>` (a session the same key created with `POST /v1/sessions`) always uses that session. Without the header, the key's **session scope** decides:

| `session_scope` | Without `X-Tripwire-Session` | Use it for |
|---|---|---|
| `header` | rejected with HTTP 400 | **any key that serves more than one user**, and production (default when `TRIPWIRE_ENV=production`) |
| `connection` | one session per MCP session id (`Mcp-Session-Id`, handshake-era clients); 2026-07-28 clients send no id and are rejected | clients that keep one connection per run. Caveat: a client that reconnects between reading untrusted content and acting on it starts with a clean taint context |
| `key` | one rolling session per key, in Redis (renewed on use, replaced after 1 h idle), shared by all its connections and workers; reconnecting cannot reset taint | **single-user keys only** (default when `TRIPWIRE_ENV=development`): taint and user-prompt entities are shared across everything the key does, so with several users one user's prompt could vouch for an address in another user's session |

Set it when creating the key:

```bash
tripwire keys create --name support-bot --session-scope header        # multi-user
tripwire keys create --name my-laptop                                  # dev default: key
TRIPWIRE_ENV=production tripwire keys create --name me --session-scope key --force-key-scope
```

With `TRIPWIRE_ENV=production`, `--session-scope key` is refused unless `--force-key-scope` is given (a warning is printed and the key is marked forced), and a key with unforced `key` scope gets HTTP 403 on `/v1/mcp` until it sends `X-Tripwire-Session`. `tripwire keys list` shows each key's scope (`key!` = forced). The stdio bridge always sends its own session, so it works with every scope. The playground uses one session per run.

## Instruction origin over MCP

Instruction origin protects against an injection that makes the model invent a destination: once untrusted content is in the session, an email address, URL, path or long number in a tool argument that matches no known value is labelled `untrusted_origin`, and rules such as `no-untrusted-recipient` block it. Entities the user typed are exempt, but Tripwire only knows them if it receives the user's prompt, and plain MCP clients never send one.

How to provide it (client application only, never model output):
- `X-Tripwire-User-Prompt: <percent-encoded text>` on MCP requests (`TRIPWIRE_USER_PROMPT` for the stdio bridge). Each new text is added to the session as a user turn; repeats are ignored. For a multi-turn chat, send the latest user message.
- `POST /v1/sessions` with `user_prompt`, then `X-Tripwire-Session` on MCP requests; later turns with `POST /v1/sessions/{id}/prompts` `{"text": "..."}` (used by the `tripwire-guard` SDK).

When no prompt is known for a session, two policy defaults decide:

```yaml
defaults:
  instruction_origin: strict          # strict | off
  no_prompt_action: require_approval  # require_approval | block (used with strict)
```

| Setting | No prompt known, untrusted content in context, argument entity from no known source | Attacker address copied from untrusted content (value match) |
|---|---|---|
| **`strict` + `no_prompt_action: require_approval`** (default) | labelled `untrusted_origin` (source `unknown:no_prompt`). A block caused only by that label becomes **`require_approval`**: an operator decides, because the user may simply have typed the address in a client that never told Tripwire | **blocked** |
| `strict` + `no_prompt_action: block` | blocked (the behaviour before this setting existed) | **blocked** |
| `off` | no label: allowed. A paraphrased or reassembled attacker address is no longer caught | **blocked** |

How "caused only by that label" is decided: when a call is blocked and an argument carries a no-prompt origin label, the policy is evaluated again without those labels. If nothing else blocks (no value match, no other rule), the call gets `no_prompt_action`; otherwise the block stands. Rate-limit counters are counted once per call either way. The decision message says that no user prompt is known.

Sessions with a known prompt always use instruction origin, and an unknown entity there blocks as before (`untrusted_origin` from source `unknown`). Before any untrusted content, nothing is labelled `untrusted_origin`. (`off` may be written unquoted in YAML.)

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
3. After fetching an untrusted page, an email to an address that came from nowhere the user named is blocked with the rule's message, even though each Inspector command is a new connection (the key used `key` scope; with `connection` scope each command would be a fresh session). (The Inspector also prints its own `tool_is_error` line after an `isError` result.)

To use the Inspector UI instead: `npx @modelcontextprotocol/inspector`, transport "Streamable HTTP", URL `http://localhost:8000/v1/mcp`, add the header `Authorization: Bearer tw_...` under Authentication. Its request-timeout settings can be shorter than an approval wait (up to 120 s); raise them (Configuration) to try held calls in the UI. Tripwire sends a progress notification every 5 s while a call is held.

## Latency

See [performance.md](performance.md#mcp-proxy-overhead).
