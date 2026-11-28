export function Hero() {
  return (
    <section className="mx-auto max-w-3xl space-y-5 px-4 pt-16 pb-10 text-center md:pt-24">
      <h1 className="text-4xl font-semibold tracking-tight text-balance md:text-5xl">
        Stop prompt injection before your agent acts on it
      </h1>
      <p className="text-muted-foreground text-lg text-balance">
        Tripwire sits between an AI agent and its tools. It tracks where every value came from,
        scans tool descriptions and results, and blocks the call when injected content tries to
        steer the agent.
      </p>
      <p className="text-muted-foreground text-sm">
        Pick an attack below. The same agent runs twice, at the same time: once calling its tools
        directly, once through Tripwire.
      </p>
      <p className="text-muted-foreground text-xs">
        Open source (MIT) · MCP proxy and SDK adapters · policies in YAML
      </p>
    </section>
  );
}
