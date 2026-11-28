import { Banknote, Mail, MessageSquare, ShieldCheck, Skull } from "lucide-react";

import type { SideRecord } from "@/lib/playground/types";

function isGoal(side: SideRecord, tool: string, args: Record<string, unknown>): boolean {
  return side.goal_calls.some(
    (c) => c.tool === tool && Object.entries(args).every(([k, v]) => c.args[k] === v),
  );
}

/** What actually happened in this side's mock environment after the run. */
export function EnvironmentPanel({ side }: { side: SideRecord }) {
  const env = side.environment;
  const empty = !env.sent.length && !env.transfers.length && !env.comments.length;
  return (
    <section className="space-y-3 rounded-lg border p-3" aria-label="Environment after the run">
      <div
        className={`flex items-center gap-2 rounded-md px-2 py-1.5 text-sm font-medium ${
          side.attacker_goal_reached ? "bg-red-500/10 text-red-500" : "bg-green-500/10 text-green-500"
        }`}
      >
        {side.attacker_goal_reached ? <Skull className="size-4" aria-hidden /> : <ShieldCheck className="size-4" aria-hidden />}
        {side.attacker_goal_reached ? "Attacker's goal reached" : "Attacker's goal not reached"}
      </div>
      <h3 className="text-muted-foreground text-xs font-medium tracking-wide uppercase">Environment after the run</h3>
      {empty && <p className="text-muted-foreground text-sm">No emails, transfers or comments.</p>}
      <ul className="space-y-1.5 text-sm">
        {env.sent.map((m, i) => (
          <li key={`m${i}`} className={`flex gap-2 ${isGoal(side, "email__send_email", { to: m.to }) ? "text-red-500" : ""}`}>
            <Mail className="mt-0.5 size-4 shrink-0" aria-hidden />
            <span>
              Email to <span className="font-mono">{m.to}</span>: {m.subject}
            </span>
          </li>
        ))}
        {env.transfers.map((t, i) => (
          <li key={`t${i}`} className={`flex gap-2 ${isGoal(side, "bank__transfer", { to_account: t.to_account }) ? "text-red-500" : ""}`}>
            <Banknote className="mt-0.5 size-4 shrink-0" aria-hidden />
            <span>
              ${t.amount.toLocaleString()} to <span className="font-mono">{t.to_account}</span>
            </span>
          </li>
        ))}
        {env.comments.map((c, i) => (
          <li key={`c${i}`} className="flex gap-2">
            <MessageSquare className="mt-0.5 size-4 shrink-0" aria-hidden />
            <span>
              Comment on PR #{c.number}: {c.body.slice(0, 120)}
            </span>
          </li>
        ))}
      </ul>
      {side.goal_calls.length > 0 && (
        <div className="space-y-1">
          <p className="text-xs text-red-500">Calls that achieved the attacker&apos;s goal:</p>
          {side.goal_calls.map((c, i) => (
            <pre key={i} className="overflow-x-auto rounded bg-red-500/5 px-2 py-1 font-mono text-[11px] whitespace-pre-wrap break-all">
              {c.tool} {JSON.stringify(c.args).slice(0, 300)}
            </pre>
          ))}
        </div>
      )}
      <p className="text-muted-foreground text-xs">
        Balance ${env.balance.toLocaleString()} · {env.calls.length} tool call{env.calls.length === 1 ? "" : "s"} executed
      </p>
    </section>
  );
}
