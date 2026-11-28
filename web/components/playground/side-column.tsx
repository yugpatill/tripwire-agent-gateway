"use client";

import { EyeOff, Shield, ShieldOff } from "lucide-react";

import { Skeleton } from "@/components/ui/skeleton";
import type {
  ModelTurnEvent,
  RunEvent,
  Side,
  SideRecord,
  ToolResultEvent,
  ToolsListedEvent,
} from "@/lib/playground/types";

import { EnvironmentPanel } from "./environment-panel";
import { PendingToolCard, ToolCard } from "./tool-card";

export function SideColumn({
  side,
  task,
  events,
  record,
  injected,
}: {
  side: Side;
  task: string;
  events: RunEvent[];
  record?: SideRecord;
  injected?: string;
}) {
  const mine = events.filter((e) => e.side === side);
  const results = new Map(
    mine.filter((e): e is ToolResultEvent => e.type === "tool.result").map((e) => [e.id, e]),
  );
  const turns = mine.filter((e): e is ModelTurnEvent => e.type === "model.turn");
  const finished = mine.some((e) => e.type === "side.finished");
  const protectedSide = side === "protected";
  const hidden = protectedSide ? hiddenTools(events) : new Map<number, string[]>();

  return (
    <section className="flex min-w-0 flex-col gap-3" aria-label={protectedSide ? "Protected run" : "Unprotected run"}>
      <header
        className={`flex items-center gap-2 rounded-lg px-3 py-2 font-semibold text-white ${
          protectedSide ? "bg-green-700" : "bg-red-700"
        }`}
      >
        {protectedSide ? <Shield className="size-4" aria-hidden /> : <ShieldOff className="size-4" aria-hidden />}
        {protectedSide ? "Protected by Tripwire" : "Unprotected"}
      </header>
      <div className="bg-muted/40 rounded-lg px-3 py-2 text-sm">
        <span className="text-muted-foreground">User: </span>
        {task}
      </div>
      {turns.map((t) => (
        <div key={t.seq} className="space-y-3">
          <HiddenNote tools={hidden.get(t.step)} />
          {t.text && (
            <div className="rounded-lg border-l-2 border-sky-500/60 px-3 py-1 text-sm whitespace-pre-wrap">
              {t.text}
            </div>
          )}
          {t.tool_calls.map((c) => {
            const r = results.get(c.id);
            return r ? (
              <ToolCard key={c.id} event={r} injected={injected} />
            ) : (
              <PendingToolCard key={c.id} tool={c.tool} args={c.args} />
            );
          })}
          {t.stop === "refusal" && <p className="text-muted-foreground text-sm">The model declined this request.</p>}
          {t.stop === "error" && <p className="text-muted-foreground text-sm">The model call failed.</p>}
        </div>
      ))}
      {!finished && <Skeleton className="h-16 w-full" />}
      {record ? <EnvironmentPanel side={record} /> : finished ? <Skeleton className="h-24 w-full" /> : null}
    </section>
  );
}

/** Per protected step: tools the unprotected agent was offered that Tripwire newly hid. */
function hiddenTools(events: RunEvent[]): Map<number, string[]> {
  const listings = events.filter((e): e is ToolsListedEvent => e.type === "tools.listed");
  const offered = new Set(listings.filter((e) => e.side === "unprotected").flatMap((e) => e.tools));
  const out = new Map<number, string[]>();
  const seen = new Set<string>();
  for (const l of listings.filter((e) => e.side === "protected")) {
    const visible = new Set(l.tools);
    const fresh = [...offered].filter((t) => !visible.has(t) && !seen.has(t));
    fresh.forEach((t) => seen.add(t));
    if (fresh.length) out.set(l.step, fresh);
  }
  return out;
}

function HiddenNote({ tools }: { tools?: string[] }) {
  if (!tools?.length) return null;
  return (
    <p className="text-muted-foreground flex items-start gap-2 rounded-lg border border-dashed px-3 py-2 text-sm">
      <EyeOff className="mt-0.5 size-4 shrink-0" aria-hidden />
      <span>
        Tripwire hid <code className="font-mono">{tools.join(", ")}</code> from the agent: the tool&apos;s description
        failed review or changed after it was approved.
      </span>
    </p>
  );
}
