"use client";

import Link from "next/link";

import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import type { EventView } from "@/lib/console/api";
import { cn } from "@/lib/utils";

import { ActionBadge, type Provenance, TaintBadge, taintTone } from "./badges";

function strongest(labels: Provenance[]): Provenance | undefined {
  const rank = (p: Provenance) =>
    p.trust === "suspicious" ? 3 : p.trust.startsWith("untrusted") ? 2 : p.confidentiality === "secret" || p.confidentiality === "confidential" ? 1 : 0;
  return [...labels].sort((a, b) => rank(b) - rank(a))[0];
}

function Value({ value }: { value: unknown }) {
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 1);
  return <pre className="font-mono text-[11px] whitespace-pre-wrap break-all">{text.length > 1500 ? `${text.slice(0, 1500)}…` : text}</pre>;
}

export function EventDrawer({ event, onClose }: { event: EventView | null; onClose: () => void }) {
  const labels = (event?.labels ?? {}) as Record<string, unknown>;
  const payload = (event?.payload ?? {}) as Record<string, unknown>;
  const args = (payload.args ?? {}) as Record<string, unknown>;
  return (
    <Sheet open={event !== null} onOpenChange={(o) => !o && onClose()}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-xl">
        {event && (
          <>
            <SheetHeader>
              <SheetTitle className="flex flex-wrap items-center gap-2">
                <span className="font-mono">{event.tool}</span>
                <ActionBadge action={event.enforced_action} />
              </SheetTitle>
              <SheetDescription>
                {event.kind === "call" ? "Tool call" : "Tool result"} · {new Date(event.created_at).toLocaleString()} ·{" "}
                {event.latency_ms.toFixed(1)} ms
              </SheetDescription>
            </SheetHeader>
            <div className="space-y-5 px-4 pb-8 text-sm">
              {(event.rule_id || event.message) && (
                <section className="space-y-1">
                  {event.rule_id && <p className="font-mono">{event.rule_id}</p>}
                  <p className="text-muted-foreground">{event.message}</p>
                  {event.action !== event.enforced_action && (
                    <p className="text-amber-500">Shadow mode: the policy computed {event.action}.</p>
                  )}
                </section>
              )}

              {event.kind === "call" && (
                <section className="space-y-2">
                  <h3 className="font-medium">Arguments and where their data came from</h3>
                  {Object.entries(args).map(([name, value]) => {
                    const ls = (labels[name] ?? []) as Provenance[];
                    const top = strongest(ls);
                    return (
                      <div key={name} className={cn("space-y-1 rounded-md border-l-4 border-y border-r p-2", top ? taintTone(top) : "border-border")}>
                        <p className="text-foreground font-mono text-xs">{name}</p>
                        <div className="text-foreground">
                          <Value value={value} />
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {ls.length ? ls.map((p, i) => <TaintBadge key={i} p={p} />) : <span className="text-muted-foreground text-xs">No tracked source</span>}
                        </div>
                      </div>
                    );
                  })}
                </section>
              )}

              {event.kind === "result" && (
                <section className="space-y-2">
                  <h3 className="font-medium">Result</h3>
                  <div className="flex flex-wrap gap-1">
                    {((labels.result ?? []) as Provenance[]).map((p, i) => (
                      <TaintBadge key={i} p={p} />
                    ))}
                    {typeof labels.context_confidentiality === "string" && (
                      <span className="text-muted-foreground text-xs">session context: {labels.context_confidentiality}</span>
                    )}
                  </div>
                  <div className="bg-muted/40 rounded p-2">
                    <Value value={payload.content} />
                  </div>
                </section>
              )}

              {event.detectors.length > 0 && (
                <section className="space-y-1">
                  <h3 className="font-medium">Detectors</h3>
                  <ul className="space-y-1">
                    {(event.detectors as { detector: string; score: number; reason: string }[]).map((d, i) => (
                      <li key={i} className="text-muted-foreground">
                        <span className="text-foreground font-mono">{d.detector}</span> {d.score.toFixed(2)}: {d.reason}
                      </li>
                    ))}
                  </ul>
                </section>
              )}

              {event.edges.length > 0 && (
                <section className="space-y-1">
                  <h3 className="font-medium">Data flow into this call</h3>
                  <ul className="space-y-1">
                    {(event.edges as { arg: string; matched_value: string; match: string; label: Provenance }[]).map((e, i) => (
                      <li key={i} className="flex flex-wrap items-center gap-1">
                        <span className="font-mono text-xs">{e.arg}</span> ← <TaintBadge p={e.label} />
                        <span className="text-muted-foreground text-xs">
                          {e.match}: “{e.matched_value.slice(0, 80)}”
                        </span>
                      </li>
                    ))}
                  </ul>
                </section>
              )}

              <Button variant="outline" size="sm" nativeButton={false} render={<Link href={`/console/traces/${event.session_id}`} />}>
                Open session trace
              </Button>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}
