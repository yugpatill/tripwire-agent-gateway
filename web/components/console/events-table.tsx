"use client";

import { useInfiniteQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useCallback, useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { type EventFilters, type EventView, fetchEvents } from "@/lib/console/api";
import { useConsoleStream } from "@/lib/console/use-console-stream";

import { ActionBadge } from "./badges";
import { useConsoleUser } from "./console-gate";
import { EventDrawer } from "./event-drawer";

const select = "border-input bg-background h-8 rounded-md border px-2 text-sm";

export function EventsTable() {
  const me = useConsoleUser();
  const qc = useQueryClient();
  const [filters, setFilters] = useState<EventFilters>({});
  const [live, setLive] = useState(true);
  const [open, setOpen] = useState<EventView | null>(null);
  const lastRefresh = useRef(0);
  const key = ["events", filters];

  const query = useInfiniteQuery({
    queryKey: key,
    queryFn: ({ pageParam }) => fetchEvents({ ...filters, before: pageParam ?? undefined }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_before ?? null,
    enabled: me !== null,
  });

  const onMessage = useCallback(
    (m: { type: string }) => {
      if (!live || m.type !== "event.recorded") return;
      const now = Date.now();
      if (now - lastRefresh.current < 1500) return;
      lastRefresh.current = now;
      void qc.invalidateQueries({ queryKey: ["events"] });
    },
    [live, qc],
  );
  const status = useConsoleStream(onMessage, me !== null);
  const rows = query.data?.pages.flatMap((p) => p.items) ?? [];
  const set = (k: keyof EventFilters) => (v: string) =>
    setFilters((f) => ({ ...f, [k]: v || undefined }));

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <select aria-label="Kind" className={select} value={filters.kind ?? ""} onChange={(e) => set("kind")(e.target.value)}>
          <option value="">Calls and results</option>
          <option value="call">Calls</option>
          <option value="result">Results</option>
        </select>
        <select aria-label="Action" className={select} value={filters.action ?? ""} onChange={(e) => set("action")(e.target.value)}>
          <option value="">Any action</option>
          {["allow", "block", "require_approval", "redact", "log_only"].map((a) => (
            <option key={a} value={a}>
              {a.replace("_", " ")}
            </option>
          ))}
        </select>
        <Input aria-label="Tool" placeholder="Tool" className="h-8 w-40" onChange={(e) => set("tool")(e.target.value)} />
        <Input aria-label="Rule" placeholder="Rule id" className="h-8 w-44" onChange={(e) => set("rule_id")(e.target.value)} />
        <label className="ml-auto flex items-center gap-2 text-sm">
          <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} />
          Live {live && <span className={status === "open" ? "text-green-500" : "text-muted-foreground"}>({status})</span>}
        </label>
      </div>

      <div className="overflow-x-auto rounded-lg border">
        <table className="w-full min-w-[720px] text-sm">
          <thead className="text-muted-foreground border-b text-left text-xs">
            <tr>
              <th className="px-3 py-2 font-medium">Time</th>
              <th className="px-3 py-2 font-medium">Kind</th>
              <th className="px-3 py-2 font-medium">Tool</th>
              <th className="px-3 py-2 font-medium">Action</th>
              <th className="px-3 py-2 font-medium">Rule</th>
              <th className="px-3 py-2 text-right font-medium">ms</th>
              <th className="px-3 py-2 font-medium">Session</th>
            </tr>
          </thead>
          <tbody>
            {query.isLoading &&
              Array.from({ length: 8 }, (_, i) => (
                <tr key={i}>
                  <td colSpan={7} className="px-3 py-1.5">
                    <Skeleton className="h-5" />
                  </td>
                </tr>
              ))}
            {rows.map((e) => (
              <tr
                key={e.id}
                className="hover:bg-muted/50 cursor-pointer border-b last:border-0"
                onClick={() => setOpen(e)}
                onKeyDown={(k) => k.key === "Enter" && setOpen(e)}
                tabIndex={0}
              >
                <td className="px-3 py-1.5 whitespace-nowrap">{new Date(e.created_at).toLocaleTimeString()}</td>
                <td className="text-muted-foreground px-3 py-1.5">{e.kind}</td>
                <td className="px-3 py-1.5 font-mono text-xs">{e.tool}</td>
                <td className="px-3 py-1.5">
                  <ActionBadge action={e.enforced_action} />
                </td>
                <td className="px-3 py-1.5 font-mono text-xs">{e.rule_id ?? ""}</td>
                <td className="px-3 py-1.5 text-right tabular-nums">{e.latency_ms.toFixed(1)}</td>
                <td className="px-3 py-1.5">
                  <Link href={`/console/traces/${e.session_id}`} className="font-mono text-xs underline-offset-2 hover:underline" onClick={(ev) => ev.stopPropagation()}>
                    {e.session_id.slice(0, 8)}
                  </Link>
                </td>
              </tr>
            ))}
            {!query.isLoading && rows.length === 0 && (
              <tr>
                <td colSpan={7} className="text-muted-foreground px-3 py-6 text-center">
                  No events match.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {query.hasNextPage && (
        <Button variant="outline" size="sm" onClick={() => query.fetchNextPage()} disabled={query.isFetchingNextPage}>
          Load older events
        </Button>
      )}
      <EventDrawer event={open} onClose={() => setOpen(null)} />
    </div>
  );
}
