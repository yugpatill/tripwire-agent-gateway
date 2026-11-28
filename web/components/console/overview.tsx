"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { fetchSummary } from "@/lib/console/api";

import { ActionBadge } from "./badges";
import { useConsoleUser } from "./console-gate";

const SERIES = [
  { key: "allow", color: "#a1a1aa", name: "allowed" },
  { key: "require_approval", color: "#f59e0b", name: "held for approval" },
  { key: "block", color: "#ef4444", name: "blocked" },
];
const RANGES = [24, 24 * 7, 24 * 30];

function Tile({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <Card>
      <CardHeader className="pb-1">
        <CardTitle className="text-muted-foreground text-xs font-medium tracking-wide uppercase">{label}</CardTitle>
      </CardHeader>
      <CardContent className={`text-2xl font-semibold tabular-nums ${tone ?? ""}`}>{value}</CardContent>
    </Card>
  );
}

/** One point per hour of the range, zeros where nothing happened (no gaps). */
function fillHours(rows: Record<string, unknown>[], hours: number) {
  const byHour = new Map(rows.map((r) => [new Date(String(r.hour)).getTime(), r]));
  const end = new Date();
  end.setMinutes(0, 0, 0);
  const out = [];
  for (let i = hours - 1; i >= 0; i -= 1) {
    const t = end.getTime() - i * 3_600_000;
    const r = byHour.get(t) ?? {};
    out.push({
      label: new Date(t).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit" }),
      allow: Number(r.allow ?? 0),
      require_approval: Number(r.require_approval ?? 0),
      block: Number(r.block ?? 0),
    });
  }
  return out;
}

export function Overview() {
  const me = useConsoleUser();
  const [hours, setHours] = useState(24 * 7);
  const { data, isLoading } = useQuery({
    queryKey: ["summary", hours],
    queryFn: () => fetchSummary(hours),
    enabled: me !== null,
    refetchInterval: 15_000,
  });
  if (isLoading || !data) {
    return (
      <div className="grid gap-4 md:grid-cols-4">
        {Array.from({ length: 4 }, (_, i) => (
          <Skeleton key={i} className="h-24" />
        ))}
        <Skeleton className="h-72 md:col-span-4" />
      </div>
    );
  }
  const total = Object.values(data.totals).reduce((a, b) => a + b, 0);
  const series = fillHours(data.series, hours);
  return (
    <div className="space-y-6">
      <div className="flex gap-1" role="group" aria-label="Time range">
        {RANGES.map((h) => (
          <button
            key={h}
            type="button"
            onClick={() => setHours(h)}
            aria-pressed={hours === h}
            className={`rounded-md border px-2.5 py-1 text-xs ${hours === h ? "bg-muted" : "text-muted-foreground"}`}
          >
            {h === 24 ? "24 hours" : `${h / 24} days`}
          </button>
        ))}
      </div>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <Tile label="Decisions" value={total.toLocaleString()} />
        <Tile label="Blocked" value={(data.totals.block ?? 0).toLocaleString()} tone="text-red-500" />
        <Tile label="Held for approval" value={(data.totals.require_approval ?? 0).toLocaleString()} tone="text-amber-500" />
        <Tile label="Sessions" value={data.sessions.toLocaleString()} />
        <Tile label="Latency p95" value={data.latency_ms.p95 != null ? `${data.latency_ms.p95} ms` : "—"} />
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Decisions over time</CardTitle>
          </CardHeader>
          <CardContent className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={series}>
                <CartesianGrid strokeDasharray="3 3" stroke="#3f3f46" />
                <XAxis dataKey="label" tick={{ fontSize: 11, fill: "#a1a1aa" }} minTickGap={24} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: "#a1a1aa" }} width={40} />
                <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #3f3f46", fontSize: 12 }} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                {SERIES.map((s) => (
                  <Line key={s.key} type="monotone" dataKey={s.key} name={s.name} stroke={s.color} dot={false} strokeWidth={2} connectNulls />
                ))}
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Top rules</CardTitle>
          </CardHeader>
          <CardContent className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.top_rules} layout="vertical" margin={{ left: 8 }}>
                <XAxis type="number" allowDecimals={false} tick={{ fontSize: 11, fill: "#a1a1aa" }} />
                <YAxis type="category" dataKey="rule_id" width={150} tick={{ fontSize: 10, fill: "#a1a1aa" }} />
                <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #3f3f46", fontSize: 12 }} />
                <Bar dataKey="count" fill="#71717a" radius={[0, 3, 3, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Recent blocks and holds</CardTitle>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <table className="w-full min-w-[560px] text-sm">
            <tbody>
              {data.recent_stops.map((e) => (
                <tr key={e.id} className="border-b last:border-0">
                  <td className="py-1.5 pr-3 whitespace-nowrap">{new Date(e.created_at).toLocaleString()}</td>
                  <td className="py-1.5 pr-3 font-mono text-xs">{e.tool}</td>
                  <td className="py-1.5 pr-3">
                    <ActionBadge action={e.enforced_action} />
                  </td>
                  <td className="py-1.5 pr-3 font-mono text-xs">{e.rule_id}</td>
                  <td className="py-1.5">
                    <Link href={`/console/traces/${e.session_id}`} className="text-xs underline-offset-2 hover:underline">
                      trace
                    </Link>
                  </td>
                </tr>
              ))}
              {!data.recent_stops.length && (
                <tr>
                  <td className="text-muted-foreground py-4">Nothing blocked or held in this period.</td>
                </tr>
              )}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}
