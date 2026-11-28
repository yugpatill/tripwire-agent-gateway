"use client";

import { useQuery } from "@tanstack/react-query";
import { FlaskConical } from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
  ZAxis,
} from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { type EvalRunView, fetchEvals } from "@/lib/console/api";

// Categorical colors for suites: none of red, amber or green (those mean actions).
const SUITE_COLORS = ["#38bdf8", "#818cf8", "#f472b6", "#94a3b8", "#2dd4bf", "#c084fc"];

const pct = (v: unknown) => (typeof v === "number" ? `${Math.round(v * 100)}%` : "—");
const num = (r: EvalRunView, k: string) => (typeof r.metrics[k] === "number" ? (r.metrics[k] as number) : null);

function mean(xs: (number | null)[]): number | null {
  const v = xs.filter((x): x is number => x !== null);
  return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null;
}

function PlaceholderMark({ on }: { on: boolean }) {
  if (!on) return null;
  return (
    <span className="ml-2 rounded border border-amber-500/60 px-1.5 py-0.5 align-middle text-[10px] font-medium tracking-wide text-amber-500 uppercase">
      placeholder
    </span>
  );
}

export function EvalsView() {
  const { data, isLoading, isError, error } = useQuery({ queryKey: ["evals"], queryFn: fetchEvals });
  if (isLoading) return <Skeleton className="h-96 w-full" />;
  if (isError) return <p className="text-sm text-red-500">{error.message}</p>;
  if (!data) return null;

  const ph = data.placeholder;
  const runs = data.runs;
  // Charts compare configurations on AgentDojo only; MCP suite and adaptive rows are in the table.
  const agentdojo = runs.filter((r) => (r.metrics.benchmark ?? "agentdojo") === "agentdojo");
  const configs = [...new Set(agentdojo.map((r) => r.config))].sort();
  const suites = [...new Set(agentdojo.map((r) => r.suite))].sort();
  const bars = configs.map((c) => ({
    config: c,
    asr: mean(agentdojo.filter((r) => r.config === c).map((r) => num(r, "asr"))),
  }));
  const tooltip = {
    contentStyle: { background: "var(--popover)", border: "1px solid var(--border)", borderRadius: 8, fontSize: 12 },
    labelStyle: { color: "var(--muted-foreground)" },
  };

  return (
    <div className="space-y-6">
      {ph && (
        <div
          role="note"
          className="flex items-start gap-3 rounded-md border border-amber-500/60 bg-amber-500/10 p-4 text-sm"
        >
          <FlaskConical aria-hidden className="mt-0.5 size-4 shrink-0 text-amber-500" />
          <div className="space-y-1">
            <p className="font-medium">Placeholder data: not results</p>
            <p className="text-muted-foreground">
              {data.note} The table and charts below only show the layout. Real attack success rates
              and utility come from the AgentDojo and MCP benchmark runs in Phase 9 (configs A to F),
              imported with a CLI command.
            </p>
          </div>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">
              Attack success rate by config (mean over suites)
              <PlaceholderMark on={ph} />
            </CardTitle>
          </CardHeader>
          <CardContent className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={bars} margin={{ left: -10, right: 8 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                <XAxis dataKey="config" tick={{ fontSize: 12 }} stroke="var(--muted-foreground)" />
                <YAxis tickFormatter={pct} domain={[0, 1]} tick={{ fontSize: 12 }} stroke="var(--muted-foreground)" />
                <Tooltip {...tooltip} formatter={(v) => [pct(v), "ASR"]} cursor={{ fill: "var(--muted)" }} />
                <Bar dataKey="asr" name="ASR" fill={ph ? "#71717a" : "#a1a1aa"} radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">
              Utility vs attack success (one point per config and suite)
              <PlaceholderMark on={ph} />
            </CardTitle>
          </CardHeader>
          <CardContent className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <ScatterChart margin={{ left: -10, right: 8, bottom: 4 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis
                  type="number"
                  dataKey="asr"
                  name="ASR"
                  domain={[0, 1]}
                  tickFormatter={pct}
                  tick={{ fontSize: 12 }}
                  stroke="var(--muted-foreground)"
                />
                <YAxis
                  type="number"
                  dataKey="utility"
                  name="Utility"
                  domain={[0, 1]}
                  tickFormatter={pct}
                  tick={{ fontSize: 12 }}
                  stroke="var(--muted-foreground)"
                />
                <ZAxis type="category" dataKey="config" name="Config" range={[60, 60]} />
                <Tooltip {...tooltip} formatter={(v, n) => [n === "Config" ? String(v) : pct(v), n]} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                {suites.map((s, i) => (
                  <Scatter
                    key={s}
                    name={s}
                    fill={SUITE_COLORS[i % SUITE_COLORS.length]}
                    data={agentdojo
                      .filter((r) => r.suite === s)
                      .map((r) => ({ asr: num(r, "asr"), utility: num(r, "utility"), config: r.config }))}
                  />
                ))}
              </ScatterChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      <section className="space-y-2">
        <h2 className="text-lg font-semibold">
          Results
          <PlaceholderMark on={ph} />
        </h2>
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full text-sm">
            <caption className="sr-only">Attack success rate and utility per config and suite</caption>
            <thead className="text-muted-foreground border-b text-left text-xs">
              <tr>
                <th scope="col" className="px-3 py-2 font-medium">Config</th>
                <th scope="col" className="px-3 py-2 font-medium">Suite</th>
                <th scope="col" className="px-3 py-2 text-right font-medium">ASR</th>
                <th scope="col" className="px-3 py-2 text-right font-medium">Utility</th>
                <th scope="col" className="px-3 py-2 text-right font-medium">Utility under attack</th>
                <th scope="col" className="hidden px-3 py-2 font-medium md:table-cell">Model</th>
              </tr>
            </thead>
            <tbody className={`divide-y ${ph ? "text-muted-foreground" : ""}`}>
              {runs.map((r) => (
                <tr key={`${r.config}-${r.suite}`}>
                  <td className="px-3 py-1.5 font-mono">{r.config}</td>
                  <td className="px-3 py-1.5">{r.suite}</td>
                  <td className="px-3 py-1.5 text-right tabular-nums">{pct(r.metrics.asr)}</td>
                  <td className="px-3 py-1.5 text-right tabular-nums">{pct(r.metrics.utility)}</td>
                  <td className="px-3 py-1.5 text-right tabular-nums">{pct(r.metrics.utility_under_attack)}</td>
                  <td className="hidden px-3 py-1.5 font-mono text-xs md:table-cell">{r.model}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
