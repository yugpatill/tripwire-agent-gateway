"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check } from "lucide-react";
import { useCallback, useState } from "react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { approveTool, fetchTools, type ToolPinView } from "@/lib/console/api";
import { READ_ONLY_HINT, useCanWrite } from "@/lib/console/hooks";
import { useConsoleStream } from "@/lib/console/use-console-stream";
import { cn } from "@/lib/utils";

import { type Finding, FindingsList, FlaggedText, ManifestDiff } from "./manifest-diff";

const STATUS: Record<string, { label: string; tone: string }> = {
  pinned: { label: "pinned", tone: "border-green-500/60 text-green-500" },
  quarantined: { label: "quarantined", tone: "border-red-500/60 text-red-500" },
  changed: { label: "changed · blocked", tone: "border-amber-500/60 text-amber-500" },
};

function StatusBadge({ status }: { status: string }) {
  const s = STATUS[status] ?? { label: status, tone: "" };
  return (
    <Badge variant="outline" className={cn("font-mono", s.tone)}>
      {s.label}
    </Badge>
  );
}

function Risk({ score }: { score: number }) {
  const pct = Math.min(100, Math.round(score * 100));
  return (
    <div className="flex items-center gap-2">
      <div className="bg-muted h-1.5 w-16 overflow-hidden rounded" aria-hidden>
        <div
          className={cn("h-full", score >= 0.5 ? "bg-red-500" : score >= 0.2 ? "bg-amber-500" : "bg-muted-foreground/50")}
          style={{ width: `${Math.max(pct, 2)}%` }}
        />
      </div>
      <span className="font-mono text-xs tabular-nums">{score.toFixed(2)}</span>
    </div>
  );
}

function ToolSheet({ tool, onClose }: { tool: ToolPinView | null; onClose: () => void }) {
  const qc = useQueryClient();
  const canWrite = useCanWrite();
  const approve = useMutation({
    mutationFn: (name: string) => approveTool(name),
    onSuccess: (t) => {
      toast.success(`${t.name} is pinned`);
      void qc.invalidateQueries({ queryKey: ["tools"] });
      void qc.invalidateQueries({ queryKey: ["approvals"] });
      onClose();
    },
    onError: (e) => toast.error(e.message),
  });
  const pending = tool?.pending_change as { manifest?: Record<string, unknown>; scan?: { score?: number; findings?: Finding[] } } | null;
  const findings = ((pending?.scan?.findings ?? tool?.findings) ?? []) as unknown as Finding[];
  const description = String((pending?.manifest ?? tool?.manifest)?.description ?? "");

  return (
    <Sheet open={tool !== null} onOpenChange={(o) => !o && onClose()}>
      <SheetContent side="right" className="overflow-y-auto data-[side=right]:w-full data-[side=right]:sm:max-w-2xl">
        {tool && (
          <>
            <SheetHeader>
              <SheetTitle className="flex flex-wrap items-center gap-2">
                <span className="font-mono break-all">{tool.name}</span>
                <StatusBadge status={tool.status} />
              </SheetTitle>
              <SheetDescription>
                Server {tool.server} · pinned hash <span className="font-mono">{tool.hash.slice(0, 12)}</span>
              </SheetDescription>
            </SheetHeader>
            <div className="space-y-5 px-4 pb-8">
              {pending ? (
                <section className="space-y-2">
                  <h3 className="text-sm font-medium">What changed since it was approved</h3>
                  <ManifestDiff before={tool.manifest} after={pending.manifest} />
                </section>
              ) : (
                <section className="space-y-2">
                  <h3 className="text-sm font-medium">Description</h3>
                  <FlaggedText text={description} findings={findings} />
                </section>
              )}
              <section className="space-y-2">
                <h3 className="text-sm font-medium">
                  Findings <span className="text-muted-foreground font-normal">(risk {Number(pending?.scan?.score ?? tool.risk_score).toFixed(2)})</span>
                </h3>
                <FindingsList findings={findings} />
              </section>
              {!pending && (
                <section className="space-y-2">
                  <h3 className="text-sm font-medium">Input schema</h3>
                  <pre className="bg-muted/50 overflow-auto rounded-md p-3 font-mono text-[11px]">
                    {JSON.stringify(tool.manifest.input_schema ?? {}, null, 2)}
                  </pre>
                </section>
              )}
              {tool.status !== "pinned" && (
                <div className="flex flex-wrap items-center gap-2">
                  <Button disabled={!canWrite || approve.isPending} onClick={() => approve.mutate(tool.name)}>
                    <Check aria-hidden /> {pending ? "Approve the change and re-pin" : "Approve and pin"}
                  </Button>
                  {!canWrite && <span className="text-muted-foreground text-xs">{READ_ONLY_HINT}</span>}
                </div>
              )}
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

export function ToolsTable() {
  const qc = useQueryClient();
  const [open, setOpen] = useState<string | null>(null);
  const { data, isLoading, isError, error } = useQuery({ queryKey: ["tools"], queryFn: fetchTools });
  useConsoleStream(
    useCallback(
      (m) => {
        if (m.type.startsWith("approval.")) void qc.invalidateQueries({ queryKey: ["tools"] });
      },
      [qc],
    ),
  );
  if (isLoading) return <Skeleton className="h-60 w-full" />;
  if (isError) return <p className="text-sm text-red-500">{error.message}</p>;
  const tools = [...(data ?? [])].sort(
    (a, b) => Number(a.status === "pinned") - Number(b.status === "pinned") || b.risk_score - a.risk_score,
  );
  if (!tools.length)
    return (
      <div className="text-muted-foreground rounded-md border border-dashed p-10 text-center text-sm">
        No tools yet. Tools appear here the first time an agent lists them through Tripwire.
      </div>
    );
  const selected = tools.find((t) => t.name === open) ?? null;
  return (
    <>
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full text-sm">
          <thead className="text-muted-foreground border-b text-left text-xs">
            <tr>
              <th scope="col" className="px-3 py-2 font-medium">Tool</th>
              <th scope="col" className="px-3 py-2 font-medium">Status</th>
              <th scope="col" className="px-3 py-2 font-medium">Risk</th>
              <th scope="col" className="hidden px-3 py-2 font-medium md:table-cell">Findings</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {tools.map((t) => (
              <tr key={t.name} className="hover:bg-muted/40">
                <td className="px-3 py-2">
                  <button
                    type="button"
                    className="font-mono break-all text-left underline-offset-2 hover:underline md:break-normal md:whitespace-nowrap"
                    onClick={() => setOpen(t.name)}
                  >
                    {t.name}
                  </button>
                </td>
                <td className="px-3 py-2">
                  <StatusBadge status={t.status} />
                </td>
                <td className="px-3 py-2">
                  <Risk score={t.risk_score} />
                </td>
                <td className="text-muted-foreground hidden px-3 py-2 text-xs md:table-cell">
                  {[...new Set((t.findings as unknown as Finding[]).map((f) => f.rule))].join(", ") || "none"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <ToolSheet tool={selected} onClose={() => setOpen(null)} />
    </>
  );
}
