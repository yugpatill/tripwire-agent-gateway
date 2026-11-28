"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bell, BellOff, Check, CheckCheck, Volume2, VolumeX, X } from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { type ApprovalRecord, decideApproval, fetchApprovals } from "@/lib/console/api";
import { READ_ONLY_HINT, useCanWrite, useNow } from "@/lib/console/hooks";
import { useConsoleStream } from "@/lib/console/use-console-stream";
import { cn } from "@/lib/utils";

import { type Finding, FindingsList, ManifestDiff } from "./manifest-diff";

const KIND_LABEL: Record<ApprovalRecord["kind"], string> = {
  call: "Tool call",
  tool_quarantine: "Quarantined tool",
  tool_change: "Changed tool (possible rug pull)",
};

function beep() {
  try {
    const ctx = new AudioContext();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.frequency.value = 880;
    gain.gain.setValueAtTime(0.08, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.35);
    osc.connect(gain).connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.35);
    osc.onended = () => void ctx.close();
  } catch {
    // no audio available
  }
}

function usePref(key: string): [boolean, (v: boolean) => void] {
  const [value, setValue] = useState(false);
  useEffect(() => {
    // Read after mount: localStorage is not available while rendering on the server.
    const stored = window.localStorage.getItem(key) === "1";
    if (stored) queueMicrotask(() => setValue(true));
  }, [key]);
  const set = useCallback(
    (v: boolean) => {
      window.localStorage.setItem(key, v ? "1" : "0");
      setValue(v);
    },
    [key],
  );
  return [value, set];
}

function Countdown({ expiresAt, createdAt }: { expiresAt: string; createdAt: string }) {
  const now = useNow();
  const end = new Date(expiresAt).getTime();
  const total = Math.max(1, end - new Date(createdAt).getTime());
  const left = now === 0 ? end - new Date(createdAt).getTime() : Math.max(0, end - now);
  const s = Math.ceil(left / 1000);
  const label =
    s === 0 ? "expired" : s >= 3600 ? `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min` : `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
  return (
    <div className="flex min-w-28 flex-col items-end gap-1">
      <span className={cn("font-mono text-xs tabular-nums", s < 30 ? "text-amber-500" : "text-muted-foreground")}>
        {s === 0 ? "Expired" : `expires in ${label}`}
      </span>
      <div
        className="bg-muted h-1 w-28 overflow-hidden rounded"
        role="progressbar"
        aria-label="Time left to decide"
        aria-valuenow={Math.round((left / total) * 100)}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div className="h-full bg-amber-500 transition-[width] duration-1000 ease-linear" style={{ width: `${(left / total) * 100}%` }} />
      </div>
    </div>
  );
}

function ApprovalCard({ rec }: { rec: ApprovalRecord }) {
  const qc = useQueryClient();
  const canWrite = useCanWrite();
  const now = useNow();
  const expired = now > 0 && new Date(rec.expires_at).getTime() <= now;
  const decide = useMutation({
    mutationFn: ({ decision, scope }: { decision: "approve" | "deny"; scope: "once" | "session" }) =>
      decideApproval(rec.id, decision, scope),
    onSuccess: (r) => {
      toast.success(`${r.tool}: ${r.status}${r.scope === "session" ? " for this session" : ""}`);
      void qc.invalidateQueries({ queryKey: ["approvals"] });
      void qc.invalidateQueries({ queryKey: ["tools"] });
    },
    onError: (e) => toast.error(e.message),
  });
  const detail = rec.detail as Record<string, unknown>;
  const findings = (detail.findings ?? []) as Finding[];
  const disabled = !canWrite || expired || decide.isPending;
  const hint = !canWrite ? READ_ONLY_HINT : expired ? "This request has expired (denied)" : undefined;

  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 space-y-1">
          <CardTitle className="flex flex-wrap items-center gap-2 text-base">
            <span className="font-mono break-all">{rec.tool}</span>
            <Badge variant="outline" className="border-amber-500/60 text-amber-500">
              {KIND_LABEL[rec.kind]}
            </Badge>
          </CardTitle>
          <p className="text-muted-foreground text-xs">
            {new Date(rec.created_at).toLocaleString()}
            {rec.session_id && (
              <>
                {" · "}
                <Link className="underline underline-offset-2" href={`/console/traces/${rec.session_id}`}>
                  session trace
                </Link>
              </>
            )}
          </p>
        </div>
        <Countdown expiresAt={rec.expires_at} createdAt={rec.created_at} />
      </CardHeader>
      <CardContent className="space-y-4">
        {rec.kind === "call" ? (
          <>
            <div className="space-y-1 text-sm">
              {typeof detail.rule_id === "string" && <p className="font-mono">{detail.rule_id}</p>}
              <p className="text-muted-foreground">{String(detail.message ?? "")}</p>
            </div>
            <pre className="bg-muted/50 max-h-60 overflow-auto rounded-md p-3 font-mono text-[11px] whitespace-pre-wrap break-all">
              {JSON.stringify(detail.args ?? {}, null, 2)}
            </pre>
          </>
        ) : (
          <>
            {rec.kind === "tool_change" ? (
              <ManifestDiff
                before={detail.before as Record<string, unknown>}
                after={detail.after as Record<string, unknown>}
              />
            ) : (
              <p className="text-sm whitespace-pre-wrap">
                {String((detail.manifest as Record<string, unknown> | undefined)?.description ?? "")}
              </p>
            )}
            <div className="space-y-1">
              <p className="text-muted-foreground text-xs">
                Risk score {Number(detail.score ?? 0).toFixed(2)}
              </p>
              <FindingsList findings={findings} />
            </div>
          </>
        )}
        <div className="flex flex-wrap gap-2" title={hint}>
          <Button size="sm" disabled={disabled} onClick={() => decide.mutate({ decision: "approve", scope: "once" })}>
            <Check aria-hidden /> {rec.kind === "call" ? "Approve once" : "Approve and re-pin"}
          </Button>
          {rec.kind === "call" && (
            <Button
              size="sm"
              variant="secondary"
              disabled={disabled}
              onClick={() => decide.mutate({ decision: "approve", scope: "session" })}
            >
              <CheckCheck aria-hidden /> Approve for session
            </Button>
          )}
          <Button size="sm" variant="destructive" disabled={disabled} onClick={() => decide.mutate({ decision: "deny", scope: "once" })}>
            <X aria-hidden /> Deny
          </Button>
          {hint && <span className="text-muted-foreground self-center text-xs">{hint}</span>}
        </div>
      </CardContent>
    </Card>
  );
}

function History() {
  const { data } = useQuery({ queryKey: ["approvals", "history"], queryFn: () => fetchApprovals(undefined, 30) });
  const done = (data ?? []).filter((r) => r.status !== "pending").slice(0, 15);
  if (!done.length) return null;
  const tone = (s: string) => (s === "approved" ? "text-green-500" : s === "denied" ? "text-red-500" : "text-muted-foreground");
  return (
    <section className="space-y-2">
      <h2 className="text-lg font-semibold">Recently decided</h2>
      <ul className="divide-y rounded-md border text-sm">
        {done.map((r) => (
          <li key={r.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2">
            <span className="font-mono break-all">{r.tool}</span>
            <span className="text-muted-foreground text-xs">{KIND_LABEL[r.kind]}</span>
            <span className={cn("ml-auto font-medium", tone(r.status))}>
              {r.status}
              {r.scope === "session" ? " (session)" : ""}
            </span>
            <span className="text-muted-foreground text-xs">
              {r.decided_by ? `${r.decided_by} · ` : ""}
              {new Date(r.decided_at ?? r.created_at).toLocaleTimeString()}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function ApprovalsQueue() {
  const qc = useQueryClient();
  const [sound, setSound] = usePref("tripwire.approvals.sound");
  const [notify, setNotify] = usePref("tripwire.approvals.notify");
  const pending = useQuery({
    queryKey: ["approvals", "pending"],
    queryFn: () => fetchApprovals("pending"),
    refetchInterval: 30_000,
  });

  const status = useConsoleStream(
    useCallback(
      (m) => {
        if (m.type !== "approval.created" && m.type !== "approval.decided") return;
        void qc.invalidateQueries({ queryKey: ["approvals"] });
        if (m.type !== "approval.created") return;
        const rec = m.approval as ApprovalRecord;
        if (sound) beep();
        if (notify && typeof Notification !== "undefined" && Notification.permission === "granted" && document.hidden) {
          new Notification("Tripwire: approval needed", { body: `${KIND_LABEL[rec.kind]}: ${rec.tool}`, tag: rec.id });
        }
      },
      [qc, sound, notify],
    ),
  );

  async function toggleNotify() {
    if (notify) return setNotify(false);
    if (typeof Notification === "undefined") return toast.error("This browser has no notifications.");
    const p = Notification.permission === "granted" ? "granted" : await Notification.requestPermission();
    if (p === "granted") setNotify(true);
    else toast.error("Notifications are blocked for this site.");
  }

  // A request past its deadline is already denied by the gateway (fail closed),
  // even if its row has not been swept yet: keep it out of the queue.
  const now = useNow(5000);
  const items = (pending.data ?? []).filter((r) => new Date(r.expires_at).getTime() > now);
  const calls = items.filter((r) => r.kind === "call");
  const tools = items.filter((r) => r.kind !== "call");

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-muted-foreground mr-auto flex items-center gap-2 text-sm">
          <span
            aria-hidden
            className={cn("size-2 rounded-full", status === "open" ? "bg-green-500" : "bg-muted-foreground animate-pulse")}
          />
          {status === "open" ? "Live" : "Reconnecting…"} · {items.length} pending
        </span>
        <Button variant="outline" size="sm" aria-pressed={sound} onClick={() => setSound(!sound)}>
          {sound ? <Volume2 aria-hidden /> : <VolumeX aria-hidden />} Sound
        </Button>
        <Button variant="outline" size="sm" aria-pressed={notify} onClick={() => void toggleNotify()}>
          {notify ? <Bell aria-hidden /> : <BellOff aria-hidden />} Notifications
        </Button>
      </div>

      {pending.isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : pending.isError ? (
        <p className="text-red-500 text-sm">{pending.error.message}</p>
      ) : items.length === 0 ? (
        <div className="text-muted-foreground rounded-md border border-dashed p-10 text-center text-sm">
          Nothing waiting. Calls that a rule sends for approval, quarantined tools and changed tools
          appear here as they happen.
        </div>
      ) : (
        <>
          {calls.length > 0 && (
            <section className="space-y-3">
              <h2 className="text-lg font-semibold">Tool calls</h2>
              {calls.map((r) => (
                <ApprovalCard key={r.id} rec={r} />
              ))}
            </section>
          )}
          {tools.length > 0 && (
            <section className="space-y-3">
              <h2 className="text-lg font-semibold">Tool reviews</h2>
              {tools.map((r) => (
                <ApprovalCard key={r.id} rec={r} />
              ))}
            </section>
          )}
        </>
      )}
      <History />
    </div>
  );
}
