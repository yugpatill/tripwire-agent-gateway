"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { ArrowLeft, Link2, Play, RotateCcw } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/lib/api/client";
import { startRun } from "@/lib/playground/api";
import type { RunStartedEvent } from "@/lib/playground/types";
import { useRunStream } from "@/lib/playground/use-run-stream";

import { ModelBadge } from "./model-badge";
import { SideColumn } from "./side-column";

const REASON: Record<string, string> = {
  no_api_key: "No model API key is configured, so this is a recorded replay.",
  daily_cap: "Today's live-run budget is used up, so this is a recorded replay.",
  rate_limited: "You've reached this hour's run limit, so this is a recorded replay.",
};

export function RunView({ runId }: { runId: string }) {
  const { events, complete, record, replay, status } = useRunStream(runId);
  const router = useRouter();
  const reason = useSearchParams().get("reason");
  const [busy, setBusy] = useState(false);
  const started = events.find((e): e is RunStartedEvent => e.type === "run.started");
  const scenario = record?.scenario ?? started?.scenario;
  const source = record?.model.source ?? started?.model.source;
  const isReplay = runId.startsWith("replay-");
  const verdict = record?.verdict;

  useEffect(() => {
    if (reason && REASON[reason]) toast.info(REASON[reason]);
  }, [reason]);

  const copyLink = async () => {
    await navigator.clipboard.writeText(window.location.href.split("?")[0]);
    toast.success("Link copied");
  };

  const runAgain = async () => {
    if (!scenario || scenario.id.startsWith("custom_")) return;
    setBusy(true);
    try {
      const out = await startRun({ scenario_id: scenario.id });
      router.push(`/run/${out.run_id}${out.reason ? `?reason=${out.reason}` : ""}`);
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "Could not start a run");
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="mx-auto w-full max-w-7xl space-y-6 px-4 py-6 md:px-6">
      <Link href="/" className="text-muted-foreground inline-flex items-center gap-1 text-sm hover:underline">
        <ArrowLeft className="size-4" aria-hidden /> All scenarios
      </Link>
      <header className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-2xl font-semibold tracking-tight">{scenario?.title ?? "Loading run…"}</h1>
          <ModelBadge source={source} />
          {isReplay && <Badge variant="secondary">Replay</Badge>}
          {status !== "open" && !complete && <Badge variant="outline">{status}</Badge>}
        </div>
        {scenario && (
          <dl className="text-muted-foreground grid gap-1 text-sm md:grid-cols-[auto_1fr] md:gap-x-4">
            <dt className="font-medium text-foreground">Attacker&apos;s goal</dt>
            <dd>{scenario.attacker_goal}</dd>
            <dt className="font-medium text-foreground">Planted in</dt>
            <dd>{scenario.malicious.where}</dd>
          </dl>
        )}
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" onClick={copyLink}>
            <Link2 aria-hidden /> Copy permalink
          </Button>
          <Button variant="outline" size="sm" onClick={replay} disabled={!complete}>
            <RotateCcw aria-hidden /> Replay
          </Button>
          {scenario && !scenario.id.startsWith("custom_") && (
            <Button size="sm" onClick={runAgain} disabled={busy}>
              <Play aria-hidden /> Run again
            </Button>
          )}
        </div>
      </header>

      {verdict && (
        <p
          className={`rounded-lg border px-4 py-3 text-sm ${
            verdict.attack_succeeded_protected ? "border-red-500/60" : "border-green-600/60"
          }`}
          role="status"
        >
          {verdict.attack_succeeded_unprotected
            ? "Unprotected, the attack worked. "
            : "Unprotected, the model did not carry out the attack this time. "}
          {verdict.attack_succeeded_protected
            ? "Through Tripwire it also got through."
            : verdict.rules_fired_protected.length
              ? `Through Tripwire it was stopped (${verdict.rules_fired_protected.join(", ")}).`
              : "Through Tripwire nothing needed stopping."}
        </p>
      )}

      <div className="grid gap-6 md:grid-cols-2">
        {(["unprotected", "protected"] as const).map((side) => (
          <SideColumn
            key={side}
            side={side}
            task={scenario?.task ?? ""}
            events={events}
            record={record?.sides[side]}
            injected={scenario?.malicious.text}
          />
        ))}
      </div>
    </main>
  );
}
