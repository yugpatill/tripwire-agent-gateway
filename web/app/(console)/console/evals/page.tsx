import type { Metadata } from "next";

import { EvalsView } from "@/components/console/evals-view";

export const metadata: Metadata = { title: "Evaluations · Tripwire console" };

export default function EvalsPage() {
  return (
    <section className="space-y-4">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Evaluations</h1>
        <p className="text-muted-foreground text-sm">
          How often prompt-injection attacks succeed (ASR) and how much of the agents&apos; normal work
          still gets done (utility), with and without Tripwire.
        </p>
      </div>
      <EvalsView />
    </section>
  );
}
