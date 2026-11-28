import type { Metadata } from "next";

import { SessionsList } from "@/components/console/sessions-list";

export const metadata: Metadata = { title: "Traces · Tripwire console" };

export default function TracesPage() {
  return (
    <section className="space-y-4">
      <h1 className="text-2xl font-semibold tracking-tight">Traces</h1>
      <p className="text-muted-foreground text-sm">Sessions with recorded events, most recent first.</p>
      <SessionsList />
    </section>
  );
}
