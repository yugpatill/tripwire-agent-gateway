import type { Metadata } from "next";
import { Suspense } from "react";

import { TraceGraph } from "@/components/console/trace-graph";
import { Skeleton } from "@/components/ui/skeleton";

export const metadata: Metadata = { title: "Trace · Tripwire console" };

async function Loader({ params }: { params: PageProps<"/console/traces/[sessionId]">["params"] }) {
  const { sessionId } = await params;
  return <TraceGraph sessionId={sessionId} />;
}

export default function TracePage({ params }: PageProps<"/console/traces/[sessionId]">) {
  return (
    <section className="space-y-4">
      <h1 className="text-2xl font-semibold tracking-tight">Session trace</h1>
      <Suspense fallback={<Skeleton className="h-[60vh]" />}>
        <Loader params={params} />
      </Suspense>
    </section>
  );
}
