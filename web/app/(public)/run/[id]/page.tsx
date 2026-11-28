import type { Metadata } from "next";
import { Suspense } from "react";

import { RunView } from "@/components/playground/run-view";
import { Skeleton } from "@/components/ui/skeleton";

export const metadata: Metadata = { title: "Playground run · Tripwire" };

function RunSkeleton() {
  return (
    <main className="mx-auto w-full max-w-7xl space-y-4 px-4 py-6 md:px-6">
      <Skeleton className="h-8 w-72" />
      <div className="grid gap-6 md:grid-cols-2">
        <Skeleton className="h-96" />
        <Skeleton className="h-96" />
      </div>
    </main>
  );
}

// `params` is request data under Cache Components: read it inside Suspense.
async function RunLoader({ params }: { params: PageProps<"/run/[id]">["params"] }) {
  const { id } = await params;
  return <RunView runId={decodeURIComponent(id)} />;
}

export default function RunPage({ params }: PageProps<"/run/[id]">) {
  return (
    <Suspense fallback={<RunSkeleton />}>
      <RunLoader params={params} />
    </Suspense>
  );
}
