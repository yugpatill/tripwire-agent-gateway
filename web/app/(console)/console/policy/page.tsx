import type { Metadata } from "next";

import { PolicyWorkbench } from "@/components/console/policy-workbench";

export const metadata: Metadata = { title: "Policy · Tripwire console" };

export default function PolicyPage() {
  return (
    <section className="space-y-4">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Policy</h1>
        <p className="text-muted-foreground text-sm">
          Edit the YAML policy with schema validation and completion, see what it would have changed
          on the last 7 days of traffic, then deploy it as a new version.
        </p>
      </div>
      <PolicyWorkbench />
    </section>
  );
}
