import type { Metadata } from "next";

import { ToolsTable } from "@/components/console/tools-table";

export const metadata: Metadata = { title: "Tools · Tripwire console" };

export default function ToolsPage() {
  return (
    <section className="space-y-4">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Tools</h1>
        <p className="text-muted-foreground text-sm">
          Every tool is pinned by the hash of its description and schema the first time it is listed.
          Quarantined and changed tools are hidden from agents until an operator approves them.
        </p>
      </div>
      <ToolsTable />
    </section>
  );
}
