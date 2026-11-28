import type { Metadata } from "next";

import { ApprovalsQueue } from "@/components/console/approvals-queue";

export const metadata: Metadata = { title: "Approvals · Tripwire console" };

export default function ApprovalsPage() {
  return (
    <section className="space-y-4">
      <h1 className="text-2xl font-semibold tracking-tight">Approvals</h1>
      <ApprovalsQueue />
    </section>
  );
}
