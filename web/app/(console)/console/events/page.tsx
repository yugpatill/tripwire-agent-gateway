import type { Metadata } from "next";

import { EventsTable } from "@/components/console/events-table";

export const metadata: Metadata = { title: "Events · Tripwire console" };

export default function EventsPage() {
  return (
    <section className="space-y-4">
      <h1 className="text-2xl font-semibold tracking-tight">Events</h1>
      <EventsTable />
    </section>
  );
}
