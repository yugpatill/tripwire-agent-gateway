"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";

import { Skeleton } from "@/components/ui/skeleton";
import { fetchSessions } from "@/lib/console/api";

import { useConsoleUser } from "./console-gate";

export function SessionsList() {
  const me = useConsoleUser();
  const { data, isLoading } = useQuery({ queryKey: ["sessions"], queryFn: () => fetchSessions(100), enabled: me !== null });
  return (
    <div className="overflow-x-auto rounded-lg border">
      <table className="w-full min-w-[640px] text-sm">
        <thead className="text-muted-foreground border-b text-left text-xs">
          <tr>
            <th className="px-3 py-2 font-medium">Last activity</th>
            <th className="px-3 py-2 font-medium">Agent</th>
            <th className="px-3 py-2 font-medium">User prompt</th>
            <th className="px-3 py-2 text-right font-medium">Events</th>
            <th className="px-3 py-2 text-right font-medium">Stopped</th>
          </tr>
        </thead>
        <tbody>
          {(isLoading || !me) && (
            <tr>
              <td colSpan={5} className="p-3">
                <Skeleton className="h-24" />
              </td>
            </tr>
          )}
          {data?.map((s) => (
            <tr key={s.id} className="hover:bg-muted/50 border-b last:border-0">
              <td className="px-3 py-1.5 whitespace-nowrap">
                <Link href={`/console/traces/${s.id}`} className="underline-offset-2 hover:underline">
                  {s.last_event_at ? new Date(s.last_event_at).toLocaleString() : "—"}
                </Link>
              </td>
              <td className="px-3 py-1.5">{s.agent_name}</td>
              <td className="text-muted-foreground max-w-md truncate px-3 py-1.5">{s.user_prompt}</td>
              <td className="px-3 py-1.5 text-right tabular-nums">{s.events}</td>
              <td className={`px-3 py-1.5 text-right tabular-nums ${s.stopped ? "text-red-500" : ""}`}>{s.stopped}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
