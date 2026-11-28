"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Play } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError } from "@/lib/api/client";
import { fetchScenarios, startRun } from "@/lib/playground/api";

import { CustomAttackDialog } from "./custom-attack-dialog";

export function ScenarioGrid() {
  const router = useRouter();
  const [starting, setStarting] = useState<string | null>(null);
  const { data, error, isLoading } = useQuery({ queryKey: ["playground-scenarios"], queryFn: fetchScenarios });

  const run = async (id: string) => {
    setStarting(id);
    try {
      const out = await startRun({ scenario_id: id });
      router.push(`/run/${out.run_id}${out.reason ? `?reason=${out.reason}` : ""}`);
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "Could not start a run");
      setStarting(null);
    }
  };

  return (
    <section id="scenarios" className="mx-auto w-full max-w-7xl space-y-6 px-4 pb-24 md:px-6" aria-labelledby="scenarios-title">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="space-y-1">
          <h2 id="scenarios-title" className="text-2xl font-semibold tracking-tight">
            Attack scenarios
          </h2>
          <p className="text-muted-foreground text-sm">
            {data?.live
              ? `Runs use ${data.model?.name}, up to ${data.limits.max_steps} steps.`
              : "No model is configured here, so runs are recorded replays and custom attacks use a simulated agent."}
          </p>
        </div>
        {data && <CustomAttackDialog tasks={data.custom_tasks} maxChars={data.custom_max_chars} live={data.live} />}
      </div>
      {error && <p className="text-sm text-red-500">The gateway is not reachable: {(error as Error).message}</p>}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {isLoading && Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-56" />)}
        {data?.presets.map((s) => (
          <Card key={s.id} className="flex flex-col">
            <CardHeader>
              <CardTitle>{s.title}</CardTitle>
              <CardDescription>{s.summary}</CardDescription>
            </CardHeader>
            <CardContent className="flex-1 space-y-2 text-sm">
              <p>
                <span className="text-muted-foreground">Task: </span>
                {s.task}
              </p>
              <p className="flex flex-wrap items-center gap-1">
                <span className="text-muted-foreground">Expected stop:</span>
                <Badge variant="outline" className="font-mono">
                  {s.expected_block.rule}
                </Badge>
              </p>
            </CardContent>
            <CardFooter className="flex flex-wrap gap-2">
              <Button size="sm" onClick={() => run(s.id)} disabled={starting !== null}>
                <Play aria-hidden /> {starting === s.id ? "Starting…" : "Run"}
              </Button>
              {s.replays?.available.includes("live") && (
                <Button variant="ghost" size="sm" nativeButton={false} render={<Link href={`/run/replay-${s.id}-live`} />}>
                  Real-model replay
                </Button>
              )}
            </CardFooter>
          </Card>
        ))}
      </div>
    </section>
  );
}
