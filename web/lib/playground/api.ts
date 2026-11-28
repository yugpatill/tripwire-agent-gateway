import { api, unwrap } from "@/lib/api/client";

import type { RunRecord, ScenariosResponse, StartResponse } from "./types";

// The playground endpoints return free-form JSON in the OpenAPI schema; the
// shapes are declared in ./types.
export async function fetchScenarios(): Promise<ScenariosResponse> {
  return (await unwrap(api.GET("/v1/playground/scenarios"))) as unknown as ScenariosResponse;
}

export async function startRun(
  body: { scenario_id: string } | { custom: { task_id: string; text: string } },
): Promise<StartResponse> {
  return (await unwrap(
    api.POST("/v1/playground/run", { body: body as never }),
  )) as unknown as StartResponse;
}

export async function fetchRun(runId: string): Promise<RunRecord> {
  return (await unwrap(
    api.GET("/v1/playground/runs/{run_id}", { params: { path: { run_id: runId } } }),
  )) as unknown as RunRecord;
}
