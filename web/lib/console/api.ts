import { api, unwrap } from "@/lib/api/client";
import type { components } from "@/lib/api/schema";

export type EventView = components["schemas"]["EventView"];
export type EventPage = components["schemas"]["EventPage"];
export type SessionView = components["schemas"]["SessionView"];
export type Trace = components["schemas"]["Trace"];
export type Summary = components["schemas"]["Summary"];

export interface EventFilters {
  kind?: "call" | "result";
  action?: string;
  tool?: string;
  rule_id?: string;
  session_id?: string;
  before?: string;
}

export const fetchEvents = (filters: EventFilters, limit = 50) =>
  unwrap(api.GET("/v1/events", { params: { query: { ...filters, limit } } }));

export const fetchSessions = (limit = 50) =>
  unwrap(api.GET("/v1/sessions", { params: { query: { limit } } }));

export const fetchTrace = (sessionId: string) =>
  unwrap(api.GET("/v1/sessions/{session_id}/trace", { params: { path: { session_id: sessionId } } }));

export const fetchSummary = (hours: number) =>
  unwrap(api.GET("/v1/metrics/summary", { params: { query: { hours } } }));

// ---------------------------------------------------------------- approvals and tools

export type ApprovalRecord = components["schemas"]["ApprovalRecord"];
export type ToolPinView = components["schemas"]["ToolPinView"];

export const fetchApprovals = (status: "pending" | "approved" | "denied" | "expired" | undefined, limit = 100) =>
  unwrap(api.GET("/v1/approvals", { params: { query: { status, limit } } }));

export const decideApproval = (id: string, decision: "approve" | "deny", scope: "once" | "session" = "once") =>
  unwrap(
    api.POST("/v1/approvals/{approval_id}", {
      params: { path: { approval_id: id } },
      body: { decision, scope },
    }),
  );

export const fetchTools = () => unwrap(api.GET("/v1/tools"));

export const approveTool = (name: string) =>
  unwrap(api.POST("/v1/tools/{name}/approve", { params: { path: { name } } }));

// ---------------------------------------------------------------- policy

export type ActivePolicy = components["schemas"]["ActivePolicy"];
export type PolicyTestResult = components["schemas"]["TestResult"];
export type PolicyMode = components["schemas"]["ModeView"]["mode"];

export interface PolicyErrorItem {
  loc: string;
  message: string;
  line: number | null;
  column: number | null;
}

export const fetchPolicy = () => unwrap(api.GET("/v1/policies/active"));
export const fetchPolicySchema = () =>
  unwrap(api.GET("/v1/policies/schema")) as Promise<Record<string, unknown>>;
export const deployPolicy = (yaml: string) => unwrap(api.PUT("/v1/policies/active", { body: { yaml } }));
export const testPolicy = (yaml: string, sinceHours = 168) =>
  unwrap(api.POST("/v1/policies/test", { body: { yaml }, params: { query: { since_hours: sinceHours } } }));
export const fetchMode = () => unwrap(api.GET("/v1/policies/mode"));
export const setMode = (mode: PolicyMode) => unwrap(api.PUT("/v1/policies/mode", { body: { mode } }));
