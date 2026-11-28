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
