import createClient from "openapi-fetch";

import { API_URL } from "./config";
import type { paths } from "./schema";

/** Typed client for the gateway's REST API (generated from its OpenAPI schema). */
export const api = createClient<paths>({ baseUrl: API_URL, credentials: "include" });

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    /** The gateway's `detail`, as sent (a string, or an object such as policy errors). */
    public detail?: unknown,
  ) {
    super(message);
  }
}

function describe(detail: unknown): string {
  if (typeof detail === "string") return detail;
  if (detail && typeof detail === "object" && "message" in detail) {
    return String((detail as { message: unknown }).message);
  }
  return detail === undefined ? "" : JSON.stringify(detail);
}

/** Return `data` or throw an ApiError carrying the gateway's `detail`. */
export async function unwrap<T>(
  request: Promise<{ data?: T; error?: unknown; response: Response }>,
): Promise<T> {
  const { data, error, response } = await request;
  if (error !== undefined || data === undefined) {
    const detail =
      error && typeof error === "object" && "detail" in error ? (error as { detail: unknown }).detail : undefined;
    const message = describe(detail) || response.statusText;
    throw new ApiError(response.status, message || `Request failed (${response.status})`, detail);
  }
  return data;
}
