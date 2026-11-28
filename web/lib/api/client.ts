import createClient from "openapi-fetch";

import { API_URL } from "./config";
import type { paths } from "./schema";

/** Typed client for the gateway's REST API (generated from its OpenAPI schema). */
export const api = createClient<paths>({ baseUrl: API_URL, credentials: "include" });

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

/** Return `data` or throw an ApiError carrying the gateway's `detail` message. */
export async function unwrap<T>(
  request: Promise<{ data?: T; error?: unknown; response: Response }>,
): Promise<T> {
  const { data, error, response } = await request;
  if (error !== undefined || data === undefined) {
    const detail =
      error && typeof error === "object" && "detail" in error
        ? String((error as { detail: unknown }).detail)
        : response.statusText;
    throw new ApiError(response.status, detail || `Request failed (${response.status})`);
  }
  return data;
}
