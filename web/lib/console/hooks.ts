"use client";

import { useEffect, useState } from "react";

import { useMe } from "./auth";

/**
 * The current time, updated every `ms` (for countdowns). 0 until mounted: the
 * clock is read only in the browser, never while prerendering.
 */
export function useNow(ms = 1000): number {
  const [now, setNow] = useState(0);
  useEffect(() => {
    const tick = () => setNow(Date.now());
    const first = setTimeout(tick, 0);
    const t = setInterval(tick, ms);
    return () => {
      clearTimeout(first);
      clearInterval(t);
    };
  }, [ms]);
  return now;
}

/** Whether the signed-in user may change things (false for the read-only demo account). */
export function useCanWrite(): boolean {
  return useMe().data?.can_write ?? false;
}

export const READ_ONLY_HINT = "The demo account is read-only";
