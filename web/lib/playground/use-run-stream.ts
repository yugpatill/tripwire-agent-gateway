"use client";

import { useQuery } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState } from "react";

import { WS_URL } from "@/lib/api/config";
import { connectWs, type WsStatus } from "@/lib/ws";

import { fetchRun } from "./api";
import type { RunEvent } from "./types";

/**
 * Streams a run's events over the gateway WebSocket (live runs as they happen,
 * stored runs and replays paced like the original), deduped by `seq`, then loads
 * the full run record once the run is complete.
 */
export function useRunStream(runId: string) {
  const [generation, setGeneration] = useState(0);
  // Events belong to one stream (run + replay count); a new stream starts empty.
  const key = `${runId}#${generation}`;
  const [stream, setStream] = useState<{ key: string; events: RunEvent[] }>({ key, events: [] });
  const [status, setStatus] = useState<WsStatus>("connecting");
  const seen = useRef(new Set<number>());
  const done = useRef(false);
  const events = stream.key === key ? stream.events : [];

  useEffect(() => {
    seen.current = new Set();
    done.current = false;
    const stop = connectWs<RunEvent>(
      `${WS_URL}/v1/playground/runs/${encodeURIComponent(runId)}/stream`,
      {
        onMessage: (ev) => {
          if (seen.current.has(ev.seq)) return;
          seen.current.add(ev.seq);
          if (ev.type === "run.completed") done.current = true;
          setStream((prev) => ({
            key,
            events: [...(prev.key === key ? prev.events : []), ev].sort((a, b) => a.seq - b.seq),
          }));
        },
        onStatus: setStatus,
        shouldReconnect: () => !done.current,
      },
    );
    return stop;
  }, [runId, key]);

  const complete = events.some((e) => e.type === "run.completed");
  const record = useQuery({
    queryKey: ["playground-run", runId],
    queryFn: () => fetchRun(runId),
    enabled: complete,
    staleTime: Infinity,
  });

  const replay = useCallback(() => setGeneration((g) => g + 1), []);
  return { events, status, complete, record: record.data, replay };
}
