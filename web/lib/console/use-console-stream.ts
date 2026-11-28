"use client";

import { useEffect, useRef, useState } from "react";

import { WS_URL } from "@/lib/api/config";
import { connectWs, type WsStatus } from "@/lib/ws";

export interface ConsoleMessage {
  type: string;
  [key: string]: unknown;
}

/** The console's live feed (WS /v1/stream, session cookie), with auto reconnect. */
export function useConsoleStream(onMessage: (m: ConsoleMessage) => void, enabled = true) {
  const [status, setStatus] = useState<WsStatus>("connecting");
  const handler = useRef(onMessage);
  useEffect(() => {
    handler.current = onMessage;
  }, [onMessage]);
  useEffect(() => {
    if (!enabled) return;
    return connectWs<ConsoleMessage>(`${WS_URL}/v1/stream`, {
      onMessage: (m) => handler.current(m),
      onStatus: setStatus,
    });
  }, [enabled]);
  return status;
}
