/**
 * WebSocket with automatic reconnect (exponential backoff with jitter).
 * Live views use this; callers dedupe messages if the server replays history.
 */
export type WsStatus = "connecting" | "open" | "closed";

export interface WsOptions<T> {
  onMessage: (message: T) => void;
  onStatus?: (status: WsStatus) => void;
  /** Return false to stop reconnecting (for example once a stream is complete). */
  shouldReconnect?: () => boolean;
  maxDelayMs?: number;
}

export function connectWs<T>(url: string, options: WsOptions<T>): () => void {
  let socket: WebSocket | null = null;
  let attempt = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let stopped = false;
  const maxDelay = options.maxDelayMs ?? 10_000;

  const open = () => {
    if (stopped) return;
    options.onStatus?.("connecting");
    socket = new WebSocket(url);
    socket.onopen = () => {
      attempt = 0;
      options.onStatus?.("open");
    };
    socket.onmessage = (event) => {
      try {
        options.onMessage(JSON.parse(event.data as string) as T);
      } catch {
        // Ignore malformed frames.
      }
    };
    socket.onclose = () => {
      options.onStatus?.("closed");
      if (stopped || options.shouldReconnect?.() === false) return;
      const delay = Math.min(maxDelay, 500 * 2 ** attempt) * (0.75 + Math.random() * 0.5);
      attempt += 1;
      timer = setTimeout(open, delay);
    };
  };

  open();
  return () => {
    stopped = true;
    if (timer) clearTimeout(timer);
    socket?.close();
  };
}
