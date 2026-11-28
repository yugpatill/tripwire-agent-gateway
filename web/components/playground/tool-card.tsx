"use client";

import { motion } from "motion/react";
import { AlertTriangle, Loader2, ShieldAlert, Wrench } from "lucide-react";
import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { ruleText } from "@/lib/playground/rules";
import type { ToolResultEvent } from "@/lib/playground/types";

import { HighlightedText } from "./highlighted-text";
import { WhyDrawer } from "./why-drawer";

const PREVIEW = 500;

function Args({ args }: { args: Record<string, unknown> }) {
  const text = JSON.stringify(args, null, 1);
  return (
    <pre className="bg-muted/50 overflow-x-auto rounded px-2 py-1 font-mono text-[11px] leading-snug whitespace-pre-wrap break-all">
      {text.length > 600 ? `${text.slice(0, 600)}…` : text}
    </pre>
  );
}

export function PendingToolCard({ tool, args }: { tool: string; args: Record<string, unknown> }) {
  return (
    <div className="space-y-2 rounded-lg border p-3">
      <div className="flex items-center gap-2 text-sm">
        <Loader2 className="text-muted-foreground size-4 animate-spin" aria-hidden />
        <span className="font-mono">{tool}</span>
      </div>
      <Args args={args} />
    </div>
  );
}

/** A call Tripwire stopped: red (blocked) or amber (held for approval, then denied). */
export function BlockedCard({ event }: { event: ToolResultEvent }) {
  const held = event.status === "denied";
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.96 }}
      animate={{ opacity: 1, scale: 1, x: [0, -6, 6, -3, 3, 0] }}
      transition={{ duration: 0.45 }}
      className={`space-y-2 rounded-lg border-2 p-3 ${held ? "border-amber-500/70 bg-amber-500/5" : "border-red-500/70 bg-red-500/5"}`}
      role="status"
    >
      <div className="flex flex-wrap items-center gap-2">
        <ShieldAlert className={`size-5 ${held ? "text-amber-500" : "text-red-500"}`} aria-hidden />
        <span className="font-semibold">{held ? "Held for approval, then denied" : "Blocked by Tripwire"}</span>
        <Badge variant="outline" className="font-mono">
          {event.rule_id ?? "policy"}
        </Badge>
      </div>
      <p className="text-sm">{ruleText(event.rule_id, event.message)}</p>
      <p className="text-muted-foreground font-mono text-xs">{event.tool}</p>
      <Args args={event.args} />
      <WhyDrawer event={event} />
    </motion.div>
  );
}

export function ToolCard({ event, injected }: { event: ToolResultEvent; injected?: string }) {
  const [open, setOpen] = useState(false);
  if (event.status === "blocked" || event.status === "denied") return <BlockedCard event={event} />;
  const long = event.content.length > PREVIEW;
  const shown = open || !long ? event.content : `${event.content.slice(0, PREVIEW)}…`;
  return (
    <div className="space-y-2 rounded-lg border p-3">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Wrench className="text-muted-foreground size-4" aria-hidden />
        <span className="font-mono">{event.tool}</span>
        {event.flagged && (
          <Badge variant="outline" className="border-amber-500/60 text-amber-500">
            <AlertTriangle aria-hidden /> Injection detected
          </Badge>
        )}
        {event.status !== "allowed" && <Badge variant="outline">{event.status}</Badge>}
      </div>
      <Args args={event.args} />
      <div className="text-sm leading-relaxed whitespace-pre-wrap break-words">
        <HighlightedText text={shown} needle={injected} />
      </div>
      {long && (
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          className="text-muted-foreground text-xs underline underline-offset-2"
        >
          {open ? "Show less" : "Show all"}
        </button>
      )}
      {event.status === "error" && <p className="text-muted-foreground text-xs">{ruleText(null, event.message)}</p>}
    </div>
  );
}
