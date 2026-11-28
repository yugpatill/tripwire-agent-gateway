"use client";

import "@xyflow/react/dist/style.css";

import { Background, type Edge, type Node, ReactFlow } from "@xyflow/react";
import { HelpCircle } from "lucide-react";
import { useMemo } from "react";

import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { ruleText } from "@/lib/playground/rules";
import type { ArgLabel, ToolResultEvent } from "@/lib/playground/types";

// Taint colors: orange untrusted, red suspicious / blocked, purple confidential.
const TONE = {
  untrusted: { border: "#f97316", bg: "rgba(249,115,22,0.12)" },
  suspicious: { border: "#ef4444", bg: "rgba(239,68,68,0.12)" },
  confidential: { border: "#a855f7", bg: "rgba(168,85,247,0.12)" },
  trusted: { border: "#71717a", bg: "rgba(113,113,122,0.15)" },
  blocked: { border: "#ef4444", bg: "rgba(239,68,68,0.22)" },
} as const;
type Tone = keyof typeof TONE;
const TRUST_TONE: Record<string, Tone> = {
  untrusted: "untrusted",
  untrusted_origin: "untrusted",
  suspicious: "suspicious",
  trusted: "trusted",
};
const COL = 175;
const ROW = 80;

function box(id: string, label: string, x: number, y: number, tone: Tone): Node {
  const t = TONE[tone];
  return {
    id,
    position: { x, y },
    data: { label },
    draggable: false,
    connectable: false,
    style: {
      width: 150,
      padding: "6px 8px",
      borderRadius: 6,
      border: `1.5px solid ${t.border}`,
      background: t.bg,
      color: "var(--foreground)",
      fontSize: 12,
      lineHeight: 1.3,
      textAlign: "left",
    },
  };
}

function edge(from: string, to: string, label?: string): Edge {
  return { id: `${from}-${to}`, source: from, target: to, label, animated: true };
}

function sourceLabel(l: ArgLabel): string {
  if (l.source === "user") return "Your request (trusted)";
  if (l.source.startsWith("unknown")) return "Unknown origin: not in anything the agent read or you typed";
  const conf = l.confidentiality === "secret" || l.confidentiality === "confidential";
  return `${l.source} result (${l.trust.replace("_", " ")}${conf ? `, ${l.confidentiality}` : ""})`;
}

/** A small taint path: where the data came from -> the argument -> the blocked call. */
function graph(ev: ToolResultEvent): { nodes: Node[]; edges: Edge[] } {
  const call = `call`;
  const callLabel = `${ev.tool}: ${ev.status === "blocked" ? "blocked" : "held, then denied"} by ${ev.rule_id ?? "policy"}`;
  if (ev.rule_id?.startsWith("manifest")) {
    const finding =
      ev.rule_id === "manifest-rug-pull"
        ? "Description changed after it was pinned (SHA-256 differs)"
        : "Description contains hidden instructions";
    return {
      nodes: [
        box("tool", `${ev.tool} tool description`, 0, 0, "untrusted"),
        box("finding", finding, COL, 0, "suspicious"),
        box(call, `Hidden from the agent; ${callLabel}`, 2 * COL, 0, "blocked"),
      ],
      edges: [edge("tool", "finding"), edge("finding", call)],
    };
  }
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const labels = Object.entries(ev.arg_labels ?? {});
  let row = 0;
  for (const [arg, ls] of labels) {
    const value = String(ev.args[arg] ?? "").slice(0, 60);
    const argId = `arg-${arg}`;
    nodes.push(box(argId, `${arg} = ${value}`, COL, row * ROW, "untrusted"));
    edges.push(edge(argId, call));
    ls.forEach((l, i) => {
      const id = `src-${arg}-${i}`;
      const tone: Tone =
        l.confidentiality === "secret" || l.confidentiality === "confidential"
          ? "confidential"
          : (TRUST_TONE[l.trust] ?? "trusted");
      nodes.push(box(id, sourceLabel(l), 0, (row + i) * ROW, tone));
      edges.push(edge(id, argId));
    });
    row += Math.max(1, ls.length);
  }
  if (!labels.length) {
    nodes.push(box("ctx", "Earlier tool result flagged as a prompt injection", 0, 0, "suspicious"));
    nodes.push(box("session", "Session marked suspicious", COL, 0, "suspicious"));
    edges.push(edge("ctx", "session"), edge("session", call));
  }
  nodes.push(box(call, callLabel, 2 * COL, Math.max(0, ((row || 1) - 1) * (ROW / 2)), "blocked"));
  return { nodes, edges };
}

export function WhyDrawer({ event }: { event: ToolResultEvent }) {
  const { nodes, edges } = useMemo(() => graph(event), [event]);
  return (
    <Sheet>
      <SheetTrigger render={<Button variant="outline" size="sm" />}>
        <HelpCircle aria-hidden /> Why?
      </SheetTrigger>
      <SheetContent side="right" className="w-full sm:max-w-xl">
        <SheetHeader>
          <SheetTitle>Why Tripwire stopped this call</SheetTitle>
          <SheetDescription>{ruleText(event.rule_id, event.message)}</SheetDescription>
        </SheetHeader>
        <div className="space-y-4 px-4 pb-6">
          <div className="h-72 rounded-md border" aria-label="Taint path">
            <ReactFlow
              nodes={nodes}
              edges={edges}
              fitView
              fitViewOptions={{ padding: 0.08, maxZoom: 1.1 }}
              nodesDraggable={false}
              nodesConnectable={false}
              elementsSelectable={false}
              panOnDrag={false}
              zoomOnScroll={false}
              zoomOnPinch={false}
              zoomOnDoubleClick={false}
              colorMode="dark"
            >
              <Background gap={16} size={1} />
            </ReactFlow>
          </div>
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
            <dt className="text-muted-foreground">Rule</dt>
            <dd className="font-mono">{event.rule_id ?? "policy"}</dd>
            <dt className="text-muted-foreground">Tool</dt>
            <dd className="font-mono">{event.tool}</dd>
            <dt className="text-muted-foreground">Gateway</dt>
            <dd>{event.message || event.content}</dd>
          </dl>
          <p className="text-muted-foreground text-xs">
            Orange: from untrusted content. Red: flagged as an injection. Purple: confidential or
            secret data.
          </p>
        </div>
      </SheetContent>
    </Sheet>
  );
}
