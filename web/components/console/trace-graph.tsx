"use client";

import "@xyflow/react/dist/style.css";

import { useQuery } from "@tanstack/react-query";
import { Background, Controls, type Edge, type Node, ReactFlow } from "@xyflow/react";
import { Lock } from "lucide-react";
import { useMemo, useState } from "react";

import { Skeleton } from "@/components/ui/skeleton";
import { type EventView, fetchTrace } from "@/lib/console/api";

import { type Provenance, TaintBadge } from "./badges";
import { useConsoleUser } from "./console-gate";
import { EventDrawer } from "./event-drawer";

interface FlowEdge {
  from_event: string;
  to_event: string;
  arg: string;
  matched_value: string;
  match: string;
  label: Provenance;
}

const COLORS = {
  red: "#ef4444",
  amber: "#f59e0b",
  orange: "#f97316",
  purple: "#a855f7",
  grey: "#71717a",
};

function nodeStyle(border: string): React.CSSProperties {
  return {
    width: 170,
    padding: "6px 8px",
    borderRadius: 6,
    border: `1.5px solid ${border}`,
    background: `${border}1f`,
    color: "var(--foreground)",
    fontSize: 12,
    textAlign: "left",
  };
}

function resultColor(e: EventView): string {
  const res = ((e.labels as Record<string, unknown>).result ?? []) as Provenance[];
  const p = res[0];
  if (!p) return COLORS.grey;
  if (p.trust === "suspicious") return COLORS.red;
  if (p.trust === "untrusted") return COLORS.orange;
  if (p.confidentiality === "secret" || p.confidentiality === "confidential") return COLORS.purple;
  return COLORS.grey;
}

function edgeColor(p: Provenance): string {
  if (p.trust === "suspicious") return COLORS.red;
  if (p.trust.startsWith("untrusted")) return COLORS.orange;
  if (p.confidentiality === "secret" || p.confidentiality === "confidential") return COLORS.purple;
  return COLORS.grey;
}

function build(sessionId: string, events: EventView[], flows: FlowEdge[], hovered: string | null) {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const resultOf = new Map<string, EventView>();
  for (const e of events) {
    if (e.kind === "result") {
      const call = (e.payload as { call_event_id?: string }).call_event_id;
      if (call) resultOf.set(call, e);
    }
  }
  nodes.push({
    id: sessionId,
    position: { x: 0, y: 0 },
    data: { label: "User prompt (trusted)" },
    style: nodeStyle(COLORS.grey),
    draggable: false,
  });
  let col = 1;
  for (const e of events.filter((x) => x.kind === "call")) {
    const stopped = e.enforced_action === "block";
    const held = e.enforced_action === "require_approval";
    nodes.push({
      id: e.id,
      position: { x: col * 210, y: 0 },
      data: {
        label: (
          <span className="flex items-start gap-1">
            {stopped && <Lock className="mt-0.5 size-3 shrink-0 text-red-500" aria-label="blocked" />}
            <span>
              <span className="font-mono">{e.tool}</span>
              <br />
              <span className="text-muted-foreground">
                {e.enforced_action.replace("_", " ")}
                {e.rule_id ? ` · ${e.rule_id}` : ""}
              </span>
            </span>
          </span>
        ),
      },
      style: nodeStyle(stopped ? COLORS.red : held ? COLORS.amber : COLORS.grey),
      draggable: false,
    });
    const r = resultOf.get(e.id);
    if (r) {
      nodes.push({
        id: r.id,
        position: { x: col * 210, y: 130 },
        data: { label: <span>result of <span className="font-mono">{r.tool}</span></span> },
        style: nodeStyle(resultColor(r)),
        draggable: false,
      });
      edges.push({ id: `${e.id}>${r.id}`, source: e.id, target: r.id, style: { stroke: COLORS.grey } });
    }
    col += 1;
  }
  const known = new Set(nodes.map((n) => n.id));
  flows.forEach((f, i) => {
    if (!known.has(f.from_event) || !known.has(f.to_event)) return;
    const id = `flow-${i}`;
    edges.push({
      id,
      source: f.from_event,
      target: f.to_event,
      animated: true,
      label: hovered === id ? `${f.arg} ← “${f.matched_value.slice(0, 40)}”` : f.arg,
      labelStyle: { fill: "var(--foreground)", fontSize: 11 },
      labelBgStyle: { fill: "var(--background)" },
      style: { stroke: edgeColor(f.label), strokeWidth: hovered === id ? 2.5 : 1.5 },
    });
  });
  return { nodes, edges };
}

export function TraceGraph({ sessionId }: { sessionId: string }) {
  const me = useConsoleUser();
  const { data, isLoading, error } = useQuery({
    queryKey: ["trace", sessionId],
    queryFn: () => fetchTrace(sessionId),
    enabled: me !== null,
  });
  const [hovered, setHovered] = useState<string | null>(null);
  const [open, setOpen] = useState<EventView | null>(null);
  const flows = useMemo(() => (data?.edges ?? []) as unknown as FlowEdge[], [data]);
  const graph = useMemo(
    () => (data ? build(sessionId, data.events, flows, hovered) : { nodes: [], edges: [] }),
    [data, flows, hovered, sessionId],
  );
  const hoveredFlow = hovered ? flows[Number(hovered.replace("flow-", ""))] : undefined;

  if (isLoading || !me) return <Skeleton className="h-[60vh]" />;
  if (error || !data) return <p className="text-sm text-red-500">Could not load this session.</p>;

  return (
    <div className="space-y-4">
      <div className="space-y-1 text-sm">
        <p>
          <span className="text-muted-foreground">Agent:</span> {data.session.agent_name}
          {data.session.key_name && <span className="text-muted-foreground"> (key {data.session.key_name})</span>} ·{" "}
          {data.session.events} events · {data.session.stopped} stopped · mode {data.session.mode}
        </p>
        {data.session.user_prompt && (
          <p>
            <span className="text-muted-foreground">User prompt:</span> {data.session.user_prompt}
          </p>
        )}
      </div>
      <div className="h-[60vh] rounded-lg border" aria-label="Session trace graph">
        <ReactFlow
          nodes={graph.nodes}
          edges={graph.edges}
          fitView
          colorMode="dark"
          nodesConnectable={false}
          onEdgeMouseEnter={(_, edge) => edge.id.startsWith("flow-") && setHovered(edge.id)}
          onEdgeMouseLeave={() => setHovered(null)}
          onNodeClick={(_, node) => setOpen(data.events.find((e) => e.id === node.id) ?? null)}
        >
          <Background gap={16} size={1} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
      <div className="text-muted-foreground min-h-6 text-sm" aria-live="polite">
        {hoveredFlow ? (
          <span className="flex flex-wrap items-center gap-2">
            <span className="text-foreground font-mono">{hoveredFlow.arg}</span> got “{hoveredFlow.matched_value}” ({hoveredFlow.match}) from
            <TaintBadge p={hoveredFlow.label} />
          </span>
        ) : (
          "Hover a colored edge to see the value that flowed; click a node for details. Orange: untrusted, red: suspicious, purple: confidential."
        )}
      </div>
      <EventDrawer event={open} onClose={() => setOpen(null)} />
    </div>
  );
}
