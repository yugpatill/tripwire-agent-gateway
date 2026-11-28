import { Lock } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

/** Only red, amber and green carry action meaning. */
export function ActionBadge({ action }: { action: string }) {
  const tone =
    action === "block"
      ? "border-red-500/60 text-red-500"
      : action === "require_approval" || action === "redact"
        ? "border-amber-500/60 text-amber-500"
        : "text-muted-foreground";
  return (
    <Badge variant="outline" className={cn("font-mono", tone)}>
      {action === "block" && <Lock aria-hidden />}
      {action.replace("_", " ")}
    </Badge>
  );
}

export interface Provenance {
  source: string;
  trust: string;
  confidentiality: string;
}

/** Taint colors: orange untrusted, red suspicious, purple confidential. */
export function taintTone(p: Pick<Provenance, "trust" | "confidentiality">): string {
  if (p.trust === "suspicious") return "border-red-500/60 bg-red-500/10 text-red-400";
  if (p.trust === "untrusted" || p.trust === "untrusted_origin")
    return "border-orange-500/60 bg-orange-500/10 text-orange-400";
  if (p.confidentiality === "confidential" || p.confidentiality === "secret")
    return "border-purple-500/60 bg-purple-500/10 text-purple-400";
  return "border-border text-muted-foreground";
}

export function TaintBadge({ p }: { p: Provenance }) {
  const conf = p.confidentiality !== "public" ? ` · ${p.confidentiality}` : "";
  return (
    <span className={cn("inline-flex rounded border px-1.5 py-0.5 font-mono text-[11px]", taintTone(p))}>
      {p.source} · {p.trust.replace("_", " ")}
      {conf}
    </span>
  );
}
