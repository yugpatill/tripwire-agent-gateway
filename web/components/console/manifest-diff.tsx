import type { ReactNode } from "react";

import { diffLines, manifestText } from "@/lib/diff";
import { cn } from "@/lib/utils";

/** Pinned manifest on the left, the changed one on the right; changed lines in amber. */
export function ManifestDiff({
  before,
  after,
}: {
  before: Record<string, unknown> | null | undefined;
  after: Record<string, unknown> | null | undefined;
}) {
  const rows = diffLines(manifestText(before), manifestText(after));
  return (
    <div className="overflow-x-auto rounded-md border">
      <table className="w-full table-fixed font-mono text-[11px]">
        <caption className="sr-only">Pinned manifest compared with the current one</caption>
        <thead className="text-muted-foreground border-b text-left">
          <tr>
            <th scope="col" className="px-2 py-1 font-medium">Pinned (approved)</th>
            <th scope="col" className="border-l px-2 py-1 font-medium">Current (blocked)</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="align-top">
              <td
                className={cn(
                  "px-2 whitespace-pre-wrap break-all",
                  r.kind === "changed" && r.left !== null && "bg-red-500/10 text-red-400",
                )}
              >
                {r.kind === "changed" && r.left !== null && <span aria-label="removed">− </span>}
                {r.left ?? ""}
              </td>
              <td
                className={cn(
                  "border-l px-2 whitespace-pre-wrap break-all",
                  r.kind === "changed" && r.right !== null && "bg-amber-500/10 text-amber-400",
                )}
              >
                {r.kind === "changed" && r.right !== null && <span aria-label="added">+ </span>}
                {r.right ?? ""}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export interface Finding {
  rule: string;
  field: string;
  weight: number;
  excerpt: string;
}

/** Text with each finding's excerpt marked in red. */
export function FlaggedText({ text, findings }: { text: string; findings: Finding[] }) {
  const spans: { start: number; end: number; rule: string }[] = [];
  for (const f of findings) {
    const ex = f.excerpt.replace(/^…|…$/g, "").trim();
    if (ex.length < 4) continue;
    const at = text.indexOf(ex);
    if (at >= 0) spans.push({ start: at, end: at + ex.length, rule: f.rule });
  }
  spans.sort((x, y) => x.start - y.start);
  const out: ReactNode[] = [];
  let pos = 0;
  for (const s of spans) {
    if (s.start < pos) continue;
    out.push(text.slice(pos, s.start));
    out.push(
      <mark
        key={s.start}
        title={s.rule}
        className="bg-red-500/10 text-inherit underline decoration-red-500 decoration-wavy underline-offset-2"
      >
        {text.slice(s.start, s.end)}
      </mark>,
    );
    pos = s.end;
  }
  out.push(text.slice(pos));
  return <p className="text-sm whitespace-pre-wrap">{out}</p>;
}

export function FindingsList({ findings }: { findings: Finding[] }) {
  if (!findings.length) return <p className="text-muted-foreground text-sm">No findings.</p>;
  return (
    <ul className="space-y-1.5 text-sm">
      {findings.map((f, i) => (
        <li key={i} className="flex flex-wrap items-baseline gap-2">
          <span className="rounded border border-red-500/50 px-1.5 font-mono text-[11px] text-red-400">{f.rule}</span>
          <span className="text-muted-foreground font-mono text-[11px]">{f.field}</span>
          <q className="min-w-0 break-words">{f.excerpt}</q>
        </li>
      ))}
    </ul>
  );
}
