/** A line diff (LCS), for side-by-side views of small texts such as tool manifests. */

export type DiffRow =
  | { kind: "same"; left: string; right: string }
  | { kind: "changed"; left: string | null; right: string | null };

export function diffLines(before: string, after: string): DiffRow[] {
  const a = before.split("\n");
  const b = after.split("\n");
  const n = a.length;
  const m = b.length;
  // lcs[i][j]: length of the LCS of a[i:] and b[j:]
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--)
    for (let j = m - 1; j >= 0; j--)
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);

  const rows: DiffRow[] = [];
  let removed: string[] = [];
  let added: string[] = [];
  const flush = () => {
    for (let k = 0; k < Math.max(removed.length, added.length); k++)
      rows.push({ kind: "changed", left: removed[k] ?? null, right: added[k] ?? null });
    removed = [];
    added = [];
  };
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && a[i] === b[j]) {
      flush();
      rows.push({ kind: "same", left: a[i], right: b[j] });
      i++;
      j++;
    } else if (j < m && (i === n || lcs[i][j + 1] >= lcs[i + 1][j])) {
      added.push(b[j++]);
    } else {
      removed.push(a[i++]);
    }
  }
  flush();
  return rows;
}

/** A manifest as reviewable text: description, then the input schema. */
export function manifestText(m: Record<string, unknown> | null | undefined): string {
  if (!m) return "";
  return [
    `name: ${String(m.name ?? "")}`,
    "description:",
    ...String(m.description ?? "").split("\n").map((l) => `  ${l}`),
    "input_schema:",
    ...JSON.stringify(m.input_schema ?? {}, null, 2).split("\n").map((l) => `  ${l}`),
  ].join("\n");
}
