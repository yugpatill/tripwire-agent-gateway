/** Text with the attacker's injected content underlined in red. */
export function HighlightedText({ text, needle }: { text: string; needle?: string }) {
  const parts = needle ? splitOn(text, needle) : [{ hit: false, value: text }];
  return (
    <>
      {parts.map((p, i) =>
        p.hit ? (
          <mark
            key={i}
            className="bg-red-500/10 text-inherit underline decoration-red-500 decoration-wavy underline-offset-2"
            title="Injected by the attacker"
          >
            {p.value}
          </mark>
        ) : (
          <span key={i}>{p.value}</span>
        ),
      )}
    </>
  );
}

function splitOn(text: string, needle: string): { hit: boolean; value: string }[] {
  // Match the whole injected text, or its first sentence when the tool shortened it.
  const candidates = [needle.trim(), needle.trim().split(/(?<=[.!?])\s/)[0]].filter(
    (c) => c.length >= 12,
  );
  for (const c of candidates) {
    const i = text.indexOf(c);
    if (i >= 0) {
      return [
        { hit: false, value: text.slice(0, i) },
        { hit: true, value: text.slice(i, i + c.length) },
        { hit: false, value: text.slice(i + c.length) },
      ].filter((p) => p.value);
    }
  }
  return [{ hit: false, value: text }];
}
