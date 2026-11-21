# Limitations

What Tripwire cannot stop, stated plainly. Every item here is either covered by an `xfail` test (so CI notices if it changes) or is a design boundary. This file is extended in each phase. The design's definition of done ([design.md](design.md) section 10) requires the final version to cover paraphrased exfiltration, attacks within trusted tools, and model-level jailbreaks.

## Taint tracking (Phase 2)

### Covered evasions (for context)

From `gateway/tests/unit/test_taint_evasion.py`:

| Evasion | Caught by |
|---|---|
| Case changes (`ATTACKER@Evil.IO`) | value matching (entity, case-insensitive) |
| Homoglyph domain used verbatim | value matching (exact text) |
| URL-encoded address (`attacker%40evil.io`) | instruction origin (`untrusted_origin`) |
| Spelled out (`attacker at evil dot io`) | instruction origin |
| Base64-encoded address | instruction origin |
| Homoglyph domain invented by the model | instruction origin (Unicode-aware entity extraction) |
| Address split across args, one part 8+ characters | value matching (exact text) |

### Known bypasses

1. **Address split across arguments into short parts.** If an injection gets the agent to pass an address as several arguments that are each shorter than 8 characters and none is a full email, URL, path or 4+ digit number, no value matches and there is no entity for instruction origin. Example: `crm__invite(user="eve", domain="evil.io")`. Test: `test_split_address_with_short_parts_bypasses` (xfail, strict).
   *Mitigation:* describe such tools in the policy with `sink: true` and use `session_has`, `context_confidentiality_at_least`, or `require_approval` for high-risk sinks. Phase 3 detectors mark the page itself `suspicious` when it contains injection language.

2. **Decoded or rewritten values in a clean context.** Instruction origin only applies once untrusted content has entered the session. A rewritten value in a session that has seen no untrusted content gets no label. This is intended (no untrusted source exists), but a compromised *trusted* tool is not detected. See "Attacks within trusted tools" below.

3. **Instruction origin is coarse.** Any email, URL, path or long number that came from neither the user nor a tool result is labelled `untrusted_origin` once untrusted content is in context, including values the model legitimately produced (for example, an address it inferred correctly). Policies should pair `untrusted_origin` with `require_approval` rather than `block` where false positives are costly.

4. **Short values are not text-matched.** Residual text under 8 characters is ignored to avoid false links (for example "notes", "yes"). Short secrets or codes copied from untrusted content carry no label unless they are 4+ digit numbers.

5. **Homoglyphs are not folded.** `evіl.io` (Cyrillic) and `evil.io` (Latin) are different entities. A lookalike is caught as untrusted or untrusted_origin, but Tripwire does not warn that it imitates a real domain.

## Injection detection (Phase 3)

Numbers and method: [detection.md](detection.md).

1. **Paraphrased overrides evade the heuristics.** Rules match known idioms. A held-out set written after tuning caught only 2 of 5 paraphrased overrides, for example "Discard the earlier brief entirely…" and "ignore *each of* your prior instructions…". Closing this gap is the classifier's job (Phase 4). Until it ships, paraphrased injections are caught only when they also trip another signal (a hidden channel, a role marker, secrecy language) or when taint rules stop the resulting tool call.
2. **Heuristics cannot tell quoting from attacking.** A security article that quotes a working payload verbatim is flagged (6/6 in `quoted_payloads.jsonl`). This is arguably correct, because an agent reading it can still be hijacked, but it is noise for security-research workflows. Use the LLM judge, or a per-tool `trust` override, for such sources.
3. **The benchmark corpus is author-written.** The benign and attack sets were written by the same person who wrote the rules. The tuned-set numbers are optimistic; the held-out numbers are the better estimate. Phase 9 evaluates on AgentDojo and external data.
4. **Lookalike folding is partial.** Common Cyrillic and Greek lookalikes are folded before matching. Other scripts, mathematical alphanumerics outside NFKC, and leetspeak (`1gn0re`) are not.
5. **PII in pattern mode skips names and places.** PERSON and LOCATION need `TRIPWIRE_PII_MODE=ner`, which is slower and marks almost every email confidential.
6. **Long outputs are only partly classified.** To bound latency, an output longer than 8 classifier windows (about 4,000 tokens, roughly 16 KB of English) is classified only on its first 4 and last 4 windows, plus any window that overlaps a weak heuristic signal. An injection placed in the middle of a long document, phrased so that it trips no heuristic at all, is not seen by the classifier (test: `test_long_input_middle_trigger_missed_without_focus`). The heuristics still scan the whole text, and taint rules still apply to whatever the agent does next. Raising `MAX_FULL_WINDOWS` trades latency for coverage. See [performance.md](performance.md).
7. **Heuristics run without a classifier when they are already confident.** If the heuristic score reaches `classifier_threshold`, the classifier is skipped (early exit). This only saves time: the content is already treated as suspicious.
8. **Long documents about prompts and LLMs can be flagged.** Weak signals combine only within 500 characters, and rules weaker than 0.4 cannot combine with each other. Even so, 50 KB of developer documentation dense with "system prompt", "User:/Assistant:" transcripts and "new instructions" phrasing scores about 0.75–0.85 and is marked suspicious. Ordinary long pages (emails, tickets, API JSON, web pages) score 0.45 or less. Use the LLM judge or a per-tool `trust` override for documentation sources.

## Attacks within trusted tools

Data returned by a tool the policy marks `trust: trusted` is trusted. If that tool is compromised, or relays attacker content (for example a CRM that stores whatever a web form submitted), Tripwire treats its output as trusted. Mark such tools `untrusted`.

## Paraphrased exfiltration

If the agent summarizes confidential data in its own words and sends it out, value matching sees no shared text. Context taint still applies: `context_confidentiality_at_least` rules see that confidential data was read in the session, and they are the intended control.
