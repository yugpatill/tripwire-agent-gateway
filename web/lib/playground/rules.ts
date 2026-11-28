/** Plain-English explanations for the rules the playground can trigger. */
export const RULE_TEXT: Record<string, string> = {
  "no-untrusted-recipient":
    "The recipient address came from content the agent read (a web page, an email, a document), not from the user.",
  "no-untrusted-payee":
    "The account number came from content the agent read, not from the user.",
  "no-secret-exfil-via-url":
    "A secret was read in this session, so requests to outside URLs are blocked: the URL could carry the secret out.",
  "confidential-to-external":
    "Confidential data is in this session and the recipient is outside the company.",
  "suspicious-session-sinks":
    "This session read content that looks like a prompt injection, so outbound actions need a human's approval. The playground has no operator, so the request was denied.",
  "manifest-quarantine":
    "The tool's description contains hidden instructions (tool poisoning). Tripwire quarantined it, so the agent never saw or used it.",
  "manifest-rug-pull":
    "The tool changed its description after it was first approved (a rug pull). Tripwire hid and blocked it until someone reviews the change.",
  "transfer-rate-limit": "Too many transfers in one session.",
};

export function ruleText(ruleId: string | null | undefined, fallback = ""): string {
  return (ruleId && RULE_TEXT[ruleId]) || fallback || "Blocked by the active policy.";
}
