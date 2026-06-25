//! Decision wire types — the audit NDJSON the daemon emits on stdout.
//!
//! These mirror the Rust `Decision` / `EnforceAction` / `Audit` serialization exactly:
//!   - `verdict` is lowercase (`"allow" | "block" | "escalate"`)
//!   - `tier` is PascalCase (`"Rules" | "Llm" | "Agent"`)
//!   - `severity` is lowercase (`"info" .. "critical"`)
//!   - `action` is an externally-tagged enum: `{"DenyEgress": "1.2.3.4"}`
//!
//! The daemon emits an audit line ONLY for blocks, escalations, and flagged-but-allowed events —
//! plain benign allows are counted, not printed.

/** A tier's conclusion about an event. Lowercase to match the Rust serialization. */
export type Verdict = "allow" | "block" | "escalate";

/** Severity of a finding, independent of the verdict. Lowercase to match Rust. */
export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** Which tier produced a decision. PascalCase to match the Rust `Tier` serialization. */
export type Tier = "Rules" | "Llm" | "Agent";

/** The kind of a concrete deny pushed to observer's deny-files. */
export type EnforceKind = "DenyEgress" | "DenyFile" | "DenyExec";

/**
 * A concrete block to enforce. The Rust enum is externally tagged on the wire
 * (`{"DenyEgress": "1.2.3.4"}`); this is the parsed, flattened form.
 */
export interface EnforceAction {
  /** Which deny-file this targets. */
  readonly kind: EnforceKind;
  /** The IP/host (egress), or path (file/exec binary). */
  readonly target: string;
}

/** A tier's full conclusion about one event. */
export interface Decision {
  readonly verdict: Verdict;
  readonly tier: Tier;
  readonly severity: Severity;
  readonly reason: string;
  /** Present only on a block that carries a concrete deny target. */
  readonly action?: EnforceAction;
}

/** One audit record — exactly what `Sentry.decisions()` yields, one per non-allow event. */
export interface Audit {
  /** Resolved agent identity, if observer supplied one. */
  readonly agent?: string;
  /** Event variant name: `"ToolExec" | "Egress" | "FileAccess" | "Dns" | "SslContent" | "SecurityAction"`. */
  readonly event: string;
  /** The matched subject text (argv, peer:port, path, query, content, …), truncated to 300 chars by the daemon. */
  readonly subject: string;
  readonly decision: Decision;
  /** The deny-file path that was written, if a block landed. */
  readonly enforced?: string;
}

const ENFORCE_KINDS: readonly EnforceKind[] = ["DenyEgress", "DenyFile", "DenyExec"];

/**
 * Parse the externally-tagged action object (`{"DenyEgress": "1.2.3.4"}`) into `{kind, target}`.
 * Returns `undefined` if the value is absent or not a recognized tag.
 */
export function parseEnforceAction(raw: unknown): EnforceAction | undefined {
  if (raw === null || typeof raw !== "object") {
    return undefined;
  }
  const obj = raw as Record<string, unknown>;
  for (const kind of ENFORCE_KINDS) {
    const target = obj[kind];
    if (typeof target === "string") {
      return { kind, target };
    }
  }
  return undefined;
}

/** Parse the `decision` sub-object of an audit line. */
export function parseDecision(raw: unknown): Decision {
  if (raw === null || typeof raw !== "object") {
    throw new TypeError("decision: expected an object");
  }
  const obj = raw as Record<string, unknown>;
  if (typeof obj["verdict"] !== "string") {
    throw new TypeError("decision.verdict: expected a string");
  }
  if (typeof obj["tier"] !== "string") {
    throw new TypeError("decision.tier: expected a string");
  }
  if (typeof obj["severity"] !== "string") {
    throw new TypeError("decision.severity: expected a string");
  }
  const action = parseEnforceAction(obj["action"]);
  const decision: Decision = {
    verdict: obj["verdict"] as Verdict,
    tier: obj["tier"] as Tier,
    severity: obj["severity"] as Severity,
    reason: typeof obj["reason"] === "string" ? obj["reason"] : "",
    ...(action ? { action } : {}),
  };
  return decision;
}

/**
 * Parse one audit NDJSON line into a typed {@link Audit}.
 * Throws on malformed JSON or a missing `decision`/`event`; callers that stream should catch
 * and skip (as `Sentry.decisions()` does).
 */
export function parseAudit(line: string): Audit {
  const raw = JSON.parse(line) as Record<string, unknown>;
  if (typeof raw["event"] !== "string") {
    throw new TypeError("audit.event: expected a string");
  }
  const audit: Audit = {
    event: raw["event"],
    subject: typeof raw["subject"] === "string" ? raw["subject"] : "",
    decision: parseDecision(raw["decision"]),
    ...(typeof raw["agent"] === "string" ? { agent: raw["agent"] } : {}),
    ...(typeof raw["enforced"] === "string" ? { enforced: raw["enforced"] } : {}),
  };
  return audit;
}
