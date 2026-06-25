//! Policy authoring — the dynamic L1 rules the daemon hot-reloads from an ACL policy file.
//!
//! ACL is the a3s ecosystem's config language. A `Policy` is an ordered list of `Rule`s. It
//! serializes to the exact shape the daemon's deserializer expects:
//!
//! ```acl
//! rules = [
//!   {
//!     name = "block-nc"
//!     on = "ToolExec"
//!     match = "\\bnc\\b"
//!     verdict = "block"
//!     severity = "high"
//!     reason = "netcat"
//!     action = "deny-exec"
//!   }
//! ]
//! ```
//!
//! The ordered list form is deliberate: it preserves first-match-wins rule order. `Policy.write(path)`
//! writes atomically (temp file in the same dir + rename) so the daemon's ~2s hot-reload poll never
//! reads a half-written file. The conventional extension is `.acl`.

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { Severity, Verdict } from "./types.js";

/** The event kind a rule selects, or `"*"` for any. */
export type EventKind =
  | "ToolExec"
  | "Egress"
  | "FileAccess"
  | "Dns"
  | "SslContent"
  | "SecurityAction"
  | "*";

/** The deny a rule enforces on a block. Optional on a rule. */
export type RuleAction = "deny-egress" | "deny-file" | "deny-exec";

/** One L1 rule. Maps 1:1 to the daemon's `RuleSpec` ACL object. */
export interface Rule {
  /** Unique-ish rule name (surfaces in the audit `reason`). */
  readonly name: string;
  /** Event kind to match, or `"*"`. */
  readonly on: EventKind;
  /** Regex (Rust `regex` syntax) matched against the event subject. */
  readonly match: string;
  readonly verdict: Verdict;
  readonly severity: Severity;
  readonly reason: string;
  /** On a block, the deny to enforce. */
  readonly action?: RuleAction;
}

/**
 * Escape a string for an ACL double-quoted literal. Order matters: backslashes first (so we don't
 * double-escape the ones we add), then quotes and newlines. Regexes are full of backslashes, so
 * this is load-bearing.
 */
function escapeAcl(s: string): string {
  return s
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n");
}

function quote(s: string): string {
  return `"${escapeAcl(s)}"`;
}

function ruleToAcl(rule: Rule): string {
  const lines = [
    `    name = ${quote(rule.name)}`,
    `    on = ${quote(rule.on)}`,
    `    match = ${quote(rule.match)}`,
    `    verdict = ${quote(rule.verdict)}`,
    `    severity = ${quote(rule.severity)}`,
    `    reason = ${quote(rule.reason)}`,
  ];
  if (rule.action !== undefined) {
    lines.push(`    action = ${quote(rule.action)}`);
  }
  return `  {\n${lines.join("\n")}\n  }`;
}

/** An ordered set of L1 rules that serializes to the daemon's hot-reloadable ACL policy. */
export class Policy {
  private readonly rules: Rule[];

  constructor(rules: Rule[] = []) {
    this.rules = [...rules];
  }

  /** Append a rule (returns `this` for chaining). Rule order is significant — first match wins. */
  add(rule: Rule): this {
    this.rules.push(rule);
    return this;
  }

  /** The rules in order. */
  toArray(): readonly Rule[] {
    return [...this.rules];
  }

  /** Serialize to the daemon's ACL policy text. Empty policy → `"rules = []\n"`. */
  toAcl(): string {
    if (this.rules.length === 0) {
      return "rules = []\n";
    }
    const body = this.rules.map(ruleToAcl).join(",\n");
    return `rules = [\n${body}\n]\n`;
  }

  /**
   * Write the policy to `target` ATOMICALLY: a temp file in the same directory is written and
   * fsync'd, then renamed over `target`. The daemon's hot-reload poll therefore never observes a
   * half-written file. The directory and a same-filesystem rename are required for atomicity.
   * Use the `.acl` extension by convention.
   */
  write(target: string): void {
    const dir = path.dirname(target);
    const base = path.basename(target);
    const tmp = path.join(dir, `.${base}.${process.pid}.${Date.now()}.tmp`);
    const fd = fs.openSync(tmp, "w");
    try {
      fs.writeFileSync(fd, this.toAcl(), "utf8");
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    try {
      fs.renameSync(tmp, target);
    } catch (err) {
      // Best-effort cleanup so a failed rename doesn't leave a temp file behind.
      try {
        fs.unlinkSync(tmp);
      } catch {
        /* ignore */
      }
      throw err;
    }
  }
}

/** Convenience: an empty policy. */
export function emptyPolicy(): Policy {
  return new Policy();
}

/** Where `os.tmpdir()` lives — re-exported so callers can place a policy on a writable fs. */
export const tmpDir = os.tmpdir;
