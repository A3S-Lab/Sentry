//! Unit + integration tests for the a3s-sentry SDK, using Node's built-in test runner.
//!
//! The integration test spawns the REAL sentry binary and verifies the live wire contract; it is
//! skipped (not failed) when the binary can't be found or built.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { Event } from "../events.js";
import { Policy } from "../policy.js";
import { parseAudit, parseEnforceAction } from "../types.js";
import { parseMetrics } from "../metrics.js";
import { Sentry } from "../process.js";

// ---------------------------------------------------------------------------
// Policy / ACL serialization
// ---------------------------------------------------------------------------

test("Rule serializes to ACL with correct fields and backslash escaping", () => {
  const acl = new Policy()
    .add({
      name: "block-nc",
      on: "ToolExec",
      match: "\\bnc\\b",
      verdict: "block",
      severity: "high",
      reason: "netcat",
      action: "deny-exec",
    })
    .toAcl();

  // top-level list form
  assert.match(acl, /^rules = \[\n/);
  assert.match(acl, /\n\]\n$/);
  // every field present, double-quoted
  assert.ok(acl.includes('name = "block-nc"'));
  assert.ok(acl.includes('on = "ToolExec"'));
  assert.ok(acl.includes('verdict = "block"'));
  assert.ok(acl.includes('severity = "high"'));
  assert.ok(acl.includes('reason = "netcat"'));
  assert.ok(acl.includes('action = "deny-exec"'));
  // the single backslash in the regex must be ESCAPED to two backslashes in the ACL literal
  assert.ok(acl.includes('match = "\\\\bnc\\\\b"'), `escaped regex missing in: ${acl}`);
});

test("empty Policy serializes to rules = []", () => {
  assert.equal(new Policy().toAcl(), "rules = []\n");
});

test("ACL escapes embedded quotes and newlines", () => {
  const acl = new Policy()
    .add({
      name: 'has"quote',
      on: "*",
      match: "a\nb",
      verdict: "allow",
      severity: "info",
      reason: "x",
    })
    .toAcl();
  assert.ok(acl.includes('name = "has\\"quote"'));
  assert.ok(acl.includes('match = "a\\nb"'));
  // action omitted when not set
  assert.ok(!acl.includes("action ="));
});

test("Policy.write is atomic and round-trips", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sentry-sdk-"));
  try {
    const target = path.join(dir, "rules.acl");
    const policy = new Policy().add({
      name: "no-curl-pipe",
      on: "ToolExec",
      match: "curl.*\\|.*sh",
      verdict: "block",
      severity: "high",
      reason: "pipe to shell",
      action: "deny-exec",
    });
    policy.write(target);
    assert.equal(fs.readFileSync(target, "utf8"), policy.toAcl());
    // no leftover temp files in the dir
    assert.deepEqual(fs.readdirSync(dir), ["rules.acl"]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Event builders / toLine()
// ---------------------------------------------------------------------------

test("Event.toolExec produces the exact compact envelope", () => {
  const line = Event.toolExec(1903, ["bash", "-c", "curl x|sh"]).toLine();
  assert.equal(
    line,
    '{"event":{"ToolExec":{"pid":1903,"argv":["bash","-c","curl x|sh"]}}}',
  );
});

test("Event.egress includes identity and provider only when present", () => {
  const withId = Event.egress(1, "1.2.3.4", 4444, {
    agent: "python3",
    provider: "Anthropic",
  }).toLine();
  assert.equal(
    withId,
    '{"event":{"Egress":{"pid":1,"peer":"1.2.3.4","port":4444}},"identity":{"agent":"python3"},"provider":"Anthropic"}',
  );

  const bare = Event.egress(1, "1.2.3.4", 80).toLine();
  assert.equal(bare, '{"event":{"Egress":{"pid":1,"peer":"1.2.3.4","port":80}}}');
  assert.ok(!bare.includes("identity"));
  assert.ok(!bare.includes("provider"));
});

test("Event.sslContent uses snake_case is_read", () => {
  const line = Event.sslContent(7, false, "API_KEY=sk-123").toLine();
  assert.equal(
    line,
    '{"event":{"SslContent":{"pid":7,"is_read":false,"content":"API_KEY=sk-123"}}}',
  );
});

test("the other builders emit their declared fields", () => {
  assert.equal(
    Event.fileAccess(2, "/etc/shadow", false).toLine(),
    '{"event":{"FileAccess":{"pid":2,"path":"/etc/shadow","write":false}}}',
  );
  assert.equal(
    Event.dns(3, "abc.oast.fun").toLine(),
    '{"event":{"Dns":{"pid":3,"query":"abc.oast.fun"}}}',
  );
  assert.equal(
    Event.securityAction(4, "setuid-root", 0).toLine(),
    '{"event":{"SecurityAction":{"pid":4,"kind":"setuid-root","detail":0}}}',
  );
});

// ---------------------------------------------------------------------------
// Audit parsing
// ---------------------------------------------------------------------------

test("parseAudit parses a block decision with an externally-tagged action", () => {
  // exact line shape verified against the real daemon
  const line =
    '{"event":"Egress","subject":"169.254.169.254:80","decision":{"verdict":"block","tier":"Rules","severity":"high","reason":"cloud-metadata: cloud instance-metadata access (SSRF/cred theft)","action":{"DenyEgress":"169.254.169.254"}}}';
  const audit = parseAudit(line);
  assert.equal(audit.event, "Egress");
  assert.equal(audit.subject, "169.254.169.254:80");
  assert.equal(audit.agent, undefined);
  assert.equal(audit.enforced, undefined);
  assert.equal(audit.decision.verdict, "block");
  assert.equal(audit.decision.tier, "Rules");
  assert.equal(audit.decision.severity, "high");
  assert.deepEqual(audit.decision.action, { kind: "DenyEgress", target: "169.254.169.254" });
});

test("parseAudit keeps agent and enforced when present, and an actionless escalate", () => {
  const line =
    '{"agent":"python3","event":"FileAccess","subject":"/etc/shadow","decision":{"verdict":"escalate","tier":"Rules","severity":"high","reason":"read-credentials: access to a credential file"},"enforced":"/tmp/file-deny.txt"}';
  const audit = parseAudit(line);
  assert.equal(audit.agent, "python3");
  assert.equal(audit.enforced, "/tmp/file-deny.txt");
  assert.equal(audit.decision.verdict, "escalate");
  assert.equal(audit.decision.action, undefined);
});

test("parseEnforceAction recognizes all three deny kinds", () => {
  assert.deepEqual(parseEnforceAction({ DenyFile: "/p" }), { kind: "DenyFile", target: "/p" });
  assert.deepEqual(parseEnforceAction({ DenyExec: "curl" }), { kind: "DenyExec", target: "curl" });
  assert.deepEqual(parseEnforceAction({ DenyEgress: "1.2.3.4" }), {
    kind: "DenyEgress",
    target: "1.2.3.4",
  });
  assert.equal(parseEnforceAction(undefined), undefined);
  assert.equal(parseEnforceAction({ Unknown: "x" }), undefined);
});

// ---------------------------------------------------------------------------
// Metrics parsing
// ---------------------------------------------------------------------------

test("parseMetrics maps counter names to fields and skips comments", () => {
  const text = [
    "# HELP sentry_events_total Observer events ingested.",
    "# TYPE sentry_events_total counter",
    "sentry_events_total 42",
    "# TYPE sentry_blocked_total counter",
    "sentry_blocked_total 7",
    "sentry_overload_degraded_total 3",
    "sentry_enforce_failed_total 1",
    "",
  ].join("\n");
  const snap = parseMetrics(text);
  assert.deepEqual(snap, {
    events: 42,
    blocked: 7,
    overloadDegraded: 3,
    enforceFailed: 1,
  });
});

test("parseMetrics defaults missing counters to zero", () => {
  const snap = parseMetrics("sentry_blocked_total 5\n");
  assert.equal(snap.blocked, 5);
  assert.equal(snap.events, 0);
  assert.equal(snap.overloadDegraded, 0);
  assert.equal(snap.enforceFailed, 0);
});

// ---------------------------------------------------------------------------
// Integration: spawn the REAL sentry binary (skipped if unavailable)
// ---------------------------------------------------------------------------

function resolveSentryBin(): string | undefined {
  const override = process.env["A3S_SENTRY_BIN"];
  if (override && fs.existsSync(override)) {
    return override;
  }
  // sdk/typescript/src/test → repo root is four levels up.
  const repoRoot = path.resolve(import.meta.dirname, "..", "..", "..", "..");
  const debugBin = path.join(repoRoot, "target", "debug", "sentry");
  if (fs.existsSync(debugBin)) {
    return debugBin;
  }
  // try to build it once
  try {
    execFileSync("cargo", ["build"], { cwd: repoRoot, stdio: "ignore" });
  } catch {
    return undefined;
  }
  return fs.existsSync(debugBin) ? debugBin : undefined;
}

test("integration: real daemon blocks cloud-metadata egress (SSRF)", async (t) => {
  const bin = resolveSentryBin();
  if (bin === undefined) {
    t.skip("sentry binary not found and could not be built");
    return;
  }

  const sentry = new Sentry({ bin });
  sentry.start();
  try {
    sentry.submit(Event.egress(1, "169.254.169.254", 80));

    // read exactly one audited decision
    const iter = sentry.decisions();
    const first = await iter.next();
    assert.equal(first.done, false, "expected at least one audit line");
    const audit = first.value;

    assert.equal(audit.event, "Egress");
    assert.equal(audit.decision.verdict, "block");
    assert.ok(audit.decision.action, "expected an enforce action");
    assert.equal(audit.decision.action?.kind, "DenyEgress");
    assert.equal(audit.decision.action?.target, "169.254.169.254");

    await iter.return?.();
  } finally {
    await sentry.stop();
  }
});
