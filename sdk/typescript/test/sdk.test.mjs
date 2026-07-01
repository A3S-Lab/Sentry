import { test } from "node:test";
import assert from "node:assert";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import {
  Sentry,
  toolExec,
  egress,
  dns,
  fileAccess,
  sslContent,
  securityAction,
} from "../index.js";

// Custom rules covering every severity, on top of the built-in defaults. (Inline-object fields are
// comma-separated; the regex backslash is doubled for ACL then again for the JS template literal.)
const CFG = `
deny { egress = "" }
rules = [
  { name = "high-dns", on = "Dns", match = "high\\\\.test", verdict = "block", severity = "high",     reason = "high rule" },
  { name = "low-dns",  on = "Dns", match = "low\\\\.test",  verdict = "block", severity = "low",      reason = "low rule" },
  { name = "med-dns",  on = "Dns", match = "med\\\\.test",  verdict = "block", severity = "medium",   reason = "med rule" },
  { name = "crit-dns", on = "Dns", match = "crit\\\\.test", verdict = "block", severity = "critical", reason = "crit rule" },
]
`;

test("create + built-in cloud-metadata SSRF blocks (DenyEgress)", () => {
  const s = Sentry.create(CFG);
  const d = s.evaluate(egress(1, "169.254.169.254", 80));
  assert.equal(d.verdict, "block");
  assert.deepEqual(d.action, { kind: "DenyEgress", target: "169.254.169.254" });
  assert.equal(d.risk.category, "systemic_risk");
  assert.equal(d.risk.riskType ?? d.risk.risk_type, "system");
});

test("SDK-authored ACL rule fires at tier=Rules", () => {
  const d = Sentry.create(CFG).evaluate(dns(1, "high.test"));
  assert.equal(d.verdict, "block");
  assert.equal(d.tier, "Rules");
  assert.match(d.reason, /high rule/);
});

test("severity arms: info / low / medium / high / critical", () => {
  const s = Sentry.create(CFG);
  assert.equal(s.evaluate(toolExec(1, ["ls", "-la"])).severity, "info"); // benign allow
  assert.equal(s.evaluate(dns(1, "low.test")).severity, "low");
  assert.equal(s.evaluate(dns(1, "med.test")).severity, "medium");
  assert.equal(s.evaluate(dns(1, "high.test")).severity, "high");
  assert.equal(s.evaluate(dns(1, "crit.test")).severity, "critical");
});

test("benign allowed; unparseable → null", () => {
  const s = Sentry.create(CFG);
  assert.equal(s.evaluate(toolExec(1, ["ls"])).verdict, "allow");
  assert.equal(s.evaluate("not a json event"), null);
  assert.equal(s.evaluateAndEnforce("still not json"), null);
});

test("all six event builders produce judgeable events", () => {
  const s = Sentry.create(CFG);
  for (const ev of [
    toolExec(1, ["echo", "hi"]),
    egress(1, "8.8.8.8", 443),
    fileAccess(1, "/tmp/x", false),
    dns(1, "example.com"),
    sslContent(1, "hello", true),
    securityAction(1, "setuid-root", 0),
  ]) {
    assert.ok(s.evaluate(ev) !== null, `builder produced an unparseable event: ${ev}`);
  }
});

test("evaluate_and_enforce: DenyExec / DenyFile / non-block", () => {
  const dir = mkdtempSync(join(tmpdir(), "sentry-node-"));
  try {
    const s = Sentry.create(`
      deny {
        exec = "${join(dir, "exec.txt")}"
        file = "${join(dir, "file.txt")}"
      }
      rules = [
        { name = "x-exec", on = "ToolExec",   match = "danger",     verdict = "block", severity = "high", reason = "x", action = "deny-exec" },
        { name = "x-file", on = "FileAccess", match = "/etc/shadow", verdict = "block", severity = "high", reason = "x", action = "deny-file" },
      ]
    `);
    // DenyExec
    const ex = s.evaluateAndEnforce(toolExec(1, ["/usr/bin/danger", "x"]));
    assert.equal(ex.decision.action.kind, "DenyExec");
    assert.equal(ex.enforced, join(dir, "exec.txt"));
    assert.match(readFileSync(ex.enforced, "utf8"), /danger/);
    // DenyFile
    const fa = s.evaluateAndEnforce(fileAccess(1, "/etc/shadow", true));
    assert.equal(fa.decision.action.kind, "DenyFile");
    assert.equal(fa.enforced, join(dir, "file.txt"));
    // non-block — benign event → no deny-file written
    const ok = s.evaluateAndEnforce(toolExec(1, ["echo", "ok"]));
    assert.equal(ok.decision.verdict, "allow");
    assert.equal(ok.enforced, undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("L2 tier: an escalating event reaches L2 (unreachable URL → escalate, tier=Llm)", () => {
  // No mock server needed: a closed port refuses fast, L2 errors → escalate, and with no L3 the
  // unresolved escalation keeps tier=Llm. Exercises the Llm arm of the decision conversion.
  const s = Sentry.create(`llm { url = "http://127.0.0.1:1/v1" }`);
  const d = s.evaluate(fileAccess(1, "/home/u/.aws/credentials", false)); // built-in: escalate
  assert.equal(d.tier, "Llm");
});

test("create() throws on a bad ACL config", () => {
  assert.throws(() => Sentry.create("this is not valid acl {{{"), /parsing sentry ACL config/);
});

test("L3 agent tier: escalating event → mock agent → tier=Agent", () => {
  const dir = mkdtempSync(join(tmpdir(), "sentry-l3-"));
  try {
    const bin = join(dir, "mock-agent.sh");
    writeFileSync(
      bin,
      '#!/bin/sh\necho \'{"verdict":"block","severity":"critical","reason":"mock L3"}\'\n',
    );
    chmodSync(bin, 0o755);
    // agent{} but no llm{} → an L1 escalate goes straight to L3 (the mock).
    const s = Sentry.create(`agent { bin = "${bin}" }`);
    const d = s.evaluate(fileAccess(1, "/home/u/.aws/credentials", false)); // built-in: escalate
    assert.equal(d.tier, "Agent");
    assert.equal(d.verdict, "block");
    assert.match(d.reason, /mock L3/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
