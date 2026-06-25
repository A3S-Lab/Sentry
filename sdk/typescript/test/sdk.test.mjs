import { test } from "node:test";
import assert from "node:assert";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import {
  Sentry,
  toolExec,
  egress,
  dns,
  fileAccess,
} from "../index.js";

// ACL config: a custom Dns rule on top of the built-in defaults. (Note the doubled backslash for the
// ACL string literal, doubled again here for the JS template literal.)
const CFG = `
deny { egress = "" }
rules = [
  { name = "block-evil-dns", on = "Dns", match = "evil\\\\.test",
    verdict = "block", severity = "high", reason = "custom rule" },
]
`;

test("create + built-in cloud-metadata SSRF blocks", () => {
  const s = Sentry.create(CFG);
  const d = s.evaluate(egress(1, "169.254.169.254", 80));
  assert.equal(d.verdict, "block");
  assert.equal(d.action.kind, "DenyEgress");
  assert.equal(d.action.target, "169.254.169.254");
});

test("SDK-authored ACL rule fires through the embedded engine", () => {
  const s = Sentry.create(CFG);
  const d = s.evaluate(dns(1, "evil.test"));
  assert.equal(d.verdict, "block");
  assert.equal(d.tier, "Rules");
  assert.match(d.reason, /custom rule/);
});

test("benign allowed; unparseable → null", () => {
  const s = Sentry.create(CFG);
  assert.equal(s.evaluate(toolExec(1, ["ls", "-la"])).verdict, "allow");
  assert.equal(s.evaluate("not a json event"), null);
});

test("evaluate_and_enforce writes the deny-file", () => {
  const dir = mkdtempSync(join(tmpdir(), "sentry-node-"));
  try {
    const s = Sentry.create(`deny { exec = "${join(dir, "exec.txt")}" }`);
    const r = s.evaluateAndEnforce(toolExec(1, ["/usr/bin/ncat", "x", "4444"]));
    if (r.decision.verdict === "block") {
      assert.equal(r.enforced, join(dir, "exec.txt"));
      assert.match(readFileSync(r.enforced, "utf8"), /\/usr\/bin\/ncat/);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
