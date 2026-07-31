# @a3s-lab/sentry — TypeScript SDK

A **native, in-process** SDK for [a3s-sentry](../../) — the Rust L1/L2/L3 judge embedded via
[napi-rs](https://napi.rs), the same model as [`@a3s-lab/code`](https://github.com/A3S-Lab/Code). You
build the judge from one ACL config and evaluate observer events in-process — no daemon, no
subprocess (beyond what L3 itself spawns).

```bash
npm install @a3s-lab/sentry
```

## Configure (one ACL file) + judge

```ts
import { Sentry, egress, toolExec } from "@a3s-lab/sentry";

// `create` takes an ACL config file path or ACL content.
const sentry = Sentry.create("sentry.acl");

const d = sentry.evaluate(egress(1, "169.254.169.254", 80)); // cloud-metadata SSRF
if (d?.verdict === "block") {
  console.log(d.reason, d.action); // -> "...", { kind: "DenyEgress", target: "169.254.169.254" }
}

// judge AND write the deny-file the kernel guards read:
const r = sentry.evaluateAndEnforce(toolExec(2, ["/usr/bin/ncat", "host", "4444"]));
console.log(r?.decision.verdict, r?.enforced); // "block", "/path/exec.txt"

// Stop after L1. Escalation remains explicit and no L2/L3 backend is contacted.
const l1 = sentry.evaluateL1(fileAccess(3, "/home/u/.aws/credentials", false));
if (l1?.nextTierEligible) {
  console.log(l1.l1Decision, l1.stageStatus, l1.stopReason);
}

// Stop after L2 and preserve an unresolved escalation for a durable external L3 worker. This runs
// on the napi worker pool, so a slow L2 request does not block Node's event loop.
const fast = await sentry.evaluateThroughL2(toolExec(4, ["bash", "-c", "base64 -d | sh"]));
if (fast?.nextTierEligible) {
  console.log(fast.escalationCause, fast.effectiveDecision);
}
```

A `sentry.acl` carries everything (see [`config.rs`](../../src/config.rs) for the schema):

```hcl
fail_closed = false
speculate   = "high"
llm   { url = "http://llm:18051/v1", model = "glm", timeout_s = 30 }   # L2 (optional)
agent { bin = "a3s-code", skills = "./skills" }                        # L3 (optional)
deny  { egress = "egress.txt", exec = "exec.txt" }                     # sinks (optional)
rules = [
  { name = "no-netcat", on = "ToolExec", match = "(?i)\\bnetcat\\b",
    verdict = "block", severity = "medium", reason = "netcat", action = "deny-exec" },
]
```

Event builders: `toolExec`, `egress`, `fileAccess`, `dns`, `sslContent`, `securityAction` — each
returns the observer event JSON `evaluate` takes. `evaluate` returns `null` for an unparseable event,
and a `Decision` (`{ verdict, tier, severity, reason, action? }`) otherwise — including `allow`.

`evaluateL1` returns `l1Decision`, `stageStatus`, `nextTierEligible`, and `stopReason`. It never
invokes L2/L3 and never resolves escalation through `fail_closed`.

`evaluateThroughL2` returns a promise containing `l1Decision`, optional `l2Decision`,
`effectiveDecision`, `stageStatus`, optional `escalationCause`, `nextTierEligible`, and
`stopReason`. It never invokes L3, never resolves an outstanding escalation through `fail_closed`,
and ignores speculative L3 settings.

## Build / test (from source)

```bash
npm install
npm run build:debug     # napi build → index.js + index.d.ts + a3s-sentry.<platform>.node
npm test
```

Requires a Rust toolchain (it compiles the embedded judge). The published package ships the prebuilt
native binary per platform, so consumers need only `npm install`.
