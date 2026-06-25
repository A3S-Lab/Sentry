# @a3s-lab/sentry

A dependency-free TypeScript SDK for **a3s-sentry** — the tiered (L1 rules / L2 LLM / L3 agent)
runtime security control for AI agents. Author policy, run and supervise the daemon, submit events,
stream typed decisions, and read metrics — all from Node/TypeScript using only Node built-ins.

- **No runtime dependencies.** Built on `child_process`, `node:readline`, `http`, `fs`, `os`, `path`.
- **Node 18+.** ESM, strict TypeScript, typed wire contract.

a3s-sentry is a Rust daemon: it reads a3s-observer NDJSON events on stdin, judges each event through
three tiers, writes blocks to observer deny-files, and emits a decision-audit NDJSON line per
non-allow on stdout. When `A3S_SENTRY_METRICS_ADDR` is set it also serves Prometheus `/metrics` and
`/healthz`.

> **Benign allows are not emitted.** The daemon prints an audit line **only** for blocks,
> escalations, and flagged-but-allowed events. Plain benign allows are counted, not printed — so
> `decisions()` yields exactly the audited (non-allow) decisions, never one per submitted event.

## Install

```sh
npm install @a3s-lab/sentry
```

You also need the `sentry` binary on `PATH` (or pass an explicit `bin`). Build it from the
[Sentry](https://github.com/A3S-Lab/Sentry) repo with `cargo build --release`.

## Authoring policy

A `Policy` is an ordered list of rules (first match wins, like a firewall). It serializes to **ACL**
— the a3s ecosystem's config language — which the daemon hot-reloads (~2s, no restart).

```ts
import { Policy } from "@a3s-lab/sentry";

const policy = new Policy()
  .add({
    name: "no-netcat",
    on: "ToolExec",
    match: "\\bnc\\b", // regexes contain backslashes — escaped correctly in the ACL output
    verdict: "block",
    severity: "high",
    reason: "netcat is not allowed",
    action: "deny-exec",
  })
  .add({
    name: "no-credential-reads",
    on: "FileAccess",
    match: "\\.aws/credentials|/etc/shadow",
    verdict: "escalate",
    severity: "high",
    reason: "credential file access",
    action: "deny-file",
  });

// Atomic write (temp file + rename) so the daemon never reads a half-written policy.
policy.write("/etc/a3s/rules.acl");
```

`policy.toAcl()` returns the text directly:

```acl
rules = [
  {
    name = "no-netcat"
    on = "ToolExec"
    match = "\\bnc\\b"
    verdict = "block"
    severity = "high"
    reason = "netcat is not allowed"
    action = "deny-exec"
  }
]
```

The daemon's built-in rules always apply on top of your policy.

## Run and stream decisions

```ts
import { Sentry, Event } from "@a3s-lab/sentry";

const sentry = new Sentry({
  bin: "sentry",
  policy: "/etc/a3s/rules.acl",
  egressDeny: "/etc/a3s/egress-deny.txt",
  failClosed: true,
  metricsAddr: "0.0.0.0:9100",
});

sentry.start();

// Submit observer events (typed builders match the daemon's exact wire contract).
sentry.submit(Event.egress(4242, "169.254.169.254", 80)); // cloud-metadata SSRF → blocked
sentry.submit(Event.toolExec(4243, ["ls", "-la"])); // benign → not emitted

// Stream typed audit decisions — only the audited (non-allow) ones appear.
for await (const audit of sentry.decisions()) {
  console.log(audit.event, audit.decision.verdict, audit.decision.action);
  // e.g. Egress block { kind: "DenyEgress", target: "169.254.169.254" }
  break;
}

await sentry.stop(); // closes stdin → the daemon drains and exits (SIGTERM after a grace period)
```

`stop()` closes stdin so the daemon reaches EOF, drains its queue, and exits cleanly; it waits up to
~10s, then sends `SIGTERM`. With `await using` the daemon stops automatically at scope exit:

```ts
await using sentry = new Sentry({ bin: "sentry" });
sentry.start();
// ... submit + stream ...
// stopped automatically here
```

### Event builders

| Builder | Variant | Fields |
| --- | --- | --- |
| `Event.toolExec(pid, argv, opts?)` | `ToolExec` | `pid, argv` |
| `Event.egress(pid, peer, port, opts?)` | `Egress` | `pid, peer, port` |
| `Event.fileAccess(pid, path, write, opts?)` | `FileAccess` | `pid, path, write` |
| `Event.dns(pid, query, opts?)` | `Dns` | `pid, query` |
| `Event.sslContent(pid, isRead, content, opts?)` | `SslContent` | `pid, is_read, content` |
| `Event.securityAction(pid, kind, detail, opts?)` | `SecurityAction` | `pid, kind, detail` |

`opts` carries an optional identity (`agent`, `task`, `session`) and `provider`; identity is included
on the wire only when at least one field is set.

### Decision shape

Each `Audit` from `decisions()` has:

```ts
interface Audit {
  agent?: string; // resolved agent identity, if any
  event: string; // "Egress", "ToolExec", …
  subject: string; // matched subject text
  decision: {
    verdict: "allow" | "block" | "escalate";
    tier: "Rules" | "Llm" | "Agent";
    severity: "info" | "low" | "medium" | "high" | "critical";
    reason: string;
    action?: { kind: "DenyEgress" | "DenyFile" | "DenyExec"; target: string };
  };
  enforced?: string; // deny-file path written, if a block landed
}
```

## Metrics

When the daemon is started with `metricsAddr`, read its counters:

```ts
import { MetricsClient } from "@a3s-lab/sentry";

const client = new MetricsClient("127.0.0.1:9100"); // "host:port" or a full URL

if (await client.health()) {
  const m = await client.metrics();
  console.log(m.events, m.blocked, m.overloadDegraded, m.enforceFailed);
}
```

| Field | Prometheus counter | Meaning |
| --- | --- | --- |
| `events` | `sentry_events_total` | Observer events ingested |
| `blocked` | `sentry_blocked_total` | Events blocked |
| `overloadDegraded` | `sentry_overload_degraded_total` | Escalations degraded to the fail mode (a fail-open bypass) |
| `enforceFailed` | `sentry_enforce_failed_total` | Deny-file writes that errored (a block that did not land) |

Alarm on `overloadDegraded` and `enforceFailed` — both mean a block may not have taken effect.

## Development

```sh
npm install     # no runtime deps; installs TypeScript + @types/node for building
npm run build   # tsc → dist/
npm test        # build + node --test (unit tests always run; the integration test
                # spawns the real sentry binary, or skips if it can't be found/built)
```

The integration test looks for `target/debug/sentry` in the repo (building it once if missing), or
honors an `A3S_SENTRY_BIN` override. It is skipped — not failed — when the binary is unavailable.

## License

MIT
