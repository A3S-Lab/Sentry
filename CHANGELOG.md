# Changelog

## [0.5.2] — Python + TypeScript SDKs; the policy language is ACL

### Added
- **Python SDK** ([`sdk/python`](sdk/python), `a3s-sentry`) and **TypeScript SDK**
  ([`sdk/typescript`](sdk/typescript), `@a3s-lab/sentry`) — dependency-free clients that author ACL
  policy in code, supervise the daemon, submit events, stream typed decisions, and read `/metrics` +
  `/healthz`. Both mirror the same model and are **contract-tested against the real binary**: an SSRF
  event round-trips to a `block`, and an SDK-authored ACL rule fires through the daemon's own parser.
  Python: 13 tests (3 integration); TypeScript: 14 tests (1 integration).

### Changed
- **The policy language is now ACL** (the a3s config language), extension `.acl` —
  `policy/rules.acl`, `A3S_SENTRY_POLICY=…/rules.acl`. Naming + extension only: the syntax is
  unchanged (the ordered `rules = [ … ]` list, parsed by the same grammar, preserving first-match-wins
  order), so existing policies keep working — just point the daemon at a `.acl` file.

## [0.5.1] — release pipeline, container image, operator runbook

GA items (ii)/(iii)/(iv) — make sentry installable, deployable, and operable. No crate code change;
infrastructure + docs. Tag `v0.5.1` to cut the first published artifacts.

### Added
- **Release pipeline** (`.github/workflows/release.yml`) — on a `vX.Y.Z` tag: builds a static
  `x86_64-unknown-linux-musl` binary (attached to the GitHub Release) and builds + pushes a container
  image to `ghcr.io/a3s-lab/sentry`.
- **Container image** (`Dockerfile`) — slim, non-root (L1+L2 out of the box; L3 needs Node +
  `@a3s-lab/code` layered into a derived image). The reference DaemonSet's combined `observer-sentry`
  image is now documented as observer's image with this binary layered on.
- **Operator runbook** ([`docs/RUNBOOK.md`](docs/RUNBOOK.md)) — rollout (dry-run → enforce), fail-open
  vs fail-closed, the two alarm metrics (`overload_degraded` / `enforce_failed`), tuning under load,
  deny-file lifecycle, LLM/L3 outage behavior, and a quick-triage table.

## [0.5.0] — self-observability (metrics + health)

GA item (i): a *fail-open* security control has to be alertable — otherwise a silent enforcement
bypass under load looks identical to a quiet day. Added a std-only metrics/health endpoint (opt-in
`A3S_SENTRY_METRICS_ADDR`, e.g. `0.0.0.0:9100`; off by default) — **no new dependency**, one accept
thread:

- **`GET /metrics`** — Prometheus counters: `sentry_events_total`, `sentry_blocked_total`,
  `sentry_overload_degraded_total`, and a new **`sentry_enforce_failed_total`** (a block whose
  deny-write errored). The last two are the ones to alarm on — both mean a block did **not** land.
- **`GET /healthz`** — `200 ok` while alive. The reference k8s DaemonSet now has liveness/readiness
  probes against it, a `metrics` containerPort, and `prometheus.io/scrape` annotations.
- The counters are shared atomics across the ingest thread + workers (the daemon's loose
  `blocked`/`degraded` atomics are now one `Metrics`); the endpoint bind fails fast on a bad address.

### Tested
- Unit: the served endpoint over a real TCP round-trip (routing + counter values) + the Prometheus
  formatting. Integration: the daemon serves **live** counters end to end (an SSRF block →
  `sentry_blocked_total 1`, `/healthz` → 200). 41 unit + 12 integration, fmt + clippy clean.

## [0.4.2] — L3 subprocess lifecycle hardening

An adversarial security review of the post-v0.1.0 code — the worker pool, the overload fail-mode, and
the L3 agent subprocess — surfaced 5 real issues (and correctly rejected 11), all clustered in the L3
subprocess lifecycle. The worker pool and the overload/fail-mode paths were found sound.

### Fixed
- **L3 stdout read is now bounded** (`agent.rs`). `read_to_string` on the agent's stdout had no cap —
  a runaway or compromised agent binary could OOM the daemon. Now `.take(1 MiB)` (a verdict JSON is
  tiny), symmetric with the daemon's 256 KiB stdin cap.
- **Timeout now SIGKILLs the agent's whole process group, not just the direct child** (`agent.rs`).
  The agent bin (a Node a3s-code) spawns helpers; a bare `child.kill()` orphaned them, and an orphan
  holding the inherited stdout pipe kept the reader thread blocked forever — leaking a thread + FD per
  timeout. The child now runs in its own process group (`process_group(0)`) and cleanup kills the group
  (`-pid`), so every pipe end closes and the reader exits. (Adds a unix-only `libc` dependency.)
- **The success path no longer blocks on `wait()` past the deadline** (`agent.rs`). Cleanup now always
  group-kills then waits, so an agent that closes stdout but lingers can't pin a worker indefinitely.
- **Speculative L3 fan-out is capped** (`pipeline.rs`). On a fast L2 `Block` the speculative L3 thread
  was detached and ran to its timeout; under opt-in speculation a high-risk flood could accumulate
  unbounded agent subprocesses. A live-count cap (`l3_spec_cap`, default 8) stops speculating once that
  many L3 are in flight — above it, evaluation falls back to sequential (still full analysis).

### Tested
- New integration coverage for the two previously-untested paths: **L3 end to end** (mock agent →
  escalate → block → deny-file) and the **overload-degrade** path (slow L3 + queue=1 → graceful
  degradation + clean exit), plus a unit test that the speculation cap forces the sequential fallback.
  39 unit + 11 integration, all green; fmt + clippy `-D warnings` clean.

## [0.4.1] — durability fix + an honest durability claim

Found by an adversarial verification pass over the v0.4.0 GA claims (the kind of overstatement that
only survives until someone tries to refute it).

### Fixed
- **A failed deny-write was deduped away permanently.** `Enforcer::apply` marked a target *seen*
  **before** writing it, so if the write errored (disk full, EIO) the block was never retried on the
  next occurrence — a dropped enforcement made permanent. It now records *seen* only **after** a
  successful write (test: `failed_write_is_retried_not_deduped`).
- **A poisoned enforcer lock no longer wedges the worker pool.** `handle()` recovers the lock
  (`into_inner`) instead of `unwrap`-panicking, so a panic inside one `apply` can't take down every
  other worker's enforcement.

### Docs
- Corrected the v0.4.0 "durable shutdown" wording, which overstated the guarantee. Precise statement:
  the deny-file is the durable enforcement record (`append` + close per target — **page-cache
  durable, not `fsync`'d**, by design, since the deny-files are ephemeral node-local scratch the
  guards re-read and re-observation regenerates); the stdout audit line is best-effort observability.
  An abrupt termination loses only the in-flight event(s) being judged, never an already-written deny;
  a signal in the narrow window between the deny write and its audit line can drop that one audit line
  while the deny still enforces.

## [0.4.0] — production-readiness: CI + deploy + verified-durable shutdown

Closes the last of the four GA gaps (#1 chain/EPERM, #2 accuracy, #3 worker-pool, #4 ops).

### Added
- **CI** (`.github/workflows/ci.yml`) — gates `cargo fmt --check`, `clippy -D warnings`, and the full
  test suite on every push / PR.
- **Reference k8s DaemonSet** (`deploy/daemonset.yaml`) — `observer-collector | sentry` per node,
  deny-files shared with observer's `enforce` / `fileguard` over an `emptyDir`, **dry-run on** for a
  safe shadow-mode rollout before enforcing.

### Verified (not changed)
- **Graceful shutdown was already durable** — a review of the premise ("SIGTERM loses the final
  flush") found it false: every decision is line-flushed (`println!` → `LineWriter`) and every deny is
  `append`-written + closed per target, so an abrupt `SIGTERM`/`SIGKILL` loses no already-written deny
  line (only the in-flight event being judged). Normal pod termination closes the upstream pipe →
  stdin EOF → the worker queue drains and
  final stats print before exit. No `signal-hook`/signal dependency added — it would only buy a
  cosmetic summary line, and in-flight escalations belong to an agent terminating in the same pod.

## [0.3.3] — worker pool: no more L2/L3 head-of-line blocking

### Changed
- **L2/L3 now run in a bounded worker pool** off the ingest thread. L1 runs inline (µs) on every
  event; only escalations dispatch to the workers, so a slow L2/L3 occupies a worker — not the event
  stream. Under an escalation flood the queue degrades gracefully to the fail-mode (audited as
  `overload-degraded`) instead of blocking ingest. `A3S_SENTRY_WORKERS` (default 4) +
  `A3S_SENTRY_QUEUE` (default 256). New `Pipeline::classify_l1` / `resolve_overload`.
- Validated on Linux (`scripts/soak-l2.sh`): **~1.15M events/s with a 0.5s L2 in the mix** (vs the old
  synchronous design's ~8 ev/s ceiling), RSS flat at 6.5 MB, 0 panics, graceful overload degradation.

## [0.3.2] — measured accuracy + eval-driven rule fixes

### Added
- **Accuracy evaluation** (`eval/` + `examples/eval.rs`): a 69-event labeled corpus and a harness
  that runs the real pipeline and reports recall / precision / FP-rate. Measured: **L1 alone 47.8%
  recall, 100% precision, 0% FP**; **L1+L2 (live GLM) 95.7% recall, 100% precision, 0% FP**.

### Fixed (found by the eval)
- **Bare `rm -rf /` was missed** — the `destructive-rm` regex's trailing `\b` didn't match a path
  ending in `/`. Now caught (and `rm -rf /tmp/cache` still allowed).
- **`.env` files** weren't covered by `read-credentials` → now escalated.
- **OOB-exfil / pentest-callback domains** (`.oast.`, `.dnslog.`, interactsh, burpcollaborator, …)
  are now a deterministic L1 **block** (unambiguous IOCs) instead of being left to a too-lenient L2.

## [0.3.1] — observer chain contract: verified + a real fix

### Fixed
- **IPv6 egress denies were unenforceable + mis-parsed.** observer's egress guard is `connect4` + a
  `u32` IPv4 map (hostnames DNS-resolved to IPv4), so an IPv6 *literal* (e.g. the v6 cloud-metadata
  `fd00:ec2::254`) can't be enforced and observer would mis-parse it as a hostname. Sentry now drops
  IPv6 egress literals instead of writing a dead line. (IPv4 + hostnames unchanged.)

### Added
- **Cross-tool contract test** (`deny_files_are_consumable_by_observer_guards`): runs a3s-observer's
  *exact* deny-file parsers (`parse_egress_policy` + fileguard `load_policy`) on sentry's output and
  asserts the blocked IP / path are extracted correctly — verifying the format contract that the
  whole enforcement chain depends on, in CI.

## [0.3.0] — real L3 deep agent investigation

### Added
- **L3 is now a real a3s-code agent**, not a stub. `scripts/l3-agent.mjs` bridges to the
  `@a3s-lab/code` SDK: it runs an a3s-code agent with the `skills/` security playbooks, deeply
  investigates a flagged event (actor identity, attack chain, blast radius) and returns a
  `{verdict,severity,reason}` JSON. Validated end-to-end against a live a3s-code + GLM: an
  SSH-private-key read → an attack-chain-aware `block` ("a generic Python interpreter, not a known SSH
  client… key material can be transmitted outbound after being loaded into memory").
- L3 is reachable three ways: when **L2 escalates** (the LLM can now answer `"escalate"` when it
  genuinely can't tell → L3), **directly from L1** when no L2 is configured, or **speculatively**
  alongside L2 on high-risk events.
- `A3S_SENTRY_L3_URL` / `_KEY` / `_MODEL` — L3's LLM config (falls back to `A3S_SENTRY_LLM_*`), so L3
  can use a stronger/different model than L2, or run without L2.

### Changed
- The L2 prompt now offers `escalate` for genuinely-uncertain cases (hands off to L3) instead of
  defaulting them to allow.

## [0.2.2] — real-LLM validation + L2 timeout fix

### Fixed
- **L2 timeout was too short for reasoning models.** Tested against a live `glm5.1-w4a8`, a real
  classification takes ~16s; the hardcoded 10s timeout would expire → escalate → fail-open →
  **allow the threat** even though the model judged it correctly. The timeout is now configurable
  (`A3S_SENTRY_LLM_TIMEOUT`, default **30s**; `A3S_SENTRY_AGENT_TIMEOUT` for L3, default 120s). This
  bug was invisible to mock tests (which respond instantly) — only a real LLM surfaced it.

### Added
- L2 round-trip integration test against a mock OpenAI endpoint (CI-reproducible, no real model).
- Validated end to end against the live GLM: a credential read → `block` (critical) → enforced; a
  placeholder secret in a README → `allow` ("not an actual secret") — L2 correctly reduces L1's
  false positives.

## [0.2.1] — hardening + full test pyramid

### Added
- **Integration suite** (`tests/integration.rs`) driving the real binary: block → deny-file write,
  dry-run, fail-open vs fail-closed, malformed-input skipping, live hot-reload, `--version`.
- **Soak harness** (`scripts/soak.sh`): sustained mixed load (benign / block / escalate / rotating
  egress / malformed) + a policy rewrite under load. Validated: 10M+ events at ~350k–850k ev/s, RSS
  flat (no leak), deny-file bounded by dedup, 0 panics, clean shutdown.

### Hardened
- **Bounded stdin reader** — each line read is capped, so a pathological unbounded input line can't
  amplify memory.
- **Enforcer dedup** is now **seeded from existing deny-files** on startup (a restart no longer
  re-appends what's already denied) and **capped** (a rotating-target flood can't grow the set
  without bound — worst case is re-appending one duplicate the guards tolerate).

## [0.2.0] — dynamic config + speculative parallelism

### Added
- **Hot-reload** of the HCL policy: `LiveRules` watches the policy file and swaps rules live
  (~2s poll), no restart — any program that rewrites the file updates the rules. A parse error keeps
  the current rules (a bad edit never disarms the engine). `LiveRules::reload()` force-applies now
  (for a signal handler or an embedder's admin API).
- **Speculative parallelism**: when L1 escalates at or above `A3S_SENTRY_SPECULATE` severity (and both
  L2+L3 are configured), L2 and L3 run concurrently instead of serially. A fast L2 `Block`
  short-circuits for response time; otherwise L3's deeper verdict — already running — is authoritative.
  Also `Pipeline::speculate_above`.
- Embeddable library API: `Pipeline` tiers are now `Arc<dyn Judge>`; `LiveRules` is a `Judge`, so an
  in-process embedder can build the pipeline and apply config changes at runtime.

### Changed
- Daemon banner shows the live rule count + speculate state; audit now surfaces flagged-but-allowed
  events (severity > Info or decided by a deeper tier), not just blocks.

## [0.1.0] — initial release

Tiered (L1 rules / L2 LLM / L3 a3s-code agent) runtime security control built on a3s-observer:
observer NDJSON events → 3-tier judge → observer deny-files → kernel EPERM. Adversarially reviewed
(rule bypass, enforce blast-radius, judge-injection, robustness) before release.
