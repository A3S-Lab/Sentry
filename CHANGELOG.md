# Changelog

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
