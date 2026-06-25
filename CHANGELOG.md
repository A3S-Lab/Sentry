# Changelog

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
