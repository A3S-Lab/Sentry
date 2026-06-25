# Changelog

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
