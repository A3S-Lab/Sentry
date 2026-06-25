//! @a3s-lab/sentry — a dependency-free TypeScript SDK for the a3s-sentry daemon.
//!
//! Author policy, run/supervise the daemon, submit events, stream typed decisions, and read
//! metrics — all from Node/TypeScript using only built-ins.

export {
  type Verdict,
  type Severity,
  type Tier,
  type EnforceKind,
  type EnforceAction,
  type Decision,
  type Audit,
  parseAudit,
  parseDecision,
  parseEnforceAction,
} from "./types.js";

export {
  Event,
  type Identity,
  type EventOptions,
  type SentryEvent,
} from "./events.js";

export {
  Policy,
  emptyPolicy,
  tmpDir,
  type Rule,
  type EventKind,
  type RuleAction,
} from "./policy.js";

export {
  Sentry,
  configToEnv,
  type SentryConfig,
} from "./process.js";

export {
  MetricsClient,
  parseMetrics,
  type MetricsSnapshot,
} from "./metrics.js";
