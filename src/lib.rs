//! a3s-sentry — tiered runtime security control for AI agents.
//!
//! Sentry is the **policy brain** for [a3s-observer](https://github.com/A3S-Lab/Observer): it reads
//! observer's event stream (what an agent ran, sent, escalated), judges each event through three
//! escalating tiers, and pushes a block down to observer's kernel guards when something is dangerous.
//!
//! ```text
//! observer NDJSON ─▶ L1 rules ──escalate─▶ L2 LLM ──escalate─▶ L3 a3s-code agent
//!                       │ block                │ block              │ block
//!                       ▼                      ▼                    ▼
//!                    Enforcer ──▶ observer deny-files ──▶ kernel denies (EPERM)
//! ```
//!
//! - **L1** ([`RuleEngine`]) — deterministic regex rules; cheap, runs on every event.
//! - **L2** ([`LlmJudge`]) — a fast LLM classifier; a second opinion on the ambiguous ones.
//! - **L3** ([`AgentJudge`]) — a deep a3s-code investigation; for the genuinely hard cases.
//!
//! The tiers are composed by [`Pipeline`]; each is a [`Judge`], so the set is swappable and testable.

pub mod agent;
pub mod enforce;
pub mod event;
pub mod llm;
pub mod pipeline;
pub mod rules;
pub mod verdict;

pub use agent::AgentJudge;
pub use enforce::Enforcer;
pub use event::{Event, Identity, ObservedEvent};
pub use llm::LlmJudge;
pub use pipeline::{Judge, Pipeline};
pub use rules::{default_rules, LiveRules, RuleEngine, RuleSpec};
pub use verdict::{Decision, EnforceAction, Severity, Tier, Verdict};
