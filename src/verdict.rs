//! The decision types every tier produces.
//!
//! A tier looks at one observed event and returns a [`Decision`]: `Allow` it, `Block` it (optionally
//! naming a concrete [`EnforceAction`] for the kernel to deny), or `Escalate` it to the next, deeper
//! tier. Escalation is how cheap tiers defer to expensive ones only when they're genuinely unsure.

use serde::{Deserialize, Serialize};

/// What a tier concluded about an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Safe — let it through.
    Allow,
    /// Dangerous — stop it (and any matching [`EnforceAction`]).
    Block,
    /// Unsure — hand off to the next, deeper tier.
    Escalate,
}

/// Severity of a finding, independent of the verdict (an `Allow` can still be `Info`-noted).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Which tier produced a decision (audit + cost accounting).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Tier {
    /// L1 — deterministic rule engine.
    Rules,
    /// L2 — fast LLM classifier.
    Llm,
    /// L3 — deep a3s-code agent investigation.
    Agent,
}

/// A concrete block to push down to a3s-observer's deny-files. The target string is an IP/host
/// (egress), or a path (file / exec binary) — matching what the observer guards read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum EnforceAction {
    DenyEgress(String),
    DenyFile(String),
    DenyExec(String),
}

/// A tier's conclusion about one event.
#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub verdict: Verdict,
    pub tier: Tier,
    pub severity: Severity,
    pub reason: String,
    /// The concrete deny to enforce — present only when `verdict == Block` and the event carries a
    /// target (an egress IP, a file path, an exec binary).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<EnforceAction>,
}

impl Decision {
    pub fn allow(tier: Tier, reason: impl Into<String>) -> Self {
        Self {
            verdict: Verdict::Allow,
            tier,
            severity: Severity::Info,
            reason: reason.into(),
            action: None,
        }
    }

    pub fn block(tier: Tier, severity: Severity, reason: impl Into<String>) -> Self {
        Self {
            verdict: Verdict::Block,
            tier,
            severity,
            reason: reason.into(),
            action: None,
        }
    }

    pub fn escalate(tier: Tier, severity: Severity, reason: impl Into<String>) -> Self {
        Self {
            verdict: Verdict::Escalate,
            tier,
            severity,
            reason: reason.into(),
            action: None,
        }
    }

    pub fn with_action(mut self, action: Option<EnforceAction>) -> Self {
        self.action = action;
        self
    }
}
