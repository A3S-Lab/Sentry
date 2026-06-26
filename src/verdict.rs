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
    /// Mechanistic interpretability — a Sparse Autoencoder over the model's residual stream, tapped
    /// in-enclave by a3s-power. Judges the model's *internal concepts* from feature activations
    /// (never the plaintext), so the score is white-box and confidential.
    Sae,
}

/// A concrete block to push down to a3s-observer's deny-files. The target string is an IP/host
/// (egress), or a path (file / exec binary) — matching what the observer guards read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum EnforceAction {
    DenyEgress(String),
    DenyFile(String),
    DenyExec(String),
}

/// One named contributor to an [`SaeScore`] — the explainability spine the dashboard renders. Each
/// driver is traceable (`source`) to a rule, a probe direction, or an SAE feature, with the
/// activation that fired and its weighted contribution to the harmful score.
#[derive(Debug, Clone, Serialize)]
pub struct Driver {
    pub concept: String,
    pub category: String,
    /// `"sae_feature:#8801"` | `"probe:cyber_offense"` | `"rule:CWE-94"`.
    pub source: String,
    pub activation: f32,
    pub contribution: f32,
}

/// The explainable safety score for one model output — the "why" behind a mechanistic [`Decision`].
/// The score is *linear in interpretable features*, so it's auditable rather than a second black box.
#[derive(Debug, Clone, Serialize)]
pub struct SaeScore {
    /// 0..1 — the worst category (a single severe category must not be diluted by benign ones).
    pub harmful: f32,
    pub safety: f32,
    pub per_category: std::collections::BTreeMap<String, f32>,
    pub drivers: Vec<Driver>,
    /// `"activation"` (white-box SAE/probe) | `"text"` (black-box judge fallback).
    pub channel: &'static str,
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
    /// The mechanistic explainability sidecar — present when an SAE/probe tier scored a model output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explain: Option<SaeScore>,
}

impl Decision {
    pub fn allow(tier: Tier, reason: impl Into<String>) -> Self {
        Self {
            verdict: Verdict::Allow,
            tier,
            severity: Severity::Info,
            reason: reason.into(),
            action: None,
            explain: None,
        }
    }

    pub fn block(tier: Tier, severity: Severity, reason: impl Into<String>) -> Self {
        Self {
            verdict: Verdict::Block,
            tier,
            severity,
            reason: reason.into(),
            action: None,
            explain: None,
        }
    }

    pub fn escalate(tier: Tier, severity: Severity, reason: impl Into<String>) -> Self {
        Self {
            verdict: Verdict::Escalate,
            tier,
            severity,
            reason: reason.into(),
            action: None,
            explain: None,
        }
    }

    pub fn with_action(mut self, action: Option<EnforceAction>) -> Self {
        self.action = action;
        self
    }

    /// Attach the mechanistic explainability sidecar (SAE/probe drivers + per-category scores).
    pub fn with_explain(mut self, explain: SaeScore) -> Self {
        self.explain = Some(explain);
        self
    }
}
