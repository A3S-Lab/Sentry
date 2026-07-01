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

/// Broad grouping for operational dashboards and incident routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskType {
    /// System / infrastructure blast radius: metadata SSRF, privilege escalation, injection.
    System,
    /// Cross-boundary communication: secrets leaving, prompt injection, callbacks.
    Communication,
    /// One agent action: dangerous command, local credential access, other single-agent risk.
    Atomic,
}

/// Stable taxonomy attached to a non-allow decision. This belongs in sentry because it is part of
/// the policy brain's semantics; downstream platforms should not reverse-engineer it from prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskDescriptor {
    pub category: String,
    pub name: String,
    pub risk_type: RiskType,
}

impl RiskDescriptor {
    pub fn new(category: &str, name: &str, risk_type: RiskType) -> Self {
        Self {
            category: category.into(),
            name: name.into(),
            risk_type,
        }
    }

    /// Infer a stable risk taxonomy from the deciding rule/tier reason and event kind. This keeps
    /// custom L1 rules and L2/L3 outputs useful even when they don't explicitly name a category.
    pub fn infer(event_kind: &str, reason: &str) -> Self {
        let r = reason.to_lowercase();
        if (r.contains("metadata") || r.contains("ssrf"))
            && (event_kind == "Egress" || event_kind == "Dns")
        {
            return Self::new("systemic_risk", "Cloud metadata SSRF", RiskType::System);
        }
        if r.contains("privilege")
            || r.contains("ptrace")
            || r.contains("process injection")
            || r.contains("listening port")
            || r.contains("backdoor")
        {
            return Self::new(
                "privilege_escalation",
                "Privilege escalation / process injection",
                RiskType::System,
            );
        }
        if r.contains("secret in outbound")
            || r.contains("secret exfil")
            || r.contains("private key")
        {
            return Self::new(
                "secret_exfil",
                "Secret exfiltration",
                RiskType::Communication,
            );
        }
        if r.contains("prompt injection") || r.contains("jailbreak") {
            return Self::new(
                "prompt_injection",
                "Prompt injection / jailbreak",
                RiskType::Communication,
            );
        }
        if r.contains("exfil")
            || r.contains("callback")
            || r.contains("oob")
            || r.contains("dnslog")
        {
            return Self::new(
                "communication_risk",
                "Suspicious external communication",
                RiskType::Communication,
            );
        }
        if r.contains("credential") || r.contains("sensitive file") || event_kind == "FileAccess" {
            return Self::new(
                "data_leak",
                "Credential or sensitive file access",
                RiskType::Atomic,
            );
        }
        if r.contains("piped")
            || r.contains("reverse-shell")
            || r.contains("destructive")
            || r.contains("disk")
            || r.contains("rce")
            || event_kind == "ToolExec"
        {
            return Self::new(
                "command_danger",
                "Dangerous command execution",
                RiskType::Atomic,
            );
        }
        Self::new("other", "Other risk", RiskType::Atomic)
    }
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
    /// Stable risk taxonomy for non-allow decisions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<RiskDescriptor>,
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
            risk: None,
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
            risk: None,
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
            risk: None,
            explain: None,
        }
    }

    pub fn with_action(mut self, action: Option<EnforceAction>) -> Self {
        self.action = action;
        self
    }

    pub fn with_risk(mut self, risk: RiskDescriptor) -> Self {
        self.risk = Some(risk);
        self
    }

    pub fn with_inferred_risk(mut self, event_kind: &str) -> Self {
        self.risk = Some(RiskDescriptor::infer(event_kind, &self.reason));
        self
    }

    /// Attach the mechanistic explainability sidecar (SAE/probe drivers + per-category scores).
    pub fn with_explain(mut self, explain: SaeScore) -> Self {
        self.explain = Some(explain);
        self
    }
}
