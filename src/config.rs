//! Unified ACL config for the in-process SDK.
//!
//! Where the daemon is configured by environment variables, the embeddable [`Sentry`](crate::Sentry)
//! reads one ACL file — the same a3s config language a3s-code uses — that carries everything: the L1
//! rules, the L2/L3 backends, the deny-file sinks, and the fail mode. Example:
//!
//! ```hcl
//! fail_closed = false
//! speculate   = "high"        # optional: run L2+L3 in parallel at/above this severity
//!
//! llm   { url = "http://llm:18051/v1" model = "glm" key = "..." timeout_s = 30 }   # L2 (optional)
//! agent { bin = "a3s-code" skills = "./skills" timeout_s = 120 }                    # L3 (optional)
//! sae   { dict = "features.json" escalate_at = 0.3 block_at = 0.6 }                 # mech-interp (optional)
//! deny  { egress = "egress.txt" file = "file.txt" exec = "exec.txt" }               # sinks (optional)
//!
//! rules = [
//!   { name = "no-netcat" on = "ToolExec" match = "(?i)\\bnetcat\\b"
//!     verdict = "block" severity = "medium" reason = "netcat" action = "deny-exec" },
//! ]
//! ```

use crate::enforce::Enforcer;
use crate::pipeline::{Judge, Pipeline};
use crate::rules::{default_rules, LiveRules, RuleEngine, RuleSpec};
use crate::sae::SaeJudge;
use crate::verdict::Severity;
use crate::{AgentJudge, LlmJudge};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// The whole embeddable configuration, deserialized from one ACL document.
#[derive(Debug, Default, Deserialize)]
pub struct SdkConfig {
    #[serde(default)]
    pub fail_closed: bool,
    #[serde(default)]
    pub dry_run: bool,
    /// Run L2 + L3 in parallel when L1 escalates at/above this severity (`info`..`critical`).
    pub speculate: Option<String>,
    /// L2 — a fast LLM classifier (OpenAI-compatible). Omit for rules-only / rules+L3.
    pub llm: Option<LlmCfg>,
    /// L3 — a deep a3s-code agent investigation. Omit if you don't run L3.
    pub agent: Option<AgentCfg>,
    /// SAE mechanistic-interpretability tier — judges model-output `LlmActivations` events (from
    /// a3s-power's in-enclave tap) against a labeled feature dictionary. Omit if you don't run it.
    pub sae: Option<SaeCfg>,
    /// Deny-file sinks the kernel guards read. Omit to judge without enforcing.
    pub deny: Option<DenyCfg>,
    /// L1 site rules, evaluated before the built-in defaults (first match wins).
    #[serde(default)]
    pub rules: Vec<RuleSpec>,
}

#[derive(Debug, Deserialize)]
pub struct LlmCfg {
    pub url: String,
    pub model: Option<String>,
    pub key: Option<String>,
    pub timeout_s: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct AgentCfg {
    pub bin: String,
    pub skills: Option<String>,
    pub timeout_s: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct SaeCfg {
    /// Path to the labeled feature dictionary JSON: `{ "8801": {concept, category, weight, severity?}, ... }`.
    pub dict: String,
    /// harmful ≥ this → escalate (default 0.30).
    pub escalate_at: Option<f32>,
    /// harmful ≥ this → block (default 0.60).
    pub block_at: Option<f32>,
}

#[derive(Debug, Default, Deserialize)]
pub struct DenyCfg {
    pub egress: Option<String>,
    pub file: Option<String>,
    pub exec: Option<String>,
}

impl SdkConfig {
    /// Parse an ACL config document.
    pub fn from_acl(acl: &str) -> anyhow::Result<Self> {
        hcl::from_str(acl).map_err(|e| anyhow::anyhow!("parsing sentry ACL config: {e}"))
    }

    /// Read + parse an ACL config file.
    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let acl = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading config {}: {e}", path.display()))?;
        Self::from_acl(&acl)
    }

    /// Build the judge [`Pipeline`] and the [`Enforcer`] this config describes.
    pub fn build(self) -> anyhow::Result<(Pipeline, Enforcer)> {
        // L1: site rules first, then the built-in defaults (first match wins).
        let mut specs = self.rules;
        specs.extend(default_rules());
        let l1: Arc<dyn Judge> = Arc::new(LiveRules::from_engine(RuleEngine::new(specs)?));

        let mut pipeline = Pipeline::new(l1).fail_closed(self.fail_closed);
        if let Some(sev) = self.speculate.as_deref() {
            pipeline = pipeline.speculate_above(Some(parse_severity(sev)));
        }
        if let Some(l) = self.llm {
            pipeline = pipeline.with_l2(Arc::new(LlmJudge::new(
                &l.url,
                l.model.as_deref().unwrap_or("default"),
                l.key,
                Duration::from_secs(l.timeout_s.unwrap_or(30)),
            )));
        }
        if let Some(a) = self.agent {
            pipeline = pipeline.with_l3(Arc::new(AgentJudge::new(
                a.bin,
                a.skills,
                Duration::from_secs(a.timeout_s.unwrap_or(120)),
                self.fail_closed,
            )));
        }
        if let Some(s) = self.sae {
            let mut judge = SaeJudge::from_path(Path::new(&s.dict))?;
            if let (Some(e), Some(b)) = (s.escalate_at, s.block_at) {
                judge = judge.thresholds(e, b);
            }
            pipeline = pipeline.with_sae(Arc::new(judge));
        }

        let deny = self.deny.unwrap_or_default();
        let enforcer = Enforcer::new(
            deny.egress.map(PathBuf::from),
            deny.file.map(PathBuf::from),
            deny.exec.map(PathBuf::from),
            self.dry_run,
        );
        Ok((pipeline, enforcer))
    }
}

/// Parse a severity name; anything unrecognized is `high` (the conservative speculate default).
fn parse_severity(s: &str) -> Severity {
    match s.trim().to_ascii_lowercase().as_str() {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "critical" => Severity::Critical,
        _ => Severity::High,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Tier, Verdict};

    #[test]
    fn sae_block_wires_the_tier_and_judges_activations() {
        // A labeled feature dictionary on disk.
        let dir = std::env::temp_dir();
        let dict_path = dir.join("sentry_sae_cfg_test_dict.json");
        std::fs::write(
            &dict_path,
            r#"{"8801":{"concept":"exploit-code-synthesis","category":"cyber_offense","weight":0.9,"severity":"high"}}"#,
        )
        .unwrap();

        let acl = format!(
            "fail_closed = false\nsae {{ dict = \"{}\" }}\n",
            dict_path.display()
        );
        let (pipeline, _enforcer) = SdkConfig::from_acl(&acl).unwrap().build().unwrap();

        // A model-output activations line with the harmful feature firing → blocked + explained.
        let line = r#"{"identity":{"agent":"deep-finance"},"event":{"LlmActivations":{"pid":1,"layer":18,"features":[[8801,0.95]]}}}"#;
        let ev = crate::event::ObservedEvent::parse(line).expect("parses");
        let d = pipeline.evaluate(&ev);
        assert_eq!(d.verdict, Verdict::Block);
        assert_eq!(d.tier, Tier::Sae);
        let ex = d.explain.expect("explainability present");
        assert_eq!(ex.drivers[0].concept, "exploit-code-synthesis");

        let _ = std::fs::remove_file(&dict_path);
    }
}
