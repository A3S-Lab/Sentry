//! Mechanistic-interpretability tier — scoring an LLM output from the model's own residual-stream
//! features, not its surface text.
//!
//! a3s-power serves the model inside a TEE and taps the residual stream at one layer, encodes it with
//! a Sparse Autoencoder, and emits only the sparse `(feature_id, activation)` pairs as an
//! [`Event::LlmActivations`] — the prompt/completion plaintext never leaves the enclave. This tier
//! ([`SaeJudge`]) scores those features against a *labeled feature dictionary* (each SAE feature →
//! a named safety concept + calibrated weight), so the verdict is:
//!
//! - **white-box** — it judges what the model *internally represented*, so a base64/cipher-obfuscated
//!   harmful output still lights its concept feature;
//! - **confidential** — only feature ids/activations are seen, never the text;
//! - **explainable** — the score is *linear in named features*, decomposed into ranked [`Driver`]s,
//!   not a second black box.

use crate::event::{Event, ObservedEvent};
use crate::pipeline::Judge;
use crate::verdict::{Decision, Driver, SaeScore, Severity, Tier, Verdict};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};

/// One SAE feature's safety meaning — turns an anonymous feature id into a named, weighted concept.
/// Produced offline by probing the SAE on a labeled safety set + causal validation (ablate the
/// feature, confirm the score moves). `weight` is the calibrated harmful contribution per unit
/// activation.
#[derive(Debug, Clone, Deserialize)]
pub struct FeatureLabel {
    pub concept: String,
    pub category: String,
    pub weight: f32,
    #[serde(default = "default_severity")]
    pub severity: Severity,
}

fn default_severity() -> Severity {
    Severity::High
}

/// The labeled feature dictionary: SAE feature id → its safety meaning. Features absent from the
/// dictionary contribute nothing (benign-by-default).
pub type FeatureDict = HashMap<u32, FeatureLabel>;

/// Scores a model output from its SAE feature activations against a labeled feature dictionary.
/// Confidential (sees only `(id, activation)` from a3s-power's enclave) and auditable (linear in
/// interpretable features). Thresholds map the harmful score onto block / escalate / allow.
pub struct SaeJudge {
    dict: FeatureDict,
    escalate_at: f32,
    block_at: f32,
    top_drivers: usize,
}

impl SaeJudge {
    /// Build from a labeled feature dictionary. Defaults: escalate ≥0.30, block ≥0.60, top-6 drivers.
    pub fn new(dict: FeatureDict) -> Self {
        Self {
            dict,
            escalate_at: 0.30,
            block_at: 0.60,
            top_drivers: 6,
        }
    }

    /// Load the dictionary from a JSON map: `{ "8801": {concept, category, weight, severity?}, ... }`.
    pub fn from_json(json: &str) -> anyhow::Result<Self> {
        let raw: HashMap<String, FeatureLabel> = serde_json::from_str(json)?;
        let dict = raw
            .into_iter()
            .filter_map(|(k, v)| k.parse::<u32>().ok().map(|id| (id, v)))
            .collect();
        Ok(Self::new(dict))
    }

    pub fn thresholds(mut self, escalate_at: f32, block_at: f32) -> Self {
        self.escalate_at = escalate_at;
        self.block_at = block_at;
        self
    }

    /// Pure scoring: features → an explainable [`SaeScore`]. `harmful` is the worst category (a single
    /// severe category is never diluted by benign ones); `drivers` are the top weighted contributors.
    pub fn score(&self, features: &[(u32, f32)]) -> SaeScore {
        let mut per_category: BTreeMap<String, f32> = BTreeMap::new();
        let mut drivers: Vec<Driver> = Vec::new();
        for &(id, act) in features {
            let Some(label) = self.dict.get(&id) else {
                continue;
            };
            let contribution = (label.weight * act).clamp(0.0, 1.0);
            if contribution <= 0.0 {
                continue;
            }
            *per_category.entry(label.category.clone()).or_insert(0.0) += contribution;
            drivers.push(Driver {
                concept: label.concept.clone(),
                category: label.category.clone(),
                source: format!("sae_feature:#{id}"),
                activation: act,
                contribution,
            });
        }
        for v in per_category.values_mut() {
            *v = v.min(1.0);
        }
        let harmful = per_category
            .values()
            .copied()
            .fold(0.0_f32, f32::max)
            .clamp(0.0, 1.0);
        drivers.sort_by(|a, b| {
            b.contribution
                .partial_cmp(&a.contribution)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        drivers.truncate(self.top_drivers);
        SaeScore {
            harmful,
            safety: 1.0 - harmful,
            per_category,
            drivers,
            channel: "activation",
        }
    }

    fn severity_of(harmful: f32) -> Severity {
        if harmful >= 0.85 {
            Severity::Critical
        } else if harmful >= 0.60 {
            Severity::High
        } else if harmful >= 0.30 {
            Severity::Medium
        } else if harmful >= 0.10 {
            Severity::Low
        } else {
            Severity::Info
        }
    }
}

impl Judge for SaeJudge {
    fn tier(&self) -> Tier {
        Tier::Sae
    }

    fn judge(&self, ev: &ObservedEvent) -> Decision {
        let Event::LlmActivations { features, .. } = &ev.event else {
            // This tier only judges model-output activations; on anything else it has no opinion.
            return Decision::allow(Tier::Sae, "no model activations to score");
        };
        let score = self.score(features);
        let severity = Self::severity_of(score.harmful);
        let top = score
            .drivers
            .first()
            .map(|d| format!("{} ({})", d.concept, d.source))
            .unwrap_or_else(|| "no safety features".to_owned());
        let cats: Vec<String> = score
            .per_category
            .iter()
            .map(|(c, v)| format!("{c}={v:.2}"))
            .collect();
        let reason = format!(
            "SAE harmful={:.2} [{}]: {top}",
            score.harmful,
            cats.join(", ")
        );
        let verdict = if score.harmful >= self.block_at {
            Verdict::Block
        } else if score.harmful >= self.escalate_at {
            Verdict::Escalate
        } else {
            Verdict::Allow
        };
        // The output *text* has no natural deny target (not an IP/path/binary). This tier scores +
        // explains; a kernel block, if warranted, rides the enclosing ToolExec/Egress action event.
        Decision {
            verdict,
            tier: Tier::Sae,
            severity,
            reason,
            action: None,
            explain: Some(score),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Identity;

    fn dict() -> FeatureDict {
        let mut d = FeatureDict::new();
        d.insert(
            8801,
            FeatureLabel {
                concept: "exploit-code-synthesis".into(),
                category: "cyber_offense".into(),
                weight: 0.9,
                severity: Severity::High,
            },
        );
        d.insert(
            221,
            FeatureLabel {
                concept: "jailbreak-compliance".into(),
                category: "jailbreak".into(),
                weight: 0.5,
                severity: Severity::Medium,
            },
        );
        d
    }

    fn ev(features: Vec<(u32, f32)>) -> ObservedEvent {
        ObservedEvent {
            identity: Identity::default(),
            provider: None,
            event: Event::LlmActivations {
                pid: 1,
                layer: 18,
                features,
            },
            raw: String::new(),
        }
    }

    #[test]
    fn harmful_output_blocks_with_named_drivers() {
        let j = SaeJudge::new(dict());
        let d = j.judge(&ev(vec![(8801, 0.95), (12, 0.4), (221, 0.2)]));
        assert_eq!(d.verdict, Verdict::Block);
        assert_eq!(d.tier, Tier::Sae);
        let ex = d.explain.expect("explain present");
        assert!(ex.harmful >= 0.6, "harmful={}", ex.harmful);
        assert_eq!(ex.drivers[0].concept, "exploit-code-synthesis");
        assert_eq!(ex.drivers[0].source, "sae_feature:#8801");
        assert!(ex.per_category.contains_key("cyber_offense"));
    }

    #[test]
    fn benign_output_allows() {
        let j = SaeJudge::new(dict());
        let d = j.judge(&ev(vec![(10, 0.9), (99, 0.5)])); // ids not in the safety dict
        assert_eq!(d.verdict, Verdict::Allow);
        assert!(d.explain.unwrap().harmful < 0.1);
    }

    #[test]
    fn moderate_output_escalates() {
        let j = SaeJudge::new(dict());
        let d = j.judge(&ev(vec![(221, 0.8)])); // 0.5*0.8=0.40 → escalate (≥0.30, <0.60)
        assert_eq!(d.verdict, Verdict::Escalate);
    }

    #[test]
    fn worst_category_not_diluted_by_benign() {
        let j = SaeJudge::new(dict());
        let s = j.score(&[(8801, 0.9)]); // 0.9*0.9 = 0.81
        assert!((s.harmful - 0.81).abs() < 0.05, "harmful={}", s.harmful);
    }
}
