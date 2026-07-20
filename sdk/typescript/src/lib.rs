//! Native (napi) Node binding for a3s-sentry's in-process judge.
//!
//! `Sentry.create(config)` builds the embedded L1→L2→L3 pipeline from one ACL config; `evaluate`
//! judges an observer event in-process and returns a typed `Decision`. No daemon, no subprocess
//! (beyond what L3 itself spawns) — the same model as @a3s-lab/code.

use a3s_sentry::{
    EnforceAction as CoreAction, RiskType as CoreRiskType, Sentry as CoreSentry, Severity, Tier,
    ThroughL2StageStatus as CoreThroughL2StageStatus, Verdict,
};
use napi::{bindgen_prelude::AsyncTask, Env, Task};
use napi_derive::napi;
use std::sync::Arc;

#[napi(object)]
pub struct EnforceAction {
    /// `DenyEgress` | `DenyFile` | `DenyExec`.
    pub kind: String,
    /// The IP/host, path, or binary the kernel guard will deny.
    pub target: String,
}

#[napi(object)]
pub struct RiskDescriptor {
    /// Stable taxonomy code, e.g. `systemic_risk` or `command_danger`.
    pub category: String,
    /// Human-readable label for operators.
    pub name: String,
    /// `system` | `communication` | `atomic`.
    pub risk_type: String,
}

#[napi(object)]
pub struct Decision {
    /// `allow` | `block` | `escalate`.
    pub verdict: String,
    /// The deciding tier: `Rules` | `Llm` | `Agent`.
    pub tier: String,
    /// `info` | `low` | `medium` | `high` | `critical`.
    pub severity: String,
    pub reason: String,
    pub action: Option<EnforceAction>,
    pub risk: Option<RiskDescriptor>,
}

#[napi(object)]
pub struct EnforceResult {
    pub decision: Decision,
    /// The deny-file the block was written to, if any.
    pub enforced: Option<String>,
}

#[napi(object)]
pub struct ThroughL2Result {
    pub l1_decision: Decision,
    pub l2_decision: Option<Decision>,
    pub effective_decision: Decision,
    /// `completed` | `escalated`.
    pub stage_status: String,
    /// `l1` | `l2` | `sae`, when the effective decision remains escalated.
    pub escalation_cause: Option<String>,
}

/// An in-process sentry judge built from one ACL config.
#[napi]
pub struct Sentry {
    inner: Arc<CoreSentry>,
}

pub struct EvaluateThroughL2Task {
    inner: Arc<CoreSentry>,
    event: String,
}

impl Task for EvaluateThroughL2Task {
    type Output = a3s_sentry::ThroughL2Result;
    type JsValue = ThroughL2Result;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        self.inner
            .evaluate_through_l2(&self.event)
            .ok_or_else(|| napi::Error::from_reason("event is not parseable"))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(to_through_l2_result(output))
    }
}

#[napi]
impl Sentry {
    /// Build from an ACL config: a file path (if it exists) or ACL content.
    #[napi(factory)]
    pub fn create(config: String) -> napi::Result<Sentry> {
        CoreSentry::create(&config)
            .map(|inner| Sentry {
                inner: Arc::new(inner),
            })
            .map_err(|e| napi::Error::from_reason(e.to_string()))
    }

    /// Judge one observer event (a JSON line/object). `null` if it isn't a parseable event.
    #[napi]
    pub fn evaluate(&self, event: String) -> Option<Decision> {
        self.inner.evaluate(&event).map(to_decision)
    }

    /// Judge through L2 on the napi worker pool, preserving escalation for an external L3 worker.
    #[napi]
    pub fn evaluate_through_l2(&self, event: String) -> AsyncTask<EvaluateThroughL2Task> {
        AsyncTask::new(EvaluateThroughL2Task {
            inner: Arc::clone(&self.inner),
            event,
        })
    }

    /// Judge and, on a block carrying a target, write it to the configured deny-file. `null` if the
    /// event isn't parseable.
    #[napi]
    pub fn evaluate_and_enforce(&self, event: String) -> Option<EnforceResult> {
        self.inner
            .evaluate_and_enforce(&event)
            .map(|(d, enforced)| EnforceResult {
                decision: to_decision(d),
                enforced,
            })
    }
}

fn to_through_l2_result(result: a3s_sentry::ThroughL2Result) -> ThroughL2Result {
    let stage_status = match result.stage_status {
        CoreThroughL2StageStatus::Completed => "completed",
        CoreThroughL2StageStatus::Escalated => "escalated",
    };
    ThroughL2Result {
        l1_decision: to_decision(result.l1_decision),
        l2_decision: result.l2_decision.map(to_decision),
        effective_decision: to_decision(result.effective_decision),
        stage_status: stage_status.to_string(),
        escalation_cause: result.escalation_cause.map(|cause| {
            match cause {
                a3s_sentry::EscalationCause::L1 => "l1",
                a3s_sentry::EscalationCause::L2 => "l2",
                a3s_sentry::EscalationCause::Sae => "sae",
            }
            .to_string()
        }),
    }
}

fn to_decision(d: a3s_sentry::Decision) -> Decision {
    let verdict = match d.verdict {
        Verdict::Allow => "allow",
        Verdict::Block => "block",
        Verdict::Escalate => "escalate",
    };
    let tier = match d.tier {
        Tier::Rules => "Rules",
        Tier::Llm => "Llm",
        Tier::Agent => "Agent",
        Tier::Sae => "Sae",
    };
    let severity = match d.severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    };
    Decision {
        verdict: verdict.to_string(),
        tier: tier.to_string(),
        severity: severity.to_string(),
        reason: d.reason,
        action: d.action.map(|a| {
            let (kind, target) = match a {
                CoreAction::DenyEgress(t) => ("DenyEgress", t),
                CoreAction::DenyFile(t) => ("DenyFile", t),
                CoreAction::DenyExec(t) => ("DenyExec", t),
            };
            EnforceAction {
                kind: kind.to_string(),
                target,
            }
        }),
        risk: d.risk.map(|r| RiskDescriptor {
            category: r.category,
            name: r.name,
            risk_type: match r.risk_type {
                CoreRiskType::System => "system",
                CoreRiskType::Communication => "communication",
                CoreRiskType::Atomic => "atomic",
            }
            .to_string(),
        }),
    }
}

// ── Event builders: construct the observer event JSON `evaluate` takes ──────────────────────────

#[napi]
pub fn tool_exec(pid: u32, argv: Vec<String>) -> String {
    serde_json::json!({ "event": { "ToolExec": { "pid": pid, "argv": argv } } }).to_string()
}

#[napi]
pub fn egress(pid: u32, peer: String, port: Option<u32>) -> String {
    serde_json::json!({ "event": { "Egress": { "pid": pid, "peer": peer, "port": port.unwrap_or(0) } } })
        .to_string()
}

#[napi]
pub fn file_access(pid: u32, path: String, write: Option<bool>) -> String {
    serde_json::json!({ "event": { "FileAccess": { "pid": pid, "path": path, "write": write.unwrap_or(false) } } })
        .to_string()
}

#[napi]
pub fn dns(pid: u32, query: String) -> String {
    serde_json::json!({ "event": { "Dns": { "pid": pid, "query": query } } }).to_string()
}

#[napi]
pub fn ssl_content(pid: u32, content: String, is_read: Option<bool>) -> String {
    serde_json::json!({ "event": { "SslContent": { "pid": pid, "is_read": is_read.unwrap_or(false), "content": content } } })
        .to_string()
}

#[napi]
pub fn security_action(pid: u32, kind: String, detail: Option<u32>) -> String {
    serde_json::json!({ "event": { "SecurityAction": { "pid": pid, "kind": kind, "detail": detail.unwrap_or(0) } } })
        .to_string()
}
