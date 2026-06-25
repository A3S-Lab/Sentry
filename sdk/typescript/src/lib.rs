//! Native (napi) Node binding for a3s-sentry's in-process judge.
//!
//! `Sentry.create(config)` builds the embedded L1→L2→L3 pipeline from one ACL config; `evaluate`
//! judges an observer event in-process and returns a typed `Decision`. No daemon, no subprocess
//! (beyond what L3 itself spawns) — the same model as @a3s-lab/code.

use a3s_sentry::{EnforceAction as CoreAction, Sentry as CoreSentry, Severity, Tier, Verdict};
use napi_derive::napi;

#[napi(object)]
pub struct EnforceAction {
    /// `DenyEgress` | `DenyFile` | `DenyExec`.
    pub kind: String,
    /// The IP/host, path, or binary the kernel guard will deny.
    pub target: String,
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
}

#[napi(object)]
pub struct EnforceResult {
    pub decision: Decision,
    /// The deny-file the block was written to, if any.
    pub enforced: Option<String>,
}

/// An in-process sentry judge built from one ACL config.
#[napi]
pub struct Sentry {
    inner: CoreSentry,
}

#[napi]
impl Sentry {
    /// Build from an ACL config: a file path (if it exists) or ACL content.
    #[napi(factory)]
    pub fn create(config: String) -> napi::Result<Sentry> {
        CoreSentry::create(&config)
            .map(|inner| Sentry { inner })
            .map_err(|e| napi::Error::from_reason(e.to_string()))
    }

    /// Judge one observer event (a JSON line/object). `null` if it isn't a parseable event.
    #[napi]
    pub fn evaluate(&self, event: String) -> Option<Decision> {
        self.inner.evaluate(&event).map(to_decision)
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
