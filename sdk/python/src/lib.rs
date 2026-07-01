//! Native (PyO3) Python bindings for `a3s-sentry`.
//!
//! This is an **in-process** binding: `Sentry` wraps the same `a3s_sentry::Sentry` judge the daemon
//! runs, so judging happens in the Python process with no daemon and no subprocess (beyond what an
//! L3 agent tier itself spawns). It mirrors the core API one-to-one:
//!
//! ```python
//! from a3s_sentry import Sentry, egress
//! s = Sentry.create("sentry.acl")          # path or inline ACL content
//! d = s.evaluate(egress(123, "169.254.169.254", 80))
//! assert d.verdict == "block"
//! ```

use ::a3s_sentry::verdict::{Decision as CoreDecision, EnforceAction as CoreAction, RiskType as CoreRiskType, Severity, Tier, Verdict};
use ::a3s_sentry::Sentry as CoreSentry;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde_json::json;

/// A concrete deny pushed to a3s-observer's deny-files: `kind` is `DenyEgress`/`DenyFile`/`DenyExec`,
/// `target` is the IP/host (egress) or path/binary (file/exec).
#[pyclass(get_all)]
#[derive(Clone)]
struct EnforceAction {
    kind: String,
    target: String,
}

#[pymethods]
impl EnforceAction {
    fn __repr__(&self) -> String {
        format!("EnforceAction(kind={:?}, target={:?})", self.kind, self.target)
    }
}

impl From<&CoreAction> for EnforceAction {
    fn from(a: &CoreAction) -> Self {
        let (kind, target) = match a {
            CoreAction::DenyEgress(t) => ("DenyEgress", t),
            CoreAction::DenyFile(t) => ("DenyFile", t),
            CoreAction::DenyExec(t) => ("DenyExec", t),
        };
        Self {
            kind: kind.to_string(),
            target: target.clone(),
        }
    }
}

/// Stable risk taxonomy attached to a decision, e.g. category=`systemic_risk`,
/// risk_type=`system`.
#[pyclass(get_all)]
#[derive(Clone)]
struct RiskDescriptor {
    category: String,
    name: String,
    risk_type: String,
}

#[pymethods]
impl RiskDescriptor {
    fn __repr__(&self) -> String {
        format!(
            "RiskDescriptor(category={:?}, name={:?}, risk_type={:?})",
            self.category, self.name, self.risk_type
        )
    }
}

/// One tier's conclusion about an event. `verdict` is `"allow"`/`"block"`/`"escalate"`, `tier` is
/// `"Rules"`/`"Llm"`/`"Agent"`, `severity` is `"info"`..`"critical"`, and `action` is the concrete
/// deny (or `None`).
#[pyclass(get_all)]
#[derive(Clone)]
struct Decision {
    verdict: String,
    tier: String,
    severity: String,
    reason: String,
    action: Option<EnforceAction>,
    risk: Option<RiskDescriptor>,
}

#[pymethods]
impl Decision {
    fn __repr__(&self) -> String {
        format!(
            "Decision(verdict={:?}, tier={:?}, severity={:?}, reason={:?}, action={}, risk={})",
            self.verdict,
            self.tier,
            self.severity,
            self.reason,
            match &self.action {
                Some(a) => a.__repr__(),
                None => "None".to_string(),
            },
            match &self.risk {
                Some(r) => r.__repr__(),
                None => "None".to_string(),
            }
        )
    }
}

fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "allow",
        Verdict::Block => "block",
        Verdict::Escalate => "escalate",
    }
}

fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn tier_str(t: Tier) -> &'static str {
    match t {
        Tier::Rules => "Rules",
        Tier::Llm => "Llm",
        Tier::Agent => "Agent",
        Tier::Sae => "Sae",
    }
}

impl From<CoreDecision> for Decision {
    fn from(d: CoreDecision) -> Self {
        Self {
            verdict: verdict_str(d.verdict).to_string(),
            tier: tier_str(d.tier).to_string(),
            severity: severity_str(d.severity).to_string(),
            reason: d.reason,
            action: d.action.as_ref().map(EnforceAction::from),
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
}

/// The in-process sentry judge — wraps `a3s_sentry::Sentry`.
#[pyclass]
struct Sentry {
    inner: CoreSentry,
}

#[pymethods]
impl Sentry {
    /// Build a judge from `config`: an ACL file **path** (if it's a readable file) or inline ACL
    /// **content** otherwise. Raises `ValueError` on a bad config.
    #[staticmethod]
    fn create(config: &str) -> PyResult<Self> {
        CoreSentry::create(config)
            .map(|inner| Self { inner })
            .map_err(|e| PyValueError::new_err(format!("{e:#}")))
    }

    /// Judge one observer event (a JSON line). Returns the `Decision`, or `None` if `event` isn't a
    /// parseable observer event.
    fn evaluate(&self, event: &str) -> Option<Decision> {
        self.inner.evaluate(event).map(Decision::from)
    }

    /// Judge one event and, on a `block` carrying a target, write the deny to the configured
    /// deny-file. Returns `(Decision, enforced_path_or_None)`, or `None` if `event` isn't parseable.
    fn evaluate_and_enforce(&self, event: &str) -> Option<(Decision, Option<String>)> {
        self.inner
            .evaluate_and_enforce(event)
            .map(|(d, path)| (Decision::from(d), path))
    }
}

// --- Event builders: return the observer event JSON string `evaluate` takes. ---

/// Attach optional `identity`/`provider` onto an event envelope.
fn wrap(
    variant: &str,
    body: serde_json::Value,
    agent: Option<&str>,
    provider: Option<&str>,
) -> String {
    let mut env = json!({ "event": { variant: body } });
    if let Some(a) = agent {
        env["identity"] = json!({ "agent": a });
    }
    if let Some(p) = provider {
        env["provider"] = json!(p);
    }
    env.to_string()
}

#[pyfunction]
#[pyo3(signature = (pid, argv, agent=None, provider=None))]
fn tool_exec(pid: u32, argv: Vec<String>, agent: Option<&str>, provider: Option<&str>) -> String {
    wrap("ToolExec", json!({ "pid": pid, "argv": argv }), agent, provider)
}

#[pyfunction]
#[pyo3(signature = (pid, peer, port=0, agent=None, provider=None))]
fn egress(pid: u32, peer: &str, port: u16, agent: Option<&str>, provider: Option<&str>) -> String {
    wrap("Egress", json!({ "pid": pid, "peer": peer, "port": port }), agent, provider)
}

#[pyfunction]
#[pyo3(signature = (pid, path, write=false, agent=None, provider=None))]
fn file_access(pid: u32, path: &str, write: bool, agent: Option<&str>, provider: Option<&str>) -> String {
    wrap("FileAccess", json!({ "pid": pid, "path": path, "write": write }), agent, provider)
}

#[pyfunction]
#[pyo3(signature = (pid, query, agent=None, provider=None))]
fn dns(pid: u32, query: &str, agent: Option<&str>, provider: Option<&str>) -> String {
    wrap("Dns", json!({ "pid": pid, "query": query }), agent, provider)
}

#[pyfunction]
#[pyo3(signature = (pid, content, is_read=false, agent=None, provider=None))]
fn ssl_content(pid: u32, content: &str, is_read: bool, agent: Option<&str>, provider: Option<&str>) -> String {
    wrap("SslContent", json!({ "pid": pid, "is_read": is_read, "content": content }), agent, provider)
}

#[pyfunction]
#[pyo3(signature = (pid, kind, detail=0, agent=None, provider=None))]
fn security_action(pid: u32, kind: &str, detail: u64, agent: Option<&str>, provider: Option<&str>) -> String {
    wrap("SecurityAction", json!({ "pid": pid, "kind": kind, "detail": detail }), agent, provider)
}

#[pymodule]
fn a3s_sentry(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Sentry>()?;
    m.add_class::<Decision>()?;
    m.add_class::<EnforceAction>()?;
    m.add_class::<RiskDescriptor>()?;
    m.add_function(wrap_pyfunction!(tool_exec, m)?)?;
    m.add_function(wrap_pyfunction!(egress, m)?)?;
    m.add_function(wrap_pyfunction!(file_access, m)?)?;
    m.add_function(wrap_pyfunction!(dns, m)?)?;
    m.add_function(wrap_pyfunction!(ssl_content, m)?)?;
    m.add_function(wrap_pyfunction!(security_action, m)?)?;
    Ok(())
}
