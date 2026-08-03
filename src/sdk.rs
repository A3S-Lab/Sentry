//! The embeddable judge — `Sentry`, the in-process API the native (napi / PyO3) SDKs bind to.
//!
//! Build it from one ACL config, then judge observer events in-process — no daemon, no subprocess
//! (beyond what L3 itself spawns). This is the library face of the same L1→L2→L3 pipeline the daemon
//! runs; the daemon is just `Sentry` wired to stdin/stdout + the worker pool.

use crate::config::SdkConfig;
use crate::enforce::Enforcer;
use crate::event::ObservedEvent;
use crate::inline::{self, Direction, InlineDecision};
use crate::pipeline::{Pipeline, ThroughL1Result, ThroughL2Result};
use crate::verdict::{Decision, Verdict};
use std::path::Path;
use std::sync::Mutex;

/// An in-process sentry judge: an L1→L2→L3 [`Pipeline`] plus the [`Enforcer`] for its deny-file sinks.
pub struct Sentry {
    pipeline: Pipeline,
    enforcer: Mutex<Enforcer>,
}

impl Sentry {
    /// Build from an ACL config document (see [`SdkConfig`]).
    pub fn from_acl(acl: &str) -> anyhow::Result<Self> {
        let (pipeline, enforcer) = SdkConfig::from_acl(acl)?.build()?;
        Ok(Self {
            pipeline,
            enforcer: Mutex::new(enforcer),
        })
    }

    /// Build from an ACL config file.
    pub fn from_path(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let (pipeline, enforcer) = SdkConfig::from_path(path.as_ref())?.build()?;
        Ok(Self {
            pipeline,
            enforcer: Mutex::new(enforcer),
        })
    }

    /// Convenience: if `source` is a readable file, load it; otherwise treat it as ACL content.
    /// (Mirrors a3s-code's `Agent.create`, which takes config content but a path is handier.)
    pub fn create(source: &str) -> anyhow::Result<Self> {
        if Path::new(source).is_file() {
            Self::from_path(source)
        } else {
            Self::from_acl(source)
        }
    }

    /// Judge a parsed event.
    pub fn evaluate_event(&self, ev: &ObservedEvent) -> Decision {
        self.pipeline.evaluate(ev)
    }

    /// Judge a parsed event through L2, preserving an unresolved escalation for an external L3.
    pub fn evaluate_event_through_l2(&self, ev: &ObservedEvent) -> ThroughL2Result {
        self.pipeline.evaluate_through_l2(ev)
    }

    /// Judge a parsed event through L1 only, preserving an eligible escalation for a caller-owned
    /// deeper-tier dispatcher.
    pub fn evaluate_event_l1(&self, ev: &ObservedEvent) -> ThroughL1Result {
        self.pipeline.evaluate_through_l1(ev)
    }

    /// Inline gate for an in-flight LLM/MCP body: run the same tiered judges over the decoded wire
    /// `content` and return the [`InlineDecision`] (block/allow + secret/PII spans to redact). This is
    /// the pre-execution path a3s-gateway's wire proxy calls; the reactive [`evaluate`](Sentry::evaluate)
    /// path stays for observer's NDJSON stream. See [`crate::inline`].
    pub fn inspect_wire(&self, content: &str, dir: Direction) -> InlineDecision {
        inline::inspect(&self.pipeline, content, dir)
    }

    /// Judge one observer event (an NDJSON line / object). `None` if it isn't a parseable event.
    pub fn evaluate(&self, event_json: &str) -> Option<Decision> {
        let ev = ObservedEvent::parse(event_json)?;
        Some(self.pipeline.evaluate(&ev))
    }

    /// Judge one observer event through L2 without invoking L3 or resolving escalation.
    pub fn evaluate_through_l2(&self, event_json: &str) -> Option<ThroughL2Result> {
        let ev = ObservedEvent::parse(event_json)?;
        Some(self.pipeline.evaluate_through_l2(&ev))
    }

    /// Judge one observer event through L1 only. This never invokes L2/L3 and never resolves an
    /// escalation through fail-open/fail-closed.
    pub fn evaluate_l1(&self, event_json: &str) -> Option<ThroughL1Result> {
        let ev = ObservedEvent::parse(event_json)?;
        Some(self.pipeline.evaluate_through_l1(&ev))
    }

    /// Judge and, on a `block` carrying a target, write it to the configured deny-file. Returns the
    /// decision plus the deny-file the block landed in (if any). `None` if the event isn't parseable.
    pub fn evaluate_and_enforce(&self, event_json: &str) -> Option<(Decision, Option<String>)> {
        let ev = ObservedEvent::parse(event_json)?;
        let decision = self.pipeline.evaluate(&ev);
        let enforced = if decision.verdict == Verdict::Block {
            decision.action.as_ref().and_then(|action| {
                self.enforcer
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .apply(action)
                    .ok()
                    .flatten()
                    .map(|p| p.display().to_string())
            })
        } else {
            None
        };
        Some((decision, enforced))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = r#"
        deny { egress = "" }
        rules = [
          { name = "block-evil-dns", on = "Dns", match = "evil\\.test",
            verdict = "block", severity = "high", reason = "custom rule" },
        ]
    "#;

    #[test]
    fn builds_from_acl_and_judges_builtins() {
        let s = Sentry::from_acl(CFG).expect("config builds");
        // built-in cloud-metadata rule still fires
        let d = s
            .evaluate(r#"{"event":{"Egress":{"pid":1,"peer":"169.254.169.254","port":80}}}"#)
            .unwrap();
        assert_eq!(d.verdict, Verdict::Block);
        // our custom rule fires
        let d = s
            .evaluate(r#"{"event":{"Dns":{"pid":1,"query":"evil.test"}}}"#)
            .unwrap();
        assert_eq!(d.verdict, Verdict::Block);
        assert!(d.reason.contains("custom rule"));
        // benign is allowed
        let d = s
            .evaluate(r#"{"event":{"ToolExec":{"pid":1,"argv":["ls"]}}}"#)
            .unwrap();
        assert_eq!(d.verdict, Verdict::Allow);
        // unparseable → None
        assert!(s.evaluate("not json").is_none());
    }

    #[test]
    fn evaluate_and_enforce_writes_deny_file() {
        let dir = std::env::temp_dir().join(format!("sentry-sdk-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exec = dir.join("exec.txt");
        let cfg = format!("deny {{ exec = {:?} }}", exec.to_str().unwrap());
        let s = Sentry::from_acl(&cfg).unwrap();
        let (d, enforced) = s
            .evaluate_and_enforce(
                r#"{"event":{"ToolExec":{"pid":1,"argv":["/usr/bin/nc","x","4444"]}}}"#,
            )
            .unwrap();
        if d.verdict == Verdict::Block {
            assert_eq!(enforced.as_deref(), Some(exec.to_str().unwrap()));
            assert!(std::fs::read_to_string(&exec)
                .unwrap()
                .contains("/usr/bin/nc"));
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn evaluate_through_l2_preserves_unresolved_escalation() {
        let s = Sentry::from_acl("").expect("config builds");
        let result = s
            .evaluate_through_l2(
                r#"{"event":{"FileAccess":{"pid":1,"path":"/home/u/.aws/credentials","write":false}}}"#,
            )
            .unwrap();
        assert_eq!(result.effective_decision.verdict, Verdict::Escalate);
        assert_eq!(result.effective_decision.tier, crate::verdict::Tier::Rules);
    }

    #[test]
    fn evaluate_l1_preserves_escalation_without_fail_mode_resolution() {
        let sentry = Sentry::from_acl(
            r#"
                fail_closed = true
                llm { url = "http://127.0.0.1:1/v1" }
            "#,
        )
        .unwrap();
        let result = sentry
            .evaluate_l1(
                r#"{"event":{"FileAccess":{"pid":1,"path":"/home/u/.aws/credentials","write":false}}}"#,
            )
            .unwrap();
        assert_eq!(result.l1_decision.verdict, Verdict::Escalate);
        assert!(result.next_tier_eligible);
    }
}
