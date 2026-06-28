//! The embeddable judge — `Sentry`, the in-process API the native (napi / PyO3) SDKs bind to.
//!
//! Build it from one ACL config, then judge observer events in-process — no daemon, no subprocess
//! (beyond what L3 itself spawns). This is the library face of the same L1→L2→L3 pipeline the daemon
//! runs; the daemon is just `Sentry` wired to stdin/stdout + the worker pool.

use crate::config::SdkConfig;
use crate::enforce::Enforcer;
use crate::event::ObservedEvent;
use crate::inline::{self, Direction, InlineDecision};
use crate::pipeline::Pipeline;
use crate::verdict::{Decision, Verdict};
use std::path::Path;
use std::sync::Mutex;

/// An in-process sentry judge: an L1→L2→L3 [`Pipeline`] plus the [`Enforcer`] for its deny-file sinks.
pub struct Sentry {
    pipeline: Pipeline,
    enforcer: Mutex<Enforcer>,
}

impl Sentry {
    /// Build from an ACL config document (see [`SdkConfig`](crate::config::SdkConfig)).
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
}
