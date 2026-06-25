//! The escalation pipeline — L1 → L2 → L3.
//!
//! Every tier is a [`Judge`]. The pipeline runs L1; an `Allow`/`Block` is final, an `Escalate`
//! defers to the next tier. L3 is terminal (its `Escalate` is treated as its best guess). When a
//! tier wants to escalate but no deeper tier exists, the `fail_closed` knob decides: closed = treat
//! unresolved suspicion as `Block` (safety-first), open = `Allow` (availability-first, the default,
//! matching observer's fail-open guards). Either way the original suspicion is preserved in `reason`.

use crate::event::ObservedEvent;
use crate::verdict::{Decision, Severity, Tier, Verdict};

/// One tier. Cheap tiers (`L1`) run on every event; expensive ones (`L2`/`L3`) only on escalations.
pub trait Judge: Send + Sync {
    fn tier(&self) -> Tier;
    fn judge(&self, ev: &ObservedEvent) -> Decision;
}

/// The tiered judge. `l2`/`l3` are optional so you can run rules-only, rules+LLM, or all three.
pub struct Pipeline {
    l1: Box<dyn Judge>,
    l2: Option<Box<dyn Judge>>,
    l3: Option<Box<dyn Judge>>,
    fail_closed: bool,
}

impl Pipeline {
    pub fn new(l1: Box<dyn Judge>) -> Self {
        Self {
            l1,
            l2: None,
            l3: None,
            fail_closed: false,
        }
    }

    pub fn with_l2(mut self, l2: Box<dyn Judge>) -> Self {
        self.l2 = Some(l2);
        self
    }

    pub fn with_l3(mut self, l3: Box<dyn Judge>) -> Self {
        self.l3 = Some(l3);
        self
    }

    /// Treat an unresolved escalation (no deeper tier available) as `Block` instead of `Allow`.
    pub fn fail_closed(mut self, yes: bool) -> Self {
        self.fail_closed = yes;
        self
    }

    /// Run the event through the tiers and return the deciding [`Decision`].
    pub fn evaluate(&self, ev: &ObservedEvent) -> Decision {
        let d1 = self.l1.judge(ev);
        if d1.verdict != Verdict::Escalate {
            return d1;
        }
        let d2 = match &self.l2 {
            Some(l2) => l2.judge(ev),
            None => return self.resolve_unescalated(d1),
        };
        if d2.verdict != Verdict::Escalate {
            return d2;
        }
        match &self.l3 {
            // L3 is terminal: whatever it says (incl. its own escalate-as-best-guess) is final.
            Some(l3) => l3.judge(ev),
            None => self.resolve_unescalated(d2),
        }
    }

    /// A tier wanted to escalate but there's no deeper tier — decide per `fail_closed`, carrying the
    /// suspicion forward so the audit trail still shows what tripped.
    fn resolve_unescalated(&self, d: Decision) -> Decision {
        let verdict = if self.fail_closed {
            Verdict::Block
        } else {
            Verdict::Allow
        };
        Decision {
            verdict,
            tier: d.tier,
            severity: d.severity.max(Severity::Low),
            reason: format!(
                "{} [unresolved escalation, fail-{}]",
                d.reason,
                if self.fail_closed { "closed" } else { "open" }
            ),
            action: if verdict == Verdict::Block {
                d.action
            } else {
                None
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::ObservedEvent;

    struct Fixed(Tier, Verdict);
    impl Judge for Fixed {
        fn tier(&self) -> Tier {
            self.0
        }
        fn judge(&self, _: &ObservedEvent) -> Decision {
            match self.1 {
                Verdict::Allow => Decision::allow(self.0, "ok"),
                Verdict::Block => Decision::block(self.0, Severity::High, "bad"),
                Verdict::Escalate => Decision::escalate(self.0, Severity::Medium, "unsure"),
            }
        }
    }
    fn ev() -> ObservedEvent {
        ObservedEvent::parse(r#"{"event":{"ToolExec":{"pid":1,"argv":["x"]}}}"#).unwrap()
    }

    #[test]
    fn l1_block_is_final_no_l2_call() {
        let p = Pipeline::new(Box::new(Fixed(Tier::Rules, Verdict::Block)));
        assert_eq!(p.evaluate(&ev()).verdict, Verdict::Block);
    }

    #[test]
    fn escalates_l1_to_l2_to_l3() {
        let p = Pipeline::new(Box::new(Fixed(Tier::Rules, Verdict::Escalate)))
            .with_l2(Box::new(Fixed(Tier::Llm, Verdict::Escalate)))
            .with_l3(Box::new(Fixed(Tier::Agent, Verdict::Block)));
        let d = p.evaluate(&ev());
        assert_eq!(d.verdict, Verdict::Block);
        assert_eq!(d.tier, Tier::Agent);
    }

    #[test]
    fn unresolved_escalation_fail_open_allows_fail_closed_blocks() {
        let open = Pipeline::new(Box::new(Fixed(Tier::Rules, Verdict::Escalate)));
        assert_eq!(open.evaluate(&ev()).verdict, Verdict::Allow);

        let closed =
            Pipeline::new(Box::new(Fixed(Tier::Rules, Verdict::Escalate))).fail_closed(true);
        assert_eq!(closed.evaluate(&ev()).verdict, Verdict::Block);
    }
}
