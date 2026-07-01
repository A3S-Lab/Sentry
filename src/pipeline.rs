//! The escalation pipeline — L1 → L2 → L3.
//!
//! Every tier is a [`Judge`]. The pipeline runs L1; an `Allow`/`Block` is final, an `Escalate`
//! defers to the next tier. L3 is terminal. When a tier wants to escalate but no deeper tier exists,
//! the `fail_closed` knob decides: closed = `Block` (safety-first), open = `Allow` (availability-first,
//! the default, matching observer's fail-open guards). The suspicion is preserved in `reason`.
//!
//! **Speculative parallelism:** when L1 escalates at or above [`speculate_above`](Pipeline::speculate_above)
//! severity and both deeper tiers exist, L2 and L3 run *concurrently* instead of L2-then-maybe-L3.
//! L2 can short-circuit a `Block` for fast response; otherwise L3's deeper verdict — already running,
//! so ready sooner — is authoritative. High-risk events thus get the deep look without paying the
//! serial L2+L3 latency.

use crate::event::{Event, ObservedEvent};
use crate::verdict::{Decision, Severity, Tier, Verdict};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

/// Hard cap on concurrent *speculative* L3 investigations. The non-speculative path is already
/// bounded by the worker pool; speculation detaches L3 on a fast L2 `Block`, so without a cap a
/// high-risk flood could fan out unbounded agent subprocesses. Above the cap, evaluate falls back to
/// sequential (which joins L3) — still full analysis, just not parallel.
const DEFAULT_L3_SPEC_CAP: u64 = 8;

/// One tier. Cheap tiers (`L1`) run on every event; expensive ones (`L2`/`L3`) only on escalations.
/// `Send + Sync` so a tier can run on a worker thread (speculative parallelism).
pub trait Judge: Send + Sync {
    fn tier(&self) -> Tier;
    fn judge(&self, ev: &ObservedEvent) -> Decision;
}

/// The tiered judge. `l2`/`l3` are optional (rules-only, rules+LLM, or all three) and `Arc` so they
/// can be shared with a speculative worker thread.
pub struct Pipeline {
    l1: Arc<dyn Judge>,
    l2: Option<Arc<dyn Judge>>,
    l3: Option<Arc<dyn Judge>>,
    /// The SAE mechanistic-interpretability tier — judges model-output `LlmActivations` events from
    /// a3s-power's in-enclave feature emission (a separate domain from the observer-event rule chain).
    sae: Option<Arc<dyn Judge>>,
    fail_closed: bool,
    speculate_above: Option<Severity>,
    /// Live count of speculative L3 threads (incl. ones detached after an L2 short-circuit), so we
    /// can stop speculating once `l3_spec_cap` are already in flight.
    l3_inflight: Arc<AtomicU64>,
    l3_spec_cap: u64,
}

impl Pipeline {
    pub fn new(l1: Arc<dyn Judge>) -> Self {
        Self {
            l1,
            l2: None,
            l3: None,
            sae: None,
            fail_closed: false,
            speculate_above: None,
            l3_inflight: Arc::new(AtomicU64::new(0)),
            l3_spec_cap: DEFAULT_L3_SPEC_CAP,
        }
    }

    /// Cap on concurrent speculative L3 investigations (default 8). Set to 0 to disable speculation.
    pub fn l3_spec_cap(mut self, cap: u64) -> Self {
        self.l3_spec_cap = cap;
        self
    }

    pub fn with_l2(mut self, l2: Arc<dyn Judge>) -> Self {
        self.l2 = Some(l2);
        self
    }

    pub fn with_l3(mut self, l3: Arc<dyn Judge>) -> Self {
        self.l3 = Some(l3);
        self
    }

    /// The SAE mechanistic-interpretability tier. Model-output `LlmActivations` events route here
    /// instead of the L1 rule chain; an SAE escalation can still defer to the deep L3 agent.
    pub fn with_sae(mut self, sae: Arc<dyn Judge>) -> Self {
        self.sae = Some(sae);
        self
    }

    /// Treat an unresolved escalation (no deeper tier available) as `Block` instead of `Allow`.
    pub fn fail_closed(mut self, yes: bool) -> Self {
        self.fail_closed = yes;
        self
    }

    /// Run L2 and L3 *concurrently* when L1 escalates at or above `sev` (needs both tiers). `None`
    /// (default) = always sequential. Trades extra L3 work on high-risk events for lower latency.
    pub fn speculate_above(mut self, sev: Option<Severity>) -> Self {
        self.speculate_above = sev;
        self
    }

    /// Route a model-output `LlmActivations` event to the SAE tier (with L3-on-escalate). Returns
    /// `None` for non-activation events, or when no SAE tier is configured (they take the rule chain).
    fn judge_model_output(&self, ev: &ObservedEvent) -> Option<Decision> {
        if !matches!(ev.event, Event::LlmActivations { .. }) {
            return None;
        }
        let sae = self.sae.as_ref()?;
        let d = sae.judge(ev);
        Some(match (d.verdict, &self.l3) {
            (Verdict::Escalate, Some(l3)) => l3.judge(ev),
            (Verdict::Escalate, None) => self.resolve_unescalated(d),
            _ => d,
        })
    }

    /// Run the event through the tiers and return the deciding [`Decision`].
    pub fn evaluate(&self, ev: &ObservedEvent) -> Decision {
        if let Some(d) = self.judge_model_output(ev) {
            return d;
        }
        let d1 = self.l1.judge(ev);
        if d1.verdict != Verdict::Escalate {
            return d1;
        }
        match (&self.l2, &self.l3) {
            (Some(l2), Some(l3)) if self.should_speculate(&d1) => self.speculative(l2, l3, ev),
            (Some(l2), _) => self.sequential(l2, ev),
            // No L2 but L3 present: L1's escalation goes straight to the deep investigator.
            (None, Some(l3)) => l3.judge(ev),
            (None, None) => self.resolve_unescalated(d1),
        }
    }

    /// Run only L1 — the cheap, always-on tier. A daemon can call this inline on its ingest thread
    /// and dispatch only the `Escalate` results to a worker pool, so a slow L2/L3 never head-of-line
    /// blocks the event stream. The worker then calls [`evaluate`](Pipeline::evaluate) (L1 re-runs in
    /// µs, then L2/L3) on the escalated event.
    pub fn classify_l1(&self, ev: &ObservedEvent) -> Decision {
        // Model-output activations are judged by the SAE tier, not the rule engine.
        if let Some(sae) = &self.sae {
            if matches!(ev.event, Event::LlmActivations { .. }) {
                return sae.judge(ev);
            }
        }
        self.l1.judge(ev)
    }

    /// Resolve an L1 escalation immediately per the fail mode (for when the worker queue is full —
    /// graceful degradation: the event gets the fail-open/closed verdict instead of deep analysis).
    pub fn resolve_overload(&self, d1: Decision) -> Decision {
        self.resolve_unescalated(d1)
    }

    fn should_speculate(&self, d1: &Decision) -> bool {
        self.speculate_above.is_some_and(|t| d1.severity >= t)
            && self.l3_inflight.load(Ordering::Relaxed) < self.l3_spec_cap
    }

    /// High-risk: start L3 (slow) alongside L2 (fast). A fast L2 `Block` short-circuits for response
    /// time (the detached L3 thread finishes harmlessly); otherwise L3 — already running, so ~ready —
    /// is the authoritative deep verdict, even when L2 would have allowed.
    fn speculative(
        &self,
        l2: &Arc<dyn Judge>,
        l3: &Arc<dyn Judge>,
        ev: &ObservedEvent,
    ) -> Decision {
        let l3c = Arc::clone(l3);
        let evc = ev.clone();
        // Count this L3 as in-flight until its thread finishes — even if we short-circuit below and
        // detach it — so `should_speculate` stops spawning once `l3_spec_cap` are concurrently live.
        self.l3_inflight.fetch_add(1, Ordering::Relaxed);
        let inflight = Arc::clone(&self.l3_inflight);
        let handle = thread::spawn(move || {
            let d = l3c.judge(&evc);
            inflight.fetch_sub(1, Ordering::Relaxed);
            d
        });
        let d2 = l2.judge(ev);
        if d2.verdict == Verdict::Block {
            return d2; // L3 detached but still counted in-flight → caps further speculation
        }
        match handle.join() {
            Ok(d3) if d3.verdict != Verdict::Escalate => d3,
            Ok(d3) => self.resolve_unescalated(d3),
            // L3 panicked (contained): fall back on L2's (non-block) verdict per the fail mode.
            Err(_) => self.resolve_unescalated(d2),
        }
    }

    fn sequential(&self, l2: &Arc<dyn Judge>, ev: &ObservedEvent) -> Decision {
        let d2 = l2.judge(ev);
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
            risk: d.risk,
            explain: None,
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

    struct FixedSev(Tier, Verdict, Severity);
    impl Judge for FixedSev {
        fn tier(&self) -> Tier {
            self.0
        }
        fn judge(&self, _: &ObservedEvent) -> Decision {
            Decision {
                verdict: self.1,
                tier: self.0,
                severity: self.2,
                reason: "x".into(),
                action: None,
                risk: None,
                explain: None,
            }
        }
    }

    fn ev() -> ObservedEvent {
        ObservedEvent::parse(r#"{"event":{"ToolExec":{"pid":1,"argv":["x"]}}}"#).unwrap()
    }

    #[test]
    fn l1_block_is_final_no_l2_call() {
        let p = Pipeline::new(Arc::new(Fixed(Tier::Rules, Verdict::Block)));
        assert_eq!(p.evaluate(&ev()).verdict, Verdict::Block);
    }

    #[test]
    fn model_activations_route_to_sae_tier() {
        use crate::event::{Event, Identity};
        let act = ObservedEvent {
            identity: Identity::default(),
            provider: None,
            event: Event::LlmActivations {
                pid: 1,
                layer: 18,
                features: vec![],
            },
            raw: String::new(),
        };
        // Activations are judged by the SAE tier, not the rule chain.
        let p = Pipeline::new(Arc::new(Fixed(Tier::Rules, Verdict::Allow)))
            .with_sae(Arc::new(Fixed(Tier::Sae, Verdict::Block)));
        let d = p.evaluate(&act);
        assert_eq!(d.verdict, Verdict::Block);
        assert_eq!(d.tier, Tier::Sae);
        // A non-activation event still takes the L1 rule chain.
        assert_eq!(p.evaluate(&ev()).verdict, Verdict::Allow);
        // An SAE escalation defers to the deep L3 agent when present.
        let p2 = Pipeline::new(Arc::new(Fixed(Tier::Rules, Verdict::Allow)))
            .with_sae(Arc::new(Fixed(Tier::Sae, Verdict::Escalate)))
            .with_l3(Arc::new(Fixed(Tier::Agent, Verdict::Block)));
        assert_eq!(p2.evaluate(&act).tier, Tier::Agent);
    }

    #[test]
    fn escalates_l1_to_l2_to_l3() {
        let p = Pipeline::new(Arc::new(Fixed(Tier::Rules, Verdict::Escalate)))
            .with_l2(Arc::new(Fixed(Tier::Llm, Verdict::Escalate)))
            .with_l3(Arc::new(Fixed(Tier::Agent, Verdict::Block)));
        let d = p.evaluate(&ev());
        assert_eq!(d.verdict, Verdict::Block);
        assert_eq!(d.tier, Tier::Agent);
    }

    #[test]
    fn unresolved_escalation_fail_open_allows_fail_closed_blocks() {
        let open = Pipeline::new(Arc::new(Fixed(Tier::Rules, Verdict::Escalate)));
        assert_eq!(open.evaluate(&ev()).verdict, Verdict::Allow);

        let closed =
            Pipeline::new(Arc::new(Fixed(Tier::Rules, Verdict::Escalate))).fail_closed(true);
        assert_eq!(closed.evaluate(&ev()).verdict, Verdict::Block);
    }

    #[test]
    fn speculative_runs_l3_even_when_l2_allows_for_high_risk() {
        // L1 escalates HIGH → L2 + L3 run in parallel; L3's block is authoritative over L2's allow.
        let p = Pipeline::new(Arc::new(FixedSev(
            Tier::Rules,
            Verdict::Escalate,
            Severity::High,
        )))
        .with_l2(Arc::new(Fixed(Tier::Llm, Verdict::Allow)))
        .with_l3(Arc::new(Fixed(Tier::Agent, Verdict::Block)))
        .speculate_above(Some(Severity::High));
        let d = p.evaluate(&ev());
        assert_eq!(d.verdict, Verdict::Block);
        assert_eq!(d.tier, Tier::Agent);
    }

    #[test]
    fn below_threshold_stays_sequential_and_l2_allow_short_circuits() {
        // L1 escalates MEDIUM (< High) → sequential: L2's allow ends it, L3 (which would block) is
        // never consulted. Proves speculation is gated by the severity threshold.
        let p = Pipeline::new(Arc::new(FixedSev(
            Tier::Rules,
            Verdict::Escalate,
            Severity::Medium,
        )))
        .with_l2(Arc::new(Fixed(Tier::Llm, Verdict::Allow)))
        .with_l3(Arc::new(Fixed(Tier::Agent, Verdict::Block)))
        .speculate_above(Some(Severity::High));
        let d = p.evaluate(&ev());
        assert_eq!(d.verdict, Verdict::Allow);
        assert_eq!(d.tier, Tier::Llm);
    }

    #[test]
    fn spec_cap_zero_disables_speculation_falls_back_to_sequential() {
        // cap=0 → even a HIGH-risk escalate won't speculate; it runs sequential, so L2's allow ends
        // it and the L3 that would block is never consulted. This bounds the detached-L3 fan-out.
        let p = Pipeline::new(Arc::new(FixedSev(
            Tier::Rules,
            Verdict::Escalate,
            Severity::High,
        )))
        .with_l2(Arc::new(Fixed(Tier::Llm, Verdict::Allow)))
        .with_l3(Arc::new(Fixed(Tier::Agent, Verdict::Block)))
        .speculate_above(Some(Severity::High))
        .l3_spec_cap(0);
        let d = p.evaluate(&ev());
        assert_eq!(d.verdict, Verdict::Allow);
        assert_eq!(d.tier, Tier::Llm);
    }

    #[test]
    fn l1_escalate_goes_straight_to_l3_when_no_l2() {
        let p = Pipeline::new(Arc::new(Fixed(Tier::Rules, Verdict::Escalate)))
            .with_l3(Arc::new(Fixed(Tier::Agent, Verdict::Block)));
        let d = p.evaluate(&ev());
        assert_eq!(d.verdict, Verdict::Block);
        assert_eq!(d.tier, Tier::Agent);
    }
}
