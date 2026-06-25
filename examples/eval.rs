//! Accuracy evaluation — runs the labeled corpus through the real pipeline and reports FP/FN.
//!
//!   cargo run --release --example eval -- eval/corpus.ndjson            # L1 only
//!   A3S_SENTRY_LLM_URL=… A3S_SENTRY_LLM_KEY=… cargo run --release --example eval -- eval/corpus.ndjson  # +L2 (live LLM)
//!
//! "clear" cases measure FP/FN rigorously; "ambiguous" cases (where L2/L3 judgment matters) are
//! scored separately against the security-conservative label.

use a3s_sentry::{LiveRules, LlmJudge, ObservedEvent, Pipeline, Verdict};
use std::sync::Arc;
use std::time::Duration;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: eval <corpus.ndjson>");
    let corpus = std::fs::read_to_string(&path).expect("read corpus");

    let live = Arc::new(LiveRules::new(None).unwrap());
    let mut p = Pipeline::new(live);
    let l2_on = std::env::var("A3S_SENTRY_LLM_URL").ok();
    if let Some(url) = &l2_on {
        p = p.with_l2(Arc::new(LlmJudge::new(
            url,
            &std::env::var("A3S_SENTRY_LLM_MODEL").unwrap_or_else(|_| "glm5.1-w4a8".into()),
            std::env::var("A3S_SENTRY_LLM_KEY").ok(),
            Duration::from_secs(90),
        )));
    }

    let (mut tp, mut fp, mut tn, mut miss) = (0u32, 0u32, 0u32, 0u32);
    let (mut amb_ok, mut amb_bad) = (0u32, 0u32);
    let mut errs: Vec<String> = Vec::new();

    for line in corpus.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line).expect("corpus line json");
        let label = v["label"].as_str().unwrap();
        let diff = v["difficulty"].as_str().unwrap();
        let cat = v["category"].as_str().unwrap_or("");
        let Some(ev) = ObservedEvent::parse(line) else {
            continue;
        };
        let blocked = p.evaluate(&ev).verdict == Verdict::Block;
        let correct = (label == "block") == blocked;

        if diff == "ambiguous" {
            if correct {
                amb_ok += 1;
            } else {
                amb_bad += 1;
                errs.push(format!(
                    "  AMB-wrong [{cat}] want={label} got={} | {}",
                    verb(blocked),
                    short(&ev)
                ));
            }
            continue;
        }
        match (label, blocked) {
            ("block", true) => tp += 1,
            ("block", false) => {
                miss += 1;
                errs.push(format!("  FN/miss [{cat}] | {}", short(&ev)));
            }
            ("allow", false) => tn += 1,
            ("allow", true) => {
                fp += 1;
                errs.push(format!("  FP/false-alarm [{cat}] | {}", short(&ev)));
            }
            _ => {}
        }
    }

    let clear = tp + fp + tn + miss;
    println!(
        "\n=== a3s-sentry accuracy — {clear} clear + {} ambiguous events | L2={} ===",
        amb_ok + amb_bad,
        if l2_on.is_some() {
            "ON (live LLM)"
        } else {
            "off"
        }
    );
    if !errs.is_empty() {
        println!("misclassifications:");
        for e in &errs {
            println!("{e}");
        }
    }
    println!("\nCLEAR:  TP={tp} FP={fp} TN={tn} FN={miss}");
    println!(
        "  recall (threats caught) = {:.1}%   precision = {:.1}%   false-positive rate = {:.1}%",
        pct(tp, tp + miss),
        pct(tp, tp + fp),
        pct(fp, fp + tn),
    );
    println!(
        "AMBIGUOUS: {amb_ok}/{} judged the security-conservative way",
        amb_ok + amb_bad
    );
}

fn pct(n: u32, d: u32) -> f64 {
    if d == 0 {
        100.0
    } else {
        n as f64 / d as f64 * 100.0
    }
}
fn verb(b: bool) -> &'static str {
    if b {
        "block"
    } else {
        "allow"
    }
}
fn short(ev: &ObservedEvent) -> String {
    let s: String = ev.event.subject().chars().take(70).collect();
    format!("{}: {}", ev.event.name(), s)
}
