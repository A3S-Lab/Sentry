//! `sentry` — the daemon: read a3s-observer NDJSON on stdin, judge each event through L1→L2→L3,
//! enforce blocks via observer's deny-files, and emit a decision audit line per non-allow.
//!
//! Wire it downstream of the collector, exactly where observer's README leaves "your controller":
//!
//! ```text
//! A3S_OBSERVER_JSON=1 A3S_OBSERVER_SSL=1 sudo -E a3s-observer-collector \
//!   | A3S_SENTRY_EGRESS_DENY=egress-deny.txt \
//!     A3S_SENTRY_LLM_URL=http://host:18051/v1 a3s-sentry
//! ```
//!
//! Config is all env (see `--help`): policy file, L2/L3 backends, deny-file sinks, fail mode.

use a3s_sentry::{
    AgentJudge, Decision, Enforcer, LiveRules, LlmJudge, ObservedEvent, Pipeline, Severity, Tier,
    Verdict,
};
use serde::Serialize;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn main() -> anyhow::Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("--version" | "-V") => {
            println!("a3s-sentry {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some("--help" | "-h") => {
            print!("{HELP}");
            return Ok(());
        }
        _ => {}
    }

    let cfg = Config::from_env();
    let live = Arc::new(LiveRules::new(cfg.policy_path.clone())?);
    let pipeline = cfg.build_pipeline(live.clone())?;
    let mut enforcer = cfg.build_enforcer();

    eprintln!(
        "a3s-sentry {}: L1={} rules L2={} L3={} fail={} speculate={} dry_run={} — reading observer NDJSON on stdin",
        env!("CARGO_PKG_VERSION"),
        live.rule_count(),
        if cfg.llm_url.is_some() { "on" } else { "off" },
        if cfg.agent_bin.is_some() { "on" } else { "off" },
        if cfg.fail_closed { "closed" } else { "open" },
        cfg.speculate_above.map_or("off", |_| "on"),
        cfg.dry_run,
    );
    // Loud footgun warning: rules-only + fail-open silently ALLOWS every escalate rule.
    if !cfg.fail_closed && cfg.llm_url.is_none() && cfg.agent_bin.is_none() {
        eprintln!(
            "a3s-sentry: WARNING — rules-only + fail-open: every `escalate` rule (credential reads, \
             secret egress, persistence, bind, …) resolves to ALLOW. Set A3S_SENTRY_FAIL_CLOSED=1, \
             or configure A3S_SENTRY_LLM_URL / A3S_SENTRY_AGENT_BIN, to act on them."
        );
    }

    // Hot-reload: poll the policy file every ~2s so any program that rewrites it updates the rules
    // live, no restart. A parse error keeps the current rules (a bad edit never disarms the engine).
    if cfg.policy_path.is_some() {
        let reloader = Arc::clone(&live);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(2));
            match reloader.reload_if_changed() {
                Ok(true) => eprintln!(
                    "a3s-sentry: policy reloaded — {} rules",
                    reloader.rule_count()
                ),
                Ok(false) => {}
                Err(e) => {
                    eprintln!("a3s-sentry: policy reload failed (keeping current rules): {e}")
                }
            }
        });
    }

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let (mut total, mut blocked) = (0u64, 0u64);

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let Some(ev) = ObservedEvent::parse(&line) else {
            continue;
        };
        total += 1;
        // Contain a panic in any judge to a single skipped event — a malformed/hostile event must
        // not take down the security daemon (which would then fail-open for everything after).
        let decision =
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pipeline.evaluate(&ev)))
            {
                Ok(d) => d,
                Err(_) => {
                    eprintln!("a3s-sentry: a judge panicked on an event — skipped");
                    continue;
                }
            };

        // Enforce blocks; allow/escalate-resolved-to-allow just flow on.
        let mut enforced: Option<String> = None;
        if decision.verdict == Verdict::Block {
            blocked += 1;
            if let Some(action) = &decision.action {
                match enforcer.apply(action) {
                    Ok(Some(path)) => enforced = Some(path.display().to_string()),
                    Ok(None) => {}
                    Err(e) => eprintln!("a3s-sentry: enforce write failed: {e}"),
                }
            }
        }

        // Audit anything noteworthy: blocks, anything a deeper tier touched, and flagged-but-allowed
        // events (an escalation that resolved to allow keeps its severity). Plain benign L1 allows
        // (Info, decided by Rules) are counted, not printed, to keep the stream signal-dense.
        if decision.verdict != Verdict::Allow
            || decision.severity > Severity::Info
            || decision.tier != Tier::Rules
        {
            let rec = Audit {
                agent: ev.identity.agent.clone(),
                event: ev.event.name(),
                subject: truncate(&ev.event.subject(), 300),
                decision: &decision,
                enforced,
            };
            if let Ok(json) = serde_json::to_string(&rec) {
                let _ = writeln!(out, "{json}");
                let _ = out.flush();
            }
        }

        if total % 10_000 == 0 {
            eprintln!("a3s-sentry: {total} events, {blocked} blocked");
        }
    }

    eprintln!("a3s-sentry: stopped — {total} events, {blocked} blocked");
    Ok(())
}

#[derive(Serialize)]
struct Audit<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    agent: Option<String>,
    event: &'a str,
    subject: String,
    decision: &'a Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    enforced: Option<String>,
}

struct Config {
    policy_path: Option<PathBuf>,
    llm_url: Option<String>,
    llm_model: String,
    llm_key: Option<String>,
    agent_bin: Option<String>,
    skills_dir: Option<String>,
    egress_deny: Option<PathBuf>,
    file_deny: Option<PathBuf>,
    exec_deny: Option<PathBuf>,
    fail_closed: bool,
    speculate_above: Option<Severity>,
    dry_run: bool,
}

impl Config {
    fn from_env() -> Self {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Self {
            policy_path: env("A3S_SENTRY_POLICY").map(PathBuf::from),
            llm_url: env("A3S_SENTRY_LLM_URL"),
            llm_model: env("A3S_SENTRY_LLM_MODEL").unwrap_or_else(|| "default".into()),
            llm_key: env("A3S_SENTRY_LLM_KEY"),
            agent_bin: env("A3S_SENTRY_AGENT_BIN"),
            skills_dir: env("A3S_SENTRY_SKILLS"),
            egress_deny: env("A3S_SENTRY_EGRESS_DENY").map(PathBuf::from),
            file_deny: env("A3S_SENTRY_FILE_DENY").map(PathBuf::from),
            exec_deny: env("A3S_SENTRY_EXEC_DENY").map(PathBuf::from),
            fail_closed: env("A3S_SENTRY_FAIL_CLOSED").is_some(),
            // Presence enables speculation; the value sets the severity threshold (default High).
            speculate_above: env("A3S_SENTRY_SPECULATE").map(|v| parse_sev(&v)),
            dry_run: env("A3S_SENTRY_DRY_RUN").is_some(),
        }
    }

    fn build_pipeline(&self, live: Arc<LiveRules>) -> anyhow::Result<Pipeline> {
        let mut p = Pipeline::new(live)
            .fail_closed(self.fail_closed)
            .speculate_above(self.speculate_above);
        if let Some(url) = &self.llm_url {
            p = p.with_l2(Arc::new(LlmJudge::new(
                url,
                &self.llm_model,
                self.llm_key.clone(),
                Duration::from_secs(10),
            )));
        }
        if let Some(bin) = &self.agent_bin {
            p = p.with_l3(Arc::new(AgentJudge::new(
                bin.clone(),
                self.skills_dir.clone(),
                Duration::from_secs(120),
                self.fail_closed,
            )));
        }
        Ok(p)
    }

    fn build_enforcer(&self) -> Enforcer {
        Enforcer::new(
            self.egress_deny.clone(),
            self.file_deny.clone(),
            self.exec_deny.clone(),
            self.dry_run,
        )
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_owned();
    }
    let mut end = n;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Parse a severity name for the speculate threshold; anything else (incl. `1`) means `high`.
fn parse_sev(s: &str) -> Severity {
    match s.trim().to_ascii_lowercase().as_str() {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "critical" => Severity::Critical,
        _ => Severity::High,
    }
}

const HELP: &str = "\
a3s-sentry — tiered (L1 rules / L2 LLM / L3 a3s-code) runtime security control for AI agents.

Reads a3s-observer NDJSON on stdin, judges each event, enforces blocks via observer deny-files,
and writes a decision audit (NDJSON) on stdout. Pipe it after a3s-observer-collector.

Env config:
  A3S_SENTRY_POLICY=<file.hcl>    extra L1 rules (HCL); built-ins always apply; HOT-RELOADED (~2s)
  A3S_SENTRY_LLM_URL=<base/v1>    enable L2; OpenAI-compatible chat endpoint
  A3S_SENTRY_LLM_MODEL=<name>     L2 model (default: \"default\")
  A3S_SENTRY_LLM_KEY=<key>        L2 bearer token (optional)
  A3S_SENTRY_AGENT_BIN=<bin>      enable L3; the a3s-code binary/path
  A3S_SENTRY_SKILLS=<dir>         L3 security-skills directory
  A3S_SENTRY_EGRESS_DENY=<file>   observer egress deny-file to append blocked IPs/hosts
  A3S_SENTRY_FILE_DENY=<file>     observer file deny-file
  A3S_SENTRY_EXEC_DENY=<file>     observer exec deny-file
  A3S_SENTRY_FAIL_CLOSED=1        unresolved escalations BLOCK (default: fail-open / allow)
  A3S_SENTRY_SPECULATE=<sev>      run L2+L3 in PARALLEL when L1 escalates at >= <sev> (default: high)
  A3S_SENTRY_DRY_RUN=1            judge + audit, but never write a deny-file

The policy file is hot-reloaded: rewrite it from any program (or your config system) and the rules
update live within ~2s, no restart. A parse error keeps the current rules.
";
