//! The block path — turn a `Block` decision into a kernel deny via a3s-observer.
//!
//! Sentry doesn't enforce anything itself; it appends the target to the plain deny-files that
//! a3s-observer's `enforce` (egress) and `fileguard` (file/exec) guards read and hot-reload. This
//! keeps sentry a pure policy brain and the kernel the single enforcement point. Appends are
//! deduped and line-oriented so the guards pick them up within their ~2s reload.

use crate::verdict::EnforceAction;
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

/// Sink files for each deny kind. A `None` path means "log the intent but don't write" — useful in
/// observe-only / dry-run mode where you want sentry's verdicts without wiring the kernel guards.
#[derive(Default)]
pub struct Enforcer {
    pub egress_deny: Option<PathBuf>,
    pub file_deny: Option<PathBuf>,
    pub exec_deny: Option<PathBuf>,
    dry_run: bool,
    seen: HashSet<String>,
}

impl Enforcer {
    pub fn new(
        egress_deny: Option<PathBuf>,
        file_deny: Option<PathBuf>,
        exec_deny: Option<PathBuf>,
        dry_run: bool,
    ) -> Self {
        // Seed dedup from the existing deny-files so a restart doesn't re-append what's already
        // denied (the files persist; the in-memory set otherwise wouldn't know about them).
        let mut seen = HashSet::new();
        seed_seen(&mut seen, "egress", &egress_deny);
        seed_seen(&mut seen, "file", &file_deny);
        seed_seen(&mut seen, "exec", &exec_deny);
        Self {
            egress_deny,
            file_deny,
            exec_deny,
            dry_run,
            seen,
        }
    }

    /// Apply a block. Returns the deny-file the target was written to (or `None` if dry-run, the
    /// target was already denied, no sink is configured, or the target failed validation).
    pub fn apply(&mut self, action: &EnforceAction) -> std::io::Result<Option<PathBuf>> {
        let (raw, sink) = match action {
            EnforceAction::DenyEgress(t) => (t, self.egress_deny.clone()),
            EnforceAction::DenyFile(t) => (t, self.file_deny.clone()),
            EnforceAction::DenyExec(t) => (t, self.exec_deny.clone()),
        };
        // Validate before the target touches observer's control file. A hostile event field must
        // not be able to inject extra deny-lines (newlines), and file/exec denies must be a single
        // absolute PATH — observer's fanotify guard matches paths, so a bare name like "curl" can't
        // match (silent no-op) and PATH-resolving it would over-block the whole binary. Drop those.
        let target = raw.trim();
        if !valid_target(action, target) {
            return Ok(None);
        }
        // Dedup across the whole kind+target so we don't grow the deny-file unboundedly under a
        // repeating attack. Cap the set so a *rotating*-target flood can't grow it without bound —
        // the only cost of forgetting an entry is re-appending one duplicate line (which the guards,
        // and our own seeding, tolerate). ponytail: crude clear-at-cap, LRU if it ever matters.
        if self.seen.len() >= 100_000 {
            self.seen.clear();
        }
        let key = format!("{}\0{}", kind_tag(action), target);
        if !self.seen.insert(key) {
            return Ok(None);
        }
        let Some(path) = sink else { return Ok(None) };
        if self.dry_run {
            return Ok(None);
        }
        let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
        writeln!(f, "{target}")?;
        Ok(Some(path))
    }
}

/// A target is writable to a deny-file only if it's a single, non-empty line with no injection, and
/// (for file/exec) an absolute path that observer's path-based guard can actually match.
fn valid_target(action: &EnforceAction, t: &str) -> bool {
    if t.is_empty() || t.contains(['\n', '\r', '\0']) {
        return false;
    }
    match action {
        // observer's egress guard is `connect4` + a u32 IPv4 map (hostnames are DNS-resolved to
        // IPv4); an IPv6 *literal* (has ':') is unenforceable and would be mis-parsed as a hostname,
        // so drop it rather than write a dead line. IPv4 + hostnames pass.
        EnforceAction::DenyEgress(_) => !t.contains(':'),
        EnforceAction::DenyFile(_) | EnforceAction::DenyExec(_) => t.starts_with('/'),
    }
}

fn kind_tag(a: &EnforceAction) -> &'static str {
    match a {
        EnforceAction::DenyEgress(_) => "egress",
        EnforceAction::DenyFile(_) => "file",
        EnforceAction::DenyExec(_) => "exec",
    }
}

/// Prime the dedup set with the entries already in a deny-file (one target per line).
fn seed_seen(seen: &mut HashSet<String>, tag: &str, path: &Option<PathBuf>) {
    if let Some(p) = path {
        if let Ok(content) = std::fs::read_to_string(p) {
            for line in content.lines() {
                let t = line.trim();
                if !t.is_empty() {
                    seen.insert(format!("{tag}\0{t}"));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_and_dedups() {
        let dir = std::env::temp_dir().join(format!("sentry-enf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let egress = dir.join("egress-deny.txt");
        let mut e = Enforcer::new(Some(egress.clone()), None, None, false);

        let a = EnforceAction::DenyEgress("1.2.3.4".into());
        assert!(e.apply(&a).unwrap().is_some(), "first write happens");
        assert!(e.apply(&a).unwrap().is_none(), "dup is skipped");
        e.apply(&EnforceAction::DenyEgress("5.6.7.8".into()))
            .unwrap();

        let body = std::fs::read_to_string(&egress).unwrap();
        assert_eq!(body, "1.2.3.4\n5.6.7.8\n");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dry_run_writes_nothing() {
        let dir = std::env::temp_dir().join(format!("sentry-dry-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exec = dir.join("exec-deny.txt");
        let mut e = Enforcer::new(None, None, Some(exec.clone()), true);
        assert!(e
            .apply(&EnforceAction::DenyExec("/usr/bin/curl".into()))
            .unwrap()
            .is_none());
        assert!(!exec.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_injection_and_bare_exec_keeps_absolute() {
        let dir = std::env::temp_dir().join(format!("sentry-val-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let egress = dir.join("e.txt");
        let exec = dir.join("x.txt");
        let mut e = Enforcer::new(Some(egress.clone()), None, Some(exec.clone()), false);

        // a hostile field can't smuggle a second deny-line via a newline
        assert!(e
            .apply(&EnforceAction::DenyEgress("1.2.3.4\nevil.com".into()))
            .unwrap()
            .is_none());
        // a bare binary name can't match observer's path guard → not written
        assert!(e
            .apply(&EnforceAction::DenyExec("curl".into()))
            .unwrap()
            .is_none());
        // an absolute path (e.g. a downloaded payload) is the case that does enforce
        assert!(e
            .apply(&EnforceAction::DenyExec("/tmp/payload".into()))
            .unwrap()
            .is_some());

        assert!(!egress.exists(), "no egress line written");
        assert_eq!(std::fs::read_to_string(&exec).unwrap(), "/tmp/payload\n");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn seeds_dedup_from_existing_deny_file_across_restart() {
        let dir = std::env::temp_dir().join(format!("sentry-seed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let egress = dir.join("egress-deny.txt");
        std::fs::write(&egress, "1.2.3.4\n5.6.7.8\n").unwrap();

        // a "restarted" enforcer pointed at the existing file knows those entries already
        let mut e = Enforcer::new(Some(egress.clone()), None, None, false);
        assert!(e
            .apply(&EnforceAction::DenyEgress("1.2.3.4".into()))
            .unwrap()
            .is_none());
        assert!(e
            .apply(&EnforceAction::DenyEgress("9.9.9.9".into()))
            .unwrap()
            .is_some());
        assert_eq!(
            std::fs::read_to_string(&egress).unwrap(),
            "1.2.3.4\n5.6.7.8\n9.9.9.9\n"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn drops_unenforceable_ipv6_egress_literal() {
        let dir = std::env::temp_dir().join(format!("sentry-v6-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let egress = dir.join("e.txt");
        let mut e = Enforcer::new(Some(egress.clone()), None, None, false);
        // IPv4 enforces; the IPv6 literal is dropped (observer's connect4 egress guard is IPv4-only)
        assert!(e
            .apply(&EnforceAction::DenyEgress("169.254.169.254".into()))
            .unwrap()
            .is_some());
        assert!(e
            .apply(&EnforceAction::DenyEgress("fd00:ec2::254".into()))
            .unwrap()
            .is_none());
        assert_eq!(
            std::fs::read_to_string(&egress).unwrap(),
            "169.254.169.254\n"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
