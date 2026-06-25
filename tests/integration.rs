//! Integration tests — drive the real `sentry` binary end to end (stdin NDJSON → audit + deny-files).

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_sentry");

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sentry-it-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Run sentry with `envs`, feed `input` on stdin, return (stdout, stderr). Asserts a clean exit.
fn run(envs: &[(&str, &str)], input: &str) -> (String, String) {
    let mut cmd = Command::new(BIN);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn sentry");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap(); // drop → EOF → sentry finishes
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "sentry exited non-zero");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

const SSRF: &str =
    "{\"event\":{\"Egress\":{\"pid\":1,\"peer\":\"169.254.169.254\",\"port\":80}}}\n";
const CREDS: &str =
    "{\"event\":{\"FileAccess\":{\"pid\":1,\"path\":\"/home/a/.aws/credentials\",\"write\":false}}}\n";

#[test]
fn blocks_metadata_ssrf_and_writes_egress_deny() {
    let dir = tmp("ssrf");
    let deny = dir.join("egress-deny.txt");
    let (stdout, _) = run(&[("A3S_SENTRY_EGRESS_DENY", deny.to_str().unwrap())], SSRF);
    assert!(
        stdout.contains("\"verdict\":\"block\""),
        "should block: {stdout}"
    );
    assert!(stdout.contains("cloud-metadata"));
    assert_eq!(
        std::fs::read_to_string(&deny).unwrap().trim(),
        "169.254.169.254"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn allows_benign_silently() {
    let (stdout, _) = run(
        &[],
        "{\"event\":{\"ToolExec\":{\"pid\":1,\"argv\":[\"ls\",\"-la\"]}}}\n",
    );
    assert!(
        stdout.trim().is_empty(),
        "benign should produce no audit line: {stdout:?}"
    );
}

#[test]
fn dry_run_blocks_but_writes_no_deny_file() {
    let dir = tmp("dry");
    let deny = dir.join("egress-deny.txt");
    let (stdout, _) = run(
        &[
            ("A3S_SENTRY_EGRESS_DENY", deny.to_str().unwrap()),
            ("A3S_SENTRY_DRY_RUN", "1"),
        ],
        SSRF,
    );
    assert!(stdout.contains("\"verdict\":\"block\""));
    assert!(!deny.exists(), "dry-run must not write a deny-file");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn fail_closed_blocks_but_fail_open_allows_same_escalation() {
    let (closed, _) = run(&[("A3S_SENTRY_FAIL_CLOSED", "1")], CREDS);
    assert!(
        closed.contains("\"verdict\":\"block\""),
        "fail-closed should block: {closed}"
    );

    let (open, _) = run(&[], CREDS);
    assert!(
        open.contains("\"verdict\":\"allow\""),
        "fail-open should allow: {open}"
    );
    assert!(
        open.contains("fail-open"),
        "but audit it as a flagged-but-allowed escalation"
    );
}

#[test]
fn skips_malformed_input_without_crashing() {
    let input = "not json\n\
        {\"garbage\":true}\n\
        {\"event\":{\"SecurityAction\":{\"pid\":1,\"kind\":\"setuid-root\",\"detail\":0}}}\n\
        also not json\n";
    let (stdout, _) = run(&[], input);
    assert!(stdout.contains("setuid-root"));
    assert_eq!(
        stdout.matches("\"verdict\"").count(),
        1,
        "exactly one decision from the one valid event"
    );
}

/// Write an executable mock script (to stand in for A3S_SENTRY_AGENT_BIN). Unix only.
#[cfg(unix)]
fn write_exec(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

/// L3 path end to end: CREDS escalates at L1; with no L2 it goes straight to the L3 agent (a mock
/// here), whose `block` is enforced to the file deny-list. (The L3 tier had no integration coverage.)
#[cfg(unix)]
#[test]
fn l3_agent_block_is_enforced() {
    let dir = tmp("l3");
    let bin = write_exec(
        &dir,
        "mock-agent.sh",
        "#!/bin/sh\necho '{\"verdict\":\"block\",\"severity\":\"high\",\"reason\":\"mock L3 investigated\"}'\n",
    );
    let deny = dir.join("file-deny.txt");
    let (stdout, _) = run(
        &[
            ("A3S_SENTRY_AGENT_BIN", bin.to_str().unwrap()),
            ("A3S_SENTRY_FILE_DENY", deny.to_str().unwrap()),
        ],
        CREDS,
    );
    assert!(
        stdout.contains("\"tier\":\"Agent\""),
        "L3 should decide: {stdout}"
    );
    assert!(
        stdout.contains("\"verdict\":\"block\""),
        "L3 should block: {stdout}"
    );
    assert!(
        stdout.contains("mock L3 investigated"),
        "carries the L3 reason: {stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(&deny).unwrap().trim(),
        "/home/a/.aws/credentials",
        "block enforced to the file deny-list"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Overload path: a slow L3 + a 1-deep queue + 1 worker means a burst of escalations can't all be
/// serviced, so the surplus degrades gracefully (counted, not lost) and the daemon still exits clean.
#[cfg(unix)]
#[test]
fn overload_degrades_under_slow_l3_and_tiny_queue() {
    let dir = tmp("overload");
    let bin = write_exec(
        &dir,
        "slow-agent.sh",
        "#!/bin/sh\nsleep 0.3\necho '{\"verdict\":\"allow\",\"severity\":\"low\",\"reason\":\"slow\"}'\n",
    );
    let input = CREDS.repeat(10); // 10 escalations vs 1 worker + 1 queue slot → most must degrade
    let (_, stderr) = run(
        &[
            ("A3S_SENTRY_AGENT_BIN", bin.to_str().unwrap()),
            ("A3S_SENTRY_WORKERS", "1"),
            ("A3S_SENTRY_QUEUE", "1"),
        ],
        &input,
    );
    // final stderr stats line: "... stopped — N events, B blocked, D overload-degraded"
    let degraded: u64 = stderr
        .lines()
        .find(|l| l.contains("stopped"))
        .and_then(|l| l.rsplit_once(", ").map(|(_, t)| t.to_string()))
        .and_then(|t| t.split_whitespace().next().map(str::to_string))
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    assert!(
        degraded >= 1,
        "a slow L3 + queue=1 + workers=1 + 10 escalations should degrade some: {stderr}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Observability end to end: with A3S_SENTRY_METRICS_ADDR set, the daemon serves live counters — an
/// SSRF block shows up as sentry_blocked_total, and /healthz answers 200.
#[test]
fn metrics_endpoint_serves_live_counters() {
    use std::io::Read as _;
    // claim a free port, then let the daemon rebind it (localhost test — TOCTOU is acceptable here)
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr = format!("127.0.0.1:{port}");
    let dir = tmp("metrics");
    let deny = dir.join("egress-deny.txt");
    let mut child = Command::new(BIN)
        .env("A3S_SENTRY_METRICS_ADDR", &addr)
        .env("A3S_SENTRY_EGRESS_DENY", deny.to_str().unwrap())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(SSRF.as_bytes()).unwrap(); // one block; keep stdin OPEN so the daemon stays up
    stdin.flush().unwrap();

    let probe = |path: &str| -> String {
        let mut s = std::net::TcpStream::connect(&addr).expect("connect metrics");
        s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .unwrap();
        let mut r = String::new();
        let _ = s.read_to_string(&mut r); // Connection: close → read to EOF
        r
    };
    // poll until the block is counted (covers daemon startup + ingest timing)
    let mut metrics = String::new();
    for _ in 0..40 {
        if let Ok(()) = std::net::TcpStream::connect(&addr).map(drop) {
            metrics = probe("/metrics");
            if metrics.contains("sentry_blocked_total 1") {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        metrics.contains("sentry_blocked_total 1"),
        "one SSRF block should be counted: {metrics}"
    );
    assert!(metrics.contains("sentry_events_total 1"));
    assert!(probe("/healthz").contains("200 OK"), "liveness up");

    drop(stdin); // EOF → daemon drains + exits
    let _ = child.wait();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn version_flag_prints_version() {
    let out = Command::new(BIN).arg("--version").output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("a3s-sentry "));
}

#[test]
fn hot_reload_applies_new_policy_live() {
    let dir = tmp("reload");
    let pol = dir.join("rules.hcl");
    std::fs::write(&pol, "rules = []\n").unwrap();
    let mut child = Command::new(BIN)
        .env("A3S_SENTRY_POLICY", pol.to_str().unwrap())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let nc = br#"{"event":{"ToolExec":{"pid":1,"argv":["nc","10.0.0.1","4444"]}}}"#;

    stdin.write_all(nc).unwrap(); // allowed before reload (no rule blocks a bare nc)
    stdin.write_all(b"\n").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    // rewrite the policy to block nc; wait past the ~2s reload poll
    std::fs::write(
        &pol,
        "rules = [ { name = \"no-nc\", on = \"ToolExec\", match = \"\\\\bnc\\\\b\", verdict = \"block\", severity = \"medium\", reason = \"nc\" } ]\n",
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_secs(3));
    stdin.write_all(nc).unwrap(); // now blocked by the live rule
    stdin.write_all(b"\n").unwrap();
    drop(stdin); // EOF

    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("no-nc"),
        "reloaded rule should block the 2nd nc: {stdout}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn l2_llm_round_trip_via_mock_endpoint() {
    use std::io::Read;
    use std::net::TcpListener;

    // a minimal OpenAI-compatible endpoint that returns a block verdict — exercises the full L2 wire
    // path (request build → POST → response parse → escalate→L2→block→enforce) without a real model.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 16384];
            let _ = sock.read(&mut buf); // drain the request (we don't need to parse it)
            let body = "{\"choices\":[{\"message\":{\"content\":\"{\\\"verdict\\\":\\\"block\\\",\\\"severity\\\":\\\"high\\\",\\\"reason\\\":\\\"mock says block\\\"}\"}}]}";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes());
        }
    });

    let url = format!("http://127.0.0.1:{port}/v1");
    let (stdout, _) = run(&[("A3S_SENTRY_LLM_URL", &url)], CREDS);
    server.join().ok();

    assert!(
        stdout.contains("\"tier\":\"Llm\""),
        "L2 should be the deciding tier: {stdout}"
    );
    assert!(stdout.contains("\"verdict\":\"block\""));
    assert!(
        stdout.contains("mock says block"),
        "should carry the model's reason: {stdout}"
    );
}

// Replicas of a3s-observer's deny-file parsers — the cross-tool contract sentry must satisfy:
//   egress: observer src/policy.rs `parse_egress_policy` (trim, skip #/blank, parse Ipv4Addr)
//   file/exec: observer a3s-observer-collector/src/bin/fileguard.rs `load_policy` (trim, skip #/blank)
fn observer_parse_egress_ips(body: &str) -> Vec<std::net::Ipv4Addr> {
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.parse().ok())
        .collect()
}
fn observer_load_paths(body: &str) -> Vec<String> {
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

#[test]
fn deny_files_are_consumable_by_observer_guards() {
    let dir = tmp("chain");
    let pol = dir.join("p.hcl");
    std::fs::write(
        &pol,
        r#"rules = [ { name = "block-key", on = "FileAccess", match = "id_rsa", verdict = "block", severity = "high", reason = "key", action = "deny-file" } ]"#,
    )
    .unwrap();
    let egress = dir.join("egress-deny.txt");
    let filed = dir.join("file-deny.txt");
    // metadata egress (built-in cloud-metadata block → deny-egress) + an SSH key read (site rule → deny-file)
    let input = "{\"event\":{\"Egress\":{\"pid\":1,\"peer\":\"169.254.169.254\",\"port\":80}}}\n\
        {\"event\":{\"FileAccess\":{\"pid\":2,\"path\":\"/home/agent/.ssh/id_rsa\",\"write\":false}}}\n";
    run(
        &[
            ("A3S_SENTRY_POLICY", pol.to_str().unwrap()),
            ("A3S_SENTRY_EGRESS_DENY", egress.to_str().unwrap()),
            ("A3S_SENTRY_FILE_DENY", filed.to_str().unwrap()),
        ],
        input,
    );

    // observer's enforce would load exactly the blocked metadata IP into DENY_EGRESS
    assert_eq!(
        observer_parse_egress_ips(&std::fs::read_to_string(&egress).unwrap()),
        vec!["169.254.169.254".parse::<std::net::Ipv4Addr>().unwrap()],
    );
    // observer's fileguard would fanotify-mark exactly the blocked key path
    assert_eq!(
        observer_load_paths(&std::fs::read_to_string(&filed).unwrap()),
        vec!["/home/agent/.ssh/id_rsa".to_string()],
    );
    std::fs::remove_dir_all(&dir).ok();
}
