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
