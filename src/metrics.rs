//! Self-observability: a tiny std-only metrics + health endpoint so an operator can ALARM on the
//! signals that matter for a *fail-open* security control — chiefly `overload_degraded` (escalations
//! that silently fell through to the fail mode because the worker queue was full) and `enforce_failed`
//! (a block whose deny-write errored, i.e. a block that did not land). Opt-in via
//! `A3S_SENTRY_METRICS_ADDR`; nothing is bound otherwise. No framework, no async — one accept thread.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// The daemon's live counters, shared (`Arc`) between the ingest thread, the workers, and the metrics
/// server. Cheap to clone.
#[derive(Clone, Default)]
pub struct Metrics {
    pub events: Arc<AtomicU64>,
    pub blocked: Arc<AtomicU64>,
    pub degraded: Arc<AtomicU64>,
    pub enforce_failed: Arc<AtomicU64>,
}

impl Metrics {
    /// Prometheus text exposition (v0.0.4) of the counters.
    pub fn prometheus(&self) -> String {
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        format!(
            "# HELP sentry_events_total Observer events ingested.\n\
             # TYPE sentry_events_total counter\n\
             sentry_events_total {}\n\
             # HELP sentry_blocked_total Events blocked (a deny-file write was attempted).\n\
             # TYPE sentry_blocked_total counter\n\
             sentry_blocked_total {}\n\
             # HELP sentry_overload_degraded_total Escalations degraded to the fail mode (worker queue full) — a fail-OPEN bypass; alarm on rate > 0.\n\
             # TYPE sentry_overload_degraded_total counter\n\
             sentry_overload_degraded_total {}\n\
             # HELP sentry_enforce_failed_total Deny-file writes that errored (a block that did NOT land) — alarm on rate > 0.\n\
             # TYPE sentry_enforce_failed_total counter\n\
             sentry_enforce_failed_total {}\n",
            g(&self.events),
            g(&self.blocked),
            g(&self.degraded),
            g(&self.enforce_failed),
        )
    }
}

/// Bind the metrics/health endpoint and serve it on a background thread. Returns the bind error so
/// the daemon fails fast on a bad address; the accept loop then runs until process exit. Routes:
///   `GET /metrics` → Prometheus counters · `GET /healthz` → `200 ok` (liveness/readiness).
pub fn serve(addr: &str, m: Metrics) -> std::io::Result<std::net::SocketAddr> {
    let listener = TcpListener::bind(addr)?;
    let local = listener.local_addr()?;
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            handle_conn(stream, &m);
        }
    });
    Ok(local)
}

fn handle_conn(mut stream: TcpStream, m: &Metrics) {
    // We only need the request line's path — read a bounded chunk and ignore headers/body.
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req.split_whitespace().nth(1).unwrap_or("/");
    let (status, ctype, body) = match path {
        "/healthz" => ("200 OK", "text/plain", "ok\n".to_string()),
        "/metrics" => ("200 OK", "text/plain; version=0.0.4", m.prometheus()),
        _ => ("404 Not Found", "text/plain", "not found\n".to_string()),
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_has_all_counters_and_values() {
        let m = Metrics::default();
        m.events.fetch_add(7, Ordering::Relaxed);
        m.degraded.fetch_add(3, Ordering::Relaxed);
        let out = m.prometheus();
        assert!(out.contains("sentry_events_total 7"));
        assert!(out.contains("sentry_overload_degraded_total 3"));
        assert!(out.contains("sentry_blocked_total 0"));
        assert!(out.contains("sentry_enforce_failed_total 0"));
        // counter type lines present for scrapers
        assert!(out.contains("# TYPE sentry_enforce_failed_total counter"));
    }

    #[test]
    fn serves_metrics_and_healthz_over_tcp() {
        let m = Metrics::default();
        m.blocked.fetch_add(5, Ordering::Relaxed);
        let addr = serve("127.0.0.1:0", m).unwrap();
        let probe = |path: &str| {
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
                .unwrap();
            let mut resp = String::new();
            s.read_to_string(&mut resp).unwrap(); // Connection: close → read to EOF
            resp
        };
        assert!(probe("/healthz").contains("200 OK"));
        let metrics = probe("/metrics");
        assert!(metrics.contains("200 OK") && metrics.contains("sentry_blocked_total 5"));
        assert!(probe("/nope").contains("404"));
    }
}
