//! Metrics client — read the daemon's Prometheus `/metrics` and `/healthz` endpoints.
//!
//! Served only when `A3S_SENTRY_METRICS_ADDR` is set. The Prometheus counter names map to fields:
//!   - `sentry_events_total`            → `events`
//!   - `sentry_blocked_total`           → `blocked`
//!   - `sentry_overload_degraded_total` → `overloadDegraded`
//!   - `sentry_enforce_failed_total`    → `enforceFailed`

import * as http from "node:http";

/** Parsed snapshot of the daemon's counters. */
export interface MetricsSnapshot {
  /** Observer events ingested (`sentry_events_total`). */
  readonly events: number;
  /** Events blocked (`sentry_blocked_total`). */
  readonly blocked: number;
  /** Escalations degraded to the fail mode — a fail-open bypass (`sentry_overload_degraded_total`). */
  readonly overloadDegraded: number;
  /** Deny-file writes that errored — a block that did not land (`sentry_enforce_failed_total`). */
  readonly enforceFailed: number;
}

const METRIC_FIELDS: Record<string, keyof MetricsSnapshot> = {
  sentry_events_total: "events",
  sentry_blocked_total: "blocked",
  sentry_overload_degraded_total: "overloadDegraded",
  sentry_enforce_failed_total: "enforceFailed",
};

/**
 * Parse Prometheus text exposition into a {@link MetricsSnapshot}. Skips `#` comment lines; a
 * metric line is `name value`. Unknown metrics are ignored; missing ones default to 0.
 */
export function parseMetrics(text: string): MetricsSnapshot {
  const snapshot: MetricsSnapshot = {
    events: 0,
    blocked: 0,
    overloadDegraded: 0,
    enforceFailed: 0,
  };
  const mutable = snapshot as { -readonly [K in keyof MetricsSnapshot]: number };
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) {
      continue;
    }
    const sep = line.indexOf(" ");
    if (sep < 0) {
      continue;
    }
    const name = line.slice(0, sep);
    const field = METRIC_FIELDS[name];
    if (field === undefined) {
      continue;
    }
    const value = Number(line.slice(sep + 1).trim());
    if (Number.isFinite(value)) {
      mutable[field] = value;
    }
  }
  return snapshot;
}

/** Normalize `"host:port"` or a full URL into a base URL with no trailing slash. */
function baseUrl(addr: string): string {
  const withScheme = /^https?:\/\//i.test(addr) ? addr : `http://${addr}`;
  return withScheme.replace(/\/+$/, "");
}

interface HttpResult {
  status: number;
  body: string;
}

function get(url: string): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const req = http.get(url, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () =>
        resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }),
      );
    });
    req.on("error", reject);
  });
}

/** A read-only client for the daemon's metrics/health endpoints. */
export class MetricsClient {
  private readonly base: string;

  /** @param addr `"host:port"` or a full `http(s)://…` URL. */
  constructor(addr: string) {
    this.base = baseUrl(addr);
  }

  /** `true` if `GET /healthz` returns 200. Never throws on a non-200; rejects only on a transport error. */
  async health(): Promise<boolean> {
    const { status } = await get(`${this.base}/healthz`);
    return status === 200;
  }

  /** Fetch and parse `GET /metrics`. */
  async metrics(): Promise<MetricsSnapshot> {
    const { status, body } = await get(`${this.base}/metrics`);
    if (status !== 200) {
      throw new Error(`metrics endpoint returned ${status}`);
    }
    return parseMetrics(body);
  }
}
