//! Process supervision — spawn, feed, stream, and stop the `sentry` daemon.
//!
//! `Sentry` maps a typed `SentryConfig` to the daemon's `A3S_SENTRY_*` env vars, spawns it,
//! writes events to its stdin, and exposes the audit NDJSON on stdout as a typed async iterator.
//!
//! IMPORTANT: the daemon emits an audit line ONLY for blocks, escalations, and flagged-but-allowed
//! events. Plain benign allows are counted, not printed — so `decisions()` yields exactly the
//! audited (non-allow) decisions, never one per submitted event.

import { type ChildProcessByStdio, spawn } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import * as readline from "node:readline";
import { type Audit, parseAudit } from "./types.js";
import type { SentryEvent } from "./events.js";

/** stdin piped (write events), stdout piped (read audit), stderr inherited (daemon logs). */
type SentryChild = ChildProcessByStdio<Writable, Readable, null>;

/** Typed daemon configuration. Each field maps to one `A3S_SENTRY_*` env var. */
export interface SentryConfig {
  /** The binary path/name. Default `"sentry"`. */
  bin?: string;
  /** Extra L1 rules (HCL) — `A3S_SENTRY_POLICY`. Built-ins always apply; hot-reloaded (~2s). */
  policy?: string;
  /** Observer egress deny-file — `A3S_SENTRY_EGRESS_DENY`. */
  egressDeny?: string;
  /** Observer file deny-file — `A3S_SENTRY_FILE_DENY`. */
  fileDeny?: string;
  /** Observer exec deny-file — `A3S_SENTRY_EXEC_DENY`. */
  execDeny?: string;
  /** L2 OpenAI-compatible endpoint base — `A3S_SENTRY_LLM_URL`. Enables L2. */
  llmUrl?: string;
  /** L2 model name — `A3S_SENTRY_LLM_MODEL`. */
  llmModel?: string;
  /** L2 bearer token — `A3S_SENTRY_LLM_KEY`. */
  llmKey?: string;
  /** L3 a3s-code binary — `A3S_SENTRY_AGENT_BIN`. Enables L3. */
  agentBin?: string;
  /** L3 security-skills directory — `A3S_SENTRY_SKILLS`. */
  skills?: string;
  /** Unresolved escalations BLOCK — `A3S_SENTRY_FAIL_CLOSED=1`. */
  failClosed?: boolean;
  /** Speculate threshold severity — `A3S_SENTRY_SPECULATE` (e.g. `"high"`). */
  speculate?: string;
  /** L2 request timeout in seconds — `A3S_SENTRY_LLM_TIMEOUT`. */
  llmTimeout?: number;
  /** L3 investigation timeout in seconds — `A3S_SENTRY_AGENT_TIMEOUT`. */
  agentTimeout?: number;
  /** L2/L3 worker thread count — `A3S_SENTRY_WORKERS`. */
  workers?: number;
  /** Escalation queue depth — `A3S_SENTRY_QUEUE`. */
  queue?: number;
  /** Judge + audit, but never write a deny-file — `A3S_SENTRY_DRY_RUN=1`. */
  dryRun?: boolean;
  /** Serve Prometheus `/metrics` + `/healthz` — `A3S_SENTRY_METRICS_ADDR` (e.g. `"0.0.0.0:9100"`). */
  metricsAddr?: boolean | string;
}

/** Build the `A3S_SENTRY_*` env overlay from a config. Exported for inspection/testing. */
export function configToEnv(config: SentryConfig): Record<string, string> {
  const env: Record<string, string> = {};
  const set = (key: string, value: string | undefined): void => {
    if (value !== undefined && value !== "") {
      env[key] = value;
    }
  };
  set("A3S_SENTRY_POLICY", config.policy);
  set("A3S_SENTRY_EGRESS_DENY", config.egressDeny);
  set("A3S_SENTRY_FILE_DENY", config.fileDeny);
  set("A3S_SENTRY_EXEC_DENY", config.execDeny);
  set("A3S_SENTRY_LLM_URL", config.llmUrl);
  set("A3S_SENTRY_LLM_MODEL", config.llmModel);
  set("A3S_SENTRY_LLM_KEY", config.llmKey);
  set("A3S_SENTRY_AGENT_BIN", config.agentBin);
  set("A3S_SENTRY_SKILLS", config.skills);
  set("A3S_SENTRY_SPECULATE", config.speculate);
  if (config.llmTimeout !== undefined) set("A3S_SENTRY_LLM_TIMEOUT", String(config.llmTimeout));
  if (config.agentTimeout !== undefined)
    set("A3S_SENTRY_AGENT_TIMEOUT", String(config.agentTimeout));
  if (config.workers !== undefined) set("A3S_SENTRY_WORKERS", String(config.workers));
  if (config.queue !== undefined) set("A3S_SENTRY_QUEUE", String(config.queue));
  if (config.failClosed) env["A3S_SENTRY_FAIL_CLOSED"] = "1";
  if (config.dryRun) env["A3S_SENTRY_DRY_RUN"] = "1";
  if (typeof config.metricsAddr === "string" && config.metricsAddr !== "") {
    env["A3S_SENTRY_METRICS_ADDR"] = config.metricsAddr;
  }
  return env;
}

/** Default grace period (ms) to wait for a clean drain-and-exit before SIGTERM. */
const DEFAULT_STOP_TIMEOUT_MS = 10_000;

/**
 * A supervised `sentry` daemon process.
 *
 * Lifecycle: `start()` → `submit(event)` (repeat) + consume `decisions()` → `stop()`.
 * Implements `Symbol.asyncDispose`, so `await using s = new Sentry(cfg); s.start();` stops it
 * automatically at scope exit.
 */
export class Sentry {
  private readonly config: SentryConfig;
  private child: SentryChild | undefined;
  private exited: Promise<number | null> | undefined;

  constructor(config: SentryConfig = {}) {
    this.config = config;
  }

  /** Whether the daemon is currently running. */
  get running(): boolean {
    return this.child !== undefined && this.child.exitCode === null && !this.child.killed;
  }

  /** The underlying process id, if started. */
  get pid(): number | undefined {
    return this.child?.pid;
  }

  /** Spawn the daemon, inheriting `process.env` with the config overlay applied. */
  start(): void {
    if (this.child !== undefined) {
      throw new Error("Sentry already started");
    }
    const bin = this.config.bin ?? "sentry";
    const env = { ...process.env, ...configToEnv(this.config) };
    // stdin: write events · stdout: read audit NDJSON · stderr: inherit (daemon logs to stderr).
    const child: SentryChild = spawn(bin, [], {
      env,
      stdio: ["pipe", "pipe", "inherit"],
    });
    this.child = child;
    this.exited = new Promise((resolve) => {
      child.once("exit", (code) => resolve(code));
    });
  }

  /** Write one event to the daemon's stdin (`event.toLine() + "\n"`). */
  submit(event: SentryEvent): void {
    const child = this.requireChild();
    child.stdin.write(event.toLine() + "\n");
  }

  /**
   * Stream typed audit decisions from the daemon's stdout, one per line. Blanks and unparseable
   * lines are skipped. Yields exactly the audited (non-allow) decisions — benign allows are not
   * emitted by the daemon. The iterator ends when the daemon's stdout closes (after `stop()`).
   */
  async *decisions(): AsyncIterableIterator<Audit> {
    const child = this.requireChild();
    const rl = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
    for await (const line of rl) {
      const trimmed = line.trim();
      if (trimmed === "") {
        continue;
      }
      let audit: Audit;
      try {
        audit = parseAudit(trimmed);
      } catch {
        continue; // skip stray non-JSON lines
      }
      yield audit;
    }
  }

  /**
   * Stop the daemon gracefully: close stdin so it reaches EOF, drains its queue, and exits.
   * Waits up to `timeoutMs` for a clean exit, then SIGTERMs. Resolves with the exit code.
   */
  async stop(timeoutMs: number = DEFAULT_STOP_TIMEOUT_MS): Promise<number | null> {
    const child = this.child;
    if (child === undefined || this.exited === undefined) {
      return null;
    }
    // EOF on stdin → the daemon finishes the queue and exits on its own.
    child.stdin.end();

    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<"timeout">((resolve) => {
      timer = setTimeout(() => resolve("timeout"), timeoutMs);
      timer.unref?.();
    });
    const result = await Promise.race([this.exited.then(() => "exited" as const), timeout]);
    if (timer !== undefined) {
      clearTimeout(timer);
    }
    if (result === "timeout" && this.running) {
      child.kill("SIGTERM");
    }
    return this.exited;
  }

  /** `await using` support — stops the daemon at scope exit. */
  async [Symbol.asyncDispose](): Promise<void> {
    await this.stop();
  }

  private requireChild(): SentryChild {
    if (this.child === undefined) {
      throw new Error("Sentry not started — call start() first");
    }
    return this.child;
  }
}
