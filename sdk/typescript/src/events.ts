//! Event builders — the NDJSON `submit` writes to the daemon's stdin, one JSON object per line.
//!
//! The envelope mirrors the observer/`ObservedEvent` shape the daemon deserializes:
//!   `{"event": {"<Variant>": {<fields>}}, "identity"?: {...}, "provider"?: string}`
//!
//! The six variants and their judged fields are taken verbatim from the Rust `Event` enum:
//!   - ToolExec       `{pid, argv}`
//!   - Egress         `{pid, peer, port}`
//!   - FileAccess     `{pid, path, write}`
//!   - Dns            `{pid, query}`
//!   - SslContent     `{pid, is_read, content}`   (note the snake_case `is_read`)
//!   - SecurityAction `{pid, kind, detail}`

/** Resolved actor for an event. Only included on the wire if at least one field is present. */
export interface Identity {
  readonly agent?: string;
  readonly task?: string;
  readonly session?: string;
}

/** Common options for every builder: an optional identity and provider tag. */
export interface EventOptions {
  readonly agent?: string;
  readonly task?: string;
  readonly session?: string;
  /** Provider tag (e.g. `"Anthropic"`), passed through to the audit. */
  readonly provider?: string;
}

/** A built event, ready to serialize for the daemon's stdin. */
export interface SentryEvent {
  /** Serialize to a single compact JSON line (no spaces), without the trailing newline. */
  toLine(): string;
  /** The plain envelope object (useful for inspection/testing). */
  toJSON(): Record<string, unknown>;
}

function identityOf(opts: EventOptions): Identity | undefined {
  const id: Record<string, string> = {};
  if (opts.agent !== undefined) id["agent"] = opts.agent;
  if (opts.task !== undefined) id["task"] = opts.task;
  if (opts.session !== undefined) id["session"] = opts.session;
  return Object.keys(id).length > 0 ? (id as Identity) : undefined;
}

function build(
  variant: string,
  fields: Record<string, unknown>,
  opts: EventOptions,
): SentryEvent {
  const envelope: Record<string, unknown> = { event: { [variant]: fields } };
  const identity = identityOf(opts);
  if (identity !== undefined) {
    envelope["identity"] = identity;
  }
  if (opts.provider !== undefined) {
    envelope["provider"] = opts.provider;
  }
  return {
    toJSON: () => envelope,
    // JSON.stringify with no spacing arg → compact, matching the daemon's tolerant parser.
    toLine: () => JSON.stringify(envelope),
  };
}

/** Typed builders for the six observer event variants the daemon judges. */
export const Event = {
  /** A process execution: `{pid, argv}`. Subject = `argv.join(" ")`. */
  toolExec(pid: number, argv: string[], opts: EventOptions = {}): SentryEvent {
    return build("ToolExec", { pid, argv }, opts);
  },

  /** An outbound connection: `{pid, peer, port}`. Subject = `"peer:port"`. */
  egress(pid: number, peer: string, port: number, opts: EventOptions = {}): SentryEvent {
    return build("Egress", { pid, peer, port }, opts);
  },

  /** A file access: `{pid, path, write}`. Subject = `path`. */
  fileAccess(
    pid: number,
    path: string,
    write: boolean,
    opts: EventOptions = {},
  ): SentryEvent {
    return build("FileAccess", { pid, path, write }, opts);
  },

  /** A DNS lookup: `{pid, query}`. Subject = `query`. */
  dns(pid: number, query: string, opts: EventOptions = {}): SentryEvent {
    return build("Dns", { pid, query }, opts);
  },

  /** Decrypted SSL content (opt-in observer capture): `{pid, is_read, content}`. Subject = `content`. */
  sslContent(
    pid: number,
    isRead: boolean,
    content: string,
    opts: EventOptions = {},
  ): SentryEvent {
    // NOTE: snake_case `is_read` on the wire — the daemon's serde field name.
    return build("SslContent", { pid, is_read: isRead, content }, opts);
  },

  /** A kernel security signal: `{pid, kind, detail}`. Subject = `"kind detail"`. */
  securityAction(
    pid: number,
    kind: string,
    detail: number,
    opts: EventOptions = {},
  ): SentryEvent {
    return build("SecurityAction", { pid, kind, detail }, opts);
  },
} as const;
