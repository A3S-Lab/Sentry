# a3s-sentry — operator runbook

Sentry is **reactive** and **fail-open by default**: it judges a3s-observer's event stream and pushes
blocks down to observer's deny-files, which the kernel guards enforce. Two consequences shape every
operational decision below: a block takes effect on the *next* matching action (not the one that
produced the event), and when sentry can't decide it **allows** unless you tell it otherwise.

## 1. Rollout — always shadow first

1. Deploy with `A3S_SENTRY_DRY_RUN=1` (the reference DaemonSet ships this on). Sentry judges and
   audits but writes **no** deny-file — zero risk to live traffic.
2. Watch the decision stream (stdout NDJSON) and `/metrics`. Confirm the blocks are the ones you
   expect and the false-positive rate is acceptable.
3. Remove `A3S_SENTRY_DRY_RUN` to begin enforcing. Roll node-by-node; the deny-files are node-local.

## 2. Fail mode — open vs closed

| | `A3S_SENTRY_FAIL_CLOSED` unset (default) | `A3S_SENTRY_FAIL_CLOSED=1` |
|---|---|---|
| Unresolved escalation (no deeper tier, or a tier errored) | **allow** | **block** |
| Overload (worker queue full) | **allow** | **block** |
| Posture | availability-first (matches observer) | safety-first |

Fail-**closed** is correct for high-assurance workloads, but note the deny is coarse and node-global —
under an escalation flood it can block legitimate traffic node-wide. Don't flip to fail-closed without
L2/L3 configured *and* headroom (see §4), or you trade a detectability gap for an availability outage.

**Rules-only + fail-open is the dangerous combination**: every `escalate` rule (credential reads,
secret egress, …) silently resolves to allow. Sentry prints a loud startup WARNING for exactly this.
Fix it by configuring L2/L3 or setting fail-closed.

## 3. Alarms — the two metrics that mean "a block didn't land"

Scrape `A3S_SENTRY_METRICS_ADDR` (`/metrics`). Page on either of these rising:

- **`sentry_overload_degraded_total`** — escalations that fell through to the fail mode because the
  worker queue was full. Under fail-open, each one is a **silent enforcement bypass**. Response:
  raise `A3S_SENTRY_WORKERS` / `A3S_SENTRY_QUEUE`, speed up or disable the slow tier, or accept
  fail-closed for the overflow. A non-zero rate means you are under-provisioned for your event rate.
- **`sentry_enforce_failed_total`** — a block whose deny-file write errored (disk full, read-only FS,
  bad path). The block did **not** take effect. Response: check the deny-file volume (space, mount,
  permissions). Sentry already retries the same target on its next occurrence, so a transient cause
  self-heals; a sustained rate is a real misconfiguration.

`sentry_blocked_total` / `sentry_events_total` are informational (throughput, block ratio).
`/healthz` returns `200 ok` while alive — wire it to the k8s liveness/readiness probes.

## 4. Tuning under load

L1 runs inline (µs) on every event and never blocks the stream. Only escalations hit the worker pool.
If `overload_degraded` climbs:

- **More workers** (`A3S_SENTRY_WORKERS`, default 4) — concurrent L2/L3 investigations.
- **Deeper queue** (`A3S_SENTRY_QUEUE`, default 256) — absorbs bursts before degrading.
- **Faster L2** — a reasoning model at ~16 s/call caps throughput hard; a smaller/faster classifier or
  tighter L1 rules (so fewer events escalate) helps more than raw worker count.
- L3 (agent) concurrency is additionally capped (speculative fan-out at `l3_spec_cap`, default 8).

## 5. Deny-files on the shared volume

Sentry **appends** to the deny-files and dedups in-memory, so a repeating attack does not grow them
without bound. They are node-local scratch (an `emptyDir` in the reference manifest), reconstructed by
re-observation, and **not** fsync'd — durable against process death, not host crash. Pod restart
re-seeds the dedup set from the existing files, so denies are not re-appended. No rotation is normally
needed; if a long-lived node accumulates a very large set, recreate the pod (the kernel guards reload).

## 6. LLM / L3 outage

- **L2 endpoint down/slow** → L2 returns escalate; the event flows to L3 if configured, else resolves
  per fail mode. Tune `A3S_SENTRY_LLM_TIMEOUT` (default 30 s) to the model's real latency — too short
  fails *open* on real threats.
- **L3 agent missing/hung** → the investigation times out (`A3S_SENTRY_AGENT_TIMEOUT`, default 120 s),
  the whole agent process group is killed, and the event resolves per fail mode.
- Watch `overload_degraded` during an outage: a slow tier pins workers, so the queue fills and
  surplus escalations degrade.

## 7. Restart / termination

Shutdown is durable: every decision is line-flushed and every deny is written + closed per target, so
an abrupt `SIGTERM`/`SIGKILL` loses no already-written deny — only the in-flight event being judged.
Normal termination closes the upstream pipe → stdin EOF → the worker queue drains and final stats
print before exit. The deny-files persist on the shared volume, so enforcement continues across a
sentry restart even before sentry is back up.

## Quick triage

| symptom | check | action |
|---|---|---|
| dangerous actions getting through | `overload_degraded`, fail mode, L1 rules | raise workers/queue; fail-closed; add a rule |
| `enforce_failed` rising | deny-file volume space/perms/mount | fix the volume; transient self-heals |
| legitimate traffic blocked | the audit stream (which rule/tier) | tune the rule; the deny is coarse + node-global |
| L2/L3 never deciding | endpoint reachability, timeouts | fix the backend; tune `*_TIMEOUT` |
| nothing being enforced | `A3S_SENTRY_DRY_RUN` still set? fail-open + rules-only? | drop dry-run; configure L2/L3 or fail-closed |
