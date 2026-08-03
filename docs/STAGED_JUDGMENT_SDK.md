# Staged judgment SDK

Status: implemented
Target branch: `feat/staged-judgment-sdk`

## Purpose

Callers that own durable queues and routing policy need to stop after L1 without invoking models or
resolving an escalation through fail-open/fail-closed. The existing Rust `Pipeline::classify_l1`
provides the core behavior, but it is not exposed consistently through `Sentry`, Node N-API, and
Python bindings.

Sentry remains identity-agnostic. A caller chooses a stage limit; Sentry never imports downstream
concepts such as Confirmed, Candidate, Unknown, or Non-Agent.

## API

Expose a structured L1 result through the Rust, Node and Python SDKs:

```rust
pub struct ThroughL1Result {
    pub l1_decision: Decision,
    pub stage_status: StageStatus,
    pub next_tier_eligible: bool,
    pub stop_reason: StageStopReason,
}
```

```ts
Sentry.evaluateL1(event: string): ThroughL1Result | null
```

```python
sentry.evaluate_l1(event: str) -> ThroughL1Result | None
```

An L1 allow/block is completed. A complete-evidence escalation is eligible for a deeper tier. An
incomplete-evidence escalation is preserved but is not eligible for a deeper tier. No L2/L3 judge
or fail-mode resolution runs on this path.

Add compatible eligibility/stop metadata to `ThroughL2Result`, so an external L3 dispatcher does
not infer safety from human-readable reasons.

## Compatibility

Existing `evaluate`, `evaluateThroughL2`, and `evaluateAndEnforce` behavior stays unchanged. New
fields are additive. Node declarations are generated and tested. The Node and Python packages
receive minor version bumps according to repository release policy.

## Verification

- Rust unit tests cover final, eligible escalation, incomplete evidence and SAE behavior.
- A counting/mock L2 proves `evaluate_l1` performs zero model calls even when L2/L3 are configured.
- Node and Python binding tests cover result shape and unchanged legacy APIs.
- `cargo fmt`, Clippy, Rust tests, Node build/tests and Python tests must pass.
