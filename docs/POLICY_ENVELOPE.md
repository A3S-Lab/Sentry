# Digest-bound workload policy envelope

`PolicyEnvelope` is the immutable admission contract for assigning one native ACL policy to one
workload instance. It binds:

- workload ID;
- immutable workload revision ID;
- durable replica ID;
- node ID;
- positive policy generation; and
- the lowercase SHA-256 digest of the canonical policy payload.

This contract is deliberately narrower than enforcement. A verified envelope proves which policy
was requested for which identity. It does not prove that egress, exec, or file controls reached the
Linux enforcement backend.

## Canonical ACL form

An envelope is one `policy_envelope` object followed by one or more block-based policy items:

```acl
policy_envelope = {generation = 7, node_id = "node-01", policy_digest = "sha256:fedb025bd0e08c2a9975ac38ce1522613ba2b51b0070acfac84031938fe72cbc", replica_id = "replica-01", revision_id = "revision-sha256-abc", version = 1, workload_id = "workload-01"}
runtime_policy "sentry-v1" {
  default = "deny"
  egress {
    mode = "allowlist"
  }
}
```

The digest is calculated with `a3s_acl::canonical_digest` over only the policy blocks after the
header. The trusted expectation carries the identity, generation, and digest together, so reusing
the same policy bytes for another workload still fails identity verification.

`PolicyEnvelope::from_policy_acl` accepts ordinary native ACL formatting and emits the exact
canonical wire form. `PolicyEnvelope::parse` accepts only that canonical form. Requiring canonical
bytes on the node boundary removes duplicate-field, comment, whitespace, and line-ending
ambiguities before any policy can be applied.

## Producer

```rust
use a3s_sentry::{PolicyBinding, PolicyEnvelope};

let binding = PolicyBinding::new(
    "workload-01",
    "revision-sha256-abc",
    "replica-01",
    "node-01",
)?;
let envelope = PolicyEnvelope::from_policy_acl(
    binding,
    7,
    r#"
runtime_policy "sentry-v1" {
  default = "deny"
  egress { mode = "allowlist" }
}
"#,
)?;

persist_command_bytes(envelope.canonical_acl().as_bytes())?;
persist_expected_digest(envelope.policy_digest())?;
```

Persist or transmit `canonical_acl()` without rewriting it. The generation is a positive integer no
larger than JavaScript's exact integer limit (`2^53 - 1`), which keeps Rust and TypeScript ACL
representations equivalent.

## Node admission

The expected values must come from trusted desired state, not from the received envelope:

```rust
use a3s_sentry::{PolicyBinding, PolicyEnvelope, PolicyExpectation};

let envelope = PolicyEnvelope::parse(received_acl)?;
let expected = PolicyExpectation::new(
    PolicyBinding::new(
        desired.workload_id,
        desired.revision_id,
        desired.replica_id,
        enrolled_node_id,
    )?,
    desired.policy_generation,
    desired.policy_digest,
)?;

envelope.verify(&expected)?;
```

Verification rejects each identity dimension independently, a lower generation as stale, a higher
generation as unexpected, and any digest mismatch. A caller must treat every parse, schema,
canonicalization, or verification error as not admitted.

## Admission invariants

| Invariant | Behavior |
| --- | --- |
| Header | exactly one `policy_envelope` object, first in the document |
| Version | exactly `1` |
| Identity | nonempty, at most 256 UTF-8 bytes, no whitespace or control characters |
| Generation | `1..=2^53-1`, exact match with trusted desired state |
| Digest | `sha256:` plus 64 lowercase hexadecimal digits; recomputed from canonical policy bytes |
| Payload | nonempty top-level blocks; root attributes and another `policy_envelope` are rejected |
| Wire bytes | exact native ACL canonical form, UTF-8, LF, one final newline |
| Resource budget | producer output and parser input at 1 MiB; depth 32; collection 10,000; token 64 KiB; 20 diagnostics |

Schema and error messages do not echo policy values or identity values. Policies must not contain
secret plaintext; reference secret material through a separately authorized delivery mechanism.

## Enforcement boundary

Do not report a workload ready merely because `verify` succeeds. Readiness eventually requires an
enforcement backend to report the same binding, generation, digest, and complete typed-capability
evidence after an atomic apply.

This first contract also treats the policy blocks as opaque native ACL. A capability-specific,
closed schema must admit their egress, exec, and file semantics before an enforcement backend uses
them; envelope verification alone does not establish that the payload is effective or supported.

The current deny-file `Enforcer` remains coarse and node-global. It does not consume
`PolicyEnvelope`, provide workload-scoped egress/exec/file capabilities, make replacement atomic, or
produce restart-safe applied-state evidence. Those enforcement and audit pieces remain follow-up
work under [Sentry issue #2](https://github.com/A3S-Lab/Sentry/issues/2).
