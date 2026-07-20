use a3s_sentry::{
    PolicyBinding, PolicyBindingField, PolicyEnvelope, PolicyEnvelopeError, PolicyExpectation,
    PolicyVerificationError, POLICY_ENVELOPE_LIMITS,
};

const POLICY: &str = r#"
runtime_policy "sentry-v1" {
  default = "deny"
  egress {
    mode = "allowlist"
  }
}
"#;

fn binding(workload_id: &str, revision_id: &str, replica_id: &str, node_id: &str) -> PolicyBinding {
    PolicyBinding::new(workload_id, revision_id, replica_id, node_id)
        .expect("fixture identity is valid")
}

fn expected_binding() -> PolicyBinding {
    binding(
        "workload-01",
        "revision-sha256-abc",
        "replica-01",
        "node-01",
    )
}

#[test]
fn canonical_envelope_round_trips_and_verifies_exact_expectation() {
    let envelope =
        PolicyEnvelope::from_policy_acl(expected_binding(), 7, POLICY).expect("build envelope");
    assert!(envelope.policy_digest().starts_with("sha256:"));
    assert_eq!(envelope.policy_digest().len(), 71);

    let parsed = PolicyEnvelope::parse(envelope.canonical_acl()).expect("parse canonical envelope");
    assert_eq!(parsed.canonical_acl(), envelope.canonical_acl());
    assert_eq!(
        parsed.canonical_policy_bytes(),
        envelope.canonical_policy_bytes()
    );
    assert_eq!(parsed.binding(), &expected_binding());
    assert_eq!(parsed.generation(), 7);
    let expected = PolicyExpectation::new(expected_binding(), 7, envelope.policy_digest()).unwrap();
    parsed
        .verify(&expected)
        .expect("exact identity, generation, and digest verify");
}

#[test]
fn policy_digest_ignores_formatting_but_preserves_policy_semantics() {
    let equivalent = r#"
# Comments and attribute order do not affect the native ACL canonical form.
runtime_policy "sentry-v1" {
  egress { mode = "allowlist" }
  default = "deny"
}
"#;
    let first =
        PolicyEnvelope::from_policy_acl(expected_binding(), 1, POLICY).expect("first policy");
    let second =
        PolicyEnvelope::from_policy_acl(expected_binding(), 1, equivalent).expect("second policy");
    assert_eq!(first.policy_digest(), second.policy_digest());
    assert_eq!(
        first.canonical_policy_bytes(),
        second.canonical_policy_bytes()
    );

    let changed = POLICY.replace("allowlist", "denylist");
    let changed =
        PolicyEnvelope::from_policy_acl(expected_binding(), 1, &changed).expect("changed policy");
    assert_ne!(first.policy_digest(), changed.policy_digest());
}

#[test]
fn tampered_policy_or_declared_digest_is_rejected() {
    let envelope =
        PolicyEnvelope::from_policy_acl(expected_binding(), 7, POLICY).expect("build envelope");

    let tampered_policy = envelope.canonical_acl().replace("allowlist", "denylist");
    assert!(matches!(
        PolicyEnvelope::parse(&tampered_policy),
        Err(PolicyEnvelopeError::DigestMismatch)
    ));

    let tampered_digest = envelope.canonical_acl().replace(
        envelope.policy_digest(),
        &format!("sha256:{}", "0".repeat(64)),
    );
    assert!(matches!(
        PolicyEnvelope::parse(&tampered_digest),
        Err(PolicyEnvelopeError::DigestMismatch)
    ));
}

#[test]
fn every_workload_identity_dimension_must_match() {
    let envelope =
        PolicyEnvelope::from_policy_acl(expected_binding(), 7, POLICY).expect("build envelope");
    let cases = [
        (
            PolicyBindingField::WorkloadId,
            binding(
                "workload-02",
                "revision-sha256-abc",
                "replica-01",
                "node-01",
            ),
        ),
        (
            PolicyBindingField::RevisionId,
            binding(
                "workload-01",
                "revision-sha256-def",
                "replica-01",
                "node-01",
            ),
        ),
        (
            PolicyBindingField::ReplicaId,
            binding(
                "workload-01",
                "revision-sha256-abc",
                "replica-02",
                "node-01",
            ),
        ),
        (
            PolicyBindingField::NodeId,
            binding(
                "workload-01",
                "revision-sha256-abc",
                "replica-01",
                "node-02",
            ),
        ),
    ];

    for (field, wrong_binding) in cases {
        let expectation = PolicyExpectation::new(wrong_binding, 7, envelope.policy_digest())
            .expect("expectation");
        assert_eq!(
            envelope.verify(&expectation),
            Err(PolicyVerificationError::IdentityMismatch(field))
        );
    }
}

#[test]
fn stale_future_and_digest_mismatched_expectations_fail_closed() {
    let envelope =
        PolicyEnvelope::from_policy_acl(expected_binding(), 7, POLICY).expect("build envelope");

    let expected_newer =
        PolicyExpectation::new(expected_binding(), 8, envelope.policy_digest()).unwrap();
    assert_eq!(
        envelope.verify(&expected_newer),
        Err(PolicyVerificationError::StaleGeneration {
            expected: 8,
            actual: 7,
        })
    );

    let expected_older =
        PolicyExpectation::new(expected_binding(), 6, envelope.policy_digest()).unwrap();
    assert_eq!(
        envelope.verify(&expected_older),
        Err(PolicyVerificationError::UnexpectedGeneration {
            expected: 6,
            actual: 7,
        })
    );

    let wrong_digest =
        PolicyExpectation::new(expected_binding(), 7, format!("sha256:{}", "0".repeat(64)))
            .unwrap();
    assert_eq!(
        envelope.verify(&wrong_digest),
        Err(PolicyVerificationError::PolicyDigestMismatch)
    );
}

#[test]
fn bounded_admission_rejects_empty_misordered_and_unknown_envelopes_without_leaks() {
    assert!(matches!(
        PolicyEnvelope::from_policy_acl(expected_binding(), 1, " \n# no policy"),
        Err(PolicyEnvelopeError::EmptyPolicy)
    ));

    let envelope =
        PolicyEnvelope::from_policy_acl(expected_binding(), 1, POLICY).expect("build envelope");
    let misordered = format!(
        "extension {{ enabled = true }}\n{}",
        envelope.canonical_acl()
    );
    assert!(matches!(
        PolicyEnvelope::parse(&misordered),
        Err(PolicyEnvelopeError::EnvelopeMustBeFirst)
    ));

    let unknown = envelope.canonical_acl().replace(
        "generation = 1,",
        "generation = 1, unexpected = \"TOP_SECRET\",",
    );
    let error = PolicyEnvelope::parse(&unknown).expect_err("unknown envelope field");
    assert!(matches!(error, PolicyEnvelopeError::Schema(_)));
    assert!(!error.to_string().contains("TOP_SECRET"));

    let duplicate = envelope
        .canonical_acl()
        .replace("generation = 1,", "generation = 1, generation = 2,");
    let duplicate_result = PolicyEnvelope::parse(&duplicate);
    assert!(
        matches!(
            duplicate_result,
            Err(PolicyEnvelopeError::NonCanonicalEnvelope)
        ),
        "{duplicate_result:?}\n{duplicate}"
    );

    let oversized = "x".repeat(POLICY_ENVELOPE_LIMITS.max_document_bytes + 1);
    let error = PolicyEnvelope::parse(&oversized).expect_err("document limit");
    assert!(matches!(error, PolicyEnvelopeError::Parse(_)));
}

#[test]
fn public_contract_types_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<PolicyBinding>();
    assert_send_sync::<PolicyEnvelope>();
    assert_send_sync::<PolicyExpectation>();
    assert_send_sync::<PolicyEnvelopeError>();
    assert_send_sync::<PolicyVerificationError>();
}
