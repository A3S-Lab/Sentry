//! Canonical, digest-bound workload policy envelopes.
//!
//! The envelope is an admission contract between a control plane and a node. It binds one native
//! ACL policy document (expressed as top-level policy blocks) to the exact workload, revision,
//! replica, node, and monotonically increasing generation that requested it. Parsing proves that
//! the declared digest matches the canonical policy bytes; [`PolicyEnvelope::verify`] must then
//! match the envelope against trusted desired state before an apply or readiness acknowledgement.
//!
//! This module does not claim that a policy has reached a Linux enforcement backend. That requires
//! separate apply evidence; a successfully verified envelope is only the immutable input to that
//! operation. Payload blocks are opaque in this first contract and still require a
//! capability-specific closed schema before enforcement.

use crate::policy_binding::{valid_generation, valid_policy_digest};
pub use crate::policy_binding::{
    PolicyBinding, PolicyBindingError, PolicyBindingField, PolicyExpectation,
    PolicyExpectationError,
};
pub use crate::policy_error::{PolicyEnvelopeError, PolicyVerificationError};
use a3s_acl::{
    canonical_bytes, canonical_digest, parse_with_limits, validate_document_with_limits,
    AttributeSchema, Block, Document, ObjectSchema, ParseLimits, Schema, Value, ValueSchema,
};
use std::collections::HashMap;

const ENVELOPE_BLOCK: &str = "policy_envelope";
const MAX_ACL_INTEGER: u64 = 9_007_199_254_740_991;

/// Current workload policy envelope schema version.
pub const POLICY_ENVELOPE_VERSION: u64 = 1;

/// Resource limits applied before an untrusted policy envelope is admitted.
///
/// Envelope wire input, canonical producer output, and producer policy input are capped at 1 MiB;
/// structural nesting is capped at 32, individual collections at 10,000 entries, individual tokens
/// at 64 KiB, and schema diagnostics at 20.
pub const POLICY_ENVELOPE_LIMITS: ParseLimits = ParseLimits {
    max_document_bytes: 1024 * 1024,
    max_nesting_depth: 32,
    max_collection_items: 10_000,
    max_token_bytes: 64 * 1024,
    max_diagnostics: 20,
};

/// Immutable, canonical workload policy plus its identity binding.
#[derive(Debug, Clone)]
pub struct PolicyEnvelope {
    binding: PolicyBinding,
    generation: u64,
    policy_digest: String,
    policy: Document,
    canonical_policy: Vec<u8>,
    canonical_acl: String,
}

impl PolicyEnvelope {
    /// Build a canonical envelope around a native, block-based ACL policy document.
    pub fn from_policy_acl(
        binding: PolicyBinding,
        generation: u64,
        policy_acl: &str,
    ) -> Result<Self, PolicyEnvelopeError> {
        if !valid_generation(generation) {
            return Err(PolicyEnvelopeError::InvalidGeneration);
        }
        let policy = parse_with_limits(policy_acl, POLICY_ENVELOPE_LIMITS)?;
        validate_policy_payload(&policy)?;
        let canonical_policy = canonical_bytes(&policy)?;
        let policy_digest = canonical_digest(&policy)?;
        Self::from_parts(binding, generation, policy_digest, policy, canonical_policy)
    }

    /// Parse and self-validate an untrusted envelope.
    ///
    /// This validates bounded ACL syntax, exact canonical wire bytes, the closed envelope header
    /// schema, identity metadata, generation, and the declared digest. The result is not authority
    /// by itself: call [`verify`](Self::verify) against trusted desired state before applying or
    /// acknowledging it.
    pub fn parse(acl: &str) -> Result<Self, PolicyEnvelopeError> {
        let document = parse_with_limits(acl, POLICY_ENVELOPE_LIMITS)?;
        let report =
            validate_document_with_limits(&document, &envelope_schema(), POLICY_ENVELOPE_LIMITS);
        if !report.is_empty() {
            return Err(PolicyEnvelopeError::Schema(report));
        }

        let header = document
            .blocks
            .first()
            .ok_or(PolicyEnvelopeError::EnvelopeMustBeFirst)?;
        if !is_bare_attribute(header, ENVELOPE_BLOCK) {
            return Err(PolicyEnvelopeError::EnvelopeMustBeFirst);
        }
        let metadata = header
            .attributes
            .get(ENVELOPE_BLOCK)
            .and_then(|value| match value {
                Value::Object(fields) => Some(fields.as_slice()),
                _ => None,
            })
            .ok_or(PolicyEnvelopeError::MissingAttribute(ENVELOPE_BLOCK))?;

        let version = required_u64(metadata, "version")?;
        if version != POLICY_ENVELOPE_VERSION {
            return Err(PolicyEnvelopeError::UnsupportedVersion(version));
        }
        let generation = required_u64(metadata, "generation")?;
        if !valid_generation(generation) {
            return Err(PolicyEnvelopeError::InvalidGeneration);
        }

        let binding = PolicyBinding::new(
            required_string(metadata, "workload_id")?,
            required_string(metadata, "revision_id")?,
            required_string(metadata, "replica_id")?,
            required_string(metadata, "node_id")?,
        )
        .map_err(PolicyEnvelopeError::InvalidBinding)?;
        let declared_digest = required_string(metadata, "policy_digest")?.to_owned();
        if !valid_policy_digest(&declared_digest) {
            return Err(PolicyEnvelopeError::InvalidPolicyDigest);
        }

        let policy = Document {
            blocks: document.blocks[1..].to_vec(),
        };
        validate_policy_payload(&policy)?;
        let canonical_policy = canonical_bytes(&policy)?;
        let actual_digest = canonical_digest(&policy)?;
        if declared_digest != actual_digest {
            return Err(PolicyEnvelopeError::DigestMismatch);
        }

        let envelope = Self::from_parts(
            binding,
            generation,
            declared_digest,
            policy,
            canonical_policy,
        )?;
        if acl.as_bytes() != envelope.canonical_acl.as_bytes() {
            return Err(PolicyEnvelopeError::NonCanonicalEnvelope);
        }
        Ok(envelope)
    }

    /// Match every bound identity field, the exact generation, and the canonical policy digest.
    pub fn verify(&self, expected: &PolicyExpectation) -> Result<(), PolicyVerificationError> {
        for (field, actual, wanted) in [
            (
                PolicyBindingField::WorkloadId,
                self.binding.workload_id(),
                expected.binding().workload_id(),
            ),
            (
                PolicyBindingField::RevisionId,
                self.binding.revision_id(),
                expected.binding().revision_id(),
            ),
            (
                PolicyBindingField::ReplicaId,
                self.binding.replica_id(),
                expected.binding().replica_id(),
            ),
            (
                PolicyBindingField::NodeId,
                self.binding.node_id(),
                expected.binding().node_id(),
            ),
        ] {
            if actual != wanted {
                return Err(PolicyVerificationError::IdentityMismatch(field));
            }
        }

        if self.generation < expected.generation() {
            return Err(PolicyVerificationError::StaleGeneration {
                expected: expected.generation(),
                actual: self.generation,
            });
        }
        if self.generation > expected.generation() {
            return Err(PolicyVerificationError::UnexpectedGeneration {
                expected: expected.generation(),
                actual: self.generation,
            });
        }
        if self.policy_digest != expected.policy_digest() {
            return Err(PolicyVerificationError::PolicyDigestMismatch);
        }
        Ok(())
    }

    /// Return the workload identity bound to this envelope.
    pub fn binding(&self) -> &PolicyBinding {
        &self.binding
    }

    /// Return the policy generation bound to this envelope.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Return the declared and recomputed canonical policy digest.
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    /// Return the parsed policy payload without the envelope header.
    pub fn policy_document(&self) -> &Document {
        &self.policy
    }

    /// Return the canonical bytes covered by [`Self::policy_digest`].
    pub fn canonical_policy_bytes(&self) -> &[u8] {
        &self.canonical_policy
    }

    /// Return the complete canonical ACL wire representation.
    pub fn canonical_acl(&self) -> &str {
        &self.canonical_acl
    }

    fn from_parts(
        binding: PolicyBinding,
        generation: u64,
        policy_digest: String,
        policy: Document,
        canonical_policy: Vec<u8>,
    ) -> Result<Self, PolicyEnvelopeError> {
        let document = envelope_document(&binding, generation, &policy_digest, &policy);
        let canonical_acl = String::from_utf8(canonical_bytes(&document)?)
            .map_err(|_| PolicyEnvelopeError::InvalidCanonicalEncoding)?;
        if canonical_acl.len() > POLICY_ENVELOPE_LIMITS.max_document_bytes {
            return Err(PolicyEnvelopeError::EnvelopeTooLarge);
        }
        Ok(Self {
            binding,
            generation,
            policy_digest,
            policy,
            canonical_policy,
            canonical_acl,
        })
    }
}

fn validate_policy_payload(policy: &Document) -> Result<(), PolicyEnvelopeError> {
    if policy.blocks.is_empty() {
        return Err(PolicyEnvelopeError::EmptyPolicy);
    }
    if policy
        .blocks
        .iter()
        .any(|block| is_bare_attribute(block, &block.name))
    {
        return Err(PolicyEnvelopeError::PolicyPayloadMustUseBlocks);
    }
    if policy
        .blocks
        .iter()
        .any(|block| block.name == ENVELOPE_BLOCK)
    {
        return Err(PolicyEnvelopeError::ReservedEnvelopeBlock);
    }
    Ok(())
}

fn required_string<'a>(
    fields: &'a [(String, Value)],
    name: &'static str,
) -> Result<&'a str, PolicyEnvelopeError> {
    fields
        .iter()
        .find_map(|(field, value)| (field == name).then_some(value))
        .and_then(Value::as_str)
        .ok_or(PolicyEnvelopeError::MissingAttribute(name))
}

fn required_u64(
    fields: &[(String, Value)],
    name: &'static str,
) -> Result<u64, PolicyEnvelopeError> {
    let number = fields
        .iter()
        .find_map(|(field, value)| (field == name).then_some(value))
        .and_then(Value::as_number)
        .ok_or(PolicyEnvelopeError::MissingAttribute(name))?;
    if !number.is_finite()
        || number < 0.0
        || number.fract() != 0.0
        || number > MAX_ACL_INTEGER as f64
    {
        return Err(if name == "generation" {
            PolicyEnvelopeError::InvalidGeneration
        } else {
            PolicyEnvelopeError::InvalidVersion
        });
    }
    Ok(number as u64)
}

fn envelope_document(
    binding: &PolicyBinding,
    generation: u64,
    policy_digest: &str,
    policy: &Document,
) -> Document {
    let metadata = Value::Object(vec![
        (
            "version".to_owned(),
            Value::Number(POLICY_ENVELOPE_VERSION as f64),
        ),
        ("generation".to_owned(), Value::Number(generation as f64)),
        (
            "workload_id".to_owned(),
            Value::String(binding.workload_id().to_owned()),
        ),
        (
            "revision_id".to_owned(),
            Value::String(binding.revision_id().to_owned()),
        ),
        (
            "replica_id".to_owned(),
            Value::String(binding.replica_id().to_owned()),
        ),
        (
            "node_id".to_owned(),
            Value::String(binding.node_id().to_owned()),
        ),
        (
            "policy_digest".to_owned(),
            Value::String(policy_digest.to_owned()),
        ),
    ]);
    let attributes = HashMap::from([(ENVELOPE_BLOCK.to_owned(), metadata)]);
    let mut blocks = Vec::with_capacity(policy.blocks.len() + 1);
    blocks.push(Block {
        name: ENVELOPE_BLOCK.to_owned(),
        labels: Vec::new(),
        blocks: Vec::new(),
        attributes,
    });
    blocks.extend(policy.blocks.iter().cloned());
    Document { blocks }
}

fn envelope_schema() -> Schema {
    let metadata = ObjectSchema::new()
        .field("version", AttributeSchema::required(ValueSchema::number()))
        .field(
            "generation",
            AttributeSchema::required(ValueSchema::number()),
        )
        .field(
            "workload_id",
            AttributeSchema::required(ValueSchema::string()),
        )
        .field(
            "revision_id",
            AttributeSchema::required(ValueSchema::string()),
        )
        .field(
            "replica_id",
            AttributeSchema::required(ValueSchema::string()),
        )
        .field("node_id", AttributeSchema::required(ValueSchema::string()))
        .field(
            "policy_digest",
            AttributeSchema::required(ValueSchema::string()),
        );
    Schema::new()
        .attribute(
            ENVELOPE_BLOCK,
            AttributeSchema::required(ValueSchema::object(metadata)),
        )
        .allow_unknown_blocks(true)
}

fn is_bare_attribute(block: &Block, name: &str) -> bool {
    block.name == name
        && block.labels.is_empty()
        && block.blocks.is_empty()
        && block.attributes.len() == 1
        && block.attributes.contains_key(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    #[test]
    fn reserved_header_cannot_be_hidden_in_policy_payload() {
        let binding = PolicyBinding::new("workload", "revision", "replica", "node").unwrap();
        assert!(matches!(
            PolicyEnvelope::from_policy_acl(
                binding,
                1,
                "policy_envelope { version = 1 generation = 1 }"
            ),
            Err(PolicyEnvelopeError::ReservedEnvelopeBlock)
        ));
    }

    #[test]
    fn policy_payload_rejects_root_attributes() {
        let binding = PolicyBinding::new("workload", "revision", "replica", "node").unwrap();
        assert!(matches!(
            PolicyEnvelope::from_policy_acl(binding, 1, "default = \"deny\""),
            Err(PolicyEnvelopeError::PolicyPayloadMustUseBlocks)
        ));
    }

    #[test]
    fn producer_rejects_envelopes_over_the_wire_budget() {
        let value = "x".repeat(65_520);
        let mut policy = String::from("runtime_policy{\n");
        for index in 0..16 {
            writeln!(&mut policy, "k{index}=\"{value}\"").unwrap();
        }
        policy.push('}');
        assert!(policy.len() <= POLICY_ENVELOPE_LIMITS.max_document_bytes);

        let binding = PolicyBinding::new("workload", "revision", "replica", "node").unwrap();
        assert!(matches!(
            PolicyEnvelope::from_policy_acl(binding, 1, &policy),
            Err(PolicyEnvelopeError::EnvelopeTooLarge)
        ));
    }
}
