use serde::Serialize;
use std::fmt;

const MAX_ID_BYTES: usize = 256;
const MAX_ACL_INTEGER: u64 = 9_007_199_254_740_991;

/// One immutable identity dimension covered by a workload policy binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyBindingField {
    WorkloadId,
    RevisionId,
    ReplicaId,
    NodeId,
}

impl fmt::Display for PolicyBindingField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WorkloadId => "workload_id",
            Self::RevisionId => "revision_id",
            Self::ReplicaId => "replica_id",
            Self::NodeId => "node_id",
        })
    }
}

/// Invalid workload policy identity metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyBindingError {
    Empty(PolicyBindingField),
    TooLong(PolicyBindingField),
    InvalidCharacter(PolicyBindingField),
}

impl fmt::Display for PolicyBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty(field) => write!(formatter, "{field} must not be empty"),
            Self::TooLong(field) => {
                write!(
                    formatter,
                    "{field} must not exceed {MAX_ID_BYTES} UTF-8 bytes"
                )
            }
            Self::InvalidCharacter(field) => {
                write!(
                    formatter,
                    "{field} must not contain whitespace or control characters"
                )
            }
        }
    }
}

impl std::error::Error for PolicyBindingError {}

/// Exact workload identity to which one policy applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyBinding {
    workload_id: String,
    revision_id: String,
    replica_id: String,
    node_id: String,
}

impl PolicyBinding {
    /// Create and validate one exact workload identity binding.
    pub fn new(
        workload_id: impl Into<String>,
        revision_id: impl Into<String>,
        replica_id: impl Into<String>,
        node_id: impl Into<String>,
    ) -> Result<Self, PolicyBindingError> {
        let binding = Self {
            workload_id: workload_id.into(),
            revision_id: revision_id.into(),
            replica_id: replica_id.into(),
            node_id: node_id.into(),
        };
        validate_id(PolicyBindingField::WorkloadId, &binding.workload_id)?;
        validate_id(PolicyBindingField::RevisionId, &binding.revision_id)?;
        validate_id(PolicyBindingField::ReplicaId, &binding.replica_id)?;
        validate_id(PolicyBindingField::NodeId, &binding.node_id)?;
        Ok(binding)
    }

    /// Return the bound workload identifier.
    pub fn workload_id(&self) -> &str {
        &self.workload_id
    }

    /// Return the bound immutable workload revision identifier.
    pub fn revision_id(&self) -> &str {
        &self.revision_id
    }

    /// Return the bound durable replica identifier.
    pub fn replica_id(&self) -> &str {
        &self.replica_id
    }

    /// Return the bound node identifier.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }
}

/// Invalid trusted expectation metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyExpectationError {
    InvalidGeneration,
    InvalidPolicyDigest,
}

impl fmt::Display for PolicyExpectationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidGeneration => "policy generation must be a positive ACL-safe integer",
            Self::InvalidPolicyDigest => {
                "policy digest must use the sha256: prefix followed by 64 lowercase hexadecimal digits"
            }
        })
    }
}

impl std::error::Error for PolicyExpectationError {}

/// Trusted desired state used to admit one envelope at an apply or readiness boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyExpectation {
    binding: PolicyBinding,
    generation: u64,
    policy_digest: String,
}

impl PolicyExpectation {
    /// Create validated trusted desired state for one envelope verification.
    pub fn new(
        binding: PolicyBinding,
        generation: u64,
        policy_digest: impl Into<String>,
    ) -> Result<Self, PolicyExpectationError> {
        if !valid_generation(generation) {
            return Err(PolicyExpectationError::InvalidGeneration);
        }
        let policy_digest = policy_digest.into();
        if !valid_policy_digest(&policy_digest) {
            return Err(PolicyExpectationError::InvalidPolicyDigest);
        }
        Ok(Self {
            binding,
            generation,
            policy_digest,
        })
    }

    /// Return the expected workload identity binding.
    pub fn binding(&self) -> &PolicyBinding {
        &self.binding
    }

    /// Return the exact expected policy generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Return the exact expected canonical policy digest.
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }
}

pub(crate) fn valid_generation(generation: u64) -> bool {
    (1..=MAX_ACL_INTEGER).contains(&generation)
}

pub(crate) fn valid_policy_digest(digest: &str) -> bool {
    digest
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
        && !digest.bytes().any(|byte| byte.is_ascii_uppercase())
}

fn validate_id(field: PolicyBindingField, value: &str) -> Result<(), PolicyBindingError> {
    if value.is_empty() {
        return Err(PolicyBindingError::Empty(field));
    }
    if value.len() > MAX_ID_BYTES {
        return Err(PolicyBindingError::TooLong(field));
    }
    if value
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(PolicyBindingError::InvalidCharacter(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_rejects_empty_long_and_whitespace_components() {
        assert_eq!(
            PolicyBinding::new("", "revision", "replica", "node"),
            Err(PolicyBindingError::Empty(PolicyBindingField::WorkloadId))
        );
        assert_eq!(
            PolicyBinding::new("workload", "r".repeat(MAX_ID_BYTES + 1), "replica", "node"),
            Err(PolicyBindingError::TooLong(PolicyBindingField::RevisionId))
        );
        assert_eq!(
            PolicyBinding::new("workload", "revision", "replica 1", "node"),
            Err(PolicyBindingError::InvalidCharacter(
                PolicyBindingField::ReplicaId
            ))
        );
    }

    #[test]
    fn expectation_rejects_noncanonical_metadata() {
        let binding = PolicyBinding::new("workload", "revision", "replica", "node").unwrap();
        assert_eq!(
            PolicyExpectation::new(binding.clone(), 0, format!("sha256:{}", "0".repeat(64))),
            Err(PolicyExpectationError::InvalidGeneration)
        );
        assert_eq!(
            PolicyExpectation::new(binding, 1, format!("sha256:{}", "A".repeat(64))),
            Err(PolicyExpectationError::InvalidPolicyDigest)
        );
    }
}
