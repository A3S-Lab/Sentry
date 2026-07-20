use crate::policy_binding::{PolicyBindingError, PolicyBindingField};
use a3s_acl::{CanonicalError, ParseError, SchemaReport};
use std::fmt;

/// Envelope parsing, admission, and canonicalization failures.
#[derive(Debug)]
pub enum PolicyEnvelopeError {
    Parse(ParseError),
    Schema(SchemaReport),
    EnvelopeMustBeFirst,
    MissingAttribute(&'static str),
    UnsupportedVersion(u64),
    InvalidVersion,
    InvalidBinding(PolicyBindingError),
    InvalidGeneration,
    InvalidPolicyDigest,
    EmptyPolicy,
    EnvelopeTooLarge,
    PolicyPayloadMustUseBlocks,
    ReservedEnvelopeBlock,
    DigestMismatch,
    NonCanonicalEnvelope,
    Canonical(CanonicalError),
    InvalidCanonicalEncoding,
}

impl fmt::Display for PolicyEnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(formatter, "invalid policy envelope ACL: {error}"),
            Self::Schema(report) => write!(
                formatter,
                "policy envelope ACL does not match its schema ({} diagnostic{}{})",
                report.diagnostics.len(),
                if report.diagnostics.len() == 1 {
                    ""
                } else {
                    "s"
                },
                if report.truncated { ", truncated" } else { "" }
            ),
            Self::EnvelopeMustBeFirst => {
                formatter.write_str("policy_envelope must be the first document item")
            }
            Self::MissingAttribute(name) => {
                write!(
                    formatter,
                    "policy envelope is missing required attribute {name}"
                )
            }
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported policy envelope version {version}")
            }
            Self::InvalidVersion => {
                formatter.write_str("policy envelope version must be an ACL-safe integer")
            }
            Self::InvalidBinding(error) => write!(formatter, "invalid policy binding: {error}"),
            Self::InvalidGeneration => {
                formatter.write_str("policy generation must be a positive ACL-safe integer")
            }
            Self::InvalidPolicyDigest => formatter.write_str(
                "policy digest must use the sha256: prefix followed by 64 lowercase hexadecimal digits",
            ),
            Self::EmptyPolicy => formatter.write_str("policy envelope payload must not be empty"),
            Self::EnvelopeTooLarge => {
                formatter.write_str("canonical policy envelope exceeds the wire-size limit")
            }
            Self::PolicyPayloadMustUseBlocks => {
                formatter.write_str("policy envelope payload must contain blocks, not attributes")
            }
            Self::ReservedEnvelopeBlock => formatter
                .write_str("policy payload must not contain the reserved policy_envelope item"),
            Self::DigestMismatch => {
                formatter.write_str("declared policy digest does not match canonical policy bytes")
            }
            Self::NonCanonicalEnvelope => {
                formatter.write_str("policy envelope bytes are not in canonical ACL form")
            }
            Self::Canonical(error) => write!(formatter, "canonicalizing policy ACL: {error}"),
            Self::InvalidCanonicalEncoding => {
                formatter.write_str("canonical policy ACL was not valid UTF-8")
            }
        }
    }
}

impl std::error::Error for PolicyEnvelopeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::InvalidBinding(error) => Some(error),
            Self::Canonical(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ParseError> for PolicyEnvelopeError {
    fn from(error: ParseError) -> Self {
        Self::Parse(error)
    }
}

impl From<CanonicalError> for PolicyEnvelopeError {
    fn from(error: CanonicalError) -> Self {
        Self::Canonical(error)
    }
}

/// Exact-match failures returned before a policy may be applied or acknowledged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyVerificationError {
    IdentityMismatch(PolicyBindingField),
    StaleGeneration { expected: u64, actual: u64 },
    UnexpectedGeneration { expected: u64, actual: u64 },
    PolicyDigestMismatch,
}

impl fmt::Display for PolicyVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdentityMismatch(field) => {
                write!(formatter, "policy binding mismatch for {field}")
            }
            Self::StaleGeneration { expected, actual } => write!(
                formatter,
                "stale policy generation: expected {expected}, received {actual}"
            ),
            Self::UnexpectedGeneration { expected, actual } => write!(
                formatter,
                "unexpected policy generation: expected {expected}, received {actual}"
            ),
            Self::PolicyDigestMismatch => {
                formatter.write_str("policy digest does not match trusted desired state")
            }
        }
    }
}

impl std::error::Error for PolicyVerificationError {}
