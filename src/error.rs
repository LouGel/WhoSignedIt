use crate::services::proof::error::ProofErrorKind;
use crate::services::signature::error::SignatureErrorKind;
use thiserror::Error;

/// Application-specific errors
#[derive(Error, Debug)]
pub enum AppError {
    /// Error related to signature verification
    #[error("Signature verification error: {0}")]
    SignatureError(#[from] SignatureErrorKind),

    /// Error related to proof generation or verification
    #[error("Proof error: {0}")]
    ProofError(#[from] ProofErrorKind),

    /// Custom error with message
    #[allow(dead_code)]
    #[error("{0}")]
    Custom(String),
}
