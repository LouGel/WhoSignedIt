use thiserror::Error;

/// Application-specific errors
#[derive(Error, Debug)]
pub enum AppError {
    /// Error from Alloy crate
    #[error("Alloy error: {0}")]
    AlloyError(String),

    /// Error related to signature verification
    #[error("Signature verification error: {0}")]
    SignatureError(String),

    /// Error related to proof generation or verification
    #[error("Proof error: {0}")]
    ProofError(String),

    /// Custom error with message
    #[error("{0}")]
    Custom(String),
}
