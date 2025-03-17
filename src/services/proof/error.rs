use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProofErrorKind {
    /// Ethereum-specific signature errors
    #[error("Zerolink: {0}")]
    ZeroLink(String),
    // /// Generic signature validation error
    // #[error("Validation failed: {0}")]
    // Stark(String),

    // /// Key related errors
    // #[error("Key error: {0}")]
    // Ring(String),
}
