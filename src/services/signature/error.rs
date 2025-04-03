use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignatureErrorKind {
    /// Ethereum-specific signature errors
    #[error("Ethereum error: {0}")]
    EthereumError(String),

    /// Ethereum-specific signature errors
    #[error("SolanaError error: {0}")]
    SolanaError(String),
    /// Generic signature validation error
    #[error("Validation failed: {0}")]
    ValidationError(String),

    /// Key related errors
    #[error("Key error: {0}")]
    KeyError(String),
}
