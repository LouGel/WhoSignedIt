use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Invalid private key format")]
    InvalidPrivateKey,

    #[error("Invalid public key format")]
    InvalidPublicKey,

    #[error("Invalid message format")]
    InvalidMessage,

    #[error("Invalid signature format")]
    InvalidSignature,

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),

    #[error("Public key not in group")]
    KeyNotInGroup,

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Hex decoding error: {0}")]
    HexError(#[from] hex::FromHexError),
    
    #[error("Alloy error: {0}")]
    AlloyError(String),
}
