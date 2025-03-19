use crate::{
    error::AppError,
    services::signature::traits::{BlockchainSignature, PublicKey},
};
use eyre::Result;
use serde::Deserialize;
use std::fmt::{Debug, Display};

#[derive(Debug, Clone)]
pub enum Format {
    Json,
    Toml,
}
impl std::str::FromStr for Format {
    type Err = AppError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "json" => Ok(Format::Json),
            "toml" => Ok(Format::Toml),
            _ => Err(AppError::Custom("Invalid format".to_owned())),
        }
    }
}
/// Base trait for all proofs
pub trait Proof: Send + Sync + Display {
    /// Verify the proof
    fn verify(&self) -> Result<bool, AppError>;

    /// Get the message associated with this proof
    fn message(&self) -> &str;

    fn format(&self, format: Format) -> String {
        format!("{}", self)
    }
}

/// Trait for proof clients
pub trait ProofClient: Send + Sync + Debug {
    /// Create a proof that someone in a group signed a message
    fn create_group_signature_proof(
        &self,
        message: &str,
        signature: &BlockchainSignature,
        group: &[PublicKey],
    ) -> Result<Box<dyn Proof>, AppError>;
}
