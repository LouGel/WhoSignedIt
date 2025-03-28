use crate::{
    error::AppError,
    services::signature::traits::{BlockchainSignature, PublicKey},
};
use eyre::Result;
use std::fmt::{Debug, Display};
use tracing_subscriber::fmt::format::Format;

#[derive(Debug, Clone, Copy)]
pub enum FormatInput {
    Json,
    Toml,
}
impl std::str::FromStr for FormatInput {
    type Err = AppError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "json" => Ok(FormatInput::Json),
            "toml" => Ok(FormatInput::Toml),
            _ => Err(AppError::Custom("Invalid format".to_owned())),
        }
    }
}
pub trait Proof: Send + Sync + Display {
    fn verify(&self) -> Result<bool, AppError>;

    fn message(&self) -> &str;

    fn format(&self, format: &FormatInput) -> String;
}

pub trait ProofClient: Send + Sync + Debug {
    fn create_group_signature_proof(
        &self,
        message: &str,
        signature: &BlockchainSignature,
        group: &[PublicKey],
    ) -> Result<Box<dyn Proof>, AppError>;
    fn from_str(&self, proof: &str, format: FormatInput) -> Result<Box<dyn Proof>, AppError>;
}
