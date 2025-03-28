use crate::{
    client::client::FormatInput,
    error::AppError,
    services::signature::traits::{BlockchainSignature, PublicKey},
};
use std::fmt::{Debug, Display};

pub trait Proof: Send + Sync + Display {
    fn verify(&self) -> Result<bool, AppError>;
    #[allow(dead_code)]
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
