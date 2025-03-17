use crate::{
    error::AppError,
    services::signature::traits::{BlockchainSignature, PublicKey},
};
use eyre::Result;
use std::fmt::Debug;

/// Base trait for all proofs
pub trait Proof: Send + Sync {
    /// Verify the proof
    fn verify(&self) -> Result<bool, AppError>;

    /// Get the message associated with this proof
    fn message(&self) -> &str;
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
