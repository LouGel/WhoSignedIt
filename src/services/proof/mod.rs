pub mod ring;
pub mod traits;

pub use ring::RingProofClient;
pub use traits::{Proof, ProofClient};

use crate::services::signature::SignatureClient;

pub struct ProofClientFactory;

impl ProofClientFactory {
    /// Create a new proof client based on proof type
    pub fn create_client(
        proof_type: &str,
        signature_client: Box<dyn SignatureClient>,
    ) -> eyre::Result<Box<dyn ProofClient>> {
        match proof_type {
            "ring" => Ok(Box::new(RingProofClient::new(signature_client))),
            // "stark" => Ok(Box::new(StarkProofClient::new(signature_client))),
            _ => Err(eyre::eyre!("Unsupported proof type: {}", proof_type)),
        }
    }
}
