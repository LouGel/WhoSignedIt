pub mod traits;
pub mod zerolink;

pub mod error;

pub use traits::{Proof, ProofClient};
pub use zerolink::RingProofClient;

use crate::services::signature::SignatureClient;

pub struct ProofClientFactory;

impl ProofClientFactory {
    /// Create a new proof client based on proof type
    pub fn create_client(
        proof: &str,
        signature_client: Box<dyn SignatureClient>,
    ) -> eyre::Result<Box<dyn ProofClient>> {
        match proof {
            "ring" => Ok(Box::new(RingProofClient::new(signature_client))),
            // "stark" => Ok(Box::new(StarkProofClient::new(signature_client))),
            _ => Err(eyre::eyre!("Unsupported proof type: {}", proof)),
        }
    }
}
