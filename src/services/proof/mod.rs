pub mod traits;
pub mod zerolink;

pub mod error;

pub use traits::ProofClient;
pub use zerolink::RingProofClient;

use crate::{error::AppError, services::signature::SignatureClient};

pub struct ProofClientFactory;

impl ProofClientFactory {
    /// Create a new proof client based on proof type
    pub fn create_client(
        proof: &str,
        signature_client: Box<dyn SignatureClient>,
    ) -> Result<Box<dyn ProofClient>, AppError> {
        match proof {
            "ring" => Ok(Box::new(RingProofClient::new(signature_client))),
            // "stark" => Ok(Box::new(StarkProofClient::new(signature_client))),
            _ => Err(AppError::Custom(format!(
                "Unsupported proof type: {}",
                proof
            ))),
        }
    }
}
