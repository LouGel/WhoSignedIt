pub mod error;
pub mod ethereum;
mod solana;
pub mod traits;

pub use ethereum::EthereumSignatureClient;
use solana::SolanaSignatureClient;
pub use traits::SignatureClient;

use crate::error::AppError;

pub struct SignatureClientFactory;

impl SignatureClientFactory {
    /// Create a new signature client based on blockchain type
    pub fn create_client(blockchain_type: &str) -> Result<Box<dyn SignatureClient>, AppError> {
        match blockchain_type {
            "ethereum" => Ok(Box::new(EthereumSignatureClient::new())),
            "solana" => Ok(Box::new(SolanaSignatureClient::new())),
            _ => Err(AppError::Custom(format!(
                "Unsupported blockchain type: {}",
                blockchain_type
            ))),
        }
    }
}
