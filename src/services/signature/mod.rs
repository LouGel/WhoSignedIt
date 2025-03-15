// File: src/services/signature/mod.rs
pub mod ethereum;
// mod solana;
pub mod traits;

pub use ethereum::EthereumSignatureClient;
// pub use solana::SolanaSignatureClient;
pub use traits::{BlockchainSignature, PublicKey, SignatureClient};

/// Factory for creating signature clients
pub struct SignatureClientFactory;

impl SignatureClientFactory {
    /// Create a new signature client based on blockchain type
    pub fn create_client(blockchain_type: &str) -> eyre::Result<Box<dyn SignatureClient>> {
        match blockchain_type {
            "ethereum" => Ok(Box::new(EthereumSignatureClient::new())),
            // "solana" => Ok(Box::new(SolanaSignatureClient::new())),
            _ => Err(eyre::eyre!(
                "Unsupported blockchain type: {}",
                blockchain_type
            )),
        }
    }
}
