// File: src/services/signature/traits.rs
use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use crate::error::AppError;

/// Represents a signature from any blockchain
#[derive(Debug, Clone)]
pub enum BlockchainSignature {
    Ethereum(alloy_primitives::PrimitiveSignature),
    Solana(solana_sdk::signature::Signature),
}

/// Represents a public key from any blockchain
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum ChainAddress {
    Ethereum(Address),
    Solana(solana_sdk::pubkey::Pubkey),
}

impl ChainAddress {
    /// Convert the public key to a vector of bytes
    pub fn to_vec_u8(&self) -> Vec<u8> {
        match self {
            ChainAddress::Ethereum(address) => address.to_vec(),
            ChainAddress::Solana(pubkey) => {
                // For Solana, you would typically use the 32-byte public key
                pubkey.to_bytes().to_vec()
            }
        }
    }
}

/// Trait for signature clients
pub trait SignatureClient: Send + Sync + Debug {
    /// Sign a message using the specified private key
    fn sign_message(
        &self,
        message: &str,
        private_key: &str,
    ) -> Result<BlockchainSignature, AppError>;

    /// Get the public key from a private key
    fn get_address(&self, private_key: &str) -> Result<ChainAddress, AppError>;

    /// Parse a signature from its string representation
    fn from_str(&self, signature_str: &str) -> Result<BlockchainSignature, AppError>;

    /// Parse a public key from its string representation
    fn parse_public_key(&self, pubkey_str: &str) -> Result<ChainAddress, AppError>;

    /// Verify a signature against a message and public key
    fn verify_signature(
        &self,
        message: &str,
        signature: &BlockchainSignature,
        address: &ChainAddress,
    ) -> bool;

    /// Clone the signature client
    fn box_clone(&self) -> Box<dyn SignatureClient>;
}

// Implement Clone for Box<dyn SignatureClient>
impl Clone for Box<dyn SignatureClient> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}
