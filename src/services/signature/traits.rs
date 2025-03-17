// File: src/services/signature/traits.rs
use alloy_primitives::Address;
use std::fmt::Debug;

use crate::error::AppError;

/// Represents a signature from any blockchain
#[derive(Debug, Clone)]
pub enum BlockchainSignature {
    Ethereum(alloy_primitives::PrimitiveSignature),
    // Solana(ed25519_dalek::Signature),
}

/// Represents a public key from any blockchain
#[derive(Debug, Clone, PartialEq)]
pub enum PublicKey {
    Ethereum(Address),
    // Solana(ed25519_dalek::PublicKey),
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
    fn get_public_key(&self, private_key: &str) -> Result<PublicKey, AppError>;

    /// Parse a signature from its string representation
    fn from_str(&self, signature_str: &str) -> Result<BlockchainSignature, AppError>;

    /// Parse a public key from its string representation
    fn parse_public_key(&self, pubkey_str: &str) -> Result<PublicKey, AppError>;

    /// Verify a signature against a message and public key
    fn verify_signature(
        &self,
        message: &str,
        signature: &BlockchainSignature,
    ) -> Result<PublicKey, AppError>;

    /// Clone the signature client
    fn box_clone(&self) -> Box<dyn SignatureClient>;
}

// Implement Clone for Box<dyn SignatureClient>
impl Clone for Box<dyn SignatureClient> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}
