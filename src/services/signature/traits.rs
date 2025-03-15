// File: src/services/signature/traits.rs
use alloy_primitives::Address;
use eyre::Result;
use std::fmt::Debug;

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
    fn sign_message(&self, message: &str, private_key: &str) -> Result<BlockchainSignature>;

    /// Get the public key from a private key
    fn get_public_key(&self, private_key: &str) -> Result<PublicKey>;

    /// Parse a signature from its string representation
    fn parse_signature(&self, signature_str: &str) -> Result<BlockchainSignature>;

    /// Parse a public key from its string representation
    fn parse_public_key(&self, pubkey_str: &str) -> Result<PublicKey>;

    /// Verify a signature against a message and public key
    fn verify_signature(
        &self,
        message: &str,
        signature: &BlockchainSignature,
        public_key: &PublicKey,
    ) -> Result<bool>;

    /// Clone the signature client
    fn box_clone(&self) -> Box<dyn SignatureClient>;
}

// Implement Clone for Box<dyn SignatureClient>
impl Clone for Box<dyn SignatureClient> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}
