use crate::error::AppError;
use alloy_primitives::{
    eip191_hash_message, keccak256, Address, FixedBytes, PrimitiveSignature as Signature, B256,
    U256,
};
use alloy_signer::{Signer, SignerSync};
use alloy_signer_local::LocalSigner;
use eyre::{Result, WrapErr};
use std::str::FromStr;
use tracing::{debug, trace};

/// PublicKey type (Ethereum address)
pub type PublicKey = Address;

/// Ethereum message prefix
const ETH_PREFIX: &str = "\x19Ethereum Signed Message:\n";

/// Hash a message using Ethereum's signing format
pub fn hash_message(message: &str) -> Result<B256> {
    // Ethereum prefixes messages with "\x19Ethereum Signed Message:\n" + message.len()
    let hash = keccak256(message.as_bytes());

    Ok(hash)
}

/// Sign a message using an Ethereum private key
pub fn sign_message(message: &str, private_key_hex: &str) -> Result<(Signature, PublicKey)> {
    // Ensure private key has 0x prefix
    let private_key_hex = if private_key_hex.starts_with("0x") {
        private_key_hex.to_string()
    } else {
        format!("0x{}", private_key_hex)
    };

    trace!("Creating wallet from private key");

    // Create wallet from private key
    let wallet =
        LocalSigner::from_str(&private_key_hex).map_err(|e| AppError::AlloyError(e.to_string()))?;

    // Get public key (address) from wallet
    let address = wallet.address();
    debug!("Public key (address): {}", address);

    // Sign the message
    let signature = wallet
        .sign_message_sync(message.as_bytes())
        .map_err(|e| AppError::AlloyError(e.to_string()))?;

    debug!("Message signed successfully");

    Ok((signature, address))
}

/// Verify a signature with a public key
pub fn verify_signature(message: &str, signature: &Signature, address: &PublicKey) -> Result<bool> {
    // Recover the address from the signature
    let recovered = signature
        .recover_address_from_msg(message.as_bytes())
        .map_err(|e| AppError::AlloyError(e.to_string()))?;

    // Check if recovered address matches expected address
    Ok(&recovered == address)
}

/// Get public key (address) from private key
pub fn get_public_key(private_key_hex: &str) -> Result<PublicKey> {
    // Ensure private key has 0x prefix
    let private_key_hex = if private_key_hex.starts_with("0x") {
        private_key_hex.to_string()
    } else {
        format!("0x{}", private_key_hex)
    };

    // Create wallet from private key
    let wallet =
        LocalSigner::from_str(&private_key_hex).map_err(|e| AppError::AlloyError(e.to_string()))?;

    // Get public key (address) from wallet
    Ok(wallet.address())
}

/// Format public key as hex string
pub fn public_key_to_hex(address: &PublicKey) -> String {
    format!("{:x}", address)
}

/// Parse public key from hex string
pub fn public_key_from_hex(hex_str: &str) -> Result<PublicKey> {
    let hex_str = if hex_str.starts_with("0x") {
        hex_str.to_string()
    } else {
        format!("0x{}", hex_str)
    };
    Address::from_str(&hex_str).wrap_err("Failed to parse public key")
}

/// Create a test key pair for unit tests
#[cfg(test)]
pub fn create_test_keypair() -> (String, PublicKey) {
    use rand::Rng;

    // Generate random private key
    let private_key = rand::rng().random::<[u8; 32]>();
    let private_key_hex = format!("0x{}", hex::encode(private_key));

    // Derive public key
    let public_key = get_public_key(&private_key_hex).unwrap();

    (private_key_hex, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let message = "Hello, world!";
        let (private_key_hex, public_key) = create_test_keypair();

        // Sign message
        let (signature, signer_key) = sign_message(message, &private_key_hex).unwrap();

        // Verify that signer key matches expected public key
        assert_eq!(signer_key, public_key);

        // Verify signature
        let is_valid = verify_signature(message, &signature, &public_key).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_public_key_from_private() {
        let (private_key_hex, expected_public_key) = create_test_keypair();

        // Get public key from private key
        let public_key = get_public_key(&private_key_hex).unwrap();

        // Check that it matches expected public key
        assert_eq!(public_key, expected_public_key);
    }

    #[test]
    fn test_public_key_to_from_hex() {
        let (_, public_key) = create_test_keypair();

        // Convert to hex
        let hex = public_key_to_hex(&public_key);

        // Convert back from hex
        let parsed = public_key_from_hex(&hex).unwrap();

        // Check that it matches original
        assert_eq!(parsed, public_key);
    }
}
