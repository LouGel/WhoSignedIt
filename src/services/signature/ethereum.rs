use crate::error::AppError;
use crate::services::signature::traits::{BlockchainSignature, PublicKey, SignatureClient};
use alloy_primitives::{Address, PrimitiveSignature as EthSignature};
use alloy_signer::{Signer, SignerSync};
use alloy_signer_local::LocalSigner;
use eyre::Result;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct EthereumSignatureClient;

impl EthereumSignatureClient {
    pub fn new() -> Self {
        Self
    }
}

impl SignatureClient for EthereumSignatureClient {
    fn sign_message(&self, message: &str, private_key: &str) -> Result<BlockchainSignature> {
        // Add 0x prefix if missing
        let private_key = if private_key.starts_with("0x") {
            private_key.to_string()
        } else {
            format!("0x{}", private_key)
        };

        // Create wallet from private key
        let wallet =
            LocalSigner::from_str(&private_key).map_err(|e| AppError::AlloyError(e.to_string()))?;

        // Sign the message
        let signature = wallet
            .sign_message_sync(message.as_bytes())
            .map_err(|e| AppError::AlloyError(e.to_string()))?;

        Ok(BlockchainSignature::Ethereum(signature))
    }

    fn get_public_key(&self, private_key: &str) -> Result<PublicKey> {
        // Add 0x prefix if missing
        let private_key = if private_key.starts_with("0x") {
            private_key.to_string()
        } else {
            format!("0x{}", private_key)
        };

        // Create wallet from private key
        let wallet =
            LocalSigner::from_str(&private_key).map_err(|e| AppError::AlloyError(e.to_string()))?;

        // Get the address
        let address = wallet.address();

        Ok(PublicKey::Ethereum(address))
    }

    fn parse_signature(&self, signature_str: &str) -> Result<BlockchainSignature> {
        // Remove 0x prefix if present
        let signature_str = if signature_str.starts_with("0x") {
            &signature_str[2..]
        } else {
            signature_str
        };
        let signature_raw =
            hex::decode(signature_str).map_err(|_| eyre::eyre!("Invalid Ethereum signature"))?;

        let signature = EthSignature::from_raw(&signature_raw)
            .map_err(|e| eyre::eyre!("Invalid signature: {}", e))?;

        Ok(BlockchainSignature::Ethereum(signature))
    }

    fn parse_public_key(&self, pubkey_str: &str) -> Result<PublicKey> {
        // Add 0x prefix if missing
        let pubkey_str = if pubkey_str.starts_with("0x") {
            pubkey_str.to_string()
        } else {
            format!("0x{}", pubkey_str)
        };

        // Parse the address
        let address =
            Address::from_str(&pubkey_str).map_err(|_| eyre::eyre!("Invalid Ethereum address"))?;

        Ok(PublicKey::Ethereum(address))
    }

    fn verify_signature(
        &self,
        message: &str,
        signature: &BlockchainSignature,
        public_key: &PublicKey,
    ) -> Result<bool> {
        match (signature, public_key) {
            (BlockchainSignature::Ethereum(sig), PublicKey::Ethereum(addr)) => {
                // Recover the address from the signature
                let recovered = sig
                    .recover_address_from_msg(message.as_bytes())
                    .map_err(|e| AppError::AlloyError(e.to_string()))?;

                // Check if it matches
                Ok(&recovered == addr)
            }
            _ => Err(eyre::eyre!("Mismatched signature and public key types")),
        }
    }
    fn box_clone(&self) -> Box<dyn SignatureClient> {
        Box::new(self.clone())
    }
}
