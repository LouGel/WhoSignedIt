use super::error::SignatureErrorKind::SolanaError;
use crate::{
    error::AppError,
    services::signature::traits::{BlockchainSignature, ChainAddress, SignatureClient},
};

use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::Signer,
};

#[derive(Debug, Clone)]
pub struct SolanaSignatureClient;

impl SolanaSignatureClient {
    pub fn new() -> Self {
        Self
    }
}

impl SignatureClient for SolanaSignatureClient {
    fn sign_message(
        &self,
        message: &str,
        private_key: &str,
    ) -> Result<BlockchainSignature, AppError> {
        let wallet = Keypair::from_base58_string(&private_key);

        let signature = wallet.sign_message(message.as_bytes());

        Ok(BlockchainSignature::Solana(signature))
    }

    fn get_address(&self, private_key: &str) -> Result<ChainAddress, AppError> {
        let wallet = Keypair::from_base58_string(&private_key);

        let address = wallet.pubkey();

        Ok(ChainAddress::Solana(address))
    }

    fn from_str(&self, signature_str: &str) -> Result<BlockchainSignature, AppError> {
        let signature_str = if signature_str.starts_with("0x") {
            &signature_str[2..]
        } else {
            signature_str
        };
        let signature_raw = hex::decode(signature_str)
            .map_err(|_| SolanaError(format!("Cannot decode : (0x){}", signature_str)))?;
        if signature_raw.len() != 65 {
            return Err(SolanaError(format!(
                "Invalid signature length: expected 65, got {}",
                signature_raw.len()
            ))
            .into());
        }

        let signature = Signature::try_from(signature_raw.as_ref()).map_err(|_| {
            SolanaError(format!(
                "Invalid signature format: expected 65 bytes, got {}",
                signature_raw.len()
            ))
        })?;

        Ok(BlockchainSignature::Solana(signature))
    }

    fn parse_public_key(&self, pubkey_str: &str) -> Result<ChainAddress, AppError> {
        let address = Pubkey::from_str_const(&pubkey_str);
        Ok(ChainAddress::Solana(address))
    }

    fn verify_signature(
        &self,
        message: &str,
        signature: &BlockchainSignature,
        address: &ChainAddress,
    ) -> bool {
        match signature {
            BlockchainSignature::Solana(sig) => {
                sig.verify(message.as_bytes(), &address.to_vec_u8())
            }
            _ => false,
        }
    }
    fn box_clone(&self) -> Box<dyn SignatureClient> {
        Box::new(self.clone())
    }
}
