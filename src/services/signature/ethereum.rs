use super::error::SignatureErrorKind::EthereumError;
use crate::{
    error::AppError,
    services::signature::traits::{BlockchainSignature, PublicKey, SignatureClient},
};
use alloy_primitives::{Address, PrimitiveSignature as EthSignature};
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;

use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct EthereumSignatureClient;

impl EthereumSignatureClient {
    pub fn new() -> Self {
        Self
    }
}

impl SignatureClient for EthereumSignatureClient {
    fn sign_message(
        &self,
        message: &str,
        private_key: &str,
    ) -> Result<BlockchainSignature, AppError> {
        let private_key = if private_key.starts_with("0x") {
            private_key.to_string()
        } else {
            format!("0x{}", private_key)
        };

        let wallet =
            LocalSigner::from_str(&private_key).map_err(|e| EthereumError(e.to_string()))?;

        let signature = wallet
            .sign_message_sync(message.as_bytes())
            .map_err(|e| EthereumError(e.to_string()))?;

        Ok(BlockchainSignature::Ethereum(signature))
    }

    fn get_public_key(&self, private_key: &str) -> Result<PublicKey, AppError> {
        let private_key = if private_key.starts_with("0x") {
            private_key.to_string()
        } else {
            format!("0x{}", private_key)
        };

        let wallet =
            LocalSigner::from_str(&private_key).map_err(|e| EthereumError(e.to_string()))?;

        let address = wallet.address();

        Ok(PublicKey::Ethereum(address))
    }

    fn from_str(&self, signature_str: &str) -> Result<BlockchainSignature, AppError> {
        let signature_str = if signature_str.starts_with("0x") {
            &signature_str[2..]
        } else {
            signature_str
        };
        let signature_raw = hex::decode(signature_str)
            .map_err(|_| EthereumError(format!("Cannot decode : (0x){}", signature_str)))?;
        if signature_raw.len() != 65 {
            return Err(EthereumError(format!(
                "Invalid signature length: expected 65, got {}",
                signature_raw.len()
            ))
            .into());
        }

        let signature = EthSignature::from_raw(&signature_raw)
            .map_err(|e| EthereumError(format!("Cannot create signature: {}", e)))?;

        Ok(BlockchainSignature::Ethereum(signature))
    }

    fn parse_public_key(&self, pubkey_str: &str) -> Result<PublicKey, AppError> {
        let pubkey_str = pubkey_str.strip_prefix("0x").unwrap_or(pubkey_str);
        let address =
            Address::from_str(&pubkey_str).map_err(|e| EthereumError(format!("{:?}", e)))?;

        Ok(PublicKey::Ethereum(address))
    }

    #[allow(unreachable_patterns)]
    fn verify_signature(
        &self,
        message: &str,
        signature: &BlockchainSignature,
    ) -> Result<PublicKey, AppError> {
        match signature {
            BlockchainSignature::Ethereum(sig) => {
                let recovered = sig
                    .recover_address_from_msg(message.as_bytes())
                    .map_err(|e| EthereumError(e.to_string()))?;

                Ok(PublicKey::Ethereum(recovered))
            }
            _ => Err(EthereumError("Cannot retreive signature".to_owned()).into()),
        }
    }
    fn box_clone(&self) -> Box<dyn SignatureClient> {
        Box::new(self.clone())
    }
}
