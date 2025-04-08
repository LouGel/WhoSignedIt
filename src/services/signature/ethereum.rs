use super::error::SignatureErrorKind::EthereumError;
use crate::{
    error::AppError,
    services::signature::traits::{BlockchainSignature, ChainAddress, SignatureClient},
};
use alloy_primitives::{Address, PrimitiveSignature as EthSignature};
use alloy_signer::{k256::ecdsa::SigningKey, SignerSync};
use alloy_signer_local::LocalSigner;

use std::str::FromStr;

const BYTES_32_HEX_LEN: usize = 64;
#[derive(Debug, Clone)]
pub struct EthereumSignatureClient;

impl EthereumSignatureClient {
    pub fn new() -> Self {
        Self
    }
}

fn generate_wallet_from_pk(private_key: &str) -> Result<LocalSigner<SigningKey>, AppError> {
    let private_key = private_key.strip_prefix("0x").unwrap_or(private_key);

    let pk_len_diff = BYTES_32_HEX_LEN.checked_sub(private_key.len());

    let padded_key = match pk_len_diff {
        Some(0) => String::from(private_key),
        Some(x) if x > 0 => format!("{}{}", "0".repeat(x), private_key),
        _ => return Err(EthereumError("Private key too long".to_string()).into()),
    };

    let wallet = LocalSigner::from_str(&padded_key)
        .map_err(|e| EthereumError(format!("Generating wallet from str : {}", e.to_string())))?;
    Ok(wallet)
}

impl SignatureClient for EthereumSignatureClient {
    fn sign_message(
        &self,
        message: &str,
        private_key: &str,
    ) -> Result<BlockchainSignature, AppError> {
        let wallet = generate_wallet_from_pk(private_key)?;

        let signature = wallet
            .sign_message_sync(message.as_bytes())
            .map_err(|e| EthereumError(e.to_string()))?;

        Ok(BlockchainSignature::Ethereum(signature))
    }

    fn get_address(&self, private_key: &str) -> Result<ChainAddress, AppError> {
        let wallet = generate_wallet_from_pk(private_key)?;
        let address = wallet.address();
        Ok(ChainAddress::Ethereum(address))
    }

    fn from_str(&self, signature_str: &str) -> Result<BlockchainSignature, AppError> {
        let signature_str = signature_str.strip_prefix("0x").unwrap_or(signature_str);
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

    fn parse_public_key(&self, pubkey_str: &str) -> Result<ChainAddress, AppError> {
        let pubkey_str = pubkey_str.strip_prefix("0x").unwrap_or(pubkey_str);
        let address =
            Address::from_str(&pubkey_str).map_err(|e| EthereumError(format!("{:?}", e)))?;

        Ok(ChainAddress::Ethereum(address))
    }

    fn verify_signature(
        &self,
        message: &str,
        signature: &BlockchainSignature,
        address: &ChainAddress,
    ) -> bool {
        match signature {
            BlockchainSignature::Ethereum(sig) => {
                let recovered = sig.recover_address_from_msg(message.as_bytes());
                if let Ok(recovered_address) = recovered {
                    ChainAddress::Ethereum(recovered_address) == *address
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn box_clone(&self) -> Box<dyn SignatureClient> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::signature::traits::{BlockchainSignature, ChainAddress};

    // Test private key and corresponding address
    // WARNING: Don't use these values in production!
    const TEST_PRIVATE_KEY: &str = "1";
    const TEST_ADDRESS: &str = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";
    const TEST_MESSAGE: &str = "Hello, Ethereum!";

    #[test]
    fn test_sign_message() {
        let client = EthereumSignatureClient::new();

        let signature = client.sign_message(TEST_MESSAGE, TEST_PRIVATE_KEY).unwrap();

        // Verify we got a valid Ethereum signature
        match signature {
            BlockchainSignature::Ethereum(_) => assert!(true), // Success
            _ => panic!("Expected Ethereum signature"),
        }

        // Test with invalid key
        let result = client.sign_message(TEST_MESSAGE, "invalid_key");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_address() {
        let client = EthereumSignatureClient::new();

        let address = client.get_address(TEST_PRIVATE_KEY).unwrap();

        match address {
            ChainAddress::Ethereum(eth_address) => {
                assert_eq!(
                    eth_address.to_string().to_lowercase(),
                    TEST_ADDRESS.to_lowercase()
                );
            }
            _ => panic!("Expected Ethereum address"),
        }

        // Test invalid key
        let result = client.get_address("invalid_key");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_str() {
        let client = EthereumSignatureClient::new();

        // First generate a valid signature to test with
        let original_signature = client.sign_message(TEST_MESSAGE, TEST_PRIVATE_KEY).unwrap();
        let signature_hex = match &original_signature {
            BlockchainSignature::Ethereum(sig) => format!("{}", sig),
            _ => panic!("Expected Ethereum signature"),
        };

        // Parse the signature
        let parsed_signature = client.from_str(&signature_hex).unwrap();

        // Verify it parsed correctly
        match parsed_signature {
            BlockchainSignature::Ethereum(_) => assert!(true), // Success
            _ => panic!("Expected Ethereum signature"),
        }

        // Test invalid signature
        let result = client.from_str("invalid_signature");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_public_key() {
        let client = EthereumSignatureClient::new();

        let address = client.parse_public_key(TEST_ADDRESS).unwrap();

        match address {
            ChainAddress::Ethereum(eth_address) => {
                assert_eq!(
                    eth_address.to_string().to_lowercase(),
                    TEST_ADDRESS.to_lowercase()
                );
            }
            _ => panic!("Expected Ethereum address"),
        }

        // Test invalid address
        let result = client.parse_public_key("invalid_address");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_signature() {
        let client = EthereumSignatureClient::new();

        // Get the test address
        let address = client.get_address(TEST_PRIVATE_KEY).unwrap();

        // Create a signature
        let signature = client.sign_message(TEST_MESSAGE, TEST_PRIVATE_KEY).unwrap();

        // Verify it
        assert!(client.verify_signature(TEST_MESSAGE, &signature, &address));

        // Verify with wrong message fails
        assert!(!client.verify_signature("Wrong message", &signature, &address));
    }
}
