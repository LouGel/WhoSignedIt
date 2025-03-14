use crate::crypto::PublicKey;
use crate::error::AppError;
use crate::group::Group;
use alloy_primitives::{keccak256, PrimitiveSignature as Signature};
use eyre::Result;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, trace};

/// Proof that a message was signed by a member of the group
#[derive(Serialize, Deserialize)]
pub struct GroupSignatureProof {
    /// Original message
    pub message: String,

    /// Message hash
    pub message_hash: String,

    /// The Ethereum signature
    pub signature: Signature,

    /// A simple proof that the signer is in the group (real impl would use ZK proofs)
    pub group_proof: String,
}

impl GroupSignatureProof {
    /// Create a new proof
    pub fn new(
        message: &str,
        signature: &Signature,
        public_key: &PublicKey,
        group: &Group,
    ) -> Result<Self> {
        // Check if the public key is in the group
        if !group.contains(public_key) {
            return Err(AppError::KeyNotInGroup.into());
        }

        debug!("Creating proof for message: {}", message);

        // Calculate message hash
        let message_hash = crate::crypto::hash_message(message)?;

        // In a real implementation, this would generate a ZK-STARK proof
        // For this simple example, we'll just use a dummy "proof"

        // Calculate a proof hash using Keccak (dummy implementation)
        // Concatenate signature bytes and public key bytes
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&signature.as_bytes());
        proof_data.extend_from_slice(&public_key.into_array());

        // Use Alloy's keccak256 function
        let proof_hash = keccak256(proof_data);

        trace!("Generated dummy proof hash with Keccak: {:?}", proof_hash);

        Ok(Self {
            message: message.to_string(),
            message_hash: format!("{:x}", message_hash),
            signature: *signature,
            group_proof: format!("{:x}", proof_hash),
        })
    }

    /// Verify the proof
    pub fn verify(&self, group: &Group) -> Result<bool> {
        debug!("Verifying proof for message: {}", self.message);

        // In a real implementation, this would verify the ZK-STARK proof

        // For this simple example, we'll do a basic check
        // Recover the signer's address from the signature
        let recovered = self
            .signature
            .recover_address_from_msg(self.message.as_bytes())
            .map_err(|e| AppError::AlloyError(e.to_string()))?;

        debug!("Recovered signer address: {}", recovered);

        // Check if the recovered address is in the group
        let result = group.contains(&recovered);

        info!("Signature verification result: {}", result);

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{create_test_keypair, sign_message};

    #[test]
    fn test_proof_creation_and_verification() {
        let message = "Test message";

        // Create two test key pairs
        let (private_key1, public_key1) = create_test_keypair();
        let (_, public_key2) = create_test_keypair();

        // Create a group with both keys
        let mut group = Group::new();
        group.add_key(&public_key1);
        group.add_key(&public_key2);

        // Sign the message with key1
        let (signature, _) = sign_message(message, &private_key1).unwrap();

        // Create a proof
        let proof = GroupSignatureProof::new(message, &signature, &public_key1, &group).unwrap();

        // Verify the proof
        let is_valid = proof.verify(&group).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_proof_verification_fails_for_non_member() {
        let message = "Test message";

        // Create two test key pairs
        let (private_key1, public_key1) = create_test_keypair();
        let (_, public_key2) = create_test_keypair();

        // Create a group with only key2
        let mut group = Group::new();
        group.add_key(&public_key2);

        // Sign the message with key1
        let (signature, _) = sign_message(message, &private_key1).unwrap();

        // Try to create a proof - should fail
        let result = GroupSignatureProof::new(message, &signature, &public_key1, &group);
        assert!(result.is_err());
    }
}
