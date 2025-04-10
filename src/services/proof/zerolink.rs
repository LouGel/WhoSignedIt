use super::error::ProofErrorKind::ZeroLink;
use crate::client::client::FormatInput;
use crate::error::AppError;
use crate::services::proof::traits::{Proof, ProofClient};
use crate::services::signature::traits::{BlockchainSignature, ChainAddress, SignatureClient};
use alloy_primitives::{keccak256, B256, U256};
use rand::{rngs::OsRng, TryRngCore};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};

#[derive(Debug)]
pub struct RingProofClient {
    signature_client: Box<dyn SignatureClient>,
}

impl RingProofClient {
    pub fn new(signature_client: Box<dyn SignatureClient>) -> Self {
        Self { signature_client }
    }
}

/// A simpler OR-proof alternative to ring signatures
#[derive(Debug, Deserialize, Serialize)]
pub struct ZeroLinkProof {
    /// The message that was signed
    message: String,

    /// The ring members (public keys)
    ring: Vec<ChainAddress>,

    /// Challenge value (same as hash of message)
    challenge: B256,

    /// Individual response values for each member
    responses: Vec<U256>,

    /// Commitments for each member
    commitments: Vec<B256>,
}
impl Display for ZeroLinkProof {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string_pretty(self).unwrap())
    }
}

impl Proof for ZeroLinkProof {
    fn format(&self, format: &FormatInput) -> String {
        match format {
            FormatInput::Json => serde_json::to_string_pretty(self).unwrap(),
            FormatInput::Toml => toml::to_string(self).unwrap(),
        }
    }

    fn verify(&self) -> Result<bool, AppError> {
        println!("Verifying zero-link-proofsignature");
        println!("{self}");

        // Verify that the sum of responses matches the challenge
        let sum_check = verify_responses_sum(&self.responses, &self.challenge)?;

        if !sum_check {
            println!("Response sum verification failed");
            return Ok(false);
        }

        // Verify each member's commitment
        let ring = order_public_keys(&self.ring);
        for i in 0..self.ring.len() {
            let valid = verify_commitment(
                &self.message,
                &ring[i],
                self.responses[i],
                &self.commitments[i],
            )?;

            if !valid {
                println!("Commitment verification failed for member {}", i);
                return Ok(false);
            }
        }

        println!("zero-link-proof verification successful");
        Ok(true)
    }

    fn message(&self) -> &str {
        &self.message
    }
}

/// Create a commitment for a group member
fn create_commitment(
    message: &str,
    public_key: &ChainAddress,
    response: U256,
) -> Result<B256, AppError> {
    // Create the commitment data
    let mut commitment_data = Vec::new();
    commitment_data.extend_from_slice(message.as_bytes());

    match public_key {
        ChainAddress::Ethereum(addr) => commitment_data.extend_from_slice(&addr.to_vec()),
        ChainAddress::Solana(pubkey) => commitment_data.extend_from_slice(pubkey.as_ref()),
    }

    commitment_data.extend_from_slice(&response.to_be_bytes::<32>());

    // Hash to create the commitment
    let commitment = keccak256(&commitment_data);

    Ok(commitment)
}

/// Verify a commitment
fn verify_commitment(
    message: &str,
    public_key: &ChainAddress,
    response: U256,
    commitment: &B256,
) -> Result<bool, AppError> {
    let computed = create_commitment(message, public_key, response)?;
    Ok(&computed == commitment)
}

/// Verify that the sum of responses matches the challenge
fn verify_responses_sum(responses: &[U256], challenge: &B256) -> Result<bool, AppError> {
    // Convert challenge to U256
    let challenge_u256 = U256::from_be_bytes(challenge.0);

    // Sum all responses
    let mut sum = U256::from(0);
    for r in responses {
        sum = sum.overflowing_add(*r).0;
    }

    // Sum of responses should be equal to challenge (mod 2^256)
    Ok(sum == challenge_u256)
}
fn order_public_keys(group: &[ChainAddress]) -> Vec<ChainAddress> {
    let mut group = group.to_vec();
    group.sort_by(|a, b| a.to_vec_u8().cmp(&b.to_vec_u8()));
    group
}
impl ProofClient for RingProofClient {
    fn create_group_signature_proof(
        &self,
        message: &str,
        signature: &BlockchainSignature,
        group: &[ChainAddress],
    ) -> Result<Box<dyn Proof>, AppError> {
        let group = order_public_keys(group);

        let signer_position = group
            .iter()
            .position(|pk| {
                self.signature_client
                    .verify_signature(message, signature, pk)
            })
            .ok_or_else(|| ZeroLink("Signer's public key not found in the group".to_owned()))?;

        let challenge = keccak256(message.as_bytes());
        let challenge_u256 = U256::from_be_bytes(challenge.0);

        // Generate random responses for everyone except the signer
        let mut responses = Vec::with_capacity(group.len());
        let mut response_sum = U256::from(0);

        for i in 0..group.len() {
            if i != signer_position {
                let mut bytes = [0u8; 32];
                OsRng
                    .try_fill_bytes(&mut bytes)
                    .expect("Couldnt fill bytes for rng");
                let response = U256::from_le_bytes(bytes);

                responses.push(response);
                response_sum = response_sum.overflowing_add(response).0;
            } else {
                responses.push(U256::from(0)); // Placeholder
            }
        }

        // Calculate signer's response to complete the sum
        // Signer's response = challenge - sum of all other responses (mod 2^256)
        let signer_response = if challenge_u256 >= response_sum {
            challenge_u256 - response_sum
        } else {
            // Handle underflow by adding 2^256
            challenge_u256 + (U256::MAX - response_sum) + U256::from(1)
        };

        responses[signer_position] = signer_response;

        println!("Calculated signer's response: {}", signer_response);

        // Create commitments for each group member
        let mut commitments = Vec::with_capacity(group.len());

        for i in 0..group.len() {
            let commitment = create_commitment(message, &group[i], responses[i])?;

            commitments.push(commitment);
            println!("Commitment {} created", i);
        }

        // Verify the proof ourselves
        let mut response_sum_check = U256::from(0);
        for r in &responses {
            response_sum_check = response_sum_check.overflowing_add(*r).0;
        }

        println!(
            "Response sum check: sum = {}, challenge = {}, match = {}",
            response_sum_check,
            challenge_u256,
            response_sum_check == challenge_u256
        );

        let proof = ZeroLinkProof {
            message: message.to_string(),
            ring: group.to_vec(),
            challenge,
            responses,
            commitments,
        };

        Ok(Box::new(proof))
    }

    fn from_str(&self, proof: &str, fmt: FormatInput) -> Result<Box<dyn Proof>, AppError> {
        let ret = match fmt {
            FormatInput::Json => serde_json::from_str::<ZeroLinkProof>(proof),
            FormatInput::Toml => serde_json::from_str::<ZeroLinkProof>(proof),
        };

        let proof = ret.or_else(|e| {
            Err(AppError::Custom(format!(
                "Wrong proof error {:?} format{:?}",
                fmt, e
            )))
        })?;
        Ok(Box::new(proof))
    }
}
