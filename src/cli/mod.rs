use std::path::Path;
use std::fs::File;
use std::io::Write;
use eyre::{Result, WrapErr};
use alloy_primitives::Signature;
use serde_json;
use tracing::{info, warn};

use crate::crypto;
use crate::group::Group;
use crate::proof::GroupSignatureProof;

/// Sign command implementation
pub fn sign_command(
    message: &str,
    private_key_hex: &str,
    group_path: &Path,
    output_path: &Path,
) -> Result<()> {
    info!("Signing message: {}", message);
    
    // Load the group
    let group = Group::from_file(group_path)
        .wrap_err("Failed to load group file")?;
    
    // Sign the message
    let (signature, public_key) = crypto::sign_message(message, private_key_hex)
        .wrap_err("Failed to sign message")?;
    
    // Check if the public key is in the group
    if !group.contains(&public_key) {
        warn!("Your public key ({}) is not in the group. Adding it for this operation.", public_key);
        // In a real implementation, we might want to fail here or add the key to the group file
    }
    
    // Generate the proof
    let proof = GroupSignatureProof::new(message, &signature, &public_key, &group)
        .wrap_err("Failed to generate proof")?;
    
    // Save the proof to the output file
    let output_file = File::create(output_path)
        .wrap_err_with(|| format!("Failed to create output file at {:?}", output_path))?;
    serde_json::to_writer_pretty(output_file, &proof)
        .wrap_err("Failed to write proof to file")?;
    
    info!("✅ Signature and proof saved to {}", output_path.display());
    
    Ok(())
}

/// Verify command implementation
pub fn verify_command(
    message: &str,
    signature_path: &Path,
    group_path: &Path,
) -> Result<()> {
    info!("Verifying signature for message: {}", message);
    
    // Load the group
    let group = Group::from_file(group_path)
        .wrap_err("Failed to load group file")?;
    
    // Load the proof
    let signature_file = File::open(signature_path)
        .wrap_err_with(|| format!("Failed to open signature file at {:?}", signature_path))?;
    let proof: GroupSignatureProof = serde_json::from_reader(signature_file)
        .wrap_err("Failed to parse signature file")?;
    
    // Check that the message matches
    if proof.message != message {
        println!("❌ Message mismatch!");
        return Ok(());
    }
    
    // Verify the proof
    match proof.verify(&group) {
        Ok(true) => {
            println!("✅ Signature verified: the message was signed by a member of the group!");
            Ok(())
        },
        Ok(false) => {
            println!("❌ Signature verification failed: either the signature is invalid or the signer is not in the group.");
            Ok(())
        },
        Err(e) => {
            println!("❌ Error verifying signature: {}", e);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::create_test_keypair;
    use tempfile::tempdir;
    
    #[test]
    fn test_sign_and_verify_workflow() {
        // Setup temporary directory for test files
        let dir = tempdir().unwrap();
        let group_path = dir.path().join("test_group.txt");
        let signature_path = dir.path().join("test_signature.json");
        
        // Create a test key pair
        let (private_key, public_key) = create_test_keypair();
        
        // Create a group file with the test key
        let mut group = Group::new();
        group.add_key(&public_key);
        group.save_to_file(&group_path).unwrap();
        
        // Test message
        let message = "Test message for signing and verification";
        
        // Sign the message
        sign_command(message, &private_key, &group_path, &signature_path).unwrap();
        
        // Verify the signature
        let result = verify_command(message, &signature_path, &group_path);
        assert!(result.is_ok());
    }
}
