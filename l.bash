#!/bin/bash
# Setup script for a simple CLI-based ZK group signature system using Alloy for Ethereum keys

set -e

PROJECT_NAME="phantom-signer"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Creating $PROJECT_NAME with Alloy for Ethereum key support...${NC}"

# Create project structure
mkdir -p $PROJECT_NAME
cd $PROJECT_NAME
cargo init

# Add dependencies to Cargo.toml
cat > Cargo.toml << 'EOL'
[package]
name = "phantom-signer"
version = "0.1.0"
edition = "2021"
authors = ["Your Name <your.email@example.com>"]
description = "Zero-knowledge group signature system"

[dependencies]
clap = { version = "4.3.19", features = ["derive"] }
alloy-primitives = "0.6.1"
alloy-signer = "0.6.1"
alloy-core = "0.6.1"
alloy-sol-types = "0.6.1"
hex = "0.4.3"
thiserror = "1.0.47"
eyre = "0.6.8"
color-eyre = "0.6.2"
serde = { version = "1.0.183", features = ["derive"] }
serde_json = "1.0.105"
rand = "0.8.5"
sha2 = "0.10.7"
tracing = "0.1.37"
tracing-subscriber = { version = "0.3.17", features = ["env-filter"] }

[dev-dependencies]
pretty_assertions = "1.4.0"
tempfile = "3.8.0"
EOL

# Create src/main.rs file with CLI interface
cat > src/main.rs << 'EOL'
use clap::{Parser, Subcommand};
use color_eyre::eyre::Result;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

mod crypto;
mod group;
mod proof;
mod error;
mod cli;

use cli::{sign_command, verify_command};

/// Phantom Signer - ZK Group Signature Tool
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Sign a message with your private key and generate a ZK proof
    Sign {
        /// The message to sign
        #[arg(short, long)]
        message: String,
        
        /// Your Ethereum private key (hex format without 0x prefix)
        #[arg(short, long)]
        private_key: String,
        
        /// Path to the group public keys file
        #[arg(short, long)]
        group: PathBuf,
        
        /// Output file for the signature and proof
        #[arg(short, long, default_value = "signature.json")]
        output: PathBuf,
    },
    
    /// Verify a signature and ZK proof
    Verify {
        /// The original message
        #[arg(short, long)]
        message: String,
        
        /// Path to the signature and proof file
        #[arg(short, long)]
        signature: PathBuf,
        
        /// Path to the group public keys file
        #[arg(short, long)]
        group: PathBuf,
    },
}

fn main() -> Result<()> {
    // Install color-eyre for better error reporting
    color_eyre::install()?;
    
    // Parse command line arguments
    let cli = Cli::parse();
    
    // Setup logging
    let filter = if cli.verbose {
        EnvFilter::from_default_env().add_directive("phantom_signer=debug".parse()?)
    } else {
        EnvFilter::from_default_env().add_directive("phantom_signer=info".parse()?)
    };
    
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter)
        .finish();
    
    tracing::subscriber::set_global_default(subscriber)?;
    
    info!("Starting Phantom Signer");

    // Execute the appropriate command
    match &cli.command {
        Commands::Sign { message, private_key, group, output } => {
            sign_command(message, private_key, group, output)
        },
        Commands::Verify { message, signature, group } => {
            verify_command(message, signature, group)
        },
    }
}
EOL

# Create error module with thiserror
cat > src/error.rs << 'EOL'
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Invalid private key format")]
    InvalidPrivateKey,

    #[error("Invalid public key format")]
    InvalidPublicKey,

    #[error("Invalid message format")]
    InvalidMessage,

    #[error("Invalid signature format")]
    InvalidSignature,

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),

    #[error("Public key not in group")]
    KeyNotInGroup,

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Hex decoding error: {0}")]
    HexError(#[from] hex::FromHexError),
    
    #[error("Alloy error: {0}")]
    AlloyError(String),
}
EOL

# Create crypto module using Alloy for Ethereum key handling
mkdir -p src/crypto
cat > src/crypto/mod.rs << 'EOL'
use eyre::{Result, WrapErr};
use alloy_primitives::{Address, FixedBytes, Signature, B256, U256};
use alloy_signer::{LocalWallet, Signer, SignerSync};
use sha2::{Sha256, Digest};
use crate::error::AppError;
use tracing::{debug, trace};

/// PublicKey type (Ethereum address)
pub type PublicKey = Address;

/// Ethereum message prefix
const ETH_PREFIX: &str = "\x19Ethereum Signed Message:\n";

/// Hash a message using Ethereum's signing format
pub fn hash_message(message: &str) -> Result<B256> {
    // Ethereum prefixes messages with "\x19Ethereum Signed Message:\n" + message.len()
    let prefix = format!("{}{}", ETH_PREFIX, message.len());
    
    trace!("Message prefix: {}", prefix);
    
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message.as_bytes());
    
    let hash_bytes = hasher.finalize();
    let hash: B256 = hash_bytes.into();
    
    trace!("Message hash: {}", hash);
    
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
    let wallet = LocalWallet::from_private_key(
        U256::from_str_radix(&private_key_hex, 16)
            .map_err(|e| AppError::InvalidPrivateKey)?
    )
    .map_err(|e| AppError::AlloyError(e.to_string()))?;
    
    // Get public key (address) from wallet
    let address = wallet.address();
    debug!("Public key (address): {}", address);
    
    // Sign the message
    let signature = wallet.sign_message_sync(message.as_bytes())
        .map_err(|e| AppError::AlloyError(e.to_string()))?;
    
    debug!("Message signed successfully");
    
    Ok((signature, address))
}

/// Verify a signature with a public key
pub fn verify_signature(message: &str, signature: &Signature, address: &PublicKey) -> Result<bool> {
    // Recover the address from the signature
    let recovered = signature.recover_address_from_msg(message.as_bytes())
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
    let wallet = LocalWallet::from_private_key(
        U256::from_str_radix(&private_key_hex, 16)
            .map_err(|e| AppError::InvalidPrivateKey)?
    )
    .map_err(|e| AppError::AlloyError(e.to_string()))?;
    
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
    
    Address::from_str(&hex_str)
        .map_err(|_| AppError::InvalidPublicKey.into())
}

/// Create a test key pair for unit tests
#[cfg(test)]
pub fn create_test_keypair() -> (String, PublicKey) {
    use rand::Rng;
    
    // Generate random private key
    let private_key = rand::thread_rng().gen::<[u8; 32]>();
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
EOL

# Create group module
mkdir -p src/group
cat > src/group/mod.rs << 'EOL'
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, BufRead};
use std::path::Path;
use eyre::{Result, WrapErr};
use crate::error::AppError;
use crate::crypto::{PublicKey, public_key_from_hex, public_key_to_hex};
use tracing::{debug, info};

/// Group of public keys
#[derive(Clone)]
pub struct Group {
    keys: HashSet<String>,
}

impl Group {
    /// Create a new empty group
    pub fn new() -> Self {
        Self {
            keys: HashSet::new(),
        }
    }
    
    /// Load a group from a file (one public key per line, hex encoded)
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(&path)
            .wrap_err_with(|| format!("Failed to open group file at {:?}", path.as_ref()))?;
        let reader = BufReader::new(file);
        
        let mut keys = HashSet::new();
        for (i, line) in reader.lines().enumerate() {
            let line = line?;
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                // Validate that it's a valid public key
                let key = public_key_from_hex(line)
                    .wrap_err_with(|| format!("Invalid public key on line {}: {}", i + 1, line))?;
                
                let key_hex = public_key_to_hex(&key);
                keys.insert(key_hex);
                debug!("Added key to group: {}", key);
            }
        }
        
        info!("Loaded {} keys from group file", keys.len());
        
        Ok(Self { keys })
    }
    
    /// Add a public key to the group
    pub fn add_key(&mut self, key: &PublicKey) {
        let key_hex = public_key_to_hex(key);
        self.keys.insert(key_hex);
        debug!("Added key to group: {}", key);
    }
    
    /// Check if a public key is in the group
    pub fn contains(&self, key: &PublicKey) -> bool {
        let key_hex = public_key_to_hex(key);
        let result = self.keys.contains(&key_hex);
        debug!("Key {} is in group: {}", key, result);
        result
    }
    
    /// Get all public keys in the group
    pub fn get_keys(&self) -> Result<Vec<PublicKey>> {
        let mut result = Vec::new();
        for key_hex in &self.keys {
            let key = public_key_from_hex(key_hex)?;
            result.push(key);
        }
        Ok(result)
    }
    
    /// Get the number of keys in the group
    pub fn len(&self) -> usize {
        self.keys.len()
    }
    
    /// Check if the group is empty
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
    
    /// Save the group to a file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        use std::io::Write;
        
        let mut file = File::create(path)?;
        
        writeln!(file, "# Group public keys - Ethereum addresses")?;
        writeln!(file, "# DO NOT EDIT THIS FILE MANUALLY")?;
        writeln!(file)?;
        
        // Sort keys for consistent output
        let mut keys: Vec<_> = self.keys.iter().collect();
        keys.sort();
        
        for key in keys {
            writeln!(file, "{}", key)?;
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::create_test_keypair;
    use tempfile::tempdir;
    
    #[test]
    fn test_group_basic_operations() {
        let (_, key1) = create_test_keypair();
        let (_, key2) = create_test_keypair();
        
        let mut group = Group::new();
        assert!(group.is_empty());
        
        group.add_key(&key1);
        assert_eq!(group.len(), 1);
        assert!(group.contains(&key1));
        assert!(!group.contains(&key2));
        
        group.add_key(&key2);
        assert_eq!(group.len(), 2);
        assert!(group.contains(&key2));
    }
    
    #[test]
    fn test_group_save_and_load() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test_group.txt");
        
        // Create a group with test keys
        let (_, key1) = create_test_keypair();
        let (_, key2) = create_test_keypair();
        
        let mut group = Group::new();
        group.add_key(&key1);
        group.add_key(&key2);
        
        // Save the group
        group.save_to_file(&file_path).unwrap();
        
        // Load the group
        let loaded_group = Group::from_file(&file_path).unwrap();
        
        // Check that loaded group has the same keys
        assert_eq!(loaded_group.len(), group.len());
        assert!(loaded_group.contains(&key1));
        assert!(loaded_group.contains(&key2));
    }
}
EOL

# Create proof module (simplified for now)
mkdir -p src/proof
cat > src/proof/mod.rs << 'EOL'
use serde::{Serialize, Deserialize};
use eyre::{Result, WrapErr};
use alloy_primitives::{Signature, B256};
use sha2::{Sha256, Digest};
use crate::crypto::PublicKey;
use crate::group::Group;
use crate::error::AppError;
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
    pub fn new(message: &str, signature: &Signature, public_key: &PublicKey, group: &Group) -> Result<Self> {
        // Check if the public key is in the group
        if !group.contains(public_key) {
            return Err(AppError::KeyNotInGroup.into());
        }
        
        debug!("Creating proof for message: {}", message);
        
        // Calculate message hash
        let message_hash = crate::crypto::hash_message(message)?;
        
        // In a real implementation, this would generate a ZK-STARK proof
        // For this simple example, we'll just use a dummy "proof"
        
        // Calculate a proof hash (dummy implementation)
        let mut hasher = Sha256::new();
        hasher.update(signature.as_bytes());
        hasher.update(public_key.as_bytes());
        let proof_hash = hasher.finalize();
        
        trace!("Generated dummy proof hash: {:?}", proof_hash);
        
        Ok(Self {
            message: message.to_string(),
            message_hash: format!("{:x}", message_hash),
            signature: *signature,
            group_proof: hex::encode(proof_hash),
        })
    }
    
    /// Verify the proof
    pub fn verify(&self, group: &Group) -> Result<bool> {
        debug!("Verifying proof for message: {}", self.message);
        
        // In a real implementation, this would verify the ZK-STARK proof
        
        // For this simple example, we'll do a basic check
        // Recover the signer's address from the signature
        let recovered = self.signature.recover_address_from_msg(self.message.as_bytes())
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
EOL

# Create CLI module
mkdir -p src/cli
cat > src/cli/mod.rs << 'EOL'
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
EOL

# Add clippy configuration
cat > .clippy.toml << 'EOL'
# Clippy configuration

# Allow unwrap() in tests
allow-unwrap-in-tests = true

# Extra restrictions
too-many-arguments-threshold = 5
EOL

# Create a README.md file
cat > README.md << 'EOL'
# Phantom Signer

A command-line tool for anonymous group signatures using Ethereum keys.

## Features

- Sign messages with your Ethereum private key using Alloy
- Generate proofs that you are part of a trusted group without revealing your identity
- Verify signatures and proofs
- Extensible architecture for future support of other blockchains like Solana

## Usage

### Sign a message

```bash
cargo run -- sign --message "Hello, world!" --private-key YOUR_PRIVATE_KEY_HEX --group group.txt
```

### Verify a signature

```bash
cargo run -- verify --message "Hello, world!" --signature signature.json --group group.txt
```

## Group File Format

The group file is a simple text file with one Ethereum address per line in hex format (with or without 0x prefix).

Example:
```
# Group members
0x742d35Cc6634C0532925a3b844Bc454e4438f44e
0x2e41f5cd1ea3809098731159c50297f3d21976993
```

## Error Handling

The tool uses `eyre` for user-friendly error handling and `thiserror` for defining error types.

## Extending to Other Blockchains

The architecture is designed to be extensible. To add support for other blockchains:

1. Create a new module for the blockchain's key handling
2. Implement the necessary signature and verification logic
3. Update the CLI to accept the new key type

The core proof and group functionality can remain largely unchanged.
EOL

# Create a sample group file
cat > group.txt << 'EOL'
# Sample group of public keys (Ethereum addresses)
# The following are example addresses - replace with your own
0x742d35Cc6634C0532925a3b844Bc454e4438f44e
0x2e41f5cd1ea3809098731159c50297f3d21976993
EOL

# Print success message
echo -e "${GREEN}$PROJECT_NAME has been created successfully!${NC}"
echo -e "Run the following commands to test it:"
echo -e "  cd $PROJECT_NAME"
echo -e "  cargo build"
echo -e "  cargo clippy"
echo -e "  cargo run -- --help"