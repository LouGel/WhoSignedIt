use crate::services::{
    proof::{ProofClient, ProofClientFactory},
    signature::{SignatureClient, SignatureClientFactory},
};
use clap::Parser;
use eyre::Result;

/// Main client for the application
pub struct AppClient {
    signature_client: Box<dyn SignatureClient>,
    proof_client: Box<dyn ProofClient>,
}

/// CLI Arguments for the application
#[derive(Parser, Debug)]
#[clap(author, version, about)]
pub struct AppArgs {
    /// Blockchain type (ethereum or solana)
    #[clap(short, long, default_value = "ethereum")]
    pub blockchain: String,

    /// Proof type (ring or stark)
    #[clap(short, long, default_value = "ring")]
    pub proof_type: String,

    /// Message to sign or verify
    #[clap(short, long)]
    pub message: String,

    /// Existing signature (optional)
    #[clap(short, long)]
    pub signature: Option<String>,

    /// Private key for signing (optional)
    #[clap(long)]
    pub private_key: Option<String>,

    /// Group public keys (comma-separated)
    #[clap(short, long, num_args = 1..)]
    pub group_public_keys: Vec<String>,
}

impl AppClient {
    /// Create a new app client
    pub fn new(args: &AppArgs) -> Result<Self> {
        // Create signature client based on blockchain type
        let signature_client = SignatureClientFactory::create_client(&args.blockchain)?;

        // Create proof client based on proof type
        let proof_client =
            ProofClientFactory::create_client(&args.proof_type, signature_client.clone())?;

        Ok(Self {
            signature_client,
            proof_client,
        })
    }

    /// Run the application
    pub fn run(&self, args: &AppArgs) -> Result<()> {
        // Parse or create a signature
        let signature = if let Some(sig_str) = &args.signature {
            // Parse an existing signature
            self.signature_client.from_str(sig_str)?
        } else if let Some(private_key) = &args.private_key {
            // Create a new signature
            self.signature_client
                .sign_message(&args.message, private_key)?
        } else {
            return Err(eyre::eyre!(
                "Either signature or private key must be provided"
            ));
        };

        // Parse the group public keys
        let mut group = Vec::new();
        for pubkey_str in &args.group_public_keys {
            let pubkey = self.signature_client.parse_public_key(pubkey_str)?;
            group.push(pubkey);
        }

        // Create the group signature proof
        let proof =
            self.proof_client
                .create_group_signature_proof(&args.message, &signature, &group)?;
        println!("Proof created: {}", proof.message());

        let is_valid = proof.verify()?;
        println!(
            "Proof verification: {}",
            if is_valid { "Valid" } else { "Invalid" }
        );

        Ok(())
    }
}
