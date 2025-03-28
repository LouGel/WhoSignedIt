use std::fs::File;
use std::io::Write;

use clap::Args;

use crate::error::AppError;
use crate::services::proof::ProofClientFactory;
use crate::services::signature::SignatureClientFactory;

use super::client::FormatInput;
#[derive(Args, Debug, Clone)]
pub struct GenerateArgs {
    #[clap(short, long, default_value = "ethereum")]
    pub blockchain: String,
    /// Proof type (ring or stark)
    #[clap(short, long, default_value = "ring")]
    pub proof_type: String,

    #[clap(short, long, default_value = "json")]
    pub format: FormatInput,

    /// Output file path (optional)
    #[clap(short, long)]
    pub output: Option<String>,
    /// Message to sign or verify
    #[clap(short, long)]
    pub message: String,

    /// Input file path (optional)
    #[clap(short, long)]
    pub input: Option<String>,

    /// Existing signature (optional)
    #[clap(short, long)]
    pub signature: Option<String>,

    /// Private key for signing (optional)
    #[clap(alias = "pk", long)]
    pub private_key: Option<String>,

    /// Group public keys (comma-separated)
    #[clap(short, long, num_args = 1..)]
    pub group_public_keys: Vec<String>,
}

pub fn generate_proof(args: GenerateArgs) -> Result<(), AppError> {
    let signature_client = SignatureClientFactory::create_client(&args.blockchain)?;

    // Parse or create a signature
    let signature = if let Some(sig_str) = &args.signature {
        // Parse an existing signature
        signature_client.from_str(sig_str)?
    } else if let Some(private_key) = &args.private_key {
        // Create a new signature
        signature_client.sign_message(&args.message, private_key)?
    } else {
        return Err(AppError::Custom(format!(
            "Either signature or private key must be provided"
        )));
    };

    // Parse the group public keys
    let mut group = Vec::new();
    for pubkey_str in &args.group_public_keys {
        let pubkey = signature_client.parse_public_key(pubkey_str)?;
        group.push(pubkey);
    }
    let proof_client = ProofClientFactory::create_client(&args.proof_type, signature_client)?;
    // Create the group signature proof
    let proof = proof_client.create_group_signature_proof(&args.message, &signature, &group)?;
    let proof_json = proof.format(&args.format);
    if let Some(output) = args.output.as_ref() {
        let mut handle = File::create(output).expect("Cannot create of open output file");
        handle.write(proof_json.as_bytes()).unwrap();
    } else {
        println!("{proof_json}")
    }

    Ok(())
}
