use super::generate::GenerateArgs;
use crate::services::{
    proof::{traits::FormatInput, ProofClient, ProofClientFactory},
    signature::{SignatureClient, SignatureClientFactory},
};
use clap::{Args, Parser, Subcommand};
use eyre::Result;
use std::{fs::File, io::Write, path::Path};

/// Main client for the application
pub struct AppClient {
    signature_client: Box<dyn SignatureClient>,
    proof_client: Box<dyn ProofClient>,
    command: Command,
    output: Option<String>,
    format: FormatInput,
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
    pub proof: String,

    #[clap(short, long, default_value = "json")]
    pub format: FormatInput,

    /// Output file path (optional)
    #[clap(short, long)]
    pub output: Option<String>,
    #[command(subcommand)]
    pub command: Command, // Fixed typo from "comand" to "command"
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Sign a message with the specified blockchain and proof type
    #[clap(name = "sign")]
    Generate(GenerateArgs),

    /// Verify a signature
    #[clap(name = "verify")]
    Verify(VerifyArgs),
}

#[derive(Args, Debug, Clone)]
pub struct VerifyArgs {
    /// Signature to verify
    #[clap(short, long)]
    pub proof: String,
}

impl AppClient {
    /// Create a new app client
    pub fn new(args: &AppArgs) -> Result<Self> {
        // Create signature client based on blockchain type
        let signature_client = SignatureClientFactory::create_client(&args.blockchain)?;

        // Create proof client based on proof type
        let proof_client =
            ProofClientFactory::create_client(&args.proof, signature_client.clone())?;

        Ok(Self {
            signature_client,
            proof_client,
            command: args.command.clone(),
            output: args.output.clone(),
            format: args.format.clone(),
        })
    }

    /// Run the application
    pub fn run(&self) -> Result<()> {
        match self.command.clone() {
            Command::Generate(sign_args) => {
                // Parse or create a signature
                let signature = if let Some(sig_str) = &sign_args.signature {
                    // Parse an existing signature
                    self.signature_client.from_str(sig_str)?
                } else if let Some(private_key) = &sign_args.private_key {
                    // Create a new signature
                    self.signature_client
                        .sign_message(&sign_args.message, private_key)?
                } else {
                    return Err(eyre::eyre!(
                        "Either signature or private key must be provided"
                    ));
                };

                // Parse the group public keys
                let mut group = Vec::new();
                for pubkey_str in &sign_args.group_public_keys {
                    let pubkey = self.signature_client.parse_public_key(pubkey_str)?;
                    group.push(pubkey);
                }

                // Create the group signature proof
                let proof = self.proof_client.create_group_signature_proof(
                    &sign_args.message,
                    &signature,
                    &group,
                )?;
                let proof_json = proof.format(&self.format);
                if let Some(output) = self.output.as_ref() {
                    let mut handle =
                        File::create(output).expect("Cannot create of open output file");
                    handle.write(proof_json.as_bytes()).unwrap();
                } else {
                    println!("{proof_json}")
                }

                Ok(())
            }
            Command::Verify(verify_args) => {
                let proof_str = if Path::new(verify_args.proof.as_str()).exists() {
                    std::fs::read_to_string(verify_args.proof.as_str()).unwrap()
                } else {
                    verify_args.proof
                };
                let proof = self.proof_client.from_str(&proof_str, self.format)?;
                Ok(())
            }
            _ => todo!("Verify command not implemented"),
        }
    }
}
