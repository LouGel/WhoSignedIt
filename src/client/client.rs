use super::{generate::GenerateArgs, verify::VerifyArgs};
use crate::{
    error::AppError,
    services::{
        proof::{error::ProofErrorKind, ProofClient, ProofClientFactory},
        signature::{SignatureClient, SignatureClientFactory},
    },
};
use clap::{Parser, Subcommand};
use std::{fs::File, io::Write, path::Path};

#[derive(Debug, Clone, Copy)]
pub enum FormatInput {
    Json,
    Toml,
}
impl std::str::FromStr for FormatInput {
    type Err = AppError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "json" => Ok(FormatInput::Json),
            "toml" => Ok(FormatInput::Toml),
            other => Err(AppError::Input(format!("Invalid format {other}"))),
        }
    }
}
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

impl AppClient {
    /// Create a new app client

    /// Run the application
    pub fn run(args: &AppArgs) -> Result<(), AppError> {
        match args.command.clone() {
            Command::Generate(sign_args) => {
                let signature_client =
                    SignatureClientFactory::create_client(&sign_args.blockchain)?;

                // Parse or create a signature
                let signature = if let Some(sig_str) = &sign_args.signature {
                    // Parse an existing signature
                    signature_client.from_str(sig_str)?
                } else if let Some(private_key) = &sign_args.private_key {
                    // Create a new signature
                    signature_client.sign_message(&sign_args.message, private_key)?
                } else {
                    return Err(AppError::Custom(format!(
                        "Either signature or private key must be provided"
                    )));
                };

                // Parse the group public keys
                let mut group = Vec::new();
                for pubkey_str in &sign_args.group_public_keys {
                    let pubkey = signature_client.parse_public_key(pubkey_str)?;
                    group.push(pubkey);
                }
                let proof_client =
                    ProofClientFactory::create_client(&sign_args.proof_type, signature_client)?;
                // Create the group signature proof
                let proof = proof_client.create_group_signature_proof(
                    &sign_args.message,
                    &signature,
                    &group,
                )?;
                let proof_json = proof.format(&sign_args.format);
                if let Some(output) = sign_args.output.as_ref() {
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
                    verify_args.proof.clone()
                };
                let signature_client =
                    SignatureClientFactory::create_client(&verify_args.blockchain)?;
                let proof_client =
                    ProofClientFactory::create_client(&verify_args.proof, signature_client)?;

                let proof = proof_client.from_str(&proof_str, verify_args.format)?;
                println!("Proof valid");
                if proof.verify()? {
                    println!("Valid proof");
                    Ok(())
                } else {
                    Err(AppError::ProofError(ProofErrorKind::Invalid))
                }
            }
            #[allow(unreachable_patterns)]
            _ => todo!("Verify command not implemented"),
        }
    }
}
