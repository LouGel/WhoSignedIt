use super::{
    generate::{generate_proof, GenerateArgs},
    verify::VerifyArgs,
};
use crate::{client::verify::verify_proof, error::AppError};
use clap::{Parser, Subcommand};

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

pub struct AppClient {}
impl AppClient {
    pub fn run(args: &AppArgs) -> Result<(), AppError> {
        match args.command.clone() {
            Command::Generate(sign_args) => generate_proof(sign_args),
            Command::Verify(verify_args) => verify_proof(verify_args),
            #[allow(unreachable_patterns)]
            _ => todo!("Verify command not implemented"),
        }
    }
}
