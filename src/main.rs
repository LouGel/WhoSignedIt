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
