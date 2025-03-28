use std::path::Path;

use clap::Args;

use crate::{
    error::AppError,
    services::{
        proof::{error::ProofErrorKind, ProofClientFactory},
        signature::SignatureClientFactory,
    },
};

use super::client::FormatInput;
#[derive(Args, Debug, Clone)]
pub struct VerifyArgs {
    /// Signature to verify
    #[clap(short, long)]
    pub proof: String,

    #[clap(short, long, default_value = "ethereum")]
    pub blockchain: String,

    #[clap(short, long, default_value = "json")]
    pub format: FormatInput,
}

pub fn verify_proof(args: VerifyArgs) -> Result<(), AppError> {
    let proof_str = if Path::new(args.proof.as_str()).exists() {
        std::fs::read_to_string(args.proof.as_str()).unwrap()
    } else {
        args.proof.clone()
    };
    let signature_client = SignatureClientFactory::create_client(&args.blockchain)?;
    let proof_client = ProofClientFactory::create_client(&args.proof, signature_client)?;

    let proof = proof_client.from_str(&proof_str, args.format)?;
    println!("Proof valid");
    if proof.verify()? {
        println!("Valid proof");
        Ok(())
    } else {
        Err(AppError::ProofError(ProofErrorKind::Invalid))
    }
}
