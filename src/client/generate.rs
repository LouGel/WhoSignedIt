use clap::Args;
#[derive(Args, Debug, Clone)]
pub struct GenerateArgs {
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
