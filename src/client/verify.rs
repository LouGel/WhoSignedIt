use clap::Args;

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
