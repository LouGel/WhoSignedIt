use crate::client::client::{AppArgs, AppClient};
use clap::Parser;
use eyre::Result;

mod client;
mod error;
mod services;

fn main() -> Result<()> {
    let args = AppArgs::parse();
    let client = AppClient::new(&args)?;
    client.run()?;
    Ok(())
}
