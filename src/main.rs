use crate::client::client::{AppArgs, AppClient};
use clap::Parser;
use error::AppError;

mod client;
mod error;
mod services;

fn main() -> Result<(), AppError> {
    let args = AppArgs::parse();
    AppClient::run(&args)?;
    Ok(())
}
