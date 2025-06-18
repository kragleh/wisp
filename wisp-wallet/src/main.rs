// wisp-wallet/src/main.rs
mod commands;
mod wallet;

use anyhow::Result;
use clap::Parser;
use log::info;
use std::{path::PathBuf, sync::Arc};

use crate::{commands::run_wallet_ui, wallet::core::Core};

/// A simple CLI wallet for the Wisp blockchain.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to the wallet configuration file.
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize the logger
    env_logger::init();

    info!("Starting Wisp Wallet...");

    let cli = Cli::parse();
    let config_path = cli.config;

    // Load or create the Core instance
    let core = Core::load(config_path.clone()).await?;

    // Run the main wallet UI loop
    run_wallet_ui(Arc::new(core), config_path).await?;

    info!("Wisp Wallet exited cleanly.");
    Ok(())
}
