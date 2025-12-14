//! PHANTOM Node CLI
//!
//! Command-line interface for running PHANTOM network nodes.
//!
//! # Usage
//!
//! ```bash
//! # Start a local development node
//! phantom node --network local
//!
//! # Start a testnet node
//! phantom node --network testnet --data-dir ~/.phantom-testnet
//!
//! # Start a validator node
//! phantom node --validator --stake 10000
//!
//! # Initialize a new node
//! phantom init --network testnet
//!
//! # Show node status
//! phantom status
//! ```

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod commands;
mod config;
mod logging;

use commands::{InitCommand, NodeCommand, StatusCommand, WalletCommand};

/// PHANTOM Network Node
#[derive(Parser)]
#[command(name = "phantom")]
#[command(author = "PHANTOM Team")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Privacy-First Cryptographic Network Node", long_about = None)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Data directory
    #[arg(short, long, global = true, env = "PHANTOM_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, global = true, default_value = "info")]
    log_level: String,

    /// Output logs as JSON
    #[arg(long, global = true)]
    json_logs: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new node
    Init(InitCommand),

    /// Run the node
    Node(NodeCommand),

    /// Show node status
    Status(StatusCommand),

    /// Wallet operations
    Wallet(WalletCommand),

    /// Show version information
    Version,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    logging::init(&cli.log_level, cli.json_logs)?;

    // Execute command
    match cli.command {
        Commands::Init(cmd) => cmd.execute(cli.data_dir).await,
        Commands::Node(cmd) => cmd.execute(cli.config, cli.data_dir).await,
        Commands::Status(cmd) => cmd.execute(cli.config, cli.data_dir).await,
        Commands::Wallet(cmd) => cmd.execute(cli.data_dir).await,
        Commands::Version => {
            println!("phantom {}", env!("CARGO_PKG_VERSION"));
            println!("Protocol: PHANTOM v1.0");
            println!("Network: Privacy-First Cryptographic Network");
            Ok(())
        }
    }
}
