//! Init Command - Initialize a new node

use std::path::PathBuf;
use std::fs;

use clap::Args;
use tracing::info;

use crate::config::{PhantomConfig, default_data_dir, default_config_path};

/// Initialize a new node
#[derive(Args)]
pub struct InitCommand {
    /// Network to initialize for (local, testnet, mainnet)
    #[arg(short, long, default_value = "local")]
    network: String,

    /// Force overwrite existing configuration
    #[arg(short, long)]
    force: bool,
}

impl InitCommand {
    pub async fn execute(self, data_dir: Option<PathBuf>) -> anyhow::Result<()> {
        let data_dir = data_dir.unwrap_or_else(|| default_data_dir(&self.network));
        let config_path = default_config_path(&data_dir);

        info!("Initializing PHANTOM node for {} network", self.network);
        info!("Data directory: {}", data_dir.display());

        // Check if already initialized
        if config_path.exists() && !self.force {
            anyhow::bail!(
                "Node already initialized at {}. Use --force to overwrite.",
                data_dir.display()
            );
        }

        // Create data directory structure
        fs::create_dir_all(&data_dir)?;
        fs::create_dir_all(data_dir.join("state"))?;
        fs::create_dir_all(data_dir.join("keystore"))?;
        fs::create_dir_all(data_dir.join("logs"))?;

        // Create configuration
        let config = PhantomConfig::for_network(&self.network);
        config.save(&config_path)?;

        info!("Configuration saved to {}", config_path.display());

        // Create genesis file for local network
        if self.network == "local" {
            let genesis_path = data_dir.join("genesis.json");
            let genesis = create_local_genesis();
            fs::write(&genesis_path, serde_json::to_string_pretty(&genesis)?)?;
            info!("Genesis file created at {}", genesis_path.display());
        }

        println!();
        println!("✅ PHANTOM node initialized successfully!");
        println!();
        println!("Configuration: {}", config_path.display());
        println!("Data directory: {}", data_dir.display());
        println!();
        println!("To start the node:");
        println!("  phantom node --data-dir {}", data_dir.display());
        println!();
        if self.network == "local" {
            println!("For a validator node:");
            println!("  phantom node --validator --stake 10000 --data-dir {}", data_dir.display());
        }

        Ok(())
    }
}

/// Create genesis configuration for local network
fn create_local_genesis() -> serde_json::Value {
    serde_json::json!({
        "network": "local",
        "chain_id": 1337,
        "timestamp": chrono_timestamp(),
        "initial_validators": [],
        "initial_balances": {
            "0x0000000000000000000000000000000000000001": 1_000_000_000_000u64
        },
        "consensus": {
            "witness_count": 5,
            "threshold": 3,
            "min_stake": 100
        },
        "esl": {
            "tree_depth": 16,
            "initial_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
        }
    })
}

fn chrono_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
