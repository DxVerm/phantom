//! Status Command - Show node status

use std::path::PathBuf;

use clap::Args;

use crate::config::{PhantomConfig, default_data_dir, default_config_path};

/// Show node status
#[derive(Args)]
pub struct StatusCommand {
    /// RPC endpoint to query
    #[arg(short, long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl StatusCommand {
    pub async fn execute(
        self,
        _config_path: Option<PathBuf>,
        data_dir: Option<PathBuf>,
    ) -> anyhow::Result<()> {
        // Try to load config to get network info
        let network = if let Some(ref dir) = data_dir {
            let config_path = default_config_path(dir);
            if config_path.exists() {
                let config = PhantomConfig::load(&config_path)?;
                config.node.network
            } else {
                "unknown".to_string()
            }
        } else {
            "unknown".to_string()
        };

        println!("Querying node at {}...", self.rpc);
        println!();

        // Make RPC call to get node info
        match query_node_info(&self.rpc).await {
            Ok(info) => {
                println!("✅ Node is running");
                println!();
                println!("Version:      {}", info.version);
                println!("Network:      {}", info.network);
                println!("Peer ID:      {}", info.peer_id);
                println!("Epoch:        {}", info.epoch);
                println!("Round:        {}", info.round);
                println!("Peers:        {}", info.peer_count);
                println!("Mempool:      {} transactions", info.mempool_size);
                println!("State Root:   {}", info.state_root);
                if info.is_validator {
                    println!("Validator:    Yes (stake: {})", info.validator_stake.unwrap_or(0));
                }
            }
            Err(e) => {
                println!("❌ Could not connect to node");
                println!();
                println!("Error: {}", e);
                println!();
                println!("Is the node running? Start it with:");
                if network != "unknown" {
                    let data_dir = data_dir.unwrap_or_else(|| default_data_dir(&network));
                    println!("  phantom node --data-dir {}", data_dir.display());
                } else {
                    println!("  phantom node");
                }
            }
        }

        Ok(())
    }
}

/// Node info from RPC
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeInfo {
    version: String,
    network: String,
    peer_id: String,
    is_running: bool,
    is_validator: bool,
    validator_stake: Option<u64>,
    epoch: u64,
    round: u64,
    state_root: String,
    peer_count: usize,
    mempool_size: usize,
}

/// Query node info via JSON-RPC
async fn query_node_info(rpc_url: &str) -> anyhow::Result<NodeInfo> {
    let client = reqwest::Client::new();

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "phantom_nodeInfo",
        "params": [],
        "id": 1
    });

    let response = client
        .post(rpc_url)
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("HTTP error: {}", response.status());
    }

    let result: serde_json::Value = response.json().await?;

    if let Some(error) = result.get("error") {
        anyhow::bail!("RPC error: {}", error);
    }

    let info: NodeInfo = serde_json::from_value(
        result.get("result")
            .ok_or_else(|| anyhow::anyhow!("Missing result"))?
            .clone()
    )?;

    Ok(info)
}
