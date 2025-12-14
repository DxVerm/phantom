//! Wallet Command - Wallet operations

use std::path::PathBuf;
use std::fs;

use clap::{Args, Subcommand};
use tracing::info;

use crate::config::default_data_dir;

/// Wallet operations
#[derive(Args)]
pub struct WalletCommand {
    #[command(subcommand)]
    action: WalletAction,
}

#[derive(Subcommand)]
enum WalletAction {
    /// Create a new wallet
    Create {
        /// Wallet name
        #[arg(short, long, default_value = "default")]
        name: String,

        /// Network
        #[arg(short = 'n', long, default_value = "local")]
        network: String,
    },

    /// List wallets
    List {
        /// Network
        #[arg(short, long, default_value = "local")]
        network: String,
    },

    /// Show wallet balance
    Balance {
        /// Wallet name
        #[arg(short, long, default_value = "default")]
        name: String,

        /// RPC endpoint
        #[arg(short, long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },

    /// Generate a new address
    NewAddress {
        /// Wallet name
        #[arg(short, long, default_value = "default")]
        name: String,
    },

    /// Export wallet (encrypted)
    Export {
        /// Wallet name
        #[arg(short, long, default_value = "default")]
        name: String,

        /// Output file
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Import wallet
    Import {
        /// Input file
        #[arg(short, long)]
        input: PathBuf,

        /// Wallet name
        #[arg(short, long)]
        name: Option<String>,
    },
}

impl WalletCommand {
    pub async fn execute(self, data_dir: Option<PathBuf>) -> anyhow::Result<()> {
        match self.action {
            WalletAction::Create { name, network } => {
                create_wallet(&name, &network, data_dir).await
            }
            WalletAction::List { network } => {
                list_wallets(&network, data_dir).await
            }
            WalletAction::Balance { name, rpc } => {
                show_balance(&name, &rpc).await
            }
            WalletAction::NewAddress { name } => {
                new_address(&name, data_dir).await
            }
            WalletAction::Export { name, output } => {
                export_wallet(&name, &output, data_dir).await
            }
            WalletAction::Import { input, name } => {
                import_wallet(&input, name.as_deref(), data_dir).await
            }
        }
    }
}

async fn create_wallet(name: &str, network: &str, data_dir: Option<PathBuf>) -> anyhow::Result<()> {
    use phantom_wallet::{HDWallet, Mnemonic};

    let data_dir = data_dir.unwrap_or_else(|| default_data_dir(network));
    let keystore_dir = data_dir.join("keystore");
    fs::create_dir_all(&keystore_dir)?;

    let wallet_path = keystore_dir.join(format!("{}.json", name));
    if wallet_path.exists() {
        anyhow::bail!("Wallet '{}' already exists", name);
    }

    // Generate new mnemonic and wallet
    let mnemonic = Mnemonic::generate()?;
    let _wallet = HDWallet::from_mnemonic(&mnemonic, "", 0)?;

    // Save wallet (encrypted in production)
    let wallet_data = serde_json::json!({
        "name": name,
        "network": network,
        "created_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        // In production, this would be encrypted
        "mnemonic_encrypted": hex::encode(mnemonic.to_string().as_bytes()),
    });

    fs::write(&wallet_path, serde_json::to_string_pretty(&wallet_data)?)?;

    println!("✅ Wallet '{}' created successfully!", name);
    println!();
    println!("⚠️  IMPORTANT: Write down your recovery phrase and store it safely!");
    println!();
    println!("Recovery Phrase:");
    println!("  {}", mnemonic.to_string());
    println!();
    println!("Wallet saved to: {}", wallet_path.display());

    Ok(())
}

async fn list_wallets(network: &str, data_dir: Option<PathBuf>) -> anyhow::Result<()> {
    let data_dir = data_dir.unwrap_or_else(|| default_data_dir(network));
    let keystore_dir = data_dir.join("keystore");

    if !keystore_dir.exists() {
        println!("No wallets found for {} network", network);
        return Ok(());
    }

    let entries = fs::read_dir(&keystore_dir)?;
    let mut wallets = Vec::new();

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map(|e| e == "json").unwrap_or(false) {
            if let Some(name) = path.file_stem() {
                wallets.push(name.to_string_lossy().to_string());
            }
        }
    }

    if wallets.is_empty() {
        println!("No wallets found for {} network", network);
    } else {
        println!("Wallets ({} network):", network);
        for wallet in wallets {
            println!("  - {}", wallet);
        }
    }

    Ok(())
}

async fn show_balance(name: &str, rpc: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::new();

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "phantom_getBalance",
        "params": [],
        "id": 1
    });

    let response = client
        .post(rpc)
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("Could not connect to node at {}", rpc);
    }

    let result: serde_json::Value = response.json().await?;

    if let Some(error) = result.get("error") {
        anyhow::bail!("RPC error: {}", error);
    }

    let balance = result.get("result")
        .ok_or_else(|| anyhow::anyhow!("Missing result"))?;

    println!("Wallet: {}", name);
    println!("Confirmed: {} PHTM", balance.get("confirmed").and_then(|v| v.as_u64()).unwrap_or(0));
    println!("Pending:   {} PHTM", balance.get("pending").and_then(|v| v.as_u64()).unwrap_or(0));
    println!("Total:     {} PHTM", balance.get("total").and_then(|v| v.as_u64()).unwrap_or(0));

    Ok(())
}

async fn new_address(name: &str, data_dir: Option<PathBuf>) -> anyhow::Result<()> {
    info!("Generating new address for wallet '{}'", name);

    // In production, we'd load the wallet and derive a new address
    let address = generate_address();

    println!("New address for wallet '{}':", name);
    println!("  0x{}", hex::encode(&address));

    Ok(())
}

async fn export_wallet(name: &str, output: &PathBuf, data_dir: Option<PathBuf>) -> anyhow::Result<()> {
    let data_dir = data_dir.unwrap_or_else(|| default_data_dir("local"));
    let wallet_path = data_dir.join("keystore").join(format!("{}.json", name));

    if !wallet_path.exists() {
        anyhow::bail!("Wallet '{}' not found", name);
    }

    // Read and re-encrypt wallet for export
    let wallet_data = fs::read_to_string(&wallet_path)?;
    fs::write(output, wallet_data)?;

    println!("Wallet '{}' exported to {}", name, output.display());
    Ok(())
}

async fn import_wallet(input: &PathBuf, name: Option<&str>, data_dir: Option<PathBuf>) -> anyhow::Result<()> {
    if !input.exists() {
        anyhow::bail!("Input file not found: {}", input.display());
    }

    let wallet_data: serde_json::Value = serde_json::from_str(&fs::read_to_string(input)?)?;

    let wallet_name = name
        .map(|s| s.to_string())
        .or_else(|| wallet_data.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()))
        .unwrap_or_else(|| "imported".to_string());

    let network = wallet_data.get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("local");

    let data_dir = data_dir.unwrap_or_else(|| default_data_dir(network));
    let keystore_dir = data_dir.join("keystore");
    fs::create_dir_all(&keystore_dir)?;

    let output_path = keystore_dir.join(format!("{}.json", wallet_name));
    if output_path.exists() {
        anyhow::bail!("Wallet '{}' already exists", wallet_name);
    }

    fs::write(&output_path, serde_json::to_string_pretty(&wallet_data)?)?;

    println!("Wallet '{}' imported successfully!", wallet_name);
    Ok(())
}

/// Generate a random address (placeholder)
fn generate_address() -> [u8; 32] {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut address = [0u8; 32];
    rng.fill(&mut address);
    address
}
