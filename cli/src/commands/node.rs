//! Node Command - Run the PHANTOM node

use std::path::PathBuf;
use std::sync::Arc;

use clap::Args;
use tokio::sync::RwLock;
use tokio::signal;
use tracing::{info, warn, error};

use phantom_p2p::{SwarmManager, P2PConfig, Multiaddr, PeerId};
use phantom_cwa::{CWAProtocol, CWAConfig};
use phantom_esl::ESLState;
use phantom_mempool::{EncryptedMempool, MempoolConfig};
use phantom_rpc::{RpcServer, RpcConfig};

use crate::config::{PhantomConfig, default_data_dir, default_config_path};

/// Run the PHANTOM node
#[derive(Args)]
pub struct NodeCommand {
    /// Network (local, testnet, mainnet)
    #[arg(short, long)]
    network: Option<String>,

    /// Run as validator
    #[arg(long)]
    validator: bool,

    /// Validator stake amount
    #[arg(long, default_value = "0")]
    stake: u64,

    /// P2P listen address
    #[arg(long)]
    listen: Option<String>,

    /// Bootstrap nodes (comma-separated)
    #[arg(long)]
    bootnodes: Option<String>,

    /// Disable RPC server
    #[arg(long)]
    no_rpc: bool,

    /// RPC HTTP bind address
    #[arg(long)]
    rpc_addr: Option<String>,
}

impl NodeCommand {
    pub async fn execute(
        self,
        config_path: Option<PathBuf>,
        data_dir: Option<PathBuf>,
    ) -> anyhow::Result<()> {
        // Load or create configuration
        let mut config = if let Some(path) = &config_path {
            PhantomConfig::load(path)?
        } else {
            let network = self.network.as_deref().unwrap_or("local");
            let default_dir = data_dir.clone().unwrap_or_else(|| default_data_dir(network));
            let default_path = default_config_path(&default_dir);

            if default_path.exists() {
                PhantomConfig::load(&default_path)?
            } else {
                PhantomConfig::for_network(network)
            }
        };

        // Apply command-line overrides
        if let Some(network) = &self.network {
            config.node.network = network.clone();
        }
        if self.validator {
            config.node.is_validator = true;
            config.node.validator_stake = self.stake;
        }
        if let Some(listen) = &self.listen {
            config.network.listen_addr = listen.clone();
        }
        if let Some(bootnodes) = &self.bootnodes {
            config.network.bootnodes = bootnodes.split(',').map(|s| s.to_string()).collect();
        }
        if self.no_rpc {
            config.rpc.enabled = false;
        }
        if let Some(rpc_addr) = &self.rpc_addr {
            config.rpc.http_addr = rpc_addr.clone();
        }

        info!("Starting PHANTOM node");
        info!("Network: {}", config.node.network);
        info!("Validator: {}", config.node.is_validator);
        if config.node.is_validator {
            info!("Stake: {}", config.node.validator_stake);
        }

        // Create P2P config
        // Parse listen address to Multiaddr
        let listen_addrs: Vec<Multiaddr> = vec![
            config.network.listen_addr.parse()
                .unwrap_or_else(|_| "/ip4/0.0.0.0/tcp/9000".parse().unwrap())
        ];

        // Parse bootstrap peers (format: "peer_id@multiaddr")
        // For now, start with empty bootstrap peers since parsing requires PeerId
        let bootstrap_peers: Vec<(PeerId, Multiaddr)> = Vec::new();

        let p2p_config = P2PConfig {
            listen_addrs,
            bootstrap_peers,
            max_inbound: config.network.max_peers as u32,
            max_outbound: (config.network.max_peers / 2) as u32,
            enable_mdns: config.network.enable_mdns,
            enable_kademlia: config.network.enable_dht,
            ..P2PConfig::default()
        };

        // Create CWA config
        let cwa_config = CWAConfig {
            witness_count: config.consensus.witness_count,
            threshold: config.consensus.threshold,
            min_stake: config.consensus.min_stake,
            timeout_ms: config.consensus.timeout_ms,
            ..CWAConfig::default()
        };

        // Create components
        let swarm = Arc::new(RwLock::new(SwarmManager::new(p2p_config)));
        let consensus = Arc::new(RwLock::new(CWAProtocol::new(cwa_config)));
        let state = Arc::new(RwLock::new(ESLState::new(config.node.esl_tree_depth)));
        let mempool = Arc::new(RwLock::new(
            EncryptedMempool::new(MempoolConfig::default())?
        ));
        let running = Arc::new(RwLock::new(true));

        // Register as validator if configured
        let validator_id = if config.node.is_validator {
            let id = register_validator(&consensus, config.node.validator_stake).await?;
            info!("Registered as validator: 0x{}", hex::encode(&id));
            Some(id)
        } else {
            None
        };

        // Start P2P network
        info!("Starting P2P network on {}", config.network.listen_addr);
        swarm.write().await.start().await?;

        let peer_id = swarm.read().await.local_peer_id().to_string();
        info!("Local peer ID: {}", peer_id);

        // Start RPC server if enabled
        let mut rpc_server = if config.rpc.enabled {
            let rpc_config = RpcConfig {
                http_addr: config.rpc.http_addr.parse()?,
                ws_addr: config.rpc.ws_addr.as_ref().map(|s| s.parse()).transpose()?,
                cors_enabled: config.rpc.cors_enabled,
                cors_origins: config.rpc.cors_origins.clone(),
                require_admin_auth: config.rpc.require_admin_auth,
                admin_api_key: config.rpc.admin_api_key.clone(),
                network: config.node.network.clone(),
                ..RpcConfig::default()
            };

            let context = phantom_rpc::server::NodeContext {
                swarm: swarm.clone(),
                consensus: consensus.clone(),
                state: state.clone(),
                mempool: mempool.clone(),
                running: running.clone(),
                validator_id,
                validator_stake: config.node.validator_stake,
                balance: Arc::new(RwLock::new(0)),
                network: config.node.network.clone(),
                peer_id: peer_id.clone(),
            };

            let mut server = RpcServer::new(rpc_config, context);
            server.start().await?;
            info!("RPC server started on {}", config.rpc.http_addr);
            Some(server)
        } else {
            None
        };

        println!();
        println!("🚀 PHANTOM node is running!");
        println!();
        println!("Network: {}", config.node.network);
        println!("Peer ID: {}", peer_id);
        if config.rpc.enabled {
            println!("RPC: http://{}", config.rpc.http_addr);
        }
        if config.node.is_validator {
            println!("Validator: 0x{}", hex::encode(validator_id.unwrap_or([0; 32])));
        }
        println!();
        println!("Press Ctrl+C to stop");

        // Wait for shutdown signal
        wait_for_shutdown().await;

        info!("Shutting down...");

        // Stop components
        *running.write().await = false;

        if let Some(ref mut server) = rpc_server {
            server.stop().await?;
        }

        swarm.write().await.stop().await?;

        info!("Node stopped");
        Ok(())
    }
}

/// Register as a validator
async fn register_validator(
    consensus: &Arc<RwLock<CWAProtocol>>,
    stake: u64,
) -> anyhow::Result<[u8; 32]> {
    use phantom_cwa::Validator;

    // Generate validator identity
    let mut validator_id = [0u8; 32];
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    validator_id[..16].copy_from_slice(&timestamp.to_le_bytes());

    // Create validator
    let public_key = vec![0u8; 64]; // Would be PQ key in production
    let vrf_key = [0u8; 32];        // Would be VRF key in production

    let validator = Validator::new(validator_id, public_key, vrf_key, stake);

    consensus.write().await.register_validator(validator)?;

    Ok(validator_id)
}

/// Wait for shutdown signal (Ctrl+C)
async fn wait_for_shutdown() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
