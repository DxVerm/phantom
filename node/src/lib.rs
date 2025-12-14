//! PHANTOM Node Implementation
//!
//! Full node with block production, storage, and consensus integration.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                         PHANTOM Node                                 │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
//! │  │   Genesis    │  │   Storage    │  │     RPC      │              │
//! │  │   Config     │──│   Layer      │──│    Server    │              │
//! │  └──────────────┘  └──────────────┘  └──────────────┘              │
//! │         │                 │                 │                       │
//! │         └─────────────────┼─────────────────┘                       │
//! │                           │                                         │
//! │  ┌────────────────────────▼────────────────────────┐               │
//! │  │              Block Producer                      │               │
//! │  │  ┌─────────┐  ┌─────────┐  ┌─────────┐         │               │
//! │  │  │ Mempool │──│Consensus│──│   ESL   │         │               │
//! │  │  └─────────┘  └─────────┘  └─────────┘         │               │
//! │  └──────────────────────────────────────────────────┘               │
//! │                           │                                         │
//! │  ┌────────────────────────▼────────────────────────┐               │
//! │  │                   P2P Network                    │               │
//! │  └──────────────────────────────────────────────────┘               │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Block Production Pipeline
//!
//! 1. **Transaction Collection**: Gather encrypted transactions from mempool
//! 2. **Witness Selection**: VRF-based selection for current round
//! 3. **Block Assembly**: Create block with Merkle root and attestations
//! 4. **Consensus**: CWA protocol for block finalization
//! 5. **State Update**: Apply block to ESL state
//! 6. **Persistence**: Store block and state snapshot

mod block;
mod error;
mod producer;
mod state_manager;
mod sync;
mod transaction;
mod validator;
mod metrics;
mod chain;
mod verifier;

pub use block::{Block, BlockHeader, BlockBody, Attestation, KeyShare};
pub use error::{NodeError, NodeResult};
pub use producer::{BlockProducer, ProducerConfig, BlockAssembler};
pub use state_manager::{StateManager, BlockValidator, EpochManager};
pub use sync::{BlockSyncManager, SyncConfig, SyncStatus, SyncPeer};
pub use transaction::{TransactionProcessor, TxProcessorConfig, TxExecution, TxReceipt, TxLog};
pub use validator::{ValidatorManager, ValidatorManagerConfig, ValidatorInfo, ValidatorStatus, SlashingReason};
pub use metrics::{MetricsServer, MetricsConfig, NodeMetrics};
pub use chain::{ChainManager, ChainConfig, ForkChoiceRule, ChainExtensionResult};
pub use verifier::{
    BlockVerifier, VerificationConfig, VerificationResult, VerificationError,
    ValidatorKeyCache, BatchVerifier, VerificationStats,
};

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};

use phantom_cwa::{CWAProtocol, CWAConfig};
use phantom_esl::ESLState;
use phantom_genesis::{GenesisBlock, GenesisConfig};
use phantom_mempool::{EncryptedMempool, MempoolConfig};
use phantom_p2p::{SwarmManager, P2PConfig, NetworkMessage, StateUpdateMessage, StateFragmentType};
use phantom_rpc::{RpcServer, RpcConfig};
use phantom_storage::Storage;

/// Node configuration
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Data directory for storage
    pub data_dir: PathBuf,
    /// Network identifier
    pub network: String,
    /// Chain ID
    pub chain_id: u64,
    /// RPC configuration
    pub rpc: RpcConfig,
    /// Enable block production (validator mode)
    pub validator: bool,
    /// Validator ID if in validator mode
    pub validator_id: Option<[u8; 32]>,
    /// Validator stake
    pub validator_stake: u64,
    /// Block production interval
    pub block_interval: Duration,
    /// Maximum transactions per block
    pub max_txs_per_block: usize,
    /// P2P listen addresses
    pub p2p_listen: Vec<String>,
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./phantom-data"),
            network: "local".to_string(),
            chain_id: 1337,
            rpc: RpcConfig::default(),
            validator: false,
            validator_id: None,
            validator_stake: 0,
            block_interval: Duration::from_secs(2),
            max_txs_per_block: 1000,
            p2p_listen: vec!["/ip4/0.0.0.0/tcp/30303".to_string()],
            bootstrap_nodes: vec![],
        }
    }
}

impl NodeConfig {
    /// Create local development configuration
    pub fn local() -> Self {
        Self::default()
    }

    /// Create testnet configuration
    pub fn testnet() -> Self {
        Self {
            network: "testnet".to_string(),
            chain_id: 2,
            rpc: RpcConfig::testnet(),
            block_interval: Duration::from_secs(3),
            ..Default::default()
        }
    }

    /// Create mainnet configuration
    pub fn mainnet() -> Self {
        Self {
            network: "mainnet".to_string(),
            chain_id: 1,
            rpc: RpcConfig::mainnet(),
            block_interval: Duration::from_secs(5),
            max_txs_per_block: 5000,
            ..Default::default()
        }
    }
}

/// The PHANTOM node
pub struct PhantomNode {
    config: NodeConfig,
    storage: Arc<RwLock<Storage>>,
    genesis: GenesisBlock,
    state: Arc<RwLock<ESLState>>,
    consensus: Arc<RwLock<CWAProtocol>>,
    mempool: Arc<RwLock<EncryptedMempool>>,
    swarm: Arc<RwLock<SwarmManager>>,
    producer: Option<BlockProducer>,
    rpc: Option<RpcServer>,
    running: Arc<RwLock<bool>>,
}

impl PhantomNode {
    /// Create a new node from configuration
    pub async fn new(config: NodeConfig) -> NodeResult<Self> {
        info!("Initializing PHANTOM node for network: {}", config.network);

        // Create data directory if needed
        std::fs::create_dir_all(&config.data_dir)
            .map_err(|e| NodeError::Io(e))?;

        // Load or create genesis
        let genesis_path = config.data_dir.join("genesis.json");
        let genesis = if genesis_path.exists() {
            info!("Loading genesis from {}", genesis_path.display());
            GenesisBlock::load_json(&genesis_path)?
        } else {
            info!("Creating new genesis for {}", config.network);
            let genesis = match config.network.as_str() {
                "mainnet" => GenesisBlock::mainnet(),
                "testnet" => GenesisBlock::testnet(),
                _ => GenesisBlock::local(),
            };
            genesis.save_json(&genesis_path)?;
            genesis
        };

        // Initialize storage
        let storage_path = config.data_dir.join("storage");
        let storage = Storage::open(&storage_path)?;

        // Initialize chain metadata if not present
        if storage.chain.get_meta()?.is_none() {
            use phantom_storage::ChainMeta;
            let meta = ChainMeta {
                genesis_hash: genesis.hash,
                network_id: genesis.config.network.network_id.clone(),
                chain_id: genesis.config.network.chain_id,
                genesis_timestamp: genesis.config.timestamp,
                current_epoch: 0,
                current_round: 0,
                current_height: 0,
                finalized_height: 0,
                finalized_hash: genesis.hash,
            };
            storage.chain.save_meta(&meta)?;
        }

        // Initialize ESL state
        let tree_depth = genesis.config.esl.tree_depth as usize;
        let state = ESLState::new(tree_depth);

        // Apply genesis allocations
        for alloc in &genesis.config.allocations {
            debug!("Applying genesis allocation: {} = {}", alloc.address, alloc.balance);
            // In production, we'd properly initialize account commitments
        }

        // Initialize CWA consensus
        let cwa_config = CWAConfig {
            witness_count: genesis.config.consensus.witness_count as usize,
            threshold: genesis.config.consensus.threshold as usize,
            timeout_ms: genesis.config.consensus.round_timeout_ms,
            min_stake: genesis.config.consensus.min_stake,
            committee_period: genesis.config.consensus.epoch_length,
            max_pending: 1000,
        };
        let consensus = CWAProtocol::new(cwa_config);

        // Initialize mempool
        let mempool = EncryptedMempool::new(MempoolConfig::default())?;

        // Initialize P2P swarm
        let mut p2p_config = P2PConfig::default();
        p2p_config.node_name = format!("phantom-{}", config.chain_id);
        let swarm = SwarmManager::new(p2p_config);

        let storage = Arc::new(RwLock::new(storage));
        let state = Arc::new(RwLock::new(state));
        let consensus = Arc::new(RwLock::new(consensus));
        let mempool = Arc::new(RwLock::new(mempool));
        let swarm = Arc::new(RwLock::new(swarm));
        let running = Arc::new(RwLock::new(false));

        // Create block producer if validator
        let producer = if config.validator {
            Some(BlockProducer::new(ProducerConfig {
                validator_id: config.validator_id.unwrap_or([0u8; 32]),
                block_interval: config.block_interval,
                max_txs_per_block: config.max_txs_per_block,
            }))
        } else {
            None
        };

        Ok(Self {
            config,
            storage,
            genesis,
            state,
            consensus,
            mempool,
            swarm,
            producer,
            rpc: None,
            running,
        })
    }

    /// Initialize node from genesis configuration
    pub async fn from_genesis(genesis_config: GenesisConfig, config: NodeConfig) -> NodeResult<Self> {
        let genesis = GenesisBlock::from_config(genesis_config);
        Self::with_genesis(genesis, config).await
    }

    /// Create node with specific genesis
    pub async fn with_genesis(genesis: GenesisBlock, config: NodeConfig) -> NodeResult<Self> {
        // Save genesis and create node
        let genesis_path = config.data_dir.join("genesis.json");
        std::fs::create_dir_all(&config.data_dir).map_err(|e| NodeError::Io(e))?;
        genesis.save_json(&genesis_path)?;
        Self::new(config).await
    }

    /// Start the node
    pub async fn start(&mut self) -> NodeResult<()> {
        info!("Starting PHANTOM node");

        // Set running flag
        *self.running.write().await = true;

        // Start P2P networking
        {
            let mut swarm = self.swarm.write().await;
            if let Err(e) = swarm.start().await {
                warn!("Failed to start P2P swarm: {}", e);
            }
        }

        // Connect to bootstrap nodes
        for bootstrap in &self.config.bootstrap_nodes {
            if let Ok(addr) = bootstrap.parse() {
                let mut swarm = self.swarm.write().await;
                if let Err(e) = swarm.connect(addr).await {
                    warn!("Failed to connect to bootstrap {}: {}", bootstrap, e);
                }
            }
        }

        // Start RPC server
        let rpc_context = phantom_rpc::server::NodeContext {
            swarm: self.swarm.clone(),
            consensus: self.consensus.clone(),
            state: self.state.clone(),
            mempool: self.mempool.clone(),
            running: self.running.clone(),
            validator_id: self.config.validator_id,
            validator_stake: self.config.validator_stake,
            balance: Arc::new(RwLock::new(0)),
            network: self.config.network.clone(),
            peer_id: "".to_string(), // Would get from swarm
        };

        let mut rpc_server = RpcServer::new(self.config.rpc.clone(), rpc_context);
        rpc_server.start().await?;
        self.rpc = Some(rpc_server);

        info!("Node started successfully");
        Ok(())
    }

    /// Run the main node loop
    pub async fn run(&mut self) -> NodeResult<()> {
        info!("Entering main node loop");

        while *self.running.read().await {
            // Check for new blocks from network
            self.process_network().await?;

            // Produce block if we're a validator
            if let Some(producer) = &mut self.producer {
                if self.should_produce_block().await {
                    match self.produce_block().await {
                        Ok(block) => {
                            info!("Produced block at height {}", block.header.height);
                            self.broadcast_block(&block).await?;
                        }
                        Err(e) => {
                            warn!("Block production failed: {}", e);
                        }
                    }
                }
            }

            // Process consensus messages
            self.process_consensus().await?;

            // Short sleep to prevent busy loop
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        info!("Node loop exiting");
        Ok(())
    }

    /// Stop the node
    pub async fn stop(&mut self) -> NodeResult<()> {
        info!("Stopping PHANTOM node");
        *self.running.write().await = false;

        // Stop RPC server
        if let Some(rpc) = &mut self.rpc {
            rpc.stop().await?;
        }

        // Close storage
        // (Storage will be closed when dropped)

        info!("Node stopped");
        Ok(())
    }

    /// Check if we should produce a block
    async fn should_produce_block(&self) -> bool {
        // Check if we're a validator and it's time to produce
        if self.config.validator_id.is_none() {
            return false;
        }

        // Check if producer says it's time
        if let Some(producer) = &self.producer {
            producer.should_produce()
        } else {
            false
        }
    }

    /// Produce a new block
    async fn produce_block(&mut self) -> NodeResult<Block> {
        let producer = self.producer.as_mut()
            .ok_or_else(|| NodeError::NotValidator)?;

        // Get transactions from mempool
        let mempool = self.mempool.read().await;
        let pending_txs = mempool.get_pending(self.config.max_txs_per_block).await;
        drop(mempool);

        // Serialize transactions for block production
        let txs: Vec<Vec<u8>> = pending_txs
            .iter()
            .filter_map(|tx| serde_json::to_vec(tx).ok())
            .collect();

        // Get current state
        let state = self.state.read().await;
        let state_root = *state.commitment_root();
        let epoch = state.epoch();
        drop(state);

        // Get previous block info
        let storage = self.storage.read().await;
        let height = storage.chain.get_meta()?
            .map(|m| m.current_height + 1)
            .unwrap_or(1);
        let prev_hash = storage.chain.get_meta()?
            .map(|m| m.finalized_hash)
            .unwrap_or(self.genesis.hash);
        drop(storage);

        // Produce the block
        let block = producer.produce(
            height,
            prev_hash,
            state_root,
            epoch,
            txs,
        )?;

        // Store the block - use From<Block> trait for conversion
        let stored_block: phantom_storage::StoredBlock = block.clone().into();
        let mut storage = self.storage.write().await;
        storage.blocks.put(&stored_block)?;

        Ok(block)
    }

    /// Broadcast block to network
    async fn broadcast_block(&self, block: &Block) -> NodeResult<()> {
        let block_data = serde_json::to_vec(block)?;
        // Create proper StateUpdateMessage for block propagation
        let state_update = StateUpdateMessage {
            fragment_id: block.hash(),
            fragment_type: StateFragmentType::StateRoot,
            encrypted_data: block_data,
            version: block.header.height,
            merkle_proof: None,
            attestations: vec![],
        };
        let message = NetworkMessage::StateUpdate(state_update);
        self.swarm.read().await.publish("phantom/blocks", message).await?;
        Ok(())
    }

    /// Process incoming network messages
    async fn process_network(&self) -> NodeResult<()> {
        // In production, this would process incoming blocks and transactions
        Ok(())
    }

    /// Process consensus messages
    async fn process_consensus(&self) -> NodeResult<()> {
        // Check for expired pending updates and handle consensus state
        let consensus = self.consensus.read().await;
        let _pending_count = consensus.pending_count();
        let _round = consensus.round();
        // In production, this would process attestations and advance rounds
        Ok(())
    }

    /// Get current chain height
    pub async fn height(&self) -> u64 {
        self.storage.read().await.chain.get_meta()
            .ok()
            .flatten()
            .map(|m| m.current_height)
            .unwrap_or(0)
    }

    /// Get genesis hash
    pub fn genesis_hash(&self) -> [u8; 32] {
        self.genesis.hash
    }

    /// Get network name
    pub fn network(&self) -> &str {
        &self.config.network
    }

    /// Check if node is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Get storage reference
    pub fn storage(&self) -> Arc<RwLock<Storage>> {
        self.storage.clone()
    }

    /// Get state reference
    pub fn state(&self) -> Arc<RwLock<ESLState>> {
        self.state.clone()
    }

    /// Get consensus reference
    pub fn consensus(&self) -> Arc<RwLock<CWAProtocol>> {
        self.consensus.clone()
    }

    /// Get mempool reference
    pub fn mempool(&self) -> Arc<RwLock<EncryptedMempool>> {
        self.mempool.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_node_creation() {
        let dir = tempdir().unwrap();
        let config = NodeConfig {
            data_dir: dir.path().to_path_buf(),
            ..NodeConfig::local()
        };

        let node = PhantomNode::new(config).await.unwrap();
        assert_eq!(node.network(), "local");
        assert_eq!(node.height().await, 0);
    }

    #[tokio::test]
    async fn test_node_genesis_persistence() {
        let dir = tempdir().unwrap();
        let config = NodeConfig {
            data_dir: dir.path().to_path_buf(),
            ..NodeConfig::local()
        };

        // Create first node
        let node1 = PhantomNode::new(config.clone()).await.unwrap();
        let genesis_hash = node1.genesis_hash();
        drop(node1);

        // Create second node - should load same genesis
        let node2 = PhantomNode::new(config).await.unwrap();
        assert_eq!(node2.genesis_hash(), genesis_hash);
    }

    #[test]
    fn test_node_config_presets() {
        let local = NodeConfig::local();
        assert_eq!(local.chain_id, 1337);

        let testnet = NodeConfig::testnet();
        assert_eq!(testnet.chain_id, 2);

        let mainnet = NodeConfig::mainnet();
        assert_eq!(mainnet.chain_id, 1);
    }
}
