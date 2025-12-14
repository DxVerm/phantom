//! PHANTOM Full Node Integration
//!
//! Ties together wallet, P2P network, mempool, and CWA consensus into
//! a unified full node that can participate in the PHANTOM network.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                       PhantomNode                            │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐       │
//! │  │   Wallet    │──│   Mempool    │──│  P2P Network │       │
//! │  │  Lifecycle  │  │  (Encrypted) │  │  (libp2p)    │       │
//! │  └──────┬──────┘  └──────┬───────┘  └──────┬───────┘       │
//! │         │                │                 │                │
//! │         └────────────────┼─────────────────┘                │
//! │                          │                                   │
//! │                 ┌────────▼────────┐                         │
//! │                 │  CWA Consensus  │                         │
//! │                 │  (Attestation)  │                         │
//! │                 └────────┬────────┘                         │
//! │                          │                                   │
//! │                 ┌────────▼────────┐                         │
//! │                 │   ESL State     │                         │
//! │                 └─────────────────┘                         │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock, Mutex};
use thiserror::Error;

// Re-exports from component crates
use phantom_wallet::{
    TransactionLifecycle, TransactionStatus, LifecycleConfig,
    TransactionPropagator, StateProvider,
    Transaction, HDWallet, StealthAddress,
};
use phantom_p2p::{
    SwarmManager, SwarmEvent_, P2PConfig, NetworkMessage, TransactionMessage,
    ConsensusMessage, ConsensusMessageType, Attestation as P2PAttestation,
    PeerId, StateSyncManager, SyncConfig,
};
use phantom_cwa::{
    CWAProtocol, CWAConfig, Validator, Attestation as CWAAttestation,
};
use phantom_esl::{
    ESLState, StateFragment, StateUpdate, ESLSnapshot,
    Nullifier, Commitment, EncryptedBalance,
};
use phantom_mempool::{EncryptedMempool, MempoolConfig, EncryptedTxId};

/// Errors during node operation
#[derive(Debug, Error)]
pub enum NodeError {
    #[error("Wallet error: {0}")]
    Wallet(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Consensus error: {0}")]
    Consensus(String),
    #[error("State error: {0}")]
    State(String),
    #[error("Mempool error: {0}")]
    Mempool(String),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Node not started")]
    NotStarted,
    #[error("Node already running")]
    AlreadyRunning,
    #[error("Channel error: {0}")]
    Channel(String),
}

/// Result type for node operations
pub type NodeResult<T> = Result<T, NodeError>;

/// Node configuration
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// P2P network configuration
    pub p2p: P2PConfig,
    /// CWA consensus configuration
    pub cwa: CWAConfig,
    /// Mempool configuration
    pub mempool: MempoolConfig,
    /// Wallet lifecycle configuration
    pub lifecycle: LifecycleConfig,
    /// Sync configuration
    pub sync: SyncConfig,
    /// ESL tree depth
    pub esl_tree_depth: usize,
    /// Is this a validator node?
    pub is_validator: bool,
    /// Validator stake (if validator)
    pub validator_stake: u64,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            p2p: P2PConfig::default(),
            cwa: CWAConfig::default(),
            mempool: MempoolConfig::default(),
            lifecycle: LifecycleConfig::default(),
            sync: SyncConfig::default(),
            esl_tree_depth: 32,
            is_validator: false,
            validator_stake: 0,
        }
    }
}

impl NodeConfig {
    /// Create configuration for a local development node
    pub fn local() -> Self {
        Self {
            p2p: P2PConfig::local(),
            cwa: CWAConfig {
                witness_count: 5,
                threshold: 3,
                timeout_ms: 10000,
                min_stake: 100,
                ..Default::default()
            },
            esl_tree_depth: 16,
            ..Default::default()
        }
    }

    /// Create configuration for a testnet node
    pub fn testnet() -> Self {
        Self {
            p2p: P2PConfig::testnet(),
            cwa: CWAConfig {
                witness_count: 21,
                threshold: 14,
                timeout_ms: 5000,
                min_stake: 10_000,
                ..Default::default()
            },
            esl_tree_depth: 24,
            ..Default::default()
        }
    }

    /// Create configuration for a mainnet node
    pub fn mainnet() -> Self {
        Self {
            p2p: P2PConfig::mainnet(),
            cwa: CWAConfig::default(),
            esl_tree_depth: 32,
            ..Default::default()
        }
    }

    /// Enable validator mode with stake
    pub fn with_validator(mut self, stake: u64) -> Self {
        self.is_validator = true;
        self.validator_stake = stake;
        self
    }
}

/// Internal node events
#[derive(Clone, Debug)]
pub enum NodeEvent {
    /// New transaction received from P2P network
    TransactionReceived { tx_id: [u8; 32], from: PeerId },
    /// Transaction added to mempool
    TransactionInMempool { tx_id: [u8; 32] },
    /// Transaction attestation received
    AttestationReceived { tx_id: [u8; 32], witness: [u8; 32] },
    /// Transaction finalized
    TransactionFinalized { tx_id: [u8; 32], attestation_count: usize },
    /// State updated
    StateUpdated { merkle_root: [u8; 32], epoch: u64 },
    /// Peer connected
    PeerConnected(PeerId),
    /// Peer disconnected
    PeerDisconnected(PeerId),
    /// Sync started
    SyncStarted { peer: PeerId },
    /// Sync completed
    SyncCompleted { fragments_received: usize },
    /// Consensus round advanced
    RoundAdvanced { round: u64 },
    /// Node error
    Error { message: String },
}

/// The PHANTOM full node
pub struct PhantomNode {
    /// Configuration
    config: NodeConfig,
    /// P2P swarm manager
    swarm: Arc<RwLock<SwarmManager>>,
    /// CWA consensus protocol
    consensus: Arc<RwLock<CWAProtocol>>,
    /// ESL state
    state: Arc<RwLock<ESLState>>,
    /// Encrypted mempool
    mempool: Arc<RwLock<EncryptedMempool>>,
    /// State sync manager
    sync_manager: Arc<RwLock<StateSyncManager>>,
    /// Wallet lifecycle (if wallet is attached)
    wallet_lifecycle: Option<Arc<RwLock<TransactionLifecycle>>>,
    /// Our validator identity (if validator)
    validator_id: Option<[u8; 32]>,
    /// Event sender
    event_tx: mpsc::Sender<NodeEvent>,
    /// Event receiver
    event_rx: Arc<Mutex<mpsc::Receiver<NodeEvent>>>,
    /// Running flag
    running: Arc<RwLock<bool>>,
    /// Transaction map (tx_id -> P2P transaction data)
    pending_txs: Arc<RwLock<HashMap<[u8; 32], TransactionMessage>>>,
    /// Attestation map (tx_id -> attestations)
    attestations: Arc<RwLock<HashMap<[u8; 32], Vec<CWAAttestation>>>>,
}

impl PhantomNode {
    /// Create a new PHANTOM node
    pub fn new(config: NodeConfig) -> NodeResult<Self> {
        let (event_tx, event_rx) = mpsc::channel(1000);

        // Create encrypted mempool
        let mempool = EncryptedMempool::new(config.mempool.clone())
            .map_err(|e| NodeError::Mempool(e.to_string()))?;

        Ok(Self {
            swarm: Arc::new(RwLock::new(SwarmManager::new(config.p2p.clone()))),
            consensus: Arc::new(RwLock::new(CWAProtocol::new(config.cwa.clone()))),
            state: Arc::new(RwLock::new(ESLState::new(config.esl_tree_depth))),
            mempool: Arc::new(RwLock::new(mempool)),
            sync_manager: Arc::new(RwLock::new(StateSyncManager::new(config.sync.clone()))),
            wallet_lifecycle: None,
            validator_id: None,
            event_tx,
            event_rx: Arc::new(Mutex::new(event_rx)),
            running: Arc::new(RwLock::new(false)),
            pending_txs: Arc::new(RwLock::new(HashMap::new())),
            attestations: Arc::new(RwLock::new(HashMap::new())),
            config,
        })
    }

    /// Attach a wallet to this node
    pub async fn attach_wallet(&mut self, wallet: HDWallet) -> NodeResult<()> {
        let lifecycle = TransactionLifecycle::new(self.config.lifecycle.clone())
            .from_hd_wallet(&wallet)
            .map_err(|e| NodeError::Wallet(e.to_string()))?
            .with_propagator(Arc::new(NodePropagator::new(
                self.swarm.clone(),
                self.mempool.clone(),
            )))
            .with_state_provider(Arc::new(NodeStateProvider::new(self.state.clone())));

        self.wallet_lifecycle = Some(Arc::new(RwLock::new(lifecycle)));
        Ok(())
    }

    /// Register as a validator
    pub async fn register_as_validator(&mut self, stake: u64) -> NodeResult<[u8; 32]> {
        // Generate validator identity from timestamp and stake
        let mut validator_id = [0u8; 32];
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        validator_id[..16].copy_from_slice(&timestamp.to_le_bytes());
        validator_id[16..24].copy_from_slice(&stake.to_le_bytes());

        // Create validator with public key (simplified - would use PQ keys in production)
        let public_key = vec![0u8; 64]; // Placeholder
        let vrf_key = [0u8; 32]; // Placeholder

        let validator = Validator::new(validator_id, public_key, vrf_key, stake);

        // Register with consensus
        self.consensus
            .write()
            .await
            .register_validator(validator)
            .map_err(|e| NodeError::Consensus(e.to_string()))?;

        self.validator_id = Some(validator_id);
        self.config.is_validator = true;
        self.config.validator_stake = stake;

        Ok(validator_id)
    }

    /// Start the node
    pub async fn start(&mut self) -> NodeResult<()> {
        if *self.running.read().await {
            return Err(NodeError::AlreadyRunning);
        }

        // Start P2P network
        self.swarm
            .write()
            .await
            .start()
            .await
            .map_err(|e| NodeError::Network(e.to_string()))?;

        *self.running.write().await = true;

        // Start the main event loop
        let node = PhantomNodeHandle {
            swarm: self.swarm.clone(),
            consensus: self.consensus.clone(),
            state: self.state.clone(),
            mempool: self.mempool.clone(),
            sync_manager: self.sync_manager.clone(),
            wallet_lifecycle: self.wallet_lifecycle.clone(),
            validator_id: self.validator_id,
            event_tx: self.event_tx.clone(),
            running: self.running.clone(),
            pending_txs: self.pending_txs.clone(),
            attestations: self.attestations.clone(),
            config: self.config.clone(),
        };

        tokio::spawn(async move {
            node.run_event_loop().await;
        });

        Ok(())
    }

    /// Stop the node
    pub async fn stop(&mut self) -> NodeResult<()> {
        *self.running.write().await = false;
        self.swarm
            .write()
            .await
            .stop()
            .await
            .map_err(|e| NodeError::Network(e.to_string()))?;
        Ok(())
    }

    /// Receive the next node event
    pub async fn recv_event(&self) -> Option<NodeEvent> {
        self.event_rx.lock().await.recv().await
    }

    /// Submit a transaction for consensus
    pub async fn submit_transaction(&self, tx_data: Vec<u8>) -> NodeResult<[u8; 32]> {
        // Hash the transaction using phantom_hash
        let tx_id = phantom_hash::hash(&tx_data);

        // Encrypt and add to mempool
        let mempool = self.mempool.read().await;
        let ciphertext = mempool.encrypt_transaction(&tx_data)
            .map_err(|e| NodeError::Mempool(e.to_string()))?;
        drop(mempool);

        self.mempool
            .read()
            .await
            .submit(ciphertext, 0)  // 0 priority fee for now
            .await
            .map_err(|e| NodeError::Mempool(e.to_string()))?;

        // Submit to consensus
        self.consensus
            .write()
            .await
            .submit_update(tx_data)
            .map_err(|e| NodeError::Consensus(e.to_string()))?;

        // Notify
        let _ = self.event_tx.send(NodeEvent::TransactionInMempool { tx_id }).await;

        Ok(tx_id)
    }

    /// Send a payment through the wallet
    pub async fn send_payment(
        &self,
        recipient: StealthAddress,
        amount: u64,
        change_address: StealthAddress,
    ) -> NodeResult<[u8; 32]> {
        let lifecycle = self.wallet_lifecycle
            .as_ref()
            .ok_or_else(|| NodeError::Wallet("No wallet attached".into()))?;

        lifecycle
            .read()
            .await
            .create_payment(recipient, amount, change_address)
            .await
            .map_err(|e| NodeError::Wallet(e.to_string()))
    }

    /// Get wallet balance
    pub async fn balance(&self) -> NodeResult<u64> {
        let lifecycle = self.wallet_lifecycle
            .as_ref()
            .ok_or_else(|| NodeError::Wallet("No wallet attached".into()))?;

        Ok(lifecycle.read().await.balance().await)
    }

    /// Get transaction status
    pub async fn get_transaction_status(&self, tx_id: &[u8; 32]) -> Option<TransactionStatus> {
        if let Some(ref lifecycle) = self.wallet_lifecycle {
            lifecycle.read().await.get_status(tx_id).await
        } else {
            None
        }
    }

    /// Get current state snapshot
    pub async fn get_state_snapshot(&self) -> ESLSnapshot {
        self.state.read().await.snapshot()
    }

    /// Get consensus round
    pub async fn get_round(&self) -> u64 {
        self.consensus.read().await.round()
    }

    /// Get peer count
    pub async fn peer_count(&self) -> usize {
        self.swarm.read().await.peer_count().await.unwrap_or(0)
    }

    /// Get mempool size
    pub async fn mempool_size(&self) -> usize {
        self.mempool.read().await.len().await
    }

    /// Check if node is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
}

/// Internal handle for the event loop
struct PhantomNodeHandle {
    swarm: Arc<RwLock<SwarmManager>>,
    consensus: Arc<RwLock<CWAProtocol>>,
    state: Arc<RwLock<ESLState>>,
    mempool: Arc<RwLock<EncryptedMempool>>,
    #[allow(dead_code)]
    sync_manager: Arc<RwLock<StateSyncManager>>,
    wallet_lifecycle: Option<Arc<RwLock<TransactionLifecycle>>>,
    validator_id: Option<[u8; 32]>,
    event_tx: mpsc::Sender<NodeEvent>,
    running: Arc<RwLock<bool>>,
    pending_txs: Arc<RwLock<HashMap<[u8; 32], TransactionMessage>>>,
    attestations: Arc<RwLock<HashMap<[u8; 32], Vec<CWAAttestation>>>>,
    config: NodeConfig,
}

impl PhantomNodeHandle {
    /// Main event loop
    async fn run_event_loop(&self) {
        while *self.running.read().await {
            // Process P2P events
            if let Some(event) = self.swarm.write().await.recv_event().await {
                self.handle_swarm_event(event).await;
            }

            // Small delay to prevent busy loop
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
    }

    /// Handle P2P swarm events
    async fn handle_swarm_event(&self, event: SwarmEvent_) {
        match event {
            SwarmEvent_::MessageReceived { peer_id, message, .. } => {
                self.handle_network_message(message, peer_id).await;
            }
            SwarmEvent_::PeerConnected(peer_id) => {
                let _ = self.event_tx.send(NodeEvent::PeerConnected(peer_id)).await;
            }
            SwarmEvent_::PeerDisconnected(peer_id) => {
                let _ = self.event_tx.send(NodeEvent::PeerDisconnected(peer_id)).await;
            }
            _ => {}
        }
    }

    /// Handle incoming network messages
    async fn handle_network_message(&self, message: NetworkMessage, from: PeerId) {
        match message {
            NetworkMessage::Transaction(tx_msg) => {
                self.handle_transaction(tx_msg, from).await;
            }
            NetworkMessage::Consensus(consensus_msg) => {
                self.handle_consensus_message(consensus_msg).await;
            }
            NetworkMessage::StateUpdate(state_msg) => {
                self.handle_state_update(state_msg).await;
            }
            _ => {}
        }
    }

    /// Handle incoming transaction
    async fn handle_transaction(&self, tx_msg: TransactionMessage, from: PeerId) {
        let tx_id = tx_msg.tx_id;

        // Store transaction for later processing
        self.pending_txs.write().await.insert(tx_id, tx_msg.clone());

        // Encrypt and add to mempool
        let mempool = self.mempool.read().await;
        if let Ok(ciphertext) = mempool.encrypt_transaction(&tx_msg.encrypted_data) {
            drop(mempool);
            if let Ok(_) = self.mempool.read().await.submit(ciphertext, 0).await {
                let _ = self.event_tx.send(NodeEvent::TransactionReceived { tx_id, from }).await;
                let _ = self.event_tx.send(NodeEvent::TransactionInMempool { tx_id }).await;
            }
        }

        // If we're a validator, process for consensus
        if self.config.is_validator && self.validator_id.is_some() {
            self.process_transaction_for_consensus(tx_id, tx_msg).await;
        }
    }

    /// Process transaction for consensus (validator only)
    async fn process_transaction_for_consensus(&self, tx_id: [u8; 32], tx_msg: TransactionMessage) {
        let validator_id = match self.validator_id {
            Some(id) => id,
            None => return,
        };

        // Submit to consensus
        let mut consensus = self.consensus.write().await;
        if let Ok(_) = consensus.submit_update(tx_msg.encrypted_data.clone()) {
            // Select witnesses
            if let Ok(witnesses) = consensus.select_witnesses_for_update(&tx_id) {
                // If we're selected as a witness, create attestation
                if witnesses.iter().any(|w| w.id == validator_id) {
                    let attestation = CWAAttestation::new(
                        validator_id,
                        tx_id,
                        vec![0u8; 64], // Signature placeholder
                        vec![0u8; 80], // VRF proof placeholder
                        consensus.round(),
                    );

                    if let Ok(_) = consensus.submit_attestation(attestation.clone()) {
                        let _ = self.event_tx.send(NodeEvent::AttestationReceived {
                            tx_id,
                            witness: validator_id,
                        }).await;
                    }
                }
            }
        }
    }

    /// Handle consensus message
    async fn handle_consensus_message(&self, msg: ConsensusMessage) {
        match msg.msg_type {
            ConsensusMessageType::Attestation => {
                // Parse attestation from payload
                if let Ok(att) = serde_json::from_slice::<P2PAttestation>(&msg.payload) {
                    self.handle_attestation(att, msg.round).await;
                }
            }
            ConsensusMessageType::ThresholdComplete => {
                // Handle finalization notice
                let _ = self.event_tx.send(NodeEvent::RoundAdvanced {
                    round: msg.round,
                }).await;
            }
            _ => {}
        }
    }

    /// Handle attestation message
    async fn handle_attestation(&self, att: P2PAttestation, round: u64) {
        // P2P Attestation has: validator_key, signature, timestamp
        // We need to track attestations by the validator_key as an identifier
        let validator_key = att.validator_key;

        // Create a CWA attestation from the P2P attestation
        // Note: P2P attestation doesn't have update_hash, so we use validator_key as context
        let cwa_attestation = CWAAttestation::new(
            validator_key,
            validator_key, // Using validator_key as update_hash placeholder
            att.signature.clone(),
            vec![], // VRF proof
            round,
        );

        // Submit to consensus
        if let Ok(_) = self.consensus.write().await.submit_attestation(cwa_attestation.clone()) {
            let _ = self.event_tx.send(NodeEvent::AttestationReceived {
                tx_id: validator_key,
                witness: validator_key,
            }).await;

            // Store attestation indexed by validator key
            self.attestations
                .write()
                .await
                .entry(validator_key)
                .or_insert_with(Vec::new)
                .push(cwa_attestation);

            // Check if threshold met
            let attestation_count = self.attestations
                .read()
                .await
                .get(&validator_key)
                .map(|v| v.len())
                .unwrap_or(0);

            if attestation_count >= self.config.cwa.threshold {
                // Finalize update
                if let Ok(_aggregated) = self.consensus.write().await.finalize_update(&validator_key) {
                    let _ = self.event_tx.send(NodeEvent::TransactionFinalized {
                        tx_id: validator_key,
                        attestation_count,
                    }).await;

                    let _ = self.event_tx.send(NodeEvent::RoundAdvanced {
                        round: self.consensus.read().await.round(),
                    }).await;
                }
            }
        }
    }

    /// Apply finalized transaction to state
    async fn apply_state_update(&self, tx_id: &[u8; 32]) {
        // Get the transaction data
        if let Some(tx_msg) = self.pending_txs.read().await.get(tx_id).cloned() {
            // Create nullifier and commitment for the transaction
            let nullifier = Nullifier::derive(&tx_msg.nullifier, tx_id);
            let commitment = Commitment::commit(0, &tx_msg.encrypted_data[..32.min(tx_msg.encrypted_data.len())].try_into().unwrap_or([0u8; 32]));

            // Create state update
            let update = StateUpdate::new(
                vec![nullifier],
                vec![commitment],
                self.consensus.read().await.round(),
                tx_msg.proof.clone(),
            );

            // Apply update
            let mut state = self.state.write().await;
            if let Ok(new_root) = state.apply_update(&update) {
                let _ = self.event_tx.send(NodeEvent::StateUpdated {
                    merkle_root: *new_root.as_bytes(),
                    epoch: state.epoch(),
                }).await;
            }

            // Clean up
            drop(state);
            self.pending_txs.write().await.remove(tx_id);

            // Remove from mempool
            let tx_id_enc = EncryptedTxId::from_bytes(*tx_id);
            let _ = self.mempool.read().await.remove(&tx_id_enc).await;
        }
    }

    /// Handle state update message
    async fn handle_state_update(&self, msg: phantom_p2p::StateUpdateMessage) {
        // Update local state from network sync
        // Verify attestations before applying
        if msg.attestations.len() < self.config.cwa.threshold {
            eprintln!("[WARN] State update rejected: insufficient attestations");
            return;
        }

        // Create encrypted balance from the sync data
        let encrypted_balance = EncryptedBalance::new(msg.encrypted_data.clone());

        // Generate commitment from fragment_id
        let commitment = msg.fragment_id;

        // Use fragment_id as owner hash for now (would come from decryption in production)
        let owner_pk_hash = msg.fragment_id;

        // Get current epoch from state
        let epoch = self.state.read().await.epoch();

        // Create state fragment
        let state_fragment = StateFragment::new(
            encrypted_balance,
            commitment,
            owner_pk_hash,
            epoch,
        );

        // Add to state
        let mut state = self.state.write().await;
        if let Err(e) = state.add_fragment(state_fragment) {
            eprintln!("[ERROR] Failed to add state fragment: {:?}", e);
        }
    }
}

/// Propagator that uses the node's P2P network and mempool
struct NodePropagator {
    swarm: Arc<RwLock<SwarmManager>>,
    mempool: Arc<RwLock<EncryptedMempool>>,
}

impl NodePropagator {
    fn new(swarm: Arc<RwLock<SwarmManager>>, mempool: Arc<RwLock<EncryptedMempool>>) -> Self {
        Self { swarm, mempool }
    }
}

#[async_trait::async_trait]
impl TransactionPropagator for NodePropagator {
    async fn submit_to_mempool(&self, tx: &Transaction) -> Result<(), String> {
        // Serialize transaction
        let tx_bytes = serde_json::to_vec(tx).map_err(|e| e.to_string())?;

        // Encrypt and submit
        let mempool = self.mempool.read().await;
        let ciphertext = mempool.encrypt_transaction(&tx_bytes).map_err(|e| e.to_string())?;
        drop(mempool);

        self.mempool.read().await.submit(ciphertext, tx.fee).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn propagate(&self, tx: &Transaction) -> Result<(), String> {
        let tx_msg = TransactionMessage::new(
            tx.hash(),
            serde_json::to_vec(tx).map_err(|e| e.to_string())?,
            tx.nullifiers.first().copied().unwrap_or([0u8; 32]),
            vec![], // Proof bytes
        );

        self.swarm
            .write()
            .await
            .publish_transaction(NetworkMessage::Transaction(tx_msg))
            .await
            .map_err(|e| e.to_string())
    }
}

/// State provider that reads from the node's ESL state
struct NodeStateProvider {
    state: Arc<RwLock<ESLState>>,
}

impl NodeStateProvider {
    fn new(state: Arc<RwLock<ESLState>>) -> Self {
        Self { state }
    }
}

#[async_trait::async_trait]
impl StateProvider for NodeStateProvider {
    async fn get_merkle_root(&self) -> [u8; 32] {
        *self.state.read().await.commitment_root()
    }

    async fn get_merkle_proof(&self, _commitment: &[u8; 32]) -> Option<(Vec<[u8; 32]>, Vec<bool>)> {
        // Would need commitment index to get witness
        // Return mock proof for now
        let path: Vec<[u8; 32]> = (0..32).map(|i| [i as u8; 32]).collect();
        let indices: Vec<bool> = (0..32).map(|i| i % 2 == 0).collect();
        Some((path, indices))
    }

    async fn nullifier_exists(&self, nullifier: &[u8; 32]) -> bool {
        let nf = Nullifier::derive(nullifier, &[0u8; 32]);
        self.state.read().await.nullifier_exists(&nf)
    }

    async fn get_epoch(&self) -> u64 {
        self.state.read().await.epoch()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_config_default() {
        let config = NodeConfig::default();
        assert!(!config.is_validator);
        assert_eq!(config.validator_stake, 0);
    }

    #[test]
    fn test_node_config_local() {
        let config = NodeConfig::local();
        assert_eq!(config.cwa.witness_count, 5);
        assert_eq!(config.cwa.threshold, 3);
    }

    #[test]
    fn test_node_config_testnet() {
        let config = NodeConfig::testnet();
        assert_eq!(config.cwa.witness_count, 21);
        assert_eq!(config.cwa.threshold, 14);
    }

    #[test]
    fn test_node_config_with_validator() {
        let config = NodeConfig::local().with_validator(10000);
        assert!(config.is_validator);
        assert_eq!(config.validator_stake, 10000);
    }

    #[tokio::test]
    async fn test_node_creation() {
        let config = NodeConfig::local();
        let node = PhantomNode::new(config).unwrap();
        assert!(!node.is_running().await);
    }
}
