//! Light Client main implementation
//!
//! Integrates header chain, sync, and verification for a complete light client.

use crate::errors::{LightClientError, LightClientResult};
use crate::header::{BlockHeader, HeaderChain, HeaderChainConfig, GenesisConfig, ChainTip};
use crate::sync::{SyncConfig, SyncManager, SyncStatus, SyncNetwork, Checkpoint};
use crate::verification::{ProofVerifier, InclusionProof, StateProof, DelegatedProof};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Light client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Header chain configuration
    pub header_config: HeaderChainConfig,
    /// Sync configuration
    pub sync_config: SyncConfig,
    /// Maximum age for delegated proofs (seconds)
    pub max_proof_age: u64,
    /// Whether to auto-sync on startup
    pub auto_sync: bool,
    /// Trusted nodes for proof delegation
    pub trusted_nodes: Vec<[u8; 32]>,
    /// Hardcoded checkpoints
    pub checkpoints: Vec<Checkpoint>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            header_config: HeaderChainConfig::default(),
            sync_config: SyncConfig::default(),
            max_proof_age: 3600, // 1 hour
            auto_sync: true,
            trusted_nodes: Vec::new(),
            checkpoints: Vec::new(),
        }
    }
}

/// Light client state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientState {
    /// Client is initializing
    Initializing,
    /// Client is syncing headers
    Syncing,
    /// Client is synced and ready
    Ready,
    /// Client encountered an error
    Error(String),
}

/// Main light client implementation
pub struct LightClient<N: SyncNetwork> {
    /// Configuration
    config: ClientConfig,
    /// Header chain
    chain: Arc<RwLock<HeaderChain>>,
    /// Sync manager
    sync_manager: Option<Arc<SyncManager<N>>>,
    /// Proof verifier
    verifier: ProofVerifier,
    /// Current state
    state: Arc<RwLock<ClientState>>,
    /// Network interface (for creating sync manager)
    network: Option<Arc<N>>,
}

impl<N: SyncNetwork + 'static> LightClient<N> {
    /// Create a new light client without network (offline mode)
    pub fn new_offline(config: ClientConfig) -> Self {
        let mut verifier = ProofVerifier::new(config.max_proof_age);
        for node in &config.trusted_nodes {
            verifier.add_trusted_node(*node);
        }

        let chain = HeaderChain::new(config.header_config.clone());

        // Add checkpoints to chain
        for checkpoint in &config.checkpoints {
            chain.add_checkpoint(checkpoint.height, checkpoint.hash);
        }

        Self {
            config,
            chain: Arc::new(RwLock::new(chain)),
            sync_manager: None,
            verifier,
            state: Arc::new(RwLock::new(ClientState::Initializing)),
            network: None,
        }
    }

    /// Create a new light client with network
    pub fn new(config: ClientConfig, network: Arc<N>) -> Self {
        let mut client = Self::new_offline(config.clone());
        client.network = Some(network.clone());

        let sync_manager = SyncManager::new(
            config.sync_config.clone(),
            network,
            client.chain.clone(),
        );

        client.sync_manager = Some(Arc::new(sync_manager));
        client
    }

    /// Initialize the client with genesis
    pub fn initialize(&self, genesis_config: GenesisConfig) -> LightClientResult<()> {
        self.chain.write().initialize_genesis(genesis_config)?;
        *self.state.write() = ClientState::Ready;
        Ok(())
    }

    /// Start syncing (if network available)
    pub async fn start_sync(&self) -> LightClientResult<()> {
        let sync_manager = self.sync_manager.as_ref()
            .ok_or(LightClientError::NotInitialized)?;

        *self.state.write() = ClientState::Syncing;

        match sync_manager.start_sync().await {
            Ok(()) => {
                *self.state.write() = ClientState::Ready;
                Ok(())
            }
            Err(e) => {
                *self.state.write() = ClientState::Error(e.to_string());
                Err(e)
            }
        }
    }

    /// Get current client state
    pub fn state(&self) -> ClientState {
        self.state.read().clone()
    }

    /// Get current sync status (if syncing)
    pub fn sync_status(&self) -> Option<SyncStatus> {
        self.sync_manager.as_ref().map(|sm| sm.status())
    }

    /// Get the current chain tip
    pub fn get_tip(&self) -> Option<ChainTip> {
        self.chain.read().get_tip()
    }

    /// Get the current height
    pub fn get_height(&self) -> u64 {
        self.chain.read().get_height()
    }

    /// Get a header by hash
    pub fn get_header(&self, hash: &[u8; 32]) -> Option<BlockHeader> {
        self.chain.read().get_header(hash)
    }

    /// Get the canonical header at a height
    pub fn get_header_at_height(&self, height: u64) -> Option<BlockHeader> {
        self.chain.read().get_canonical_header(height)
    }

    /// Get headers in a range
    pub fn get_headers(&self, start: u64, count: u64) -> Vec<BlockHeader> {
        self.chain.read().get_headers_range(start, count)
    }

    /// Verify a transaction inclusion proof
    pub fn verify_transaction(
        &self,
        tx_hash: &[u8; 32],
        proof: &InclusionProof,
    ) -> LightClientResult<bool> {
        // Get the header for this proof
        let header = self.chain.read()
            .get_header(&proof.block_hash)
            .ok_or(LightClientError::HeaderNotFound(proof.block_height))?;

        // Verify the proof is for the correct transaction
        if proof.item_hash != *tx_hash {
            return Err(LightClientError::InvalidProof(
                "Transaction hash mismatch".into()
            ));
        }

        self.verifier.verify_inclusion(proof, &header)?;
        Ok(true)
    }

    /// Verify a state proof
    pub fn verify_state(&self, proof: &StateProof) -> LightClientResult<bool> {
        let header = self.chain.read()
            .get_header(&proof.inclusion_proof.block_hash)
            .ok_or(LightClientError::HeaderNotFound(proof.inclusion_proof.block_height))?;

        self.verifier.verify_state(proof, &header)?;
        Ok(true)
    }

    /// Verify a delegated proof from a full node
    pub fn verify_delegated_proof(
        &self,
        proof: &DelegatedProof,
        current_time: u64,
    ) -> LightClientResult<bool> {
        self.verifier.verify_delegated(proof, current_time)?;
        Ok(true)
    }

    /// Add a trusted node for proof delegation
    pub fn add_trusted_node(&mut self, pubkey: [u8; 32]) {
        self.verifier.add_trusted_node(pubkey);
        self.config.trusted_nodes.push(pubkey);
    }

    /// Remove a trusted node
    pub fn remove_trusted_node(&mut self, pubkey: &[u8; 32]) {
        self.verifier.remove_trusted_node(pubkey);
        self.config.trusted_nodes.retain(|k| k != pubkey);
    }

    /// Add a checkpoint
    pub fn add_checkpoint(&self, checkpoint: Checkpoint) {
        self.chain.write().add_checkpoint(checkpoint.height, checkpoint.hash);
        // Note: In real implementation, checkpoints could be added to sync_manager
        // For now, checkpoints should be added before sync starts via config
        let _ = &self.sync_manager; // Acknowledge sync_manager exists
    }

    /// Check if a header is in the canonical chain
    pub fn is_canonical(&self, hash: &[u8; 32]) -> bool {
        self.chain.read().is_canonical(hash)
    }

    /// Get chain statistics
    pub fn stats(&self) -> ClientStats {
        let chain_stats = self.chain.read().stats();
        let sync_status = self.sync_status();

        ClientStats {
            state: self.state(),
            height: chain_stats.height,
            total_headers: chain_stats.total_headers,
            total_difficulty: chain_stats.total_difficulty,
            checkpoints: chain_stats.checkpoints,
            sync_progress: match sync_status {
                Some(SyncStatus::Syncing { current_height, target_height, .. }) => {
                    if target_height == 0 {
                        0.0
                    } else {
                        current_height as f32 / target_height as f32 * 100.0
                    }
                }
                Some(SyncStatus::Synced { .. }) => 100.0,
                _ => 0.0,
            },
            trusted_nodes: self.config.trusted_nodes.len(),
        }
    }

    /// Process a new header announcement (for real-time updates)
    pub fn process_new_header(&self, header: BlockHeader) -> LightClientResult<()> {
        self.chain.write().insert_header(header)
    }

    /// Get the expected next header after the tip
    pub fn expected_next_header_info(&self) -> Option<NextHeaderInfo> {
        let tip = self.get_tip()?;
        Some(NextHeaderInfo {
            expected_height: tip.header.height + 1,
            parent_hash: tip.header.hash,
            min_timestamp: tip.header.timestamp,
        })
    }
}

/// Information about expected next header
#[derive(Debug, Clone)]
pub struct NextHeaderInfo {
    pub expected_height: u64,
    pub parent_hash: [u8; 32],
    pub min_timestamp: u64,
}

/// Client statistics
#[derive(Debug, Clone)]
pub struct ClientStats {
    pub state: ClientState,
    pub height: u64,
    pub total_headers: u64,
    pub total_difficulty: u128,
    pub checkpoints: usize,
    pub sync_progress: f32,
    pub trusted_nodes: usize,
}

/// Builder for light client configuration
pub struct ClientBuilder {
    config: ClientConfig,
}

impl ClientBuilder {
    /// Create a new builder with default config
    pub fn new() -> Self {
        Self {
            config: ClientConfig::default(),
        }
    }

    /// Set maximum headers to store
    pub fn max_headers(mut self, max: usize) -> Self {
        self.config.header_config.max_headers = max;
        self
    }

    /// Set maximum reorg depth
    pub fn max_reorg_depth(mut self, depth: u64) -> Self {
        self.config.header_config.max_reorg_depth = depth;
        self
    }

    /// Set sync batch size
    pub fn sync_batch_size(mut self, size: usize) -> Self {
        self.config.sync_config.batch_size = size;
        self
    }

    /// Set sync timeout
    pub fn sync_timeout(mut self, secs: u64) -> Self {
        self.config.sync_config.timeout_secs = secs;
        self
    }

    /// Add trusted node
    pub fn trusted_node(mut self, pubkey: [u8; 32]) -> Self {
        self.config.trusted_nodes.push(pubkey);
        self
    }

    /// Add checkpoint
    pub fn checkpoint(mut self, checkpoint: Checkpoint) -> Self {
        self.config.checkpoints.push(checkpoint);
        self
    }

    /// Set auto sync
    pub fn auto_sync(mut self, enabled: bool) -> Self {
        self.config.auto_sync = enabled;
        self
    }

    /// Set max proof age
    pub fn max_proof_age(mut self, secs: u64) -> Self {
        self.config.max_proof_age = secs;
        self
    }

    /// Disable signature verification (for testing)
    pub fn skip_signatures(mut self) -> Self {
        self.config.header_config.verify_signatures = false;
        self
    }

    /// Build the configuration
    pub fn build(self) -> ClientConfig {
        self.config
    }

    /// Build an offline light client
    pub fn build_offline<N: SyncNetwork + 'static>(self) -> LightClient<N> {
        LightClient::new_offline(self.config)
    }

    /// Build a light client with network
    pub fn build_with_network<N: SyncNetwork + 'static>(self, network: Arc<N>) -> LightClient<N> {
        LightClient::new(self.config, network)
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{SyncPeer, SyncResponse};
    use async_trait::async_trait;

    // Mock network for testing
    struct MockNetwork {
        headers: Vec<BlockHeader>,
    }

    #[async_trait]
    impl SyncNetwork for MockNetwork {
        async fn discover_peers(&self) -> LightClientResult<Vec<SyncPeer>> {
            Ok(vec![SyncPeer::new([1u8; 32], 100, 100)])
        }

        async fn request_headers(
            &self,
            _peer_id: &[u8; 32],
            start_height: u64,
            count: u64,
        ) -> LightClientResult<SyncResponse> {
            let headers: Vec<_> = self.headers
                .iter()
                .filter(|h| h.height >= start_height && h.height < start_height + count)
                .cloned()
                .collect();

            Ok(SyncResponse {
                request_id: 0,
                headers,
                has_more: false,
            })
        }

        async fn get_peer_height(&self, _peer_id: &[u8; 32]) -> LightClientResult<(u64, u128)> {
            Ok((self.headers.last().map(|h| h.height).unwrap_or(0), 100))
        }
    }

    #[test]
    fn test_client_builder() {
        let config = ClientBuilder::new()
            .max_headers(5000)
            .sync_batch_size(100)
            .max_proof_age(7200)
            .skip_signatures()
            .build();

        assert_eq!(config.header_config.max_headers, 5000);
        assert_eq!(config.sync_config.batch_size, 100);
        assert_eq!(config.max_proof_age, 7200);
        assert!(!config.header_config.verify_signatures);
    }

    #[test]
    fn test_offline_client() {
        let config = ClientBuilder::new()
            .skip_signatures()
            .build();

        let client: LightClient<MockNetwork> = LightClient::new_offline(config);

        // Initialize with genesis
        client.initialize(GenesisConfig::default()).unwrap();

        assert_eq!(client.state(), ClientState::Ready);
        assert_eq!(client.get_height(), 0);
    }

    #[test]
    fn test_add_headers() {
        let config = ClientBuilder::new()
            .skip_signatures()
            .build();

        let client: LightClient<MockNetwork> = LightClient::new_offline(config);
        client.initialize(GenesisConfig::default()).unwrap();

        let genesis = client.get_header_at_height(0).unwrap();

        // Add a new header
        let header = BlockHeader::new(
            1,
            genesis.hash,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            1001,
            [4u8; 32],
            1,
        );

        client.process_new_header(header.clone()).unwrap();

        assert_eq!(client.get_height(), 1);
        assert!(client.is_canonical(&header.hash));
    }

    #[test]
    fn test_client_stats() {
        let config = ClientBuilder::new()
            .skip_signatures()
            .trusted_node([1u8; 32])
            .checkpoint(Checkpoint::new(1000, [1u8; 32], 1000))
            .build();

        let client: LightClient<MockNetwork> = LightClient::new_offline(config);
        client.initialize(GenesisConfig::default()).unwrap();

        let stats = client.stats();

        assert_eq!(stats.state, ClientState::Ready);
        assert_eq!(stats.height, 0);
        assert_eq!(stats.trusted_nodes, 1);
        assert_eq!(stats.checkpoints, 1);
    }
}
