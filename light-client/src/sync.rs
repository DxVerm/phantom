//! Sync Protocol for Light Clients
//!
//! Implements efficient header synchronization using checkpoints and peer management.

use crate::errors::{LightClientError, LightClientResult};
use crate::header::{BlockHeader, HeaderChain};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use parking_lot::RwLock;

/// Sync configuration
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Maximum headers to request per batch
    pub batch_size: usize,
    /// Timeout for sync operations (seconds)
    pub timeout_secs: u64,
    /// Maximum parallel peer connections
    pub max_peers: usize,
    /// Minimum peers required for sync
    pub min_peers: usize,
    /// Checkpoint interval for verification
    pub checkpoint_interval: u64,
    /// Whether to verify all signatures during sync
    pub verify_signatures: bool,
    /// Fast sync threshold (headers behind to trigger fast sync)
    pub fast_sync_threshold: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            batch_size: 500,
            timeout_secs: 30,
            max_peers: 8,
            min_peers: 2,
            checkpoint_interval: 1000,
            verify_signatures: true,
            fast_sync_threshold: 10000,
        }
    }
}

/// Current sync status
#[derive(Debug, Clone, PartialEq)]
pub enum SyncStatus {
    /// Not syncing
    Idle,
    /// Discovering peers
    DiscoveringPeers,
    /// Downloading headers
    Syncing {
        current_height: u64,
        target_height: u64,
        peers: usize,
    },
    /// Verifying downloaded headers
    Verifying { progress: f32 },
    /// Sync complete
    Synced { height: u64 },
    /// Sync failed
    Failed { error: String },
}

/// A checkpoint for trusted sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Block height
    pub height: u64,
    /// Block hash
    pub hash: [u8; 32],
    /// Total difficulty at this checkpoint
    pub total_difficulty: u128,
    /// Optional state root for state sync
    pub state_root: Option<[u8; 32]>,
}

impl Checkpoint {
    /// Create a new checkpoint
    pub fn new(height: u64, hash: [u8; 32], total_difficulty: u128) -> Self {
        Self {
            height,
            hash,
            total_difficulty,
            state_root: None,
        }
    }

    /// Add state root for state sync
    pub fn with_state_root(mut self, state_root: [u8; 32]) -> Self {
        self.state_root = Some(state_root);
        self
    }
}

/// Peer information for sync
#[derive(Debug, Clone)]
pub struct SyncPeer {
    /// Peer identifier
    pub id: [u8; 32],
    /// Peer's reported height
    pub height: u64,
    /// Peer's total difficulty
    pub total_difficulty: u128,
    /// Last seen timestamp
    pub last_seen: Instant,
    /// Number of successful requests
    pub success_count: u32,
    /// Number of failed requests
    pub failure_count: u32,
    /// Current request in flight
    pub pending_request: Option<SyncRequest>,
}

impl SyncPeer {
    /// Create a new sync peer
    pub fn new(id: [u8; 32], height: u64, total_difficulty: u128) -> Self {
        Self {
            id,
            height,
            total_difficulty,
            last_seen: Instant::now(),
            success_count: 0,
            failure_count: 0,
            pending_request: None,
        }
    }

    /// Calculate peer score for selection
    pub fn score(&self) -> f64 {
        let success_rate = if self.success_count + self.failure_count == 0 {
            0.5
        } else {
            self.success_count as f64 / (self.success_count + self.failure_count) as f64
        };

        let recency = 1.0 / (1.0 + self.last_seen.elapsed().as_secs() as f64 / 60.0);

        success_rate * 0.7 + recency * 0.3
    }

    /// Record a successful request
    pub fn record_success(&mut self) {
        self.success_count += 1;
        self.last_seen = Instant::now();
        self.pending_request = None;
    }

    /// Record a failed request
    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        self.pending_request = None;
    }
}

/// Sync request to a peer
#[derive(Debug, Clone)]
pub struct SyncRequest {
    /// Request ID
    pub id: u64,
    /// Start height
    pub start_height: u64,
    /// Number of headers requested
    pub count: u64,
    /// Request timestamp
    pub timestamp: Instant,
}

/// Response from a peer
#[derive(Debug, Clone)]
pub struct SyncResponse {
    /// Request ID this responds to
    pub request_id: u64,
    /// Headers received
    pub headers: Vec<BlockHeader>,
    /// Whether there are more headers available
    pub has_more: bool,
}

/// Trait for network communication
#[async_trait]
pub trait SyncNetwork: Send + Sync {
    /// Discover peers on the network
    async fn discover_peers(&self) -> LightClientResult<Vec<SyncPeer>>;

    /// Request headers from a peer
    async fn request_headers(
        &self,
        peer_id: &[u8; 32],
        start_height: u64,
        count: u64,
    ) -> LightClientResult<SyncResponse>;

    /// Get peer's latest height
    async fn get_peer_height(&self, peer_id: &[u8; 32]) -> LightClientResult<(u64, u128)>;
}

/// Sync manager for coordinating header synchronization
pub struct SyncManager<N: SyncNetwork> {
    /// Configuration
    config: SyncConfig,
    /// Network interface
    network: Arc<N>,
    /// Header chain
    chain: Arc<RwLock<HeaderChain>>,
    /// Known peers
    peers: Arc<RwLock<HashMap<[u8; 32], SyncPeer>>>,
    /// Trusted checkpoints
    checkpoints: Vec<Checkpoint>,
    /// Current sync status
    status: Arc<RwLock<SyncStatus>>,
    /// Next request ID (for tracking in-flight requests)
    #[allow(dead_code)]
    next_request_id: Arc<RwLock<u64>>,
    /// Pending requests (for request-response correlation)
    #[allow(dead_code)]
    pending: Arc<RwLock<HashMap<u64, SyncRequest>>>,
}

impl<N: SyncNetwork> SyncManager<N> {
    /// Create a new sync manager
    pub fn new(
        config: SyncConfig,
        network: Arc<N>,
        chain: Arc<RwLock<HeaderChain>>,
    ) -> Self {
        Self {
            config,
            network,
            chain,
            peers: Arc::new(RwLock::new(HashMap::new())),
            checkpoints: Vec::new(),
            status: Arc::new(RwLock::new(SyncStatus::Idle)),
            next_request_id: Arc::new(RwLock::new(0)),
            pending: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a trusted checkpoint
    pub fn add_checkpoint(&mut self, checkpoint: Checkpoint) {
        // Keep checkpoints sorted by height
        let pos = self.checkpoints
            .binary_search_by_key(&checkpoint.height, |c| c.height)
            .unwrap_or_else(|e| e);
        self.checkpoints.insert(pos, checkpoint);
    }

    /// Get current sync status
    pub fn status(&self) -> SyncStatus {
        self.status.read().clone()
    }

    /// Start header synchronization
    pub async fn start_sync(&self) -> LightClientResult<()> {
        *self.status.write() = SyncStatus::DiscoveringPeers;

        // Discover peers
        let discovered_peers = self.network.discover_peers().await?;

        if discovered_peers.len() < self.config.min_peers {
            *self.status.write() = SyncStatus::Failed {
                error: "Not enough peers".into(),
            };
            return Err(LightClientError::NoPeersAvailable);
        }

        // Add peers
        {
            let mut peers = self.peers.write();
            for peer in discovered_peers {
                peers.insert(peer.id, peer);
            }
        }

        // Determine target height
        let target_height = self.get_network_height();
        let current_height = self.chain.read().get_height();

        if current_height >= target_height {
            *self.status.write() = SyncStatus::Synced { height: current_height };
            return Ok(());
        }

        *self.status.write() = SyncStatus::Syncing {
            current_height,
            target_height,
            peers: self.peers.read().len(),
        };

        // Perform sync
        self.sync_headers(current_height, target_height).await?;

        *self.status.write() = SyncStatus::Synced {
            height: self.chain.read().get_height()
        };

        Ok(())
    }

    /// Sync headers from current to target
    async fn sync_headers(
        &self,
        start: u64,
        target: u64,
    ) -> LightClientResult<()> {
        let mut current = start;

        while current < target {
            // Select best peer
            let peer_id = self.select_best_peer()?;

            let batch_size = std::cmp::min(
                self.config.batch_size as u64,
                target - current,
            );

            // Request headers
            let response = self.network
                .request_headers(&peer_id, current + 1, batch_size)
                .await;

            match response {
                Ok(resp) => {
                    // Validate and insert headers
                    self.process_headers(resp.headers)?;

                    // Update peer stats
                    if let Some(peer) = self.peers.write().get_mut(&peer_id) {
                        peer.record_success();
                    }

                    current = self.chain.read().get_height();

                    // Update status
                    *self.status.write() = SyncStatus::Syncing {
                        current_height: current,
                        target_height: target,
                        peers: self.peers.read().len(),
                    };
                }
                Err(e) => {
                    // Update peer stats
                    if let Some(peer) = self.peers.write().get_mut(&peer_id) {
                        peer.record_failure();
                    }

                    // Try again with different peer if available
                    if self.count_healthy_peers() < self.config.min_peers {
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Process received headers
    fn process_headers(&self, headers: Vec<BlockHeader>) -> LightClientResult<()> {
        let chain = self.chain.write();

        for header in headers {
            // Verify against checkpoints
            if !self.verify_checkpoint(&header) {
                return Err(LightClientError::InvalidCheckpoint(header.height));
            }

            // Insert into chain
            chain.insert_header(header)?;
        }

        Ok(())
    }

    /// Verify header against checkpoints
    fn verify_checkpoint(&self, header: &BlockHeader) -> bool {
        for checkpoint in &self.checkpoints {
            if checkpoint.height == header.height {
                return checkpoint.hash == header.hash;
            }
        }
        true
    }

    /// Select the best peer for syncing
    fn select_best_peer(&self) -> LightClientResult<[u8; 32]> {
        let peers = self.peers.read();

        peers
            .values()
            .filter(|p| p.pending_request.is_none())
            .max_by(|a, b| a.score().partial_cmp(&b.score()).unwrap())
            .map(|p| p.id)
            .ok_or(LightClientError::NoPeersAvailable)
    }

    /// Get network height from peers
    fn get_network_height(&self) -> u64 {
        let peers = self.peers.read();
        peers
            .values()
            .map(|p| p.height)
            .max()
            .unwrap_or(0)
    }

    /// Count healthy peers
    fn count_healthy_peers(&self) -> usize {
        let peers = self.peers.read();
        peers
            .values()
            .filter(|p| p.score() > 0.3)
            .count()
    }

    /// Handle a new peer announcement
    pub fn handle_peer_announcement(
        &self,
        peer_id: [u8; 32],
        height: u64,
        total_difficulty: u128,
    ) {
        let mut peers = self.peers.write();
        peers
            .entry(peer_id)
            .and_modify(|p| {
                p.height = height;
                p.total_difficulty = total_difficulty;
                p.last_seen = Instant::now();
            })
            .or_insert_with(|| SyncPeer::new(peer_id, height, total_difficulty));
    }

    /// Remove a disconnected peer
    pub fn handle_peer_disconnect(&self, peer_id: &[u8; 32]) {
        self.peers.write().remove(peer_id);
    }

    /// Get sync progress as percentage
    pub fn progress(&self) -> f32 {
        match &*self.status.read() {
            SyncStatus::Syncing { current_height, target_height, .. } => {
                if *target_height == 0 {
                    0.0
                } else {
                    *current_height as f32 / *target_height as f32 * 100.0
                }
            }
            SyncStatus::Synced { .. } => 100.0,
            _ => 0.0,
        }
    }

    /// Check if sync is needed
    pub fn needs_sync(&self) -> bool {
        let network_height = self.get_network_height();
        let current_height = self.chain.read().get_height();
        network_height > current_height
    }

    /// Get peer statistics
    pub fn peer_stats(&self) -> PeerStats {
        let peers = self.peers.read();
        PeerStats {
            total: peers.len(),
            healthy: peers.values().filter(|p| p.score() > 0.5).count(),
            avg_height: if peers.is_empty() {
                0
            } else {
                peers.values().map(|p| p.height).sum::<u64>() / peers.len() as u64
            },
        }
    }
}

/// Peer statistics
#[derive(Debug, Clone)]
pub struct PeerStats {
    pub total: usize,
    pub healthy: usize,
    pub avg_height: u64,
}

/// Fast sync support for catching up quickly
pub struct FastSync {
    /// Trusted checkpoints for fast sync
    checkpoints: Vec<Checkpoint>,
    /// State snapshot heights available
    state_heights: HashSet<u64>,
}

impl FastSync {
    /// Create a new fast sync helper
    pub fn new() -> Self {
        Self {
            checkpoints: Vec::new(),
            state_heights: HashSet::new(),
        }
    }

    /// Add checkpoint
    pub fn add_checkpoint(&mut self, checkpoint: Checkpoint) {
        if checkpoint.state_root.is_some() {
            self.state_heights.insert(checkpoint.height);
        }
        self.checkpoints.push(checkpoint);
        self.checkpoints.sort_by_key(|c| c.height);
    }

    /// Get the best checkpoint for fast sync
    pub fn best_checkpoint(&self, current_height: u64) -> Option<&Checkpoint> {
        self.checkpoints
            .iter()
            .filter(|c| c.height > current_height && c.state_root.is_some())
            .max_by_key(|c| c.height)
    }

    /// Check if fast sync is beneficial
    pub fn should_fast_sync(&self, current: u64, target: u64, threshold: u64) -> bool {
        let gap = target.saturating_sub(current);
        gap > threshold && self.best_checkpoint(current).is_some()
    }
}

impl Default for FastSync {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_sorting() {
        let mut checkpoints = vec![
            Checkpoint::new(100, [1u8; 32], 100),
            Checkpoint::new(50, [2u8; 32], 50),
            Checkpoint::new(200, [3u8; 32], 200),
        ];

        checkpoints.sort_by_key(|c| c.height);

        assert_eq!(checkpoints[0].height, 50);
        assert_eq!(checkpoints[1].height, 100);
        assert_eq!(checkpoints[2].height, 200);
    }

    #[test]
    fn test_peer_scoring() {
        let mut peer = SyncPeer::new([0u8; 32], 100, 100);

        // Initial score
        let initial_score = peer.score();

        // After successes
        for _ in 0..5 {
            peer.record_success();
        }
        let success_score = peer.score();

        // After failures
        for _ in 0..5 {
            peer.record_failure();
        }
        let mixed_score = peer.score();

        assert!(success_score > initial_score);
        assert!(mixed_score < success_score);
    }

    #[test]
    fn test_sync_status() {
        let status = SyncStatus::Syncing {
            current_height: 500,
            target_height: 1000,
            peers: 5,
        };

        assert!(matches!(status, SyncStatus::Syncing { .. }));
    }

    #[test]
    fn test_fast_sync_decision() {
        let mut fast_sync = FastSync::new();

        // Without checkpoints, shouldn't fast sync
        assert!(!fast_sync.should_fast_sync(0, 10000, 5000));

        // Add checkpoint with state root
        fast_sync.add_checkpoint(
            Checkpoint::new(8000, [1u8; 32], 8000)
                .with_state_root([2u8; 32])
        );

        // Now should fast sync
        assert!(fast_sync.should_fast_sync(0, 10000, 5000));
    }
}
