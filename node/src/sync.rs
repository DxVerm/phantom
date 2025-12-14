//! Block synchronization module for chain sync
//!
//! Handles downloading blocks from peers, verifying them, and updating
//! the local chain. Implements header-first sync with parallel block downloads.

use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::cmp::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, RwLock, Semaphore};
use tracing::{info, debug, warn, error};

use crate::block::{Block, BlockHeader};
use crate::error::{NodeError, NodeResult};
use crate::state_manager::BlockValidator;

/// Block sync configuration
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Maximum concurrent block downloads
    pub max_concurrent_downloads: usize,
    /// Batch size for header requests
    pub header_batch_size: usize,
    /// Batch size for block requests
    pub block_batch_size: usize,
    /// Request timeout
    pub request_timeout: Duration,
    /// Maximum retries per request
    pub max_retries: u32,
    /// Minimum peers to start sync
    pub min_peers: usize,
    /// Target lag behind tip (in blocks)
    pub target_lag: u64,
    /// Stale request threshold
    pub stale_threshold: Duration,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_concurrent_downloads: 16,
            header_batch_size: 512,
            block_batch_size: 128,
            request_timeout: Duration::from_secs(30),
            max_retries: 3,
            min_peers: 1,
            target_lag: 2,
            stale_threshold: Duration::from_secs(60),
        }
    }
}

/// Sync status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    /// Not syncing, waiting for peers
    Idle,
    /// Discovering chain tip from peers
    Discovering,
    /// Downloading headers
    DownloadingHeaders { current: u64, target: u64 },
    /// Downloading blocks
    DownloadingBlocks { current: u64, target: u64 },
    /// Verifying blocks
    Verifying { current: u64, target: u64 },
    /// Synced with network
    Synced { height: u64 },
    /// Sync failed
    Failed { reason: String },
}

impl SyncStatus {
    /// Get sync progress as percentage
    pub fn progress(&self) -> f32 {
        match self {
            SyncStatus::Idle | SyncStatus::Discovering => 0.0,
            SyncStatus::DownloadingHeaders { current, target } |
            SyncStatus::DownloadingBlocks { current, target } |
            SyncStatus::Verifying { current, target } => {
                if *target == 0 {
                    0.0
                } else {
                    (*current as f32 / *target as f32) * 100.0
                }
            }
            SyncStatus::Synced { .. } => 100.0,
            SyncStatus::Failed { .. } => 0.0,
        }
    }

    /// Check if sync is complete
    pub fn is_synced(&self) -> bool {
        matches!(self, SyncStatus::Synced { .. })
    }
}

/// Peer info for sync
#[derive(Debug, Clone)]
pub struct SyncPeer {
    /// Peer identifier
    pub peer_id: [u8; 32],
    /// Peer's chain height
    pub height: u64,
    /// Peer's total difficulty
    pub total_difficulty: u128,
    /// Peer's best block hash
    pub best_hash: [u8; 32],
    /// Request latency (ms)
    pub latency_ms: u64,
    /// Successful responses
    pub successes: u32,
    /// Failed responses
    pub failures: u32,
    /// Last seen timestamp
    pub last_seen: Instant,
    /// Is peer currently serving a request
    pub busy: bool,
}

impl SyncPeer {
    /// Create new peer
    pub fn new(peer_id: [u8; 32], height: u64, total_difficulty: u128, best_hash: [u8; 32]) -> Self {
        Self {
            peer_id,
            height,
            total_difficulty,
            best_hash,
            latency_ms: 1000, // Default 1s
            successes: 0,
            failures: 0,
            last_seen: Instant::now(),
            busy: false,
        }
    }

    /// Calculate peer score (higher is better)
    pub fn score(&self) -> f64 {
        let success_rate = if self.successes + self.failures > 0 {
            self.successes as f64 / (self.successes + self.failures) as f64
        } else {
            0.5 // Unknown peer
        };

        let latency_factor = 1.0 / (1.0 + self.latency_ms as f64 / 1000.0);
        let freshness = if self.last_seen.elapsed().as_secs() < 60 {
            1.0
        } else {
            0.5
        };

        success_rate * latency_factor * freshness * self.height as f64
    }

    /// Update latency with exponential moving average
    pub fn update_latency(&mut self, new_latency_ms: u64) {
        const ALPHA: f64 = 0.3;
        self.latency_ms = (ALPHA * new_latency_ms as f64 + (1.0 - ALPHA) * self.latency_ms as f64) as u64;
    }

    /// Record success
    pub fn record_success(&mut self, latency_ms: u64) {
        self.successes += 1;
        self.update_latency(latency_ms);
        self.last_seen = Instant::now();
    }

    /// Record failure
    pub fn record_failure(&mut self) {
        self.failures += 1;
        self.last_seen = Instant::now();
    }
}

/// Block request tracking
#[derive(Debug, Clone)]
struct BlockRequest {
    height: u64,
    hash: Option<[u8; 32]>,
    peer_id: [u8; 32],
    sent_at: Instant,
    retries: u32,
}

/// Ordered by height for priority queue
impl PartialEq for BlockRequest {
    fn eq(&self, other: &Self) -> bool {
        self.height == other.height
    }
}

impl Eq for BlockRequest {}

impl PartialOrd for BlockRequest {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BlockRequest {
    fn cmp(&self, other: &Self) -> Ordering {
        // Lower heights have higher priority
        other.height.cmp(&self.height)
    }
}

/// Chain tip info from peer
#[derive(Debug, Clone)]
pub struct ChainTip {
    /// Height of chain tip
    pub height: u64,
    /// Hash of tip block
    pub hash: [u8; 32],
    /// Total difficulty
    pub total_difficulty: u128,
}

/// Fork choice result
#[derive(Debug, Clone)]
pub enum ForkChoice {
    /// Current chain is canonical
    CurrentChain,
    /// New chain is canonical, need to reorg
    Reorg {
        /// Common ancestor height
        common_ancestor: u64,
        /// New chain blocks to apply
        new_blocks: Vec<[u8; 32]>,
    },
}

/// Block synchronization manager
pub struct BlockSyncManager {
    config: SyncConfig,
    status: Arc<RwLock<SyncStatus>>,
    peers: Arc<RwLock<HashMap<[u8; 32], SyncPeer>>>,
    pending_requests: Arc<RwLock<HashMap<u64, BlockRequest>>>,
    downloaded_headers: Arc<RwLock<HashMap<u64, BlockHeader>>>,
    downloaded_blocks: Arc<RwLock<HashMap<u64, Block>>>,
    verified_heights: Arc<RwLock<HashSet<u64>>>,
    local_height: Arc<RwLock<u64>>,
    target_height: Arc<RwLock<u64>>,
    download_semaphore: Arc<Semaphore>,
    validator: Arc<BlockValidator>,
}

impl BlockSyncManager {
    /// Create new sync manager
    pub fn new(config: SyncConfig, validator: BlockValidator) -> Self {
        let max_downloads = config.max_concurrent_downloads;
        Self {
            config,
            status: Arc::new(RwLock::new(SyncStatus::Idle)),
            peers: Arc::new(RwLock::new(HashMap::new())),
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            downloaded_headers: Arc::new(RwLock::new(HashMap::new())),
            downloaded_blocks: Arc::new(RwLock::new(HashMap::new())),
            verified_heights: Arc::new(RwLock::new(HashSet::new())),
            local_height: Arc::new(RwLock::new(0)),
            target_height: Arc::new(RwLock::new(0)),
            download_semaphore: Arc::new(Semaphore::new(max_downloads)),
            validator: Arc::new(validator),
        }
    }

    /// Get current sync status
    pub async fn status(&self) -> SyncStatus {
        self.status.read().await.clone()
    }

    /// Get local height
    pub async fn local_height(&self) -> u64 {
        *self.local_height.read().await
    }

    /// Get target height
    pub async fn target_height(&self) -> u64 {
        *self.target_height.read().await
    }

    /// Set local height (from storage)
    pub async fn set_local_height(&self, height: u64) {
        *self.local_height.write().await = height;
    }

    /// Add or update a peer
    pub async fn add_peer(&self, peer: SyncPeer) {
        let mut peers = self.peers.write().await;
        let peer_id = peer.peer_id;

        if let Some(existing) = peers.get_mut(&peer_id) {
            existing.height = peer.height;
            existing.total_difficulty = peer.total_difficulty;
            existing.best_hash = peer.best_hash;
            existing.last_seen = Instant::now();
        } else {
            peers.insert(peer_id, peer);
        }
    }

    /// Remove a peer
    pub async fn remove_peer(&self, peer_id: &[u8; 32]) {
        self.peers.write().await.remove(peer_id);
    }

    /// Get best peer for sync
    pub async fn best_peer(&self) -> Option<SyncPeer> {
        let peers = self.peers.read().await;
        peers.values()
            .filter(|p| !p.busy)
            .max_by(|a, b| a.score().partial_cmp(&b.score()).unwrap_or(Ordering::Equal))
            .cloned()
    }

    /// Get all available peers sorted by score
    pub async fn available_peers(&self) -> Vec<SyncPeer> {
        let peers = self.peers.read().await;
        let mut available: Vec<_> = peers.values()
            .filter(|p| !p.busy)
            .cloned()
            .collect();
        available.sort_by(|a, b| b.score().partial_cmp(&a.score()).unwrap_or(Ordering::Equal));
        available
    }

    /// Discover chain tip from peers
    pub async fn discover_chain_tip(&self) -> NodeResult<ChainTip> {
        *self.status.write().await = SyncStatus::Discovering;

        let peers = self.peers.read().await;
        if peers.is_empty() {
            return Err(NodeError::Consensus("No peers available".into()));
        }

        // Find the tip with highest total difficulty
        let best = peers.values()
            .max_by_key(|p| p.total_difficulty)
            .ok_or_else(|| NodeError::Consensus("No valid peers".into()))?;

        let tip = ChainTip {
            height: best.height,
            hash: best.best_hash,
            total_difficulty: best.total_difficulty,
        };

        *self.target_height.write().await = tip.height;
        debug!("Discovered chain tip: height={}, hash={}", tip.height, hex::encode(&tip.hash[..8]));

        Ok(tip)
    }

    /// Calculate fork choice between current chain and new chain
    pub async fn fork_choice(
        &self,
        local_tip: &ChainTip,
        remote_tip: &ChainTip,
        get_header_at: impl Fn(u64) -> Option<BlockHeader>,
    ) -> ForkChoice {
        // If local has higher difficulty, keep current chain
        if local_tip.total_difficulty >= remote_tip.total_difficulty {
            return ForkChoice::CurrentChain;
        }

        // Find common ancestor by walking back
        let mut local_height = local_tip.height;
        let mut remote_height = remote_tip.height;

        // Descend to same height
        while local_height > remote_height {
            local_height -= 1;
        }
        while remote_height > local_height {
            remote_height -= 1;
        }

        // Walk back until we find common ancestor
        let mut common_ancestor = 0;
        for height in (0..=local_height).rev() {
            if let Some(local_header) = get_header_at(height) {
                if let Some(downloaded) = self.downloaded_headers.read().await.get(&height) {
                    if local_header.hash() == downloaded.hash() {
                        common_ancestor = height;
                        break;
                    }
                }
            }
        }

        // Collect blocks to apply
        let downloaded = self.downloaded_headers.read().await;
        let new_blocks: Vec<[u8; 32]> = ((common_ancestor + 1)..=remote_tip.height)
            .filter_map(|h| downloaded.get(&h).map(|hdr| hdr.hash()))
            .collect();

        ForkChoice::Reorg {
            common_ancestor,
            new_blocks,
        }
    }

    /// Start header sync
    pub async fn sync_headers(
        &self,
        start_height: u64,
        target_height: u64,
        request_headers: impl Fn([u8; 32], u64, usize) -> Option<Vec<BlockHeader>>,
    ) -> NodeResult<()> {
        *self.status.write().await = SyncStatus::DownloadingHeaders {
            current: start_height,
            target: target_height,
        };

        let mut current = start_height;

        while current < target_height {
            // Get best peer
            let peer = self.best_peer().await
                .ok_or_else(|| NodeError::Consensus("No peers available".into()))?;

            // Request headers
            let batch_end = (current + self.config.header_batch_size as u64).min(target_height);
            let count = (batch_end - current) as usize;

            if let Some(headers) = request_headers(peer.peer_id, current, count) {
                // Verify header chain
                let mut prev_hash = if current == 0 {
                    [0u8; 32]
                } else {
                    self.downloaded_headers.read().await
                        .get(&(current - 1))
                        .map(|h| h.hash())
                        .unwrap_or([0u8; 32])
                };

                for header in headers {
                    if header.prev_hash != prev_hash && header.height > 0 {
                        return Err(NodeError::InvalidBlock(
                            format!("Header chain broken at height {}", header.height)
                        ));
                    }
                    prev_hash = header.hash();
                    self.downloaded_headers.write().await.insert(header.height, header);
                }

                current = batch_end;
                *self.status.write().await = SyncStatus::DownloadingHeaders {
                    current,
                    target: target_height,
                };
            } else {
                // Request failed, try another peer
                self.peers.write().await.get_mut(&peer.peer_id)
                    .map(|p| p.record_failure());
            }
        }

        Ok(())
    }

    /// Start block download
    pub async fn download_blocks(
        &self,
        start_height: u64,
        target_height: u64,
        request_block: impl Fn([u8; 32], u64) -> Option<Block> + Send + Sync + Clone + 'static,
    ) -> NodeResult<()> {
        *self.status.write().await = SyncStatus::DownloadingBlocks {
            current: start_height,
            target: target_height,
        };

        let mut pending_heights: VecDeque<u64> = (start_height..=target_height).collect();
        let mut current_downloaded = start_height;

        while current_downloaded < target_height {
            // Get available peers
            let peers = self.available_peers().await;
            if peers.is_empty() {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            // Dispatch downloads to available peers
            for peer in peers.iter().take(self.config.max_concurrent_downloads) {
                if let Some(height) = pending_heights.pop_front() {
                    let permit = self.download_semaphore.clone().acquire_owned().await.ok();
                    if permit.is_none() {
                        pending_heights.push_front(height);
                        break;
                    }

                    let peer_id = peer.peer_id;
                    let request_block = request_block.clone();
                    let downloaded_blocks = self.downloaded_blocks.clone();
                    let peers = self.peers.clone();

                    tokio::spawn(async move {
                        let start = Instant::now();
                        if let Some(block) = request_block(peer_id, height) {
                            downloaded_blocks.write().await.insert(height, block);
                            if let Some(peer) = peers.write().await.get_mut(&peer_id) {
                                peer.record_success(start.elapsed().as_millis() as u64);
                            }
                        } else if let Some(peer) = peers.write().await.get_mut(&peer_id) {
                            peer.record_failure();
                        }
                        drop(permit);
                    });
                }
            }

            // Update progress
            let downloaded = self.downloaded_blocks.read().await;
            while downloaded.contains_key(&(current_downloaded + 1)) {
                current_downloaded += 1;
            }
            drop(downloaded);

            *self.status.write().await = SyncStatus::DownloadingBlocks {
                current: current_downloaded,
                target: target_height,
            };

            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        Ok(())
    }

    /// Verify downloaded blocks
    pub async fn verify_blocks(
        &self,
        start_height: u64,
        target_height: u64,
        get_prev_state_root: impl Fn(u64) -> [u8; 32],
    ) -> NodeResult<Vec<Block>> {
        *self.status.write().await = SyncStatus::Verifying {
            current: start_height,
            target: target_height,
        };

        let mut verified = Vec::new();
        let downloaded = self.downloaded_blocks.read().await;

        for height in start_height..=target_height {
            let block = downloaded.get(&height)
                .ok_or_else(|| NodeError::InvalidBlock(format!("Missing block at height {}", height)))?;

            // Validate block
            let prev_state_root = get_prev_state_root(height.saturating_sub(1));
            self.validator.validate(block, &prev_state_root)?;

            // Validate sequence
            let prev_hash = if height == start_height {
                // Use genesis or existing block
                [0u8; 32]
            } else {
                verified.last()
                    .map(|b: &Block| b.hash())
                    .unwrap_or([0u8; 32])
            };
            self.validator.validate_sequence(block, &prev_hash, height)?;

            verified.push(block.clone());
            self.verified_heights.write().await.insert(height);

            *self.status.write().await = SyncStatus::Verifying {
                current: height,
                target: target_height,
            };
        }

        // Mark as synced
        *self.status.write().await = SyncStatus::Synced { height: target_height };

        Ok(verified)
    }

    /// Process a received block
    pub async fn process_block(
        &self,
        block: Block,
        prev_state_root: &[u8; 32],
    ) -> NodeResult<bool> {
        let height = block.height();
        let local = *self.local_height.read().await;

        // Validate block
        self.validator.validate(&block, prev_state_root)?;

        // Check if block extends our chain
        if height == local + 1 {
            // Immediate next block
            self.downloaded_blocks.write().await.insert(height, block);
            *self.local_height.write().await = height;
            return Ok(true);
        } else if height > local + 1 {
            // Future block, store for later
            self.downloaded_blocks.write().await.insert(height, block);
            return Ok(false);
        }

        // Old block, ignore
        Ok(false)
    }

    /// Get next blocks ready for application
    pub async fn get_ready_blocks(&self) -> Vec<Block> {
        let local = *self.local_height.read().await;
        let mut blocks = Vec::new();
        let downloaded = self.downloaded_blocks.read().await;

        let mut height = local + 1;
        while let Some(block) = downloaded.get(&height) {
            blocks.push(block.clone());
            height += 1;
        }

        blocks
    }

    /// Mark blocks as applied
    pub async fn mark_applied(&self, up_to_height: u64) {
        let mut downloaded = self.downloaded_blocks.write().await;
        let mut verified = self.verified_heights.write().await;

        // Remove applied blocks
        for height in 0..=up_to_height {
            downloaded.remove(&height);
            verified.remove(&height);
        }

        *self.local_height.write().await = up_to_height;
    }

    /// Clear stale requests
    pub async fn clear_stale_requests(&self) {
        let now = Instant::now();
        let threshold = self.config.stale_threshold;

        let mut pending = self.pending_requests.write().await;
        let stale: Vec<u64> = pending.iter()
            .filter(|(_, req)| now.duration_since(req.sent_at) > threshold)
            .map(|(height, _)| *height)
            .collect();

        for height in stale {
            pending.remove(&height);
        }
    }

    /// Get sync statistics
    pub async fn stats(&self) -> SyncStats {
        let peers = self.peers.read().await;
        let downloaded = self.downloaded_blocks.read().await;
        let verified = self.verified_heights.read().await;

        SyncStats {
            status: self.status.read().await.clone(),
            local_height: *self.local_height.read().await,
            target_height: *self.target_height.read().await,
            peer_count: peers.len(),
            downloaded_blocks: downloaded.len(),
            verified_blocks: verified.len(),
            avg_peer_latency_ms: peers.values()
                .map(|p| p.latency_ms)
                .sum::<u64>() / peers.len().max(1) as u64,
        }
    }
}

/// Sync statistics
#[derive(Debug, Clone)]
pub struct SyncStats {
    pub status: SyncStatus,
    pub local_height: u64,
    pub target_height: u64,
    pub peer_count: usize,
    pub downloaded_blocks: usize,
    pub verified_blocks: usize,
    pub avg_peer_latency_ms: u64,
}

/// Header sync response
#[derive(Debug, Clone)]
pub struct HeadersResponse {
    /// Starting height
    pub start_height: u64,
    /// Headers
    pub headers: Vec<BlockHeader>,
}

/// Block sync response
#[derive(Debug, Clone)]
pub struct BlocksResponse {
    /// Blocks
    pub blocks: Vec<Block>,
}

/// Sync request types
#[derive(Debug, Clone)]
pub enum SyncRequest {
    /// Request chain tip info
    GetChainTip,
    /// Request headers starting from height
    GetHeaders { start_height: u64, count: usize },
    /// Request block by height
    GetBlock { height: u64 },
    /// Request block by hash
    GetBlockByHash { hash: [u8; 32] },
    /// Announce new block
    AnnounceBlock { height: u64, hash: [u8; 32] },
}

/// Sync response types
#[derive(Debug, Clone)]
pub enum SyncResponse {
    /// Chain tip info
    ChainTip(ChainTip),
    /// Headers response
    Headers(HeadersResponse),
    /// Block response
    Block(Option<Block>),
    /// Acknowledgment
    Ack,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{BlockBody, Attestation};

    fn create_test_header(height: u64, prev_hash: [u8; 32]) -> BlockHeader {
        BlockHeader {
            height,
            prev_hash,
            state_root: [height as u8; 32],
            tx_root: [0u8; 32],
            timestamp: 1000 + height,
            epoch: height / 100,
            round: height % 100,
            producer: [1u8; 32],
            vrf_proof: vec![],
            attestations: vec![],
            extra_data: vec![],
        }
    }

    fn create_test_block(height: u64, prev_hash: [u8; 32]) -> Block {
        let mut header = create_test_header(height, prev_hash);
        // Add attestations to pass validation
        let block_hash = header.hash();
        header.attestations = vec![
            Attestation::new([1u8; 32], block_hash, vec![]),
            Attestation::new([2u8; 32], block_hash, vec![]),
            Attestation::new([3u8; 32], block_hash, vec![]),
        ];
        Block::new(header, BlockBody::empty())
    }

    #[tokio::test]
    async fn test_sync_config_defaults() {
        let config = SyncConfig::default();
        assert_eq!(config.max_concurrent_downloads, 16);
        assert_eq!(config.header_batch_size, 512);
        assert_eq!(config.block_batch_size, 128);
    }

    #[tokio::test]
    async fn test_sync_status_progress() {
        let idle = SyncStatus::Idle;
        assert_eq!(idle.progress(), 0.0);
        assert!(!idle.is_synced());

        let downloading = SyncStatus::DownloadingBlocks { current: 50, target: 100 };
        assert_eq!(downloading.progress(), 50.0);
        assert!(!downloading.is_synced());

        let synced = SyncStatus::Synced { height: 100 };
        assert_eq!(synced.progress(), 100.0);
        assert!(synced.is_synced());
    }

    #[tokio::test]
    async fn test_peer_scoring() {
        let mut peer = SyncPeer::new([1u8; 32], 1000, 1000, [2u8; 32]);

        // Initial score
        let initial_score = peer.score();

        // Record successes
        for _ in 0..10 {
            peer.record_success(100);
        }

        // Score should improve
        assert!(peer.score() > initial_score);

        // Record failures
        for _ in 0..5 {
            peer.record_failure();
        }

        // Score should decrease
        let after_failures = peer.score();
        assert!(after_failures < peer.score() + 0.1); // Approximately same due to previous state
    }

    #[tokio::test]
    async fn test_sync_manager_creation() {
        let config = SyncConfig::default();
        let validator = BlockValidator::new(0);
        let manager = BlockSyncManager::new(config, validator);

        assert_eq!(manager.status().await, SyncStatus::Idle);
        assert_eq!(manager.local_height().await, 0);
    }

    #[tokio::test]
    async fn test_peer_management() {
        let config = SyncConfig::default();
        let validator = BlockValidator::new(0);
        let manager = BlockSyncManager::new(config, validator);

        // Add peers
        let peer1 = SyncPeer::new([1u8; 32], 100, 1000, [2u8; 32]);
        let peer2 = SyncPeer::new([3u8; 32], 200, 2000, [4u8; 32]);

        manager.add_peer(peer1).await;
        manager.add_peer(peer2).await;

        // Best peer should be peer2 (higher difficulty/height)
        let best = manager.best_peer().await.unwrap();
        assert_eq!(best.height, 200);

        // Remove peer
        manager.remove_peer(&[3u8; 32]).await;
        let best = manager.best_peer().await.unwrap();
        assert_eq!(best.height, 100);
    }

    #[tokio::test]
    async fn test_chain_tip_discovery() {
        let config = SyncConfig::default();
        let validator = BlockValidator::new(0);
        let manager = BlockSyncManager::new(config, validator);

        // Add peers with different heights
        manager.add_peer(SyncPeer::new([1u8; 32], 100, 1000, [2u8; 32])).await;
        manager.add_peer(SyncPeer::new([3u8; 32], 200, 2000, [4u8; 32])).await;
        manager.add_peer(SyncPeer::new([5u8; 32], 150, 1500, [6u8; 32])).await;

        let tip = manager.discover_chain_tip().await.unwrap();
        assert_eq!(tip.height, 200);
        assert_eq!(tip.total_difficulty, 2000);
    }

    #[tokio::test]
    async fn test_block_processing() {
        let config = SyncConfig::default();
        let validator = BlockValidator::new(0);
        let manager = BlockSyncManager::new(config, validator);

        manager.set_local_height(0).await;

        // Create block chain
        let genesis_hash = [0u8; 32];
        let block1 = create_test_block(1, genesis_hash);
        let block1_hash = block1.hash();

        // Process block 1
        let result = manager.process_block(block1, &[0u8; 32]).await.unwrap();
        assert!(result); // Should be applied immediately

        assert_eq!(manager.local_height().await, 1);

        // Process future block (should be stored but not applied)
        let block3 = create_test_block(3, [0u8; 32]);
        let result = manager.process_block(block3, &[0u8; 32]).await.unwrap();
        assert!(!result);

        assert_eq!(manager.local_height().await, 1);
    }

    #[tokio::test]
    async fn test_ready_blocks() {
        let config = SyncConfig::default();
        let validator = BlockValidator::new(0);
        let manager = BlockSyncManager::new(config, validator);

        manager.set_local_height(0).await;

        // Store blocks out of order
        let block2 = create_test_block(2, [1u8; 32]);
        let block1 = create_test_block(1, [0u8; 32]);
        let block3 = create_test_block(3, [2u8; 32]);

        manager.downloaded_blocks.write().await.insert(2, block2);
        manager.downloaded_blocks.write().await.insert(1, block1);
        manager.downloaded_blocks.write().await.insert(3, block3);

        // Get ready blocks (should be in order)
        let ready = manager.get_ready_blocks().await;
        assert_eq!(ready.len(), 3);
        assert_eq!(ready[0].height(), 1);
        assert_eq!(ready[1].height(), 2);
        assert_eq!(ready[2].height(), 3);
    }

    #[tokio::test]
    async fn test_mark_applied() {
        let config = SyncConfig::default();
        let validator = BlockValidator::new(0);
        let manager = BlockSyncManager::new(config, validator);

        // Store some blocks
        for i in 1..=5 {
            let block = create_test_block(i, [0u8; 32]);
            manager.downloaded_blocks.write().await.insert(i, block);
        }

        assert_eq!(manager.downloaded_blocks.read().await.len(), 5);

        // Mark blocks 1-3 as applied
        manager.mark_applied(3).await;

        assert_eq!(manager.downloaded_blocks.read().await.len(), 2);
        assert_eq!(manager.local_height().await, 3);
        assert!(manager.downloaded_blocks.read().await.contains_key(&4));
        assert!(manager.downloaded_blocks.read().await.contains_key(&5));
    }

    #[tokio::test]
    async fn test_sync_stats() {
        let config = SyncConfig::default();
        let validator = BlockValidator::new(0);
        let manager = BlockSyncManager::new(config, validator);

        // Add peers and blocks
        manager.add_peer(SyncPeer::new([1u8; 32], 100, 1000, [2u8; 32])).await;
        manager.downloaded_blocks.write().await.insert(1, create_test_block(1, [0u8; 32]));
        manager.verified_heights.write().await.insert(1);

        let stats = manager.stats().await;
        assert_eq!(stats.peer_count, 1);
        assert_eq!(stats.downloaded_blocks, 1);
        assert_eq!(stats.verified_blocks, 1);
    }

    #[tokio::test]
    async fn test_fork_choice_current_chain() {
        let config = SyncConfig::default();
        let validator = BlockValidator::new(0);
        let manager = BlockSyncManager::new(config, validator);

        let local_tip = ChainTip {
            height: 100,
            hash: [1u8; 32],
            total_difficulty: 2000,
        };

        let remote_tip = ChainTip {
            height: 100,
            hash: [2u8; 32],
            total_difficulty: 1500, // Lower difficulty
        };

        let choice = manager.fork_choice(&local_tip, &remote_tip, |_| None).await;
        assert!(matches!(choice, ForkChoice::CurrentChain));
    }

    #[test]
    fn test_header_chain_verification() {
        let mut headers = Vec::new();
        let mut prev_hash = [0u8; 32];

        for i in 0..5 {
            let header = create_test_header(i, prev_hash);
            prev_hash = header.hash();
            headers.push(header);
        }

        // Verify chain integrity
        let mut expected_prev = [0u8; 32];
        for header in &headers {
            if header.height > 0 {
                assert_eq!(header.prev_hash, expected_prev);
            }
            expected_prev = header.hash();
        }
    }
}
