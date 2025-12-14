//! Block Header Chain
//!
//! Maintains a chain of block headers for light client verification.
//! Headers are compact representations containing:
//! - Previous block hash
//! - State root (encrypted state commitment)
//! - Transactions root
//! - Timestamp and height

use crate::errors::{LightClientError, LightClientResult};
use dashmap::DashMap;
use lru::LruCache;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use std::sync::Arc;

/// Block header containing essential chain data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockHeader {
    /// Block height
    pub height: u64,
    /// Hash of this header
    pub hash: [u8; 32],
    /// Hash of the parent block
    pub parent_hash: [u8; 32],
    /// Merkle root of the encrypted state
    pub state_root: [u8; 32],
    /// Merkle root of transactions
    pub transactions_root: [u8; 32],
    /// Merkle root of receipts/effects
    pub receipts_root: [u8; 32],
    /// Block timestamp (Unix time)
    pub timestamp: u64,
    /// Validator/proposer public key hash
    pub proposer: [u8; 32],
    /// Aggregate signature from CWA consensus
    pub signature: Vec<u8>,
    /// Number of transactions in block
    pub tx_count: u32,
    /// Difficulty or weight (for fork choice)
    pub difficulty: u64,
    /// Extra data (protocol version, etc.)
    pub extra_data: Vec<u8>,
}

impl BlockHeader {
    /// Create a new block header
    pub fn new(
        height: u64,
        parent_hash: [u8; 32],
        state_root: [u8; 32],
        transactions_root: [u8; 32],
        receipts_root: [u8; 32],
        timestamp: u64,
        proposer: [u8; 32],
        difficulty: u64,
    ) -> Self {
        let mut header = Self {
            height,
            hash: [0u8; 32],
            parent_hash,
            state_root,
            transactions_root,
            receipts_root,
            timestamp,
            proposer,
            signature: Vec::new(),
            tx_count: 0,
            difficulty,
            extra_data: Vec::new(),
        };
        header.hash = header.compute_hash();
        header
    }

    /// Compute the header hash using BLAKE3
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.parent_hash);
        hasher.update(&self.state_root);
        hasher.update(&self.transactions_root);
        hasher.update(&self.receipts_root);
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.proposer);
        hasher.update(&self.difficulty.to_le_bytes());
        hasher.finalize().into()
    }

    /// Verify the header hash is correct
    pub fn verify_hash(&self) -> bool {
        self.hash == self.compute_hash()
    }

    /// Verify the header signature (placeholder - would use CWA verification)
    pub fn verify_signature(&self) -> bool {
        // In production, this would verify the aggregate signature
        // from the Collaborative Weighted Agreement consensus
        !self.signature.is_empty()
    }

    /// Check if this header is a valid child of the given parent
    pub fn is_valid_child_of(&self, parent: &BlockHeader) -> bool {
        self.parent_hash == parent.hash
            && self.height == parent.height + 1
            && self.timestamp >= parent.timestamp
    }

    /// Get the header size in bytes (approximate)
    pub fn size_bytes(&self) -> usize {
        // Fixed fields: 8 + 32*5 + 8 + 32 + 4 + 8 = 220 bytes
        // Plus variable signature and extra_data
        220 + self.signature.len() + self.extra_data.len()
    }
}

/// Genesis header configuration
pub struct GenesisConfig {
    pub state_root: [u8; 32],
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
}

impl Default for GenesisConfig {
    fn default() -> Self {
        Self {
            state_root: [0u8; 32],
            timestamp: 0,
            extra_data: b"PHANTOM Genesis".to_vec(),
        }
    }
}

/// Information about the chain tip
#[derive(Debug, Clone)]
pub struct ChainTip {
    /// The latest header
    pub header: BlockHeader,
    /// Total difficulty from genesis
    pub total_difficulty: u128,
    /// Number of headers in the chain
    pub chain_length: u64,
}

/// Header chain configuration
#[derive(Debug, Clone)]
pub struct HeaderChainConfig {
    /// Maximum headers to keep in memory
    pub max_headers: usize,
    /// Maximum reorg depth allowed
    pub max_reorg_depth: u64,
    /// Checkpoint interval (for pruning)
    pub checkpoint_interval: u64,
    /// Whether to verify signatures
    pub verify_signatures: bool,
}

impl Default for HeaderChainConfig {
    fn default() -> Self {
        Self {
            max_headers: 10_000,
            max_reorg_depth: 100,
            checkpoint_interval: 1000,
            verify_signatures: true,
        }
    }
}

/// Header chain maintaining block headers for light client
pub struct HeaderChain {
    /// Configuration
    config: HeaderChainConfig,
    /// Headers indexed by hash
    headers_by_hash: DashMap<[u8; 32], BlockHeader>,
    /// Headers indexed by height (may have multiple at same height during reorgs)
    headers_by_height: DashMap<u64, Vec<[u8; 32]>>,
    /// LRU cache for recently accessed headers
    cache: Arc<RwLock<LruCache<[u8; 32], BlockHeader>>>,
    /// Current chain tip
    tip: Arc<RwLock<Option<ChainTip>>>,
    /// Genesis header
    genesis: Option<BlockHeader>,
    /// Finalized checkpoints (height -> hash)
    checkpoints: DashMap<u64, [u8; 32]>,
    /// Total headers stored
    header_count: Arc<RwLock<u64>>,
}

impl HeaderChain {
    /// Create a new header chain
    pub fn new(config: HeaderChainConfig) -> Self {
        let cache_size = NonZeroUsize::new(config.max_headers / 10).unwrap_or(NonZeroUsize::new(100).unwrap());
        Self {
            config,
            headers_by_hash: DashMap::new(),
            headers_by_height: DashMap::new(),
            cache: Arc::new(RwLock::new(LruCache::new(cache_size))),
            tip: Arc::new(RwLock::new(None)),
            genesis: None,
            checkpoints: DashMap::new(),
            header_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Initialize the chain with a genesis header
    pub fn initialize_genesis(&mut self, config: GenesisConfig) -> LightClientResult<BlockHeader> {
        let genesis = BlockHeader {
            height: 0,
            hash: [0u8; 32],
            parent_hash: [0u8; 32],
            state_root: config.state_root,
            transactions_root: [0u8; 32],
            receipts_root: [0u8; 32],
            timestamp: config.timestamp,
            proposer: [0u8; 32],
            signature: b"genesis".to_vec(),
            tx_count: 0,
            difficulty: 1,
            extra_data: config.extra_data,
        };

        let mut genesis = genesis;
        genesis.hash = genesis.compute_hash();

        self.genesis = Some(genesis.clone());
        self.insert_header(genesis.clone())?;

        let tip = ChainTip {
            header: genesis.clone(),
            total_difficulty: genesis.difficulty as u128,
            chain_length: 1,
        };
        *self.tip.write() = Some(tip);

        Ok(genesis)
    }

    /// Insert a new header into the chain
    pub fn insert_header(&self, header: BlockHeader) -> LightClientResult<()> {
        // Verify header hash
        if !header.verify_hash() {
            return Err(LightClientError::InvalidHeader("Hash mismatch".into()));
        }

        // Verify signature if configured
        if self.config.verify_signatures && header.height > 0 && !header.verify_signature() {
            return Err(LightClientError::InvalidHeader("Invalid signature".into()));
        }

        // Check if we already have this header
        if self.headers_by_hash.contains_key(&header.hash) {
            return Ok(());
        }

        // For non-genesis headers, verify parent exists
        if header.height > 0 {
            if !self.headers_by_hash.contains_key(&header.parent_hash) {
                return Err(LightClientError::InvalidParentHash {
                    expected: hex::encode(header.parent_hash),
                    actual: "not found".into(),
                });
            }
        }

        // Check chain limits
        let count = *self.header_count.read();
        if count as usize >= self.config.max_headers {
            self.prune_old_headers()?;
        }

        // Insert into indexes
        let hash = header.hash;
        let height = header.height;

        self.headers_by_hash.insert(hash, header.clone());
        self.headers_by_height
            .entry(height)
            .or_default()
            .push(hash);

        // Update cache
        self.cache.write().put(hash, header.clone());

        // Update header count
        *self.header_count.write() += 1;

        // Update tip if this extends the best chain
        self.maybe_update_tip(&header)?;

        Ok(())
    }

    /// Get a header by hash
    pub fn get_header(&self, hash: &[u8; 32]) -> Option<BlockHeader> {
        // Check cache first
        if let Some(header) = self.cache.write().get(hash).cloned() {
            return Some(header);
        }

        // Check main storage
        self.headers_by_hash.get(hash).map(|h| {
            let header = h.clone();
            // Add to cache
            self.cache.write().put(*hash, header.clone());
            header
        })
    }

    /// Get headers at a specific height
    pub fn get_headers_at_height(&self, height: u64) -> Vec<BlockHeader> {
        self.headers_by_height
            .get(&height)
            .map(|hashes| {
                hashes
                    .iter()
                    .filter_map(|h| self.get_header(h))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the canonical header at a height
    pub fn get_canonical_header(&self, height: u64) -> Option<BlockHeader> {
        let tip = self.tip.read();
        let tip = tip.as_ref()?;

        if height > tip.header.height {
            return None;
        }

        // Walk back from tip to find the header at this height
        let mut current = tip.header.clone();
        while current.height > height {
            current = self.get_header(&current.parent_hash)?;
        }

        Some(current)
    }

    /// Get the current chain tip
    pub fn get_tip(&self) -> Option<ChainTip> {
        self.tip.read().clone()
    }

    /// Get the current height
    pub fn get_height(&self) -> u64 {
        self.tip
            .read()
            .as_ref()
            .map(|t| t.header.height)
            .unwrap_or(0)
    }

    /// Check if a header is in the canonical chain
    pub fn is_canonical(&self, hash: &[u8; 32]) -> bool {
        let header = match self.get_header(hash) {
            Some(h) => h,
            None => return false,
        };

        self.get_canonical_header(header.height)
            .map(|h| h.hash == *hash)
            .unwrap_or(false)
    }

    /// Add a checkpoint (for trusted sync)
    pub fn add_checkpoint(&self, height: u64, hash: [u8; 32]) {
        self.checkpoints.insert(height, hash);
    }

    /// Verify a header against checkpoints
    pub fn verify_against_checkpoints(&self, header: &BlockHeader) -> bool {
        if let Some(expected_hash) = self.checkpoints.get(&header.height) {
            return header.hash == *expected_hash;
        }
        true
    }

    /// Get headers in a range (for sync)
    pub fn get_headers_range(&self, start: u64, count: u64) -> Vec<BlockHeader> {
        let mut headers = Vec::with_capacity(count as usize);
        for height in start..start + count {
            if let Some(header) = self.get_canonical_header(height) {
                headers.push(header);
            } else {
                break;
            }
        }
        headers
    }

    /// Calculate total difficulty from genesis to a header
    pub fn total_difficulty_to(&self, hash: &[u8; 32]) -> Option<u128> {
        let mut total: u128 = 0;
        let mut current_hash = *hash;

        loop {
            let header = self.get_header(&current_hash)?;
            total += header.difficulty as u128;

            if header.height == 0 {
                break;
            }
            current_hash = header.parent_hash;
        }

        Some(total)
    }

    /// Update the chain tip if the new header creates a better chain
    fn maybe_update_tip(&self, header: &BlockHeader) -> LightClientResult<()> {
        let new_total_difficulty = self.total_difficulty_to(&header.hash).unwrap_or(0);

        let should_update = {
            let tip = self.tip.read();
            match tip.as_ref() {
                None => true,
                Some(current) => new_total_difficulty > current.total_difficulty,
            }
        };

        if should_update {
            let new_tip = ChainTip {
                header: header.clone(),
                total_difficulty: new_total_difficulty,
                chain_length: header.height + 1,
            };
            *self.tip.write() = Some(new_tip);
        }

        Ok(())
    }

    /// Prune old headers beyond the max limit
    fn prune_old_headers(&self) -> LightClientResult<()> {
        let tip_height = self.get_height();
        let prune_below = tip_height.saturating_sub(self.config.max_headers as u64);

        // Don't prune checkpointed headers
        let checkpoint_heights: Vec<_> = self.checkpoints.iter().map(|e| *e.key()).collect();

        for height in 0..prune_below {
            // Skip if this height has a checkpoint
            if checkpoint_heights.contains(&height) {
                continue;
            }

            if let Some((_, hashes)) = self.headers_by_height.remove(&height) {
                for hash in hashes {
                    self.headers_by_hash.remove(&hash);
                }
                let mut count = self.header_count.write();
                *count = count.saturating_sub(1);
            }
        }

        Ok(())
    }

    /// Get chain statistics
    pub fn stats(&self) -> ChainStats {
        let tip = self.tip.read();
        ChainStats {
            height: tip.as_ref().map(|t| t.header.height).unwrap_or(0),
            total_headers: *self.header_count.read(),
            total_difficulty: tip.as_ref().map(|t| t.total_difficulty).unwrap_or(0),
            checkpoints: self.checkpoints.len(),
            cache_size: self.cache.read().len(),
        }
    }
}

/// Chain statistics
#[derive(Debug, Clone)]
pub struct ChainStats {
    pub height: u64,
    pub total_headers: u64,
    pub total_difficulty: u128,
    pub checkpoints: usize,
    pub cache_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_header(height: u64, parent_hash: [u8; 32]) -> BlockHeader {
        BlockHeader::new(
            height,
            parent_hash,
            [1u8; 32], // state_root
            [2u8; 32], // tx_root
            [3u8; 32], // receipts_root
            1000 + height,
            [4u8; 32], // proposer
            1,
        )
    }

    #[test]
    fn test_header_hash() {
        let header = create_test_header(1, [0u8; 32]);
        assert!(header.verify_hash());
    }

    #[test]
    fn test_genesis_initialization() {
        let mut chain = HeaderChain::new(HeaderChainConfig::default());
        let genesis = chain.initialize_genesis(GenesisConfig::default()).unwrap();

        assert_eq!(genesis.height, 0);
        assert_eq!(chain.get_height(), 0);
        assert!(chain.get_tip().is_some());
    }

    #[test]
    fn test_header_insertion() {
        let config = HeaderChainConfig {
            verify_signatures: false,
            ..Default::default()
        };
        let mut chain = HeaderChain::new(config);
        let genesis = chain.initialize_genesis(GenesisConfig::default()).unwrap();

        // Insert child header
        let header1 = create_test_header(1, genesis.hash);
        chain.insert_header(header1.clone()).unwrap();

        assert_eq!(chain.get_height(), 1);
        assert!(chain.get_header(&header1.hash).is_some());
    }

    #[test]
    fn test_canonical_chain() {
        let config = HeaderChainConfig {
            verify_signatures: false,
            ..Default::default()
        };
        let mut chain = HeaderChain::new(config);
        let genesis = chain.initialize_genesis(GenesisConfig::default()).unwrap();

        // Build a chain of 5 headers
        let mut parent_hash = genesis.hash;
        for height in 1..=5 {
            let header = create_test_header(height, parent_hash);
            chain.insert_header(header.clone()).unwrap();
            parent_hash = header.hash;
        }

        assert_eq!(chain.get_height(), 5);

        // Verify canonical headers
        for height in 0..=5 {
            let header = chain.get_canonical_header(height);
            assert!(header.is_some());
            assert_eq!(header.unwrap().height, height);
        }
    }

    #[test]
    fn test_headers_range() {
        let config = HeaderChainConfig {
            verify_signatures: false,
            ..Default::default()
        };
        let mut chain = HeaderChain::new(config);
        let genesis = chain.initialize_genesis(GenesisConfig::default()).unwrap();

        // Build chain
        let mut parent_hash = genesis.hash;
        for height in 1..=10 {
            let header = create_test_header(height, parent_hash);
            chain.insert_header(header.clone()).unwrap();
            parent_hash = header.hash;
        }

        // Get range
        let headers = chain.get_headers_range(3, 5);
        assert_eq!(headers.len(), 5);
        assert_eq!(headers[0].height, 3);
        assert_eq!(headers[4].height, 7);
    }

    #[test]
    fn test_checkpoints() {
        let config = HeaderChainConfig {
            verify_signatures: false,
            ..Default::default()
        };
        let mut chain = HeaderChain::new(config);
        let genesis = chain.initialize_genesis(GenesisConfig::default()).unwrap();

        // Add checkpoint
        chain.add_checkpoint(0, genesis.hash);

        // Verify against checkpoint
        assert!(chain.verify_against_checkpoints(&genesis));

        // Invalid header at checkpoint height
        let mut fake_header = genesis.clone();
        fake_header.hash = [99u8; 32];
        assert!(!chain.verify_against_checkpoints(&fake_header));
    }

    #[test]
    fn test_invalid_parent() {
        let config = HeaderChainConfig {
            verify_signatures: false,
            ..Default::default()
        };
        let mut chain = HeaderChain::new(config);
        chain.initialize_genesis(GenesisConfig::default()).unwrap();

        // Try to insert header with non-existent parent
        let orphan = create_test_header(1, [99u8; 32]);
        let result = chain.insert_header(orphan);

        assert!(matches!(result, Err(LightClientError::InvalidParentHash { .. })));
    }
}
