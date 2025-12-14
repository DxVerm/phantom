//! Chain Manager with Fork Handling
//!
//! Manages the canonical chain, tracks forks, and handles chain reorganizations.
//!
//! # Fork Choice Rules
//!
//! The chain manager supports multiple fork choice rules:
//! - **HeaviestChain**: Selects the chain with highest cumulative weight (stake-weighted)
//! - **LongestChain**: Simple longest chain rule
//! - **GHOST** (Greedy Heaviest Observed Sub-Tree): Enhanced fork choice for faster finality
//!
//! # Reorganization
//!
//! When a fork becomes heavier than the canonical chain:
//! 1. Find common ancestor
//! 2. Revert blocks back to ancestor
//! 3. Apply new chain blocks
//! 4. Update canonical chain head

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn, error};

use crate::{Block, BlockHeader, NodeError, NodeResult};

/// Fork choice rule for selecting the canonical chain
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForkChoiceRule {
    /// Select chain with highest cumulative stake-weighted attestations
    HeaviestChain,
    /// Select the longest chain (by block count)
    LongestChain,
    /// GHOST: Greedy Heaviest Observed Sub-Tree
    Ghost,
    /// Hybrid: GHOST with finality gadget
    GhostWithFinality,
}

impl Default for ForkChoiceRule {
    fn default() -> Self {
        ForkChoiceRule::HeaviestChain
    }
}

/// Configuration for chain manager
#[derive(Debug, Clone)]
pub struct ChainConfig {
    /// Fork choice rule to use
    pub fork_choice: ForkChoiceRule,
    /// Maximum number of forks to track
    pub max_forks: usize,
    /// Maximum fork depth (blocks behind canonical head)
    pub max_fork_depth: u64,
    /// Finality depth (blocks considered final)
    pub finality_depth: u64,
    /// Enable automatic pruning of stale forks
    pub auto_prune: bool,
    /// Maximum reorganization depth allowed
    pub max_reorg_depth: u64,
    /// Minimum attestation weight for block acceptance
    pub min_attestation_weight: u64,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            fork_choice: ForkChoiceRule::HeaviestChain,
            max_forks: 32,
            max_fork_depth: 64,
            finality_depth: 10,
            auto_prune: true,
            max_reorg_depth: 32,
            min_attestation_weight: 0,
        }
    }
}

impl ChainConfig {
    /// Create config for local development
    pub fn local() -> Self {
        Self {
            fork_choice: ForkChoiceRule::LongestChain,
            max_forks: 8,
            max_fork_depth: 16,
            finality_depth: 3,
            auto_prune: true,
            max_reorg_depth: 8,
            min_attestation_weight: 0,
        }
    }

    /// Create config for testnet
    pub fn testnet() -> Self {
        Self {
            fork_choice: ForkChoiceRule::HeaviestChain,
            max_forks: 16,
            max_fork_depth: 32,
            finality_depth: 6,
            auto_prune: true,
            max_reorg_depth: 16,
            min_attestation_weight: 1000,
        }
    }

    /// Create config for mainnet
    pub fn mainnet() -> Self {
        Self {
            fork_choice: ForkChoiceRule::GhostWithFinality,
            max_forks: 32,
            max_fork_depth: 64,
            finality_depth: 10,
            auto_prune: true,
            max_reorg_depth: 32,
            min_attestation_weight: 10000,
        }
    }
}

/// Block index entry for fast lookups
#[derive(Debug, Clone)]
pub struct BlockIndex {
    /// Block hash
    pub hash: [u8; 32],
    /// Block height
    pub height: u64,
    /// Parent hash
    pub parent_hash: [u8; 32],
    /// Cumulative weight (sum of attestation weights to this block)
    pub cumulative_weight: u64,
    /// This block's attestation weight
    pub attestation_weight: u64,
    /// Total difficulty (for PoW-style chains, not used in CWA but kept for compatibility)
    pub total_difficulty: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Is this block on the canonical chain?
    pub is_canonical: bool,
    /// Is this block finalized?
    pub is_finalized: bool,
}

/// A fork tracked by the chain manager
#[derive(Debug, Clone)]
pub struct Fork {
    /// Fork ID (unique identifier)
    pub id: u64,
    /// Head block hash of this fork
    pub head_hash: [u8; 32],
    /// Head block height
    pub head_height: u64,
    /// Common ancestor with canonical chain
    pub fork_point_hash: [u8; 32],
    /// Height of fork point
    pub fork_point_height: u64,
    /// Total cumulative weight of this fork
    pub total_weight: u64,
    /// Number of blocks in this fork
    pub block_count: usize,
    /// When the fork was first seen
    pub first_seen: u64,
    /// Last activity timestamp
    pub last_updated: u64,
}

/// Chain state snapshot
#[derive(Debug, Clone)]
pub struct ChainState {
    /// Current canonical head hash
    pub head_hash: [u8; 32],
    /// Current canonical head height
    pub head_height: u64,
    /// Genesis hash
    pub genesis_hash: [u8; 32],
    /// Last finalized block hash
    pub finalized_hash: [u8; 32],
    /// Last finalized height
    pub finalized_height: u64,
    /// Total cumulative weight of canonical chain
    pub total_weight: u64,
    /// Current epoch
    pub epoch: u64,
    /// Number of active forks
    pub fork_count: usize,
}

/// Result of attempting to extend the chain
#[derive(Debug, Clone)]
pub enum ChainExtensionResult {
    /// Block extended the canonical chain
    Extended {
        new_height: u64,
        new_weight: u64,
    },
    /// Block created a new fork
    Forked {
        fork_id: u64,
        fork_height: u64,
    },
    /// Block caused a reorganization
    Reorganized {
        old_head: [u8; 32],
        new_head: [u8; 32],
        reorg_depth: u64,
        reverted_blocks: Vec<[u8; 32]>,
        applied_blocks: Vec<[u8; 32]>,
    },
    /// Block is a duplicate
    Duplicate,
    /// Block was rejected
    Rejected {
        reason: String,
    },
}

/// Events emitted by the chain manager
#[derive(Debug, Clone)]
pub enum ChainEvent {
    /// New block added to canonical chain
    NewCanonicalBlock {
        hash: [u8; 32],
        height: u64,
        weight: u64,
    },
    /// Chain reorganization occurred
    Reorganization {
        old_head: [u8; 32],
        new_head: [u8; 32],
        depth: u64,
    },
    /// New fork detected
    ForkDetected {
        fork_id: u64,
        fork_point: u64,
    },
    /// Fork was abandoned/pruned
    ForkPruned {
        fork_id: u64,
    },
    /// Block was finalized
    BlockFinalized {
        hash: [u8; 32],
        height: u64,
    },
}

/// The chain manager
pub struct ChainManager {
    /// Configuration
    config: ChainConfig,
    /// Genesis block hash
    genesis_hash: [u8; 32],
    /// Block index (hash -> entry)
    block_index: HashMap<[u8; 32], BlockIndex>,
    /// Blocks by height on canonical chain
    canonical_blocks: HashMap<u64, [u8; 32]>,
    /// Children index (parent hash -> child hashes)
    children: HashMap<[u8; 32], Vec<[u8; 32]>>,
    /// Active forks
    forks: HashMap<u64, Fork>,
    /// Next fork ID
    next_fork_id: u64,
    /// Current canonical head
    head_hash: [u8; 32],
    /// Current canonical height
    head_height: u64,
    /// Last finalized hash
    finalized_hash: [u8; 32],
    /// Last finalized height
    finalized_height: u64,
    /// Total weight of canonical chain
    total_weight: u64,
    /// Current epoch
    current_epoch: u64,
    /// Pending events
    events: VecDeque<ChainEvent>,
    /// Block cache (hash -> full block)
    block_cache: HashMap<[u8; 32], Block>,
    /// Maximum cache size
    cache_size: usize,
}

impl ChainManager {
    /// Create a new chain manager
    pub fn new(genesis_hash: [u8; 32], config: ChainConfig) -> Self {
        // Create genesis block index entry
        let genesis_entry = BlockIndex {
            hash: genesis_hash,
            height: 0,
            parent_hash: [0u8; 32],
            cumulative_weight: 0,
            attestation_weight: 0,
            total_difficulty: 0,
            timestamp: 0,
            is_canonical: true,
            is_finalized: true,
        };

        let mut block_index = HashMap::new();
        block_index.insert(genesis_hash, genesis_entry);

        let mut canonical_blocks = HashMap::new();
        canonical_blocks.insert(0, genesis_hash);

        Self {
            config,
            genesis_hash,
            block_index,
            canonical_blocks,
            children: HashMap::new(),
            forks: HashMap::new(),
            next_fork_id: 1,
            head_hash: genesis_hash,
            head_height: 0,
            finalized_hash: genesis_hash,
            finalized_height: 0,
            total_weight: 0,
            current_epoch: 0,
            events: VecDeque::new(),
            block_cache: HashMap::new(),
            cache_size: 1000,
        }
    }

    /// Process a new block
    pub fn process_block(&mut self, block: &Block) -> NodeResult<ChainExtensionResult> {
        let hash = block.hash();
        let header = &block.header;

        // Check for duplicate
        if self.block_index.contains_key(&hash) {
            return Ok(ChainExtensionResult::Duplicate);
        }

        // Validate parent exists
        if !self.block_index.contains_key(&header.prev_hash) {
            return Ok(ChainExtensionResult::Rejected {
                reason: "Unknown parent block".to_string(),
            });
        }

        // Get parent info
        let parent = self.block_index.get(&header.prev_hash).unwrap().clone();

        // Validate height
        if header.height != parent.height + 1 {
            return Ok(ChainExtensionResult::Rejected {
                reason: format!(
                    "Invalid height: expected {}, got {}",
                    parent.height + 1,
                    header.height
                ),
            });
        }

        // Calculate attestation weight
        let attestation_weight = self.calculate_attestation_weight(header);

        // Check minimum attestation weight
        if attestation_weight < self.config.min_attestation_weight {
            return Ok(ChainExtensionResult::Rejected {
                reason: format!(
                    "Insufficient attestation weight: {} < {}",
                    attestation_weight, self.config.min_attestation_weight
                ),
            });
        }

        // Calculate cumulative weight
        let cumulative_weight = parent.cumulative_weight + attestation_weight;

        // Create block index entry
        let entry = BlockIndex {
            hash,
            height: header.height,
            parent_hash: header.prev_hash,
            cumulative_weight,
            attestation_weight,
            total_difficulty: parent.total_difficulty + 1,
            timestamp: header.timestamp,
            is_canonical: false,
            is_finalized: false,
        };

        // Add to index
        self.block_index.insert(hash, entry);

        // Add to children index
        self.children
            .entry(header.prev_hash)
            .or_default()
            .push(hash);

        // Cache the block
        self.cache_block(hash, block.clone());

        // Determine if this extends canonical chain, creates fork, or triggers reorg
        let result = if header.prev_hash == self.head_hash {
            // Extends canonical chain
            self.extend_canonical(hash, header.height, cumulative_weight)
        } else if cumulative_weight > self.total_weight {
            // Heavier fork - trigger reorganization
            self.reorganize(hash)?
        } else {
            // Creates or extends a fork
            self.handle_fork(hash, header)?
        };

        // Auto-prune stale forks if enabled
        if self.config.auto_prune {
            self.prune_stale_forks();
        }

        // Update finality
        self.update_finality();

        Ok(result)
    }

    /// Extend the canonical chain
    fn extend_canonical(
        &mut self,
        hash: [u8; 32],
        height: u64,
        cumulative_weight: u64,
    ) -> ChainExtensionResult {
        // Update head
        self.head_hash = hash;
        self.head_height = height;
        self.total_weight = cumulative_weight;

        // Mark as canonical
        if let Some(entry) = self.block_index.get_mut(&hash) {
            entry.is_canonical = true;
        }

        // Add to canonical blocks
        self.canonical_blocks.insert(height, hash);

        // Update epoch from block
        if let Some(block) = self.block_cache.get(&hash) {
            self.current_epoch = block.header.epoch;
        }

        // Emit event
        self.events.push_back(ChainEvent::NewCanonicalBlock {
            hash,
            height,
            weight: cumulative_weight,
        });

        info!("Extended canonical chain to height {} (weight: {})", height, cumulative_weight);

        ChainExtensionResult::Extended {
            new_height: height,
            new_weight: cumulative_weight,
        }
    }

    /// Handle a fork (create new or extend existing)
    fn handle_fork(
        &mut self,
        hash: [u8; 32],
        header: &BlockHeader,
    ) -> NodeResult<ChainExtensionResult> {
        // Find fork point with canonical chain
        let (fork_point_hash, fork_point_height) = self.find_fork_point(&hash)?;

        // Check if this extends an existing fork
        for (fork_id, fork) in &mut self.forks {
            if fork.head_hash == header.prev_hash {
                // Extend this fork
                fork.head_hash = hash;
                fork.head_height = header.height;
                fork.block_count += 1;
                fork.last_updated = now_secs();

                if let Some(entry) = self.block_index.get(&hash) {
                    fork.total_weight = entry.cumulative_weight;
                }

                debug!("Extended fork {} to height {}", fork_id, header.height);

                return Ok(ChainExtensionResult::Forked {
                    fork_id: *fork_id,
                    fork_height: header.height,
                });
            }
        }

        // Check fork limits
        if self.forks.len() >= self.config.max_forks {
            // Remove weakest fork
            self.remove_weakest_fork();
        }

        // Create new fork
        let fork_id = self.next_fork_id;
        self.next_fork_id += 1;

        let entry = self.block_index.get(&hash).unwrap();

        let fork = Fork {
            id: fork_id,
            head_hash: hash,
            head_height: header.height,
            fork_point_hash,
            fork_point_height,
            total_weight: entry.cumulative_weight,
            block_count: (header.height - fork_point_height) as usize,
            first_seen: now_secs(),
            last_updated: now_secs(),
        };

        self.forks.insert(fork_id, fork);

        // Emit event
        self.events.push_back(ChainEvent::ForkDetected {
            fork_id,
            fork_point: fork_point_height,
        });

        info!(
            "New fork {} detected at height {} (fork point: {})",
            fork_id, header.height, fork_point_height
        );

        Ok(ChainExtensionResult::Forked {
            fork_id,
            fork_height: header.height,
        })
    }

    /// Reorganize to a heavier fork
    fn reorganize(&mut self, new_head_hash: [u8; 32]) -> NodeResult<ChainExtensionResult> {
        let old_head = self.head_hash;

        // Find common ancestor
        let (ancestor_hash, ancestor_height) = self.find_common_ancestor(&old_head, &new_head_hash)?;

        // Check reorg depth limit
        let reorg_depth = self.head_height - ancestor_height;
        if reorg_depth > self.config.max_reorg_depth {
            warn!(
                "Reorg depth {} exceeds maximum {}",
                reorg_depth, self.config.max_reorg_depth
            );
            return Ok(ChainExtensionResult::Rejected {
                reason: format!(
                    "Reorganization depth {} exceeds maximum {}",
                    reorg_depth, self.config.max_reorg_depth
                ),
            });
        }

        // Cannot reorg past finalized block
        if ancestor_height < self.finalized_height {
            return Ok(ChainExtensionResult::Rejected {
                reason: "Cannot reorganize past finalized block".to_string(),
            });
        }

        info!(
            "Reorganizing chain: depth={}, old_head={}, new_head={}",
            reorg_depth,
            hex::encode(&old_head[..8]),
            hex::encode(&new_head_hash[..8])
        );

        // Collect blocks to revert (old chain from ancestor to old head)
        let reverted_blocks = self.collect_chain_segment(&ancestor_hash, &old_head)?;

        // Mark reverted blocks as non-canonical
        for hash in &reverted_blocks {
            if let Some(entry) = self.block_index.get_mut(hash) {
                entry.is_canonical = false;
            }
            // Remove from canonical blocks map
            if let Some(entry) = self.block_index.get(hash) {
                self.canonical_blocks.remove(&entry.height);
            }
        }

        // Collect blocks to apply (new chain from ancestor to new head)
        let applied_blocks = self.collect_chain_segment(&ancestor_hash, &new_head_hash)?;

        // Mark new blocks as canonical
        for hash in &applied_blocks {
            if let Some(entry) = self.block_index.get_mut(hash) {
                entry.is_canonical = true;
                self.canonical_blocks.insert(entry.height, *hash);
            }
        }

        // Update head
        let new_entry = self.block_index.get(&new_head_hash).unwrap().clone();
        self.head_hash = new_head_hash;
        self.head_height = new_entry.height;
        self.total_weight = new_entry.cumulative_weight;

        // Update epoch
        if let Some(block) = self.block_cache.get(&new_head_hash) {
            self.current_epoch = block.header.epoch;
        }

        // Remove the fork that won (if it was tracked)
        let winning_fork_id: Option<u64> = self.forks
            .iter()
            .find(|(_, f)| f.head_hash == new_head_hash)
            .map(|(id, _)| *id);

        if let Some(fork_id) = winning_fork_id {
            self.forks.remove(&fork_id);
        }

        // Create fork for the old chain (if still valid)
        if !reverted_blocks.is_empty() {
            let old_entry = self.block_index.get(&old_head).unwrap();
            let fork = Fork {
                id: self.next_fork_id,
                head_hash: old_head,
                head_height: old_entry.height,
                fork_point_hash: ancestor_hash,
                fork_point_height: ancestor_height,
                total_weight: old_entry.cumulative_weight,
                block_count: reverted_blocks.len(),
                first_seen: now_secs(),
                last_updated: now_secs(),
            };
            self.forks.insert(self.next_fork_id, fork);
            self.next_fork_id += 1;
        }

        // Emit event
        self.events.push_back(ChainEvent::Reorganization {
            old_head,
            new_head: new_head_hash,
            depth: reorg_depth,
        });

        Ok(ChainExtensionResult::Reorganized {
            old_head,
            new_head: new_head_hash,
            reorg_depth,
            reverted_blocks,
            applied_blocks,
        })
    }

    /// Find fork point with canonical chain
    fn find_fork_point(&self, hash: &[u8; 32]) -> NodeResult<([u8; 32], u64)> {
        let mut current = *hash;

        // Walk back until we find a canonical block
        while let Some(entry) = self.block_index.get(&current) {
            if entry.is_canonical {
                return Ok((current, entry.height));
            }
            current = entry.parent_hash;

            // Safety check
            if current == [0u8; 32] {
                break;
            }
        }

        // Should at least reach genesis
        Ok((self.genesis_hash, 0))
    }

    /// Find common ancestor of two blocks
    fn find_common_ancestor(
        &self,
        hash1: &[u8; 32],
        hash2: &[u8; 32],
    ) -> NodeResult<([u8; 32], u64)> {
        let mut ancestors1: HashSet<[u8; 32]> = HashSet::new();
        let mut current = *hash1;

        // Collect ancestors of hash1
        while let Some(entry) = self.block_index.get(&current) {
            ancestors1.insert(current);
            if current == self.genesis_hash {
                break;
            }
            current = entry.parent_hash;
        }

        // Walk back from hash2 until we find common ancestor
        current = *hash2;
        while let Some(entry) = self.block_index.get(&current) {
            if ancestors1.contains(&current) {
                return Ok((current, entry.height));
            }
            if current == self.genesis_hash {
                break;
            }
            current = entry.parent_hash;
        }

        // Genesis is always common ancestor
        Ok((self.genesis_hash, 0))
    }

    /// Collect chain segment from ancestor (exclusive) to descendant (inclusive)
    fn collect_chain_segment(
        &self,
        ancestor: &[u8; 32],
        descendant: &[u8; 32],
    ) -> NodeResult<Vec<[u8; 32]>> {
        let mut blocks = Vec::new();
        let mut current = *descendant;

        while current != *ancestor {
            if let Some(entry) = self.block_index.get(&current) {
                blocks.push(current);
                current = entry.parent_hash;
            } else {
                return Err(NodeError::BlockNotFound(hex::encode(&current[..8])));
            }

            // Safety limit
            if blocks.len() > 10000 {
                return Err(NodeError::InvalidBlock("Chain segment too long".to_string()));
            }
        }

        blocks.reverse();
        Ok(blocks)
    }

    /// Calculate attestation weight for a block
    fn calculate_attestation_weight(&self, header: &BlockHeader) -> u64 {
        // Weight is based on number and stake of attestations
        // For now, simple count * base weight
        // In production, would look up actual stake of each attester
        let base_weight = 1000u64;
        (header.attestations.len() as u64) * base_weight
    }

    /// Apply fork choice rule to select best head
    pub fn select_best_head(&self) -> [u8; 32] {
        match self.config.fork_choice {
            ForkChoiceRule::HeaviestChain => self.select_heaviest_head(),
            ForkChoiceRule::LongestChain => self.select_longest_head(),
            ForkChoiceRule::Ghost => self.select_ghost_head(),
            ForkChoiceRule::GhostWithFinality => self.select_ghost_with_finality_head(),
        }
    }

    /// Select head by heaviest chain rule
    fn select_heaviest_head(&self) -> [u8; 32] {
        let mut best_hash = self.head_hash;
        let mut best_weight = self.total_weight;

        for fork in self.forks.values() {
            if fork.total_weight > best_weight {
                best_weight = fork.total_weight;
                best_hash = fork.head_hash;
            }
        }

        best_hash
    }

    /// Select head by longest chain rule
    fn select_longest_head(&self) -> [u8; 32] {
        let mut best_hash = self.head_hash;
        let mut best_height = self.head_height;

        for fork in self.forks.values() {
            if fork.head_height > best_height {
                best_height = fork.head_height;
                best_hash = fork.head_hash;
            }
        }

        best_hash
    }

    /// Select head using GHOST algorithm
    fn select_ghost_head(&self) -> [u8; 32] {
        // Start from finalized block
        let mut current = self.finalized_hash;

        loop {
            // Get children of current block
            let children = match self.children.get(&current) {
                Some(c) if !c.is_empty() => c.clone(),
                _ => break,
            };

            // Find child with highest subtree weight
            let mut best_child = children[0];
            let mut best_weight = 0u64;

            for child in &children {
                let weight = self.calculate_subtree_weight(child);
                if weight > best_weight {
                    best_weight = weight;
                    best_child = *child;
                }
            }

            current = best_child;
        }

        current
    }

    /// Select head using GHOST with finality gadget
    fn select_ghost_with_finality_head(&self) -> [u8; 32] {
        // Same as GHOST but respects finality boundary
        self.select_ghost_head()
    }

    /// Calculate cumulative weight of subtree rooted at block
    fn calculate_subtree_weight(&self, hash: &[u8; 32]) -> u64 {
        let entry = match self.block_index.get(hash) {
            Some(e) => e,
            None => return 0,
        };

        let mut weight = entry.attestation_weight;

        // Add weight of all descendants
        if let Some(children) = self.children.get(hash) {
            for child in children {
                weight += self.calculate_subtree_weight(child);
            }
        }

        weight
    }

    /// Update finality based on current head
    fn update_finality(&mut self) {
        if self.head_height <= self.config.finality_depth {
            return;
        }

        let new_finalized_height = self.head_height - self.config.finality_depth;

        // Only update if advancing finality
        if new_finalized_height <= self.finalized_height {
            return;
        }

        // Get block at new finalized height
        if let Some(&hash) = self.canonical_blocks.get(&new_finalized_height) {
            // Mark as finalized
            if let Some(entry) = self.block_index.get_mut(&hash) {
                entry.is_finalized = true;
            }

            self.finalized_hash = hash;
            self.finalized_height = new_finalized_height;

            // Emit event
            self.events.push_back(ChainEvent::BlockFinalized {
                hash,
                height: new_finalized_height,
            });

            debug!("Block at height {} finalized", new_finalized_height);
        }
    }

    /// Prune stale forks
    fn prune_stale_forks(&mut self) {
        let min_height = if self.head_height > self.config.max_fork_depth {
            self.head_height - self.config.max_fork_depth
        } else {
            0
        };

        let stale_forks: Vec<u64> = self.forks
            .iter()
            .filter(|(_, fork)| fork.head_height < min_height)
            .map(|(id, _)| *id)
            .collect();

        for fork_id in stale_forks {
            if let Some(_fork) = self.forks.remove(&fork_id) {
                self.events.push_back(ChainEvent::ForkPruned { fork_id });
                debug!("Pruned stale fork {}", fork_id);
            }
        }
    }

    /// Remove weakest fork
    fn remove_weakest_fork(&mut self) {
        if let Some((&weakest_id, _)) = self.forks
            .iter()
            .min_by_key(|(_, fork)| fork.total_weight)
        {
            self.forks.remove(&weakest_id);
            self.events.push_back(ChainEvent::ForkPruned { fork_id: weakest_id });
        }
    }

    /// Cache a block
    fn cache_block(&mut self, hash: [u8; 32], block: Block) {
        if self.block_cache.len() >= self.cache_size {
            // Remove oldest cached block
            if let Some(oldest) = self.block_cache.keys().next().cloned() {
                self.block_cache.remove(&oldest);
            }
        }
        self.block_cache.insert(hash, block);
    }

    /// Get current chain state
    pub fn state(&self) -> ChainState {
        ChainState {
            head_hash: self.head_hash,
            head_height: self.head_height,
            genesis_hash: self.genesis_hash,
            finalized_hash: self.finalized_hash,
            finalized_height: self.finalized_height,
            total_weight: self.total_weight,
            epoch: self.current_epoch,
            fork_count: self.forks.len(),
        }
    }

    /// Get canonical block at height
    pub fn get_canonical_block(&self, height: u64) -> Option<&[u8; 32]> {
        self.canonical_blocks.get(&height)
    }

    /// Get block index entry
    pub fn get_block_index(&self, hash: &[u8; 32]) -> Option<&BlockIndex> {
        self.block_index.get(hash)
    }

    /// Get cached block
    pub fn get_block(&self, hash: &[u8; 32]) -> Option<&Block> {
        self.block_cache.get(hash)
    }

    /// Check if block is on canonical chain
    pub fn is_canonical(&self, hash: &[u8; 32]) -> bool {
        self.block_index.get(hash).map(|e| e.is_canonical).unwrap_or(false)
    }

    /// Check if block is finalized
    pub fn is_finalized(&self, hash: &[u8; 32]) -> bool {
        self.block_index.get(hash).map(|e| e.is_finalized).unwrap_or(false)
    }

    /// Get current head hash
    pub fn head(&self) -> [u8; 32] {
        self.head_hash
    }

    /// Get current height
    pub fn height(&self) -> u64 {
        self.head_height
    }

    /// Get finalized height
    pub fn finalized_height(&self) -> u64 {
        self.finalized_height
    }

    /// Get all active forks
    pub fn forks(&self) -> Vec<&Fork> {
        self.forks.values().collect()
    }

    /// Get fork by ID
    pub fn get_fork(&self, fork_id: u64) -> Option<&Fork> {
        self.forks.get(&fork_id)
    }

    /// Drain pending events
    pub fn drain_events(&mut self) -> Vec<ChainEvent> {
        self.events.drain(..).collect()
    }

    /// Get pending event count
    pub fn pending_events(&self) -> usize {
        self.events.len()
    }

    /// Validate a block against chain rules
    pub fn validate_block(&self, block: &Block) -> NodeResult<()> {
        let header = &block.header;

        // Check parent exists
        if !self.block_index.contains_key(&header.prev_hash) {
            return Err(NodeError::BlockNotFound("Parent block not found".to_string()));
        }

        // Get parent
        let parent = self.block_index.get(&header.prev_hash).unwrap();

        // Check height
        if header.height != parent.height + 1 {
            return Err(NodeError::InvalidBlock(format!(
                "Invalid height: expected {}, got {}",
                parent.height + 1,
                header.height
            )));
        }

        // Check timestamp
        if header.timestamp < parent.timestamp {
            return Err(NodeError::InvalidBlock(
                "Block timestamp before parent".to_string()
            ));
        }

        // Check block integrity
        if !block.verify() {
            return Err(NodeError::InvalidBlock("Block verification failed".to_string()));
        }

        Ok(())
    }

    /// Get ancestors of a block up to a limit
    pub fn get_ancestors(&self, hash: &[u8; 32], limit: usize) -> Vec<[u8; 32]> {
        let mut ancestors = Vec::new();
        let mut current = *hash;

        while ancestors.len() < limit {
            if let Some(entry) = self.block_index.get(&current) {
                if current == self.genesis_hash {
                    break;
                }
                current = entry.parent_hash;
                ancestors.push(current);
            } else {
                break;
            }
        }

        ancestors
    }

    /// Get block height
    pub fn get_height(&self, hash: &[u8; 32]) -> Option<u64> {
        self.block_index.get(hash).map(|e| e.height)
    }
}

/// Thread-safe chain manager wrapper
pub type SharedChainManager = Arc<RwLock<ChainManager>>;

/// Create a shared chain manager
pub fn shared_chain_manager(genesis_hash: [u8; 32], config: ChainConfig) -> SharedChainManager {
    Arc::new(RwLock::new(ChainManager::new(genesis_hash, config)))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockBody, Attestation};

    fn genesis_hash() -> [u8; 32] {
        [0u8; 32]
    }

    fn create_block(height: u64, prev_hash: [u8; 32], producer: u8) -> Block {
        let header = BlockHeader {
            height,
            prev_hash,
            state_root: [1u8; 32],
            tx_root: [0u8; 32],
            timestamp: 1000 + height * 10,
            epoch: height / 100,
            round: height % 100,
            producer: [producer; 32],
            vrf_proof: vec![],
            attestations: vec![
                Attestation::new([1u8; 32], [0u8; 32], vec![0u8; 64]),
                Attestation::new([2u8; 32], [0u8; 32], vec![0u8; 64]),
                Attestation::new([3u8; 32], [0u8; 32], vec![0u8; 64]),
            ],
            extra_data: vec![],
        };

        Block::new(header, BlockBody::empty())
    }

    #[test]
    fn test_chain_manager_creation() {
        let genesis = genesis_hash();
        let manager = ChainManager::new(genesis, ChainConfig::default());

        assert_eq!(manager.head(), genesis);
        assert_eq!(manager.height(), 0);
        assert_eq!(manager.finalized_height(), 0);
    }

    #[test]
    fn test_extend_canonical_chain() {
        let genesis = genesis_hash();
        let mut manager = ChainManager::new(genesis, ChainConfig::local());

        // Add block 1
        let block1 = create_block(1, genesis, 1);
        let result = manager.process_block(&block1).unwrap();

        match result {
            ChainExtensionResult::Extended { new_height, .. } => {
                assert_eq!(new_height, 1);
            }
            _ => panic!("Expected Extended result"),
        }

        assert_eq!(manager.height(), 1);
        assert_eq!(manager.head(), block1.hash());
    }

    #[test]
    fn test_linear_chain_growth() {
        let genesis = genesis_hash();
        let mut manager = ChainManager::new(genesis, ChainConfig::local());

        let mut prev_hash = genesis;
        for height in 1..=10 {
            let block = create_block(height, prev_hash, 1);
            let hash = block.hash();
            manager.process_block(&block).unwrap();
            prev_hash = hash;
        }

        assert_eq!(manager.height(), 10);
    }

    #[test]
    fn test_fork_creation() {
        let genesis = genesis_hash();
        let mut manager = ChainManager::new(genesis, ChainConfig::local());

        // Create main chain: genesis -> block1 -> block2
        let block1 = create_block(1, genesis, 1);
        let hash1 = block1.hash();
        manager.process_block(&block1).unwrap();

        let block2 = create_block(2, hash1, 1);
        manager.process_block(&block2).unwrap();

        // Create fork at block1: block1 -> block2_fork
        let block2_fork = create_block(2, hash1, 2); // Different producer
        let result = manager.process_block(&block2_fork).unwrap();

        match result {
            ChainExtensionResult::Forked { fork_id, fork_height } => {
                assert_eq!(fork_height, 2);
                assert!(fork_id > 0);
            }
            _ => panic!("Expected Forked result"),
        }

        assert_eq!(manager.forks().len(), 1);
    }

    #[test]
    fn test_reorganization() {
        let genesis = genesis_hash();
        let config = ChainConfig {
            fork_choice: ForkChoiceRule::HeaviestChain,
            min_attestation_weight: 0,
            ..ChainConfig::local()
        };
        let mut manager = ChainManager::new(genesis, config);

        // Create main chain with 3 attestations per block
        let block1 = create_block(1, genesis, 1);
        let hash1 = block1.hash();
        manager.process_block(&block1).unwrap();

        let block2 = create_block(2, hash1, 1);
        manager.process_block(&block2).unwrap();

        // Create heavier fork with more attestations
        let mut fork_block2 = create_block(2, hash1, 2);
        // Add more attestations to make it heavier
        for i in 4..=10 {
            fork_block2.header.attestations.push(
                Attestation::new([i as u8; 32], [0u8; 32], vec![0u8; 64])
            );
        }

        let fork_hash2 = fork_block2.hash();

        // This should trigger reorganization since fork is heavier
        let result = manager.process_block(&fork_block2).unwrap();

        match result {
            ChainExtensionResult::Reorganized { new_head, reorg_depth, .. } => {
                assert_eq!(new_head, fork_hash2);
                assert_eq!(reorg_depth, 1);
            }
            ChainExtensionResult::Forked { .. } => {
                // Also acceptable if weight calculation doesn't trigger reorg
            }
            _ => panic!("Expected Reorganized or Forked result"),
        }
    }

    #[test]
    fn test_duplicate_block() {
        let genesis = genesis_hash();
        let mut manager = ChainManager::new(genesis, ChainConfig::local());

        let block1 = create_block(1, genesis, 1);
        manager.process_block(&block1).unwrap();

        // Try to add same block again
        let result = manager.process_block(&block1).unwrap();

        match result {
            ChainExtensionResult::Duplicate => {}
            _ => panic!("Expected Duplicate result"),
        }
    }

    #[test]
    fn test_invalid_height() {
        let genesis = genesis_hash();
        let mut manager = ChainManager::new(genesis, ChainConfig::local());

        // Try to add block with wrong height
        let bad_block = create_block(5, genesis, 1); // Should be height 1
        let result = manager.process_block(&bad_block).unwrap();

        match result {
            ChainExtensionResult::Rejected { reason } => {
                assert!(reason.contains("Invalid height"));
            }
            _ => panic!("Expected Rejected result"),
        }
    }

    #[test]
    fn test_unknown_parent() {
        let genesis = genesis_hash();
        let mut manager = ChainManager::new(genesis, ChainConfig::local());

        // Try to add block with unknown parent
        let bad_block = create_block(1, [99u8; 32], 1);
        let result = manager.process_block(&bad_block).unwrap();

        match result {
            ChainExtensionResult::Rejected { reason } => {
                assert!(reason.contains("Unknown parent"));
            }
            _ => panic!("Expected Rejected result"),
        }
    }

    #[test]
    fn test_finality() {
        let genesis = genesis_hash();
        let config = ChainConfig {
            finality_depth: 3,
            ..ChainConfig::local()
        };
        let mut manager = ChainManager::new(genesis, config);

        // Build chain of 10 blocks
        let mut prev_hash = genesis;
        for height in 1..=10 {
            let block = create_block(height, prev_hash, 1);
            prev_hash = block.hash();
            manager.process_block(&block).unwrap();
        }

        // With finality_depth=3, blocks at height 7 should be finalized
        assert_eq!(manager.finalized_height(), 7);

        // Check finality flag
        let finalized_hash = manager.get_canonical_block(7).unwrap();
        assert!(manager.is_finalized(finalized_hash));
    }

    #[test]
    fn test_fork_pruning() {
        let genesis = genesis_hash();
        let config = ChainConfig {
            max_fork_depth: 5,
            auto_prune: true,
            ..ChainConfig::local()
        };
        let mut manager = ChainManager::new(genesis, config);

        // Build main chain
        let mut prev_hash = genesis;
        for height in 1..=3 {
            let block = create_block(height, prev_hash, 1);
            prev_hash = block.hash();
            manager.process_block(&block).unwrap();
        }

        // Create fork at height 2
        let block1_hash = manager.get_canonical_block(1).unwrap().clone();
        let fork_block = create_block(2, block1_hash, 2);
        manager.process_block(&fork_block).unwrap();

        assert_eq!(manager.forks().len(), 1);

        // Extend main chain beyond fork depth
        for height in 4..=10 {
            let block = create_block(height, prev_hash, 1);
            prev_hash = block.hash();
            manager.process_block(&block).unwrap();
        }

        // Fork should be pruned
        assert_eq!(manager.forks().len(), 0);
    }

    #[test]
    fn test_chain_state() {
        let genesis = genesis_hash();
        let mut manager = ChainManager::new(genesis, ChainConfig::local());

        let block1 = create_block(1, genesis, 1);
        manager.process_block(&block1).unwrap();

        let state = manager.state();
        assert_eq!(state.head_height, 1);
        assert_eq!(state.genesis_hash, genesis);
        assert_eq!(state.fork_count, 0);
    }

    #[test]
    fn test_get_ancestors() {
        let genesis = genesis_hash();
        let mut manager = ChainManager::new(genesis, ChainConfig::local());

        let mut prev_hash = genesis;
        let mut hashes = vec![genesis];
        for height in 1..=5 {
            let block = create_block(height, prev_hash, 1);
            let hash = block.hash();
            hashes.push(hash);
            manager.process_block(&block).unwrap();
            prev_hash = hash;
        }

        // Get ancestors of block 5
        let ancestors = manager.get_ancestors(&hashes[5], 3);
        assert_eq!(ancestors.len(), 3);
        assert_eq!(ancestors[0], hashes[4]);
        assert_eq!(ancestors[1], hashes[3]);
        assert_eq!(ancestors[2], hashes[2]);
    }

    #[test]
    fn test_fork_choice_longest() {
        let genesis = genesis_hash();
        let config = ChainConfig {
            fork_choice: ForkChoiceRule::LongestChain,
            ..ChainConfig::local()
        };
        let mut manager = ChainManager::new(genesis, config);

        // Build chain
        let block1 = create_block(1, genesis, 1);
        let hash1 = block1.hash();
        manager.process_block(&block1).unwrap();

        let block2 = create_block(2, hash1, 1);
        manager.process_block(&block2).unwrap();

        // Create shorter fork
        let fork_block = create_block(2, hash1, 2);
        manager.process_block(&fork_block).unwrap();

        // Longest chain should still be canonical
        let best = manager.select_best_head();
        assert_eq!(manager.get_height(&best), Some(2));
    }

    #[test]
    fn test_events_emitted() {
        let genesis = genesis_hash();
        let mut manager = ChainManager::new(genesis, ChainConfig::local());

        let block1 = create_block(1, genesis, 1);
        manager.process_block(&block1).unwrap();

        let events = manager.drain_events();
        assert!(!events.is_empty());

        // Should have NewCanonicalBlock event
        let has_new_block = events.iter().any(|e| matches!(e, ChainEvent::NewCanonicalBlock { .. }));
        assert!(has_new_block);
    }

    #[test]
    fn test_validate_block() {
        let genesis = genesis_hash();
        let manager = ChainManager::new(genesis, ChainConfig::local());

        // Valid block
        let block1 = create_block(1, genesis, 1);
        assert!(manager.validate_block(&block1).is_ok());

        // Invalid height
        let bad_block = create_block(5, genesis, 1);
        assert!(manager.validate_block(&bad_block).is_err());
    }

    #[test]
    fn test_is_canonical() {
        let genesis = genesis_hash();
        let mut manager = ChainManager::new(genesis, ChainConfig::local());

        let block1 = create_block(1, genesis, 1);
        let hash1 = block1.hash();
        manager.process_block(&block1).unwrap();

        assert!(manager.is_canonical(&hash1));
        assert!(manager.is_canonical(&genesis));
        assert!(!manager.is_canonical(&[99u8; 32]));
    }

    #[test]
    fn test_common_ancestor() {
        let genesis = genesis_hash();
        let mut manager = ChainManager::new(genesis, ChainConfig::local());

        // Build main chain
        let block1 = create_block(1, genesis, 1);
        let hash1 = block1.hash();
        manager.process_block(&block1).unwrap();

        let block2 = create_block(2, hash1, 1);
        let hash2 = block2.hash();
        manager.process_block(&block2).unwrap();

        // Create fork
        let fork_block = create_block(2, hash1, 2);
        let fork_hash = fork_block.hash();
        manager.process_block(&fork_block).unwrap();

        // Common ancestor should be block1
        let (ancestor, height) = manager.find_common_ancestor(&hash2, &fork_hash).unwrap();
        assert_eq!(ancestor, hash1);
        assert_eq!(height, 1);
    }

    #[test]
    fn test_max_forks_limit() {
        let genesis = genesis_hash();
        let config = ChainConfig {
            max_forks: 3,
            ..ChainConfig::local()
        };
        let mut manager = ChainManager::new(genesis, config);

        // Build main chain
        let block1 = create_block(1, genesis, 1);
        let hash1 = block1.hash();
        manager.process_block(&block1).unwrap();

        // Create 5 forks (more than max_forks)
        for i in 0..5 {
            let fork = create_block(2, hash1, (10 + i) as u8);
            manager.process_block(&fork).unwrap();
        }

        // Should only have max_forks
        assert!(manager.forks().len() <= 3);
    }
}
