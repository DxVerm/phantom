//! State manager for applying blocks to ESL state

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, debug, warn};

use phantom_esl::ESLState;
use phantom_storage::{Storage, StateSnapshot};

use crate::block::Block;
use crate::error::{NodeError, NodeResult};

/// State manager for block application
pub struct StateManager {
    state: Arc<RwLock<ESLState>>,
    storage: Arc<RwLock<Storage>>,
    snapshot_interval: u64,
    last_snapshot_epoch: u64,
}

impl StateManager {
    /// Create new state manager
    pub fn new(
        state: Arc<RwLock<ESLState>>,
        storage: Arc<RwLock<Storage>>,
        snapshot_interval: u64,
    ) -> Self {
        Self {
            state,
            storage,
            snapshot_interval,
            last_snapshot_epoch: 0,
        }
    }

    /// Apply a block to the state
    pub async fn apply_block(&mut self, block: &Block) -> NodeResult<()> {
        debug!("Applying block {} to state", block.height());

        let mut state = self.state.write().await;

        // Apply each transaction
        for (i, tx_data) in block.body.transactions.iter().enumerate() {
            if let Err(e) = self.apply_transaction(&mut state, tx_data) {
                warn!(
                    "Failed to apply transaction {} in block {}: {}",
                    i, block.height(), e
                );
                // Continue with other transactions
            }
        }

        // Check if we should create a snapshot
        let epoch = state.epoch();
        if epoch > 0 && epoch % self.snapshot_interval == 0 && epoch > self.last_snapshot_epoch {
            self.create_snapshot(&state, block.height(), epoch).await?;
            self.last_snapshot_epoch = epoch;
        }

        Ok(())
    }

    /// Apply a single transaction to state
    fn apply_transaction(&self, state: &mut ESLState, tx_data: &[u8]) -> NodeResult<()> {
        // In a full implementation, we would:
        // 1. Decrypt the transaction (if we have the key)
        // 2. Verify the proof
        // 3. Create StateUpdate with nullifiers and commitments
        // 4. Apply via state.apply_update()

        // For now, create a minimal state update from the tx data hash
        let commitment = phantom_esl::Commitment::from_bytes(*blake3::hash(tx_data).as_bytes());
        let update = phantom_esl::StateUpdate::new(
            vec![], // No nullifiers in this stub
            vec![commitment],
            state.epoch(),
            tx_data.to_vec(), // Use tx_data as proof placeholder
        );

        state.apply_update(&update)
            .map_err(|e| NodeError::State(e.to_string()))?;

        Ok(())
    }

    /// Create a state snapshot
    async fn create_snapshot(
        &self,
        state: &ESLState,
        height: u64,
        epoch: u64,
    ) -> NodeResult<()> {
        info!("Creating state snapshot for epoch {}", epoch);

        // Get ESL snapshot (contains roots and counts)
        let esl_snapshot = state.snapshot();

        // Serialize the ESLSnapshot as tree_data
        let tree_data = bincode::serialize(&esl_snapshot)
            .map_err(|e| NodeError::State(e.to_string()))?;

        let snapshot = StateSnapshot {
            epoch,
            height,
            state_root: *state.commitment_root(),
            account_count: esl_snapshot.num_commitments as u64,
            validator_set_hash: *state.nullifier_root(), // Store nullifier root here
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            tree_data,
        };

        let storage = self.storage.write().await;
        storage.state.save_snapshot(&snapshot)?;

        info!(
            "Snapshot created: epoch={}, height={}, root={}",
            epoch,
            height,
            hex::encode(&snapshot.state_root[..8])
        );

        Ok(())
    }

    /// Restore state from latest snapshot
    ///
    /// Note: ESLState trees cannot be fully deserialized from snapshots.
    /// This method logs the snapshot info and returns the checkpoint height
    /// for block replay. The state will be rebuilt by replaying blocks
    /// from the snapshot height.
    pub async fn restore_from_snapshot(&mut self) -> NodeResult<Option<u64>> {
        let storage = self.storage.read().await;

        // Get current epoch from chain metadata
        let meta = storage.chain.get_meta()?;
        let target_epoch = meta.map(|m| m.current_height / 100).unwrap_or(0); // Estimate epoch

        if let Some(snapshot) = storage.state.get_nearest_snapshot(target_epoch)? {
            info!(
                "Found snapshot: epoch={}, height={}, state_root={}",
                snapshot.epoch,
                snapshot.height,
                hex::encode(&snapshot.state_root[..8])
            );

            // Deserialize ESLSnapshot metadata if available
            if !snapshot.tree_data.is_empty() {
                if let Ok(esl_snapshot) = bincode::deserialize::<phantom_esl::ESLSnapshot>(&snapshot.tree_data) {
                    info!(
                        "Snapshot metadata: {} commitments, {} nullifiers",
                        esl_snapshot.num_commitments,
                        esl_snapshot.num_nullifiers
                    );
                }
            }

            // State will be rebuilt by replaying blocks from snapshot height
            // A fresh ESLState is used and blocks are replayed to reconstruct
            self.last_snapshot_epoch = snapshot.epoch;
            return Ok(Some(snapshot.height));
        }

        Ok(None)
    }

    /// Get current state root
    pub async fn state_root(&self) -> [u8; 32] {
        *self.state.read().await.commitment_root()
    }

    /// Get current epoch
    pub async fn epoch(&self) -> u64 {
        self.state.read().await.epoch()
    }

    /// Verify state root matches expected
    pub async fn verify_state_root(&self, expected: &[u8; 32]) -> bool {
        let current = self.state_root().await;
        &current == expected
    }

    /// Prune old snapshots
    pub async fn prune_snapshots(&self, keep_epochs: u64) -> NodeResult<usize> {
        let current_epoch = self.epoch().await;
        if current_epoch <= keep_epochs {
            return Ok(0);
        }

        let storage = self.storage.write().await;
        let pruned = storage.state.prune_snapshots(current_epoch - keep_epochs)?;

        if pruned > 0 {
            info!("Pruned {} old state snapshots", pruned);
        }

        Ok(pruned)
    }
}

/// Block validator for verifying incoming blocks
pub struct BlockValidator {
    min_attestations: usize,
}

impl BlockValidator {
    /// Create new validator
    pub fn new(min_attestations: usize) -> Self {
        Self { min_attestations }
    }

    /// Validate a block
    pub fn validate(&self, block: &Block, prev_state_root: &[u8; 32]) -> NodeResult<()> {
        // Check attestation count
        if block.header.attestations.len() < self.min_attestations {
            return Err(NodeError::InvalidBlock(format!(
                "Insufficient attestations: {} < {}",
                block.header.attestations.len(),
                self.min_attestations
            )));
        }

        // Verify block integrity (tx root)
        if !block.verify() {
            return Err(NodeError::InvalidBlock("Block verification failed".into()));
        }

        // In production, we would also:
        // - Verify attestation signatures
        // - Verify VRF proof
        // - Verify state transition
        // - Verify timestamp is reasonable

        Ok(())
    }

    /// Validate block sequence
    pub fn validate_sequence(&self, block: &Block, prev_hash: &[u8; 32], expected_height: u64) -> NodeResult<()> {
        if block.header.prev_hash != *prev_hash {
            return Err(NodeError::InvalidBlock("Previous hash mismatch".into()));
        }

        if block.height() != expected_height {
            return Err(NodeError::InvalidBlock(format!(
                "Height mismatch: {} != {}",
                block.height(),
                expected_height
            )));
        }

        Ok(())
    }
}

/// Epoch manager for epoch transitions
pub struct EpochManager {
    epoch_length: u64,
    current_epoch: u64,
    epoch_start_height: u64,
}

impl EpochManager {
    /// Create new epoch manager
    pub fn new(epoch_length: u64) -> Self {
        Self {
            epoch_length,
            current_epoch: 0,
            epoch_start_height: 0,
        }
    }

    /// Check if we're at an epoch boundary
    pub fn is_epoch_boundary(&self, height: u64) -> bool {
        height > 0 && height % self.epoch_length == 0
    }

    /// Get epoch for a given height
    pub fn epoch_at_height(&self, height: u64) -> u64 {
        height / self.epoch_length
    }

    /// Process height update
    pub fn update(&mut self, height: u64) -> Option<EpochTransition> {
        let new_epoch = self.epoch_at_height(height);

        if new_epoch > self.current_epoch {
            let transition = EpochTransition {
                from_epoch: self.current_epoch,
                to_epoch: new_epoch,
                transition_height: height,
            };

            self.current_epoch = new_epoch;
            self.epoch_start_height = height;

            return Some(transition);
        }

        None
    }

    /// Get current epoch
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Get blocks remaining in current epoch
    pub fn blocks_until_epoch_end(&self, height: u64) -> u64 {
        let next_epoch_start = (self.current_epoch + 1) * self.epoch_length;
        next_epoch_start.saturating_sub(height)
    }
}

/// Epoch transition event
#[derive(Debug, Clone)]
pub struct EpochTransition {
    /// Previous epoch
    pub from_epoch: u64,
    /// New epoch
    pub to_epoch: u64,
    /// Height at which transition occurred
    pub transition_height: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_manager_boundaries() {
        let manager = EpochManager::new(100);

        assert!(!manager.is_epoch_boundary(0));
        assert!(!manager.is_epoch_boundary(50));
        assert!(manager.is_epoch_boundary(100));
        assert!(!manager.is_epoch_boundary(150));
        assert!(manager.is_epoch_boundary(200));
    }

    #[test]
    fn test_epoch_at_height() {
        let manager = EpochManager::new(100);

        assert_eq!(manager.epoch_at_height(0), 0);
        assert_eq!(manager.epoch_at_height(50), 0);
        assert_eq!(manager.epoch_at_height(100), 1);
        assert_eq!(manager.epoch_at_height(250), 2);
    }

    #[test]
    fn test_epoch_transitions() {
        let mut manager = EpochManager::new(100);

        // No transition at start
        assert!(manager.update(50).is_none());
        assert_eq!(manager.current_epoch(), 0);

        // Transition at height 100
        let transition = manager.update(100);
        assert!(transition.is_some());
        let t = transition.unwrap();
        assert_eq!(t.from_epoch, 0);
        assert_eq!(t.to_epoch, 1);
        assert_eq!(manager.current_epoch(), 1);

        // No transition within epoch
        assert!(manager.update(150).is_none());

        // Transition at height 200
        let transition = manager.update(200);
        assert!(transition.is_some());
        assert_eq!(manager.current_epoch(), 2);
    }

    #[test]
    fn test_blocks_until_epoch_end() {
        let mut manager = EpochManager::new(100);

        assert_eq!(manager.blocks_until_epoch_end(0), 100);
        assert_eq!(manager.blocks_until_epoch_end(50), 50);
        assert_eq!(manager.blocks_until_epoch_end(99), 1);

        manager.update(100);
        assert_eq!(manager.blocks_until_epoch_end(100), 100);
        assert_eq!(manager.blocks_until_epoch_end(150), 50);
    }

    #[test]
    fn test_block_validator() {
        use crate::block::{BlockHeader, BlockBody, Block, Attestation};

        let validator = BlockValidator::new(2);

        let mut header = BlockHeader {
            height: 1,
            prev_hash: [0u8; 32],
            state_root: [1u8; 32],
            tx_root: [0u8; 32],
            timestamp: 12345,
            epoch: 0,
            round: 0,
            producer: [2u8; 32],
            vrf_proof: vec![],
            attestations: vec![],
            extra_data: vec![],
        };

        let block = Block::new(header.clone(), BlockBody::empty());

        // Should fail - no attestations
        assert!(validator.validate(&block, &[0u8; 32]).is_err());

        // Add attestations
        let block_hash = block.hash();
        header.attestations = vec![
            Attestation::new([1u8; 32], block_hash, vec![]),
            Attestation::new([2u8; 32], block_hash, vec![]),
        ];

        let block = Block::new(header, BlockBody::empty());
        assert!(validator.validate(&block, &[0u8; 32]).is_ok());
    }

    #[test]
    fn test_sequence_validation() {
        use crate::block::{BlockHeader, BlockBody, Block};

        let validator = BlockValidator::new(0);

        let header = BlockHeader {
            height: 5,
            prev_hash: [1u8; 32],
            state_root: [2u8; 32],
            tx_root: [0u8; 32],
            timestamp: 12345,
            epoch: 0,
            round: 0,
            producer: [3u8; 32],
            vrf_proof: vec![],
            attestations: vec![],
            extra_data: vec![],
        };

        let block = Block::new(header, BlockBody::empty());

        // Correct sequence
        assert!(validator.validate_sequence(&block, &[1u8; 32], 5).is_ok());

        // Wrong prev_hash
        assert!(validator.validate_sequence(&block, &[0u8; 32], 5).is_err());

        // Wrong height
        assert!(validator.validate_sequence(&block, &[1u8; 32], 4).is_err());
    }
}
