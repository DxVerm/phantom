//! Block producer for validators

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::{info, debug};

use crate::block::{Block, BlockHeader, BlockBody, Attestation};
use crate::error::{NodeError, NodeResult};

/// Block producer configuration
#[derive(Debug, Clone)]
pub struct ProducerConfig {
    /// Validator ID
    pub validator_id: [u8; 32],
    /// Block production interval
    pub block_interval: Duration,
    /// Maximum transactions per block
    pub max_txs_per_block: usize,
}

impl Default for ProducerConfig {
    fn default() -> Self {
        Self {
            validator_id: [0u8; 32],
            block_interval: Duration::from_secs(2),
            max_txs_per_block: 1000,
        }
    }
}

/// Block producer for validators
pub struct BlockProducer {
    config: ProducerConfig,
    last_block_time: u64,
    blocks_produced: u64,
    round: u64,
}

impl BlockProducer {
    /// Create a new block producer
    pub fn new(config: ProducerConfig) -> Self {
        Self {
            config,
            last_block_time: 0,
            blocks_produced: 0,
            round: 0,
        }
    }

    /// Check if it's time to produce a block
    pub fn should_produce(&self) -> bool {
        let now = Self::current_timestamp();
        now >= self.last_block_time + self.config.block_interval.as_secs()
    }

    /// Produce a new block
    pub fn produce(
        &mut self,
        height: u64,
        prev_hash: [u8; 32],
        state_root: [u8; 32],
        epoch: u64,
        transactions: Vec<Vec<u8>>,
    ) -> NodeResult<Block> {
        let now = Self::current_timestamp();

        // Limit transactions
        let txs: Vec<Vec<u8>> = transactions
            .into_iter()
            .take(self.config.max_txs_per_block)
            .collect();

        debug!(
            "Producing block {} with {} transactions",
            height,
            txs.len()
        );

        // Create block body
        let body = BlockBody {
            transactions: txs.clone(),
            key_shares: vec![],
        };

        // Compute transaction root
        let tx_root = Self::compute_tx_root(&txs);

        // Generate VRF proof (placeholder)
        let vrf_proof = self.generate_vrf_proof(height, epoch);

        // Create header
        let header = BlockHeader {
            height,
            prev_hash,
            state_root,
            tx_root,
            timestamp: now,
            epoch,
            round: self.round,
            producer: self.config.validator_id,
            vrf_proof,
            attestations: vec![],
            extra_data: vec![],
        };

        let block = Block::new(header, body);

        // Update producer state
        self.last_block_time = now;
        self.blocks_produced += 1;
        self.round += 1;

        info!(
            "Produced block {} at height {} (epoch {})",
            hex::encode(&block.hash()[..4]),
            height,
            epoch
        );

        Ok(block)
    }

    /// Add attestation to block
    pub fn add_attestation(&self, block: &mut Block, attestation: Attestation) -> NodeResult<()> {
        // Verify attestation is for this block
        if attestation.block_hash != block.hash() {
            return Err(NodeError::InvalidBlock("Attestation hash mismatch".into()));
        }

        block.header.attestations.push(attestation);
        Ok(())
    }

    /// Check if block has sufficient attestations
    pub fn has_quorum(&self, block: &Block, threshold: usize) -> bool {
        block.header.has_quorum(threshold)
    }

    /// Get blocks produced count
    pub fn blocks_produced(&self) -> u64 {
        self.blocks_produced
    }

    /// Get current round
    pub fn round(&self) -> u64 {
        self.round
    }

    /// Set current round (for sync)
    pub fn set_round(&mut self, round: u64) {
        self.round = round;
    }

    /// Compute transaction Merkle root
    fn compute_tx_root(transactions: &[Vec<u8>]) -> [u8; 32] {
        if transactions.is_empty() {
            return [0u8; 32];
        }

        let mut leaves: Vec<[u8; 32]> = transactions
            .iter()
            .map(|tx| blake3::hash(tx).into())
            .collect();

        while leaves.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in leaves.chunks(2) {
                let mut combined = Vec::new();
                combined.extend_from_slice(&chunk[0]);
                if chunk.len() > 1 {
                    combined.extend_from_slice(&chunk[1]);
                } else {
                    combined.extend_from_slice(&chunk[0]);
                }
                next_level.push(blake3::hash(&combined).into());
            }
            leaves = next_level;
        }

        leaves[0]
    }

    /// Generate VRF proof for witness selection
    fn generate_vrf_proof(&self, height: u64, epoch: u64) -> Vec<u8> {
        // In production, this would use actual VRF
        let mut data = Vec::new();
        data.extend_from_slice(&self.config.validator_id);
        data.extend_from_slice(&height.to_le_bytes());
        data.extend_from_slice(&epoch.to_le_bytes());
        blake3::hash(&data).as_bytes().to_vec()
    }

    /// Get current timestamp
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Block assembler for collecting transactions
pub struct BlockAssembler {
    transactions: Vec<Vec<u8>>,
    max_size: usize,
    max_txs: usize,
    current_size: usize,
}

impl BlockAssembler {
    /// Create new assembler
    pub fn new(max_size: usize, max_txs: usize) -> Self {
        Self {
            transactions: Vec::with_capacity(max_txs),
            max_size,
            max_txs,
            current_size: 0,
        }
    }

    /// Add transaction to block
    pub fn add_transaction(&mut self, tx: Vec<u8>) -> bool {
        if self.transactions.len() >= self.max_txs {
            return false;
        }

        let tx_size = tx.len();
        if self.current_size + tx_size > self.max_size {
            return false;
        }

        self.current_size += tx_size;
        self.transactions.push(tx);
        true
    }

    /// Get all transactions
    pub fn finish(self) -> Vec<Vec<u8>> {
        self.transactions
    }

    /// Get transaction count
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Get current size in bytes
    pub fn size(&self) -> usize {
        self.current_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_producer_creation() {
        let config = ProducerConfig::default();
        let producer = BlockProducer::new(config);
        assert_eq!(producer.blocks_produced(), 0);
    }

    #[test]
    fn test_block_production() {
        let config = ProducerConfig {
            validator_id: [1u8; 32],
            ..Default::default()
        };
        let mut producer = BlockProducer::new(config);

        let block = producer.produce(
            1,
            [0u8; 32],
            [1u8; 32],
            0,
            vec![b"tx1".to_vec(), b"tx2".to_vec()],
        ).unwrap();

        assert_eq!(block.height(), 1);
        assert_eq!(block.tx_count(), 2);
        assert_eq!(producer.blocks_produced(), 1);
    }

    #[test]
    fn test_tx_limit() {
        let config = ProducerConfig {
            max_txs_per_block: 2,
            ..Default::default()
        };
        let mut producer = BlockProducer::new(config);

        let block = producer.produce(
            1,
            [0u8; 32],
            [1u8; 32],
            0,
            vec![b"tx1".to_vec(), b"tx2".to_vec(), b"tx3".to_vec()],
        ).unwrap();

        // Should be limited to 2 transactions
        assert_eq!(block.tx_count(), 2);
    }

    #[test]
    fn test_block_assembler() {
        let mut assembler = BlockAssembler::new(1000, 10);

        assert!(assembler.add_transaction(b"tx1".to_vec()));
        assert!(assembler.add_transaction(b"tx2".to_vec()));
        assert_eq!(assembler.len(), 2);

        let txs = assembler.finish();
        assert_eq!(txs.len(), 2);
    }

    #[test]
    fn test_assembler_limits() {
        let mut assembler = BlockAssembler::new(10, 2);

        // Add first transaction
        assert!(assembler.add_transaction(b"12345".to_vec()));

        // Add second transaction (at tx limit)
        assert!(assembler.add_transaction(b"123".to_vec()));

        // Should reject - at tx limit
        assert!(!assembler.add_transaction(b"x".to_vec()));

        // Reset with size limit
        let mut assembler2 = BlockAssembler::new(10, 100);
        assert!(assembler2.add_transaction(b"12345".to_vec()));
        assert!(assembler2.add_transaction(b"1234".to_vec()));
        // This would exceed size limit (5 + 4 + 2 > 10)
        assert!(!assembler2.add_transaction(b"12".to_vec()));
    }

    #[test]
    fn test_vrf_proof_generation() {
        let config = ProducerConfig {
            validator_id: [1u8; 32],
            ..Default::default()
        };
        let producer = BlockProducer::new(config);

        let proof1 = producer.generate_vrf_proof(1, 0);
        let proof2 = producer.generate_vrf_proof(2, 0);

        // Different heights should produce different proofs
        assert_ne!(proof1, proof2);
        assert_eq!(proof1.len(), 32);
    }

    #[test]
    fn test_quorum_check() {
        let config = ProducerConfig::default();
        let mut producer = BlockProducer::new(config);

        let mut block = producer.produce(
            1,
            [0u8; 32],
            [1u8; 32],
            0,
            vec![],
        ).unwrap();

        assert!(!producer.has_quorum(&block, 3));

        // Add attestations
        for i in 0..3 {
            let attestation = Attestation::new(
                [i as u8; 32],
                block.hash(),
                vec![],
            );
            block.header.attestations.push(attestation);
        }

        assert!(producer.has_quorum(&block, 3));
    }

    #[test]
    fn test_merkle_root() {
        let root1 = BlockProducer::compute_tx_root(&[]);
        assert_eq!(root1, [0u8; 32]);

        let root2 = BlockProducer::compute_tx_root(&[b"tx1".to_vec()]);
        assert_ne!(root2, [0u8; 32]);

        let root3 = BlockProducer::compute_tx_root(&[b"tx1".to_vec(), b"tx2".to_vec()]);
        assert_ne!(root3, root2);
    }
}
