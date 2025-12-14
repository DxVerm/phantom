//! Block types for the node

use serde::{Deserialize, Serialize};

/// Complete block with header and body
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Block header
    pub header: BlockHeader,
    /// Block body
    pub body: BlockBody,
}

impl Block {
    /// Create a new block
    pub fn new(header: BlockHeader, body: BlockBody) -> Self {
        Self { header, body }
    }

    /// Compute block hash
    pub fn hash(&self) -> [u8; 32] {
        let data = serde_json::to_vec(&self.header).unwrap_or_default();
        blake3::hash(&data).into()
    }

    /// Verify block integrity
    pub fn verify(&self) -> bool {
        // Verify transaction Merkle root
        let computed_root = self.compute_tx_root();
        if computed_root != self.header.tx_root {
            return false;
        }

        // Verify attestation count meets threshold
        // (In production, would verify signatures too)
        true
    }

    /// Compute transaction Merkle root
    fn compute_tx_root(&self) -> [u8; 32] {
        if self.body.transactions.is_empty() {
            return [0u8; 32];
        }

        let mut leaves: Vec<[u8; 32]> = self.body.transactions
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

    /// Get block height
    pub fn height(&self) -> u64 {
        self.header.height
    }

    /// Get transaction count
    pub fn tx_count(&self) -> usize {
        self.body.transactions.len()
    }
}

/// Block header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block height (number)
    pub height: u64,
    /// Previous block hash
    pub prev_hash: [u8; 32],
    /// State root after applying this block
    pub state_root: [u8; 32],
    /// Transaction Merkle root
    pub tx_root: [u8; 32],
    /// Block timestamp (Unix seconds)
    pub timestamp: u64,
    /// Epoch number
    pub epoch: u64,
    /// Round within epoch
    pub round: u64,
    /// Block producer (validator ID)
    pub producer: [u8; 32],
    /// VRF proof for witness selection
    pub vrf_proof: Vec<u8>,
    /// Attestations from witnesses
    pub attestations: Vec<Attestation>,
    /// Extra data (for comments/notes)
    pub extra_data: Vec<u8>,
}

impl BlockHeader {
    /// Compute header hash
    pub fn hash(&self) -> [u8; 32] {
        let data = serde_json::to_vec(self).unwrap_or_default();
        blake3::hash(&data).into()
    }

    /// Check if block has sufficient attestations
    pub fn has_quorum(&self, threshold: usize) -> bool {
        self.attestations.len() >= threshold
    }
}

/// Block body containing transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockBody {
    /// Encrypted transactions
    pub transactions: Vec<Vec<u8>>,
    /// Decryption key shares (for epoch n-1)
    pub key_shares: Vec<KeyShare>,
}

impl BlockBody {
    /// Create empty body
    pub fn empty() -> Self {
        Self {
            transactions: vec![],
            key_shares: vec![],
        }
    }
}

/// Witness attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// Witness ID
    pub witness_id: [u8; 32],
    /// Block hash being attested
    pub block_hash: [u8; 32],
    /// Signature over block hash
    pub signature: Vec<u8>,
    /// Timestamp of attestation
    pub timestamp: u64,
}

impl Attestation {
    /// Create new attestation
    pub fn new(witness_id: [u8; 32], block_hash: [u8; 32], signature: Vec<u8>) -> Self {
        Self {
            witness_id,
            block_hash,
            signature,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Verify attestation signature
    pub fn verify(&self, _public_key: &[u8]) -> bool {
        // In production, verify signature with public key
        true
    }
}

/// Key share for threshold decryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShare {
    /// Validator providing the share
    pub validator_id: [u8; 32],
    /// Epoch this share is for
    pub epoch: u64,
    /// The encrypted key share
    pub share: Vec<u8>,
    /// Proof of correct sharing
    pub proof: Vec<u8>,
}

/// Convert Block to storage format
impl From<Block> for phantom_storage::StoredBlock {
    fn from(block: Block) -> Self {
        let header = phantom_storage::StoredBlockHeader {
            height: block.header.height,
            hash: block.hash(),
            prev_hash: block.header.prev_hash,
            state_root: block.header.state_root,
            tx_root: block.header.tx_root,
            timestamp: block.header.timestamp,
            producer: block.header.producer,
            attestation_count: block.header.attestations.len() as u32,
        };

        let body = phantom_storage::StoredBlockBody {
            transactions: block.body.transactions.iter()
                .map(|tx| phantom_storage::StoredTransaction {
                    hash: blake3::hash(tx).into(),
                    tx_type: phantom_storage::TransactionType::Transfer,
                    encrypted_sender: vec![],
                    encrypted_receiver: vec![],
                    encrypted_amount: vec![],
                    encrypted_memo: None,
                    fee: 0,
                    nonce: 0,
                    proof: vec![],
                    signature: vec![],
                    timestamp: block.header.timestamp,
                    block_height: Some(block.header.height),
                })
                .collect(),
        };

        phantom_storage::StoredBlock { header, body }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_block(height: u64) -> Block {
        let header = BlockHeader {
            height,
            prev_hash: [0u8; 32],
            state_root: [1u8; 32],
            tx_root: [0u8; 32],
            timestamp: 12345,
            epoch: 1,
            round: 0,
            producer: [2u8; 32],
            vrf_proof: vec![],
            attestations: vec![],
            extra_data: vec![],
        };

        Block::new(header, BlockBody::empty())
    }

    #[test]
    fn test_block_hash() {
        let block1 = create_test_block(1);
        let block2 = create_test_block(2);

        assert_ne!(block1.hash(), block2.hash());
    }

    #[test]
    fn test_empty_block_verify() {
        let block = create_test_block(1);
        assert!(block.verify());
    }

    #[test]
    fn test_block_with_transactions() {
        let mut block = create_test_block(1);
        block.body.transactions = vec![
            b"tx1".to_vec(),
            b"tx2".to_vec(),
        ];

        // Recompute tx_root
        let tx_root = block.compute_tx_root();
        block.header.tx_root = tx_root;

        assert!(block.verify());
        assert_eq!(block.tx_count(), 2);
    }

    #[test]
    fn test_quorum_check() {
        let mut block = create_test_block(1);

        assert!(!block.header.has_quorum(3));

        for i in 0..3 {
            block.header.attestations.push(Attestation {
                witness_id: [i as u8; 32],
                block_hash: block.hash(),
                signature: vec![],
                timestamp: 12345,
            });
        }

        assert!(block.header.has_quorum(3));
    }

    #[test]
    fn test_merkle_root_computation() {
        let mut block = create_test_block(1);

        // Empty block
        assert_eq!(block.compute_tx_root(), [0u8; 32]);

        // Single transaction
        block.body.transactions = vec![b"tx1".to_vec()];
        let root1 = block.compute_tx_root();
        assert_ne!(root1, [0u8; 32]);

        // Multiple transactions
        block.body.transactions = vec![b"tx1".to_vec(), b"tx2".to_vec()];
        let root2 = block.compute_tx_root();
        assert_ne!(root2, root1);
    }
}
