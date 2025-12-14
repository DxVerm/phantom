//! Proof Verification for Light Clients
//!
//! Provides SPV-style proofs and FHE proof verification without full state.

use crate::errors::{LightClientError, LightClientResult};
use crate::header::BlockHeader;
use serde::{Deserialize, Serialize};

/// Merkle proof for transaction/state inclusion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    /// The item being proven (transaction hash, state key, etc.)
    pub item_hash: [u8; 32],
    /// Merkle path from leaf to root
    pub path: Vec<MerkleNode>,
    /// Block height where the proof is anchored
    pub block_height: u64,
    /// Block hash for verification
    pub block_hash: [u8; 32],
    /// Root type (transactions, state, receipts)
    pub root_type: RootType,
}

/// Type of Merkle root being proven against
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RootType {
    /// Transaction Merkle root
    Transactions,
    /// State Merkle root
    State,
    /// Receipts Merkle root
    Receipts,
}

/// Node in a Merkle proof path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNode {
    /// Hash of the sibling node
    pub hash: [u8; 32],
    /// Whether this sibling is on the left (true) or right (false)
    pub is_left: bool,
}

impl InclusionProof {
    /// Create a new inclusion proof
    pub fn new(
        item_hash: [u8; 32],
        path: Vec<MerkleNode>,
        block_height: u64,
        block_hash: [u8; 32],
        root_type: RootType,
    ) -> Self {
        Self {
            item_hash,
            path,
            block_height,
            block_hash,
            root_type,
        }
    }

    /// Compute the root from this proof
    pub fn compute_root(&self) -> [u8; 32] {
        let mut current = self.item_hash;

        for node in &self.path {
            let mut hasher = blake3::Hasher::new();
            if node.is_left {
                hasher.update(&node.hash);
                hasher.update(&current);
            } else {
                hasher.update(&current);
                hasher.update(&node.hash);
            }
            current = hasher.finalize().into();
        }

        current
    }

    /// Verify this proof against a block header
    pub fn verify(&self, header: &BlockHeader) -> bool {
        if header.hash != self.block_hash || header.height != self.block_height {
            return false;
        }

        let computed_root = self.compute_root();
        let expected_root = match self.root_type {
            RootType::Transactions => header.transactions_root,
            RootType::State => header.state_root,
            RootType::Receipts => header.receipts_root,
        };

        computed_root == expected_root
    }
}

/// Proof of state at a specific key (for FHE state queries)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateProof {
    /// State key being proven
    pub key: Vec<u8>,
    /// Encrypted value at this key (if exists)
    pub value: Option<Vec<u8>>,
    /// Merkle inclusion proof
    pub inclusion_proof: InclusionProof,
    /// Additional FHE commitment proof (optional)
    pub fhe_commitment: Option<Vec<u8>>,
}

impl StateProof {
    /// Create a new state proof
    pub fn new(
        key: Vec<u8>,
        value: Option<Vec<u8>>,
        inclusion_proof: InclusionProof,
    ) -> Self {
        Self {
            key,
            value,
            inclusion_proof,
            fhe_commitment: None,
        }
    }

    /// Add FHE commitment proof
    pub fn with_fhe_commitment(mut self, commitment: Vec<u8>) -> Self {
        self.fhe_commitment = Some(commitment);
        self
    }

    /// Verify the state proof against a header
    pub fn verify(&self, header: &BlockHeader) -> bool {
        // Verify the key-value hash matches what's in the inclusion proof
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.key);
        if let Some(ref value) = self.value {
            hasher.update(value);
        }
        let kv_hash: [u8; 32] = hasher.finalize().into();

        if kv_hash != self.inclusion_proof.item_hash {
            return false;
        }

        self.inclusion_proof.verify(header)
    }
}

/// Delegated proof response from a full node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedProof {
    /// Request ID for tracking
    pub request_id: [u8; 32],
    /// The actual proof data
    pub proof: DelegatedProofType,
    /// Full node's signature over the proof
    pub node_signature: Vec<u8>,
    /// Timestamp of proof generation
    pub timestamp: u64,
    /// Expiry timestamp
    pub expires_at: u64,
}

/// Types of delegated proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DelegatedProofType {
    /// Balance query result
    Balance {
        /// Encrypted balance
        encrypted_balance: Vec<u8>,
        /// State proof
        proof: StateProof,
    },
    /// Transaction verification
    Transaction {
        /// Transaction hash
        tx_hash: [u8; 32],
        /// Inclusion proof
        proof: InclusionProof,
        /// Transaction effects (encrypted)
        effects: Vec<u8>,
    },
    /// FHE computation result
    Computation {
        /// Input commitment
        input_commitment: [u8; 32],
        /// Output (encrypted)
        output: Vec<u8>,
        /// Zero-knowledge proof of correct computation
        zk_proof: Vec<u8>,
    },
}

impl DelegatedProof {
    /// Check if the proof has expired
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time > self.expires_at
    }

    /// Verify the node signature (placeholder)
    pub fn verify_signature(&self, _node_pubkey: &[u8; 32]) -> bool {
        // In production, verify Ed25519 or post-quantum signature
        !self.node_signature.is_empty()
    }
}

/// Proof verifier for light clients
pub struct ProofVerifier {
    /// Trusted full node public keys for delegated proofs
    trusted_nodes: Vec<[u8; 32]>,
    /// Maximum proof age in seconds
    max_proof_age: u64,
}

impl ProofVerifier {
    /// Create a new proof verifier
    pub fn new(max_proof_age: u64) -> Self {
        Self {
            trusted_nodes: Vec::new(),
            max_proof_age,
        }
    }

    /// Add a trusted node for delegated proofs
    pub fn add_trusted_node(&mut self, pubkey: [u8; 32]) {
        if !self.trusted_nodes.contains(&pubkey) {
            self.trusted_nodes.push(pubkey);
        }
    }

    /// Remove a trusted node
    pub fn remove_trusted_node(&mut self, pubkey: &[u8; 32]) {
        self.trusted_nodes.retain(|k| k != pubkey);
    }

    /// Verify an inclusion proof against a header
    pub fn verify_inclusion(
        &self,
        proof: &InclusionProof,
        header: &BlockHeader,
    ) -> LightClientResult<()> {
        if proof.block_hash != header.hash {
            return Err(LightClientError::InvalidProof(
                "Block hash mismatch".into(),
            ));
        }

        if proof.block_height != header.height {
            return Err(LightClientError::InvalidProof(
                "Block height mismatch".into(),
            ));
        }

        if !proof.verify(header) {
            return Err(LightClientError::InvalidMerklePath);
        }

        Ok(())
    }

    /// Verify a state proof
    pub fn verify_state(
        &self,
        proof: &StateProof,
        header: &BlockHeader,
    ) -> LightClientResult<()> {
        if proof.inclusion_proof.root_type != RootType::State {
            return Err(LightClientError::InvalidProof(
                "Expected state root proof".into(),
            ));
        }

        if !proof.verify(header) {
            return Err(LightClientError::StateRootMismatch {
                expected: hex::encode(header.state_root),
                actual: hex::encode(proof.inclusion_proof.compute_root()),
            });
        }

        Ok(())
    }

    /// Verify a delegated proof from a full node
    pub fn verify_delegated(
        &self,
        proof: &DelegatedProof,
        current_time: u64,
    ) -> LightClientResult<()> {
        // Check expiry
        if proof.is_expired(current_time) {
            return Err(LightClientError::DelegatedProofExpired);
        }

        // Check proof age
        if current_time > proof.timestamp + self.max_proof_age {
            return Err(LightClientError::DelegatedProofExpired);
        }

        // Verify node is trusted
        let node_trusted = self.trusted_nodes.iter().any(|node| {
            proof.verify_signature(node)
        });

        if !node_trusted {
            return Err(LightClientError::InvalidDelegationResponse);
        }

        Ok(())
    }

    /// Build a Merkle proof for an item given the tree leaves
    pub fn build_merkle_proof(
        leaves: &[[u8; 32]],
        leaf_index: usize,
    ) -> Vec<MerkleNode> {
        if leaves.is_empty() || leaf_index >= leaves.len() {
            return Vec::new();
        }

        let mut path = Vec::new();
        let mut current_level: Vec<[u8; 32]> = leaves.to_vec();
        let mut index = leaf_index;

        while current_level.len() > 1 {
            // Pad to even number if needed
            if current_level.len() % 2 == 1 {
                current_level.push(*current_level.last().unwrap());
            }

            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            let is_left = index % 2 == 1;

            path.push(MerkleNode {
                hash: current_level[sibling_index],
                is_left,
            });

            // Build next level
            let mut next_level = Vec::with_capacity(current_level.len() / 2);
            for chunk in current_level.chunks(2) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&chunk[0]);
                hasher.update(&chunk[1]);
                next_level.push(hasher.finalize().into());
            }

            current_level = next_level;
            index /= 2;
        }

        path
    }

    /// Compute Merkle root from leaves
    pub fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            return [0u8; 32];
        }

        if leaves.len() == 1 {
            return leaves[0];
        }

        let mut current_level: Vec<[u8; 32]> = leaves.to_vec();

        while current_level.len() > 1 {
            // Pad to even
            if current_level.len() % 2 == 1 {
                current_level.push(*current_level.last().unwrap());
            }

            let mut next_level = Vec::with_capacity(current_level.len() / 2);
            for chunk in current_level.chunks(2) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&chunk[0]);
                hasher.update(&chunk[1]);
                next_level.push(hasher.finalize().into());
            }

            current_level = next_level;
        }

        current_level[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_root_computation() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i as u8;
                h
            })
            .collect();

        let root = ProofVerifier::compute_merkle_root(&leaves);
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn test_merkle_proof_verification() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i as u8;
                h
            })
            .collect();

        let root = ProofVerifier::compute_merkle_root(&leaves);

        // Build proof for leaf at index 2
        let path = ProofVerifier::build_merkle_proof(&leaves, 2);

        let proof = InclusionProof {
            item_hash: leaves[2],
            path,
            block_height: 1,
            block_hash: [0u8; 32],
            root_type: RootType::Transactions,
        };

        // Verify computed root matches
        assert_eq!(proof.compute_root(), root);
    }

    #[test]
    fn test_inclusion_proof_against_header() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i as u8;
                h
            })
            .collect();

        let root = ProofVerifier::compute_merkle_root(&leaves);
        let path = ProofVerifier::build_merkle_proof(&leaves, 1);

        let mut header = BlockHeader::new(
            1,
            [0u8; 32],
            [0u8; 32],
            root,
            [0u8; 32],
            1000,
            [0u8; 32],
            1,
        );
        header.hash = header.compute_hash();

        let proof = InclusionProof {
            item_hash: leaves[1],
            path,
            block_height: 1,
            block_hash: header.hash,
            root_type: RootType::Transactions,
        };

        assert!(proof.verify(&header));
    }

    #[test]
    fn test_delegated_proof_expiry() {
        let proof = DelegatedProof {
            request_id: [0u8; 32],
            proof: DelegatedProofType::Balance {
                encrypted_balance: vec![1, 2, 3],
                proof: StateProof::new(
                    vec![1, 2, 3],
                    Some(vec![4, 5, 6]),
                    InclusionProof::new(
                        [0u8; 32],
                        vec![],
                        0,
                        [0u8; 32],
                        RootType::State,
                    ),
                ),
            },
            node_signature: vec![1, 2, 3],
            timestamp: 1000,
            expires_at: 2000,
        };

        assert!(!proof.is_expired(1500));
        assert!(proof.is_expired(2001));
    }

    #[test]
    fn test_state_proof_verification() {
        let key = vec![1, 2, 3];
        let value = vec![4, 5, 6];

        // Compute key-value hash
        let mut hasher = blake3::Hasher::new();
        hasher.update(&key);
        hasher.update(&value);
        let kv_hash: [u8; 32] = hasher.finalize().into();

        let leaves = vec![kv_hash, [1u8; 32], [2u8; 32], [3u8; 32]];
        let root = ProofVerifier::compute_merkle_root(&leaves);
        let path = ProofVerifier::build_merkle_proof(&leaves, 0);

        let mut header = BlockHeader::new(
            1,
            [0u8; 32],
            root,  // state_root
            [0u8; 32],
            [0u8; 32],
            1000,
            [0u8; 32],
            1,
        );
        header.hash = header.compute_hash();

        let inclusion_proof = InclusionProof {
            item_hash: kv_hash,
            path,
            block_height: 1,
            block_hash: header.hash,
            root_type: RootType::State,
        };

        let state_proof = StateProof::new(key, Some(value), inclusion_proof);

        assert!(state_proof.verify(&header));
    }
}
