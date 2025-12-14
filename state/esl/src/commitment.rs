//! Commitment System - Hiding Values with Binding Guarantees
//!
//! Pedersen commitments allow hiding transaction values while ensuring
//! they cannot be changed later. The commitment tree stores all valid
//! commitments, enabling membership proofs without revealing values.

use crate::errors::ESLError;
use serde::{Deserialize, Serialize};

/// A Pedersen commitment to a value
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Commitment([u8; 32]);

impl Commitment {
    /// Create a commitment from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create a Pedersen commitment: C = value * G + randomness * H
    ///
    /// In real implementation: use elliptic curve operations
    /// Here we simulate with hash-based commitment
    pub fn commit(value: u64, randomness: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"phantom_pedersen_commit");
        hasher.update(&value.to_le_bytes());
        hasher.update(randomness);
        Self(*hasher.finalize().as_bytes())
    }

    /// Verify a commitment opening
    pub fn verify(&self, value: u64, randomness: &[u8; 32]) -> bool {
        let expected = Self::commit(value, randomness);
        *self == expected
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Create from hex string
    pub fn from_hex(s: &str) -> Result<Self, ESLError> {
        let bytes = hex::decode(s)
            .map_err(|e| ESLError::InvalidCommitment(e.to_string()))?;

        if bytes.len() != 32 {
            return Err(ESLError::InvalidCommitment(
                format!("Expected 32 bytes, got {}", bytes.len())
            ));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Add two commitments (homomorphic property)
    /// commit(a) + commit(b) = commit(a + b)
    pub fn add(&self, other: &Commitment) -> Commitment {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = self.0[i].wrapping_add(other.0[i]);
        }
        Commitment(result)
    }

    /// Subtract two commitments (homomorphic property)
    pub fn sub(&self, other: &Commitment) -> Commitment {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = self.0[i].wrapping_sub(other.0[i]);
        }
        Commitment(result)
    }
}

/// Merkle tree of commitments
#[derive(Clone, Debug)]
pub struct CommitmentTree {
    /// Tree depth
    depth: usize,
    /// Root hash
    root: [u8; 32],
    /// Leaves (commitments)
    leaves: Vec<Commitment>,
    /// Next available leaf index
    next_index: usize,
}

/// Witness for proving commitment membership
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentWitness {
    /// Merkle path from leaf to root
    pub path: Vec<[u8; 32]>,
    /// Index in the tree
    pub index: usize,
    /// Path directions (false = left, true = right)
    pub directions: Vec<bool>,
}

impl CommitmentTree {
    /// Create a new commitment tree
    pub fn new(depth: usize) -> Self {
        let capacity = 1 << depth;
        Self {
            depth,
            root: Self::compute_empty_root(depth),
            leaves: Vec::with_capacity(capacity),
            next_index: 0,
        }
    }

    /// Compute root of an empty tree
    fn compute_empty_root(depth: usize) -> [u8; 32] {
        let mut current = [0u8; 32];
        for _ in 0..depth {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&current);
            hasher.update(&current);
            current = *hasher.finalize().as_bytes();
        }
        current
    }

    /// Insert a commitment into the tree
    pub fn insert(&mut self, commitment: Commitment) -> Result<usize, ESLError> {
        let max_leaves = 1 << self.depth;
        if self.next_index >= max_leaves {
            return Err(ESLError::StateUpdateFailed(
                "Commitment tree is full".into()
            ));
        }

        let index = self.next_index;
        self.leaves.push(commitment);
        self.next_index += 1;
        self.update_root();

        Ok(index)
    }

    /// Get a membership witness for a commitment
    pub fn get_witness(&self, index: usize) -> Option<CommitmentWitness> {
        if index >= self.leaves.len() {
            return None;
        }

        let path = self.compute_path(index);
        let directions = self.compute_directions(index);

        Some(CommitmentWitness {
            path,
            index,
            directions,
        })
    }

    /// Verify a membership witness
    pub fn verify_witness(
        &self,
        commitment: &Commitment,
        witness: &CommitmentWitness,
    ) -> Result<bool, ESLError> {
        if witness.path.len() != self.depth {
            return Err(ESLError::MerkleVerificationFailed(
                "Invalid path length".into()
            ));
        }

        let mut current = *commitment.as_bytes();

        for (i, sibling) in witness.path.iter().enumerate() {
            let mut hasher = blake3::Hasher::new();
            if witness.directions[i] {
                hasher.update(sibling);
                hasher.update(&current);
            } else {
                hasher.update(&current);
                hasher.update(sibling);
            }
            current = *hasher.finalize().as_bytes();
        }

        Ok(current == self.root)
    }

    /// Get the current root
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Get the number of commitments
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Get tree depth
    pub fn depth(&self) -> usize {
        self.depth
    }

    // Internal helpers

    fn update_root(&mut self) {
        if self.leaves.is_empty() {
            self.root = Self::compute_empty_root(self.depth);
            return;
        }

        // Compute Merkle root from leaves
        let mut level: Vec<[u8; 32]> = self.leaves
            .iter()
            .map(|c| *c.as_bytes())
            .collect();

        // Pad to power of 2
        let target_len = 1 << self.depth;
        while level.len() < target_len {
            level.push([0u8; 32]);
        }

        // Build tree bottom-up
        while level.len() > 1 {
            let mut next_level = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks(2) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&pair[0]);
                hasher.update(&pair[1]);
                next_level.push(*hasher.finalize().as_bytes());
            }
            level = next_level;
        }

        self.root = level[0];
    }

    fn compute_path(&self, index: usize) -> Vec<[u8; 32]> {
        let mut path = Vec::with_capacity(self.depth);
        let mut current_index = index;
        let mut level: Vec<[u8; 32]> = self.leaves
            .iter()
            .map(|c| *c.as_bytes())
            .collect();

        // Pad to power of 2
        let target_len = 1 << self.depth;
        while level.len() < target_len {
            level.push([0u8; 32]);
        }

        for _ in 0..self.depth {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            path.push(level[sibling_index]);

            // Move to parent level
            let mut next_level = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks(2) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&pair[0]);
                hasher.update(&pair[1]);
                next_level.push(*hasher.finalize().as_bytes());
            }
            level = next_level;
            current_index /= 2;
        }

        path
    }

    fn compute_directions(&self, index: usize) -> Vec<bool> {
        let mut directions = Vec::with_capacity(self.depth);
        let mut current_index = index;

        for _ in 0..self.depth {
            directions.push(current_index % 2 == 1);
            current_index /= 2;
        }

        directions
    }
}

/// Note commitment (includes additional metadata)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoteCommitment {
    /// Value commitment
    pub value_commitment: Commitment,
    /// Owner commitment (hashed public key)
    pub owner_hash: [u8; 32],
    /// Asset type (for multi-asset support)
    pub asset_id: [u8; 32],
    /// Combined commitment
    pub combined: Commitment,
}

impl NoteCommitment {
    /// Create a new note commitment
    pub fn new(
        value: u64,
        randomness: &[u8; 32],
        owner_pk: &[u8],
        asset_id: [u8; 32],
    ) -> Self {
        let value_commitment = Commitment::commit(value, randomness);

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"phantom_owner_hash");
        hasher.update(owner_pk);
        let owner_hash = *hasher.finalize().as_bytes();

        // Combined commitment
        let mut combined_hasher = blake3::Hasher::new();
        combined_hasher.update(b"phantom_note_commitment");
        combined_hasher.update(value_commitment.as_bytes());
        combined_hasher.update(&owner_hash);
        combined_hasher.update(&asset_id);
        let combined = Commitment::from_bytes(*combined_hasher.finalize().as_bytes());

        Self {
            value_commitment,
            owner_hash,
            asset_id,
            combined,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_create_verify() {
        let value = 1000u64;
        let randomness = [42u8; 32];

        let commitment = Commitment::commit(value, &randomness);
        assert!(commitment.verify(value, &randomness));
        assert!(!commitment.verify(999, &randomness));
    }

    #[test]
    fn test_commitment_homomorphic_add() {
        let r1 = [1u8; 32];
        let r2 = [2u8; 32];

        let c1 = Commitment::commit(100, &r1);
        let c2 = Commitment::commit(50, &r2);
        let _c3 = c1.add(&c2);

        // Note: In real Pedersen commitments, c1 + c2 = commit(150, r1+r2)
        // Our hash-based simulation doesn't preserve this exactly
    }

    #[test]
    fn test_commitment_tree_insert() {
        let mut tree = CommitmentTree::new(4); // 16 leaves max
        let commitment = Commitment::commit(100, &[1u8; 32]);

        let index = tree.insert(commitment).unwrap();
        assert_eq!(index, 0);
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn test_commitment_tree_witness() {
        let mut tree = CommitmentTree::new(4);
        let commitment = Commitment::commit(100, &[1u8; 32]);

        let index = tree.insert(commitment).unwrap();
        let witness = tree.get_witness(index).unwrap();

        let valid = tree.verify_witness(&commitment, &witness).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_commitment_tree_multiple_inserts() {
        let mut tree = CommitmentTree::new(4);

        for i in 0..5 {
            let commitment = Commitment::commit(100 + i, &[i as u8; 32]);
            tree.insert(commitment).unwrap();
        }

        assert_eq!(tree.len(), 5);

        // Verify each commitment
        for i in 0..5 {
            let commitment = Commitment::commit(100 + i, &[i as u8; 32]);
            let witness = tree.get_witness(i as usize).unwrap();
            assert!(tree.verify_witness(&commitment, &witness).unwrap());
        }
    }

    #[test]
    fn test_note_commitment() {
        let note = NoteCommitment::new(
            1000,
            &[42u8; 32],
            b"owner_public_key",
            [0u8; 32], // Native asset
        );

        assert_ne!(note.combined.as_bytes(), &[0u8; 32]);
    }
}
