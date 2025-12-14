//! Nullifier System - Double-Spend Prevention Without History
//!
//! Nullifiers are cryptographic identifiers that prevent double-spending
//! without revealing which notes were spent. Each note can only produce
//! one nullifier, and once a nullifier is in the set, the note is "spent".

use crate::errors::ESLError;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A nullifier - unique identifier for a spent note
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Nullifier([u8; 32]);

impl Nullifier {
    /// Create a nullifier from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Derive a nullifier from secret key and commitment
    ///
    /// nullifier = PRF(secret_key, commitment)
    pub fn derive(secret_key: &[u8; 32], commitment: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new_keyed(secret_key);
        hasher.update(commitment);
        hasher.update(b"phantom_nullifier_v1");
        Self(*hasher.finalize().as_bytes())
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
            .map_err(|e| ESLError::InvalidNullifier(e.to_string()))?;

        if bytes.len() != 32 {
            return Err(ESLError::InvalidNullifier(
                format!("Expected 32 bytes, got {}", bytes.len())
            ));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

/// In-memory nullifier set for fast lookups
#[derive(Clone, Debug, Default)]
pub struct NullifierSet {
    nullifiers: HashSet<Nullifier>,
}

impl NullifierSet {
    /// Create an empty nullifier set
    pub fn new() -> Self {
        Self {
            nullifiers: HashSet::new(),
        }
    }

    /// Create with pre-allocated capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            nullifiers: HashSet::with_capacity(capacity),
        }
    }

    /// Add a nullifier to the set
    ///
    /// Returns error if nullifier already exists (double-spend attempt)
    pub fn insert(&mut self, nullifier: Nullifier) -> Result<(), ESLError> {
        if self.nullifiers.contains(&nullifier) {
            return Err(ESLError::DoubleSpendDetected(
                format!("Nullifier {} already exists", nullifier.to_hex())
            ));
        }
        self.nullifiers.insert(nullifier);
        Ok(())
    }

    /// Check if a nullifier exists
    pub fn contains(&self, nullifier: &Nullifier) -> bool {
        self.nullifiers.contains(nullifier)
    }

    /// Get the number of nullifiers
    pub fn len(&self) -> usize {
        self.nullifiers.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.nullifiers.is_empty()
    }

    /// Compute a root hash of all nullifiers (for verification)
    pub fn root_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"phantom_nullifier_set_root");

        // Sort nullifiers for deterministic ordering
        let mut sorted: Vec<_> = self.nullifiers.iter().collect();
        sorted.sort_by_key(|n| n.as_bytes());

        for nullifier in sorted {
            hasher.update(nullifier.as_bytes());
        }

        *hasher.finalize().as_bytes()
    }
}

/// Sparse Merkle Tree for nullifiers (efficient membership proofs)
#[derive(Clone, Debug)]
pub struct NullifierTree {
    /// Tree depth (256 for 32-byte keys)
    depth: usize,
    /// Root hash
    root: [u8; 32],
    /// Sparse storage of non-empty leaves
    leaves: HashSet<Nullifier>,
    /// Cached intermediate nodes (optional optimization)
    cache: std::collections::HashMap<Vec<u8>, [u8; 32]>,
}

/// Merkle proof for nullifier membership/non-membership
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NullifierProof {
    /// Path from leaf to root
    pub path: Vec<[u8; 32]>,
    /// Direction at each level (false = left, true = right)
    pub indices: Vec<bool>,
    /// Whether this proves membership or non-membership
    pub is_membership_proof: bool,
}

impl NullifierTree {
    /// Create a new nullifier tree
    pub fn new() -> Self {
        Self {
            depth: 256,
            root: Self::empty_root(256),
            leaves: HashSet::new(),
            cache: std::collections::HashMap::new(),
        }
    }

    /// Create with custom depth
    pub fn with_depth(depth: usize) -> Self {
        Self {
            depth,
            root: Self::empty_root(depth),
            leaves: HashSet::new(),
            cache: std::collections::HashMap::new(),
        }
    }

    /// Compute the root of an empty tree of given depth
    fn empty_root(depth: usize) -> [u8; 32] {
        let mut current = [0u8; 32];
        for _ in 0..depth {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&current);
            hasher.update(&current);
            current = *hasher.finalize().as_bytes();
        }
        current
    }

    /// Insert a nullifier into the tree
    pub fn insert(&mut self, nullifier: Nullifier) -> Result<(), ESLError> {
        if self.leaves.contains(&nullifier) {
            return Err(ESLError::DoubleSpendDetected(
                format!("Nullifier {} already in tree", nullifier.to_hex())
            ));
        }

        self.leaves.insert(nullifier);
        self.update_root();

        Ok(())
    }

    /// Check if a nullifier exists in the tree
    pub fn contains(&self, nullifier: &Nullifier) -> bool {
        self.leaves.contains(nullifier)
    }

    /// Get the current root
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Get a membership proof for a nullifier
    pub fn get_membership_proof(&self, nullifier: &Nullifier) -> Option<NullifierProof> {
        if !self.leaves.contains(nullifier) {
            return None;
        }

        // Generate path from leaf to root
        let path = self.generate_path(nullifier);
        let indices = self.compute_indices(nullifier);

        Some(NullifierProof {
            path,
            indices,
            is_membership_proof: true,
        })
    }

    /// Get a non-membership proof for a nullifier
    pub fn get_non_membership_proof(&self, nullifier: &Nullifier) -> Option<NullifierProof> {
        if self.leaves.contains(nullifier) {
            return None;
        }

        // Generate path showing the position is empty
        let path = self.generate_path(nullifier);
        let indices = self.compute_indices(nullifier);

        Some(NullifierProof {
            path,
            indices,
            is_membership_proof: false,
        })
    }

    /// Verify a proof
    pub fn verify_proof(
        &self,
        nullifier: &Nullifier,
        proof: &NullifierProof,
    ) -> Result<bool, ESLError> {
        if proof.path.len() != self.depth || proof.indices.len() != self.depth {
            return Err(ESLError::MerkleVerificationFailed(
                "Invalid proof length".into()
            ));
        }

        // Compute root from proof
        let mut current = self.hash_leaf(nullifier, proof.is_membership_proof);

        for (i, sibling) in proof.path.iter().enumerate() {
            let mut hasher = blake3::Hasher::new();
            if proof.indices[i] {
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

    /// Get the number of nullifiers
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    // Internal helpers

    fn update_root(&mut self) {
        // Simplified: recompute root from all leaves
        // In production: use incremental updates
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"phantom_nullifier_tree_root");

        let mut sorted: Vec<_> = self.leaves.iter().collect();
        sorted.sort_by_key(|n| n.as_bytes());

        for nullifier in sorted {
            hasher.update(nullifier.as_bytes());
        }

        self.root = *hasher.finalize().as_bytes();
    }

    fn hash_leaf(&self, nullifier: &Nullifier, is_member: bool) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"phantom_leaf");
        hasher.update(nullifier.as_bytes());
        hasher.update(&[is_member as u8]);
        *hasher.finalize().as_bytes()
    }

    fn generate_path(&self, _nullifier: &Nullifier) -> Vec<[u8; 32]> {
        // Simplified: return placeholder path
        // In production: traverse the sparse tree
        vec![[0u8; 32]; self.depth]
    }

    fn compute_indices(&self, nullifier: &Nullifier) -> Vec<bool> {
        // Path direction is determined by bits of the nullifier
        nullifier.as_bytes()
            .iter()
            .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1 == 1))
            .take(self.depth)
            .collect()
    }
}

impl Default for NullifierTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_derive() {
        let secret = [1u8; 32];
        let commitment = [2u8; 32];

        let n1 = Nullifier::derive(&secret, &commitment);
        let n2 = Nullifier::derive(&secret, &commitment);

        assert_eq!(n1, n2);

        // Different inputs produce different nullifiers
        let n3 = Nullifier::derive(&[3u8; 32], &commitment);
        assert_ne!(n1, n3);
    }

    #[test]
    fn test_nullifier_set_double_spend() {
        let mut set = NullifierSet::new();
        let nullifier = Nullifier::from_bytes([1u8; 32]);

        assert!(set.insert(nullifier).is_ok());
        assert!(set.insert(nullifier).is_err()); // Double spend!
    }

    #[test]
    fn test_nullifier_tree_insert() {
        let mut tree = NullifierTree::with_depth(32);
        let nullifier = Nullifier::from_bytes([1u8; 32]);

        assert!(tree.insert(nullifier).is_ok());
        assert!(tree.contains(&nullifier));
    }

    #[test]
    fn test_nullifier_tree_double_spend() {
        let mut tree = NullifierTree::with_depth(32);
        let nullifier = Nullifier::from_bytes([1u8; 32]);

        assert!(tree.insert(nullifier).is_ok());
        assert!(tree.insert(nullifier).is_err()); // Double spend!
    }

    #[test]
    fn test_membership_proof() {
        let mut tree = NullifierTree::with_depth(32);
        let nullifier = Nullifier::from_bytes([1u8; 32]);

        tree.insert(nullifier).unwrap();

        let proof = tree.get_membership_proof(&nullifier).unwrap();
        assert!(proof.is_membership_proof);
    }

    #[test]
    fn test_nullifier_hex_roundtrip() {
        let nullifier = Nullifier::from_bytes([0xAB; 32]);
        let hex = nullifier.to_hex();
        let recovered = Nullifier::from_hex(&hex).unwrap();
        assert_eq!(nullifier, recovered);
    }
}
