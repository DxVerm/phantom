//! ESL State Management
//!
//! The global ESL state consists of:
//! - Commitment tree (valid notes)
//! - Nullifier set (spent notes)
//! - State root (cryptographic summary)

use crate::commitment::{Commitment, CommitmentTree, CommitmentWitness};
use crate::errors::ESLError;
use crate::fragment::{StateFragment, FragmentId};
use crate::nullifier::{Nullifier, NullifierTree};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Root hash summarizing the entire ESL state
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StateRoot([u8; 32]);

impl StateRoot {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// A state update representing a transaction
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateUpdate {
    /// Nullifiers being spent
    pub nullifiers: Vec<Nullifier>,
    /// New commitments being created
    pub commitments: Vec<Commitment>,
    /// Epoch of this update
    pub epoch: u64,
    /// ZK proof of validity
    pub proof: Vec<u8>,
    /// Witness signatures (threshold)
    pub witness_signatures: Vec<Vec<u8>>,
}

impl StateUpdate {
    /// Create a new state update
    pub fn new(
        nullifiers: Vec<Nullifier>,
        commitments: Vec<Commitment>,
        epoch: u64,
        proof: Vec<u8>,
    ) -> Self {
        Self {
            nullifiers,
            commitments,
            epoch,
            proof,
            witness_signatures: Vec::new(),
        }
    }

    /// Add a witness signature
    pub fn add_witness_signature(&mut self, signature: Vec<u8>) {
        self.witness_signatures.push(signature);
    }

    /// Check if enough witnesses have signed
    pub fn has_threshold_signatures(&self, threshold: usize) -> bool {
        self.witness_signatures.len() >= threshold
    }

    /// Compute a hash of this update for signing
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"phantom_state_update");
        hasher.update(&self.epoch.to_le_bytes());

        for nullifier in &self.nullifiers {
            hasher.update(nullifier.as_bytes());
        }

        for commitment in &self.commitments {
            hasher.update(commitment.as_bytes());
        }

        hasher.update(&self.proof);
        *hasher.finalize().as_bytes()
    }
}

/// The complete ESL state
#[derive(Clone)]
pub struct ESLState {
    /// Commitment tree (all valid notes)
    commitment_tree: CommitmentTree,
    /// Nullifier tree (all spent notes)
    nullifier_tree: NullifierTree,
    /// Current epoch
    epoch: u64,
    /// Fragments indexed by ID
    fragments: HashMap<FragmentId, StateFragment>,
    /// Current state root
    root: StateRoot,
}

impl ESLState {
    /// Create a new ESL state
    pub fn new(tree_depth: usize) -> Self {
        let commitment_tree = CommitmentTree::new(tree_depth);
        let nullifier_tree = NullifierTree::with_depth(tree_depth);

        let root = Self::compute_root(&commitment_tree, &nullifier_tree, 0);

        Self {
            commitment_tree,
            nullifier_tree,
            epoch: 0,
            fragments: HashMap::new(),
            root,
        }
    }

    /// Apply a state update (transaction)
    pub fn apply_update(&mut self, update: &StateUpdate) -> Result<StateRoot, ESLError> {
        // Verify update epoch is current or next
        if update.epoch > self.epoch + 1 {
            return Err(ESLError::StateUpdateFailed(
                format!("Update epoch {} too far ahead of current {}", update.epoch, self.epoch)
            ));
        }

        // Check nullifiers don't already exist (no double-spend)
        for nullifier in &update.nullifiers {
            if self.nullifier_tree.contains(nullifier) {
                return Err(ESLError::DoubleSpendDetected(
                    format!("Nullifier {} already exists", nullifier.to_hex())
                ));
            }
        }

        // Insert nullifiers
        for nullifier in &update.nullifiers {
            self.nullifier_tree.insert(*nullifier)?;
        }

        // Insert commitments
        for commitment in &update.commitments {
            self.commitment_tree.insert(*commitment)?;
        }

        // Update epoch if needed
        if update.epoch > self.epoch {
            self.epoch = update.epoch;
        }

        // Recompute root
        self.root = Self::compute_root(&self.commitment_tree, &self.nullifier_tree, self.epoch);

        Ok(self.root)
    }

    /// Add a fragment to the state
    pub fn add_fragment(&mut self, fragment: StateFragment) -> Result<(), ESLError> {
        fragment.verify_structure()?;

        // Insert commitment
        self.commitment_tree.insert(Commitment::from_bytes(fragment.commitment))?;

        // Store fragment
        self.fragments.insert(fragment.id, fragment);

        // Update root
        self.root = Self::compute_root(&self.commitment_tree, &self.nullifier_tree, self.epoch);

        Ok(())
    }

    /// Get a fragment by ID
    pub fn get_fragment(&self, id: &FragmentId) -> Option<&StateFragment> {
        self.fragments.get(id)
    }

    /// Get a commitment membership witness
    pub fn get_commitment_witness(&self, index: usize) -> Option<CommitmentWitness> {
        self.commitment_tree.get_witness(index)
    }

    /// Check if a nullifier exists
    pub fn nullifier_exists(&self, nullifier: &Nullifier) -> bool {
        self.nullifier_tree.contains(nullifier)
    }

    /// Get current state root
    pub fn root(&self) -> &StateRoot {
        &self.root
    }

    /// Get current epoch
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Get commitment tree root
    pub fn commitment_root(&self) -> &[u8; 32] {
        self.commitment_tree.root()
    }

    /// Get nullifier tree root
    pub fn nullifier_root(&self) -> &[u8; 32] {
        self.nullifier_tree.root()
    }

    /// Get number of commitments
    pub fn num_commitments(&self) -> usize {
        self.commitment_tree.len()
    }

    /// Get number of nullifiers
    pub fn num_nullifiers(&self) -> usize {
        self.nullifier_tree.len()
    }

    /// Compute state root from components
    fn compute_root(
        commitment_tree: &CommitmentTree,
        nullifier_tree: &NullifierTree,
        epoch: u64,
    ) -> StateRoot {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"phantom_state_root");
        hasher.update(commitment_tree.root());
        hasher.update(nullifier_tree.root());
        hasher.update(&epoch.to_le_bytes());
        StateRoot(*hasher.finalize().as_bytes())
    }

    /// Create a snapshot of the current state
    pub fn snapshot(&self) -> ESLSnapshot {
        ESLSnapshot {
            root: self.root,
            epoch: self.epoch,
            commitment_root: *self.commitment_tree.root(),
            nullifier_root: *self.nullifier_tree.root(),
            num_commitments: self.commitment_tree.len(),
            num_nullifiers: self.nullifier_tree.len(),
        }
    }
}

/// Lightweight snapshot of ESL state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ESLSnapshot {
    /// State root
    pub root: StateRoot,
    /// Epoch
    pub epoch: u64,
    /// Commitment tree root
    pub commitment_root: [u8; 32],
    /// Nullifier tree root
    pub nullifier_root: [u8; 32],
    /// Number of commitments
    pub num_commitments: usize,
    /// Number of nullifiers
    pub num_nullifiers: usize,
}

/// State transition proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateTransitionProof {
    /// Previous state root
    pub prev_root: StateRoot,
    /// New state root
    pub new_root: StateRoot,
    /// Update that caused transition
    pub update_hash: [u8; 32],
    /// ZK proof of valid transition
    pub proof: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esl_state_creation() {
        let state = ESLState::new(16);
        assert_eq!(state.epoch(), 0);
        assert_eq!(state.num_commitments(), 0);
        assert_eq!(state.num_nullifiers(), 0);
    }

    #[test]
    fn test_state_update() {
        let mut state = ESLState::new(16);

        let nullifier = Nullifier::derive(&[1u8; 32], &[2u8; 32]);
        let commitment = Commitment::commit(1000, &[3u8; 32]);

        let update = StateUpdate::new(
            vec![nullifier],
            vec![commitment],
            1,
            vec![0u8; 64], // placeholder proof
        );

        let new_root = state.apply_update(&update).unwrap();

        assert_eq!(state.epoch(), 1);
        assert_eq!(state.num_commitments(), 1);
        assert_eq!(state.num_nullifiers(), 1);
        assert_eq!(*state.root(), new_root);
    }

    #[test]
    fn test_double_spend_prevention() {
        let mut state = ESLState::new(16);

        let nullifier = Nullifier::derive(&[1u8; 32], &[2u8; 32]);
        let commitment = Commitment::commit(1000, &[3u8; 32]);

        let update1 = StateUpdate::new(
            vec![nullifier],
            vec![commitment],
            1,
            vec![0u8; 64],
        );

        state.apply_update(&update1).unwrap();

        // Try to spend the same nullifier again
        let update2 = StateUpdate::new(
            vec![nullifier], // Same nullifier!
            vec![Commitment::commit(500, &[4u8; 32])],
            2,
            vec![0u8; 64],
        );

        assert!(state.apply_update(&update2).is_err());
    }

    #[test]
    fn test_state_snapshot() {
        let state = ESLState::new(16);
        let snapshot = state.snapshot();

        assert_eq!(snapshot.epoch, 0);
        assert_eq!(snapshot.num_commitments, 0);
        assert_eq!(snapshot.root, *state.root());
    }

    #[test]
    fn test_state_root_changes() {
        let mut state = ESLState::new(16);
        let initial_root = *state.root();

        let update = StateUpdate::new(
            vec![Nullifier::derive(&[1u8; 32], &[2u8; 32])],
            vec![Commitment::commit(1000, &[3u8; 32])],
            1,
            vec![],
        );

        state.apply_update(&update).unwrap();

        assert_ne!(initial_root, *state.root());
    }
}
