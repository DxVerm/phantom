//! Encrypted State Lattice (ESL) - PHANTOM's Blockchain Replacement
//!
//! The ESL is a novel data structure that eliminates the need for a global ledger.
//! Unlike blockchain (which has a single linear chain of blocks), the ESL consists
//! of encrypted state fragments that have no global ordering.
//!
//! # Key Properties
//! - **No Global Ledger**: State exists as encrypted fragments, not a chain
//! - **Local Verification**: Each transaction verified by small validator subset
//! - **Nullifier-Based Double-Spend Prevention**: Cryptographic proofs, not history
//! - **Homomorphic State Updates**: Compute on encrypted balances directly
//!
//! # Architecture
//! ```text
//! ╔═══════════════════════════════════╗
//! ║    Encrypted State Fragments      ║
//! ║    (No global ordering)           ║
//! ╠═══════════════════════════════════╣
//! ║  ┌───┐  ┌───┐  ┌───┐  ┌───┐      ║
//! ║  │ E │  │ E │  │ E │  │ E │      ║
//! ║  └─┬─┘  └─┬─┘  └─┬─┘  └─┬─┘      ║
//! ║    │ CWA │      │ CWA │          ║
//! ║    └─────┘      └─────┘          ║
//! ╚═══════════════════════════════════╝
//! ```

pub mod fragment;
pub mod nullifier;
pub mod commitment;
pub mod state;
pub mod witness;
pub mod errors;

pub use fragment::{StateFragment, FragmentId, EncryptedBalance, EncryptedBool, ESLKeys, FragmentRef};
pub use nullifier::{Nullifier, NullifierTree, NullifierSet};
pub use commitment::{Commitment, CommitmentTree, CommitmentWitness};
pub use state::{ESLState, StateUpdate, StateRoot, ESLSnapshot};
pub use witness::{WitnessSet, WitnessAttestation};
pub use errors::ESLError;

/// ESL Configuration
pub struct ESLConfig {
    /// Tree depth for commitments
    pub commitment_tree_depth: usize,
    /// Maximum nullifiers before pruning
    pub max_nullifiers: usize,
    /// Number of witnesses required for attestation
    pub witness_threshold: usize,
    /// Total witnesses in the set
    pub witness_set_size: usize,
}

impl Default for ESLConfig {
    fn default() -> Self {
        Self {
            commitment_tree_depth: 32,
            max_nullifiers: 1_000_000,
            witness_threshold: 67,  // 2/3 + 1
            witness_set_size: 100,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esl_config_default() {
        let config = ESLConfig::default();
        assert_eq!(config.commitment_tree_depth, 32);
        assert!(config.witness_threshold > config.witness_set_size / 2);
    }
}
