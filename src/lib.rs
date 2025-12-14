//! PHANTOM: Privacy-First Cryptographic Network
//!
//! This is the root crate that re-exports all PHANTOM components for integration
//! testing and provides unified access to the protocol primitives.
//!
//! ## Architecture Overview
//!
//! PHANTOM replaces traditional blockchain with an Encrypted State Lattice (ESL)
//! and Cryptographic Witness Attestation (CWA) consensus, providing:
//!
//! - **Post-Quantum Security**: CRYSTALS-Kyber/Dilithium throughout
//! - **FHE State Management**: Compute on encrypted balances
//! - **Zero-Knowledge Proofs**: Nova folding schemes for efficient verification
//! - **Network Privacy**: P2P mixnet with Sphinx packets and Dandelion++
//! - **Full Node Integration**: Wallet, P2P, Mempool, and Consensus unified
//!
//! ## Crate Organization
//!
//! - `phantom-pq`: Post-quantum cryptographic primitives
//! - `phantom-nova`: Nova/HyperNova ZKP system
//! - `phantom-fhe`: Fully homomorphic encryption operations
//! - `phantom-esl`: Encrypted State Lattice structures
//! - `phantom-cwa`: Cryptographic Witness Attestation consensus
//! - `phantom-mixnet`: P2P privacy network layer
//! - `phantom-p2p`: libp2p-based P2P networking
//! - `phantom-wallet`: Privacy-preserving wallet
//! - `phantom-mempool`: Encrypted transaction mempool

pub mod node;

// Re-export all crates for integration testing
pub use phantom_pq as pq;
// pub use phantom_nova as nova;  // Temporarily disabled
pub use phantom_fhe as fhe;
pub use phantom_esl as esl;
pub use phantom_cwa as cwa;
pub use phantom_mixnet as mixnet;
pub use phantom_p2p as p2p;
pub use phantom_wallet as wallet;
pub use phantom_mempool as mempool;

/// PHANTOM protocol version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Security configuration
pub mod config {
    use phantom_pq::SecurityLevel;

    /// Default security level for PHANTOM network
    pub const DEFAULT_SECURITY_LEVEL: SecurityLevel = SecurityLevel::Level3;

    /// Minimum committee size for CWA consensus
    pub const MIN_COMMITTEE_SIZE: usize = 7;

    /// Default threshold for threshold signatures (2/3 + 1)
    pub fn default_threshold(n: usize) -> usize {
        (2 * n / 3) + 1
    }

    /// Mixnet configuration defaults
    pub mod mixnet {
        /// Default number of hops in mixnet circuit
        pub const DEFAULT_HOPS: usize = 5;

        /// Cover traffic rate (messages per second)
        pub const COVER_TRAFFIC_RATE: f64 = 10.0;

        /// Stem length for Dandelion++
        pub const STEM_LENGTH: usize = 3;
    }

    /// FHE configuration defaults
    pub mod fhe {
        /// Default FHE security parameter
        pub const DEFAULT_SECURITY_PARAM: u32 = 128;
    }
}

/// Prelude module for convenient imports
pub mod prelude {
    pub use phantom_pq::{kyber, dilithium, SecurityLevel};
    pub use phantom_esl::nullifier::{Nullifier, NullifierSet, NullifierTree};
    pub use phantom_cwa::{Validator, vrf::Committee, threshold::ThresholdScheme};
    pub use phantom_mixnet::{SphinxPacket, MixNode, MixDirectory, MixnetClient};
    pub use phantom_p2p::{SwarmManager, P2PConfig, NetworkMessage, PeerId};
    pub use phantom_wallet::{HDWallet, TransactionLifecycle, Transaction};
    pub use crate::node::{PhantomNode, NodeConfig, NodeEvent, NodeError};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_exists() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_default_threshold() {
        assert_eq!(config::default_threshold(10), 7);
        assert_eq!(config::default_threshold(20), 14);
        assert_eq!(config::default_threshold(100), 67);
    }
}
