//! Cryptographic Witness Attestation (CWA) Consensus
//!
//! CWA is PHANTOM's novel consensus mechanism that provides:
//! - Asynchronous Byzantine Fault Tolerance
//! - VRF-based witness selection
//! - Threshold cryptographic attestations
//! - No global ordering requirement
//!
//! Unlike PoW/PoS, CWA achieves consensus through local verification
//! by randomly selected witness sets, enabling privacy-preserving
//! transaction finality.

pub mod validator;
pub mod vrf;
pub mod attestation;
pub mod protocol;
pub mod threshold;
pub mod errors;

pub use validator::{Validator, ValidatorSet};
pub use attestation::{Attestation, AggregatedAttestation, AttestationCollector};
pub use protocol::{CWAProtocol, ProtocolState};
pub use threshold::{ThresholdScheme, PartialSignature, ThresholdSignature, KeyShare, GroupPublicKey};
pub use errors::CWAError;

/// CWA configuration
#[derive(Clone, Debug)]
pub struct CWAConfig {
    /// Number of witnesses per attestation
    pub witness_count: usize,
    /// Threshold for valid attestation (t of n)
    pub threshold: usize,
    /// Maximum attestation time (ms)
    pub timeout_ms: u64,
    /// Minimum stake to be a validator
    pub min_stake: u64,
    /// VRF committee selection period (blocks)
    pub committee_period: u64,
    /// Maximum pending transactions
    pub max_pending: usize,
}

impl Default for CWAConfig {
    fn default() -> Self {
        Self {
            witness_count: 100,
            threshold: 67, // 2/3 + 1
            timeout_ms: 5000,
            min_stake: 1_000_000,
            committee_period: 100,
            max_pending: 10000,
        }
    }
}

/// Result type for CWA operations
pub type CWAResult<T> = Result<T, CWAError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = CWAConfig::default();
        assert!(config.threshold < config.witness_count);
        assert_eq!(config.threshold, 67);
    }
}
