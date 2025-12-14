//! PHANTOM Nova ZKP System
//!
//! This crate provides Nova/HyperNova folding scheme integration for PHANTOM.
//! Nova enables efficient recursive SNARK composition with O(1) verification.
//!
//! # Key Features
//! - Incremental Verifiable Computation (IVC)
//! - Folding-based proof aggregation
//! - ~170ms proving time for typical transactions
//! - Post-quantum compatible hash functions

pub mod circuit;
pub mod folding;
pub mod prover;
pub mod verifier;
pub mod types;
pub mod errors;
pub mod r1cs_circuit;
pub mod groth16_prover;

pub use circuit::PhantomCircuit;
pub use folding::FoldingScheme;
pub use prover::NovaProver;
pub use verifier::NovaVerifier;
pub use types::*;
pub use errors::NovaError;
pub use groth16_prover::{
    Groth16ProvingKey, Groth16VerifyingKey, Groth16Proof,
    groth16_setup, groth16_prove, groth16_verify, get_circuit_stats,
};

/// Nova configuration for PHANTOM
pub struct NovaConfig {
    /// Number of folding steps before compression
    pub folding_steps: usize,
    /// Security parameter (bits)
    pub security_bits: usize,
    /// Enable parallel proving
    pub parallel: bool,
}

impl Default for NovaConfig {
    fn default() -> Self {
        Self {
            folding_steps: 10,
            security_bits: 128,
            parallel: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nova_config_default() {
        let config = NovaConfig::default();
        assert_eq!(config.security_bits, 128);
        assert!(config.parallel);
    }
}
