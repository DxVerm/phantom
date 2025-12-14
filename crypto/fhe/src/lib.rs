//! PHANTOM FHE Operations
//!
//! Fully Homomorphic Encryption using TFHE-rs.
//! Enables computation on encrypted balances without revealing values.
//!
//! # Key Features:
//! - Encrypt/decrypt u64 balance values
//! - Homomorphic addition, subtraction, multiplication
//! - Comparison operations for range proofs
//! - Server keys for validators (compute without decryption)
//!
//! # Architecture:
//! - ClientKey: For encryption/decryption (held by wallet owner)
//! - ServerKey: For homomorphic operations (shared with validators)
//! - PublicKey: For encryption only (can be published)

pub mod errors;
mod real_impl;

// Export all real TFHE-rs implementations
pub use real_impl::*;
pub use errors::FHEError;

/// FHE Configuration
#[derive(Clone, Debug)]
pub struct FHEConfig {
    /// Security parameter (bits)
    pub security_bits: u32,
    /// Enable multi-threaded operations
    pub multi_threaded: bool,
    /// Cache bootstrapping keys
    pub cache_bootstrap: bool,
}

impl Default for FHEConfig {
    fn default() -> Self {
        Self {
            security_bits: 128,
            multi_threaded: true,
            cache_bootstrap: true,
        }
    }
}

/// Result type for FHE operations
pub type FHEResult<T> = Result<T, FHEError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = FHEConfig::default();
        assert_eq!(config.security_bits, 128);
        assert!(config.multi_threaded);
    }
}
