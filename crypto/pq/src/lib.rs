//! PHANTOM Post-Quantum Cryptographic Primitives
//!
//! This crate provides NIST-standardized post-quantum cryptographic primitives:
//! - CRYSTALS-Kyber: Key Encapsulation Mechanism (KEM)
//! - CRYSTALS-Dilithium: Digital Signatures
//! - SPHINCS+: Stateless Hash-Based Signatures (backup)
//!
//! All primitives are quantum-resistant under current cryptographic assumptions.

pub mod kyber;
pub mod dilithium;
pub mod sphincs;
pub mod errors;
pub mod hybrid;

pub use kyber::{KyberKeypair, KyberPublicKey, KyberSecretKey, KyberCiphertext, KyberSharedSecret};
pub use dilithium::{DilithiumKeypair, DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature};
pub use sphincs::{SphincsKeypair, SphincsPublicKey, SphincsSecretKey, SphincsSignature};
pub use errors::PQError;
pub use hybrid::HybridScheme;

/// Security level for post-quantum primitives
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SecurityLevel {
    /// NIST Level 1 (~AES-128 equivalent)
    Level1,
    /// NIST Level 3 (~AES-192 equivalent)
    Level3,
    /// NIST Level 5 (~AES-256 equivalent)
    Level5,
}

impl Default for SecurityLevel {
    fn default() -> Self {
        // PHANTOM uses maximum security by default
        SecurityLevel::Level5
    }
}

/// Configuration for post-quantum primitives
pub struct PQConfig {
    /// Security level
    pub security_level: SecurityLevel,
    /// Use hybrid mode (combine with classical crypto)
    pub hybrid_mode: bool,
}

impl Default for PQConfig {
    fn default() -> Self {
        Self {
            security_level: SecurityLevel::Level5,
            hybrid_mode: true, // Recommended for transition period
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_level_default() {
        assert_eq!(SecurityLevel::default(), SecurityLevel::Level5);
    }

    #[test]
    fn test_config_default() {
        let config = PQConfig::default();
        assert_eq!(config.security_level, SecurityLevel::Level5);
        assert!(config.hybrid_mode);
    }
}
