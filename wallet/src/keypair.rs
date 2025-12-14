//! Wallet keypair

use phantom_pq::{dilithium, kyber, SecurityLevel};

/// Wallet keypair with PQ keys
pub struct Keypair {
    /// Signing keypair (Dilithium)
    pub signing: dilithium::DilithiumKeypair,
    /// Encryption keypair (Kyber)
    pub encryption: kyber::KyberKeypair,
}

impl Keypair {
    /// Generate a new keypair
    pub fn generate() -> Result<Self, phantom_pq::PQError> {
        Ok(Self {
            signing: dilithium::generate_keypair(SecurityLevel::Level5)?,
            encryption: kyber::generate_keypair(SecurityLevel::Level5)?,
        })
    }
}
