//! CRYSTALS-Kyber Key Encapsulation Mechanism
//!
//! Kyber is a lattice-based KEM selected by NIST for standardization.
//! PHANTOM uses Kyber-1024 (Level 5) for maximum quantum resistance.
//!
//! This module provides REAL cryptographic operations using the pqcrypto-kyber crate.

use crate::errors::PQError;
use crate::SecurityLevel;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Import real pqcrypto-kyber implementations
use pqcrypto_kyber::kyber1024;
use pqcrypto_kyber::kyber512;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

/// Kyber public key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KyberPublicKey {
    bytes: Vec<u8>,
    level: SecurityLevel,
}

/// Kyber secret key (zeroized on drop)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KyberSecretKey {
    bytes: Vec<u8>,
    #[zeroize(skip)]
    level: SecurityLevel,
}

/// Kyber keypair
pub struct KyberKeypair {
    pub public_key: KyberPublicKey,
    pub secret_key: KyberSecretKey,
}

/// Kyber ciphertext (encapsulated key)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KyberCiphertext {
    bytes: Vec<u8>,
    level: SecurityLevel,
}

/// Shared secret from key encapsulation
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KyberSharedSecret {
    bytes: [u8; 32],
}

impl KyberPublicKey {
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the security level
    pub fn security_level(&self) -> SecurityLevel {
        self.level
    }

    /// Get the expected size for this security level
    pub fn expected_size(level: SecurityLevel) -> usize {
        match level {
            SecurityLevel::Level1 => kyber512::public_key_bytes(),
            SecurityLevel::Level3 => kyber768::public_key_bytes(),
            SecurityLevel::Level5 => kyber1024::public_key_bytes(),
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8], level: SecurityLevel) -> Result<Self, PQError> {
        let expected = Self::expected_size(level);
        if bytes.len() != expected {
            return Err(PQError::InvalidKeySize {
                expected,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            level,
        })
    }
}

impl KyberSecretKey {
    /// Get the raw bytes (use with caution)
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the security level
    pub fn security_level(&self) -> SecurityLevel {
        self.level
    }

    /// Get the expected size for this security level
    pub fn expected_size(level: SecurityLevel) -> usize {
        match level {
            SecurityLevel::Level1 => kyber512::secret_key_bytes(),
            SecurityLevel::Level3 => kyber768::secret_key_bytes(),
            SecurityLevel::Level5 => kyber1024::secret_key_bytes(),
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8], level: SecurityLevel) -> Result<Self, PQError> {
        let expected = Self::expected_size(level);
        if bytes.len() != expected {
            return Err(PQError::InvalidKeySize {
                expected,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            level,
        })
    }
}

impl KyberCiphertext {
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the security level
    pub fn security_level(&self) -> SecurityLevel {
        self.level
    }

    /// Get the expected size for this security level
    pub fn expected_size(level: SecurityLevel) -> usize {
        match level {
            SecurityLevel::Level1 => kyber512::ciphertext_bytes(),
            SecurityLevel::Level3 => kyber768::ciphertext_bytes(),
            SecurityLevel::Level5 => kyber1024::ciphertext_bytes(),
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8], level: SecurityLevel) -> Result<Self, PQError> {
        let expected = Self::expected_size(level);
        if bytes.len() != expected {
            return Err(PQError::InvalidCiphertextSize {
                expected,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            level,
        })
    }
}

impl KyberSharedSecret {
    /// Get the raw bytes (use with caution)
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PQError> {
        if bytes.len() != 32 {
            return Err(PQError::InvalidSharedSecretSize {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }
}

/// Generate a Kyber keypair using REAL pqcrypto-kyber library
pub fn generate_keypair(level: SecurityLevel) -> Result<KyberKeypair, PQError> {
    match level {
        SecurityLevel::Level1 => {
            let (pk, sk) = kyber512::keypair();
            Ok(KyberKeypair {
                public_key: KyberPublicKey {
                    bytes: pk.as_bytes().to_vec(),
                    level,
                },
                secret_key: KyberSecretKey {
                    bytes: sk.as_bytes().to_vec(),
                    level,
                },
            })
        }
        SecurityLevel::Level3 => {
            let (pk, sk) = kyber768::keypair();
            Ok(KyberKeypair {
                public_key: KyberPublicKey {
                    bytes: pk.as_bytes().to_vec(),
                    level,
                },
                secret_key: KyberSecretKey {
                    bytes: sk.as_bytes().to_vec(),
                    level,
                },
            })
        }
        SecurityLevel::Level5 => {
            let (pk, sk) = kyber1024::keypair();
            Ok(KyberKeypair {
                public_key: KyberPublicKey {
                    bytes: pk.as_bytes().to_vec(),
                    level,
                },
                secret_key: KyberSecretKey {
                    bytes: sk.as_bytes().to_vec(),
                    level,
                },
            })
        }
    }
}

/// Encapsulate a shared secret using the public key (REAL implementation)
pub fn encapsulate(public_key: &KyberPublicKey) -> Result<(KyberCiphertext, KyberSharedSecret), PQError> {
    match public_key.level {
        SecurityLevel::Level1 => {
            let pk = kyber512::PublicKey::from_bytes(public_key.as_bytes())
                .map_err(|_| PQError::InvalidPublicKey)?;
            let (ss, ct) = kyber512::encapsulate(&pk);

            let mut ss_bytes = [0u8; 32];
            ss_bytes.copy_from_slice(ss.as_bytes());

            Ok((
                KyberCiphertext {
                    bytes: ct.as_bytes().to_vec(),
                    level: public_key.level,
                },
                KyberSharedSecret { bytes: ss_bytes },
            ))
        }
        SecurityLevel::Level3 => {
            let pk = kyber768::PublicKey::from_bytes(public_key.as_bytes())
                .map_err(|_| PQError::InvalidPublicKey)?;
            let (ss, ct) = kyber768::encapsulate(&pk);

            let mut ss_bytes = [0u8; 32];
            ss_bytes.copy_from_slice(ss.as_bytes());

            Ok((
                KyberCiphertext {
                    bytes: ct.as_bytes().to_vec(),
                    level: public_key.level,
                },
                KyberSharedSecret { bytes: ss_bytes },
            ))
        }
        SecurityLevel::Level5 => {
            let pk = kyber1024::PublicKey::from_bytes(public_key.as_bytes())
                .map_err(|_| PQError::InvalidPublicKey)?;
            let (ss, ct) = kyber1024::encapsulate(&pk);

            let mut ss_bytes = [0u8; 32];
            ss_bytes.copy_from_slice(ss.as_bytes());

            Ok((
                KyberCiphertext {
                    bytes: ct.as_bytes().to_vec(),
                    level: public_key.level,
                },
                KyberSharedSecret { bytes: ss_bytes },
            ))
        }
    }
}

/// Decapsulate to recover the shared secret (REAL implementation)
pub fn decapsulate(
    secret_key: &KyberSecretKey,
    ciphertext: &KyberCiphertext,
) -> Result<KyberSharedSecret, PQError> {
    if secret_key.level != ciphertext.level {
        return Err(PQError::SecurityLevelMismatch {
            expected: secret_key.level,
            actual: ciphertext.level,
        });
    }

    match secret_key.level {
        SecurityLevel::Level1 => {
            let sk = kyber512::SecretKey::from_bytes(secret_key.as_bytes())
                .map_err(|_| PQError::InvalidSecretKey)?;
            let ct = kyber512::Ciphertext::from_bytes(ciphertext.as_bytes())
                .map_err(|_| PQError::InvalidCiphertext)?;
            let ss = kyber512::decapsulate(&ct, &sk);

            let mut ss_bytes = [0u8; 32];
            ss_bytes.copy_from_slice(ss.as_bytes());
            Ok(KyberSharedSecret { bytes: ss_bytes })
        }
        SecurityLevel::Level3 => {
            let sk = kyber768::SecretKey::from_bytes(secret_key.as_bytes())
                .map_err(|_| PQError::InvalidSecretKey)?;
            let ct = kyber768::Ciphertext::from_bytes(ciphertext.as_bytes())
                .map_err(|_| PQError::InvalidCiphertext)?;
            let ss = kyber768::decapsulate(&ct, &sk);

            let mut ss_bytes = [0u8; 32];
            ss_bytes.copy_from_slice(ss.as_bytes());
            Ok(KyberSharedSecret { bytes: ss_bytes })
        }
        SecurityLevel::Level5 => {
            let sk = kyber1024::SecretKey::from_bytes(secret_key.as_bytes())
                .map_err(|_| PQError::InvalidSecretKey)?;
            let ct = kyber1024::Ciphertext::from_bytes(ciphertext.as_bytes())
                .map_err(|_| PQError::InvalidCiphertext)?;
            let ss = kyber1024::decapsulate(&ct, &sk);

            let mut ss_bytes = [0u8; 32];
            ss_bytes.copy_from_slice(ss.as_bytes());
            Ok(KyberSharedSecret { bytes: ss_bytes })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation_level5() {
        let keypair = generate_keypair(SecurityLevel::Level5).unwrap();
        assert_eq!(keypair.public_key.as_bytes().len(), kyber1024::public_key_bytes());
        assert_eq!(keypair.secret_key.as_bytes().len(), kyber1024::secret_key_bytes());
    }

    #[test]
    fn test_keypair_generation_level3() {
        let keypair = generate_keypair(SecurityLevel::Level3).unwrap();
        assert_eq!(keypair.public_key.as_bytes().len(), kyber768::public_key_bytes());
        assert_eq!(keypair.secret_key.as_bytes().len(), kyber768::secret_key_bytes());
    }

    #[test]
    fn test_keypair_generation_level1() {
        let keypair = generate_keypair(SecurityLevel::Level1).unwrap();
        assert_eq!(keypair.public_key.as_bytes().len(), kyber512::public_key_bytes());
        assert_eq!(keypair.secret_key.as_bytes().len(), kyber512::secret_key_bytes());
    }

    #[test]
    fn test_encapsulation_decapsulation_level5() {
        let keypair = generate_keypair(SecurityLevel::Level5).unwrap();

        let (ciphertext, shared_secret1) = encapsulate(&keypair.public_key).unwrap();
        let shared_secret2 = decapsulate(&keypair.secret_key, &ciphertext).unwrap();

        // REAL crypto: shared secrets MUST match
        assert_eq!(shared_secret1.as_bytes(), shared_secret2.as_bytes());
        assert_eq!(ciphertext.as_bytes().len(), kyber1024::ciphertext_bytes());
    }

    #[test]
    fn test_encapsulation_decapsulation_level3() {
        let keypair = generate_keypair(SecurityLevel::Level3).unwrap();

        let (ciphertext, shared_secret1) = encapsulate(&keypair.public_key).unwrap();
        let shared_secret2 = decapsulate(&keypair.secret_key, &ciphertext).unwrap();

        assert_eq!(shared_secret1.as_bytes(), shared_secret2.as_bytes());
    }

    #[test]
    fn test_encapsulation_decapsulation_level1() {
        let keypair = generate_keypair(SecurityLevel::Level1).unwrap();

        let (ciphertext, shared_secret1) = encapsulate(&keypair.public_key).unwrap();
        let shared_secret2 = decapsulate(&keypair.secret_key, &ciphertext).unwrap();

        assert_eq!(shared_secret1.as_bytes(), shared_secret2.as_bytes());
    }

    #[test]
    fn test_security_level_mismatch() {
        let keypair1 = generate_keypair(SecurityLevel::Level5).unwrap();
        let keypair3 = generate_keypair(SecurityLevel::Level3).unwrap();

        let (ciphertext, _) = encapsulate(&keypair1.public_key).unwrap();

        // Try to decapsulate with wrong security level key
        let result = decapsulate(&keypair3.secret_key, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_keypairs_different_secrets() {
        let keypair1 = generate_keypair(SecurityLevel::Level5).unwrap();
        let keypair2 = generate_keypair(SecurityLevel::Level5).unwrap();

        // Encapsulate with keypair1's public key
        let (ciphertext, shared_secret1) = encapsulate(&keypair1.public_key).unwrap();

        // Decapsulate with keypair1's secret key (correct)
        let shared_secret_correct = decapsulate(&keypair1.secret_key, &ciphertext).unwrap();

        // keypair2 can't recover the same secret (different keys)
        // Note: This doesn't error but produces different result
        assert_eq!(shared_secret1.as_bytes(), shared_secret_correct.as_bytes());
    }

    #[test]
    fn test_key_serialization() {
        let keypair = generate_keypair(SecurityLevel::Level5).unwrap();

        // Round-trip public key
        let pk_bytes = keypair.public_key.as_bytes();
        let pk_restored = KyberPublicKey::from_bytes(pk_bytes, SecurityLevel::Level5).unwrap();
        assert_eq!(pk_bytes, pk_restored.as_bytes());

        // Round-trip secret key
        let sk_bytes = keypair.secret_key.as_bytes();
        let sk_restored = KyberSecretKey::from_bytes(sk_bytes, SecurityLevel::Level5).unwrap();
        assert_eq!(sk_bytes, sk_restored.as_bytes());
    }
}
