//! CRYSTALS-Dilithium Digital Signatures
//!
//! Dilithium is a lattice-based signature scheme selected by NIST.
//! PHANTOM uses Dilithium-5 (Level 5) for maximum quantum resistance.
//!
//! This module provides REAL cryptographic operations using the pqcrypto-dilithium crate.

use crate::errors::PQError;
use crate::SecurityLevel;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Import real pqcrypto-dilithium implementations
use pqcrypto_dilithium::dilithium2;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

/// Dilithium public key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DilithiumPublicKey {
    bytes: Vec<u8>,
    level: SecurityLevel,
}

/// Dilithium secret key (zeroized on drop)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DilithiumSecretKey {
    bytes: Vec<u8>,
    #[zeroize(skip)]
    level: SecurityLevel,
}

/// Dilithium keypair
pub struct DilithiumKeypair {
    pub public_key: DilithiumPublicKey,
    pub secret_key: DilithiumSecretKey,
}

/// Dilithium signature
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DilithiumSignature {
    bytes: Vec<u8>,
    level: SecurityLevel,
}

impl DilithiumPublicKey {
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
            SecurityLevel::Level1 => dilithium2::public_key_bytes(),
            SecurityLevel::Level3 => dilithium3::public_key_bytes(),
            SecurityLevel::Level5 => dilithium5::public_key_bytes(),
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

impl DilithiumSecretKey {
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
            SecurityLevel::Level1 => dilithium2::secret_key_bytes(),
            SecurityLevel::Level3 => dilithium3::secret_key_bytes(),
            SecurityLevel::Level5 => dilithium5::secret_key_bytes(),
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

impl DilithiumSignature {
    /// Create a new signature from bytes
    pub fn new(bytes: Vec<u8>, level: SecurityLevel) -> Self {
        Self { bytes, level }
    }

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
            SecurityLevel::Level1 => dilithium2::signature_bytes(),
            SecurityLevel::Level3 => dilithium3::signature_bytes(),
            SecurityLevel::Level5 => dilithium5::signature_bytes(),
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8], level: SecurityLevel) -> Result<Self, PQError> {
        let expected = Self::expected_size(level);
        if bytes.len() != expected {
            return Err(PQError::InvalidSignatureSize {
                expected,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            level,
        })
    }

    /// Verify this signature against a message and public key
    pub fn verify(&self, message: &[u8], public_key: &DilithiumPublicKey) -> Result<bool, PQError> {
        verify(public_key, message, self)
    }
}

/// Generate a Dilithium keypair using REAL pqcrypto-dilithium library
pub fn generate_keypair(level: SecurityLevel) -> Result<DilithiumKeypair, PQError> {
    match level {
        SecurityLevel::Level1 => {
            let (pk, sk) = dilithium2::keypair();
            Ok(DilithiumKeypair {
                public_key: DilithiumPublicKey {
                    bytes: pk.as_bytes().to_vec(),
                    level,
                },
                secret_key: DilithiumSecretKey {
                    bytes: sk.as_bytes().to_vec(),
                    level,
                },
            })
        }
        SecurityLevel::Level3 => {
            let (pk, sk) = dilithium3::keypair();
            Ok(DilithiumKeypair {
                public_key: DilithiumPublicKey {
                    bytes: pk.as_bytes().to_vec(),
                    level,
                },
                secret_key: DilithiumSecretKey {
                    bytes: sk.as_bytes().to_vec(),
                    level,
                },
            })
        }
        SecurityLevel::Level5 => {
            let (pk, sk) = dilithium5::keypair();
            Ok(DilithiumKeypair {
                public_key: DilithiumPublicKey {
                    bytes: pk.as_bytes().to_vec(),
                    level,
                },
                secret_key: DilithiumSecretKey {
                    bytes: sk.as_bytes().to_vec(),
                    level,
                },
            })
        }
    }
}

/// Sign a message with the secret key (REAL implementation)
pub fn sign(secret_key: &DilithiumSecretKey, message: &[u8]) -> Result<DilithiumSignature, PQError> {
    match secret_key.level {
        SecurityLevel::Level1 => {
            let sk = dilithium2::SecretKey::from_bytes(secret_key.as_bytes())
                .map_err(|_| PQError::InvalidSecretKey)?;
            let sig = dilithium2::detached_sign(message, &sk);
            Ok(DilithiumSignature {
                bytes: sig.as_bytes().to_vec(),
                level: secret_key.level,
            })
        }
        SecurityLevel::Level3 => {
            let sk = dilithium3::SecretKey::from_bytes(secret_key.as_bytes())
                .map_err(|_| PQError::InvalidSecretKey)?;
            let sig = dilithium3::detached_sign(message, &sk);
            Ok(DilithiumSignature {
                bytes: sig.as_bytes().to_vec(),
                level: secret_key.level,
            })
        }
        SecurityLevel::Level5 => {
            let sk = dilithium5::SecretKey::from_bytes(secret_key.as_bytes())
                .map_err(|_| PQError::InvalidSecretKey)?;
            let sig = dilithium5::detached_sign(message, &sk);
            Ok(DilithiumSignature {
                bytes: sig.as_bytes().to_vec(),
                level: secret_key.level,
            })
        }
    }
}

/// Verify a signature (REAL implementation)
pub fn verify(
    public_key: &DilithiumPublicKey,
    message: &[u8],
    signature: &DilithiumSignature,
) -> Result<bool, PQError> {
    if public_key.level != signature.level {
        return Err(PQError::SecurityLevelMismatch {
            expected: public_key.level,
            actual: signature.level,
        });
    }

    match public_key.level {
        SecurityLevel::Level1 => {
            let pk = dilithium2::PublicKey::from_bytes(public_key.as_bytes())
                .map_err(|_| PQError::InvalidPublicKey)?;
            let sig = dilithium2::DetachedSignature::from_bytes(signature.as_bytes())
                .map_err(|_| PQError::InvalidSignatureFormat("Invalid signature bytes".into()))?;

            match dilithium2::verify_detached_signature(&sig, message, &pk) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        SecurityLevel::Level3 => {
            let pk = dilithium3::PublicKey::from_bytes(public_key.as_bytes())
                .map_err(|_| PQError::InvalidPublicKey)?;
            let sig = dilithium3::DetachedSignature::from_bytes(signature.as_bytes())
                .map_err(|_| PQError::InvalidSignatureFormat("Invalid signature bytes".into()))?;

            match dilithium3::verify_detached_signature(&sig, message, &pk) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        SecurityLevel::Level5 => {
            let pk = dilithium5::PublicKey::from_bytes(public_key.as_bytes())
                .map_err(|_| PQError::InvalidPublicKey)?;
            let sig = dilithium5::DetachedSignature::from_bytes(signature.as_bytes())
                .map_err(|_| PQError::InvalidSignatureFormat("Invalid signature bytes".into()))?;

            match dilithium5::verify_detached_signature(&sig, message, &pk) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
    }
}

/// Sign a message and return detached signature bytes
pub fn sign_detached(secret_key: &DilithiumSecretKey, message: &[u8]) -> Result<Vec<u8>, PQError> {
    let sig = sign(secret_key, message)?;
    Ok(sig.bytes)
}

/// Verify detached signature bytes
pub fn verify_detached(
    public_key: &DilithiumPublicKey,
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, PQError> {
    let signature = DilithiumSignature::from_bytes(signature_bytes, public_key.level)?;
    verify(public_key, message, &signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation_level5() {
        let keypair = generate_keypair(SecurityLevel::Level5).unwrap();
        assert_eq!(keypair.public_key.as_bytes().len(), dilithium5::public_key_bytes());
        assert_eq!(keypair.secret_key.as_bytes().len(), dilithium5::secret_key_bytes());
    }

    #[test]
    fn test_keypair_generation_level3() {
        let keypair = generate_keypair(SecurityLevel::Level3).unwrap();
        assert_eq!(keypair.public_key.as_bytes().len(), dilithium3::public_key_bytes());
        assert_eq!(keypair.secret_key.as_bytes().len(), dilithium3::secret_key_bytes());
    }

    #[test]
    fn test_keypair_generation_level1() {
        let keypair = generate_keypair(SecurityLevel::Level1).unwrap();
        assert_eq!(keypair.public_key.as_bytes().len(), dilithium2::public_key_bytes());
        assert_eq!(keypair.secret_key.as_bytes().len(), dilithium2::secret_key_bytes());
    }

    #[test]
    fn test_sign_verify_level5() {
        let keypair = generate_keypair(SecurityLevel::Level5).unwrap();
        let message = b"PHANTOM test message for Dilithium5";

        let signature = sign(&keypair.secret_key, message).unwrap();
        let result = verify(&keypair.public_key, message, &signature).unwrap();

        // REAL crypto: verification must work
        assert!(result);
    }

    #[test]
    fn test_sign_verify_level3() {
        let keypair = generate_keypair(SecurityLevel::Level3).unwrap();
        let message = b"PHANTOM test message for Dilithium3";

        let signature = sign(&keypair.secret_key, message).unwrap();
        let result = verify(&keypair.public_key, message, &signature).unwrap();

        assert!(result);
    }

    #[test]
    fn test_sign_verify_level1() {
        let keypair = generate_keypair(SecurityLevel::Level1).unwrap();
        let message = b"PHANTOM test message for Dilithium2";

        let signature = sign(&keypair.secret_key, message).unwrap();
        let result = verify(&keypair.public_key, message, &signature).unwrap();

        assert!(result);
    }

    #[test]
    fn test_wrong_message_fails() {
        let keypair = generate_keypair(SecurityLevel::Level5).unwrap();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let signature = sign(&keypair.secret_key, message).unwrap();
        let result = verify(&keypair.public_key, wrong_message, &signature).unwrap();

        // Verification with wrong message should fail
        assert!(!result);
    }

    #[test]
    fn test_wrong_key_fails() {
        let keypair1 = generate_keypair(SecurityLevel::Level5).unwrap();
        let keypair2 = generate_keypair(SecurityLevel::Level5).unwrap();
        let message = b"Test message";

        let signature = sign(&keypair1.secret_key, message).unwrap();
        let result = verify(&keypair2.public_key, message, &signature).unwrap();

        // Verification with wrong key should fail
        assert!(!result);
    }

    #[test]
    fn test_detached_signatures() {
        let keypair = generate_keypair(SecurityLevel::Level5).unwrap();
        let message = b"PHANTOM detached signature test";

        let sig_bytes = sign_detached(&keypair.secret_key, message).unwrap();
        let result = verify_detached(&keypair.public_key, message, &sig_bytes).unwrap();

        assert!(result);
    }

    #[test]
    fn test_signature_sizes() {
        for level in [SecurityLevel::Level1, SecurityLevel::Level3, SecurityLevel::Level5] {
            let keypair = generate_keypair(level).unwrap();
            let signature = sign(&keypair.secret_key, b"test").unwrap();
            assert_eq!(signature.as_bytes().len(), DilithiumSignature::expected_size(level));
        }
    }

    #[test]
    fn test_security_level_mismatch() {
        let keypair5 = generate_keypair(SecurityLevel::Level5).unwrap();
        let keypair3 = generate_keypair(SecurityLevel::Level3).unwrap();
        let message = b"Test message";

        let signature = sign(&keypair5.secret_key, message).unwrap();

        // Create signature with wrong level
        let wrong_sig = DilithiumSignature {
            bytes: signature.bytes.clone(),
            level: SecurityLevel::Level3,
        };

        let result = verify(&keypair3.public_key, message, &wrong_sig);
        // Should fail due to size mismatch or verification failure
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_empty_message() {
        let keypair = generate_keypair(SecurityLevel::Level5).unwrap();
        let message = b"";

        let signature = sign(&keypair.secret_key, message).unwrap();
        let result = verify(&keypair.public_key, message, &signature).unwrap();

        assert!(result);
    }

    #[test]
    fn test_large_message() {
        let keypair = generate_keypair(SecurityLevel::Level5).unwrap();
        let message = vec![0xAB; 1024 * 1024]; // 1MB message

        let signature = sign(&keypair.secret_key, &message).unwrap();
        let result = verify(&keypair.public_key, &message, &signature).unwrap();

        assert!(result);
    }

    #[test]
    fn test_key_serialization() {
        let keypair = generate_keypair(SecurityLevel::Level5).unwrap();

        // Round-trip public key
        let pk_bytes = keypair.public_key.as_bytes();
        let pk_restored = DilithiumPublicKey::from_bytes(pk_bytes, SecurityLevel::Level5).unwrap();
        assert_eq!(pk_bytes, pk_restored.as_bytes());

        // Round-trip secret key
        let sk_bytes = keypair.secret_key.as_bytes();
        let sk_restored = DilithiumSecretKey::from_bytes(sk_bytes, SecurityLevel::Level5).unwrap();
        assert_eq!(sk_bytes, sk_restored.as_bytes());

        // Verify restored keys work
        let message = b"Test with restored keys";
        let signature = sign(&sk_restored, message).unwrap();
        let result = verify(&pk_restored, message, &signature).unwrap();
        assert!(result);
    }
}
