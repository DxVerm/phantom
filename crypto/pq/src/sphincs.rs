//! SPHINCS+ Stateless Hash-Based Signatures
//!
//! SPHINCS+ provides a conservative backup to lattice-based signatures.
//! It relies only on hash function security, making it extremely conservative.
//! Trade-off: Larger signatures (~50KB) but highest confidence in security.
//!
//! This module provides REAL cryptographic operations using the pqcrypto-sphincsplus crate.

use crate::errors::PQError;
use crate::SecurityLevel;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Import real pqcrypto-sphincsplus implementations
// Using SHA-2 based "small" variants for smaller signatures
use pqcrypto_sphincsplus::sphincssha2128ssimple as sphincs128;
use pqcrypto_sphincsplus::sphincssha2192ssimple as sphincs192;
use pqcrypto_sphincsplus::sphincssha2256ssimple as sphincs256;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

/// SPHINCS+ public key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SphincsPublicKey {
    bytes: Vec<u8>,
    level: SecurityLevel,
    variant: SphincsVariant,
}

/// SPHINCS+ secret key (zeroized on drop)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SphincsSecretKey {
    bytes: Vec<u8>,
    #[zeroize(skip)]
    level: SecurityLevel,
    #[zeroize(skip)]
    variant: SphincsVariant,
}

/// SPHINCS+ keypair
pub struct SphincsKeypair {
    pub public_key: SphincsPublicKey,
    pub secret_key: SphincsSecretKey,
}

/// SPHINCS+ signature
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SphincsSignature {
    bytes: Vec<u8>,
    level: SecurityLevel,
    variant: SphincsVariant,
}

/// SPHINCS+ variant (trade-off between signature size and speed)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SphincsVariant {
    /// Smaller signatures, slower signing (SHA-2 based "s" variants)
    Small,
    /// Faster signing, larger signatures (SHA-2 based "f" variants)
    Fast,
}

impl Default for SphincsVariant {
    fn default() -> Self {
        SphincsVariant::Small
    }
}

impl SphincsPublicKey {
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the security level
    pub fn security_level(&self) -> SecurityLevel {
        self.level
    }

    /// Get the variant
    pub fn variant(&self) -> SphincsVariant {
        self.variant
    }

    /// Get the expected size for this configuration (REAL sizes from pqcrypto)
    pub fn expected_size(level: SecurityLevel, _variant: SphincsVariant) -> usize {
        // Note: For "small" variants, public key sizes are the same regardless of s/f
        match level {
            SecurityLevel::Level1 => sphincs128::public_key_bytes(),
            SecurityLevel::Level3 => sphincs192::public_key_bytes(),
            SecurityLevel::Level5 => sphincs256::public_key_bytes(),
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8], level: SecurityLevel, variant: SphincsVariant) -> Result<Self, PQError> {
        let expected = Self::expected_size(level, variant);
        if bytes.len() != expected {
            return Err(PQError::InvalidKeySize {
                expected,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            level,
            variant,
        })
    }
}

impl SphincsSecretKey {
    /// Get the raw bytes (use with caution)
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the security level
    pub fn security_level(&self) -> SecurityLevel {
        self.level
    }

    /// Get the variant
    pub fn variant(&self) -> SphincsVariant {
        self.variant
    }

    /// Get the expected size for this configuration (REAL sizes from pqcrypto)
    pub fn expected_size(level: SecurityLevel, _variant: SphincsVariant) -> usize {
        match level {
            SecurityLevel::Level1 => sphincs128::secret_key_bytes(),
            SecurityLevel::Level3 => sphincs192::secret_key_bytes(),
            SecurityLevel::Level5 => sphincs256::secret_key_bytes(),
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8], level: SecurityLevel, variant: SphincsVariant) -> Result<Self, PQError> {
        let expected = Self::expected_size(level, variant);
        if bytes.len() != expected {
            return Err(PQError::InvalidKeySize {
                expected,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            level,
            variant,
        })
    }
}

impl SphincsSignature {
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the security level
    pub fn security_level(&self) -> SecurityLevel {
        self.level
    }

    /// Get the variant
    pub fn variant(&self) -> SphincsVariant {
        self.variant
    }

    /// Get the expected size for this configuration (REAL sizes from pqcrypto)
    pub fn expected_size(level: SecurityLevel, _variant: SphincsVariant) -> usize {
        // Using "small" (ssimple) variants - smaller signatures
        match level {
            SecurityLevel::Level1 => sphincs128::signature_bytes(),
            SecurityLevel::Level3 => sphincs192::signature_bytes(),
            SecurityLevel::Level5 => sphincs256::signature_bytes(),
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8], level: SecurityLevel, variant: SphincsVariant) -> Result<Self, PQError> {
        let expected = Self::expected_size(level, variant);
        if bytes.len() != expected {
            return Err(PQError::InvalidSignatureSize {
                expected,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            level,
            variant,
        })
    }

    /// Verify this signature against a message and public key
    pub fn verify(&self, message: &[u8], public_key: &SphincsPublicKey) -> Result<bool, PQError> {
        verify(public_key, message, self)
    }
}

/// Generate a SPHINCS+ keypair using REAL pqcrypto-sphincsplus library
pub fn generate_keypair(
    level: SecurityLevel,
    variant: SphincsVariant,
) -> Result<SphincsKeypair, PQError> {
    // Currently only implementing "Small" variant (ssimple)
    // Fast variant would use sphincssha2*fsimple modules
    match (level, variant) {
        (SecurityLevel::Level1, SphincsVariant::Small) => {
            let (pk, sk) = sphincs128::keypair();
            Ok(SphincsKeypair {
                public_key: SphincsPublicKey {
                    bytes: pk.as_bytes().to_vec(),
                    level,
                    variant,
                },
                secret_key: SphincsSecretKey {
                    bytes: sk.as_bytes().to_vec(),
                    level,
                    variant,
                },
            })
        }
        (SecurityLevel::Level3, SphincsVariant::Small) => {
            let (pk, sk) = sphincs192::keypair();
            Ok(SphincsKeypair {
                public_key: SphincsPublicKey {
                    bytes: pk.as_bytes().to_vec(),
                    level,
                    variant,
                },
                secret_key: SphincsSecretKey {
                    bytes: sk.as_bytes().to_vec(),
                    level,
                    variant,
                },
            })
        }
        (SecurityLevel::Level5, SphincsVariant::Small) => {
            let (pk, sk) = sphincs256::keypair();
            Ok(SphincsKeypair {
                public_key: SphincsPublicKey {
                    bytes: pk.as_bytes().to_vec(),
                    level,
                    variant,
                },
                secret_key: SphincsSecretKey {
                    bytes: sk.as_bytes().to_vec(),
                    level,
                    variant,
                },
            })
        }
        (_, SphincsVariant::Fast) => {
            // Fast variants would use sphincssha2*fsimple modules
            // For now, fall back to Small variant with a note
            // In production, this would import and use the "f" variants
            Err(PQError::UnsupportedSecurityLevel(
                "Fast variant not yet implemented - use Small variant".into()
            ))
        }
    }
}

/// Sign a message with SPHINCS+ (REAL implementation)
pub fn sign(secret_key: &SphincsSecretKey, message: &[u8]) -> Result<SphincsSignature, PQError> {
    match (secret_key.level, secret_key.variant) {
        (SecurityLevel::Level1, SphincsVariant::Small) => {
            let sk = sphincs128::SecretKey::from_bytes(secret_key.as_bytes())
                .map_err(|_| PQError::InvalidSecretKey)?;
            let sig = sphincs128::detached_sign(message, &sk);
            Ok(SphincsSignature {
                bytes: sig.as_bytes().to_vec(),
                level: secret_key.level,
                variant: secret_key.variant,
            })
        }
        (SecurityLevel::Level3, SphincsVariant::Small) => {
            let sk = sphincs192::SecretKey::from_bytes(secret_key.as_bytes())
                .map_err(|_| PQError::InvalidSecretKey)?;
            let sig = sphincs192::detached_sign(message, &sk);
            Ok(SphincsSignature {
                bytes: sig.as_bytes().to_vec(),
                level: secret_key.level,
                variant: secret_key.variant,
            })
        }
        (SecurityLevel::Level5, SphincsVariant::Small) => {
            let sk = sphincs256::SecretKey::from_bytes(secret_key.as_bytes())
                .map_err(|_| PQError::InvalidSecretKey)?;
            let sig = sphincs256::detached_sign(message, &sk);
            Ok(SphincsSignature {
                bytes: sig.as_bytes().to_vec(),
                level: secret_key.level,
                variant: secret_key.variant,
            })
        }
        (_, SphincsVariant::Fast) => {
            Err(PQError::UnsupportedSecurityLevel(
                "Fast variant not yet implemented".into()
            ))
        }
    }
}

/// Verify a SPHINCS+ signature (REAL implementation)
pub fn verify(
    public_key: &SphincsPublicKey,
    message: &[u8],
    signature: &SphincsSignature,
) -> Result<bool, PQError> {
    if public_key.level != signature.level {
        return Err(PQError::SecurityLevelMismatch {
            expected: public_key.level,
            actual: signature.level,
        });
    }

    if public_key.variant != signature.variant {
        return Err(PQError::VerificationFailed(
            "Variant mismatch".into()
        ));
    }

    match (public_key.level, public_key.variant) {
        (SecurityLevel::Level1, SphincsVariant::Small) => {
            let pk = sphincs128::PublicKey::from_bytes(public_key.as_bytes())
                .map_err(|_| PQError::InvalidPublicKey)?;
            let sig = sphincs128::DetachedSignature::from_bytes(signature.as_bytes())
                .map_err(|_| PQError::InvalidSignatureFormat("Invalid signature bytes".into()))?;

            match sphincs128::verify_detached_signature(&sig, message, &pk) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        (SecurityLevel::Level3, SphincsVariant::Small) => {
            let pk = sphincs192::PublicKey::from_bytes(public_key.as_bytes())
                .map_err(|_| PQError::InvalidPublicKey)?;
            let sig = sphincs192::DetachedSignature::from_bytes(signature.as_bytes())
                .map_err(|_| PQError::InvalidSignatureFormat("Invalid signature bytes".into()))?;

            match sphincs192::verify_detached_signature(&sig, message, &pk) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        (SecurityLevel::Level5, SphincsVariant::Small) => {
            let pk = sphincs256::PublicKey::from_bytes(public_key.as_bytes())
                .map_err(|_| PQError::InvalidPublicKey)?;
            let sig = sphincs256::DetachedSignature::from_bytes(signature.as_bytes())
                .map_err(|_| PQError::InvalidSignatureFormat("Invalid signature bytes".into()))?;

            match sphincs256::verify_detached_signature(&sig, message, &pk) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        (_, SphincsVariant::Fast) => {
            Err(PQError::UnsupportedSecurityLevel(
                "Fast variant not yet implemented".into()
            ))
        }
    }
}

/// Sign a message and return detached signature bytes
pub fn sign_detached(secret_key: &SphincsSecretKey, message: &[u8]) -> Result<Vec<u8>, PQError> {
    let sig = sign(secret_key, message)?;
    Ok(sig.bytes)
}

/// Verify detached signature bytes
pub fn verify_detached(
    public_key: &SphincsPublicKey,
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, PQError> {
    let signature = SphincsSignature::from_bytes(signature_bytes, public_key.level, public_key.variant)?;
    verify(public_key, message, &signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation_level5() {
        let keypair = generate_keypair(SecurityLevel::Level5, SphincsVariant::Small).unwrap();
        assert_eq!(keypair.public_key.as_bytes().len(), sphincs256::public_key_bytes());
        assert_eq!(keypair.secret_key.as_bytes().len(), sphincs256::secret_key_bytes());
    }

    #[test]
    fn test_keypair_generation_level3() {
        let keypair = generate_keypair(SecurityLevel::Level3, SphincsVariant::Small).unwrap();
        assert_eq!(keypair.public_key.as_bytes().len(), sphincs192::public_key_bytes());
        assert_eq!(keypair.secret_key.as_bytes().len(), sphincs192::secret_key_bytes());
    }

    #[test]
    fn test_keypair_generation_level1() {
        let keypair = generate_keypair(SecurityLevel::Level1, SphincsVariant::Small).unwrap();
        assert_eq!(keypair.public_key.as_bytes().len(), sphincs128::public_key_bytes());
        assert_eq!(keypair.secret_key.as_bytes().len(), sphincs128::secret_key_bytes());
    }

    #[test]
    fn test_sign_verify_level5() {
        let keypair = generate_keypair(SecurityLevel::Level5, SphincsVariant::Small).unwrap();
        let message = b"PHANTOM SPHINCS+ test message";

        let signature = sign(&keypair.secret_key, message).unwrap();
        let result = verify(&keypair.public_key, message, &signature).unwrap();

        // REAL crypto: verification must work
        assert!(result);
    }

    #[test]
    fn test_sign_verify_level3() {
        let keypair = generate_keypair(SecurityLevel::Level3, SphincsVariant::Small).unwrap();
        let message = b"PHANTOM SPHINCS+ test for Level3";

        let signature = sign(&keypair.secret_key, message).unwrap();
        let result = verify(&keypair.public_key, message, &signature).unwrap();

        assert!(result);
    }

    #[test]
    fn test_sign_verify_level1() {
        let keypair = generate_keypair(SecurityLevel::Level1, SphincsVariant::Small).unwrap();
        let message = b"PHANTOM SPHINCS+ test for Level1";

        let signature = sign(&keypair.secret_key, message).unwrap();
        let result = verify(&keypair.public_key, message, &signature).unwrap();

        assert!(result);
    }

    #[test]
    fn test_wrong_message_fails() {
        let keypair = generate_keypair(SecurityLevel::Level5, SphincsVariant::Small).unwrap();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let signature = sign(&keypair.secret_key, message).unwrap();
        let result = verify(&keypair.public_key, wrong_message, &signature).unwrap();

        // Verification with wrong message should fail
        assert!(!result);
    }

    #[test]
    fn test_wrong_key_fails() {
        let keypair1 = generate_keypair(SecurityLevel::Level5, SphincsVariant::Small).unwrap();
        let keypair2 = generate_keypair(SecurityLevel::Level5, SphincsVariant::Small).unwrap();
        let message = b"Test message";

        let signature = sign(&keypair1.secret_key, message).unwrap();
        let result = verify(&keypair2.public_key, message, &signature).unwrap();

        // Verification with wrong key should fail
        assert!(!result);
    }

    #[test]
    fn test_signature_sizes() {
        for level in [SecurityLevel::Level1, SecurityLevel::Level3, SecurityLevel::Level5] {
            let keypair = generate_keypair(level, SphincsVariant::Small).unwrap();
            let signature = sign(&keypair.secret_key, b"test").unwrap();
            let expected = SphincsSignature::expected_size(level, SphincsVariant::Small);
            assert_eq!(signature.as_bytes().len(), expected);
        }
    }

    #[test]
    fn test_detached_signatures() {
        let keypair = generate_keypair(SecurityLevel::Level5, SphincsVariant::Small).unwrap();
        let message = b"PHANTOM detached signature test";

        let sig_bytes = sign_detached(&keypair.secret_key, message).unwrap();
        let result = verify_detached(&keypair.public_key, message, &sig_bytes).unwrap();

        assert!(result);
    }

    #[test]
    fn test_key_serialization() {
        let keypair = generate_keypair(SecurityLevel::Level5, SphincsVariant::Small).unwrap();

        // Round-trip public key
        let pk_bytes = keypair.public_key.as_bytes();
        let pk_restored = SphincsPublicKey::from_bytes(pk_bytes, SecurityLevel::Level5, SphincsVariant::Small).unwrap();
        assert_eq!(pk_bytes, pk_restored.as_bytes());

        // Round-trip secret key
        let sk_bytes = keypair.secret_key.as_bytes();
        let sk_restored = SphincsSecretKey::from_bytes(sk_bytes, SecurityLevel::Level5, SphincsVariant::Small).unwrap();
        assert_eq!(sk_bytes, sk_restored.as_bytes());

        // Verify restored keys work
        let message = b"Test with restored keys";
        let signature = sign(&sk_restored, message).unwrap();
        let result = verify(&pk_restored, message, &signature).unwrap();
        assert!(result);
    }

    #[test]
    fn test_empty_message() {
        let keypair = generate_keypair(SecurityLevel::Level5, SphincsVariant::Small).unwrap();
        let message = b"";

        let signature = sign(&keypair.secret_key, message).unwrap();
        let result = verify(&keypair.public_key, message, &signature).unwrap();

        assert!(result);
    }

    #[test]
    fn test_security_level_mismatch() {
        let keypair5 = generate_keypair(SecurityLevel::Level5, SphincsVariant::Small).unwrap();
        let keypair3 = generate_keypair(SecurityLevel::Level3, SphincsVariant::Small).unwrap();
        let message = b"Test message";

        let signature = sign(&keypair5.secret_key, message).unwrap();

        // Create signature with wrong level
        let wrong_sig = SphincsSignature {
            bytes: signature.bytes.clone(),
            level: SecurityLevel::Level3,
            variant: SphincsVariant::Small,
        };

        let result = verify(&keypair3.public_key, message, &wrong_sig);
        // Should fail due to size mismatch
        assert!(result.is_err() || !result.unwrap());
    }
}
