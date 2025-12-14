//! Hybrid Post-Quantum Cryptographic Schemes
//!
//! Combines classical and post-quantum cryptography for defense-in-depth.
//! If either scheme is broken, the other provides security.

use crate::errors::PQError;
use crate::dilithium::{self, DilithiumKeypair, DilithiumSignature};
use crate::kyber::{self, KyberCiphertext, KyberKeypair};
use crate::SecurityLevel;
use serde::{Deserialize, Serialize};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature as Ed25519Signature, Signer, Verifier};
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use rand::rngs::OsRng;

/// Hybrid signature combining classical and post-quantum signatures
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Post-quantum component (Dilithium)
    pub pq_signature: Vec<u8>,
    /// Classical component (Ed25519)
    pub classical_signature: Vec<u8>,
}

/// Hybrid ciphertext combining classical and post-quantum KEM
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridCiphertext {
    /// Post-quantum component (Kyber)
    pub pq_ciphertext: KyberCiphertext,
    /// Classical component (X25519 ephemeral public key)
    pub classical_ciphertext: Vec<u8>,
}

/// Hybrid shared secret
pub struct HybridSharedSecret {
    /// Combined shared secret
    bytes: [u8; 32],
}

/// Hybrid cryptographic scheme manager
pub struct HybridScheme {
    /// Security level
    level: SecurityLevel,
    /// Enable hybrid mode
    enabled: bool,
}

impl HybridScheme {
    /// Create a new hybrid scheme
    pub fn new(level: SecurityLevel) -> Self {
        Self {
            level,
            enabled: true,
        }
    }

    /// Disable hybrid mode (use PQ-only)
    pub fn disable_hybrid(&mut self) {
        self.enabled = false;
    }

    /// Enable hybrid mode
    pub fn enable_hybrid(&mut self) {
        self.enabled = true;
    }

    /// Check if hybrid mode is enabled
    pub fn is_hybrid(&self) -> bool {
        self.enabled
    }

    /// Generate hybrid signing keypair with real Ed25519
    pub fn generate_signing_keypair(&self) -> Result<HybridSigningKeypair, PQError> {
        let pq_keypair = dilithium::generate_keypair(self.level)?;

        // Real Ed25519 keypair generation
        let classical_signing_key = SigningKey::generate(&mut OsRng);
        let classical_verifying_key = classical_signing_key.verifying_key();

        Ok(HybridSigningKeypair {
            pq_keypair,
            classical_signing_key,
            classical_verifying_key,
        })
    }

    /// Generate hybrid KEM keypair with real X25519
    pub fn generate_kem_keypair(&self) -> Result<HybridKEMKeypair, PQError> {
        let pq_keypair = kyber::generate_keypair(self.level)?;

        // Real X25519 keypair generation
        let classical_secret_key = StaticSecret::random_from_rng(OsRng);
        let classical_public_key = X25519PublicKey::from(&classical_secret_key);

        Ok(HybridKEMKeypair {
            pq_keypair,
            classical_secret_key,
            classical_public_key,
        })
    }

    /// Sign with hybrid scheme using real Ed25519
    pub fn sign(
        &self,
        keypair: &HybridSigningKeypair,
        message: &[u8],
    ) -> Result<HybridSignature, PQError> {
        // Post-quantum signature (Dilithium)
        let pq_sig = dilithium::sign(&keypair.pq_keypair.secret_key, message)?;

        // Real Ed25519 signature
        let classical_sig = keypair.classical_signing_key.sign(message);

        Ok(HybridSignature {
            pq_signature: pq_sig.as_bytes().to_vec(),
            classical_signature: classical_sig.to_bytes().to_vec(),
        })
    }

    /// Verify hybrid signature with real Ed25519 verification
    pub fn verify(
        &self,
        keypair: &HybridSigningKeypair,
        message: &[u8],
        signature: &HybridSignature,
    ) -> Result<bool, PQError> {
        // Verify PQ component (Dilithium)
        let pq_sig = DilithiumSignature::new(signature.pq_signature.clone(), self.level);
        let pq_valid = dilithium::verify(&keypair.pq_keypair.public_key, message, &pq_sig)?;

        if self.enabled {
            // In hybrid mode, both must verify
            // Real Ed25519 verification
            let classical_sig_bytes: [u8; 64] = signature.classical_signature
                .as_slice()
                .try_into()
                .map_err(|_| PQError::InvalidSignatureFormat("Ed25519 signature must be 64 bytes".to_string()))?;
            let classical_sig = Ed25519Signature::from_bytes(&classical_sig_bytes);
            let classical_valid = keypair.classical_verifying_key
                .verify(message, &classical_sig)
                .is_ok();

            Ok(pq_valid && classical_valid)
        } else {
            // PQ-only mode
            Ok(pq_valid)
        }
    }

    /// Encapsulate with hybrid scheme using real X25519 ECDH
    pub fn encapsulate(
        &self,
        recipient_keypair: &HybridKEMKeypair,
    ) -> Result<(HybridCiphertext, HybridSharedSecret), PQError> {
        // PQ encapsulation (Kyber)
        let (pq_ct, pq_ss) = kyber::encapsulate(&recipient_keypair.pq_keypair.public_key)?;

        // Real X25519 key exchange
        // Generate ephemeral keypair for sender
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

        // Compute shared secret: ephemeral_secret * recipient_public_key
        let classical_ss = ephemeral_secret.diffie_hellman(&recipient_keypair.classical_public_key);

        // Combine shared secrets using domain-separated KDF
        let combined_ss = self.combine_shared_secrets(pq_ss.as_bytes(), classical_ss.as_bytes());

        Ok((
            HybridCiphertext {
                pq_ciphertext: pq_ct,
                classical_ciphertext: ephemeral_public.as_bytes().to_vec(),
            },
            HybridSharedSecret { bytes: combined_ss },
        ))
    }

    /// Decapsulate with hybrid scheme using real X25519 ECDH
    pub fn decapsulate(
        &self,
        keypair: &HybridKEMKeypair,
        ciphertext: &HybridCiphertext,
    ) -> Result<HybridSharedSecret, PQError> {
        // PQ decapsulation (Kyber)
        let pq_ss = kyber::decapsulate(&keypair.pq_keypair.secret_key, &ciphertext.pq_ciphertext)?;

        // Real X25519 key exchange
        // Parse sender's ephemeral public key from ciphertext
        let ephemeral_public_bytes: [u8; 32] = ciphertext.classical_ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| PQError::DecapsulationFailed("X25519 public key must be 32 bytes".to_string()))?;
        let ephemeral_public = X25519PublicKey::from(ephemeral_public_bytes);

        // Compute shared secret: recipient_secret_key * ephemeral_public_key
        let classical_ss = keypair.classical_secret_key.diffie_hellman(&ephemeral_public);

        // Combine shared secrets
        let combined_ss = self.combine_shared_secrets(pq_ss.as_bytes(), classical_ss.as_bytes());

        Ok(HybridSharedSecret { bytes: combined_ss })
    }

    /// Combine two shared secrets using domain-separated BLAKE3 KDF
    fn combine_shared_secrets(&self, pq_ss: &[u8; 32], classical_ss: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("phantom_hybrid_kdf_v1");
        // Include both shared secrets
        hasher.update(pq_ss);
        hasher.update(classical_ss);
        // Domain separation with security level
        hasher.update(&[self.level as u8]);
        *hasher.finalize().as_bytes()
    }
}

/// Hybrid signing keypair with real Ed25519
pub struct HybridSigningKeypair {
    /// Post-quantum keypair (Dilithium)
    pub pq_keypair: DilithiumKeypair,
    /// Classical signing key (Ed25519)
    pub classical_signing_key: SigningKey,
    /// Classical verification key (Ed25519)
    pub classical_verifying_key: VerifyingKey,
}

/// Hybrid KEM keypair with real X25519
pub struct HybridKEMKeypair {
    /// Post-quantum keypair (Kyber)
    pub pq_keypair: KyberKeypair,
    /// Classical secret key (X25519)
    pub classical_secret_key: StaticSecret,
    /// Classical public key (X25519)
    pub classical_public_key: X25519PublicKey,
}

impl HybridSharedSecret {
    /// Get the combined shared secret
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_scheme_creation() {
        let scheme = HybridScheme::new(SecurityLevel::Level5);
        assert!(scheme.is_hybrid());
    }

    #[test]
    fn test_hybrid_toggle() {
        let mut scheme = HybridScheme::new(SecurityLevel::Level3);
        assert!(scheme.is_hybrid());
        scheme.disable_hybrid();
        assert!(!scheme.is_hybrid());
        scheme.enable_hybrid();
        assert!(scheme.is_hybrid());
    }

    #[test]
    fn test_hybrid_signing_roundtrip() {
        let scheme = HybridScheme::new(SecurityLevel::Level5);
        let keypair = scheme.generate_signing_keypair().unwrap();
        let message = b"PHANTOM hybrid test message for signing";

        let signature = scheme.sign(&keypair, message).unwrap();
        let valid = scheme.verify(&keypair, message, &signature).unwrap();

        assert!(valid, "Hybrid signature verification should succeed");
    }

    #[test]
    fn test_hybrid_signing_wrong_message_fails() {
        let scheme = HybridScheme::new(SecurityLevel::Level5);
        let keypair = scheme.generate_signing_keypair().unwrap();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let signature = scheme.sign(&keypair, message).unwrap();
        let valid = scheme.verify(&keypair, wrong_message, &signature).unwrap();

        assert!(!valid, "Verification with wrong message should fail");
    }

    #[test]
    fn test_hybrid_signing_wrong_key_fails() {
        let scheme = HybridScheme::new(SecurityLevel::Level5);
        let keypair1 = scheme.generate_signing_keypair().unwrap();
        let keypair2 = scheme.generate_signing_keypair().unwrap();
        let message = b"Test message";

        let signature = scheme.sign(&keypair1, message).unwrap();
        // Try to verify with different keypair - should fail
        let valid = scheme.verify(&keypair2, message, &signature).unwrap();

        assert!(!valid, "Verification with wrong key should fail");
    }

    #[test]
    fn test_hybrid_kem_roundtrip() {
        let scheme = HybridScheme::new(SecurityLevel::Level5);
        let keypair = scheme.generate_kem_keypair().unwrap();

        // Sender encapsulates
        let (ciphertext, ss_sender) = scheme.encapsulate(&keypair).unwrap();

        // Recipient decapsulates
        let ss_recipient = scheme.decapsulate(&keypair, &ciphertext).unwrap();

        // Both parties should derive the same shared secret
        assert_eq!(
            ss_sender.as_bytes(),
            ss_recipient.as_bytes(),
            "Sender and recipient should derive identical shared secrets"
        );
    }

    #[test]
    fn test_hybrid_kem_different_keys_different_secrets() {
        let scheme = HybridScheme::new(SecurityLevel::Level5);
        let keypair1 = scheme.generate_kem_keypair().unwrap();
        let keypair2 = scheme.generate_kem_keypair().unwrap();

        let (_, ss1) = scheme.encapsulate(&keypair1).unwrap();
        let (_, ss2) = scheme.encapsulate(&keypair2).unwrap();

        // Different keypairs should produce different shared secrets
        assert_ne!(
            ss1.as_bytes(),
            ss2.as_bytes(),
            "Different keypairs should produce different shared secrets"
        );
    }

    #[test]
    fn test_pq_only_mode_signing() {
        let mut scheme = HybridScheme::new(SecurityLevel::Level5);
        scheme.disable_hybrid();
        assert!(!scheme.is_hybrid());

        let keypair = scheme.generate_signing_keypair().unwrap();
        let message = b"PQ-only test message";

        let signature = scheme.sign(&keypair, message).unwrap();
        let valid = scheme.verify(&keypair, message, &signature).unwrap();

        assert!(valid, "PQ-only signature verification should succeed");
    }

    #[test]
    fn test_all_security_levels() {
        for level in [SecurityLevel::Level1, SecurityLevel::Level3, SecurityLevel::Level5] {
            let scheme = HybridScheme::new(level);

            // Test signing
            let sign_keypair = scheme.generate_signing_keypair().unwrap();
            let message = b"Test all levels";
            let signature = scheme.sign(&sign_keypair, message).unwrap();
            assert!(scheme.verify(&sign_keypair, message, &signature).unwrap());

            // Test KEM
            let kem_keypair = scheme.generate_kem_keypair().unwrap();
            let (ct, ss1) = scheme.encapsulate(&kem_keypair).unwrap();
            let ss2 = scheme.decapsulate(&kem_keypair, &ct).unwrap();
            assert_eq!(ss1.as_bytes(), ss2.as_bytes());
        }
    }
}
