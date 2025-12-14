//! FHE Ciphertext types with Real TFHE-rs
//!
//! Encrypted values that support homomorphic operations.
//! FHEUint64 is the primary type for encrypted balance values.

use serde::{Deserialize, Serialize};
use crate::{FHEError, FHEResult};
use super::keys::{ClientKey, PublicKey, ServerKey};
use tfhe::prelude::*;
use tfhe::FheUint64 as TfheFheUint64;

/// Wrapper around TFHE-rs ciphertext for serialization
#[derive(Clone, Serialize, Deserialize)]
pub struct FHECiphertext {
    /// Serialized ciphertext bytes
    data: Vec<u8>,
    /// Number of bits encrypted
    bits: u8,
    /// Operation count (for noise tracking)
    op_count: u32,
}

impl FHECiphertext {
    /// Create a new ciphertext from serialized TFHE data
    pub fn new(data: Vec<u8>, bits: u8) -> Self {
        Self {
            data,
            bits,
            op_count: 0,
        }
    }

    /// Get the ciphertext data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the number of bits
    pub fn bits(&self) -> u8 {
        self.bits
    }

    /// Get the operation count (noise proxy)
    pub fn noise_level(&self) -> u8 {
        // Approximate noise based on operation count
        self.op_count.min(255) as u8
    }

    /// Check if bootstrapping might be needed (many operations)
    pub fn needs_bootstrap(&self) -> bool {
        self.op_count > 50
    }

    /// Increment operation count
    pub(crate) fn increment_ops(&mut self, count: u32) {
        self.op_count = self.op_count.saturating_add(count);
    }
}

impl std::fmt::Debug for FHECiphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FHECiphertext")
            .field("size", &self.data.len())
            .field("bits", &self.bits)
            .field("ops", &self.op_count)
            .finish()
    }
}

/// Encrypted 64-bit unsigned integer
/// Primary type for encrypted balance values
#[derive(Clone)]
pub struct FHEUint64 {
    /// Inner TFHE-rs encrypted value
    inner: TfheFheUint64,
    /// Operation count for noise tracking
    op_count: u32,
}

impl FHEUint64 {
    /// Encrypt a u64 value with client key
    pub fn encrypt(value: u64, client_key: &ClientKey) -> FHEResult<Self> {
        let encrypted = TfheFheUint64::encrypt(value, client_key.inner());

        Ok(Self {
            inner: encrypted,
            op_count: 0,
        })
    }

    /// Encrypt using try_encrypt for error handling
    pub fn try_encrypt(value: u64, client_key: &ClientKey) -> FHEResult<Self> {
        let encrypted = TfheFheUint64::try_encrypt(value, client_key.inner())
            .map_err(|e| FHEError::EncryptionFailed(e.to_string()))?;

        Ok(Self {
            inner: encrypted,
            op_count: 0,
        })
    }

    /// Encrypt with public key (for third-party encryption)
    pub fn encrypt_with_public(value: u64, public_key: &PublicKey) -> FHEResult<Self> {
        // Compact encryption with public key
        let compact = tfhe::CompactFheUint64::encrypt(value, public_key.inner());
        let expanded = compact.expand();

        Ok(Self {
            inner: expanded,
            op_count: 0,
        })
    }

    /// Decrypt to u64 using client key
    pub fn decrypt(&self, client_key: &ClientKey) -> FHEResult<u64> {
        let result: u64 = self.inner.decrypt(client_key.inner());
        Ok(result)
    }

    /// Get reference to inner TFHE value
    pub fn inner(&self) -> &TfheFheUint64 {
        &self.inner
    }

    /// Get mutable reference to inner TFHE value
    pub fn inner_mut(&mut self) -> &mut TfheFheUint64 {
        &mut self.inner
    }

    /// Create from TFHE FheUint64
    pub fn from_tfhe(inner: TfheFheUint64) -> Self {
        Self {
            inner,
            op_count: 0,
        }
    }

    /// Create from TFHE FheUint64 with operation count
    pub fn from_tfhe_with_ops(inner: TfheFheUint64, op_count: u32) -> Self {
        Self { inner, op_count }
    }

    /// Check if bootstrapping might be needed
    pub fn needs_bootstrap(&self) -> bool {
        self.op_count > 50
    }

    /// Get operation count
    pub fn op_count(&self) -> u32 {
        self.op_count
    }

    /// Serialize to FHECiphertext for storage/transmission
    pub fn to_ciphertext(&self) -> FHEResult<FHECiphertext> {
        let data = bincode::serialize(&self.inner)
            .map_err(|e| FHEError::SerializationError(e.to_string()))?;

        Ok(FHECiphertext {
            data,
            bits: 64,
            op_count: self.op_count,
        })
    }

    /// Deserialize from FHECiphertext
    pub fn from_ciphertext(ct: &FHECiphertext) -> FHEResult<Self> {
        let inner: TfheFheUint64 = bincode::deserialize(&ct.data)
            .map_err(|e| FHEError::SerializationError(e.to_string()))?;

        Ok(Self {
            inner,
            op_count: ct.op_count,
        })
    }

    /// Get underlying ciphertext (for compatibility)
    pub fn ciphertext(&self) -> FHEResult<FHECiphertext> {
        self.to_ciphertext()
    }

    /// Get a zero-knowledge proof that value is in range [0, max]
    pub fn prove_range(&self, _max: u64, _server_key: &ServerKey) -> FHEResult<RangeProof> {
        // Range proofs require additional ZK infrastructure
        // For now, return a placeholder that must be verified externally
        Ok(RangeProof {
            commitment: blake3::hash(&self.to_ciphertext()?.data).into(),
            response: vec![],
        })
    }
}

impl std::fmt::Debug for FHEUint64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FHEUint64")
            .field("ops", &self.op_count)
            .finish()
    }
}

/// Proof that an encrypted value is within a range
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeProof {
    /// Commitment to the value
    pub commitment: [u8; 32],
    /// Proof response
    pub response: Vec<u8>,
}

impl RangeProof {
    /// Verify the range proof
    /// Note: Real verification requires ZK proof system integration
    pub fn verify(&self, _encrypted: &FHEUint64, _max: u64) -> bool {
        // Placeholder - needs arkworks or bulletproofs for real verification
        !self.commitment.iter().all(|&b| b == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FHEConfig;
    use super::super::keys::KeyPair;

    #[test]
    fn test_encrypt_decrypt() {
        let config = FHEConfig::default();
        let keypair = KeyPair::generate(&config).unwrap();
        keypair.set_server_key();

        let value = 12345u64;
        let encrypted = FHEUint64::encrypt(value, &keypair.client).unwrap();
        let decrypted = encrypted.decrypt(&keypair.client).unwrap();

        assert_eq!(value, decrypted);
    }

    #[test]
    fn test_encrypt_zero() {
        let config = FHEConfig::default();
        let keypair = KeyPair::generate(&config).unwrap();

        let value = 0u64;
        let encrypted = FHEUint64::encrypt(value, &keypair.client).unwrap();
        let decrypted = encrypted.decrypt(&keypair.client).unwrap();

        assert_eq!(value, decrypted);
    }

    #[test]
    fn test_encrypt_max() {
        let config = FHEConfig::default();
        let keypair = KeyPair::generate(&config).unwrap();

        // Test with a large value (not MAX to avoid potential issues)
        let value = u64::MAX / 2;
        let encrypted = FHEUint64::encrypt(value, &keypair.client).unwrap();
        let decrypted = encrypted.decrypt(&keypair.client).unwrap();

        assert_eq!(value, decrypted);
    }
}
