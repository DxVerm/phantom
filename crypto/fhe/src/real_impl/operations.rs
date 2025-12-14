//! FHE Homomorphic Operations with Real TFHE-rs
//!
//! Operations on encrypted values without decryption.
//! These are performed by validators using the server key.

use crate::{FHEError, FHEResult};
use super::ciphertext::{FHECiphertext, FHEUint64};
use super::keys::ServerKey;
use tfhe::prelude::*;
use tfhe::FheBool as TfheFheBool;

/// Trait for homomorphic operations
pub trait HomomorphicOps {
    /// Add two encrypted values
    fn add(&self, other: &Self, server_key: &ServerKey) -> FHEResult<Self> where Self: Sized;

    /// Subtract two encrypted values
    fn sub(&self, other: &Self, server_key: &ServerKey) -> FHEResult<Self> where Self: Sized;

    /// Compare two encrypted values (returns encrypted boolean)
    fn lt(&self, other: &Self, server_key: &ServerKey) -> FHEResult<FHEBool>;

    /// Check if equal
    fn eq(&self, other: &Self, server_key: &ServerKey) -> FHEResult<FHEBool>;
}

/// Encrypted boolean for comparison results
#[derive(Clone)]
pub struct FHEBool {
    inner: TfheFheBool,
}

impl FHEBool {
    /// Create from TFHE FheBool
    pub fn from_tfhe(inner: TfheFheBool) -> Self {
        Self { inner }
    }

    /// Get reference to inner value
    pub fn inner(&self) -> &TfheFheBool {
        &self.inner
    }

    /// Decrypt to bool
    pub fn decrypt(&self, client_key: &super::keys::ClientKey) -> bool {
        self.inner.decrypt(client_key.inner())
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> FHEResult<Vec<u8>> {
        bincode::serialize(&self.inner)
            .map_err(|e| FHEError::SerializationError(e.to_string()))
    }

    /// Create from ciphertext for compatibility
    pub fn from_ciphertext(ct: FHECiphertext) -> FHEResult<Self> {
        let inner: TfheFheBool = bincode::deserialize(ct.data())
            .map_err(|e| FHEError::SerializationError(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Get underlying ciphertext
    pub fn ciphertext(&self) -> FHEResult<FHECiphertext> {
        let data = bincode::serialize(&self.inner)
            .map_err(|e| FHEError::SerializationError(e.to_string()))?;
        Ok(FHECiphertext::new(data, 1))
    }
}

impl std::fmt::Debug for FHEBool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FHEBool").finish()
    }
}

impl HomomorphicOps for FHEUint64 {
    fn add(&self, other: &Self, server_key: &ServerKey) -> FHEResult<Self> {
        FHEOps::add(self, other, server_key)
    }

    fn sub(&self, other: &Self, server_key: &ServerKey) -> FHEResult<Self> {
        FHEOps::sub(self, other, server_key)
    }

    fn lt(&self, other: &Self, server_key: &ServerKey) -> FHEResult<FHEBool> {
        FHEOps::lt(self, other, server_key)
    }

    fn eq(&self, other: &Self, server_key: &ServerKey) -> FHEResult<FHEBool> {
        FHEOps::eq(self, other, server_key)
    }
}

/// FHE Operations using server key
pub struct FHEOps;

impl FHEOps {
    /// Homomorphic addition of two encrypted u64 values
    ///
    /// This adds the encrypted values using TFHE-rs native operators.
    /// Server key must be set globally before calling.
    pub fn add(a: &FHEUint64, b: &FHEUint64, _server_key: &ServerKey) -> FHEResult<FHEUint64> {
        // TFHE-rs uses operator overloading for homomorphic ops
        // Server key is already set globally
        let result = a.inner() + b.inner();

        Ok(FHEUint64::from_tfhe_with_ops(
            result,
            a.op_count() + b.op_count() + 1
        ))
    }

    /// Homomorphic subtraction of two encrypted u64 values
    pub fn sub(a: &FHEUint64, b: &FHEUint64, _server_key: &ServerKey) -> FHEResult<FHEUint64> {
        let result = a.inner() - b.inner();

        Ok(FHEUint64::from_tfhe_with_ops(
            result,
            a.op_count() + b.op_count() + 1
        ))
    }

    /// Homomorphic multiplication
    pub fn mul(a: &FHEUint64, b: &FHEUint64, _server_key: &ServerKey) -> FHEResult<FHEUint64> {
        let result = a.inner() * b.inner();

        Ok(FHEUint64::from_tfhe_with_ops(
            result,
            a.op_count() + b.op_count() + 5  // Mul is more expensive
        ))
    }

    /// Homomorphic less-than comparison
    pub fn lt(a: &FHEUint64, b: &FHEUint64, _server_key: &ServerKey) -> FHEResult<FHEBool> {
        let result = a.inner().lt(b.inner());
        Ok(FHEBool::from_tfhe(result))
    }

    /// Homomorphic less-than-or-equal comparison
    pub fn le(a: &FHEUint64, b: &FHEUint64, _server_key: &ServerKey) -> FHEResult<FHEBool> {
        let result = a.inner().le(b.inner());
        Ok(FHEBool::from_tfhe(result))
    }

    /// Homomorphic greater-than comparison
    pub fn gt(a: &FHEUint64, b: &FHEUint64, _server_key: &ServerKey) -> FHEResult<FHEBool> {
        let result = a.inner().gt(b.inner());
        Ok(FHEBool::from_tfhe(result))
    }

    /// Homomorphic greater-than-or-equal comparison
    pub fn ge(a: &FHEUint64, b: &FHEUint64, _server_key: &ServerKey) -> FHEResult<FHEBool> {
        let result = a.inner().ge(b.inner());
        Ok(FHEBool::from_tfhe(result))
    }

    /// Homomorphic equality comparison
    pub fn eq(a: &FHEUint64, b: &FHEUint64, _server_key: &ServerKey) -> FHEResult<FHEBool> {
        let result = a.inner().eq(b.inner());
        Ok(FHEBool::from_tfhe(result))
    }

    /// Homomorphic not-equal comparison
    pub fn ne(a: &FHEUint64, b: &FHEUint64, _server_key: &ServerKey) -> FHEResult<FHEBool> {
        let result = a.inner().ne(b.inner());
        Ok(FHEBool::from_tfhe(result))
    }

    /// Add a plaintext scalar to encrypted value
    pub fn add_scalar(a: &FHEUint64, scalar: u64, _server_key: &ServerKey) -> FHEResult<FHEUint64> {
        let result = a.inner() + scalar;

        Ok(FHEUint64::from_tfhe_with_ops(
            result,
            a.op_count() + 1
        ))
    }

    /// Subtract a plaintext scalar from encrypted value
    pub fn sub_scalar(a: &FHEUint64, scalar: u64, _server_key: &ServerKey) -> FHEResult<FHEUint64> {
        let result = a.inner() - scalar;

        Ok(FHEUint64::from_tfhe_with_ops(
            result,
            a.op_count() + 1
        ))
    }

    /// Multiply encrypted value by plaintext scalar
    pub fn mul_scalar(a: &FHEUint64, scalar: u64, _server_key: &ServerKey) -> FHEResult<FHEUint64> {
        let result = a.inner() * scalar;

        Ok(FHEUint64::from_tfhe_with_ops(
            result,
            a.op_count() + 2
        ))
    }

    /// Bitwise AND
    pub fn and(a: &FHEUint64, b: &FHEUint64, _server_key: &ServerKey) -> FHEResult<FHEUint64> {
        let result = a.inner() & b.inner();
        Ok(FHEUint64::from_tfhe_with_ops(result, a.op_count() + b.op_count() + 1))
    }

    /// Bitwise OR
    pub fn or(a: &FHEUint64, b: &FHEUint64, _server_key: &ServerKey) -> FHEResult<FHEUint64> {
        let result = a.inner() | b.inner();
        Ok(FHEUint64::from_tfhe_with_ops(result, a.op_count() + b.op_count() + 1))
    }

    /// Bitwise XOR
    pub fn xor(a: &FHEUint64, b: &FHEUint64, _server_key: &ServerKey) -> FHEResult<FHEUint64> {
        let result = a.inner() ^ b.inner();
        Ok(FHEUint64::from_tfhe_with_ops(result, a.op_count() + b.op_count() + 1))
    }

    /// Left shift by plaintext amount
    pub fn shl(a: &FHEUint64, shift: u64, _server_key: &ServerKey) -> FHEResult<FHEUint64> {
        let result = a.inner() << shift;
        Ok(FHEUint64::from_tfhe_with_ops(result, a.op_count() + 1))
    }

    /// Right shift by plaintext amount
    pub fn shr(a: &FHEUint64, shift: u64, _server_key: &ServerKey) -> FHEResult<FHEUint64> {
        let result = a.inner() >> shift;
        Ok(FHEUint64::from_tfhe_with_ops(result, a.op_count() + 1))
    }

    /// Conditional select: if cond then a else b
    pub fn select(cond: &FHEBool, a: &FHEUint64, b: &FHEUint64, _server_key: &ServerKey) -> FHEResult<FHEUint64> {
        let result = cond.inner().if_then_else(a.inner(), b.inner());
        Ok(FHEUint64::from_tfhe_with_ops(result, a.op_count() + b.op_count() + 5))
    }

    /// Min of two encrypted values
    pub fn min(a: &FHEUint64, b: &FHEUint64, _server_key: &ServerKey) -> FHEResult<FHEUint64> {
        let result = a.inner().min(b.inner());
        Ok(FHEUint64::from_tfhe_with_ops(result, a.op_count() + b.op_count() + 3))
    }

    /// Max of two encrypted values
    pub fn max(a: &FHEUint64, b: &FHEUint64, _server_key: &ServerKey) -> FHEResult<FHEUint64> {
        let result = a.inner().max(b.inner());
        Ok(FHEUint64::from_tfhe_with_ops(result, a.op_count() + b.op_count() + 3))
    }

    /// Bootstrap a ciphertext to reduce noise
    /// Note: TFHE-rs handles bootstrapping automatically, this is mainly for tracking
    pub fn bootstrap(ct: &FHEUint64, _server_key: &ServerKey) -> FHEResult<FHEUint64> {
        // TFHE-rs automatically bootstraps as needed
        // We just reset our operation counter
        Ok(FHEUint64::from_tfhe_with_ops(ct.inner().clone(), 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FHEConfig;
    use super::super::keys::KeyPair;

    #[test]
    fn test_homomorphic_add() {
        let config = FHEConfig::default();
        let keypair = KeyPair::generate(&config).unwrap();
        keypair.set_server_key();

        let a = FHEUint64::encrypt(100, &keypair.client).unwrap();
        let b = FHEUint64::encrypt(50, &keypair.client).unwrap();

        let sum = FHEOps::add(&a, &b, &keypair.server).unwrap();
        let result = sum.decrypt(&keypair.client).unwrap();

        assert_eq!(result, 150);
    }

    #[test]
    fn test_homomorphic_sub() {
        let config = FHEConfig::default();
        let keypair = KeyPair::generate(&config).unwrap();
        keypair.set_server_key();

        let a = FHEUint64::encrypt(100, &keypair.client).unwrap();
        let b = FHEUint64::encrypt(30, &keypair.client).unwrap();

        let diff = FHEOps::sub(&a, &b, &keypair.server).unwrap();
        let result = diff.decrypt(&keypair.client).unwrap();

        assert_eq!(result, 70);
    }

    #[test]
    fn test_homomorphic_comparison() {
        let config = FHEConfig::default();
        let keypair = KeyPair::generate(&config).unwrap();
        keypair.set_server_key();

        let a = FHEUint64::encrypt(50, &keypair.client).unwrap();
        let b = FHEUint64::encrypt(100, &keypair.client).unwrap();

        let lt_result = FHEOps::lt(&a, &b, &keypair.server).unwrap();
        assert!(lt_result.decrypt(&keypair.client)); // 50 < 100

        let gt_result = FHEOps::gt(&a, &b, &keypair.server).unwrap();
        assert!(!gt_result.decrypt(&keypair.client)); // 50 > 100 is false
    }

    #[test]
    fn test_scalar_operations() {
        let config = FHEConfig::default();
        let keypair = KeyPair::generate(&config).unwrap();
        keypair.set_server_key();

        let a = FHEUint64::encrypt(100, &keypair.client).unwrap();

        let sum = FHEOps::add_scalar(&a, 25, &keypair.server).unwrap();
        assert_eq!(sum.decrypt(&keypair.client).unwrap(), 125);

        let diff = FHEOps::sub_scalar(&a, 25, &keypair.server).unwrap();
        assert_eq!(diff.decrypt(&keypair.client).unwrap(), 75);

        let prod = FHEOps::mul_scalar(&a, 3, &keypair.server).unwrap();
        assert_eq!(prod.decrypt(&keypair.client).unwrap(), 300);
    }
}
