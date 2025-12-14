//! State Fragments - The atomic units of the ESL
//!
//! A StateFragment represents an encrypted piece of state. Unlike blockchain
//! UTXOs or account states, fragments have no ordering and cannot be traced.
//!
//! This implementation uses REAL TFHE-rs for homomorphic encryption operations.

use crate::errors::ESLError;
use phantom_fhe::{
    FHECiphertext, FHEUint64, FHEConfig, FHEBool,
    FHEOps, ServerKey, ClientKey, PublicKey, KeyPair
};
use serde::{Deserialize, Serialize};

/// Unique identifier for a state fragment
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FragmentId([u8; 32]);

/// An encrypted balance that can be operated on homomorphically
///
/// This wraps a real TFHE ciphertext, storing the serialized form for
/// persistence while providing methods for homomorphic operations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedBalance {
    /// Serialized FHE ciphertext containing the encrypted balance
    ciphertext_data: Vec<u8>,
    /// Number of bits in the encrypted value
    bits: u8,
    /// Operation count (proxy for noise level)
    op_count: u32,
    /// Encryption scheme version
    scheme_version: u8,
}

/// Result of an encrypted comparison (e.g., balance >= 0)
#[derive(Clone, Debug)]
pub struct EncryptedBool {
    /// Serialized encrypted boolean
    pub(crate) data: Vec<u8>,
}

impl EncryptedBool {
    /// Create a new encrypted bool from raw data
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Convert to FHEBool for FHE operations
    pub fn to_fhe_bool(&self) -> Result<FHEBool, ESLError> {
        FHEBool::from_ciphertext(FHECiphertext::new(self.data.clone(), 1))
            .map_err(|e| ESLError::EncryptionError(e.to_string()))
    }
}

/// A state fragment - the atomic unit of the ESL
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateFragment {
    /// Unique fragment identifier
    pub id: FragmentId,
    /// Encrypted balance (FHE ciphertext)
    pub encrypted_balance: EncryptedBalance,
    /// Commitment to the plaintext state
    pub commitment: [u8; 32],
    /// Owner's public key (encrypted or stealth address)
    pub owner_pk_hash: [u8; 32],
    /// Fragment creation epoch (for time-based operations)
    pub epoch: u64,
    /// Post-quantum signature from witness set
    pub witness_signature: Option<Vec<u8>>,
}

impl FragmentId {
    /// Create a new fragment ID from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generate a random fragment ID
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        Self(bytes)
    }

    /// Generate a fragment ID from components
    pub fn derive(commitment: &[u8; 32], epoch: u64, randomness: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(commitment);
        hasher.update(&epoch.to_le_bytes());
        hasher.update(randomness);
        Self(*hasher.finalize().as_bytes())
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl EncryptedBalance {
    /// Create a new encrypted balance from serialized ciphertext data
    pub fn new(ciphertext_data: Vec<u8>) -> Self {
        Self {
            ciphertext_data,
            bits: 64,
            op_count: 0,
            scheme_version: 2, // TFHE v2 (real implementation)
        }
    }

    /// Create an encrypted balance from a plaintext value using client key
    ///
    /// This encrypts a u64 balance value using TFHE.
    pub fn encrypt(value: u64, client_key: &ClientKey) -> Result<Self, ESLError> {
        let encrypted = FHEUint64::encrypt(value, client_key)
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        let ciphertext = encrypted.to_ciphertext()
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        Ok(Self {
            ciphertext_data: ciphertext.data().to_vec(),
            bits: 64,
            op_count: 0,
            scheme_version: 2,
        })
    }

    /// Create an encrypted balance from a plaintext value using public key
    ///
    /// Allows third parties to encrypt values for a specific owner.
    pub fn encrypt_with_public(value: u64, public_key: &PublicKey) -> Result<Self, ESLError> {
        let encrypted = FHEUint64::encrypt_with_public(value, public_key)
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        let ciphertext = encrypted.to_ciphertext()
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        Ok(Self {
            ciphertext_data: ciphertext.data().to_vec(),
            bits: 64,
            op_count: 0,
            scheme_version: 2,
        })
    }

    /// Decrypt the balance using client key
    ///
    /// Only the balance owner (with client key) can decrypt.
    pub fn decrypt(&self, client_key: &ClientKey) -> Result<u64, ESLError> {
        let encrypted = self.to_fhe_uint64()?;
        encrypted.decrypt(client_key)
            .map_err(|e| ESLError::EncryptionError(e.to_string()))
    }

    /// Convert to FHEUint64 for operations
    fn to_fhe_uint64(&self) -> Result<FHEUint64, ESLError> {
        let ciphertext = FHECiphertext::new(self.ciphertext_data.clone(), self.bits);
        FHEUint64::from_ciphertext(&ciphertext)
            .map_err(|e| ESLError::EncryptionError(e.to_string()))
    }

    /// Create from FHEUint64 after operations
    fn from_fhe_uint64(encrypted: &FHEUint64, prev_ops: u32) -> Result<Self, ESLError> {
        let ciphertext = encrypted.to_ciphertext()
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        Ok(Self {
            ciphertext_data: ciphertext.data().to_vec(),
            bits: 64,
            op_count: prev_ops + encrypted.op_count(),
            scheme_version: 2,
        })
    }

    /// Get the ciphertext bytes (for hashing, storage, etc.)
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext_data
    }

    /// Get the encryption scheme version
    pub fn scheme_version(&self) -> u8 {
        self.scheme_version
    }

    /// Get the operation count (noise proxy)
    pub fn op_count(&self) -> u32 {
        self.op_count
    }

    /// Check if bootstrapping might be needed
    pub fn needs_bootstrap(&self) -> bool {
        self.op_count > 50
    }

    /// Add two encrypted balances (homomorphic addition)
    ///
    /// Uses TFHE-rs for real homomorphic addition.
    /// Server key must be set globally before calling.
    pub fn add(&self, other: &EncryptedBalance, server_key: &ServerKey) -> Result<EncryptedBalance, ESLError> {
        if self.scheme_version != other.scheme_version {
            return Err(ESLError::EncryptionError(
                "Incompatible encryption schemes".into()
            ));
        }

        let a = self.to_fhe_uint64()?;
        let b = other.to_fhe_uint64()?;

        let result = FHEOps::add(&a, &b, server_key)
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        Self::from_fhe_uint64(&result, self.op_count + other.op_count)
    }

    /// Subtract two encrypted balances (homomorphic subtraction)
    ///
    /// Uses TFHE-rs for real homomorphic subtraction.
    pub fn sub(&self, other: &EncryptedBalance, server_key: &ServerKey) -> Result<EncryptedBalance, ESLError> {
        if self.scheme_version != other.scheme_version {
            return Err(ESLError::EncryptionError(
                "Incompatible encryption schemes".into()
            ));
        }

        let a = self.to_fhe_uint64()?;
        let b = other.to_fhe_uint64()?;

        let result = FHEOps::sub(&a, &b, server_key)
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        Self::from_fhe_uint64(&result, self.op_count + other.op_count)
    }

    /// Multiply by a plaintext scalar (homomorphic scalar multiplication)
    pub fn mul_scalar(&self, scalar: u64, server_key: &ServerKey) -> Result<EncryptedBalance, ESLError> {
        let a = self.to_fhe_uint64()?;

        let result = FHEOps::mul_scalar(&a, scalar, server_key)
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        Self::from_fhe_uint64(&result, self.op_count)
    }

    /// Add a plaintext scalar (homomorphic scalar addition)
    pub fn add_scalar(&self, scalar: u64, server_key: &ServerKey) -> Result<EncryptedBalance, ESLError> {
        let a = self.to_fhe_uint64()?;

        let result = FHEOps::add_scalar(&a, scalar, server_key)
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        Self::from_fhe_uint64(&result, self.op_count)
    }

    /// Check if balance is non-negative (encrypted comparison with zero)
    ///
    /// Returns an encrypted boolean that can be decrypted or used in ZK proofs.
    /// For u64, this always returns true (unsigned can't be negative).
    /// This is kept for API compatibility and potential signed balance support.
    pub fn is_non_negative(&self, server_key: &ServerKey) -> Result<EncryptedBool, ESLError> {
        let a = self.to_fhe_uint64()?;

        // For unsigned u64, we check if a >= 0, which is always true
        // But we perform the comparison to get an encrypted result
        // that can be verified without revealing the actual value
        let zero = FHEUint64::encrypt(0, &ClientKey::generate(&FHEConfig::default())
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?)
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        let result = FHEOps::ge(&a, &zero, server_key)
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        let data = result.to_bytes()
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        Ok(EncryptedBool { data })
    }

    /// Compare two encrypted balances: self < other
    pub fn lt(&self, other: &EncryptedBalance, server_key: &ServerKey) -> Result<EncryptedBool, ESLError> {
        let a = self.to_fhe_uint64()?;
        let b = other.to_fhe_uint64()?;

        let result = FHEOps::lt(&a, &b, server_key)
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        let data = result.to_bytes()
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        Ok(EncryptedBool { data })
    }

    /// Compare two encrypted balances: self <= other
    pub fn le(&self, other: &EncryptedBalance, server_key: &ServerKey) -> Result<EncryptedBool, ESLError> {
        let a = self.to_fhe_uint64()?;
        let b = other.to_fhe_uint64()?;

        let result = FHEOps::le(&a, &b, server_key)
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        let data = result.to_bytes()
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        Ok(EncryptedBool { data })
    }

    /// Compare two encrypted balances: self > other
    pub fn gt(&self, other: &EncryptedBalance, server_key: &ServerKey) -> Result<EncryptedBool, ESLError> {
        let a = self.to_fhe_uint64()?;
        let b = other.to_fhe_uint64()?;

        let result = FHEOps::gt(&a, &b, server_key)
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        let data = result.to_bytes()
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        Ok(EncryptedBool { data })
    }

    /// Compare two encrypted balances: self >= other
    pub fn ge(&self, other: &EncryptedBalance, server_key: &ServerKey) -> Result<EncryptedBool, ESLError> {
        let a = self.to_fhe_uint64()?;
        let b = other.to_fhe_uint64()?;

        let result = FHEOps::ge(&a, &b, server_key)
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        let data = result.to_bytes()
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        Ok(EncryptedBool { data })
    }

    /// Check equality of two encrypted balances
    pub fn eq(&self, other: &EncryptedBalance, server_key: &ServerKey) -> Result<EncryptedBool, ESLError> {
        let a = self.to_fhe_uint64()?;
        let b = other.to_fhe_uint64()?;

        let result = FHEOps::eq(&a, &b, server_key)
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        let data = result.to_bytes()
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        Ok(EncryptedBool { data })
    }

    /// Min of two encrypted balances
    pub fn min(&self, other: &EncryptedBalance, server_key: &ServerKey) -> Result<EncryptedBalance, ESLError> {
        let a = self.to_fhe_uint64()?;
        let b = other.to_fhe_uint64()?;

        let result = FHEOps::min(&a, &b, server_key)
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        Self::from_fhe_uint64(&result, self.op_count + other.op_count)
    }

    /// Max of two encrypted balances
    pub fn max(&self, other: &EncryptedBalance, server_key: &ServerKey) -> Result<EncryptedBalance, ESLError> {
        let a = self.to_fhe_uint64()?;
        let b = other.to_fhe_uint64()?;

        let result = FHEOps::max(&a, &b, server_key)
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        Self::from_fhe_uint64(&result, self.op_count + other.op_count)
    }

    /// Multiply two encrypted balances (homomorphic multiplication)
    ///
    /// WARNING: Encrypted multiplication is very expensive and increases noise.
    pub fn mul(&self, other: &EncryptedBalance, server_key: &ServerKey) -> Result<EncryptedBalance, ESLError> {
        if self.scheme_version != other.scheme_version {
            return Err(ESLError::EncryptionError(
                "Incompatible encryption schemes".into()
            ));
        }

        let a = self.to_fhe_uint64()?;
        let b = other.to_fhe_uint64()?;

        let result = FHEOps::mul(&a, &b, server_key)
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        Self::from_fhe_uint64(&result, self.op_count + other.op_count + 10) // Extra ops for mul
    }

    /// Subtract a plaintext scalar (homomorphic scalar subtraction)
    pub fn sub_scalar(&self, scalar: u64, server_key: &ServerKey) -> Result<EncryptedBalance, ESLError> {
        let a = self.to_fhe_uint64()?;

        let result = FHEOps::sub_scalar(&a, scalar, server_key)
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        Self::from_fhe_uint64(&result, self.op_count)
    }

    /// Serialize the balance to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize a balance from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ESLError> {
        bincode::deserialize(bytes)
            .map_err(|e| ESLError::SerializationError(e.to_string()))
    }

    /// Get ciphertext bytes (alias for ciphertext())
    pub fn ciphertext_bytes(&self) -> &[u8] {
        &self.ciphertext_data
    }

    /// Create an EncryptedBalance from an EncryptedBool
    ///
    /// This converts the encrypted boolean (0 or 1) into an encrypted u64
    /// by using the encrypted bool's data directly. The value will be 0 or 1.
    pub fn from_encrypted_bool(encrypted_bool: EncryptedBool) -> Result<Self, ESLError> {
        // The EncryptedBool data represents an encrypted 0 or 1
        // We store it directly as an EncryptedBalance with the bool data
        Ok(Self {
            ciphertext_data: encrypted_bool.data,
            bits: 1, // It's really just 1 bit
            op_count: 1,
            scheme_version: 2,
        })
    }

    /// Conditional select: if condition then if_true else if_false
    ///
    /// This is the fundamental primitive for FHE branching. Since we cannot
    /// know the encrypted condition value, we compute both branches and use
    /// FHE's select operation to obliviously choose the correct result.
    ///
    /// # Arguments
    /// * `condition` - Encrypted boolean (0 or 1)
    /// * `if_true` - Value to return if condition is true (encrypted 1)
    /// * `if_false` - Value to return if condition is false (encrypted 0)
    /// * `server_key` - Server key for FHE operations
    ///
    /// # Example
    /// ```ignore
    /// // Compute: result = (a > b) ? a : b (max function)
    /// let cond = a.gt(&b, &server_key)?;
    /// let result = EncryptedBalance::select(&cond, &a, &b, &server_key)?;
    /// ```
    pub fn select(
        condition: &EncryptedBool,
        if_true: &EncryptedBalance,
        if_false: &EncryptedBalance,
        server_key: &ServerKey,
    ) -> Result<EncryptedBalance, ESLError> {
        // Convert EncryptedBool to FHEBool
        let cond = condition.to_fhe_bool()?;

        // Convert EncryptedBalances to FHEUint64
        let a = if_true.to_fhe_uint64()?;
        let b = if_false.to_fhe_uint64()?;

        // Use FHEOps::select for oblivious selection
        let result = FHEOps::select(&cond, &a, &b, server_key)
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        // Convert back to EncryptedBalance
        Self::from_fhe_uint64(&result, if_true.op_count + if_false.op_count + 5)
    }

    /// Convert to EncryptedBool (for use as condition)
    ///
    /// Assumes the balance holds an encrypted 0 or 1.
    /// Used when a balance on the stack represents a boolean condition.
    pub fn to_encrypted_bool(&self) -> Result<EncryptedBool, ESLError> {
        // The ciphertext_data already contains serialized FHEBool/FHEUint64
        // For a balance that was created from a comparison or boolean operation,
        // we can treat its data as an encrypted boolean
        Ok(EncryptedBool {
            data: self.ciphertext_data.clone(),
        })
    }
}

impl EncryptedBool {
    /// Decrypt the encrypted boolean using client key
    pub fn decrypt(&self, client_key: &ClientKey) -> Result<bool, ESLError> {
        let fhe_bool = FHEBool::from_ciphertext(FHECiphertext::new(self.data.clone(), 1))
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        Ok(fhe_bool.decrypt(client_key))
    }

    /// Get the serialized data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Logical AND of two encrypted booleans
    pub fn and(&self, other: &EncryptedBool, server_key: &ServerKey) -> Result<EncryptedBool, ESLError> {
        let a = self.to_fhe_bool()?;
        let b = other.to_fhe_bool()?;

        // Use bitwise AND on the underlying TFHE bools
        let result_inner = a.inner() & b.inner();
        let result = FHEBool::from_tfhe(result_inner);

        let data = result.to_bytes()
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        Ok(EncryptedBool { data })
    }

    /// Logical OR of two encrypted booleans
    pub fn or(&self, other: &EncryptedBool, server_key: &ServerKey) -> Result<EncryptedBool, ESLError> {
        let a = self.to_fhe_bool()?;
        let b = other.to_fhe_bool()?;

        // Use bitwise OR on the underlying TFHE bools
        let result_inner = a.inner() | b.inner();
        let result = FHEBool::from_tfhe(result_inner);

        let data = result.to_bytes()
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        Ok(EncryptedBool { data })
    }

    /// Logical NOT of an encrypted boolean
    pub fn not(&self, server_key: &ServerKey) -> Result<EncryptedBool, ESLError> {
        let a = self.to_fhe_bool()?;

        // Use bitwise NOT on the underlying TFHE bool
        let result_inner = !a.inner();
        let result = FHEBool::from_tfhe(result_inner);

        let data = result.to_bytes()
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        Ok(EncryptedBool { data })
    }
}

impl StateFragment {
    /// Create a new state fragment
    pub fn new(
        encrypted_balance: EncryptedBalance,
        commitment: [u8; 32],
        owner_pk_hash: [u8; 32],
        epoch: u64,
    ) -> Self {
        let randomness = FragmentId::random().0;
        let id = FragmentId::derive(&commitment, epoch, &randomness);

        Self {
            id,
            encrypted_balance,
            commitment,
            owner_pk_hash,
            epoch,
            witness_signature: None,
        }
    }

    /// Create a fragment with a specific ID
    pub fn with_id(
        id: FragmentId,
        encrypted_balance: EncryptedBalance,
        commitment: [u8; 32],
        owner_pk_hash: [u8; 32],
        epoch: u64,
    ) -> Self {
        Self {
            id,
            encrypted_balance,
            commitment,
            owner_pk_hash,
            epoch,
            witness_signature: None,
        }
    }

    /// Create a fragment with an encrypted balance from plaintext
    pub fn from_plaintext(
        balance: u64,
        commitment: [u8; 32],
        owner_pk_hash: [u8; 32],
        epoch: u64,
        client_key: &ClientKey,
    ) -> Result<Self, ESLError> {
        let encrypted_balance = EncryptedBalance::encrypt(balance, client_key)?;
        Ok(Self::new(encrypted_balance, commitment, owner_pk_hash, epoch))
    }

    /// Set the witness signature (called after attestation)
    pub fn set_witness_signature(&mut self, signature: Vec<u8>) {
        self.witness_signature = Some(signature);
    }

    /// Check if the fragment has been attested by witnesses
    pub fn is_attested(&self) -> bool {
        self.witness_signature.is_some()
    }

    /// Compute a hash of the fragment for signing
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.id.as_bytes());
        hasher.update(&self.commitment);
        hasher.update(&self.owner_pk_hash);
        hasher.update(&self.epoch.to_le_bytes());
        hasher.update(self.encrypted_balance.ciphertext());
        *hasher.finalize().as_bytes()
    }

    /// Verify the fragment's structural integrity
    pub fn verify_structure(&self) -> Result<(), ESLError> {
        // Verify commitment is non-zero
        if self.commitment == [0u8; 32] {
            return Err(ESLError::InvalidFragment(
                "Zero commitment".into()
            ));
        }

        // Verify owner hash is non-zero
        if self.owner_pk_hash == [0u8; 32] {
            return Err(ESLError::InvalidFragment(
                "Zero owner hash".into()
            ));
        }

        // Verify ciphertext is not empty
        if self.encrypted_balance.ciphertext().is_empty() {
            return Err(ESLError::InvalidFragment(
                "Empty encrypted balance".into()
            ));
        }

        Ok(())
    }

    /// Serialize the fragment
    pub fn serialize(&self) -> Result<Vec<u8>, ESLError> {
        bincode::serialize(self)
            .map_err(|e| ESLError::SerializationError(e.to_string()))
    }

    /// Deserialize a fragment
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ESLError> {
        bincode::deserialize(bytes)
            .map_err(|e| ESLError::SerializationError(e.to_string()))
    }

    /// Decrypt the fragment's balance (requires owner's client key)
    pub fn decrypt_balance(&self, client_key: &ClientKey) -> Result<u64, ESLError> {
        self.encrypted_balance.decrypt(client_key)
    }
}

/// A fragment reference (lightweight pointer to a fragment)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FragmentRef {
    /// Fragment ID
    pub id: FragmentId,
    /// Commitment (for verification)
    pub commitment: [u8; 32],
    /// Epoch
    pub epoch: u64,
}

impl FragmentRef {
    /// Create a reference from a fragment
    pub fn from_fragment(fragment: &StateFragment) -> Self {
        Self {
            id: fragment.id,
            commitment: fragment.commitment,
            epoch: fragment.epoch,
        }
    }
}

/// FHE key management for ESL operations
///
/// Holds the keys needed for encrypted balance operations.
pub struct ESLKeys {
    /// Client key (secret, held by balance owner)
    pub client: ClientKey,
    /// Server key (can be shared with validators)
    pub server: ServerKey,
    /// Public key (can be published)
    pub public: PublicKey,
}

impl ESLKeys {
    /// Generate a new key set
    ///
    /// WARNING: Key generation is slow (~10-30 seconds)
    pub fn generate() -> Result<Self, ESLError> {
        let config = FHEConfig::default();
        let keypair = KeyPair::generate(&config)
            .map_err(|e| ESLError::EncryptionError(e.to_string()))?;

        // Set the server key globally for operations
        keypair.set_server_key();

        Ok(Self {
            client: keypair.client,
            server: keypair.server,
            public: keypair.public,
        })
    }

    /// Set the server key globally (required before FHE operations)
    pub fn set_server_key(&self) {
        self.server.set_global();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_id_random() {
        let id1 = FragmentId::random();
        let id2 = FragmentId::random();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_fragment_id_derive() {
        let commitment = [1u8; 32];
        let epoch = 100;
        let randomness = [2u8; 32];

        let id1 = FragmentId::derive(&commitment, epoch, &randomness);
        let id2 = FragmentId::derive(&commitment, epoch, &randomness);

        assert_eq!(id1, id2);
    }

    // Note: These tests require TFHE key generation which is slow (~10-30s)
    // They are marked with #[ignore] for CI and can be run with:
    // cargo test -p phantom-esl --release -- --ignored

    #[test]
    #[ignore]
    fn test_encrypted_balance_encrypt_decrypt() {
        let keys = ESLKeys::generate().unwrap();

        let value = 1000u64;
        let balance = EncryptedBalance::encrypt(value, &keys.client).unwrap();
        let decrypted = balance.decrypt(&keys.client).unwrap();

        assert_eq!(value, decrypted);
    }

    #[test]
    #[ignore]
    fn test_encrypted_balance_add() {
        let keys = ESLKeys::generate().unwrap();

        let balance1 = EncryptedBalance::encrypt(100, &keys.client).unwrap();
        let balance2 = EncryptedBalance::encrypt(50, &keys.client).unwrap();

        let result = balance1.add(&balance2, &keys.server).unwrap();
        let decrypted = result.decrypt(&keys.client).unwrap();

        assert_eq!(decrypted, 150);
    }

    #[test]
    #[ignore]
    fn test_encrypted_balance_sub() {
        let keys = ESLKeys::generate().unwrap();

        let balance1 = EncryptedBalance::encrypt(100, &keys.client).unwrap();
        let balance2 = EncryptedBalance::encrypt(30, &keys.client).unwrap();

        let result = balance1.sub(&balance2, &keys.server).unwrap();
        let decrypted = result.decrypt(&keys.client).unwrap();

        assert_eq!(decrypted, 70);
    }

    #[test]
    #[ignore]
    fn test_encrypted_balance_comparison() {
        let keys = ESLKeys::generate().unwrap();

        let balance1 = EncryptedBalance::encrypt(50, &keys.client).unwrap();
        let balance2 = EncryptedBalance::encrypt(100, &keys.client).unwrap();

        let lt_result = balance1.lt(&balance2, &keys.server).unwrap();
        assert!(lt_result.decrypt(&keys.client).unwrap()); // 50 < 100

        let gt_result = balance1.gt(&balance2, &keys.server).unwrap();
        assert!(!gt_result.decrypt(&keys.client).unwrap()); // 50 > 100 is false
    }

    #[test]
    #[ignore]
    fn test_state_fragment_with_real_encryption() {
        let keys = ESLKeys::generate().unwrap();

        let balance = 1000u64;
        let commitment = [1u8; 32];
        let owner = [2u8; 32];

        let fragment = StateFragment::from_plaintext(
            balance, commitment, owner, 1, &keys.client
        ).unwrap();

        assert!(!fragment.is_attested());
        assert!(fragment.verify_structure().is_ok());

        // Decrypt and verify balance
        let decrypted = fragment.decrypt_balance(&keys.client).unwrap();
        assert_eq!(decrypted, balance);
    }

    #[test]
    #[ignore]
    fn test_fragment_serialization_with_real_fhe() {
        let keys = ESLKeys::generate().unwrap();

        let fragment = StateFragment::from_plaintext(
            500, [1u8; 32], [2u8; 32], 1, &keys.client
        ).unwrap();

        let serialized = fragment.serialize().unwrap();
        let deserialized = StateFragment::deserialize(&serialized).unwrap();

        assert_eq!(fragment.id, deserialized.id);
        assert_eq!(fragment.commitment, deserialized.commitment);

        // Verify encrypted balance survives serialization
        let original_balance = fragment.decrypt_balance(&keys.client).unwrap();
        let deserialized_balance = deserialized.decrypt_balance(&keys.client).unwrap();
        assert_eq!(original_balance, deserialized_balance);
    }

    #[test]
    #[ignore]
    fn test_scalar_operations() {
        let keys = ESLKeys::generate().unwrap();

        let balance = EncryptedBalance::encrypt(100, &keys.client).unwrap();

        // Test scalar multiplication
        let doubled = balance.mul_scalar(2, &keys.server).unwrap();
        assert_eq!(doubled.decrypt(&keys.client).unwrap(), 200);

        // Test scalar addition
        let added = balance.add_scalar(50, &keys.server).unwrap();
        assert_eq!(added.decrypt(&keys.client).unwrap(), 150);
    }

    #[test]
    #[ignore]
    fn test_min_max_operations() {
        let keys = ESLKeys::generate().unwrap();

        let balance1 = EncryptedBalance::encrypt(30, &keys.client).unwrap();
        let balance2 = EncryptedBalance::encrypt(70, &keys.client).unwrap();

        let min_result = balance1.min(&balance2, &keys.server).unwrap();
        assert_eq!(min_result.decrypt(&keys.client).unwrap(), 30);

        let max_result = balance1.max(&balance2, &keys.server).unwrap();
        assert_eq!(max_result.decrypt(&keys.client).unwrap(), 70);
    }

    // Fast tests that don't require FHE key generation
    #[test]
    fn test_encrypted_balance_new() {
        let balance = EncryptedBalance::new(vec![0u8; 64]);
        assert_eq!(balance.scheme_version(), 2);
        assert_eq!(balance.op_count(), 0);
        assert!(!balance.needs_bootstrap());
    }

    #[test]
    fn test_fragment_ref() {
        let balance = EncryptedBalance::new(vec![0u8; 64]);
        let fragment = StateFragment::new(balance, [1u8; 32], [2u8; 32], 100);

        let frag_ref = FragmentRef::from_fragment(&fragment);
        assert_eq!(frag_ref.id, fragment.id);
        assert_eq!(frag_ref.commitment, fragment.commitment);
        assert_eq!(frag_ref.epoch, fragment.epoch);
    }
}
