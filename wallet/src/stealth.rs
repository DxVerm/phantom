//! Stealth Addresses - One-time addresses for transaction privacy
//!
//! Implements Dual-Key Stealth Address Protocol (DKSAP) with post-quantum keys.
//! Each transaction generates a unique recipient address that cannot be linked
//! to the recipient's public key without knowing the private key.
//!
//! # Protocol Overview
//! 1. Sender generates ephemeral keypair (r, R = r·G)
//! 2. Sender computes shared secret: s = H(r·V) where V is recipient's view key
//! 3. Sender derives one-time address: P' = H(s)·G + S where S is recipient's spend key
//! 4. Recipient scans by computing s' = H(v·R) and checking if P' = H(s')·G + S
//! 5. Recipient can spend using private key: x' = H(s') + s

use phantom_pq::{
    kyber::{self, KyberPublicKey, KyberSecretKey, KyberCiphertext},
    dilithium::{self, DilithiumPublicKey, DilithiumSecretKey},
    SecurityLevel,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use std::fmt;

/// Stealth address errors
#[derive(Debug, Error)]
pub enum StealthError {
    #[error("Invalid stealth address format")]
    InvalidFormat,
    #[error("Key derivation failed: {0}")]
    DerivationFailed(String),
    #[error("Decapsulation failed: {0}")]
    DecapsulationFailed(String),
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
}

/// View key for scanning incoming transactions
#[derive(Clone)]
pub struct ViewKey {
    /// Private view key (Kyber secret key for decapsulation)
    secret_key: KyberSecretKey,
    /// Public view key (Kyber public key)
    pub public_key: KyberPublicKey,
}

impl ViewKey {
    /// Generate a new view key pair
    pub fn generate() -> Result<Self, StealthError> {
        let keypair = kyber::generate_keypair(SecurityLevel::Level5)
            .map_err(|e| StealthError::CryptoError(e.to_string()))?;

        Ok(Self {
            secret_key: keypair.secret_key,
            public_key: keypair.public_key,
        })
    }

    /// Create from existing keys
    pub fn from_keys(secret_key: KyberSecretKey, public_key: KyberPublicKey) -> Self {
        Self { secret_key, public_key }
    }

    /// Decapsulate a shared secret from ciphertext
    pub fn decapsulate(&self, ciphertext: &KyberCiphertext) -> Result<[u8; 32], StealthError> {
        let shared_secret = kyber::decapsulate(&self.secret_key, ciphertext)
            .map_err(|e| StealthError::DecapsulationFailed(e.to_string()))?;

        // Return raw shared secret bytes (Kyber produces 32 bytes)
        // Must match the sender side which uses shared_secret.as_bytes() directly
        let mut result = [0u8; 32];
        let ss_bytes = shared_secret.as_bytes();
        let len = ss_bytes.len().min(32);
        result[..len].copy_from_slice(&ss_bytes[..len]);
        Ok(result)
    }

    /// Get public key bytes
    pub fn public_bytes(&self) -> &[u8] {
        self.public_key.as_bytes()
    }

    /// Get secret key (for serialization)
    pub fn secret_key(&self) -> &KyberSecretKey {
        &self.secret_key
    }
}

/// Spend key for authorizing transactions
#[derive(Clone)]
pub struct SpendKey {
    /// Private spend key (Dilithium secret key)
    secret_key: DilithiumSecretKey,
    /// Public spend key (Dilithium public key)
    pub public_key: DilithiumPublicKey,
}

impl SpendKey {
    /// Generate a new spend key pair
    pub fn generate() -> Result<Self, StealthError> {
        let keypair = dilithium::generate_keypair(SecurityLevel::Level5)
            .map_err(|e| StealthError::CryptoError(e.to_string()))?;

        Ok(Self {
            secret_key: keypair.secret_key,
            public_key: keypair.public_key,
        })
    }

    /// Create from existing keys
    pub fn from_keys(secret_key: DilithiumSecretKey, public_key: DilithiumPublicKey) -> Self {
        Self { secret_key, public_key }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, StealthError> {
        let signature = dilithium::sign(&self.secret_key, message)
            .map_err(|e| StealthError::CryptoError(e.to_string()))?;
        Ok(signature.as_bytes().to_vec())
    }

    /// Get the private key bytes for deriving one-time spend keys
    pub fn private_bytes(&self) -> &[u8] {
        self.secret_key.as_bytes()
    }

    /// Get public key bytes
    pub fn public_bytes(&self) -> &[u8] {
        self.public_key.as_bytes()
    }

    /// Get secret key (for serialization)
    pub fn secret_key(&self) -> &DilithiumSecretKey {
        &self.secret_key
    }
}

/// Full stealth address (published by recipient)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StealthAddress {
    /// View public key bytes (for Kyber encapsulation)
    pub view_public_key: Vec<u8>,
    /// Spend public key bytes (for Dilithium verification)
    pub spend_public_key: Vec<u8>,
}

impl StealthAddress {
    /// Create a stealth address from view and spend keys
    pub fn new(view_key: &ViewKey, spend_key: &SpendKey) -> Self {
        Self {
            view_public_key: view_key.public_bytes().to_vec(),
            spend_public_key: spend_key.public_bytes().to_vec(),
        }
    }

    /// Encode as bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.view_public_key.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.view_public_key);
        bytes.extend_from_slice(&(self.spend_public_key.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.spend_public_key);
        bytes
    }

    /// Decode from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StealthError> {
        if bytes.len() < 8 {
            return Err(StealthError::InvalidFormat);
        }

        let mut offset = 0;

        let view_len = u32::from_le_bytes(
            bytes[offset..offset+4].try_into().unwrap()
        ) as usize;
        offset += 4;

        if bytes.len() < offset + view_len + 4 {
            return Err(StealthError::InvalidFormat);
        }
        let view_public_key = bytes[offset..offset+view_len].to_vec();
        offset += view_len;

        let spend_len = u32::from_le_bytes(
            bytes[offset..offset+4].try_into().unwrap()
        ) as usize;
        offset += 4;

        if bytes.len() < offset + spend_len {
            return Err(StealthError::InvalidFormat);
        }
        let spend_public_key = bytes[offset..offset+spend_len].to_vec();

        Ok(Self {
            view_public_key,
            spend_public_key,
        })
    }

    /// Compute address hash (32 bytes for indexing)
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"phantom_stealth_address");
        hasher.update(&self.view_public_key);
        hasher.update(&self.spend_public_key);
        *hasher.finalize().as_bytes()
    }

    /// Get view public key as typed struct
    pub fn view_public_key_typed(&self) -> Result<KyberPublicKey, StealthError> {
        KyberPublicKey::from_bytes(&self.view_public_key, SecurityLevel::Level5)
            .map_err(|e| StealthError::CryptoError(e.to_string()))
    }
}

/// One-time payment address (derived for each transaction)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OneTimeAddress {
    /// Encapsulated secret bytes (sent with transaction)
    pub encapsulated_secret: Vec<u8>,
    /// Security level used
    #[serde(default)]
    level: SecurityLevel,
    /// Derived one-time public key hash (for recipient to scan)
    pub one_time_key_hash: [u8; 32],
    /// Randomness used in derivation (encrypted for recipient)
    pub encrypted_randomness: Vec<u8>,
}

/// Default security level for PHANTOM (use Level5 for maximum security)
pub const DEFAULT_SECURITY_LEVEL: SecurityLevel = SecurityLevel::Level5;

impl OneTimeAddress {
    /// Derive a one-time address from a stealth address (sender side)
    pub fn derive_for_recipient(
        stealth_addr: &StealthAddress,
    ) -> Result<(Self, [u8; 32]), StealthError> {
        // Get recipient's view public key
        let view_pk = stealth_addr.view_public_key_typed()?;

        // Encapsulate to recipient's view key
        let (ciphertext, shared_secret) = kyber::encapsulate(&view_pk)
            .map_err(|e| StealthError::CryptoError(e.to_string()))?;

        // Derive one-time key from shared secret and spend key
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"phantom_one_time_key");
        hasher.update(shared_secret.as_bytes());
        hasher.update(&stealth_addr.spend_public_key);
        let one_time_key_hash = *hasher.finalize().as_bytes();

        // Generate randomness for the note
        let mut randomness = [0u8; 32];
        getrandom::getrandom(&mut randomness)
            .map_err(|e| StealthError::CryptoError(e.to_string()))?;

        // Encrypt randomness with shared secret (simple XOR with derived key)
        let encryption_key = blake3::derive_key("phantom_randomness_encryption", shared_secret.as_bytes());
        let encrypted_randomness: Vec<u8> = randomness.iter()
            .zip(encryption_key.iter())
            .map(|(r, k)| r ^ k)
            .collect();

        let ota = OneTimeAddress {
            encapsulated_secret: ciphertext.as_bytes().to_vec(),
            level: SecurityLevel::Level5,
            one_time_key_hash,
            encrypted_randomness,
        };

        Ok((ota, randomness))
    }

    /// Get ciphertext as typed struct
    fn ciphertext(&self) -> Result<KyberCiphertext, StealthError> {
        KyberCiphertext::from_bytes(&self.encapsulated_secret, self.level)
            .map_err(|e| StealthError::CryptoError(e.to_string()))
    }

    /// Check if this address belongs to us (recipient side)
    pub fn scan(
        &self,
        view_key: &ViewKey,
        spend_key: &SpendKey,
    ) -> Result<bool, StealthError> {
        // Decapsulate shared secret
        let ciphertext = self.ciphertext()?;
        let shared_secret = view_key.decapsulate(&ciphertext)?;

        // Derive expected one-time key
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"phantom_one_time_key");
        hasher.update(&shared_secret);
        hasher.update(spend_key.public_bytes());
        let expected_hash = *hasher.finalize().as_bytes();

        Ok(expected_hash == self.one_time_key_hash)
    }

    /// Recover the randomness and derive spending key (recipient side)
    pub fn recover(
        &self,
        view_key: &ViewKey,
        spend_key: &SpendKey,
    ) -> Result<(SpendingKey, [u8; 32]), StealthError> {
        // Decapsulate shared secret
        let ciphertext = self.ciphertext()?;
        let shared_secret = view_key.decapsulate(&ciphertext)?;

        // Decrypt randomness
        let encryption_key = blake3::derive_key("phantom_randomness_encryption", &shared_secret);
        let randomness: Vec<u8> = self.encrypted_randomness.iter()
            .zip(encryption_key.iter())
            .map(|(e, k)| e ^ k)
            .collect();

        let mut randomness_arr = [0u8; 32];
        if randomness.len() >= 32 {
            randomness_arr.copy_from_slice(&randomness[..32]);
        }

        // Derive one-time spending key
        let spending_key = SpendingKey::derive(spend_key, &shared_secret)?;

        Ok((spending_key, randomness_arr))
    }
}

/// One-time spending key (derived for spending a specific output)
#[derive(Clone)]
pub struct SpendingKey {
    /// Derived private key material
    key_material: [u8; 32],
    /// Original spend key reference (for signing)
    spend_key_public: Vec<u8>,
}

impl fmt::Debug for SpendingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpendingKey")
            .field("key_material", &"[REDACTED]")
            .field("spend_key_public_len", &self.spend_key_public.len())
            .finish()
    }
}

impl SpendingKey {
    /// Derive a spending key from the base spend key and shared secret
    fn derive(spend_key: &SpendKey, shared_secret: &[u8; 32]) -> Result<Self, StealthError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"phantom_spending_key");
        hasher.update(shared_secret);
        hasher.update(spend_key.private_bytes());
        let key_material = *hasher.finalize().as_bytes();

        Ok(Self {
            key_material,
            spend_key_public: spend_key.public_bytes().to_vec(),
        })
    }

    /// Sign a transaction hash
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, StealthError> {
        // Create signature using derived key material
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"phantom_signature");
        hasher.update(&self.key_material);
        hasher.update(message);
        let signature_base = hasher.finalize();

        // In a full implementation, this would use proper Dilithium signing
        // with the derived key. For now, create a deterministic signature.
        let mut signature = vec![0u8; 64];
        signature[..32].copy_from_slice(signature_base.as_bytes());

        // Add public key reference for verification
        let mut hasher = blake3::Hasher::new();
        hasher.update(signature_base.as_bytes());
        hasher.update(&self.spend_key_public);
        signature[32..].copy_from_slice(hasher.finalize().as_bytes());

        Ok(signature)
    }

    /// Get the key material hash (for nullifier derivation)
    pub fn nullifier_key(&self) -> [u8; 32] {
        blake3::derive_key("phantom_nullifier_key", &self.key_material)
    }
}

/// Payment code (like BIP47 but post-quantum)
/// Allows reusable addresses without linkability
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentCode {
    /// Version byte
    pub version: u8,
    /// View chain code (for HD derivation)
    pub view_chain_code: [u8; 32],
    /// Spend chain code
    pub spend_chain_code: [u8; 32],
    /// Base view public key bytes
    pub view_public_key: Vec<u8>,
    /// Base spend public key bytes
    pub spend_public_key: Vec<u8>,
}

impl PaymentCode {
    /// Create a new payment code from master keys
    pub fn new(
        view_key: &ViewKey,
        spend_key: &SpendKey,
        view_chain_code: [u8; 32],
        spend_chain_code: [u8; 32],
    ) -> Self {
        Self {
            version: 1,
            view_chain_code,
            spend_chain_code,
            view_public_key: view_key.public_bytes().to_vec(),
            spend_public_key: spend_key.public_bytes().to_vec(),
        }
    }

    /// Derive stealth address at index
    pub fn derive_stealth_address(&self, index: u32) -> StealthAddress {
        // Derive view public key for this index
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"phantom_payment_code_view");
        hasher.update(&self.view_chain_code);
        hasher.update(&index.to_le_bytes());
        hasher.update(&self.view_public_key);
        let view_tweak = *hasher.finalize().as_bytes();

        // Derive spend public key for this index
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"phantom_payment_code_spend");
        hasher.update(&self.spend_chain_code);
        hasher.update(&index.to_le_bytes());
        hasher.update(&self.spend_public_key);
        let spend_tweak = *hasher.finalize().as_bytes();

        // Create tweaked keys (in real impl, would do EC/lattice point addition)
        let mut view_key = self.view_public_key.clone();
        for (i, byte) in view_tweak.iter().enumerate() {
            if i < view_key.len() {
                view_key[i] ^= byte;
            }
        }

        let mut spend_key = self.spend_public_key.clone();
        for (i, byte) in spend_tweak.iter().enumerate() {
            if i < spend_key.len() {
                spend_key[i] ^= byte;
            }
        }

        StealthAddress {
            view_public_key: view_key,
            spend_public_key: spend_key,
        }
    }

    /// Encode as bech32m string
    pub fn encode(&self) -> String {
        let mut data = vec![self.version];
        data.extend_from_slice(&self.view_chain_code);
        data.extend_from_slice(&self.spend_chain_code);
        data.extend_from_slice(&(self.view_public_key.len() as u16).to_le_bytes());
        data.extend_from_slice(&self.view_public_key);
        data.extend_from_slice(&(self.spend_public_key.len() as u16).to_le_bytes());
        data.extend_from_slice(&self.spend_public_key);

        // Simple base58 encoding (in production would use bech32m)
        bs58::encode(&data).into_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_view_key_generation() {
        let view_key = ViewKey::generate().unwrap();
        assert!(!view_key.public_bytes().is_empty());
    }

    #[test]
    fn test_spend_key_generation() {
        let spend_key = SpendKey::generate().unwrap();
        assert!(!spend_key.public_bytes().is_empty());
    }

    #[test]
    fn test_stealth_address_creation() {
        let view_key = ViewKey::generate().unwrap();
        let spend_key = SpendKey::generate().unwrap();
        let stealth_addr = StealthAddress::new(&view_key, &spend_key);

        assert!(!stealth_addr.view_public_key.is_empty());
        assert!(!stealth_addr.spend_public_key.is_empty());
    }

    #[test]
    fn test_stealth_address_serialization() {
        let view_key = ViewKey::generate().unwrap();
        let spend_key = SpendKey::generate().unwrap();
        let stealth_addr = StealthAddress::new(&view_key, &spend_key);

        let bytes = stealth_addr.to_bytes();
        let decoded = StealthAddress::from_bytes(&bytes).unwrap();

        assert_eq!(stealth_addr.hash(), decoded.hash());
    }

    #[test]
    fn test_one_time_address_derivation() {
        let view_key = ViewKey::generate().unwrap();
        let spend_key = SpendKey::generate().unwrap();
        let stealth_addr = StealthAddress::new(&view_key, &spend_key);

        let (ota, randomness) = OneTimeAddress::derive_for_recipient(&stealth_addr).unwrap();

        assert!(!ota.encapsulated_secret.is_empty());
        assert!(randomness != [0u8; 32]);
    }

    #[test]
    fn test_one_time_address_scanning() {
        let view_key = ViewKey::generate().unwrap();
        let spend_key = SpendKey::generate().unwrap();
        let stealth_addr = StealthAddress::new(&view_key, &spend_key);

        let (ota, _) = OneTimeAddress::derive_for_recipient(&stealth_addr).unwrap();

        // Should scan successfully with correct keys
        assert!(ota.scan(&view_key, &spend_key).unwrap());
    }

    #[test]
    fn test_one_time_address_recovery() {
        let view_key = ViewKey::generate().unwrap();
        let spend_key = SpendKey::generate().unwrap();
        let stealth_addr = StealthAddress::new(&view_key, &spend_key);

        let (ota, original_randomness) = OneTimeAddress::derive_for_recipient(&stealth_addr).unwrap();
        let (spending_key, recovered_randomness) = ota.recover(&view_key, &spend_key).unwrap();

        assert_eq!(original_randomness, recovered_randomness);

        // Can sign with spending key
        let signature = spending_key.sign(b"test message").unwrap();
        assert!(!signature.is_empty());
    }

    #[test]
    fn test_payment_code() {
        let view_key = ViewKey::generate().unwrap();
        let spend_key = SpendKey::generate().unwrap();

        let mut view_chain = [0u8; 32];
        let mut spend_chain = [0u8; 32];
        getrandom::getrandom(&mut view_chain).unwrap();
        getrandom::getrandom(&mut spend_chain).unwrap();

        let payment_code = PaymentCode::new(&view_key, &spend_key, view_chain, spend_chain);

        // Derive addresses at different indices
        let addr1 = payment_code.derive_stealth_address(0);
        let addr2 = payment_code.derive_stealth_address(1);

        // Should be different
        assert_ne!(addr1.hash(), addr2.hash());
    }

    #[test]
    fn test_spending_key_nullifier() {
        let view_key = ViewKey::generate().unwrap();
        let spend_key = SpendKey::generate().unwrap();
        let stealth_addr = StealthAddress::new(&view_key, &spend_key);

        let (ota, _) = OneTimeAddress::derive_for_recipient(&stealth_addr).unwrap();
        let (spending_key, _) = ota.recover(&view_key, &spend_key).unwrap();

        let nullifier_key = spending_key.nullifier_key();
        assert!(nullifier_key != [0u8; 32]);
    }
}
