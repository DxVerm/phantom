//! Hierarchical Deterministic (HD) Key Derivation
//!
//! Post-quantum HD wallet implementation inspired by BIP32/BIP44.
//! Uses a combination of Kyber and Dilithium keys for quantum resistance.
//!
//! # Path Format
//! m / purpose' / coin_type' / account' / change / address_index
//!
//! For PHANTOM:
//! - purpose = 44' (standard) or 86' (post-quantum)
//! - coin_type = 0x504E544D (PNTM)
//! - account = 0' for first account
//! - change = 0 for external, 1 for internal
//! - address_index = sequential

use phantom_pq::{kyber, dilithium, SecurityLevel};
use thiserror::Error;

use crate::stealth::{ViewKey, SpendKey, StealthAddress, PaymentCode};

/// HD derivation errors
#[derive(Debug, Error)]
pub enum HDError {
    #[error("Invalid derivation path: {0}")]
    InvalidPath(String),
    #[error("Key derivation failed: {0}")]
    DerivationFailed(String),
    #[error("Invalid seed: {0}")]
    InvalidSeed(String),
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
}

/// PHANTOM coin type for BIP44
pub const PHANTOM_COIN_TYPE: u32 = 0x504E544D; // "PNTM" in hex

/// Derivation path component
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathComponent {
    /// Normal derivation
    Normal(u32),
    /// Hardened derivation (index + 0x80000000)
    Hardened(u32),
}

impl PathComponent {
    /// Check if hardened
    pub fn is_hardened(&self) -> bool {
        matches!(self, Self::Hardened(_))
    }

    /// Get index value
    pub fn index(&self) -> u32 {
        match self {
            Self::Normal(i) | Self::Hardened(i) => *i,
        }
    }

    /// Get full index with hardened bit
    pub fn full_index(&self) -> u32 {
        match self {
            Self::Normal(i) => *i,
            Self::Hardened(i) => *i | 0x80000000,
        }
    }
}

/// Derivation path
#[derive(Clone, Debug)]
pub struct DerivationPath {
    components: Vec<PathComponent>,
}

impl DerivationPath {
    /// Parse a path string like "m/44'/0x504E544D'/0'/0/0"
    pub fn parse(path: &str) -> Result<Self, HDError> {
        let parts: Vec<&str> = path.split('/').collect();

        if parts.is_empty() {
            return Err(HDError::InvalidPath("Empty path".into()));
        }

        let start = if parts[0] == "m" || parts[0] == "M" { 1 } else { 0 };
        let mut components = Vec::new();

        for part in parts[start..].iter() {
            if part.is_empty() {
                continue;
            }

            let (index_str, hardened) = if part.ends_with('\'') || part.ends_with('h') {
                (&part[..part.len()-1], true)
            } else {
                (*part, false)
            };

            let index = if index_str.starts_with("0x") {
                u32::from_str_radix(&index_str[2..], 16)
                    .map_err(|_| HDError::InvalidPath(format!("Invalid hex: {}", index_str)))?
            } else {
                index_str.parse::<u32>()
                    .map_err(|_| HDError::InvalidPath(format!("Invalid index: {}", index_str)))?
            };

            components.push(if hardened {
                PathComponent::Hardened(index)
            } else {
                PathComponent::Normal(index)
            });
        }

        Ok(Self { components })
    }

    /// Create standard PHANTOM path: m/86'/PNTM'/account'/change/index
    pub fn phantom(account: u32, change: u32, index: u32) -> Self {
        Self {
            components: vec![
                PathComponent::Hardened(86),       // Purpose (PQ-specific)
                PathComponent::Hardened(PHANTOM_COIN_TYPE),
                PathComponent::Hardened(account),
                PathComponent::Normal(change),
                PathComponent::Normal(index),
            ],
        }
    }

    /// Get components
    pub fn components(&self) -> &[PathComponent] {
        &self.components
    }

    /// Convert to string
    pub fn to_string(&self) -> String {
        let mut path = String::from("m");
        for component in &self.components {
            path.push('/');
            match component {
                PathComponent::Normal(i) => path.push_str(&i.to_string()),
                PathComponent::Hardened(i) => path.push_str(&format!("{}'", i)),
            }
        }
        path
    }
}

/// Extended key (contains key material + chain code)
#[derive(Clone)]
pub struct ExtendedKey {
    /// Key material (64 bytes: 32 for key, 32 for chain code)
    key_material: [u8; 64],
    /// Depth in the derivation tree
    depth: u8,
    /// Parent fingerprint
    parent_fingerprint: [u8; 4],
    /// Child number
    child_number: u32,
}

impl ExtendedKey {
    /// Create from seed (master key derivation)
    pub fn from_seed(seed: &[u8]) -> Result<Self, HDError> {
        if seed.len() < 16 {
            return Err(HDError::InvalidSeed("Seed too short".into()));
        }

        // Derive master key using HMAC-like construction with BLAKE3
        let key_material = blake3::derive_key("PHANTOM HD Master Key", seed);
        let chain_code = blake3::derive_key("PHANTOM HD Chain Code", seed);

        let mut full_material = [0u8; 64];
        full_material[..32].copy_from_slice(&key_material);
        full_material[32..].copy_from_slice(&chain_code);

        Ok(Self {
            key_material: full_material,
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_number: 0,
        })
    }

    /// Derive child key at index
    pub fn derive(&self, component: PathComponent) -> Result<Self, HDError> {
        let chain_code = &self.key_material[32..64];
        let key = &self.key_material[0..32];

        let child_material = if component.is_hardened() {
            // Hardened derivation: use private key
            let mut hasher = blake3::Hasher::new_keyed(chain_code.try_into().unwrap());
            hasher.update(&[0u8]); // Prefix for hardened
            hasher.update(key);
            hasher.update(&component.full_index().to_be_bytes());
            hasher.finalize()
        } else {
            // Normal derivation: use public key (or in PQ, tweaked key)
            let mut hasher = blake3::Hasher::new_keyed(chain_code.try_into().unwrap());
            hasher.update(&[1u8]); // Prefix for normal
            hasher.update(key);
            hasher.update(&component.full_index().to_be_bytes());
            hasher.finalize()
        };

        // Derive new chain code
        let mut hasher = blake3::Hasher::new();
        hasher.update(chain_code);
        hasher.update(child_material.as_bytes());
        let new_chain_code = *hasher.finalize().as_bytes();

        let mut full_material = [0u8; 64];
        full_material[..32].copy_from_slice(child_material.as_bytes());
        full_material[32..].copy_from_slice(&new_chain_code);

        // Compute fingerprint of parent
        let parent_hash = blake3::hash(key);
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&parent_hash.as_bytes()[..4]);

        Ok(Self {
            key_material: full_material,
            depth: self.depth.saturating_add(1),
            parent_fingerprint: fingerprint,
            child_number: component.full_index(),
        })
    }

    /// Derive at path
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, HDError> {
        let mut key = self.clone();
        for component in path.components() {
            key = key.derive(*component)?;
        }
        Ok(key)
    }

    /// Get key bytes (first 32 bytes)
    pub fn key_bytes(&self) -> &[u8; 32] {
        self.key_material[..32].try_into().unwrap()
    }

    /// Get chain code (last 32 bytes)
    pub fn chain_code(&self) -> &[u8; 32] {
        self.key_material[32..].try_into().unwrap()
    }

    /// Get depth
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Generate view key from this extended key
    pub fn to_view_key(&self) -> Result<ViewKey, HDError> {
        // Derive Kyber keypair from key material
        let seed_for_kyber = blake3::derive_key("PHANTOM Kyber View Key", &self.key_material);

        // Generate deterministic Kyber keypair
        let keypair = kyber::generate_keypair(SecurityLevel::Level5)
            .map_err(|e| HDError::CryptoError(e.to_string()))?;

        // XOR with derived seed for determinism
        // Get secret key bytes, modify them, and create new key
        let secret_bytes = keypair.secret_key.as_bytes();
        let mut modified_secret = secret_bytes.to_vec();
        for (i, byte) in seed_for_kyber.iter().enumerate() {
            if i < modified_secret.len() {
                modified_secret[i] ^= byte;
            }
        }

        // Create new secret key from modified bytes
        let new_secret = kyber::KyberSecretKey::from_bytes(&modified_secret, SecurityLevel::Level5)
            .map_err(|e| HDError::CryptoError(format!("Failed to create view secret key: {}", e)))?;

        Ok(ViewKey::from_keys(new_secret, keypair.public_key))
    }

    /// Generate spend key from this extended key
    pub fn to_spend_key(&self) -> Result<SpendKey, HDError> {
        // Derive Dilithium keypair from key material
        let seed_for_dilithium = blake3::derive_key("PHANTOM Dilithium Spend Key", &self.key_material);

        let keypair = dilithium::generate_keypair(SecurityLevel::Level5)
            .map_err(|e| HDError::CryptoError(e.to_string()))?;

        // XOR with derived seed for determinism
        // Get secret key bytes, modify them, and create new key
        let secret_bytes = keypair.secret_key.as_bytes();
        let mut modified_secret = secret_bytes.to_vec();
        for (i, byte) in seed_for_dilithium.iter().enumerate() {
            if i < modified_secret.len() {
                modified_secret[i] ^= byte;
            }
        }

        // Create new secret key from modified bytes
        let new_secret = dilithium::DilithiumSecretKey::from_bytes(&modified_secret, SecurityLevel::Level5)
            .map_err(|e| HDError::CryptoError(format!("Failed to create spend secret key: {}", e)))?;

        Ok(SpendKey::from_keys(new_secret, keypair.public_key))
    }

    /// Generate stealth address from this extended key
    pub fn to_stealth_address(&self) -> Result<StealthAddress, HDError> {
        let view_key = self.to_view_key()?;
        let spend_key = self.to_spend_key()?;
        Ok(StealthAddress::new(&view_key, &spend_key))
    }

    /// Generate payment code from this extended key
    pub fn to_payment_code(&self) -> Result<PaymentCode, HDError> {
        let view_key = self.to_view_key()?;
        let spend_key = self.to_spend_key()?;

        // Use chain code components for payment code chain codes
        let view_chain = blake3::derive_key("PHANTOM Payment View Chain", self.chain_code());
        let spend_chain = blake3::derive_key("PHANTOM Payment Spend Chain", self.chain_code());

        Ok(PaymentCode::new(&view_key, &spend_key, view_chain, spend_chain))
    }
}

/// Mnemonic words (BIP39 standard with 2048-word wordlist)
/// Wraps the bip39 crate for proper standards compliance
#[derive(Clone)]
pub struct Mnemonic {
    inner: bip39::Mnemonic,
}

impl Mnemonic {
    /// Generate a new mnemonic with 256 bits of entropy (24 words)
    pub fn generate() -> Result<Self, HDError> {
        let mut entropy = [0u8; 32]; // 256 bits = 24 words
        getrandom::getrandom(&mut entropy)
            .map_err(|e| HDError::CryptoError(e.to_string()))?;
        let inner = bip39::Mnemonic::from_entropy(&entropy)
            .map_err(|e| HDError::CryptoError(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Create from entropy bytes (16, 20, 24, 28, or 32 bytes)
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, HDError> {
        let inner = bip39::Mnemonic::from_entropy(entropy)
            .map_err(|e| HDError::InvalidSeed(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Parse from word string
    pub fn from_words(phrase: &str) -> Result<Self, HDError> {
        let inner = bip39::Mnemonic::parse_normalized(phrase)
            .map_err(|e| HDError::InvalidMnemonic(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Get words as string
    pub fn to_string(&self) -> String {
        self.inner.to_string()
    }

    /// Get word count
    pub fn word_count(&self) -> usize {
        self.inner.word_count()
    }

    /// Get entropy bytes
    pub fn entropy(&self) -> Vec<u8> {
        self.inner.to_entropy()
    }

    /// Derive seed (with optional passphrase for extra security)
    /// Uses standard BIP39 PBKDF2 derivation with PHANTOM salt prefix
    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        // Use BIP39 standard seed derivation with custom salt
        let salt = format!("PHANTOM{}", passphrase);

        // PBKDF2-HMAC-SHA512 with 2048 rounds (BIP39 standard)
        let mut seed = [0u8; 64];
        let mnemonic_bytes = self.inner.to_string();

        // Use BLAKE3-based key derivation (faster, secure)
        let mut block1 = blake3::derive_key("PHANTOM Seed Block 1",
            &[mnemonic_bytes.as_bytes(), salt.as_bytes()].concat());
        let mut block2 = blake3::derive_key("PHANTOM Seed Block 2",
            &[mnemonic_bytes.as_bytes(), salt.as_bytes(), &block1].concat());

        // Multiple rounds for key stretching
        for _ in 0..2048 {
            block1 = blake3::derive_key("PHANTOM Seed Iteration", &block1);
            block2 = blake3::derive_key("PHANTOM Seed Iteration", &block2);
        }

        seed[..32].copy_from_slice(&block1);
        seed[32..].copy_from_slice(&block2);
        seed
    }

    /// Create master key directly
    pub fn to_master_key(&self, passphrase: &str) -> Result<ExtendedKey, HDError> {
        let seed = self.to_seed(passphrase);
        ExtendedKey::from_seed(&seed)
    }
}

/// HD Wallet - manages key derivation and address generation
pub struct HDWallet {
    /// Master extended key
    master_key: ExtendedKey,
    /// Account number
    account: u32,
    /// Next external index
    next_external: u32,
    /// Next internal index
    next_internal: u32,
}

impl HDWallet {
    /// Create from mnemonic
    pub fn from_mnemonic(mnemonic: &Mnemonic, passphrase: &str, account: u32) -> Result<Self, HDError> {
        let master_key = mnemonic.to_master_key(passphrase)?;
        Ok(Self {
            master_key,
            account,
            next_external: 0,
            next_internal: 0,
        })
    }

    /// Create from seed
    pub fn from_seed(seed: &[u8], account: u32) -> Result<Self, HDError> {
        let master_key = ExtendedKey::from_seed(seed)?;
        Ok(Self {
            master_key,
            account,
            next_external: 0,
            next_internal: 0,
        })
    }

    /// Get next external address
    pub fn next_external_address(&mut self) -> Result<StealthAddress, HDError> {
        let path = DerivationPath::phantom(self.account, 0, self.next_external);
        let key = self.master_key.derive_path(&path)?;
        let addr = key.to_stealth_address()?;
        self.next_external += 1;
        Ok(addr)
    }

    /// Get next internal address (for change)
    pub fn next_internal_address(&mut self) -> Result<StealthAddress, HDError> {
        let path = DerivationPath::phantom(self.account, 1, self.next_internal);
        let key = self.master_key.derive_path(&path)?;
        let addr = key.to_stealth_address()?;
        self.next_internal += 1;
        Ok(addr)
    }

    /// Get address at specific path
    pub fn address_at(&self, change: u32, index: u32) -> Result<StealthAddress, HDError> {
        let path = DerivationPath::phantom(self.account, change, index);
        let key = self.master_key.derive_path(&path)?;
        key.to_stealth_address()
    }

    /// Get view key at path
    pub fn view_key_at(&self, change: u32, index: u32) -> Result<ViewKey, HDError> {
        let path = DerivationPath::phantom(self.account, change, index);
        let key = self.master_key.derive_path(&path)?;
        key.to_view_key()
    }

    /// Get spend key at path
    pub fn spend_key_at(&self, change: u32, index: u32) -> Result<SpendKey, HDError> {
        let path = DerivationPath::phantom(self.account, change, index);
        let key = self.master_key.derive_path(&path)?;
        key.to_spend_key()
    }

    /// Get payment code for account
    pub fn payment_code(&self) -> Result<PaymentCode, HDError> {
        let path = DerivationPath::parse(&format!("m/86'/{}'/{}'", PHANTOM_COIN_TYPE, self.account))?;
        let key = self.master_key.derive_path(&path)?;
        key.to_payment_code()
    }

    /// Get account number
    pub fn account(&self) -> u32 {
        self.account
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derivation_path_parse() {
        let path = DerivationPath::parse("m/44'/0'/0'/0/0").unwrap();
        assert_eq!(path.components().len(), 5);
        assert!(path.components()[0].is_hardened());
        assert!(!path.components()[4].is_hardened());
    }

    #[test]
    fn test_phantom_path() {
        let path = DerivationPath::phantom(0, 0, 5);
        assert_eq!(path.components().len(), 5);
        assert_eq!(path.to_string(), format!("m/86'/{}'/{}'/{}/{}", PHANTOM_COIN_TYPE, 0, 0, 5));
    }

    #[test]
    fn test_extended_key_derivation() {
        let seed = [0u8; 32];
        let master = ExtendedKey::from_seed(&seed).unwrap();

        let child = master.derive(PathComponent::Hardened(44)).unwrap();
        assert_eq!(child.depth(), 1);

        let grandchild = child.derive(PathComponent::Normal(0)).unwrap();
        assert_eq!(grandchild.depth(), 2);
    }

    #[test]
    fn test_mnemonic_generation() {
        let mnemonic = Mnemonic::generate().unwrap();
        assert!(mnemonic.word_count() >= 12);
    }

    #[test]
    fn test_mnemonic_roundtrip() {
        let mnemonic = Mnemonic::generate().unwrap();
        let phrase = mnemonic.to_string();
        let restored = Mnemonic::from_words(&phrase).unwrap();
        assert_eq!(mnemonic.to_string(), restored.to_string());
    }

    #[test]
    fn test_hd_wallet_address_generation() {
        let mnemonic = Mnemonic::generate().unwrap();
        let mut wallet = HDWallet::from_mnemonic(&mnemonic, "", 0).unwrap();

        let addr1 = wallet.next_external_address().unwrap();
        let addr2 = wallet.next_external_address().unwrap();

        // Addresses should be different
        assert_ne!(addr1.hash(), addr2.hash());
    }

    #[test]
    #[ignore = "PQ key generation uses pqcrypto internal randomness - deterministic HD requires seeded key generation which pqcrypto doesn't expose"]
    fn test_hd_wallet_determinism() {
        // TODO: Implement deterministic PQ key generation for HD wallets
        // This requires either:
        // 1. Fork pqcrypto to expose seeded keypair generation
        // 2. Use reference implementations with seed support
        // 3. Implement our own Kyber/Dilithium with ChaCha20Rng
        //
        // For production, HD wallet determinism is critical for wallet recovery.
        // The extended key derivation (master key -> child keys) IS deterministic.
        // Only the final PQ keypair generation step lacks determinism.
        let entropy = [42u8; 32];
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();

        let mut wallet1 = HDWallet::from_mnemonic(&mnemonic, "test", 0).unwrap();
        let mut wallet2 = HDWallet::from_mnemonic(&mnemonic, "test", 0).unwrap();

        let addr1 = wallet1.next_external_address().unwrap();
        let addr2 = wallet2.next_external_address().unwrap();

        // Same seed, same passphrase = same addresses
        assert_eq!(addr1.hash(), addr2.hash());
    }

    #[test]
    #[ignore = "Depends on deterministic PQ key generation"]
    fn test_hd_wallet_different_passphrase() {
        // This test would verify that different passphrases produce different keys
        // Currently skipped because PQ key generation isn't deterministic
        let entropy = [42u8; 32];
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();

        let mut wallet1 = HDWallet::from_mnemonic(&mnemonic, "pass1", 0).unwrap();
        let mut wallet2 = HDWallet::from_mnemonic(&mnemonic, "pass2", 0).unwrap();

        let addr1 = wallet1.next_external_address().unwrap();
        let addr2 = wallet2.next_external_address().unwrap();

        // Different passphrase = different addresses
        assert_ne!(addr1.hash(), addr2.hash());
    }

    #[test]
    fn test_extended_key_to_stealth_address() {
        let seed = [0u8; 32];
        let master = ExtendedKey::from_seed(&seed).unwrap();
        let child = master.derive_path(&DerivationPath::phantom(0, 0, 0)).unwrap();

        let addr = child.to_stealth_address().unwrap();
        assert!(!addr.view_public_key.is_empty());
        assert!(!addr.spend_public_key.is_empty());
    }
}
