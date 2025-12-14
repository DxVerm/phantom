//! FHE Key Management with Real TFHE-rs
//!
//! Provides key generation and management for FHE operations.
//! - ClientKey: For encryption and decryption (held by wallet owner)
//! - ServerKey: For homomorphic operations (shared with validators)
//! - PublicKey: For encryption only (can be published)

use crate::{FHEConfig, FHEError, FHEResult};
use tfhe::{ConfigBuilder, generate_keys, CompactPublicKey};
use tfhe::{ClientKey as TfheClientKey, ServerKey as TfheServerKey};
use std::sync::Arc;
use parking_lot::RwLock;
use once_cell::sync::OnceCell;

/// Global server key storage for homomorphic operations
/// TFHE-rs requires setting server key globally before operations
static GLOBAL_SERVER_KEY: OnceCell<Arc<RwLock<Option<TfheServerKey>>>> = OnceCell::new();

fn get_global_server_key() -> &'static Arc<RwLock<Option<TfheServerKey>>> {
    GLOBAL_SERVER_KEY.get_or_init(|| Arc::new(RwLock::new(None)))
}

/// Set the server key for homomorphic operations
pub fn set_server_key(key: &ServerKey) {
    let global = get_global_server_key();
    let mut guard = global.write();
    *guard = Some(key.inner.clone());

    // Also set in TFHE-rs global context
    tfhe::set_server_key(key.inner.clone());
}

/// Clear the global server key
pub fn clear_server_key() {
    let global = get_global_server_key();
    let mut guard = global.write();
    *guard = None;
}

/// Client key for encryption and decryption
/// This key must be kept secret by the balance owner
#[derive(Clone)]
pub struct ClientKey {
    /// Inner TFHE-rs client key
    pub(crate) inner: TfheClientKey,
    /// Configuration hash for versioning
    config_hash: [u8; 32],
}

impl ClientKey {
    /// Generate a new client key
    pub fn generate(config: &FHEConfig) -> FHEResult<Self> {
        // Build TFHE configuration based on security level
        let tfhe_config = if config.security_bits >= 128 {
            ConfigBuilder::default().build()
        } else {
            // Lower security for testing
            ConfigBuilder::default_with_small_encryption().build()
        };

        // Generate keys
        let (client_key, _server_key) = generate_keys(tfhe_config);

        // Hash the config for versioning
        let mut hasher = blake3::Hasher::new();
        hasher.update(&config.security_bits.to_le_bytes());
        hasher.update(&[config.multi_threaded as u8]);
        let config_hash = *hasher.finalize().as_bytes();

        Ok(Self {
            inner: client_key,
            config_hash,
        })
    }

    /// Create from existing TFHE client key
    pub fn from_tfhe_key(key: TfheClientKey, config: &FHEConfig) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&config.security_bits.to_le_bytes());
        hasher.update(&[config.multi_threaded as u8]);
        let config_hash = *hasher.finalize().as_bytes();

        Self {
            inner: key,
            config_hash,
        }
    }

    /// Derive server key from client key
    pub fn derive_server_key(&self) -> FHEResult<ServerKey> {
        let server_key = TfheServerKey::new(&self.inner);

        Ok(ServerKey {
            inner: server_key,
            config_hash: self.config_hash,
        })
    }

    /// Derive public key from client key
    pub fn derive_public_key(&self) -> FHEResult<PublicKey> {
        let public_key = CompactPublicKey::new(&self.inner);

        Ok(PublicKey {
            inner: public_key,
            config_hash: self.config_hash,
        })
    }

    /// Get reference to inner TFHE key
    pub fn inner(&self) -> &TfheClientKey {
        &self.inner
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> FHEResult<Vec<u8>> {
        bincode::serialize(&self.inner)
            .map_err(|e| FHEError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8], config: &FHEConfig) -> FHEResult<Self> {
        let inner: TfheClientKey = bincode::deserialize(bytes)
            .map_err(|e| FHEError::SerializationError(e.to_string()))?;

        Ok(Self::from_tfhe_key(inner, config))
    }
}

impl std::fmt::Debug for ClientKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientKey")
            .field("config_hash", &hex::encode(&self.config_hash[..8]))
            .finish()
    }
}

/// Server key for homomorphic operations
/// Can be shared with validators to enable computation on encrypted data
#[derive(Clone)]
pub struct ServerKey {
    /// Inner TFHE-rs server key
    pub(crate) inner: TfheServerKey,
    /// Configuration hash
    config_hash: [u8; 32],
}

impl ServerKey {
    /// Verify this key matches the expected configuration
    pub fn verify_config(&self, config: &FHEConfig) -> bool {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&config.security_bits.to_le_bytes());
        hasher.update(&[config.multi_threaded as u8]);
        *hasher.finalize().as_bytes() == self.config_hash
    }

    /// Set this as the global server key for operations
    pub fn set_global(&self) {
        set_server_key(self);
    }

    /// Serialize to bytes (WARNING: ServerKey is large, ~50-100MB)
    pub fn to_bytes(&self) -> FHEResult<Vec<u8>> {
        bincode::serialize(&self.inner)
            .map_err(|e| FHEError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8], config: &FHEConfig) -> FHEResult<Self> {
        let inner: TfheServerKey = bincode::deserialize(bytes)
            .map_err(|e| FHEError::SerializationError(e.to_string()))?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(&config.security_bits.to_le_bytes());
        hasher.update(&[config.multi_threaded as u8]);
        let config_hash = *hasher.finalize().as_bytes();

        Ok(Self { inner, config_hash })
    }
}

impl std::fmt::Debug for ServerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerKey")
            .field("config_hash", &hex::encode(&self.config_hash[..8]))
            .finish()
    }
}

/// Public key for encryption only
/// Can be published for anyone to encrypt values for this owner
#[derive(Clone)]
pub struct PublicKey {
    /// Inner TFHE-rs compact public key
    inner: CompactPublicKey,
    /// Configuration hash
    config_hash: [u8; 32],
}

impl PublicKey {
    /// Get a compact identifier for this public key
    pub fn id(&self) -> [u8; 32] {
        // Serialize and hash to get ID
        let serialized = bincode::serialize(&self.inner).unwrap_or_default();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&serialized);
        *hasher.finalize().as_bytes()
    }

    /// Get reference to inner key
    pub fn inner(&self) -> &CompactPublicKey {
        &self.inner
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> FHEResult<Vec<u8>> {
        bincode::serialize(&self.inner)
            .map_err(|e| FHEError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8], config: &FHEConfig) -> FHEResult<Self> {
        let inner: CompactPublicKey = bincode::deserialize(bytes)
            .map_err(|e| FHEError::SerializationError(e.to_string()))?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(&config.security_bits.to_le_bytes());
        hasher.update(&[config.multi_threaded as u8]);
        let config_hash = *hasher.finalize().as_bytes();

        Ok(Self { inner, config_hash })
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKey")
            .field("id", &hex::encode(&self.id()[..8]))
            .finish()
    }
}

/// Complete key pair for FHE operations
#[derive(Clone)]
pub struct KeyPair {
    /// Client key (secret)
    pub client: ClientKey,
    /// Server key (can be shared)
    pub server: ServerKey,
    /// Public key (can be published)
    pub public: PublicKey,
}

impl KeyPair {
    /// Generate a new key pair
    ///
    /// WARNING: Key generation is slow (~10-30 seconds)
    pub fn generate(config: &FHEConfig) -> FHEResult<Self> {
        // Build TFHE configuration
        let tfhe_config = if config.security_bits >= 128 {
            ConfigBuilder::default().build()
        } else {
            ConfigBuilder::default_with_small_encryption().build()
        };

        // Generate all keys at once
        let (client_key, server_key) = generate_keys(tfhe_config);
        let public_key = CompactPublicKey::new(&client_key);

        let mut hasher = blake3::Hasher::new();
        hasher.update(&config.security_bits.to_le_bytes());
        hasher.update(&[config.multi_threaded as u8]);
        let config_hash = *hasher.finalize().as_bytes();

        Ok(Self {
            client: ClientKey {
                inner: client_key,
                config_hash,
            },
            server: ServerKey {
                inner: server_key,
                config_hash,
            },
            public: PublicKey {
                inner: public_key,
                config_hash,
            },
        })
    }

    /// Set the server key globally for operations
    pub fn set_server_key(&self) {
        self.server.set_global();
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_id", &hex::encode(&self.public.id()[..8]))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let config = FHEConfig::default();
        let keypair = KeyPair::generate(&config).unwrap();

        assert!(keypair.server.verify_config(&config));
    }

    #[test]
    fn test_server_key_derivation() {
        let config = FHEConfig::default();
        let client = ClientKey::generate(&config).unwrap();
        let server1 = client.derive_server_key().unwrap();

        assert!(server1.verify_config(&config));
    }
}
