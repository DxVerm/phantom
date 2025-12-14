//! FHE Error types

use thiserror::Error;

/// Errors that can occur during FHE operations
#[derive(Error, Debug)]
pub enum FHEError {
    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Invalid ciphertext
    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(String),

    /// Homomorphic operation failed
    #[error("Homomorphic operation failed: {0}")]
    OperationFailed(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Invalid key
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Overflow during computation
    #[error("Overflow during computation")]
    Overflow,

    /// Underflow during computation
    #[error("Underflow during computation")]
    Underflow,

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),
}
