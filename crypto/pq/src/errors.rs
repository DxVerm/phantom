//! Error types for post-quantum cryptographic operations

use thiserror::Error;
use crate::SecurityLevel;

/// Errors that can occur during post-quantum cryptographic operations
#[derive(Error, Debug)]
pub enum PQError {
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("Encapsulation failed: {0}")]
    EncapsulationFailed(String),

    #[error("Decapsulation failed: {0}")]
    DecapsulationFailed(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Invalid signature format: {0}")]
    InvalidSignatureFormat(String),

    #[error("Invalid ciphertext format: {0}")]
    InvalidCiphertextFormat(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Random number generation error: {0}")]
    RngError(String),

    #[error("Unsupported security level: {0}")]
    UnsupportedSecurityLevel(String),

    // New error types for real crypto implementations
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },

    #[error("Invalid ciphertext size: expected {expected}, got {actual}")]
    InvalidCiphertextSize { expected: usize, actual: usize },

    #[error("Invalid signature size: expected {expected}, got {actual}")]
    InvalidSignatureSize { expected: usize, actual: usize },

    #[error("Invalid shared secret size: expected {expected}, got {actual}")]
    InvalidSharedSecretSize { expected: usize, actual: usize },

    #[error("Security level mismatch: expected {expected:?}, got {actual:?}")]
    SecurityLevelMismatch { expected: SecurityLevel, actual: SecurityLevel },

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid secret key")]
    InvalidSecretKey,

    #[error("Invalid ciphertext")]
    InvalidCiphertext,

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Message too long: max {max} bytes, got {actual}")]
    MessageTooLong { max: usize, actual: usize },
}
