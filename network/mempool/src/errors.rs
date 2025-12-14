//! Encrypted mempool error types

use thiserror::Error;

/// Errors that can occur in the encrypted mempool
#[derive(Debug, Error)]
pub enum MempoolError {
    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),

    #[error("Invalid encrypted transaction: {0}")]
    InvalidEncryptedTransaction(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Threshold not met: {0}")]
    ThresholdNotMet(String),

    #[error("Invalid decryption share: {0}")]
    InvalidDecryptionShare(String),

    #[error("Mempool full: capacity {capacity}, current {current}")]
    MempoolFull { capacity: usize, current: usize },

    #[error("Transaction expired: age {age_ms}ms, max {max_ms}ms")]
    TransactionExpired { age_ms: u64, max_ms: u64 },

    #[error("Duplicate transaction: {0}")]
    DuplicateTransaction(String),

    #[error("Invalid validator: {0}")]
    InvalidValidator(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for mempool operations
pub type MempoolResult<T> = Result<T, MempoolError>;
