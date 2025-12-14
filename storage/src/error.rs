//! Storage errors

use thiserror::Error;

/// Storage result type
pub type StorageResult<T> = Result<T, StorageError>;

/// Storage errors
#[derive(Error, Debug)]
pub enum StorageError {
    /// Database error
    #[error("Database error: {0}")]
    Database(#[from] redb::DatabaseError),

    /// Transaction error
    #[error("Transaction error: {0}")]
    Transaction(#[from] redb::TransactionError),

    /// Table error
    #[error("Table error: {0}")]
    Table(#[from] redb::TableError),

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(#[from] redb::StorageError),

    /// Commit error
    #[error("Commit error: {0}")]
    Commit(#[from] redb::CommitError),

    /// Compaction error
    #[error("Compaction error: {0}")]
    Compaction(#[from] redb::CompactionError),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Block not found
    #[error("Block not found: height={0}")]
    BlockNotFound(u64),

    /// Transaction not found
    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),

    /// State not found
    #[error("State not found at epoch {0}")]
    StateNotFound(u64),

    /// Invalid data
    #[error("Invalid data: {0}")]
    InvalidData(String),

    /// Corruption detected
    #[error("Data corruption detected: {0}")]
    Corruption(String),
}

impl From<bincode::Error> for StorageError {
    fn from(e: bincode::Error) -> Self {
        StorageError::Serialization(e.to_string())
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(e: serde_json::Error) -> Self {
        StorageError::Serialization(e.to_string())
    }
}
