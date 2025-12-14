//! PHANTOM Storage Layer
//!
//! Provides persistent storage for blockchain state, transactions, and blocks.
//!
//! # Architecture
//!
//! The storage layer uses redb (an embedded database) for:
//! - Block storage (headers + bodies)
//! - Transaction storage with indices
//! - State snapshots at epoch boundaries
//! - Validator set history
//! - Mempool persistence (optional)

pub mod block;
pub mod state;
pub mod tx;
pub mod chain;
mod error;

pub use error::{StorageError, StorageResult};
pub use block::{
    BlockStore, StoredBlock, StoredBlockHeader, StoredBlockBody,
    StoredTransaction, TransactionType,
};
pub use state::{StateStore, StateSnapshot};
pub use tx::{TransactionStore, TransactionLog, TransactionReceipt, TransactionLocation};
pub use chain::{ChainStore, ChainMeta};

use std::path::Path;
use std::sync::Arc;
use redb::Database;

/// Storage configuration
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Database path
    pub path: std::path::PathBuf,
    /// Maximum database size (bytes)
    pub max_size: u64,
    /// Enable transaction caching
    pub enable_tx_cache: bool,
    /// Transaction cache size
    pub tx_cache_size: usize,
    /// Enable state snapshots
    pub enable_snapshots: bool,
    /// Snapshot interval (epochs)
    pub snapshot_interval: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: std::path::PathBuf::from("./phantom_data"),
            max_size: 10 * 1024 * 1024 * 1024, // 10 GB
            enable_tx_cache: true,
            tx_cache_size: 10_000,
            enable_snapshots: true,
            snapshot_interval: 100,
        }
    }
}

/// Main storage interface
pub struct Storage {
    db: Arc<Database>,
    config: StorageConfig,
    pub blocks: BlockStore,
    pub state: StateStore,
    pub transactions: TransactionStore,
    pub chain: ChainStore,
}

impl Storage {
    /// Open or create storage at the given path
    pub fn open<P: AsRef<Path>>(path: P) -> StorageResult<Self> {
        let config = StorageConfig {
            path: path.as_ref().to_path_buf(),
            ..Default::default()
        };
        Self::with_config(config)
    }

    /// Open storage with custom configuration
    pub fn with_config(config: StorageConfig) -> StorageResult<Self> {
        // Ensure directory exists
        if let Some(parent) = config.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let db = Database::create(&config.path)?;
        let db = Arc::new(db);

        // Initialize stores
        let blocks = BlockStore::new(db.clone())?;
        let state = StateStore::new(db.clone())?;
        let transactions = TransactionStore::new(db.clone())?;
        let chain = ChainStore::new(db.clone())?;

        Ok(Self {
            db,
            config,
            blocks,
            state,
            transactions,
            chain,
        })
    }

    /// Get storage configuration
    pub fn config(&self) -> &StorageConfig {
        &self.config
    }

    /// Get database statistics
    pub fn stats(&self) -> StorageStats {
        StorageStats {
            path: self.config.path.clone(),
            block_count: self.blocks.count().unwrap_or(0),
            tx_count: self.transactions.count().unwrap_or(0),
            state_snapshots: self.state.snapshot_count().unwrap_or(0),
        }
    }
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub path: std::path::PathBuf,
    pub block_count: u64,
    pub tx_count: u64,
    pub state_snapshots: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_storage_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");

        let storage = Storage::open(&path).unwrap();
        let stats = storage.stats();

        assert_eq!(stats.block_count, 0);
        assert_eq!(stats.tx_count, 0);
    }

    #[test]
    fn test_storage_config() {
        let config = StorageConfig::default();
        assert_eq!(config.max_size, 10 * 1024 * 1024 * 1024);
        assert!(config.enable_tx_cache);
    }
}
