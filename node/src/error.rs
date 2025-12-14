//! Node errors

use thiserror::Error;

/// Node result type
pub type NodeResult<T> = Result<T, NodeError>;

/// Node errors
#[derive(Error, Debug)]
pub enum NodeError {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(#[from] phantom_storage::StorageError),

    /// Genesis error
    #[error("Genesis error: {0}")]
    Genesis(#[from] phantom_genesis::GenesisError),

    /// RPC error
    #[error("RPC error: {0}")]
    Rpc(#[from] phantom_rpc::RpcError),

    /// P2P error
    #[error("P2P error: {0}")]
    P2p(#[from] phantom_p2p::P2PError),

    /// Mempool error
    #[error("Mempool error: {0}")]
    Mempool(#[from] phantom_mempool::MempoolError),

    /// Consensus error
    #[error("Consensus error: {0}")]
    Consensus(String),

    /// State error
    #[error("State error: {0}")]
    State(String),

    /// Block production error
    #[error("Block production error: {0}")]
    BlockProduction(String),

    /// Not a validator
    #[error("Node is not configured as validator")]
    NotValidator,

    /// Invalid block
    #[error("Invalid block: {0}")]
    InvalidBlock(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Node not running
    #[error("Node not running")]
    NotRunning,

    /// Block not found
    #[error("Block not found: {0}")]
    BlockNotFound(String),

    /// Verification error
    #[error("Verification error: {0}")]
    Verification(String),

    /// Invalid transaction
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    /// Sync error
    #[error("Sync error: {0}")]
    Sync(String),

    /// Validator error
    #[error("Validator error: {0}")]
    Validator(String),

    /// Channel error
    #[error("Channel error: {0}")]
    Channel(String),
}
