//! RPC Error Types

use jsonrpsee::types::ErrorObjectOwned;
use thiserror::Error;

/// RPC error codes following JSON-RPC 2.0 spec + custom PHANTOM codes
#[derive(Debug, Clone, Copy)]
pub enum RpcErrorCode {
    // Standard JSON-RPC errors
    ParseError = -32700,
    InvalidRequest = -32600,
    MethodNotFound = -32601,
    InvalidParams = -32602,
    InternalError = -32603,

    // PHANTOM custom errors (-32000 to -32099)
    NodeNotRunning = -32000,
    WalletNotAttached = -32001,
    TransactionFailed = -32002,
    InsufficientBalance = -32003,
    InvalidAddress = -32004,
    ConsensusFailed = -32005,
    StateSyncRequired = -32006,
    MempoolFull = -32007,
    RateLimited = -32008,
    Unauthorized = -32009,
}

impl RpcErrorCode {
    pub fn code(self) -> i32 {
        self as i32
    }
}

/// RPC errors
#[derive(Debug, Error)]
pub enum RpcError {
    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Method not found: {0}")]
    MethodNotFound(String),

    #[error("Invalid params: {0}")]
    InvalidParams(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Node not running")]
    NodeNotRunning,

    #[error("Wallet not attached")]
    WalletNotAttached,

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("Insufficient balance")]
    InsufficientBalance,

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Consensus failed: {0}")]
    ConsensusFailed(String),

    #[error("State sync required")]
    StateSyncRequired,

    #[error("Mempool full")]
    MempoolFull,

    #[error("Rate limited")]
    RateLimited,

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Server error: {0}")]
    ServerError(String),
}

impl From<RpcError> for ErrorObjectOwned {
    fn from(err: RpcError) -> Self {
        let (code, message) = match &err {
            RpcError::ParseError(msg) => (RpcErrorCode::ParseError.code(), msg.clone()),
            RpcError::InvalidRequest(msg) => (RpcErrorCode::InvalidRequest.code(), msg.clone()),
            RpcError::MethodNotFound(msg) => (RpcErrorCode::MethodNotFound.code(), msg.clone()),
            RpcError::InvalidParams(msg) => (RpcErrorCode::InvalidParams.code(), msg.clone()),
            RpcError::InternalError(msg) => (RpcErrorCode::InternalError.code(), msg.clone()),
            RpcError::NodeNotRunning => (RpcErrorCode::NodeNotRunning.code(), "Node not running".to_string()),
            RpcError::WalletNotAttached => (RpcErrorCode::WalletNotAttached.code(), "Wallet not attached".to_string()),
            RpcError::TransactionFailed(msg) => (RpcErrorCode::TransactionFailed.code(), msg.clone()),
            RpcError::InsufficientBalance => (RpcErrorCode::InsufficientBalance.code(), "Insufficient balance".to_string()),
            RpcError::InvalidAddress(msg) => (RpcErrorCode::InvalidAddress.code(), msg.clone()),
            RpcError::ConsensusFailed(msg) => (RpcErrorCode::ConsensusFailed.code(), msg.clone()),
            RpcError::StateSyncRequired => (RpcErrorCode::StateSyncRequired.code(), "State sync required".to_string()),
            RpcError::MempoolFull => (RpcErrorCode::MempoolFull.code(), "Mempool full".to_string()),
            RpcError::RateLimited => (RpcErrorCode::RateLimited.code(), "Rate limited".to_string()),
            RpcError::Unauthorized => (RpcErrorCode::Unauthorized.code(), "Unauthorized".to_string()),
            RpcError::ServerError(msg) => (RpcErrorCode::InternalError.code(), msg.clone()),
        };

        ErrorObjectOwned::owned(code, message, None::<()>)
    }
}

/// Result type for RPC operations
pub type RpcResult<T> = Result<T, RpcError>;
