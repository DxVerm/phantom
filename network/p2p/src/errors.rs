//! P2P Network Error Types

use thiserror::Error;

/// P2P network errors
#[derive(Error, Debug)]
pub enum P2PError {
    /// Transport error
    #[error("Transport error: {0}")]
    Transport(String),

    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// Peer not found
    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    /// Discovery error
    #[error("Discovery error: {0}")]
    Discovery(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Channel error
    #[error("Channel error: {0}")]
    Channel(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Network not started
    #[error("Network not started")]
    NotStarted,

    /// Network already running
    #[error("Network already running")]
    AlreadyRunning,

    /// Timeout
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Message error
    #[error("Message error: {0}")]
    MessageError(String),

    /// Sync failed
    #[error("Sync failed: {0}")]
    SyncFailed(String),

    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}

/// Result type for P2P operations
pub type P2PResult<T> = Result<T, P2PError>;
