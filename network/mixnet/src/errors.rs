//! Mixnet error types

use thiserror::Error;

/// Errors that can occur in the mixnet
#[derive(Error, Debug)]
pub enum MixnetError {
    /// Invalid packet format
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Invalid routing info
    #[error("Invalid routing: {0}")]
    InvalidRouting(String),

    /// No route available
    #[error("No route to destination")]
    NoRoute,

    /// Circuit construction failed
    #[error("Circuit construction failed: {0}")]
    CircuitFailed(String),

    /// Node not found
    #[error("Mix node not found: {0}")]
    NodeNotFound(String),

    /// Authentication failed
    #[error("Authentication failed")]
    AuthenticationFailed,

    /// Replay attack detected
    #[error("Replay detected")]
    ReplayDetected,

    /// Packet too large
    #[error("Packet too large: {size} > {max}")]
    PacketTooLarge { size: usize, max: usize },

    /// Network error
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Timeout
    #[error("Operation timed out")]
    Timeout,

    /// Cryptographic error
    #[error("Crypto error: {0}")]
    CryptoError(String),
}

pub type MixnetResult<T> = Result<T, MixnetError>;
