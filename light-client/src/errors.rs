//! Light Client Error Types

use thiserror::Error;

/// Errors that can occur in light client operations
#[derive(Error, Debug, Clone, PartialEq)]
pub enum LightClientError {
    // Header errors
    #[error("Invalid block header: {0}")]
    InvalidHeader(String),

    #[error("Header not found: height {0}")]
    HeaderNotFound(u64),

    #[error("Invalid parent hash: expected {expected}, got {actual}")]
    InvalidParentHash { expected: String, actual: String },

    #[error("Header chain gap at height {0}")]
    ChainGap(u64),

    #[error("Reorg depth {depth} exceeds maximum {max}")]
    ReorgTooDeep { depth: u64, max: u64 },

    // Sync errors
    #[error("Sync failed: {0}")]
    SyncFailed(String),

    #[error("Invalid checkpoint at height {0}")]
    InvalidCheckpoint(u64),

    #[error("Peer disconnected during sync")]
    PeerDisconnected,

    #[error("Sync timeout after {0} seconds")]
    SyncTimeout(u64),

    #[error("No peers available for sync")]
    NoPeersAvailable,

    // Verification errors
    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Proof verification failed")]
    ProofVerificationFailed,

    #[error("Invalid Merkle path")]
    InvalidMerklePath,

    #[error("State root mismatch: expected {expected}, got {actual}")]
    StateRootMismatch { expected: String, actual: String },

    // Delegation errors
    #[error("Proof delegation failed: {0}")]
    DelegationFailed(String),

    #[error("Delegated proof expired")]
    DelegatedProofExpired,

    #[error("Invalid delegation response")]
    InvalidDelegationResponse,

    #[error("Not enough nodes: required {required}, available {available}")]
    NotEnoughNodes { required: usize, available: usize },

    #[error("Delegation request not found: {0}")]
    RequestNotFound(u64),

    #[error("Unexpected node in response: {0:?}")]
    UnexpectedNode([u8; 32]),

    #[error("Unknown delegation node: {0:?}")]
    UnknownNode([u8; 32]),

    #[error("Proof has expired")]
    ProofExpired,

    #[error("No responses received from delegation nodes")]
    NoResponses,

    #[error("Delegation consensus failed - nodes returned different proofs")]
    ConsensusFailed,

    #[error("Delegation request timed out")]
    DelegationTimeout,

    // Storage errors
    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Header cache full")]
    CacheFull,

    // General errors
    #[error("Client not initialized")]
    NotInitialized,

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for light client operations
pub type LightClientResult<T> = Result<T, LightClientError>;
