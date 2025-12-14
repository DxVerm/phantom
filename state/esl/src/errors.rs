//! Error types for Encrypted State Lattice operations

use thiserror::Error;

/// Errors that can occur during ESL operations
#[derive(Error, Debug)]
pub enum ESLError {
    #[error("Fragment not found: {0}")]
    FragmentNotFound(String),

    #[error("Invalid fragment: {0}")]
    InvalidFragment(String),

    #[error("Nullifier already exists: {0}")]
    NullifierAlreadyExists(String),

    #[error("Invalid nullifier: {0}")]
    InvalidNullifier(String),

    #[error("Commitment not found in tree: {0}")]
    CommitmentNotFound(String),

    #[error("Invalid commitment: {0}")]
    InvalidCommitment(String),

    #[error("Merkle path verification failed: {0}")]
    MerkleVerificationFailed(String),

    #[error("Insufficient witnesses: got {got}, need {need}")]
    InsufficientWitnesses { got: usize, need: usize },

    #[error("Invalid witness attestation: {0}")]
    InvalidWitnessAttestation(String),

    #[error("State update failed: {0}")]
    StateUpdateFailed(String),

    #[error("Double spend detected: {0}")]
    DoubleSpendDetected(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}
