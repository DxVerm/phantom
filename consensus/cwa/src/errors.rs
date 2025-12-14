//! CWA Error types

use thiserror::Error;

/// Errors that can occur during CWA consensus
#[derive(Error, Debug)]
pub enum CWAError {
    /// Invalid attestation
    #[error("Invalid attestation: {0}")]
    InvalidAttestation(String),

    /// Insufficient signatures
    #[error("Insufficient signatures: got {got}, need {need}")]
    InsufficientSignatures { got: usize, need: usize },

    /// Validator not found
    #[error("Validator not found: {0}")]
    ValidatorNotFound(String),

    /// Invalid signature
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Threshold not met
    #[error("Threshold not met: {0}")]
    ThresholdNotMet(String),

    /// VRF verification failed
    #[error("VRF verification failed: {0}")]
    VRFVerificationFailed(String),

    /// Timeout
    #[error("Attestation timeout")]
    Timeout,

    /// Double attestation
    #[error("Double attestation detected")]
    DoubleAttestation,

    /// Invalid state update
    #[error("Invalid state update: {0}")]
    InvalidStateUpdate(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    ProtocolError(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Cryptographic error
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
}
