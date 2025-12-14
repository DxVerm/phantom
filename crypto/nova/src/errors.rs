//! Error types for Nova ZKP operations

use thiserror::Error;

/// Errors that can occur during Nova operations
#[derive(Error, Debug)]
pub enum NovaError {
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    #[error("Circuit constraint violation: {0}")]
    ConstraintViolation(String),

    #[error("Folding error: {0}")]
    FoldingError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid public input: {0}")]
    InvalidPublicInput(String),

    #[error("Setup error: {0}")]
    SetupError(String),
}

impl From<std::io::Error> for NovaError {
    fn from(err: std::io::Error) -> Self {
        NovaError::SerializationError(err.to_string())
    }
}
