//! Error types for private contracts

use thiserror::Error;

/// Errors that can occur during contract operations
#[derive(Error, Debug)]
pub enum ContractError {
    #[error("Invalid opcode: {0}")]
    InvalidOpcode(u8),

    #[error("Stack underflow: need {needed} values, have {have}")]
    StackUnderflow { needed: usize, have: usize },

    #[error("Stack overflow: maximum {max} values")]
    StackOverflow { max: usize },

    #[error("Invalid memory access at offset {offset}")]
    InvalidMemoryAccess { offset: usize },

    #[error("Division by zero")]
    DivisionByZero,

    #[error("Insufficient balance for transfer")]
    InsufficientBalance,

    #[error("FHE operation failed: {0}")]
    FHEError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid contract code: {0}")]
    InvalidCode(String),

    #[error("Contract not found: {0}")]
    ContractNotFound(String),

    #[error("Execution limit exceeded: {limit} gas")]
    GasExhausted { limit: u64 },

    #[error("Invalid state transition")]
    InvalidStateTransition,

    #[error("Proof generation failed: {0}")]
    ProofError(String),

    #[error("Server key not set - call set_server_key first")]
    ServerKeyNotSet,

    #[error("ABI encoding error: {0}")]
    ABIEncodingError(String),

    #[error("ABI decoding error: {0}")]
    ABIDecodingError(String),

    #[error("Invalid function selector: expected {expected}, got {got}")]
    InvalidSelector { expected: String, got: String },

    #[error("Parameter count mismatch: expected {expected}, got {got}")]
    ParameterCountMismatch { expected: usize, got: usize },

    #[error("Invalid parameter type at index {index}: {message}")]
    InvalidParameterType { index: usize, message: String },
}

impl From<phantom_fhe::FHEError> for ContractError {
    fn from(err: phantom_fhe::FHEError) -> Self {
        ContractError::FHEError(err.to_string())
    }
}

impl From<phantom_esl::ESLError> for ContractError {
    fn from(err: phantom_esl::ESLError) -> Self {
        ContractError::FHEError(err.to_string())
    }
}
