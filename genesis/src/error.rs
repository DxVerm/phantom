//! Genesis errors

use thiserror::Error;

/// Genesis result type
pub type GenesisResult<T> = Result<T, GenesisError>;

/// Genesis errors
#[derive(Error, Debug)]
pub enum GenesisError {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parsing error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// TOML parsing error
    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    /// TOML serialization error
    #[error("TOML serialize error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Invalid address format
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid public key format
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Invalid validator configuration
    #[error("Invalid validator config: {0}")]
    InvalidValidator(String),

    /// Duplicate allocation
    #[error("Duplicate allocation for address: {0}")]
    DuplicateAllocation(String),
}
