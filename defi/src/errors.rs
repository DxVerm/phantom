//! DeFi Error Types

use thiserror::Error;

/// Errors that can occur in DeFi operations
#[derive(Error, Debug, Clone, PartialEq)]
pub enum DeFiError {
    // Pool errors
    #[error("Pool not found: {0}")]
    PoolNotFound(String),

    #[error("Pool already exists: {0}")]
    PoolAlreadyExists(String),

    #[error("Pool is paused")]
    PoolPaused,

    #[error("Pool is not initialized")]
    PoolNotInitialized,

    // Liquidity errors
    #[error("Insufficient liquidity for operation")]
    InsufficientLiquidity,

    #[error("Minimum liquidity not met: required {required}, got {actual}")]
    MinimumLiquidityNotMet { required: u64, actual: u64 },

    #[error("Zero liquidity provided")]
    ZeroLiquidity,

    #[error("Liquidity locked until block {0}")]
    LiquidityLocked(u64),

    // Swap errors
    #[error("Slippage exceeded: expected minimum {expected}, got {actual}")]
    SlippageExceeded { expected: u64, actual: u64 },

    #[error("Swap amount too small")]
    SwapAmountTooSmall,

    #[error("Swap amount exceeds reserve")]
    SwapAmountExceedsReserve,

    #[error("Invalid swap direction")]
    InvalidSwapDirection,

    #[error("Price impact too high: {0}%")]
    PriceImpactTooHigh(u8),

    // Token errors
    #[error("Invalid token address: {0}")]
    InvalidTokenAddress(String),

    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u64, available: u64 },

    #[error("Token transfer failed")]
    TokenTransferFailed,

    // LP token errors
    #[error("Insufficient LP tokens: required {required}, available {available}")]
    InsufficientLPTokens { required: u64, available: u64 },

    #[error("LP token minting failed")]
    LPMintFailed,

    #[error("LP token burning failed")]
    LPBurnFailed,

    // FHE errors
    #[error("FHE operation failed: {0}")]
    FheOperationFailed(String),

    #[error("Server key not initialized")]
    ServerKeyNotSet,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Encrypted comparison failed")]
    EncryptedComparisonFailed,

    // Lending errors
    #[error("Collateral ratio too low: {current}% < {required}%")]
    CollateralRatioTooLow { current: u8, required: u8 },

    #[error("Position not found")]
    PositionNotFound,

    #[error("Position already exists")]
    PositionAlreadyExists,

    #[error("Liquidation threshold not reached")]
    LiquidationThresholdNotReached,

    #[error("Borrow amount exceeds limit")]
    BorrowAmountExceedsLimit,

    // Staking errors
    #[error("Market is not active")]
    MarketNotActive,

    #[error("Unstaking period not elapsed")]
    UnstakingPeriodNotElapsed,

    #[error("Stake amount too small")]
    StakeAmountTooSmall,

    #[error("Validator not found")]
    ValidatorNotFound,

    #[error("Already delegated to this validator")]
    AlreadyDelegated,

    // Fee errors
    #[error("Fee too high: requested {requested} bps, maximum {maximum} bps")]
    FeeTooHigh { requested: u16, maximum: u16 },

    // Deadline errors
    #[error("Deadline expired: deadline block {deadline}, current block {current}")]
    DeadlineExpired { deadline: u64, current: u64 },

    // General errors
    #[error("Arithmetic overflow")]
    ArithmeticOverflow,

    #[error("Arithmetic underflow")]
    ArithmeticUnderflow,

    #[error("Division by zero")]
    DivisionByZero,

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Unauthorized operation")]
    Unauthorized,

    #[error("Operation deadline exceeded")]
    DeadlineExceeded,

    #[error("Reentrancy detected")]
    ReentrancyDetected,

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for DeFi operations
pub type DeFiResult<T> = Result<T, DeFiError>;
