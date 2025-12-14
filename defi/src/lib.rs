//! PHANTOM DeFi Primitives
//!
//! Privacy-preserving decentralized finance components built on FHE.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    PHANTOM DeFi Stack                        │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
//! │  │  Private    │  │   Private   │  │   Private   │         │
//! │  │    AMM      │  │   Lending   │  │   Staking   │         │
//! │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
//! │         │                │                │                 │
//! │         └────────────────┼────────────────┘                 │
//! │                          ▼                                  │
//! │  ┌─────────────────────────────────────────────────────┐   │
//! │  │           Encrypted State (FHE + ESL)                │   │
//! │  │  - Hidden reserve balances                           │   │
//! │  │  - Private swap amounts                              │   │
//! │  │  - Encrypted collateral ratios                       │   │
//! │  │  - Hidden stake amounts                              │   │
//! │  └─────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key Features
//!
//! - **Private AMM**: Constant product formula with encrypted reserves
//! - **Private Lending**: Hidden collateral and borrow positions
//! - **Private Staking**: Concealed stake amounts with verifiable rewards

pub mod amm;
pub mod errors;
pub mod lending;
pub mod liquidity;
pub mod pool;
pub mod staking;
pub mod swap;

// Re-export main types
pub use amm::{ConstantProductAMM, PrivateAMM, PoolStats};
pub use errors::DeFiError;
pub use lending::{LendingConfig, LendingMarket, LendingPosition, LiquidationResult, DecryptedPosition, DecryptedLiquidation};
pub use liquidity::{LPToken, LiquidityPosition, LiquidityRegistry, FeeDistributor};
pub use pool::{LiquidityPool, PoolConfig, PoolState};
pub use staking::{StakingConfig, StakingPool, StakingPosition, EpochInfo, PoolStats as StakingPoolStats, DecryptedPosition as StakingDecryptedPosition};
pub use swap::{SwapDirection, SwapExecution, SwapRequest, SwapResult, SwapQuote, DecryptedSwapResult};

/// Prelude for convenient imports
pub mod prelude {
    pub use crate::amm::{ConstantProductAMM, PrivateAMM, PoolStats};
    pub use crate::errors::DeFiError;
    pub use crate::lending::{LendingConfig, LendingMarket, LendingPosition, DecryptedPosition as LendingDecryptedPosition};
    pub use crate::liquidity::{LPToken, LiquidityPosition, LiquidityRegistry};
    pub use crate::pool::{LiquidityPool, PoolConfig, PoolState};
    pub use crate::staking::{StakingConfig, StakingPool, StakingPosition, EpochInfo, DecryptedPosition as StakingDecryptedPosition};
    pub use crate::swap::{SwapDirection, SwapExecution, SwapRequest, SwapResult, SwapQuote};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prelude_imports() {
        // Verify all prelude types are accessible
        let _ = DeFiError::InsufficientLiquidity;
        let _ = SwapDirection::AtoB;
    }
}
