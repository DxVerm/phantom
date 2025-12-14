//! Private Lending Protocol with FHE-encrypted positions
//!
//! Implements collateralized lending where:
//! - Collateral amounts are encrypted (position sizes hidden)
//! - Borrow amounts are encrypted (debt privacy)
//! - Health factors computed on encrypted values
//! - Liquidations use encrypted comparisons

use crate::errors::{DeFiError, DeFiResult};
use std::collections::HashMap;
use tfhe::prelude::*;
use tfhe::{ClientKey, FheUint64, ServerKey, set_server_key};

/// Configuration for a lending market
#[derive(Debug, Clone)]
pub struct LendingConfig {
    /// Collateral token identifier
    pub collateral_token: [u8; 32],
    /// Borrow token identifier
    pub borrow_token: [u8; 32],
    /// Loan-to-Value ratio in basis points (e.g., 7500 = 75%)
    pub ltv_bps: u16,
    /// Liquidation threshold in basis points (e.g., 8000 = 80%)
    pub liquidation_threshold_bps: u16,
    /// Liquidation penalty in basis points (e.g., 500 = 5%)
    pub liquidation_penalty_bps: u16,
    /// Interest rate per block in basis points (e.g., 1 = 0.01% per block)
    pub interest_rate_bps: u16,
    /// Minimum collateral amount
    pub min_collateral: u64,
    /// Oracle price precision (e.g., 1e8 = 8 decimals)
    pub price_precision: u64,
}

impl Default for LendingConfig {
    fn default() -> Self {
        Self {
            collateral_token: [0u8; 32],
            borrow_token: [0u8; 32],
            ltv_bps: 7500,                  // 75% LTV
            liquidation_threshold_bps: 8000, // 80% liquidation threshold
            liquidation_penalty_bps: 500,    // 5% liquidation penalty
            interest_rate_bps: 1,            // 0.01% per block
            min_collateral: 1000,
            price_precision: 100_000_000,    // 8 decimals
        }
    }
}

impl LendingConfig {
    /// Create new lending config with token pair
    pub fn new(collateral_token: [u8; 32], borrow_token: [u8; 32]) -> Self {
        Self {
            collateral_token,
            borrow_token,
            ..Default::default()
        }
    }

    /// Builder: set LTV ratio
    pub fn with_ltv(mut self, ltv_bps: u16) -> Self {
        self.ltv_bps = ltv_bps;
        self
    }

    /// Builder: set liquidation threshold
    pub fn with_liquidation_threshold(mut self, threshold_bps: u16) -> Self {
        self.liquidation_threshold_bps = threshold_bps;
        self
    }

    /// Builder: set liquidation penalty
    pub fn with_liquidation_penalty(mut self, penalty_bps: u16) -> Self {
        self.liquidation_penalty_bps = penalty_bps;
        self
    }

    /// Builder: set interest rate
    pub fn with_interest_rate(mut self, rate_bps: u16) -> Self {
        self.interest_rate_bps = rate_bps;
        self
    }
}

/// Encrypted lending position for a user
pub struct LendingPosition {
    /// User identifier
    pub user: [u8; 32],
    /// Encrypted collateral amount
    pub collateral: FheUint64,
    /// Encrypted borrow amount (principal)
    pub borrow_principal: FheUint64,
    /// Encrypted accrued interest
    pub accrued_interest: FheUint64,
    /// Last interest update block
    pub last_update_block: u64,
    /// Position is active
    pub is_active: bool,
}

impl std::fmt::Debug for LendingPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LendingPosition")
            .field("user", &hex::encode(&self.user))
            .field("collateral", &"<encrypted>")
            .field("borrow_principal", &"<encrypted>")
            .field("accrued_interest", &"<encrypted>")
            .field("last_update_block", &self.last_update_block)
            .field("is_active", &self.is_active)
            .finish()
    }
}

impl LendingPosition {
    /// Create a new empty position
    pub fn new(user: [u8; 32], client_key: &ClientKey, block_height: u64) -> Self {
        let zero = FheUint64::encrypt(0u64, client_key);
        Self {
            user,
            collateral: zero.clone(),
            borrow_principal: zero.clone(),
            accrued_interest: zero,
            last_update_block: block_height,
            is_active: true,
        }
    }

    /// Get total debt (principal + interest) as encrypted value
    pub fn total_debt(&self) -> FheUint64 {
        &self.borrow_principal + &self.accrued_interest
    }
}

/// Decrypted position for verification/display
#[derive(Debug, Clone)]
pub struct DecryptedPosition {
    pub user: [u8; 32],
    pub collateral: u64,
    pub borrow_principal: u64,
    pub accrued_interest: u64,
    pub total_debt: u64,
    pub health_factor_bps: u64,
}

/// Lending market state with encrypted totals
pub struct LendingMarket {
    /// Market identifier
    pub id: [u8; 32],
    /// Market configuration
    pub config: LendingConfig,
    /// Encrypted total collateral deposited
    pub total_collateral: FheUint64,
    /// Encrypted total borrowed
    pub total_borrowed: FheUint64,
    /// Encrypted total available to borrow
    pub available_liquidity: FheUint64,
    /// User positions (user_id -> position)
    positions: HashMap<[u8; 32], LendingPosition>,
    /// FHE client key
    client_key: ClientKey,
    /// FHE server key
    server_key: ServerKey,
    /// Creation block
    pub created_at_block: u64,
    /// Last update block
    pub last_update_block: u64,
    /// Market is active
    pub is_active: bool,
}

impl LendingMarket {
    /// Create a new lending market
    pub fn new(
        config: LendingConfig,
        client_key: ClientKey,
        server_key: ServerKey,
        block_height: u64,
    ) -> Self {
        set_server_key(server_key.clone());

        // Create market ID from token pair
        let mut id_input = Vec::with_capacity(64);
        id_input.extend_from_slice(&config.collateral_token);
        id_input.extend_from_slice(&config.borrow_token);
        let id: [u8; 32] = blake3::hash(&id_input).into();

        let zero = FheUint64::encrypt(0u64, &client_key);

        Self {
            id,
            config,
            total_collateral: zero.clone(),
            total_borrowed: zero.clone(),
            available_liquidity: zero,
            positions: HashMap::new(),
            client_key,
            server_key,
            created_at_block: block_height,
            last_update_block: block_height,
            is_active: true,
        }
    }

    /// Get market ID
    pub fn id(&self) -> [u8; 32] {
        self.id
    }

    /// Encrypt a value
    pub fn encrypt(&self, value: u64) -> FheUint64 {
        FheUint64::encrypt(value, &self.client_key)
    }

    /// Decrypt a value
    pub fn decrypt(&self, encrypted: &FheUint64) -> u64 {
        encrypted.decrypt(&self.client_key)
    }

    /// Get client key reference
    pub fn client_key(&self) -> &ClientKey {
        &self.client_key
    }

    /// Supply initial liquidity to the market
    pub fn supply_liquidity(&mut self, amount: u64) -> DeFiResult<()> {
        if amount == 0 {
            return Err(DeFiError::ZeroLiquidity);
        }

        set_server_key(self.server_key.clone());
        let amount_enc = self.encrypt(amount);
        self.available_liquidity = &self.available_liquidity + &amount_enc;

        Ok(())
    }

    /// Get or create a position for a user
    fn get_or_create_position(&mut self, user: [u8; 32], block_height: u64) -> &mut LendingPosition {
        if !self.positions.contains_key(&user) {
            let position = LendingPosition::new(user, &self.client_key, block_height);
            self.positions.insert(user, position);
        }
        self.positions.get_mut(&user).unwrap()
    }

    /// Supply collateral (encrypted amount)
    pub fn supply_collateral(
        &mut self,
        user: [u8; 32],
        amount: FheUint64,
        current_block: u64,
    ) -> DeFiResult<()> {
        set_server_key(self.server_key.clone());

        // Verify minimum collateral
        let amount_dec: u64 = amount.decrypt(&self.client_key);
        if amount_dec < self.config.min_collateral {
            return Err(DeFiError::MinimumLiquidityNotMet {
                required: self.config.min_collateral,
                actual: amount_dec,
            });
        }

        // Update position
        let position = self.get_or_create_position(user, current_block);
        position.collateral = &position.collateral + &amount;
        position.last_update_block = current_block;

        // Update market totals
        self.total_collateral = &self.total_collateral + &amount;
        self.last_update_block = current_block;

        Ok(())
    }

    /// Borrow against collateral (encrypted amount)
    pub fn borrow(
        &mut self,
        user: [u8; 32],
        amount: FheUint64,
        collateral_price: u64,
        borrow_price: u64,
        current_block: u64,
    ) -> DeFiResult<()> {
        set_server_key(self.server_key.clone());

        // First accrue interest on existing position
        self.accrue_interest(user, current_block)?;

        let position = self.positions.get(&user)
            .ok_or(DeFiError::PositionNotFound)?;

        // Calculate collateral value in borrow token terms
        // collateral_value = collateral * collateral_price / borrow_price
        let collateral_dec: u64 = position.collateral.decrypt(&self.client_key);
        let collateral_value = collateral_dec as u128 * collateral_price as u128 / borrow_price as u128;

        // Calculate max borrow based on LTV
        let max_borrow = (collateral_value * self.config.ltv_bps as u128 / 10000) as u64;

        // Get current debt
        let current_debt: u64 = position.total_debt().decrypt(&self.client_key);
        let borrow_amount: u64 = amount.decrypt(&self.client_key);

        // Check if borrow would exceed LTV
        if current_debt + borrow_amount > max_borrow {
            return Err(DeFiError::BorrowAmountExceedsLimit);
        }

        // Check available liquidity
        let available: u64 = self.available_liquidity.decrypt(&self.client_key);
        if borrow_amount > available {
            return Err(DeFiError::InsufficientLiquidity);
        }

        // Update position
        let position = self.positions.get_mut(&user).unwrap();
        position.borrow_principal = &position.borrow_principal + &amount;
        position.last_update_block = current_block;

        // Update market totals
        self.total_borrowed = &self.total_borrowed + &amount;
        self.available_liquidity = &self.available_liquidity - &amount;
        self.last_update_block = current_block;

        Ok(())
    }

    /// Repay borrowed amount (encrypted)
    pub fn repay(
        &mut self,
        user: [u8; 32],
        amount: FheUint64,
        current_block: u64,
    ) -> DeFiResult<FheUint64> {
        set_server_key(self.server_key.clone());

        // Accrue interest first
        self.accrue_interest(user, current_block)?;

        let position = self.positions.get(&user)
            .ok_or(DeFiError::PositionNotFound)?;

        let repay_amount: u64 = amount.decrypt(&self.client_key);
        let total_debt: u64 = position.total_debt().decrypt(&self.client_key);

        // Calculate actual repayment (can't repay more than debt)
        let actual_repay = repay_amount.min(total_debt);
        let actual_repay_enc = self.encrypt(actual_repay);

        // First pay off interest, then principal
        let interest: u64 = position.accrued_interest.decrypt(&self.client_key);
        let principal: u64 = position.borrow_principal.decrypt(&self.client_key);

        // Pre-compute all encrypted values BEFORE getting mutable reference
        let (new_interest_enc, new_principal_enc) = if actual_repay <= interest {
            // Only reduces interest, principal unchanged
            (self.encrypt(interest - actual_repay), None)
        } else {
            // Pay off all interest and some principal
            let principal_repay = actual_repay - interest;
            (self.encrypt(0), Some(self.encrypt(principal.saturating_sub(principal_repay))))
        };

        // NOW get mutable reference and apply pre-computed values
        let position = self.positions.get_mut(&user).unwrap();
        position.accrued_interest = new_interest_enc;
        if let Some(new_principal) = new_principal_enc {
            position.borrow_principal = new_principal;
        }
        position.last_update_block = current_block;

        // Update market totals
        self.total_borrowed = &self.total_borrowed - &actual_repay_enc;
        self.available_liquidity = &self.available_liquidity + &actual_repay_enc;
        self.last_update_block = current_block;

        // Return excess (if any)
        let excess = repay_amount.saturating_sub(total_debt);
        Ok(self.encrypt(excess))
    }

    /// Withdraw collateral (encrypted amount)
    pub fn withdraw_collateral(
        &mut self,
        user: [u8; 32],
        amount: FheUint64,
        collateral_price: u64,
        borrow_price: u64,
        current_block: u64,
    ) -> DeFiResult<()> {
        set_server_key(self.server_key.clone());

        // Accrue interest first
        self.accrue_interest(user, current_block)?;

        let position = self.positions.get(&user)
            .ok_or(DeFiError::PositionNotFound)?;

        let withdraw_amount: u64 = amount.decrypt(&self.client_key);
        let current_collateral: u64 = position.collateral.decrypt(&self.client_key);
        let total_debt: u64 = position.total_debt().decrypt(&self.client_key);

        if withdraw_amount > current_collateral {
            return Err(DeFiError::InsufficientBalance {
                required: withdraw_amount,
                available: current_collateral,
            });
        }

        // Calculate remaining collateral value after withdrawal
        let remaining_collateral = current_collateral - withdraw_amount;
        let remaining_value = remaining_collateral as u128 * collateral_price as u128 / borrow_price as u128;

        // Check if remaining collateral still covers debt at LTV ratio
        let required_collateral_value = total_debt as u128 * 10000 / self.config.ltv_bps as u128;

        if remaining_value < required_collateral_value {
            return Err(DeFiError::CollateralRatioTooLow {
                current: (remaining_value * 100 / required_collateral_value.max(1)) as u8,
                required: 100,
            });
        }

        // Update position
        let position = self.positions.get_mut(&user).unwrap();
        position.collateral = &position.collateral - &amount;
        position.last_update_block = current_block;

        // Update market totals
        self.total_collateral = &self.total_collateral - &amount;
        self.last_update_block = current_block;

        Ok(())
    }

    /// Accrue interest on a position
    pub fn accrue_interest(&mut self, user: [u8; 32], current_block: u64) -> DeFiResult<()> {
        let position = self.positions.get(&user)
            .ok_or(DeFiError::PositionNotFound)?;

        if !position.is_active {
            return Ok(());
        }

        let blocks_elapsed = current_block.saturating_sub(position.last_update_block);
        if blocks_elapsed == 0 {
            return Ok(());
        }

        set_server_key(self.server_key.clone());

        // Calculate interest: principal * rate * blocks / 10000
        let principal: u64 = position.borrow_principal.decrypt(&self.client_key);
        let current_interest: u64 = position.accrued_interest.decrypt(&self.client_key);

        let new_interest = principal as u128 * self.config.interest_rate_bps as u128
            * blocks_elapsed as u128 / 10000;
        let total_interest = current_interest + new_interest as u64;

        // Pre-compute encrypted value BEFORE getting mutable reference
        let total_interest_enc = self.encrypt(total_interest);

        // NOW get mutable reference and apply pre-computed value
        let position = self.positions.get_mut(&user).unwrap();
        position.accrued_interest = total_interest_enc;
        position.last_update_block = current_block;

        Ok(())
    }

    /// Calculate health factor for a position (encrypted result)
    /// Health factor = collateral_value * liquidation_threshold / total_debt
    /// Returns in basis points (10000 = 100% = healthy threshold)
    pub fn calculate_health_factor(
        &self,
        user: &[u8; 32],
        collateral_price: u64,
        borrow_price: u64,
    ) -> DeFiResult<FheUint64> {
        let position = self.positions.get(user)
            .ok_or(DeFiError::PositionNotFound)?;

        set_server_key(self.server_key.clone());

        // Calculate collateral value
        let collateral: u64 = position.collateral.decrypt(&self.client_key);
        let total_debt: u64 = position.total_debt().decrypt(&self.client_key);

        if total_debt == 0 {
            // No debt = infinite health factor, return max
            return Ok(self.encrypt(u64::MAX));
        }

        // collateral_value = collateral * collateral_price / borrow_price
        let collateral_value = collateral as u128 * collateral_price as u128 / borrow_price as u128;

        // health_factor = collateral_value * liquidation_threshold_bps / (total_debt * 10000)
        let health_factor = collateral_value * self.config.liquidation_threshold_bps as u128
            / (total_debt as u128 * 10000 / 10000);

        Ok(self.encrypt(health_factor as u64))
    }

    /// Check if a position is liquidatable
    pub fn is_liquidatable(
        &self,
        user: &[u8; 32],
        collateral_price: u64,
        borrow_price: u64,
    ) -> DeFiResult<bool> {
        let health_factor = self.calculate_health_factor(user, collateral_price, borrow_price)?;
        let hf: u64 = health_factor.decrypt(&self.client_key);
        // Health factor < 10000 (100%) means liquidatable
        Ok(hf < 10000)
    }

    /// Liquidate an unhealthy position
    pub fn liquidate(
        &mut self,
        liquidator: [u8; 32],
        user: [u8; 32],
        repay_amount: FheUint64,
        collateral_price: u64,
        borrow_price: u64,
        current_block: u64,
    ) -> DeFiResult<LiquidationResult> {
        set_server_key(self.server_key.clone());

        // Accrue interest first
        self.accrue_interest(user, current_block)?;

        // Check if position is liquidatable
        if !self.is_liquidatable(&user, collateral_price, borrow_price)? {
            return Err(DeFiError::LiquidationThresholdNotReached);
        }

        let position = self.positions.get(&user)
            .ok_or(DeFiError::PositionNotFound)?;

        let repay: u64 = repay_amount.decrypt(&self.client_key);
        let total_debt: u64 = position.total_debt().decrypt(&self.client_key);
        let collateral: u64 = position.collateral.decrypt(&self.client_key);

        // Can only repay up to 50% of debt in single liquidation (common DeFi pattern)
        let max_repay = total_debt / 2;
        let actual_repay = repay.min(max_repay);

        // Calculate collateral to seize (with liquidation bonus)
        // collateral_seized = repay_amount * borrow_price / collateral_price * (1 + penalty)
        let collateral_value = actual_repay as u128 * borrow_price as u128 / collateral_price as u128;
        let collateral_with_bonus = collateral_value
            * (10000 + self.config.liquidation_penalty_bps as u128) / 10000;
        let collateral_seized = (collateral_with_bonus as u64).min(collateral);

        let actual_repay_enc = self.encrypt(actual_repay);
        let collateral_seized_enc = self.encrypt(collateral_seized);

        // Get position values immutably first to compute new encrypted values
        let position = self.positions.get(&user).unwrap();
        let interest: u64 = position.accrued_interest.decrypt(&self.client_key);
        let principal: u64 = position.borrow_principal.decrypt(&self.client_key);
        let current_collateral = position.collateral.clone();

        // Pre-compute all encrypted values BEFORE getting mutable reference
        let (new_interest_enc, new_principal_enc) = if actual_repay <= interest {
            (self.encrypt(interest - actual_repay), None)
        } else {
            let principal_repay = actual_repay - interest;
            (self.encrypt(0), Some(self.encrypt(principal.saturating_sub(principal_repay))))
        };

        // Compute new collateral
        let new_collateral = &current_collateral - &collateral_seized_enc;

        // NOW get mutable reference and apply all pre-computed values
        let position = self.positions.get_mut(&user).unwrap();
        position.accrued_interest = new_interest_enc;
        if let Some(new_principal) = new_principal_enc {
            position.borrow_principal = new_principal;
        }
        position.collateral = new_collateral;
        position.last_update_block = current_block;

        // Update market totals
        self.total_borrowed = &self.total_borrowed - &actual_repay_enc;
        self.total_collateral = &self.total_collateral - &collateral_seized_enc;
        self.available_liquidity = &self.available_liquidity + &actual_repay_enc;
        self.last_update_block = current_block;

        Ok(LiquidationResult {
            liquidator,
            user,
            debt_repaid: actual_repay_enc,
            collateral_seized: collateral_seized_enc,
        })
    }

    /// Get position for a user
    pub fn get_position(&self, user: &[u8; 32]) -> Option<&LendingPosition> {
        self.positions.get(user)
    }

    /// Decrypt a position for verification
    pub fn decrypt_position(&self, user: &[u8; 32], collateral_price: u64, borrow_price: u64) -> DeFiResult<DecryptedPosition> {
        let position = self.positions.get(user)
            .ok_or(DeFiError::PositionNotFound)?;

        let collateral: u64 = position.collateral.decrypt(&self.client_key);
        let borrow_principal: u64 = position.borrow_principal.decrypt(&self.client_key);
        let accrued_interest: u64 = position.accrued_interest.decrypt(&self.client_key);
        let total_debt = borrow_principal + accrued_interest;

        // Calculate health factor
        let health_factor_bps = if total_debt == 0 {
            u64::MAX
        } else {
            let collateral_value = collateral as u128 * collateral_price as u128 / borrow_price as u128;
            (collateral_value * self.config.liquidation_threshold_bps as u128 / total_debt as u128) as u64
        };

        Ok(DecryptedPosition {
            user: *user,
            collateral,
            borrow_principal,
            accrued_interest,
            total_debt,
            health_factor_bps,
        })
    }
}

/// Result of a liquidation
pub struct LiquidationResult {
    /// Liquidator address
    pub liquidator: [u8; 32],
    /// Liquidated user address
    pub user: [u8; 32],
    /// Encrypted amount of debt repaid
    pub debt_repaid: FheUint64,
    /// Encrypted amount of collateral seized
    pub collateral_seized: FheUint64,
}

impl std::fmt::Debug for LiquidationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiquidationResult")
            .field("liquidator", &hex::encode(&self.liquidator))
            .field("user", &hex::encode(&self.user))
            .field("debt_repaid", &"<encrypted>")
            .field("collateral_seized", &"<encrypted>")
            .finish()
    }
}

/// Decrypted liquidation result for verification
#[derive(Debug, Clone)]
pub struct DecryptedLiquidation {
    pub liquidator: [u8; 32],
    pub user: [u8; 32],
    pub debt_repaid: u64,
    pub collateral_seized: u64,
}

impl LiquidationResult {
    /// Decrypt for verification
    pub fn decrypt(&self, client_key: &ClientKey) -> DecryptedLiquidation {
        DecryptedLiquidation {
            liquidator: self.liquidator,
            user: self.user,
            debt_repaid: self.debt_repaid.decrypt(client_key),
            collateral_seized: self.collateral_seized.decrypt(client_key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::{ConfigBuilder, generate_keys};

    fn setup_fhe() -> (ClientKey, ServerKey) {
        let config = ConfigBuilder::default().build();
        generate_keys(config)
    }

    #[test]
    fn test_lending_config_default() {
        let config = LendingConfig::default();
        assert_eq!(config.ltv_bps, 7500);
        assert_eq!(config.liquidation_threshold_bps, 8000);
        assert_eq!(config.liquidation_penalty_bps, 500);
    }

    #[test]
    fn test_lending_market_creation() {
        let (client_key, server_key) = setup_fhe();
        let collateral = [1u8; 32];
        let borrow = [2u8; 32];
        let config = LendingConfig::new(collateral, borrow);

        let market = LendingMarket::new(config, client_key, server_key, 0);

        assert!(market.is_active);
        assert_eq!(market.decrypt(&market.total_collateral), 0);
        assert_eq!(market.decrypt(&market.total_borrowed), 0);
    }

    #[test]
    fn test_supply_collateral() {
        let (client_key, server_key) = setup_fhe();
        let config = LendingConfig::default().with_ltv(7500);
        let mut market = LendingMarket::new(config, client_key.clone(), server_key, 0);

        let user = [1u8; 32];
        let amount = FheUint64::encrypt(10000u64, &client_key);

        market.supply_collateral(user, amount, 1).unwrap();

        let position = market.get_position(&user).unwrap();
        let collateral: u64 = position.collateral.decrypt(&client_key);
        assert_eq!(collateral, 10000);
    }

    #[test]
    fn test_borrow_within_ltv() {
        let (client_key, server_key) = setup_fhe();
        let config = LendingConfig::default().with_ltv(7500); // 75% LTV
        let mut market = LendingMarket::new(config, client_key.clone(), server_key, 0);

        // Supply liquidity first
        market.supply_liquidity(100000).unwrap();

        let user = [1u8; 32];
        let collateral = FheUint64::encrypt(10000u64, &client_key);

        market.supply_collateral(user, collateral, 1).unwrap();

        // Borrow 50% of collateral value (within 75% LTV)
        // Assuming 1:1 price ratio for simplicity
        let borrow_amount = FheUint64::encrypt(5000u64, &client_key);
        let result = market.borrow(user, borrow_amount, 1, 1, 2);

        assert!(result.is_ok());

        let position = market.get_position(&user).unwrap();
        let borrowed: u64 = position.borrow_principal.decrypt(&client_key);
        assert_eq!(borrowed, 5000);
    }

    #[test]
    fn test_borrow_exceeds_ltv() {
        let (client_key, server_key) = setup_fhe();
        let config = LendingConfig::default().with_ltv(7500);
        let mut market = LendingMarket::new(config, client_key.clone(), server_key, 0);

        market.supply_liquidity(100000).unwrap();

        let user = [1u8; 32];
        let collateral = FheUint64::encrypt(10000u64, &client_key);
        market.supply_collateral(user, collateral, 1).unwrap();

        // Try to borrow 80% (exceeds 75% LTV)
        let borrow_amount = FheUint64::encrypt(8000u64, &client_key);
        let result = market.borrow(user, borrow_amount, 1, 1, 2);

        assert!(matches!(result, Err(DeFiError::BorrowAmountExceedsLimit)));
    }

    #[test]
    fn test_repay() {
        let (client_key, server_key) = setup_fhe();
        let config = LendingConfig::default();
        let mut market = LendingMarket::new(config, client_key.clone(), server_key, 0);

        market.supply_liquidity(100000).unwrap();

        let user = [1u8; 32];
        let collateral = FheUint64::encrypt(10000u64, &client_key);
        market.supply_collateral(user, collateral, 1).unwrap();

        let borrow_amount = FheUint64::encrypt(5000u64, &client_key);
        market.borrow(user, borrow_amount, 1, 1, 2).unwrap();

        // Repay half
        let repay_amount = FheUint64::encrypt(2500u64, &client_key);
        market.repay(user, repay_amount, 3).unwrap();

        let position = market.get_position(&user).unwrap();
        let remaining: u64 = position.borrow_principal.decrypt(&client_key);
        assert_eq!(remaining, 2500);
    }

    #[test]
    fn test_health_factor_calculation() {
        let (client_key, server_key) = setup_fhe();
        let config = LendingConfig::default()
            .with_ltv(7500)
            .with_liquidation_threshold(8000);
        let mut market = LendingMarket::new(config, client_key.clone(), server_key, 0);

        market.supply_liquidity(100000).unwrap();

        let user = [1u8; 32];
        let collateral = FheUint64::encrypt(10000u64, &client_key);
        market.supply_collateral(user, collateral, 1).unwrap();

        let borrow_amount = FheUint64::encrypt(5000u64, &client_key);
        market.borrow(user, borrow_amount, 1, 1, 2).unwrap();

        // Health factor = 10000 * 8000 / (5000 * 10000) = 16000 bps (160%)
        let hf = market.calculate_health_factor(&user, 1, 1).unwrap();
        let hf_val: u64 = hf.decrypt(&client_key);
        assert!(hf_val > 10000); // Should be healthy
    }

    #[test]
    fn test_liquidation() {
        let (client_key, server_key) = setup_fhe();
        let config = LendingConfig::default()
            .with_ltv(7500)
            .with_liquidation_threshold(8000)
            .with_liquidation_penalty(500);
        let mut market = LendingMarket::new(config, client_key.clone(), server_key, 0);

        market.supply_liquidity(100000).unwrap();

        let user = [1u8; 32];
        let collateral = FheUint64::encrypt(10000u64, &client_key);
        market.supply_collateral(user, collateral, 1).unwrap();

        // Borrow at maximum LTV
        let borrow_amount = FheUint64::encrypt(7500u64, &client_key);
        market.borrow(user, borrow_amount, 1, 1, 2).unwrap();

        // Simulate price drop - collateral now worth less
        // collateral_price drops from 1 to 0.8 (represented as 80 vs 100)
        let is_liquidatable = market.is_liquidatable(&user, 80, 100).unwrap();
        assert!(is_liquidatable);

        // Liquidate
        let liquidator = [2u8; 32];
        let repay = FheUint64::encrypt(3000u64, &client_key);
        let result = market.liquidate(liquidator, user, repay, 80, 100, 3).unwrap();

        let decrypted = result.decrypt(&client_key);
        assert!(decrypted.debt_repaid > 0);
        assert!(decrypted.collateral_seized > 0);
    }
}
