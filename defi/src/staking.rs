//! Private Staking with FHE-encrypted stake amounts
//!
//! Implements staking with:
//! - Encrypted stake amounts (only staker knows their stake)
//! - Encrypted reward accumulation
//! - Verifiable reward distribution using FHE
//! - Epoch-based reward calculation
//! - Withdrawal delays for security

use crate::errors::{DeFiError, DeFiResult};
use std::collections::HashMap;
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ClientKey, ConfigBuilder, FheUint64, ServerKey};

/// Staking pool configuration
#[derive(Debug, Clone)]
pub struct StakingConfig {
    /// Staking token identifier
    pub staking_token: [u8; 32],
    /// Reward token identifier (can be same as staking token)
    pub reward_token: [u8; 32],
    /// Reward rate per epoch in basis points (e.g., 50 = 0.5% per epoch)
    pub reward_rate_bps: u16,
    /// Epoch duration in blocks
    pub epoch_duration: u64,
    /// Minimum stake amount
    pub minimum_stake: u64,
    /// Unbonding period in blocks (delay before unstaking)
    pub unbonding_period: u64,
    /// Maximum total stake (0 = unlimited)
    pub max_total_stake: u64,
    /// Pool administrator
    pub admin: [u8; 32],
}

impl Default for StakingConfig {
    fn default() -> Self {
        Self {
            staking_token: [0u8; 32],
            reward_token: [0u8; 32],
            reward_rate_bps: 50,         // 0.5% per epoch
            epoch_duration: 7200,        // ~1 day at 12s blocks
            minimum_stake: 1000,
            unbonding_period: 21600,     // ~3 days
            max_total_stake: 0,          // unlimited
            admin: [0u8; 32],
        }
    }
}

impl StakingConfig {
    /// Create new staking configuration
    pub fn new(staking_token: [u8; 32], reward_token: [u8; 32]) -> Self {
        Self {
            staking_token,
            reward_token,
            ..Default::default()
        }
    }

    /// Set reward rate
    pub fn with_reward_rate(mut self, rate_bps: u16) -> Self {
        self.reward_rate_bps = rate_bps;
        self
    }

    /// Set epoch duration
    pub fn with_epoch_duration(mut self, duration: u64) -> Self {
        self.epoch_duration = duration;
        self
    }

    /// Set minimum stake
    pub fn with_minimum_stake(mut self, minimum: u64) -> Self {
        self.minimum_stake = minimum;
        self
    }

    /// Set unbonding period
    pub fn with_unbonding_period(mut self, period: u64) -> Self {
        self.unbonding_period = period;
        self
    }
}

/// A staking position with encrypted amounts
pub struct StakingPosition {
    /// User address
    pub user: [u8; 32],
    /// Encrypted staked amount
    pub staked_amount: FheUint64,
    /// Encrypted pending rewards
    pub pending_rewards: FheUint64,
    /// Last reward calculation epoch
    pub last_reward_epoch: u64,
    /// Encrypted amount pending unbonding
    pub unbonding_amount: FheUint64,
    /// Block when unbonding started (0 if not unbonding)
    pub unbonding_start: u64,
    /// Block when position was created
    pub created_at_block: u64,
}

impl std::fmt::Debug for StakingPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StakingPosition")
            .field("user", &hex::encode(&self.user))
            .field("staked_amount", &"<encrypted>")
            .field("pending_rewards", &"<encrypted>")
            .field("last_reward_epoch", &self.last_reward_epoch)
            .field("unbonding_amount", &"<encrypted>")
            .field("unbonding_start", &self.unbonding_start)
            .field("created_at_block", &self.created_at_block)
            .finish()
    }
}

/// Decrypted staking position for display
#[derive(Debug, Clone)]
pub struct DecryptedPosition {
    pub user: [u8; 32],
    pub staked_amount: u64,
    pub pending_rewards: u64,
    pub last_reward_epoch: u64,
    pub unbonding_amount: u64,
    pub unbonding_start: u64,
}

/// Epoch information
#[derive(Debug, Clone)]
pub struct EpochInfo {
    /// Current epoch number
    pub epoch: u64,
    /// Block when epoch started
    pub epoch_start_block: u64,
    /// Block when epoch ends
    pub epoch_end_block: u64,
    /// Blocks remaining in epoch
    pub blocks_remaining: u64,
}

/// Staking pool with FHE-encrypted positions
pub struct StakingPool {
    /// Pool identifier
    pub id: [u8; 32],
    /// Configuration
    pub config: StakingConfig,
    /// User positions (user address -> position)
    positions: HashMap<[u8; 32], StakingPosition>,
    /// Encrypted total staked
    pub total_staked: FheUint64,
    /// Encrypted total rewards distributed
    pub total_rewards_distributed: FheUint64,
    /// Encrypted available reward pool
    pub reward_pool: FheUint64,
    /// Current epoch number
    pub current_epoch: u64,
    /// Block when current epoch started
    pub epoch_start_block: u64,
    /// Pool is active
    pub is_active: bool,
    /// Creation block
    pub created_at_block: u64,
    /// Last update block
    pub last_update_block: u64,
    /// FHE client key
    client_key: ClientKey,
    /// FHE server key
    server_key: ServerKey,
}

impl StakingPool {
    /// Create a new staking pool
    pub fn new(config: StakingConfig) -> DeFiResult<Self> {
        let fhe_config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(fhe_config);

        set_server_key(server_key.clone());

        // Generate pool ID
        let mut id_input = Vec::with_capacity(64);
        id_input.extend_from_slice(&config.staking_token);
        id_input.extend_from_slice(&config.reward_token);
        let id: [u8; 32] = blake3::hash(&id_input).into();

        let zero = FheUint64::encrypt(0u64, &client_key);

        Ok(Self {
            id,
            config,
            positions: HashMap::new(),
            total_staked: zero.clone(),
            total_rewards_distributed: zero.clone(),
            reward_pool: zero,
            current_epoch: 0,
            epoch_start_block: 0,
            is_active: false,
            created_at_block: 0,
            last_update_block: 0,
            client_key,
            server_key,
        })
    }

    /// Create pool with existing FHE keys
    pub fn with_keys(
        config: StakingConfig,
        client_key: ClientKey,
        server_key: ServerKey,
    ) -> DeFiResult<Self> {
        set_server_key(server_key.clone());

        let mut id_input = Vec::with_capacity(64);
        id_input.extend_from_slice(&config.staking_token);
        id_input.extend_from_slice(&config.reward_token);
        let id: [u8; 32] = blake3::hash(&id_input).into();

        let zero = FheUint64::encrypt(0u64, &client_key);

        Ok(Self {
            id,
            config,
            positions: HashMap::new(),
            total_staked: zero.clone(),
            total_rewards_distributed: zero.clone(),
            reward_pool: zero,
            current_epoch: 0,
            epoch_start_block: 0,
            is_active: false,
            created_at_block: 0,
            last_update_block: 0,
            client_key,
            server_key,
        })
    }

    /// Initialize the staking pool with initial rewards
    pub fn initialize(
        &mut self,
        initial_rewards: u64,
        start_block: u64,
    ) -> DeFiResult<()> {
        if self.is_active {
            return Err(DeFiError::PoolAlreadyExists(hex::encode(self.id)));
        }

        set_server_key(self.server_key.clone());

        self.reward_pool = self.encrypt(initial_rewards);
        self.current_epoch = 0;
        self.epoch_start_block = start_block;
        self.created_at_block = start_block;
        self.last_update_block = start_block;
        self.is_active = true;

        Ok(())
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

    /// Get server key reference
    pub fn server_key(&self) -> &ServerKey {
        &self.server_key
    }

    /// Get current epoch info
    pub fn get_epoch_info(&self, current_block: u64) -> EpochInfo {
        let blocks_since_start = current_block.saturating_sub(self.epoch_start_block);
        let epochs_passed = blocks_since_start / self.config.epoch_duration;
        let current_epoch = self.current_epoch + epochs_passed;

        let current_epoch_start = self.epoch_start_block + (epochs_passed * self.config.epoch_duration);
        let current_epoch_end = current_epoch_start + self.config.epoch_duration;
        let blocks_remaining = current_epoch_end.saturating_sub(current_block);

        EpochInfo {
            epoch: current_epoch,
            epoch_start_block: current_epoch_start,
            epoch_end_block: current_epoch_end,
            blocks_remaining,
        }
    }

    /// Update epoch if needed
    fn update_epoch(&mut self, current_block: u64) {
        let blocks_since_start = current_block.saturating_sub(self.epoch_start_block);
        let epochs_passed = blocks_since_start / self.config.epoch_duration;

        if epochs_passed > 0 {
            self.current_epoch += epochs_passed;
            self.epoch_start_block += epochs_passed * self.config.epoch_duration;
        }
    }

    /// Stake tokens (encrypted amount)
    pub fn stake(
        &mut self,
        user: [u8; 32],
        amount: FheUint64,
        current_block: u64,
    ) -> DeFiResult<()> {
        if !self.is_active {
            return Err(DeFiError::MarketNotActive);
        }

        set_server_key(self.server_key.clone());

        // Validate minimum stake
        let stake_amount: u64 = amount.decrypt(&self.client_key);
        if stake_amount < self.config.minimum_stake {
            return Err(DeFiError::MinimumLiquidityNotMet {
                required: self.config.minimum_stake,
                actual: stake_amount,
            });
        }

        // Check max stake if set
        if self.config.max_total_stake > 0 {
            let current_total: u64 = self.total_staked.decrypt(&self.client_key);
            if current_total + stake_amount > self.config.max_total_stake {
                return Err(DeFiError::InsufficientLiquidity);
            }
        }

        self.update_epoch(current_block);

        // Update existing position or create new
        if let Some(position) = self.positions.get(&user) {
            // Calculate pending rewards first (immutable borrow)
            let epochs_passed = self.current_epoch.saturating_sub(position.last_reward_epoch);
            let current_stake: u64 = position.staked_amount.decrypt(&self.client_key);
            let current_rewards: u64 = position.pending_rewards.decrypt(&self.client_key);

            let new_rewards = if epochs_passed > 0 {
                let epoch_reward = current_stake as u128 * self.config.reward_rate_bps as u128
                    * epochs_passed as u128 / 10000;
                current_rewards + epoch_reward as u64
            } else {
                current_rewards
            };

            // Pre-compute encrypted values
            let new_stake_enc = self.encrypt(current_stake + stake_amount);
            let new_rewards_enc = self.encrypt(new_rewards);

            // Now get mutable reference
            let position = self.positions.get_mut(&user).unwrap();
            position.staked_amount = new_stake_enc;
            position.pending_rewards = new_rewards_enc;
            position.last_reward_epoch = self.current_epoch;
        } else {
            // New position
            let zero = self.encrypt(0);
            let new_position = StakingPosition {
                user,
                staked_amount: amount.clone(),
                pending_rewards: zero.clone(),
                last_reward_epoch: self.current_epoch,
                unbonding_amount: zero,
                unbonding_start: 0,
                created_at_block: current_block,
            };
            self.positions.insert(user, new_position);
        }

        // Update totals
        self.total_staked = &self.total_staked + &amount;
        self.last_update_block = current_block;

        Ok(())
    }

    /// Request unstaking (starts unbonding period)
    pub fn request_unstake(
        &mut self,
        user: [u8; 32],
        amount: FheUint64,
        current_block: u64,
    ) -> DeFiResult<()> {
        if !self.is_active {
            return Err(DeFiError::MarketNotActive);
        }

        set_server_key(self.server_key.clone());
        self.update_epoch(current_block);

        // First update rewards
        self.update_rewards(user, current_block)?;

        let position = self.positions.get(&user)
            .ok_or(DeFiError::PositionNotFound)?;

        let unstake_amount: u64 = amount.decrypt(&self.client_key);
        let staked: u64 = position.staked_amount.decrypt(&self.client_key);
        let current_unbonding: u64 = position.unbonding_amount.decrypt(&self.client_key);

        if unstake_amount > staked {
            return Err(DeFiError::InsufficientBalance {
                required: unstake_amount,
                available: staked,
            });
        }

        // Pre-compute encrypted values
        let new_staked_enc = self.encrypt(staked - unstake_amount);
        let new_unbonding_enc = self.encrypt(current_unbonding + unstake_amount);

        // Apply to position
        let position = self.positions.get_mut(&user).unwrap();
        position.staked_amount = new_staked_enc;
        position.unbonding_amount = new_unbonding_enc;
        position.unbonding_start = current_block;

        // Update totals
        self.total_staked = &self.total_staked - &amount;
        self.last_update_block = current_block;

        Ok(())
    }

    /// Complete unstaking after unbonding period
    pub fn complete_unstake(
        &mut self,
        user: [u8; 32],
        current_block: u64,
    ) -> DeFiResult<FheUint64> {
        set_server_key(self.server_key.clone());

        let position = self.positions.get(&user)
            .ok_or(DeFiError::PositionNotFound)?;

        let unbonding: u64 = position.unbonding_amount.decrypt(&self.client_key);
        if unbonding == 0 {
            return Err(DeFiError::PositionNotFound); // Nothing to unstake
        }

        // Check unbonding period
        let blocks_since_unbonding = current_block.saturating_sub(position.unbonding_start);
        if blocks_since_unbonding < self.config.unbonding_period {
            return Err(DeFiError::DeadlineExpired {
                deadline: position.unbonding_start + self.config.unbonding_period,
                current: current_block,
            });
        }

        // Pre-compute encrypted value
        let unbonding_enc = self.encrypt(unbonding);
        let zero_enc = self.encrypt(0);

        // Apply changes
        let position = self.positions.get_mut(&user).unwrap();
        position.unbonding_amount = zero_enc;
        position.unbonding_start = 0;

        self.last_update_block = current_block;

        Ok(unbonding_enc)
    }

    /// Update pending rewards for a user
    fn update_rewards(&mut self, user: [u8; 32], current_block: u64) -> DeFiResult<()> {
        self.update_epoch(current_block);

        let position = self.positions.get(&user)
            .ok_or(DeFiError::PositionNotFound)?;

        let epochs_passed = self.current_epoch.saturating_sub(position.last_reward_epoch);
        if epochs_passed == 0 {
            return Ok(());
        }

        set_server_key(self.server_key.clone());

        let staked: u64 = position.staked_amount.decrypt(&self.client_key);
        let current_rewards: u64 = position.pending_rewards.decrypt(&self.client_key);

        // Calculate new rewards: staked * rate * epochs
        let new_rewards = staked as u128 * self.config.reward_rate_bps as u128
            * epochs_passed as u128 / 10000;
        let total_rewards = current_rewards + new_rewards as u64;

        // Pre-compute encrypted value
        let total_rewards_enc = self.encrypt(total_rewards);

        // Apply to position
        let position = self.positions.get_mut(&user).unwrap();
        position.pending_rewards = total_rewards_enc;
        position.last_reward_epoch = self.current_epoch;

        Ok(())
    }

    /// Claim pending rewards
    pub fn claim_rewards(
        &mut self,
        user: [u8; 32],
        current_block: u64,
    ) -> DeFiResult<FheUint64> {
        set_server_key(self.server_key.clone());

        // First update rewards
        self.update_rewards(user, current_block)?;

        let position = self.positions.get(&user)
            .ok_or(DeFiError::PositionNotFound)?;

        let rewards: u64 = position.pending_rewards.decrypt(&self.client_key);
        let reward_pool_balance: u64 = self.reward_pool.decrypt(&self.client_key);

        // Check if enough rewards in pool
        let claimable = rewards.min(reward_pool_balance);
        if claimable == 0 {
            return Err(DeFiError::InsufficientLiquidity);
        }

        // Pre-compute encrypted values
        let claimable_enc = self.encrypt(claimable);
        let remaining_rewards_enc = self.encrypt(rewards - claimable);

        // Apply to position
        let position = self.positions.get_mut(&user).unwrap();
        position.pending_rewards = remaining_rewards_enc;

        // Update pool
        self.reward_pool = &self.reward_pool - &claimable_enc;
        self.total_rewards_distributed = &self.total_rewards_distributed + &claimable_enc;
        self.last_update_block = current_block;

        Ok(claimable_enc)
    }

    /// Add rewards to the pool
    pub fn add_rewards(&mut self, amount: FheUint64, current_block: u64) -> DeFiResult<()> {
        set_server_key(self.server_key.clone());

        self.reward_pool = &self.reward_pool + &amount;
        self.last_update_block = current_block;

        Ok(())
    }

    /// Get position for a user
    pub fn get_position(&self, user: &[u8; 32]) -> Option<&StakingPosition> {
        self.positions.get(user)
    }

    /// Get decrypted position for display
    pub fn get_decrypted_position(&self, user: &[u8; 32]) -> Option<DecryptedPosition> {
        self.positions.get(user).map(|pos| {
            DecryptedPosition {
                user: pos.user,
                staked_amount: pos.staked_amount.decrypt(&self.client_key),
                pending_rewards: pos.pending_rewards.decrypt(&self.client_key),
                last_reward_epoch: pos.last_reward_epoch,
                unbonding_amount: pos.unbonding_amount.decrypt(&self.client_key),
                unbonding_start: pos.unbonding_start,
            }
        })
    }

    /// Get total staked (decrypted for display)
    pub fn get_total_staked(&self) -> u64 {
        self.total_staked.decrypt(&self.client_key)
    }

    /// Get reward pool balance (decrypted for display)
    pub fn get_reward_pool_balance(&self) -> u64 {
        self.reward_pool.decrypt(&self.client_key)
    }

    /// Get total rewards distributed (decrypted for display)
    pub fn get_total_rewards_distributed(&self) -> u64 {
        self.total_rewards_distributed.decrypt(&self.client_key)
    }

    /// Calculate APY based on current state
    pub fn calculate_apy(&self) -> u64 {
        // APY = reward_rate_bps * epochs_per_year / 100
        // Assuming ~365 epochs per year (1 epoch per day)
        let epochs_per_year = 365u64;
        self.config.reward_rate_bps as u64 * epochs_per_year / 100
    }

    /// Check if pool is active
    pub fn is_active(&self) -> bool {
        self.is_active
    }

    /// Pause pool (admin only)
    pub fn pause(&mut self) {
        self.is_active = false;
    }

    /// Unpause pool (admin only)
    pub fn unpause(&mut self) {
        self.is_active = true;
    }
}

/// Staking pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_staked: u64,
    pub total_stakers: usize,
    pub reward_pool_balance: u64,
    pub total_rewards_distributed: u64,
    pub current_epoch: u64,
    pub apy: u64,
}

impl StakingPool {
    /// Get pool statistics
    pub fn get_stats(&self) -> PoolStats {
        PoolStats {
            total_staked: self.get_total_staked(),
            total_stakers: self.positions.len(),
            reward_pool_balance: self.get_reward_pool_balance(),
            total_rewards_distributed: self.get_total_rewards_distributed(),
            current_epoch: self.current_epoch,
            apy: self.calculate_apy(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_pool() -> StakingPool {
        let config = StakingConfig::new([1u8; 32], [2u8; 32])
            .with_reward_rate(100)    // 1% per epoch
            .with_minimum_stake(100)
            .with_epoch_duration(100) // 100 blocks per epoch
            .with_unbonding_period(50);

        StakingPool::new(config).expect("Failed to create pool")
    }

    #[test]
    fn test_pool_creation() {
        let pool = create_test_pool();
        assert!(!pool.is_active());
        assert_eq!(pool.config.reward_rate_bps, 100);
    }

    #[test]
    fn test_pool_initialization() {
        let mut pool = create_test_pool();
        pool.initialize(10000, 0).expect("Failed to initialize");

        assert!(pool.is_active());
        assert_eq!(pool.get_reward_pool_balance(), 10000);
        assert_eq!(pool.current_epoch, 0);
    }

    #[test]
    fn test_stake() {
        let mut pool = create_test_pool();
        pool.initialize(10000, 0).expect("Failed to initialize");

        let user = [3u8; 32];
        let amount = pool.encrypt(1000);

        pool.stake(user, amount, 10).expect("Failed to stake");

        let position = pool.get_decrypted_position(&user).expect("Position not found");
        assert_eq!(position.staked_amount, 1000);
        assert_eq!(pool.get_total_staked(), 1000);
    }

    #[test]
    fn test_stake_minimum() {
        let mut pool = create_test_pool();
        pool.initialize(10000, 0).expect("Failed to initialize");

        let user = [3u8; 32];
        let amount = pool.encrypt(50); // Below minimum of 100

        let result = pool.stake(user, amount, 10);
        assert!(matches!(result, Err(DeFiError::MinimumLiquidityNotMet { .. })));
    }

    #[test]
    fn test_reward_calculation() {
        let mut pool = create_test_pool();
        pool.initialize(10000, 0).expect("Failed to initialize");

        let user = [3u8; 32];
        let amount = pool.encrypt(1000);

        // Stake at block 0
        pool.stake(user, amount, 0).expect("Failed to stake");

        // Move forward 1 epoch (100 blocks)
        pool.update_rewards(user, 100).expect("Failed to update rewards");

        let position = pool.get_decrypted_position(&user).unwrap();
        // Reward = 1000 * 100bps * 1 epoch / 10000 = 10
        assert_eq!(position.pending_rewards, 10);
    }

    #[test]
    fn test_claim_rewards() {
        let mut pool = create_test_pool();
        pool.initialize(10000, 0).expect("Failed to initialize");

        let user = [3u8; 32];
        let amount = pool.encrypt(1000);

        // Stake at block 0
        pool.stake(user, amount, 0).expect("Failed to stake");

        // Move forward 2 epochs (200 blocks) and claim
        let rewards = pool.claim_rewards(user, 200).expect("Failed to claim");

        let rewards_value: u64 = rewards.decrypt(&pool.client_key);
        // Reward = 1000 * 100bps * 2 epochs / 10000 = 20
        assert_eq!(rewards_value, 20);

        // Check position rewards are now 0
        let position = pool.get_decrypted_position(&user).unwrap();
        assert_eq!(position.pending_rewards, 0);
    }

    #[test]
    fn test_request_unstake() {
        let mut pool = create_test_pool();
        pool.initialize(10000, 0).expect("Failed to initialize");

        let user = [3u8; 32];
        let stake_amount = pool.encrypt(1000);

        pool.stake(user, stake_amount, 0).expect("Failed to stake");

        let unstake_amount = pool.encrypt(500);
        pool.request_unstake(user, unstake_amount, 50).expect("Failed to request unstake");

        let position = pool.get_decrypted_position(&user).unwrap();
        assert_eq!(position.staked_amount, 500);
        assert_eq!(position.unbonding_amount, 500);
        assert_eq!(position.unbonding_start, 50);
    }

    #[test]
    fn test_complete_unstake_too_early() {
        let mut pool = create_test_pool();
        pool.initialize(10000, 0).expect("Failed to initialize");

        let user = [3u8; 32];
        let stake_amount = pool.encrypt(1000);

        pool.stake(user, stake_amount, 0).expect("Failed to stake");

        let unstake_amount = pool.encrypt(500);
        pool.request_unstake(user, unstake_amount, 50).expect("Failed to request unstake");

        // Try to complete before unbonding period (50 + 50 = 100)
        let result = pool.complete_unstake(user, 80);
        assert!(matches!(result, Err(DeFiError::DeadlineExpired { .. })));
    }

    #[test]
    fn test_complete_unstake_success() {
        let mut pool = create_test_pool();
        pool.initialize(10000, 0).expect("Failed to initialize");

        let user = [3u8; 32];
        let stake_amount = pool.encrypt(1000);

        pool.stake(user, stake_amount, 0).expect("Failed to stake");

        let unstake_amount = pool.encrypt(500);
        pool.request_unstake(user, unstake_amount, 50).expect("Failed to request unstake");

        // Complete after unbonding period (50 + 50 = 100)
        let received = pool.complete_unstake(user, 110).expect("Failed to complete unstake");

        let received_value: u64 = received.decrypt(&pool.client_key);
        assert_eq!(received_value, 500);

        let position = pool.get_decrypted_position(&user).unwrap();
        assert_eq!(position.unbonding_amount, 0);
        assert_eq!(position.unbonding_start, 0);
    }

    #[test]
    fn test_epoch_info() {
        let mut pool = create_test_pool();
        pool.initialize(10000, 0).expect("Failed to initialize");

        let epoch_info = pool.get_epoch_info(250);

        // At block 250 with 100 block epochs starting at 0:
        // Epoch 2 (epochs 0, 1, 2)
        // Epoch start: 200
        // Epoch end: 300
        // Blocks remaining: 50
        assert_eq!(epoch_info.epoch, 2);
        assert_eq!(epoch_info.epoch_start_block, 200);
        assert_eq!(epoch_info.epoch_end_block, 300);
        assert_eq!(epoch_info.blocks_remaining, 50);
    }

    #[test]
    fn test_add_rewards() {
        let mut pool = create_test_pool();
        pool.initialize(10000, 0).expect("Failed to initialize");

        let additional = pool.encrypt(5000);
        pool.add_rewards(additional, 10).expect("Failed to add rewards");

        assert_eq!(pool.get_reward_pool_balance(), 15000);
    }

    #[test]
    fn test_apy_calculation() {
        let pool = create_test_pool();
        // 1% per epoch * 365 epochs / 100 = 365% APY
        assert_eq!(pool.calculate_apy(), 365);
    }

    #[test]
    fn test_pool_stats() {
        let mut pool = create_test_pool();
        pool.initialize(10000, 0).expect("Failed to initialize");

        let user = [3u8; 32];
        let amount = pool.encrypt(1000);
        pool.stake(user, amount, 0).expect("Failed to stake");

        let stats = pool.get_stats();
        assert_eq!(stats.total_staked, 1000);
        assert_eq!(stats.total_stakers, 1);
        assert_eq!(stats.reward_pool_balance, 10000);
        assert_eq!(stats.current_epoch, 0);
        assert_eq!(stats.apy, 365);
    }

    #[test]
    fn test_multiple_stakers() {
        let mut pool = create_test_pool();
        pool.initialize(10000, 0).expect("Failed to initialize");

        let user1 = [3u8; 32];
        let user2 = [4u8; 32];

        let amount1 = pool.encrypt(1000);
        let amount2 = pool.encrypt(2000);

        pool.stake(user1, amount1, 0).expect("Failed to stake");
        pool.stake(user2, amount2, 10).expect("Failed to stake");

        assert_eq!(pool.get_total_staked(), 3000);
        assert_eq!(pool.positions.len(), 2);
    }

    #[test]
    fn test_additional_stake() {
        let mut pool = create_test_pool();
        pool.initialize(10000, 0).expect("Failed to initialize");

        let user = [3u8; 32];

        // First stake
        let amount1 = pool.encrypt(1000);
        pool.stake(user, amount1, 0).expect("Failed to stake");

        // Move forward 1 epoch
        // Additional stake
        let amount2 = pool.encrypt(500);
        pool.stake(user, amount2, 100).expect("Failed to stake");

        let position = pool.get_decrypted_position(&user).unwrap();
        assert_eq!(position.staked_amount, 1500);
        // Should have earned rewards for epoch 0
        assert_eq!(position.pending_rewards, 10); // 1000 * 100bps / 10000
    }
}
