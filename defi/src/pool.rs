//! Liquidity Pool Management
//!
//! Manages pool state with encrypted reserves using FHE.

use crate::errors::{DeFiError, DeFiResult};
use serde::{Deserialize, Serialize};
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ClientKey, ConfigBuilder, FheUint64, ServerKey};

/// Pool configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    /// Token A identifier (32 bytes)
    pub token_a: [u8; 32],
    /// Token B identifier (32 bytes)
    pub token_b: [u8; 32],
    /// Fee in basis points (e.g., 30 = 0.3%)
    pub fee_bps: u16,
    /// Minimum liquidity to prevent manipulation
    pub minimum_liquidity: u64,
    /// Maximum price impact allowed (basis points)
    pub max_price_impact_bps: u16,
    /// Pool administrator address
    pub admin: [u8; 32],
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            token_a: [0u8; 32],
            token_b: [0u8; 32],
            fee_bps: 30, // 0.3% fee like Uniswap
            minimum_liquidity: 1000,
            max_price_impact_bps: 100, // 1% max price impact
            admin: [0u8; 32],
        }
    }
}

impl PoolConfig {
    /// Create a new pool configuration
    pub fn new(token_a: [u8; 32], token_b: [u8; 32]) -> Self {
        Self {
            token_a,
            token_b,
            ..Default::default()
        }
    }

    /// Set the fee in basis points
    pub fn with_fee(mut self, fee_bps: u16) -> Self {
        self.fee_bps = fee_bps;
        self
    }

    /// Set the minimum liquidity
    pub fn with_minimum_liquidity(mut self, min_liq: u64) -> Self {
        self.minimum_liquidity = min_liq;
        self
    }

    /// Calculate fee amount from input
    pub fn calculate_fee(&self, amount: u64) -> u64 {
        (amount as u128 * self.fee_bps as u128 / 10_000) as u64
    }

    /// Calculate amount after fee deduction
    pub fn amount_after_fee(&self, amount: u64) -> u64 {
        amount.saturating_sub(self.calculate_fee(amount))
    }
}

/// Encrypted pool state - reserves are hidden using FHE
#[derive(Clone)]
pub struct PoolState {
    /// Encrypted reserve of token A
    pub reserve_a: FheUint64,
    /// Encrypted reserve of token B
    pub reserve_b: FheUint64,
    /// Encrypted total LP token supply
    pub total_lp_supply: FheUint64,
    /// Encrypted accumulated fees for token A
    pub accumulated_fees_a: FheUint64,
    /// Encrypted accumulated fees for token B
    pub accumulated_fees_b: FheUint64,
    /// Pool is active
    pub is_active: bool,
    /// Creation block height
    pub created_at_block: u64,
    /// Last update block height
    pub last_update_block: u64,
}

impl PoolState {
    /// Create new pool state with initial reserves
    pub fn new(
        reserve_a: FheUint64,
        reserve_b: FheUint64,
        initial_lp: FheUint64,
        block_height: u64,
    ) -> Self {
        // Create zero values for fees - clone the key since encrypt needs owned value
        let init_key = get_client_key_for_init().clone();
        let zero = FheUint64::encrypt(0u64, &init_key);

        Self {
            reserve_a,
            reserve_b,
            total_lp_supply: initial_lp,
            accumulated_fees_a: zero.clone(),
            accumulated_fees_b: zero,
            is_active: true,
            created_at_block: block_height,
            last_update_block: block_height,
        }
    }

    /// Create empty pool state (for initialization)
    pub fn empty(client_key: &ClientKey, block_height: u64) -> Self {
        let zero = FheUint64::encrypt(0u64, client_key);

        Self {
            reserve_a: zero.clone(),
            reserve_b: zero.clone(),
            total_lp_supply: zero.clone(),
            accumulated_fees_a: zero.clone(),
            accumulated_fees_b: zero,
            is_active: false,
            created_at_block: block_height,
            last_update_block: block_height,
        }
    }

    /// Check if pool has sufficient liquidity (using FHE comparison)
    pub fn has_liquidity(&self, minimum: &FheUint64) -> bool {
        // Returns true if reserve_a >= minimum
        self.reserve_a.ge(minimum).decrypt(&get_client_key_for_init())
    }

    /// Update the last update block
    pub fn touch(&mut self, block_height: u64) {
        self.last_update_block = block_height;
    }

    /// Pause the pool
    pub fn pause(&mut self) {
        self.is_active = false;
    }

    /// Unpause the pool
    pub fn unpause(&mut self) {
        self.is_active = true;
    }
}

/// Liquidity Pool - combines config and state
pub struct LiquidityPool {
    /// Pool identifier (hash of token pair)
    pub id: [u8; 32],
    /// Pool configuration
    pub config: PoolConfig,
    /// Encrypted pool state
    pub state: PoolState,
    /// FHE client key for operations
    client_key: ClientKey,
    /// FHE server key for computations
    server_key: ServerKey,
}

impl LiquidityPool {
    /// Create a new liquidity pool
    pub fn new(config: PoolConfig) -> DeFiResult<Self> {
        // Generate FHE keys
        let fhe_config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(fhe_config);

        // Set server key for computations
        set_server_key(server_key.clone());

        // Create pool ID from token pair
        let mut id_input = Vec::with_capacity(64);
        id_input.extend_from_slice(&config.token_a);
        id_input.extend_from_slice(&config.token_b);
        let id: [u8; 32] = blake3::hash(&id_input).into();

        // Create empty state
        let state = PoolState::empty(&client_key, 0);

        Ok(Self {
            id,
            config,
            state,
            client_key,
            server_key,
        })
    }

    /// Initialize pool with existing FHE keys
    pub fn with_keys(
        config: PoolConfig,
        client_key: ClientKey,
        server_key: ServerKey,
    ) -> DeFiResult<Self> {
        // Set server key for computations
        set_server_key(server_key.clone());

        // Create pool ID from token pair
        let mut id_input = Vec::with_capacity(64);
        id_input.extend_from_slice(&config.token_a);
        id_input.extend_from_slice(&config.token_b);
        let id: [u8; 32] = blake3::hash(&id_input).into();

        // Create empty state
        let state = PoolState::empty(&client_key, 0);

        Ok(Self {
            id,
            config,
            state,
            client_key,
            server_key,
        })
    }

    /// Get pool ID
    pub fn id(&self) -> [u8; 32] {
        self.id
    }

    /// Check if pool is active
    pub fn is_active(&self) -> bool {
        self.state.is_active
    }

    /// Encrypt a value using pool's client key
    pub fn encrypt(&self, value: u64) -> FheUint64 {
        FheUint64::encrypt(value, &self.client_key)
    }

    /// Decrypt a value using pool's client key
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

    /// Initialize the pool with initial liquidity
    pub fn initialize(
        &mut self,
        amount_a: u64,
        amount_b: u64,
        block_height: u64,
    ) -> DeFiResult<u64> {
        if self.state.is_active {
            return Err(DeFiError::PoolAlreadyExists(hex::encode(self.id)));
        }

        if amount_a < self.config.minimum_liquidity || amount_b < self.config.minimum_liquidity {
            return Err(DeFiError::MinimumLiquidityNotMet {
                required: self.config.minimum_liquidity,
                actual: amount_a.min(amount_b),
            });
        }

        // Calculate initial LP tokens using geometric mean
        // sqrt(amount_a * amount_b) to prevent manipulation
        let initial_lp = integer_sqrt(amount_a as u128 * amount_b as u128) as u64;

        // Encrypt reserves
        let reserve_a = self.encrypt(amount_a);
        let reserve_b = self.encrypt(amount_b);
        let total_lp = self.encrypt(initial_lp);

        // Update state
        self.state = PoolState::new(reserve_a, reserve_b, total_lp, block_height);

        Ok(initial_lp)
    }

    /// Get decrypted reserve A (for testing/admin purposes)
    pub fn get_reserve_a(&self) -> u64 {
        self.decrypt(&self.state.reserve_a)
    }

    /// Get decrypted reserve B (for testing/admin purposes)
    pub fn get_reserve_b(&self) -> u64 {
        self.decrypt(&self.state.reserve_b)
    }

    /// Get decrypted total LP supply (for testing/admin purposes)
    pub fn get_total_lp_supply(&self) -> u64 {
        self.decrypt(&self.state.total_lp_supply)
    }

    /// Compute constant product k = reserve_a * reserve_b (encrypted)
    pub fn compute_k(&self) -> FheUint64 {
        // Note: This may overflow for large reserves
        // In production, use FheUint128 or handle overflow
        &self.state.reserve_a * &self.state.reserve_b
    }

    /// Update reserves after a swap (called internally)
    pub fn update_reserves(
        &mut self,
        new_reserve_a: FheUint64,
        new_reserve_b: FheUint64,
        block_height: u64,
    ) {
        self.state.reserve_a = new_reserve_a;
        self.state.reserve_b = new_reserve_b;
        self.state.last_update_block = block_height;
    }

    /// Add to LP supply
    pub fn add_lp_supply(&mut self, amount: &FheUint64) {
        self.state.total_lp_supply = &self.state.total_lp_supply + amount;
    }

    /// Subtract from LP supply
    pub fn sub_lp_supply(&mut self, amount: &FheUint64) {
        self.state.total_lp_supply = &self.state.total_lp_supply - amount;
    }

    /// Add to reserve A
    pub fn add_reserve_a(&mut self, amount: &FheUint64) {
        self.state.reserve_a = &self.state.reserve_a + amount;
    }

    /// Add to reserve B
    pub fn add_reserve_b(&mut self, amount: &FheUint64) {
        self.state.reserve_b = &self.state.reserve_b + amount;
    }

    /// Subtract from reserve A
    pub fn sub_reserve_a(&mut self, amount: &FheUint64) {
        self.state.reserve_a = &self.state.reserve_a - amount;
    }

    /// Subtract from reserve B
    pub fn sub_reserve_b(&mut self, amount: &FheUint64) {
        self.state.reserve_b = &self.state.reserve_b - amount;
    }
}

/// Integer square root using Newton's method
fn integer_sqrt(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

// Global client key for initialization (set once)
static mut INIT_CLIENT_KEY: Option<ClientKey> = None;

/// Get client key for initialization
fn get_client_key_for_init() -> &'static ClientKey {
    unsafe {
        INIT_CLIENT_KEY.as_ref().expect("Client key not initialized")
    }
}

/// Set global client key for initialization
pub fn set_init_client_key(key: ClientKey) {
    unsafe {
        INIT_CLIENT_KEY = Some(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_default() {
        let config = PoolConfig::default();
        assert_eq!(config.fee_bps, 30);
        assert_eq!(config.minimum_liquidity, 1000);
    }

    #[test]
    fn test_pool_config_fee_calculation() {
        let config = PoolConfig::default().with_fee(30); // 0.3%
        assert_eq!(config.calculate_fee(10000), 30);
        assert_eq!(config.amount_after_fee(10000), 9970);
    }

    #[test]
    fn test_integer_sqrt() {
        assert_eq!(integer_sqrt(0), 0);
        assert_eq!(integer_sqrt(1), 1);
        assert_eq!(integer_sqrt(4), 2);
        assert_eq!(integer_sqrt(9), 3);
        assert_eq!(integer_sqrt(10), 3); // floor
        assert_eq!(integer_sqrt(100), 10);
        assert_eq!(integer_sqrt(1000000), 1000);
    }

    #[test]
    fn test_pool_creation() {
        let token_a = [1u8; 32];
        let token_b = [2u8; 32];
        let config = PoolConfig::new(token_a, token_b);

        let pool = LiquidityPool::new(config).expect("Failed to create pool");

        assert!(!pool.is_active());
        assert_eq!(pool.config.token_a, token_a);
        assert_eq!(pool.config.token_b, token_b);
    }

    #[test]
    fn test_pool_initialization() {
        let token_a = [1u8; 32];
        let token_b = [2u8; 32];
        let config = PoolConfig::new(token_a, token_b).with_minimum_liquidity(100);

        let mut pool = LiquidityPool::new(config).expect("Failed to create pool");

        // Initialize with 10000 of each token
        let lp_tokens = pool.initialize(10000, 10000, 1).expect("Failed to initialize");

        assert!(pool.is_active());
        assert_eq!(lp_tokens, 10000); // sqrt(10000 * 10000) = 10000
        assert_eq!(pool.get_reserve_a(), 10000);
        assert_eq!(pool.get_reserve_b(), 10000);
        assert_eq!(pool.get_total_lp_supply(), 10000);
    }

    #[test]
    fn test_pool_minimum_liquidity() {
        let config = PoolConfig::default().with_minimum_liquidity(1000);
        let mut pool = LiquidityPool::new(config).expect("Failed to create pool");

        // Should fail with insufficient liquidity
        let result = pool.initialize(100, 100, 1);
        assert!(matches!(result, Err(DeFiError::MinimumLiquidityNotMet { .. })));
    }

    #[test]
    fn test_pool_id_deterministic() {
        let token_a = [1u8; 32];
        let token_b = [2u8; 32];

        let pool1 = LiquidityPool::new(PoolConfig::new(token_a, token_b)).unwrap();
        let pool2 = LiquidityPool::new(PoolConfig::new(token_a, token_b)).unwrap();

        assert_eq!(pool1.id(), pool2.id());
    }
}
