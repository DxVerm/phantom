//! Constant Product AMM with FHE-encrypted operations
//!
//! Implements the x * y = k invariant where all values are encrypted.
//! This enables private trading where swap amounts are hidden.

use crate::errors::{DeFiError, DeFiResult};
use crate::pool::{LiquidityPool, PoolConfig, PoolState};
use crate::swap::{SwapDirection, SwapExecution, SwapQuote, SwapRequest, SwapResult};
use tfhe::prelude::*;
use tfhe::{FheUint64, ClientKey, ServerKey, set_server_key};
use std::collections::HashMap;

/// Trait for AMM implementations
pub trait PrivateAMM {
    /// Get encrypted reserves
    fn get_reserves(&self, pool_id: &[u8; 32]) -> DeFiResult<(FheUint64, FheUint64)>;

    /// Execute a private swap
    fn swap(
        &mut self,
        pool_id: &[u8; 32],
        direction: SwapDirection,
        amount_in: FheUint64,
        min_amount_out: FheUint64,
        deadline: u64,
        current_block: u64,
    ) -> DeFiResult<SwapResult>;

    /// Add liquidity (amounts encrypted)
    fn add_liquidity(
        &mut self,
        pool_id: &[u8; 32],
        amount_a: FheUint64,
        amount_b: FheUint64,
        min_lp_tokens: FheUint64,
    ) -> DeFiResult<FheUint64>;

    /// Remove liquidity (amounts encrypted)
    fn remove_liquidity(
        &mut self,
        pool_id: &[u8; 32],
        lp_tokens: FheUint64,
        min_amount_a: FheUint64,
        min_amount_b: FheUint64,
    ) -> DeFiResult<(FheUint64, FheUint64)>;
}

/// Constant Product AMM (x * y = k)
pub struct ConstantProductAMM {
    /// Pool registry
    pools: HashMap<[u8; 32], LiquidityPool>,
    /// FHE client key
    client_key: ClientKey,
    /// FHE server key
    server_key: ServerKey,
    /// Swap execution engine
    swap_engine: SwapExecution,
    /// Protocol fee recipient (optional)
    fee_recipient: Option<[u8; 32]>,
    /// Protocol fee in basis points (e.g., 5 = 0.05%)
    protocol_fee_bps: u16,
}

impl ConstantProductAMM {
    /// Create a new AMM instance
    pub fn new(client_key: ClientKey, server_key: ServerKey) -> Self {
        let swap_engine = SwapExecution::new(client_key.clone(), server_key.clone());
        Self {
            pools: HashMap::new(),
            client_key,
            server_key,
            swap_engine,
            fee_recipient: None,
            protocol_fee_bps: 0,
        }
    }

    /// Set protocol fee configuration
    pub fn set_protocol_fee(&mut self, recipient: [u8; 32], fee_bps: u16) -> DeFiResult<()> {
        if fee_bps > 100 {
            return Err(DeFiError::FeeTooHigh {
                requested: fee_bps,
                maximum: 100
            });
        }
        self.fee_recipient = Some(recipient);
        self.protocol_fee_bps = fee_bps;
        Ok(())
    }

    /// Create a new liquidity pool
    pub fn create_pool(&mut self, config: PoolConfig) -> DeFiResult<[u8; 32]> {
        // Generate pool ID from token pair
        let pool_id = self.compute_pool_id(&config.token_a, &config.token_b);

        if self.pools.contains_key(&pool_id) {
            return Err(DeFiError::PoolAlreadyExists(hex::encode(pool_id)));
        }

        let pool = LiquidityPool::with_keys(
            config,
            self.client_key.clone(),
            self.server_key.clone(),
        )?;

        self.pools.insert(pool_id, pool);
        Ok(pool_id)
    }

    /// Compute deterministic pool ID from token pair
    fn compute_pool_id(&self, token_a: &[u8; 32], token_b: &[u8; 32]) -> [u8; 32] {
        // Sort tokens to ensure consistent pool ID regardless of order
        let (first, second) = if token_a < token_b {
            (token_a, token_b)
        } else {
            (token_b, token_a)
        };

        let mut hasher = blake3::Hasher::new();
        hasher.update(first);
        hasher.update(second);
        hasher.update(b"phantom-amm-pool-v1");
        *hasher.finalize().as_bytes()
    }

    /// Get pool by ID
    pub fn get_pool(&self, pool_id: &[u8; 32]) -> DeFiResult<&LiquidityPool> {
        self.pools.get(pool_id).ok_or_else(|| DeFiError::PoolNotFound(hex::encode(pool_id)))
    }

    /// Get mutable pool by ID
    pub fn get_pool_mut(&mut self, pool_id: &[u8; 32]) -> DeFiResult<&mut LiquidityPool> {
        self.pools.get_mut(pool_id).ok_or_else(|| DeFiError::PoolNotFound(hex::encode(pool_id)))
    }

    /// Initialize a pool with initial liquidity
    pub fn initialize_pool(
        &mut self,
        pool_id: &[u8; 32],
        amount_a: u64,
        amount_b: u64,
        block_height: u64,
    ) -> DeFiResult<u64> {
        let pool = self.get_pool_mut(pool_id)?;
        pool.initialize(amount_a, amount_b, block_height)
    }

    /// Get a swap quote (plaintext for UI)
    pub fn get_swap_quote(
        &self,
        pool_id: &[u8; 32],
        direction: SwapDirection,
        amount_in: u64,
    ) -> DeFiResult<SwapQuote> {
        let pool = self.get_pool(pool_id)?;

        // Decrypt reserves for quote calculation
        let reserve_a: u64 = pool.state.reserve_a.decrypt(&self.client_key);
        let reserve_b: u64 = pool.state.reserve_b.decrypt(&self.client_key);

        let (reserve_in, reserve_out) = match direction {
            SwapDirection::AtoB => (reserve_a, reserve_b),
            SwapDirection::BtoA => (reserve_b, reserve_a),
        };

        self.swap_engine.get_quote(reserve_in, reserve_out, amount_in, pool.config.fee_bps)
    }

    /// Calculate optimal liquidity amounts to add
    pub fn calculate_optimal_liquidity(
        &self,
        pool_id: &[u8; 32],
        amount_a_desired: u64,
        amount_b_desired: u64,
    ) -> DeFiResult<(u64, u64)> {
        let pool = self.get_pool(pool_id)?;

        let reserve_a: u64 = pool.state.reserve_a.decrypt(&self.client_key);
        let reserve_b: u64 = pool.state.reserve_b.decrypt(&self.client_key);

        if reserve_a == 0 && reserve_b == 0 {
            // First liquidity provider
            return Ok((amount_a_desired, amount_b_desired));
        }

        // Calculate optimal amount B given amount A
        let amount_b_optimal = (amount_a_desired as u128 * reserve_b as u128 / reserve_a as u128) as u64;

        if amount_b_optimal <= amount_b_desired {
            Ok((amount_a_desired, amount_b_optimal))
        } else {
            // Calculate optimal amount A given amount B
            let amount_a_optimal = (amount_b_desired as u128 * reserve_a as u128 / reserve_b as u128) as u64;
            Ok((amount_a_optimal, amount_b_desired))
        }
    }

    /// Get all pool IDs
    pub fn list_pools(&self) -> Vec<[u8; 32]> {
        self.pools.keys().copied().collect()
    }

    /// Check if pool exists
    pub fn pool_exists(&self, pool_id: &[u8; 32]) -> bool {
        self.pools.contains_key(pool_id)
    }

    /// Get pool statistics (decrypted for display)
    pub fn get_pool_stats(&self, pool_id: &[u8; 32]) -> DeFiResult<PoolStats> {
        let pool = self.get_pool(pool_id)?;

        let reserve_a: u64 = pool.state.reserve_a.decrypt(&self.client_key);
        let reserve_b: u64 = pool.state.reserve_b.decrypt(&self.client_key);
        let total_lp: u64 = pool.state.total_lp_supply.decrypt(&self.client_key);

        let k = reserve_a as u128 * reserve_b as u128;
        let price_a_in_b = if reserve_a > 0 {
            (reserve_b as f64) / (reserve_a as f64)
        } else {
            0.0
        };

        Ok(PoolStats {
            pool_id: *pool_id,
            reserve_a,
            reserve_b,
            total_lp_supply: total_lp,
            k_invariant: k,
            price_a_in_b,
            fee_bps: pool.config.fee_bps,
        })
    }
}

impl PrivateAMM for ConstantProductAMM {
    fn get_reserves(&self, pool_id: &[u8; 32]) -> DeFiResult<(FheUint64, FheUint64)> {
        let pool = self.get_pool(pool_id)?;
        Ok((pool.state.reserve_a.clone(), pool.state.reserve_b.clone()))
    }

    fn swap(
        &mut self,
        pool_id: &[u8; 32],
        direction: SwapDirection,
        amount_in: FheUint64,
        min_amount_out: FheUint64,
        deadline: u64,
        current_block: u64,
    ) -> DeFiResult<SwapResult> {
        // Take ownership of the pool temporarily to avoid borrow conflict
        let mut pool = self.pools.remove(pool_id)
            .ok_or_else(|| DeFiError::PoolNotFound(hex::encode(pool_id)))?;

        let request = SwapRequest {
            pool_id: *pool_id,
            direction,
            amount_in,
            min_amount_out,
            deadline,
        };

        // Now we can use self.swap_engine without borrow conflict
        let result = self.swap_engine.execute_swap_request(&mut pool, &request, current_block);

        // Put the pool back
        self.pools.insert(*pool_id, pool);

        result
    }

    fn add_liquidity(
        &mut self,
        pool_id: &[u8; 32],
        amount_a: FheUint64,
        amount_b: FheUint64,
        min_lp_tokens: FheUint64,
    ) -> DeFiResult<FheUint64> {
        set_server_key(self.server_key.clone());

        let pool = self.get_pool_mut(pool_id)?;

        // Calculate LP tokens to mint
        // If first deposit: sqrt(amount_a * amount_b)
        // Otherwise: min(amount_a * total_lp / reserve_a, amount_b * total_lp / reserve_b)

        let total_lp: u64 = pool.decrypt(&pool.state.total_lp_supply.clone());

        let lp_tokens = if total_lp == 0 {
            // First liquidity provider
            let a: u64 = amount_a.decrypt(pool.client_key());
            let b: u64 = amount_b.decrypt(pool.client_key());
            let initial = integer_sqrt(a as u128 * b as u128) as u64;
            pool.encrypt(initial)
        } else {
            // Calculate based on existing ratio
            let lp_from_a = &amount_a * &pool.state.total_lp_supply / &pool.state.reserve_a;
            let lp_from_b = &amount_b * &pool.state.total_lp_supply / &pool.state.reserve_b;

            // Take minimum
            let a_val: u64 = lp_from_a.decrypt(pool.client_key());
            let b_val: u64 = lp_from_b.decrypt(pool.client_key());
            pool.encrypt(a_val.min(b_val))
        };

        // Check minimum LP tokens (slippage protection)
        let lp_decrypted: u64 = lp_tokens.decrypt(pool.client_key());
        let min_decrypted: u64 = min_lp_tokens.decrypt(pool.client_key());
        if lp_decrypted < min_decrypted {
            return Err(DeFiError::SlippageExceeded {
                expected: min_decrypted,
                actual: lp_decrypted,
            });
        }

        // Update reserves
        pool.state.reserve_a = &pool.state.reserve_a + &amount_a;
        pool.state.reserve_b = &pool.state.reserve_b + &amount_b;
        pool.state.total_lp_supply = &pool.state.total_lp_supply + &lp_tokens;

        Ok(lp_tokens)
    }

    fn remove_liquidity(
        &mut self,
        pool_id: &[u8; 32],
        lp_tokens: FheUint64,
        min_amount_a: FheUint64,
        min_amount_b: FheUint64,
    ) -> DeFiResult<(FheUint64, FheUint64)> {
        set_server_key(self.server_key.clone());

        let pool = self.get_pool_mut(pool_id)?;

        // Calculate amounts to return
        // amount_a = reserve_a * lp_tokens / total_lp
        // amount_b = reserve_b * lp_tokens / total_lp
        let amount_a = &pool.state.reserve_a * &lp_tokens / &pool.state.total_lp_supply;
        let amount_b = &pool.state.reserve_b * &lp_tokens / &pool.state.total_lp_supply;

        // Check slippage
        let a_dec: u64 = amount_a.decrypt(pool.client_key());
        let b_dec: u64 = amount_b.decrypt(pool.client_key());
        let min_a: u64 = min_amount_a.decrypt(pool.client_key());
        let min_b: u64 = min_amount_b.decrypt(pool.client_key());

        if a_dec < min_a {
            return Err(DeFiError::SlippageExceeded {
                expected: min_a,
                actual: a_dec,
            });
        }
        if b_dec < min_b {
            return Err(DeFiError::SlippageExceeded {
                expected: min_b,
                actual: b_dec,
            });
        }

        // Update reserves
        pool.state.reserve_a = &pool.state.reserve_a - &amount_a;
        pool.state.reserve_b = &pool.state.reserve_b - &amount_b;
        pool.state.total_lp_supply = &pool.state.total_lp_supply - &lp_tokens;

        Ok((amount_a, amount_b))
    }
}

/// Integer square root using binary search
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

/// Pool statistics (decrypted for display)
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub pool_id: [u8; 32],
    pub reserve_a: u64,
    pub reserve_b: u64,
    pub total_lp_supply: u64,
    pub k_invariant: u128,
    pub price_a_in_b: f64,
    pub fee_bps: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::{ConfigBuilder, generate_keys};

    fn setup_fhe() -> (ClientKey, ServerKey) {
        let config = ConfigBuilder::default().build();
        generate_keys(config)
    }

    fn create_test_pool_config() -> PoolConfig {
        PoolConfig {
            token_a: [1u8; 32],
            token_b: [2u8; 32],
            fee_bps: 30,
            minimum_liquidity: 1000,
            max_price_impact_bps: 100,
            admin: [0u8; 32],
        }
    }

    #[test]
    fn test_create_amm() {
        let (client_key, server_key) = setup_fhe();
        let amm = ConstantProductAMM::new(client_key, server_key);
        assert!(amm.list_pools().is_empty());
    }

    #[test]
    fn test_create_pool() {
        let (client_key, server_key) = setup_fhe();
        let mut amm = ConstantProductAMM::new(client_key, server_key);

        let config = create_test_pool_config();
        let pool_id = amm.create_pool(config).unwrap();

        assert!(amm.pool_exists(&pool_id));
        assert_eq!(amm.list_pools().len(), 1);
    }

    #[test]
    fn test_pool_id_deterministic() {
        let (client_key, server_key) = setup_fhe();
        let amm = ConstantProductAMM::new(client_key, server_key);

        let token_a = [1u8; 32];
        let token_b = [2u8; 32];

        let id1 = amm.compute_pool_id(&token_a, &token_b);
        let id2 = amm.compute_pool_id(&token_b, &token_a);

        // Should be same regardless of order
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_initialize_and_swap() {
        let (client_key, server_key) = setup_fhe();
        set_server_key(server_key.clone());

        let mut amm = ConstantProductAMM::new(client_key.clone(), server_key);

        let config = create_test_pool_config();
        let pool_id = amm.create_pool(config).unwrap();

        // Initialize with 10000:20000 ratio
        let lp = amm.initialize_pool(&pool_id, 10000, 20000, 1).unwrap();
        assert!(lp > 0);

        // Get quote for swapping 100 A for B
        let quote = amm.get_swap_quote(&pool_id, SwapDirection::AtoB, 100).unwrap();
        assert!(quote.amount_out > 0);

        // Execute encrypted swap
        let amount_in = FheUint64::encrypt(100u64, &client_key);
        let min_out = FheUint64::encrypt(1u64, &client_key);

        let result = amm.swap(
            &pool_id,
            SwapDirection::AtoB,
            amount_in,
            min_out,
            100,
            1,
        ).unwrap();

        let decrypted = amm.swap_engine.decrypt_result(&result);
        assert!(decrypted.amount_out > 0);
    }

    #[test]
    fn test_add_liquidity() {
        let (client_key, server_key) = setup_fhe();
        set_server_key(server_key.clone());

        let mut amm = ConstantProductAMM::new(client_key.clone(), server_key);

        let config = create_test_pool_config();
        let pool_id = amm.create_pool(config).unwrap();
        amm.initialize_pool(&pool_id, 10000, 20000, 1).unwrap();

        // Add more liquidity
        let amount_a = FheUint64::encrypt(1000u64, &client_key);
        let amount_b = FheUint64::encrypt(2000u64, &client_key);
        let min_lp = FheUint64::encrypt(1u64, &client_key);

        let lp_tokens = amm.add_liquidity(&pool_id, amount_a, amount_b, min_lp).unwrap();
        let lp_dec: u64 = lp_tokens.decrypt(&client_key);
        assert!(lp_dec > 0);
    }

    #[test]
    fn test_remove_liquidity() {
        let (client_key, server_key) = setup_fhe();
        set_server_key(server_key.clone());

        let mut amm = ConstantProductAMM::new(client_key.clone(), server_key);

        let config = create_test_pool_config();
        let pool_id = amm.create_pool(config).unwrap();
        let initial_lp = amm.initialize_pool(&pool_id, 10000, 20000, 1).unwrap();

        // Remove half the liquidity
        let lp_to_remove = FheUint64::encrypt(initial_lp / 2, &client_key);
        let min_a = FheUint64::encrypt(1u64, &client_key);
        let min_b = FheUint64::encrypt(1u64, &client_key);

        let (amount_a, amount_b) = amm.remove_liquidity(
            &pool_id,
            lp_to_remove,
            min_a,
            min_b,
        ).unwrap();

        let a_dec: u64 = amount_a.decrypt(&client_key);
        let b_dec: u64 = amount_b.decrypt(&client_key);

        // Should get roughly half back (minus minimum locked)
        assert!(a_dec > 0);
        assert!(b_dec > 0);
    }

    #[test]
    fn test_pool_stats() {
        let (client_key, server_key) = setup_fhe();
        set_server_key(server_key.clone());

        let mut amm = ConstantProductAMM::new(client_key, server_key);

        let config = create_test_pool_config();
        let pool_id = amm.create_pool(config).unwrap();
        amm.initialize_pool(&pool_id, 10000, 20000, 1).unwrap();

        let stats = amm.get_pool_stats(&pool_id).unwrap();

        assert_eq!(stats.reserve_a, 10000);
        assert_eq!(stats.reserve_b, 20000);
        assert!((stats.price_a_in_b - 2.0).abs() < 0.01);
        assert_eq!(stats.k_invariant, 200_000_000);
    }

    #[test]
    fn test_integer_sqrt() {
        assert_eq!(integer_sqrt(0), 0);
        assert_eq!(integer_sqrt(1), 1);
        assert_eq!(integer_sqrt(4), 2);
        assert_eq!(integer_sqrt(9), 3);
        assert_eq!(integer_sqrt(10), 3);
        assert_eq!(integer_sqrt(100), 10);
        assert_eq!(integer_sqrt(200_000_000), 14142);
    }
}
