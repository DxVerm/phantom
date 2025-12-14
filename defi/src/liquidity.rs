//! LP Token management and liquidity provider tracking
//!
//! Manages LP tokens with encrypted balances and provides
//! privacy-preserving liquidity position tracking.

use crate::errors::{DeFiError, DeFiResult};
use tfhe::prelude::*;
use tfhe::{FheUint64, ClientKey, ServerKey, set_server_key};
use std::collections::HashMap;

/// Unique identifier for an LP token
pub type LPTokenId = [u8; 32];

/// LP Token metadata
#[derive(Clone)]
pub struct LPToken {
    /// Unique token ID (derived from pool)
    pub id: LPTokenId,
    /// Pool this LP token represents
    pub pool_id: [u8; 32],
    /// Token A address
    pub token_a: [u8; 32],
    /// Token B address
    pub token_b: [u8; 32],
    /// Total supply (encrypted)
    pub total_supply: FheUint64,
    /// Decimals (usually 18)
    pub decimals: u8,
}

impl std::fmt::Debug for LPToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LPToken")
            .field("id", &hex::encode(&self.id))
            .field("pool_id", &hex::encode(&self.pool_id))
            .field("token_a", &hex::encode(&self.token_a))
            .field("token_b", &hex::encode(&self.token_b))
            .field("total_supply", &"<encrypted>")
            .field("decimals", &self.decimals)
            .finish()
    }
}

impl LPToken {
    /// Create a new LP token for a pool
    pub fn new(
        pool_id: [u8; 32],
        token_a: [u8; 32],
        token_b: [u8; 32],
        client_key: &ClientKey,
    ) -> Self {
        // Generate LP token ID from pool
        let mut hasher = blake3::Hasher::new();
        hasher.update(&pool_id);
        hasher.update(b"phantom-lp-token-v1");
        let id = *hasher.finalize().as_bytes();

        Self {
            id,
            pool_id,
            token_a,
            token_b,
            total_supply: FheUint64::encrypt(0u64, client_key),
            decimals: 18,
        }
    }

    /// Get token symbol (for display)
    pub fn symbol(&self) -> String {
        format!("PLP-{}", hex::encode(&self.id[..4]))
    }
}

/// A liquidity position held by an address
#[derive(Clone)]
pub struct LiquidityPosition {
    /// Owner address (encrypted or hashed for privacy)
    pub owner: [u8; 32],
    /// Pool ID
    pub pool_id: [u8; 32],
    /// LP token balance (encrypted)
    pub balance: FheUint64,
    /// Block when position was created
    pub created_at: u64,
    /// Last update block
    pub updated_at: u64,
}

impl std::fmt::Debug for LiquidityPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiquidityPosition")
            .field("owner", &hex::encode(&self.owner))
            .field("pool_id", &hex::encode(&self.pool_id))
            .field("balance", &"<encrypted>")
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl LiquidityPosition {
    /// Create a new position
    pub fn new(
        owner: [u8; 32],
        pool_id: [u8; 32],
        initial_balance: FheUint64,
        block_height: u64,
    ) -> Self {
        Self {
            owner,
            pool_id,
            balance: initial_balance,
            created_at: block_height,
            updated_at: block_height,
        }
    }

    /// Add to position
    pub fn add(&mut self, amount: &FheUint64, block_height: u64) {
        self.balance = &self.balance + amount;
        self.updated_at = block_height;
    }

    /// Remove from position
    pub fn remove(&mut self, amount: &FheUint64, block_height: u64) -> DeFiResult<()> {
        self.balance = &self.balance - amount;
        self.updated_at = block_height;
        Ok(())
    }
}

/// Registry for LP tokens and positions
pub struct LiquidityRegistry {
    /// LP tokens by ID
    lp_tokens: HashMap<LPTokenId, LPToken>,
    /// Pool ID to LP token ID mapping
    pool_to_lp: HashMap<[u8; 32], LPTokenId>,
    /// Positions by (pool_id, owner) key
    positions: HashMap<([u8; 32], [u8; 32]), LiquidityPosition>,
    /// FHE keys
    client_key: ClientKey,
    server_key: ServerKey,
}

impl LiquidityRegistry {
    /// Create a new registry
    pub fn new(client_key: ClientKey, server_key: ServerKey) -> Self {
        Self {
            lp_tokens: HashMap::new(),
            pool_to_lp: HashMap::new(),
            positions: HashMap::new(),
            client_key,
            server_key,
        }
    }

    /// Register a new LP token for a pool
    pub fn register_lp_token(
        &mut self,
        pool_id: [u8; 32],
        token_a: [u8; 32],
        token_b: [u8; 32],
    ) -> DeFiResult<LPTokenId> {
        if self.pool_to_lp.contains_key(&pool_id) {
            return Err(DeFiError::PoolAlreadyExists(hex::encode(pool_id)));
        }

        let lp_token = LPToken::new(pool_id, token_a, token_b, &self.client_key);
        let lp_id = lp_token.id;

        self.lp_tokens.insert(lp_id, lp_token);
        self.pool_to_lp.insert(pool_id, lp_id);

        Ok(lp_id)
    }

    /// Get LP token for a pool
    pub fn get_lp_token(&self, pool_id: &[u8; 32]) -> DeFiResult<&LPToken> {
        let lp_id = self.pool_to_lp.get(pool_id)
            .ok_or_else(|| DeFiError::PoolNotFound(hex::encode(pool_id)))?;
        self.lp_tokens.get(lp_id)
            .ok_or_else(|| DeFiError::PoolNotFound(hex::encode(pool_id)))
    }

    /// Mint LP tokens to an address
    pub fn mint(
        &mut self,
        pool_id: [u8; 32],
        to: [u8; 32],
        amount: FheUint64,
        block_height: u64,
    ) -> DeFiResult<()> {
        set_server_key(self.server_key.clone());

        // Update total supply
        let pool_id_hex = hex::encode(pool_id);
        let lp_id = self.pool_to_lp.get(&pool_id)
            .ok_or_else(|| DeFiError::PoolNotFound(pool_id_hex.clone()))?;
        let lp_token = self.lp_tokens.get_mut(lp_id)
            .ok_or_else(|| DeFiError::PoolNotFound(pool_id_hex))?;
        lp_token.total_supply = &lp_token.total_supply + &amount;

        // Update or create position
        let key = (pool_id, to);
        if let Some(position) = self.positions.get_mut(&key) {
            position.add(&amount, block_height);
        } else {
            let position = LiquidityPosition::new(to, pool_id, amount, block_height);
            self.positions.insert(key, position);
        }

        Ok(())
    }

    /// Burn LP tokens from an address
    pub fn burn(
        &mut self,
        pool_id: [u8; 32],
        from: [u8; 32],
        amount: FheUint64,
        block_height: u64,
    ) -> DeFiResult<()> {
        set_server_key(self.server_key.clone());

        // Update total supply
        let lp_id = self.pool_to_lp.get(&pool_id)
            .ok_or_else(|| DeFiError::PoolNotFound(hex::encode(pool_id)))?;
        let lp_token = self.lp_tokens.get_mut(lp_id)
            .ok_or_else(|| DeFiError::PoolNotFound(hex::encode(pool_id)))?;
        lp_token.total_supply = &lp_token.total_supply - &amount;

        // Update position
        let key = (pool_id, from);
        let position = self.positions.get_mut(&key)
            .ok_or(DeFiError::InsufficientLPTokens { required: 0, available: 0 })?;
        position.remove(&amount, block_height)?;

        Ok(())
    }

    /// Transfer LP tokens between addresses (encrypted)
    pub fn transfer(
        &mut self,
        pool_id: [u8; 32],
        from: [u8; 32],
        to: [u8; 32],
        amount: FheUint64,
        block_height: u64,
    ) -> DeFiResult<()> {
        set_server_key(self.server_key.clone());

        // Debit from sender
        let from_key = (pool_id, from);
        let from_position = self.positions.get_mut(&from_key)
            .ok_or(DeFiError::InsufficientLPTokens { required: 0, available: 0 })?;
        from_position.remove(&amount, block_height)?;

        // Credit to receiver
        let to_key = (pool_id, to);
        if let Some(to_position) = self.positions.get_mut(&to_key) {
            to_position.add(&amount, block_height);
        } else {
            let position = LiquidityPosition::new(to, pool_id, amount, block_height);
            self.positions.insert(to_key, position);
        }

        Ok(())
    }

    /// Get position for an address
    pub fn get_position(
        &self,
        pool_id: &[u8; 32],
        owner: &[u8; 32],
    ) -> DeFiResult<&LiquidityPosition> {
        self.positions.get(&(*pool_id, *owner))
            .ok_or(DeFiError::InsufficientLPTokens { required: 0, available: 0 })
    }

    /// Get decrypted balance
    pub fn get_balance_decrypted(
        &self,
        pool_id: &[u8; 32],
        owner: &[u8; 32],
    ) -> DeFiResult<u64> {
        let position = self.get_position(pool_id, owner)?;
        Ok(position.balance.decrypt(&self.client_key))
    }

    /// Get total supply decrypted
    pub fn get_total_supply_decrypted(&self, pool_id: &[u8; 32]) -> DeFiResult<u64> {
        let lp_token = self.get_lp_token(pool_id)?;
        Ok(lp_token.total_supply.decrypt(&self.client_key))
    }

    /// Calculate share of pool for a position
    pub fn calculate_pool_share(
        &self,
        pool_id: &[u8; 32],
        owner: &[u8; 32],
    ) -> DeFiResult<f64> {
        let balance = self.get_balance_decrypted(pool_id, owner)?;
        let total = self.get_total_supply_decrypted(pool_id)?;

        if total == 0 {
            return Ok(0.0);
        }

        Ok(balance as f64 / total as f64)
    }

    /// Get all positions for an owner across all pools
    pub fn get_all_positions(&self, owner: &[u8; 32]) -> Vec<&LiquidityPosition> {
        self.positions.iter()
            .filter(|((_, o), _)| o == owner)
            .map(|(_, pos)| pos)
            .collect()
    }

    /// Calculate value of position given current reserves
    pub fn calculate_position_value(
        &self,
        pool_id: &[u8; 32],
        owner: &[u8; 32],
        reserve_a: u64,
        reserve_b: u64,
    ) -> DeFiResult<(u64, u64)> {
        let share = self.calculate_pool_share(pool_id, owner)?;

        let value_a = (reserve_a as f64 * share) as u64;
        let value_b = (reserve_b as f64 * share) as u64;

        Ok((value_a, value_b))
    }
}

/// Fee distribution for LP holders
pub struct FeeDistributor {
    /// Accumulated fees per pool (token A)
    accumulated_fees_a: HashMap<[u8; 32], FheUint64>,
    /// Accumulated fees per pool (token B)
    accumulated_fees_b: HashMap<[u8; 32], FheUint64>,
    /// Last fee claim block per (pool, owner)
    last_claim: HashMap<([u8; 32], [u8; 32]), u64>,
    /// FHE keys
    client_key: ClientKey,
    server_key: ServerKey,
}

impl FeeDistributor {
    /// Create a new fee distributor
    pub fn new(client_key: ClientKey, server_key: ServerKey) -> Self {
        Self {
            accumulated_fees_a: HashMap::new(),
            accumulated_fees_b: HashMap::new(),
            last_claim: HashMap::new(),
            client_key,
            server_key,
        }
    }

    /// Add fees to pool
    pub fn add_fees(
        &mut self,
        pool_id: [u8; 32],
        fee_a: FheUint64,
        fee_b: FheUint64,
    ) {
        set_server_key(self.server_key.clone());

        if let Some(acc) = self.accumulated_fees_a.get_mut(&pool_id) {
            *acc = &*acc + &fee_a;
        } else {
            self.accumulated_fees_a.insert(pool_id, fee_a);
        }

        if let Some(acc) = self.accumulated_fees_b.get_mut(&pool_id) {
            *acc = &*acc + &fee_b;
        } else {
            self.accumulated_fees_b.insert(pool_id, fee_b);
        }
    }

    /// Calculate claimable fees for a position
    pub fn calculate_claimable(
        &self,
        pool_id: &[u8; 32],
        owner: &[u8; 32],
        registry: &LiquidityRegistry,
    ) -> DeFiResult<(u64, u64)> {
        let share = registry.calculate_pool_share(pool_id, owner)?;

        let total_fees_a: u64 = self.accumulated_fees_a.get(pool_id)
            .map(|f| -> u64 { f.decrypt(&self.client_key) })
            .unwrap_or(0);
        let total_fees_b: u64 = self.accumulated_fees_b.get(pool_id)
            .map(|f| -> u64 { f.decrypt(&self.client_key) })
            .unwrap_or(0);

        let claimable_a = (total_fees_a as f64 * share) as u64;
        let claimable_b = (total_fees_b as f64 * share) as u64;

        Ok((claimable_a, claimable_b))
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
    fn test_create_lp_token() {
        let (client_key, _server_key) = setup_fhe();

        let pool_id = [1u8; 32];
        let token_a = [2u8; 32];
        let token_b = [3u8; 32];

        let lp_token = LPToken::new(pool_id, token_a, token_b, &client_key);

        assert_eq!(lp_token.pool_id, pool_id);
        assert_eq!(lp_token.decimals, 18);
        assert!(lp_token.symbol().starts_with("PLP-"));
    }

    #[test]
    fn test_liquidity_registry() {
        let (client_key, server_key) = setup_fhe();
        set_server_key(server_key.clone());

        let mut registry = LiquidityRegistry::new(client_key.clone(), server_key);

        let pool_id = [1u8; 32];
        let token_a = [2u8; 32];
        let token_b = [3u8; 32];
        let user = [4u8; 32];

        // Register LP token
        let lp_id = registry.register_lp_token(pool_id, token_a, token_b).unwrap();
        assert!(!lp_id.iter().all(|&b| b == 0));

        // Mint LP tokens
        let amount = FheUint64::encrypt(1000u64, &client_key);
        registry.mint(pool_id, user, amount, 1).unwrap();

        // Check balance
        let balance = registry.get_balance_decrypted(&pool_id, &user).unwrap();
        assert_eq!(balance, 1000);

        // Check total supply
        let total = registry.get_total_supply_decrypted(&pool_id).unwrap();
        assert_eq!(total, 1000);
    }

    #[test]
    fn test_mint_and_burn() {
        let (client_key, server_key) = setup_fhe();
        set_server_key(server_key.clone());

        let mut registry = LiquidityRegistry::new(client_key.clone(), server_key);

        let pool_id = [1u8; 32];
        let user = [2u8; 32];

        registry.register_lp_token(pool_id, [3u8; 32], [4u8; 32]).unwrap();

        // Mint
        let mint_amount = FheUint64::encrypt(1000u64, &client_key);
        registry.mint(pool_id, user, mint_amount, 1).unwrap();

        assert_eq!(registry.get_balance_decrypted(&pool_id, &user).unwrap(), 1000);

        // Burn half
        let burn_amount = FheUint64::encrypt(500u64, &client_key);
        registry.burn(pool_id, user, burn_amount, 2).unwrap();

        assert_eq!(registry.get_balance_decrypted(&pool_id, &user).unwrap(), 500);
        assert_eq!(registry.get_total_supply_decrypted(&pool_id).unwrap(), 500);
    }

    #[test]
    fn test_transfer() {
        let (client_key, server_key) = setup_fhe();
        set_server_key(server_key.clone());

        let mut registry = LiquidityRegistry::new(client_key.clone(), server_key);

        let pool_id = [1u8; 32];
        let user_a = [2u8; 32];
        let user_b = [3u8; 32];

        registry.register_lp_token(pool_id, [4u8; 32], [5u8; 32]).unwrap();

        // Mint to user A
        let amount = FheUint64::encrypt(1000u64, &client_key);
        registry.mint(pool_id, user_a, amount, 1).unwrap();

        // Transfer to user B
        let transfer_amount = FheUint64::encrypt(300u64, &client_key);
        registry.transfer(pool_id, user_a, user_b, transfer_amount, 2).unwrap();

        assert_eq!(registry.get_balance_decrypted(&pool_id, &user_a).unwrap(), 700);
        assert_eq!(registry.get_balance_decrypted(&pool_id, &user_b).unwrap(), 300);
    }

    #[test]
    fn test_pool_share_calculation() {
        let (client_key, server_key) = setup_fhe();
        set_server_key(server_key.clone());

        let mut registry = LiquidityRegistry::new(client_key.clone(), server_key);

        let pool_id = [1u8; 32];
        let user_a = [2u8; 32];
        let user_b = [3u8; 32];

        registry.register_lp_token(pool_id, [4u8; 32], [5u8; 32]).unwrap();

        // User A: 750, User B: 250 = 1000 total
        let amount_a = FheUint64::encrypt(750u64, &client_key);
        let amount_b = FheUint64::encrypt(250u64, &client_key);

        registry.mint(pool_id, user_a, amount_a, 1).unwrap();
        registry.mint(pool_id, user_b, amount_b, 1).unwrap();

        let share_a = registry.calculate_pool_share(&pool_id, &user_a).unwrap();
        let share_b = registry.calculate_pool_share(&pool_id, &user_b).unwrap();

        assert!((share_a - 0.75).abs() < 0.01);
        assert!((share_b - 0.25).abs() < 0.01);
    }

    #[test]
    fn test_position_value() {
        let (client_key, server_key) = setup_fhe();
        set_server_key(server_key.clone());

        let mut registry = LiquidityRegistry::new(client_key.clone(), server_key);

        let pool_id = [1u8; 32];
        let user = [2u8; 32];

        registry.register_lp_token(pool_id, [3u8; 32], [4u8; 32]).unwrap();

        // User owns 100% of pool
        let amount = FheUint64::encrypt(1000u64, &client_key);
        registry.mint(pool_id, user, amount, 1).unwrap();

        // Pool has 10000 token A and 20000 token B
        let (value_a, value_b) = registry.calculate_position_value(
            &pool_id,
            &user,
            10000,
            20000,
        ).unwrap();

        assert_eq!(value_a, 10000);
        assert_eq!(value_b, 20000);
    }

    #[test]
    fn test_fee_distributor() {
        let (client_key, server_key) = setup_fhe();
        set_server_key(server_key.clone());

        let mut registry = LiquidityRegistry::new(client_key.clone(), server_key.clone());
        let mut distributor = FeeDistributor::new(client_key.clone(), server_key);

        let pool_id = [1u8; 32];
        let user = [2u8; 32];

        registry.register_lp_token(pool_id, [3u8; 32], [4u8; 32]).unwrap();

        // User owns 100% of pool
        let amount = FheUint64::encrypt(1000u64, &client_key);
        registry.mint(pool_id, user, amount, 1).unwrap();

        // Add fees
        let fee_a = FheUint64::encrypt(100u64, &client_key);
        let fee_b = FheUint64::encrypt(200u64, &client_key);
        distributor.add_fees(pool_id, fee_a, fee_b);

        // Calculate claimable
        let (claimable_a, claimable_b) = distributor.calculate_claimable(
            &pool_id,
            &user,
            &registry,
        ).unwrap();

        assert_eq!(claimable_a, 100);
        assert_eq!(claimable_b, 200);
    }
}
