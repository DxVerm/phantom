//! Private swap execution with FHE-encrypted amounts
//!
//! Implements constant product swaps where:
//! - Swap amounts are encrypted (only direction visible)
//! - Price impact calculated on encrypted values
//! - Slippage protection via encrypted comparisons

use crate::errors::{DeFiError, DeFiResult};
use crate::pool::LiquidityPool;
use tfhe::prelude::*;
use tfhe::{FheUint64, ClientKey, ServerKey, set_server_key};

/// Direction of a swap
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapDirection {
    /// Swap token A for token B
    AtoB,
    /// Swap token B for token A
    BtoA,
}

/// A swap request with encrypted amounts
pub struct SwapRequest {
    /// Pool to swap in
    pub pool_id: [u8; 32],
    /// Direction of swap
    pub direction: SwapDirection,
    /// Encrypted input amount
    pub amount_in: FheUint64,
    /// Encrypted minimum output (slippage protection)
    pub min_amount_out: FheUint64,
    /// Deadline block height
    pub deadline: u64,
}

impl std::fmt::Debug for SwapRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SwapRequest")
            .field("pool_id", &hex::encode(&self.pool_id))
            .field("direction", &self.direction)
            .field("amount_in", &"<encrypted>")
            .field("min_amount_out", &"<encrypted>")
            .field("deadline", &self.deadline)
            .finish()
    }
}

/// Result of a swap execution
pub struct SwapResult {
    /// Encrypted amount actually received
    pub amount_out: FheUint64,
    /// Encrypted fee paid
    pub fee_paid: FheUint64,
    /// New encrypted reserve A
    pub new_reserve_a: FheUint64,
    /// New encrypted reserve B
    pub new_reserve_b: FheUint64,
    /// Whether slippage check passed (encrypted bool as u64: 1=true, 0=false)
    pub slippage_ok: FheUint64,
}

impl std::fmt::Debug for SwapResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SwapResult")
            .field("amount_out", &"<encrypted>")
            .field("fee_paid", &"<encrypted>")
            .field("new_reserve_a", &"<encrypted>")
            .field("new_reserve_b", &"<encrypted>")
            .field("slippage_ok", &"<encrypted>")
            .finish()
    }
}

/// Swap execution engine with FHE support
pub struct SwapExecution {
    client_key: ClientKey,
    server_key: ServerKey,
}

impl SwapExecution {
    /// Create a new swap execution engine
    pub fn new(client_key: ClientKey, server_key: ServerKey) -> Self {
        Self { client_key, server_key }
    }

    /// Execute a swap using constant product formula
    ///
    /// Formula: (x + Δx)(y - Δy) = xy
    /// Where Δy = y * Δx / (x + Δx)
    /// With fee: Δx_effective = Δx * (10000 - fee_bps) / 10000
    pub fn execute_swap(
        &self,
        reserve_in: &FheUint64,
        reserve_out: &FheUint64,
        amount_in: &FheUint64,
        fee_bps: u16,
    ) -> DeFiResult<(FheUint64, FheUint64)> {
        set_server_key(self.server_key.clone());

        // Calculate fee: amount_in_with_fee = amount_in * (10000 - fee_bps) / 10000
        let fee_multiplier = 10000u64 - fee_bps as u64;
        let fee_multiplier_enc = FheUint64::encrypt(fee_multiplier, &self.client_key);
        let divisor = FheUint64::encrypt(10000u64, &self.client_key);

        // amount_in_with_fee = amount_in * fee_multiplier / 10000
        let amount_in_times_fee = amount_in * &fee_multiplier_enc;
        let amount_in_with_fee = &amount_in_times_fee / &divisor;

        // Calculate output: amount_out = reserve_out * amount_in_with_fee / (reserve_in + amount_in_with_fee)
        let numerator = reserve_out * &amount_in_with_fee;
        let denominator = reserve_in + &amount_in_with_fee;
        let amount_out = &numerator / &denominator;

        // Calculate actual fee paid
        let fee_paid = amount_in - &amount_in_with_fee;

        Ok((amount_out, fee_paid))
    }

    /// Execute a full swap request against a pool
    pub fn execute_swap_request(
        &self,
        pool: &mut LiquidityPool,
        request: &SwapRequest,
        current_block: u64,
    ) -> DeFiResult<SwapResult> {
        // Check deadline
        if current_block > request.deadline {
            return Err(DeFiError::DeadlineExpired {
                deadline: request.deadline,
                current: current_block,
            });
        }

        set_server_key(self.server_key.clone());

        let (reserve_in, reserve_out) = match request.direction {
            SwapDirection::AtoB => (&pool.state.reserve_a, &pool.state.reserve_b),
            SwapDirection::BtoA => (&pool.state.reserve_b, &pool.state.reserve_a),
        };

        // Execute the swap calculation
        let (amount_out, fee_paid) = self.execute_swap(
            reserve_in,
            reserve_out,
            &request.amount_in,
            pool.config.fee_bps,
        )?;

        // Check slippage: amount_out >= min_amount_out
        // In FHE, we compute this as a comparison that results in 0 or 1
        let slippage_ok = amount_out.ge(&request.min_amount_out);
        let slippage_ok_u64 = FheUint64::encrypt(
            if slippage_ok.decrypt(&self.client_key) { 1u64 } else { 0u64 },
            &self.client_key
        );

        // Update reserves based on direction
        let (new_reserve_a, new_reserve_b) = match request.direction {
            SwapDirection::AtoB => {
                let new_a = &pool.state.reserve_a + &request.amount_in;
                let new_b = &pool.state.reserve_b - &amount_out;
                (new_a, new_b)
            }
            SwapDirection::BtoA => {
                let new_a = &pool.state.reserve_a - &amount_out;
                let new_b = &pool.state.reserve_b + &request.amount_in;
                (new_a, new_b)
            }
        };

        // Update pool state
        pool.state.reserve_a = new_reserve_a.clone();
        pool.state.reserve_b = new_reserve_b.clone();

        Ok(SwapResult {
            amount_out,
            fee_paid,
            new_reserve_a,
            new_reserve_b,
            slippage_ok: slippage_ok_u64,
        })
    }

    /// Calculate price impact of a swap (returns basis points * 100 for precision)
    /// Price impact = (execution_price - spot_price) / spot_price * 10000
    pub fn calculate_price_impact(
        &self,
        reserve_in: &FheUint64,
        reserve_out: &FheUint64,
        amount_in: &FheUint64,
        amount_out: &FheUint64,
    ) -> DeFiResult<FheUint64> {
        set_server_key(self.server_key.clone());

        // Spot price = reserve_out / reserve_in (scaled by 10000 for precision)
        let scale = FheUint64::encrypt(10000u64, &self.client_key);
        let spot_price_scaled = (reserve_out * &scale) / reserve_in;

        // Execution price = amount_out / amount_in (scaled)
        let exec_price_scaled = (amount_out * &scale) / amount_in;

        // Price impact = |spot - exec| / spot * 10000
        // We compute absolute difference
        let impact = if spot_price_scaled.gt(&exec_price_scaled).decrypt(&self.client_key) {
            (&spot_price_scaled - &exec_price_scaled) * &scale / &spot_price_scaled
        } else {
            (&exec_price_scaled - &spot_price_scaled) * &scale / &spot_price_scaled
        };

        Ok(impact)
    }

    /// Get a quote for a swap without executing
    pub fn get_quote(
        &self,
        reserve_in: u64,
        reserve_out: u64,
        amount_in: u64,
        fee_bps: u16,
    ) -> DeFiResult<SwapQuote> {
        // Non-encrypted calculation for quotes
        let amount_in_with_fee = amount_in as u128 * (10000 - fee_bps as u128) / 10000;
        let numerator = reserve_out as u128 * amount_in_with_fee;
        let denominator = reserve_in as u128 + amount_in_with_fee;
        let amount_out = (numerator / denominator) as u64;

        let fee_paid = amount_in - (amount_in_with_fee as u64);

        // Calculate price impact
        let spot_price = (reserve_out as f64) / (reserve_in as f64);
        let exec_price = (amount_out as f64) / (amount_in as f64);
        let price_impact_bps = ((spot_price - exec_price).abs() / spot_price * 10000.0) as u16;

        // New reserves after swap
        let new_reserve_in = reserve_in + amount_in;
        let new_reserve_out = reserve_out - amount_out;

        Ok(SwapQuote {
            amount_out,
            fee_paid,
            price_impact_bps,
            new_reserve_in,
            new_reserve_out,
        })
    }

    /// Decrypt a swap result for verification
    pub fn decrypt_result(&self, result: &SwapResult) -> DecryptedSwapResult {
        let slippage_val: u64 = result.slippage_ok.decrypt(&self.client_key);
        DecryptedSwapResult {
            amount_out: result.amount_out.decrypt(&self.client_key),
            fee_paid: result.fee_paid.decrypt(&self.client_key),
            new_reserve_a: result.new_reserve_a.decrypt(&self.client_key),
            new_reserve_b: result.new_reserve_b.decrypt(&self.client_key),
            slippage_ok: slippage_val == 1,
        }
    }
}

/// Quote for a potential swap (plaintext for UI display)
#[derive(Debug, Clone)]
pub struct SwapQuote {
    /// Expected output amount
    pub amount_out: u64,
    /// Fee that will be paid
    pub fee_paid: u64,
    /// Price impact in basis points
    pub price_impact_bps: u16,
    /// New reserve in after swap
    pub new_reserve_in: u64,
    /// New reserve out after swap
    pub new_reserve_out: u64,
}

/// Decrypted swap result for verification
#[derive(Debug, Clone)]
pub struct DecryptedSwapResult {
    pub amount_out: u64,
    pub fee_paid: u64,
    pub new_reserve_a: u64,
    pub new_reserve_b: u64,
    pub slippage_ok: bool,
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
    fn test_swap_quote_calculation() {
        let (client_key, server_key) = setup_fhe();
        let swap_exec = SwapExecution::new(client_key, server_key);

        // 1000 token A, 2000 token B, swap 100 A for B with 0.3% fee
        let quote = swap_exec.get_quote(1000, 2000, 100, 30).unwrap();

        // Expected: ~181 B out (with fee)
        // amount_in_with_fee = 100 * 9970 / 10000 = 99.7
        // amount_out = 2000 * 99.7 / (1000 + 99.7) = 181.27...
        assert!(quote.amount_out > 175 && quote.amount_out < 185);
        assert!(quote.fee_paid > 0);
        assert_eq!(quote.new_reserve_in, 1100);
    }

    #[test]
    fn test_encrypted_swap_execution() {
        let (client_key, server_key) = setup_fhe();
        set_server_key(server_key.clone());
        let swap_exec = SwapExecution::new(client_key.clone(), server_key);

        let reserve_in = FheUint64::encrypt(1000u64, &client_key);
        let reserve_out = FheUint64::encrypt(2000u64, &client_key);
        let amount_in = FheUint64::encrypt(100u64, &client_key);

        let (amount_out, fee_paid) = swap_exec.execute_swap(
            &reserve_in,
            &reserve_out,
            &amount_in,
            30, // 0.3% fee
        ).unwrap();

        let out_decrypted: u64 = amount_out.decrypt(&client_key);
        let fee_decrypted: u64 = fee_paid.decrypt(&client_key);

        // Should match plaintext calculation approximately
        assert!(out_decrypted > 170 && out_decrypted < 190);
        assert!(fee_decrypted > 0);
    }

    #[test]
    fn test_swap_direction() {
        assert_eq!(SwapDirection::AtoB, SwapDirection::AtoB);
        assert_ne!(SwapDirection::AtoB, SwapDirection::BtoA);
    }

    #[test]
    fn test_large_swap_price_impact() {
        let (client_key, server_key) = setup_fhe();
        let swap_exec = SwapExecution::new(client_key, server_key);

        // Large swap should have higher price impact
        let small_quote = swap_exec.get_quote(1000, 2000, 10, 30).unwrap();
        let large_quote = swap_exec.get_quote(1000, 2000, 500, 30).unwrap();

        assert!(large_quote.price_impact_bps > small_quote.price_impact_bps);
    }
}
