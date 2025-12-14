//! FHE Server for Validator Operations with Real TFHE-rs
//!
//! Validators use the FHE server to process encrypted transactions
//! without learning the values involved.

use crate::{FHEError, FHEResult};
use super::ciphertext::FHEUint64;
use super::keys::ServerKey;
use super::operations::{FHEOps, FHEBool};

/// FHE Server for validator computations
pub struct FHEServer {
    /// Server key for homomorphic operations
    server_key: ServerKey,
}

impl FHEServer {
    /// Create a new FHE server with the given server key
    pub fn new(server_key: ServerKey) -> Self {
        // Set the server key globally for TFHE-rs operations
        server_key.set_global();
        Self { server_key }
    }

    /// Get reference to server key
    pub fn server_key(&self) -> &ServerKey {
        &self.server_key
    }

    /// Verify a balance update is valid (inputs >= outputs)
    ///
    /// Returns encrypted boolean indicating if the transaction is valid.
    /// The actual values remain hidden from the validator.
    pub fn verify_balance_conservation(
        &self,
        input_sum: &FHEUint64,
        output_sum: &FHEUint64,
    ) -> FHEResult<FHEBool> {
        // inputs >= outputs means outputs <= inputs
        FHEOps::le(output_sum, input_sum, &self.server_key)
    }

    /// Verify balance conservation and decrypt result (requires client key for verification)
    pub fn verify_balance_conservation_plaintext(
        &self,
        input_sum: &FHEUint64,
        output_sum: &FHEUint64,
        client_key: &super::keys::ClientKey,
    ) -> FHEResult<bool> {
        let encrypted_result = self.verify_balance_conservation(input_sum, output_sum)?;
        Ok(encrypted_result.decrypt(client_key))
    }

    /// Update an encrypted balance by adding a delta
    pub fn update_balance(
        &self,
        current: &FHEUint64,
        delta: &FHEUint64,
        is_credit: bool,
    ) -> FHEResult<FHEUint64> {
        if is_credit {
            FHEOps::add(current, delta, &self.server_key)
        } else {
            FHEOps::sub(current, delta, &self.server_key)
        }
    }

    /// Batch process multiple balance updates
    pub fn batch_update(
        &self,
        updates: &[(FHEUint64, FHEUint64, bool)], // (current, delta, is_credit)
    ) -> FHEResult<Vec<FHEUint64>> {
        updates
            .iter()
            .map(|(current, delta, is_credit)| {
                self.update_balance(current, delta, *is_credit)
            })
            .collect()
    }

    /// Sum multiple encrypted values
    pub fn sum(&self, values: &[FHEUint64]) -> FHEResult<FHEUint64> {
        if values.is_empty() {
            return Err(FHEError::OperationFailed("Empty sum".into()));
        }

        let mut result = values[0].clone();
        for value in values.iter().skip(1) {
            result = FHEOps::add(&result, value, &self.server_key)?;
        }

        Ok(result)
    }

    /// Compute weighted sum: sum(values[i] * weights[i])
    pub fn weighted_sum(&self, values: &[FHEUint64], weights: &[u64]) -> FHEResult<FHEUint64> {
        if values.is_empty() || values.len() != weights.len() {
            return Err(FHEError::OperationFailed("Mismatched arrays".into()));
        }

        let mut result = FHEOps::mul_scalar(&values[0], weights[0], &self.server_key)?;
        for (value, &weight) in values.iter().zip(weights.iter()).skip(1) {
            let term = FHEOps::mul_scalar(value, weight, &self.server_key)?;
            result = FHEOps::add(&result, &term, &self.server_key)?;
        }

        Ok(result)
    }

    /// Verify a range proof on an encrypted value
    ///
    /// The encrypted_max must be provided by the client who encrypted it
    /// Server cannot create encrypted values (no client key)
    pub fn verify_range(
        &self,
        value: &FHEUint64,
        encrypted_max: &FHEUint64,
    ) -> FHEResult<FHEBool> {
        // Compare encrypted value against encrypted max
        // Both must be encrypted with the same client key
        FHEOps::le(value, encrypted_max, &self.server_key)
    }

    /// Bootstrap a ciphertext to reduce noise
    pub fn bootstrap(&self, value: &FHEUint64) -> FHEResult<FHEUint64> {
        FHEOps::bootstrap(value, &self.server_key)
    }

    /// Check if a value needs bootstrapping
    pub fn needs_bootstrap(&self, value: &FHEUint64) -> bool {
        value.needs_bootstrap()
    }

    /// Process a transaction (sum inputs, sum outputs, verify conservation)
    pub fn process_transaction(
        &self,
        inputs: &[FHEUint64],
        outputs: &[FHEUint64],
    ) -> FHEResult<TransactionResult> {
        if inputs.is_empty() || outputs.is_empty() {
            return Err(FHEError::OperationFailed("Empty inputs or outputs".into()));
        }

        // Sum all inputs
        let input_sum = self.sum(inputs)?;

        // Sum all outputs
        let output_sum = self.sum(outputs)?;

        // Verify conservation (inputs >= outputs)
        let valid = self.verify_balance_conservation(&input_sum, &output_sum)?;

        Ok(TransactionResult {
            input_sum,
            output_sum,
            valid,
        })
    }

    /// Compute fee from transaction (inputs - outputs)
    pub fn compute_fee(
        &self,
        input_sum: &FHEUint64,
        output_sum: &FHEUint64,
    ) -> FHEResult<FHEUint64> {
        FHEOps::sub(input_sum, output_sum, &self.server_key)
    }

    /// Select between two values based on encrypted condition
    pub fn conditional_select(
        &self,
        condition: &FHEBool,
        if_true: &FHEUint64,
        if_false: &FHEUint64,
    ) -> FHEResult<FHEUint64> {
        FHEOps::select(condition, if_true, if_false, &self.server_key)
    }

    /// Find minimum of encrypted values
    pub fn min(&self, values: &[FHEUint64]) -> FHEResult<FHEUint64> {
        if values.is_empty() {
            return Err(FHEError::OperationFailed("Empty values".into()));
        }

        let mut result = values[0].clone();
        for value in values.iter().skip(1) {
            result = FHEOps::min(&result, value, &self.server_key)?;
        }

        Ok(result)
    }

    /// Find maximum of encrypted values
    pub fn max(&self, values: &[FHEUint64]) -> FHEResult<FHEUint64> {
        if values.is_empty() {
            return Err(FHEError::OperationFailed("Empty values".into()));
        }

        let mut result = values[0].clone();
        for value in values.iter().skip(1) {
            result = FHEOps::max(&result, value, &self.server_key)?;
        }

        Ok(result)
    }
}

/// Result of processing a transaction
#[derive(Debug)]
pub struct TransactionResult {
    /// Sum of input values (encrypted)
    pub input_sum: FHEUint64,
    /// Sum of output values (encrypted)
    pub output_sum: FHEUint64,
    /// Whether conservation law is satisfied (encrypted boolean)
    pub valid: FHEBool,
}

impl TransactionResult {
    /// Decrypt the validity flag (requires client key)
    pub fn is_valid(&self, client_key: &super::keys::ClientKey) -> bool {
        self.valid.decrypt(client_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FHEConfig;
    use super::super::keys::KeyPair;

    #[test]
    fn test_server_sum() {
        let config = FHEConfig::default();
        let keypair = KeyPair::generate(&config).unwrap();
        let server = FHEServer::new(keypair.server.clone());

        let values: Vec<FHEUint64> = [10u64, 20, 30, 40]
            .iter()
            .map(|&v| FHEUint64::encrypt(v, &keypair.client).unwrap())
            .collect();

        let sum = server.sum(&values).unwrap();
        let result = sum.decrypt(&keypair.client).unwrap();

        assert_eq!(result, 100);
    }

    #[test]
    fn test_transaction_processing_valid() {
        let config = FHEConfig::default();
        let keypair = KeyPair::generate(&config).unwrap();
        let server = FHEServer::new(keypair.server.clone());

        // Valid transaction: 100 + 50 >= 80 + 60
        let inputs: Vec<FHEUint64> = [100u64, 50]
            .iter()
            .map(|&v| FHEUint64::encrypt(v, &keypair.client).unwrap())
            .collect();

        let outputs: Vec<FHEUint64> = [80u64, 60]
            .iter()
            .map(|&v| FHEUint64::encrypt(v, &keypair.client).unwrap())
            .collect();

        let result = server.process_transaction(&inputs, &outputs).unwrap();
        assert!(result.is_valid(&keypair.client)); // 150 >= 140
    }

    #[test]
    fn test_transaction_processing_invalid() {
        let config = FHEConfig::default();
        let keypair = KeyPair::generate(&config).unwrap();
        let server = FHEServer::new(keypair.server.clone());

        // Invalid transaction: 50 < 100
        let inputs: Vec<FHEUint64> = [50u64]
            .iter()
            .map(|&v| FHEUint64::encrypt(v, &keypair.client).unwrap())
            .collect();

        let outputs: Vec<FHEUint64> = [100u64]
            .iter()
            .map(|&v| FHEUint64::encrypt(v, &keypair.client).unwrap())
            .collect();

        let result = server.process_transaction(&inputs, &outputs).unwrap();
        assert!(!result.is_valid(&keypair.client)); // 50 < 100
    }

    #[test]
    fn test_balance_update() {
        let config = FHEConfig::default();
        let keypair = KeyPair::generate(&config).unwrap();
        let server = FHEServer::new(keypair.server.clone());

        let balance = FHEUint64::encrypt(1000, &keypair.client).unwrap();
        let delta = FHEUint64::encrypt(250, &keypair.client).unwrap();

        // Credit
        let new_balance = server.update_balance(&balance, &delta, true).unwrap();
        assert_eq!(new_balance.decrypt(&keypair.client).unwrap(), 1250);

        // Debit
        let new_balance = server.update_balance(&balance, &delta, false).unwrap();
        assert_eq!(new_balance.decrypt(&keypair.client).unwrap(), 750);
    }

    #[test]
    fn test_fee_computation() {
        let config = FHEConfig::default();
        let keypair = KeyPair::generate(&config).unwrap();
        let server = FHEServer::new(keypair.server.clone());

        let inputs = FHEUint64::encrypt(150, &keypair.client).unwrap();
        let outputs = FHEUint64::encrypt(140, &keypair.client).unwrap();

        let fee = server.compute_fee(&inputs, &outputs).unwrap();
        assert_eq!(fee.decrypt(&keypair.client).unwrap(), 10);
    }
}
