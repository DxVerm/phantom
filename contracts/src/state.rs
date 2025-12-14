//! Contract state management with FHE encryption
//!
//! All contract state is encrypted using TFHE. State can be operated on
//! homomorphically without decryption.

use crate::errors::ContractError;
use crate::vm::CompiledContract;
use phantom_esl::EncryptedBalance;
use phantom_fhe::ServerKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Encrypted contract state
///
/// Each contract has its own isolated state that is fully encrypted.
/// Operations on state are performed homomorphically.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractState {
    /// Contract identifier
    pub contract_id: [u8; 32],
    /// Encrypted storage slots (slot index -> encrypted value)
    storage: HashMap<u32, EncryptedBalance>,
    /// State root (commitment to current state)
    pub state_root: [u8; 32],
    /// Number of state modifications
    pub nonce: u64,
}

impl ContractState {
    /// Create new empty contract state
    pub fn new(contract_id: [u8; 32]) -> Self {
        let state_root = Self::compute_empty_root(&contract_id);
        Self {
            contract_id,
            storage: HashMap::new(),
            state_root,
            nonce: 0,
        }
    }

    /// Load encrypted value from storage slot
    pub fn load(&self, slot: u32) -> Option<&EncryptedBalance> {
        self.storage.get(&slot)
    }

    /// Store encrypted value to storage slot
    pub fn store(&mut self, slot: u32, value: EncryptedBalance) {
        self.storage.insert(slot, value);
        self.nonce += 1;
        self.update_state_root();
    }

    /// Perform encrypted addition on storage slot
    pub fn add_to_slot(
        &mut self,
        slot: u32,
        amount: &EncryptedBalance,
        server_key: &ServerKey,
    ) -> Result<(), ContractError> {
        let current = self.storage.get(&slot)
            .ok_or_else(|| ContractError::InvalidMemoryAccess { offset: slot as usize })?;

        let new_value = current.add(amount, server_key)?;
        self.storage.insert(slot, new_value);
        self.nonce += 1;
        self.update_state_root();
        Ok(())
    }

    /// Perform encrypted subtraction on storage slot
    pub fn sub_from_slot(
        &mut self,
        slot: u32,
        amount: &EncryptedBalance,
        server_key: &ServerKey,
    ) -> Result<(), ContractError> {
        let current = self.storage.get(&slot)
            .ok_or_else(|| ContractError::InvalidMemoryAccess { offset: slot as usize })?;

        let new_value = current.sub(amount, server_key)?;
        self.storage.insert(slot, new_value);
        self.nonce += 1;
        self.update_state_root();
        Ok(())
    }

    /// Get number of storage slots used
    pub fn slot_count(&self) -> usize {
        self.storage.len()
    }

    /// Check if slot exists
    pub fn has_slot(&self, slot: u32) -> bool {
        self.storage.contains_key(&slot)
    }

    /// Get all storage slot indices
    pub fn slots(&self) -> Vec<u32> {
        self.storage.keys().copied().collect()
    }

    /// Compute state root from current state
    fn update_state_root(&mut self) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.contract_id);
        hasher.update(&self.nonce.to_le_bytes());

        // Hash all storage slots in sorted order for determinism
        let mut slots: Vec<_> = self.storage.iter().collect();
        slots.sort_by_key(|(k, _)| *k);

        for (slot, value) in slots {
            hasher.update(&slot.to_le_bytes());
            hasher.update(value.ciphertext_bytes());
        }

        self.state_root = *hasher.finalize().as_bytes();
    }

    /// Compute empty state root
    fn compute_empty_root(contract_id: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(contract_id);
        hasher.update(&0u64.to_le_bytes()); // nonce = 0
        *hasher.finalize().as_bytes()
    }

    /// Serialize state for persistence
    pub fn serialize(&self) -> Result<Vec<u8>, ContractError> {
        bincode::serialize(self)
            .map_err(|e| ContractError::SerializationError(e.to_string()))
    }

    /// Deserialize state from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, ContractError> {
        bincode::deserialize(data)
            .map_err(|e| ContractError::SerializationError(e.to_string()))
    }
}

/// Global state manager for all contracts
#[derive(Clone, Debug, Default)]
pub struct StateManager {
    /// Contract states indexed by contract ID
    contracts: HashMap<[u8; 32], ContractState>,
    /// Account balances (encrypted)
    balances: HashMap<[u8; 32], EncryptedBalance>,
    /// Deployed contract code indexed by contract ID
    code_registry: HashMap<[u8; 32], CompiledContract>,
}

impl StateManager {
    /// Create new state manager
    pub fn new() -> Self {
        Self {
            contracts: HashMap::new(),
            balances: HashMap::new(),
            code_registry: HashMap::new(),
        }
    }

    /// Register compiled contract code
    pub fn register_code(&mut self, contract_id: [u8; 32], code: CompiledContract) {
        self.code_registry.insert(contract_id, code);
    }

    /// Get contract code by ID
    pub fn get_code(&self, contract_id: &[u8; 32]) -> Option<&CompiledContract> {
        self.code_registry.get(contract_id)
    }

    /// Check if contract code is registered
    pub fn has_code(&self, contract_id: &[u8; 32]) -> bool {
        self.code_registry.contains_key(contract_id)
    }

    /// Get or create contract state
    pub fn get_or_create_contract(&mut self, contract_id: [u8; 32]) -> &mut ContractState {
        self.contracts.entry(contract_id)
            .or_insert_with(|| ContractState::new(contract_id))
    }

    /// Get contract state (immutable)
    pub fn get_contract(&self, contract_id: &[u8; 32]) -> Option<&ContractState> {
        self.contracts.get(contract_id)
    }

    /// Get contract state (mutable)
    pub fn get_contract_mut(&mut self, contract_id: &[u8; 32]) -> Option<&mut ContractState> {
        self.contracts.get_mut(contract_id)
    }

    /// Set account balance
    pub fn set_balance(&mut self, account: [u8; 32], balance: EncryptedBalance) {
        self.balances.insert(account, balance);
    }

    /// Get account balance
    pub fn get_balance(&self, account: &[u8; 32]) -> Option<&EncryptedBalance> {
        self.balances.get(account)
    }

    /// Transfer encrypted amount between accounts
    pub fn transfer(
        &mut self,
        from: &[u8; 32],
        to: &[u8; 32],
        amount: &EncryptedBalance,
        server_key: &ServerKey,
    ) -> Result<(), ContractError> {
        let from_balance = self.balances.get(from)
            .ok_or(ContractError::InsufficientBalance)?;

        let to_balance = self.balances.get(to).cloned();

        // Compute new balances homomorphically
        let new_from = from_balance.sub(amount, server_key)?;
        let new_to = match to_balance {
            Some(balance) => balance.add(amount, server_key)?,
            None => amount.clone(),
        };

        self.balances.insert(*from, new_from);
        self.balances.insert(*to, new_to);
        Ok(())
    }

    /// Get global state root (commitment to all contracts)
    pub fn global_state_root(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();

        // Hash all contract roots in sorted order
        let mut roots: Vec<_> = self.contracts.iter()
            .map(|(id, state)| (*id, state.state_root))
            .collect();
        roots.sort_by_key(|(id, _)| *id);

        for (id, root) in roots {
            hasher.update(&id);
            hasher.update(&root);
        }

        // Include balance commitments
        let mut balances: Vec<_> = self.balances.iter().collect();
        balances.sort_by_key(|(id, _)| *id);

        for (id, balance) in balances {
            hasher.update(id);
            hasher.update(balance.ciphertext_bytes());
        }

        *hasher.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_state_creation() {
        let contract_id = [1u8; 32];
        let state = ContractState::new(contract_id);
        assert_eq!(state.contract_id, contract_id);
        assert_eq!(state.nonce, 0);
        assert_eq!(state.slot_count(), 0);
    }

    #[test]
    fn test_state_manager_creation() {
        let manager = StateManager::new();
        assert!(manager.contracts.is_empty());
        assert!(manager.balances.is_empty());
    }

    #[test]
    fn test_state_serialization() {
        let contract_id = [2u8; 32];
        let state = ContractState::new(contract_id);

        let serialized = state.serialize().unwrap();
        let deserialized = ContractState::deserialize(&serialized).unwrap();

        assert_eq!(state.contract_id, deserialized.contract_id);
        assert_eq!(state.state_root, deserialized.state_root);
    }
}
