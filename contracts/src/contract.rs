//! Contract types and deployment

use crate::errors::ContractError;
use crate::opcodes::{Instruction, Opcode, Operand};
use crate::state::StateManager;
use crate::vm::{CompiledContract, ExecutionContext, ExecutionResult, PrivateVM};
use phantom_esl::EncryptedBalance;
use phantom_fhe::ServerKey;
use serde::{Deserialize, Serialize};

/// A deployed private contract
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contract {
    /// Contract identifier (derived from deployment params)
    pub id: [u8; 32],
    /// Hash of the contract code
    pub code_hash: [u8; 32],
    /// Current state root
    pub state_root: [u8; 32],
    /// Deployer address
    pub deployer: [u8; 32],
    /// Block number at deployment
    pub deployed_at: u64,
    /// Contract is active (not self-destructed)
    pub active: bool,
}

impl Contract {
    /// Create a new contract
    pub fn new(
        id: [u8; 32],
        code_hash: [u8; 32],
        deployer: [u8; 32],
        deployed_at: u64,
    ) -> Self {
        // Initial state root is the code hash
        Self {
            id,
            code_hash,
            state_root: code_hash,
            deployer,
            deployed_at,
            active: true,
        }
    }

    /// Compute contract ID from deployment parameters
    pub fn compute_id(deployer: &[u8; 32], nonce: u64, code_hash: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(deployer);
        hasher.update(&nonce.to_le_bytes());
        hasher.update(code_hash);
        *hasher.finalize().as_bytes()
    }
}

/// Contract deployment manager
pub struct ContractDeployer {
    /// Server key for FHE operations
    server_key: Option<ServerKey>,
}

impl ContractDeployer {
    /// Create new deployer
    pub fn new() -> Self {
        Self { server_key: None }
    }

    /// Set server key for FHE operations
    pub fn set_server_key(&mut self, key: ServerKey) {
        self.server_key = Some(key);
    }

    /// Deploy a new contract
    pub fn deploy(
        &self,
        compiled: &CompiledContract,
        deployer: [u8; 32],
        nonce: u64,
        block_number: u64,
        state_manager: &mut StateManager,
    ) -> Result<Contract, ContractError> {
        // Compute contract ID
        let contract_id = Contract::compute_id(&deployer, nonce, &compiled.code_hash);

        // Create contract record
        let contract = Contract::new(
            contract_id,
            compiled.code_hash,
            deployer,
            block_number,
        );

        // Initialize contract state
        state_manager.get_or_create_contract(contract_id);

        // Run constructor if present
        if let Some(constructor) = &compiled.constructor {
            let server_key = self.server_key.as_ref()
                .ok_or(ContractError::ServerKeyNotSet)?;

            let mut vm = PrivateVM::new();
            vm.set_server_key(server_key.clone());

            let ctx = ExecutionContext::new(deployer, contract_id);
            let result = vm.execute(constructor, &ctx, state_manager);

            match result {
                ExecutionResult::Success { .. } | ExecutionResult::Halted { .. } => {}
                ExecutionResult::Failure { reason, .. } => {
                    return Err(ContractError::InvalidCode(format!(
                        "Constructor failed: {}", reason
                    )));
                }
            }
        }

        Ok(contract)
    }
}

impl Default for ContractDeployer {
    fn default() -> Self {
        Self::new()
    }
}

/// Contract call builder
#[derive(Clone, Debug)]
pub struct ContractCall {
    /// Target contract
    pub contract_id: [u8; 32],
    /// Caller address
    pub caller: [u8; 32],
    /// Value to send (encrypted)
    pub value: Option<EncryptedBalance>,
    /// Input data (encoded function call)
    pub input: Vec<u8>,
    /// Gas limit
    pub gas_limit: u64,
}

impl ContractCall {
    /// Create a new contract call
    pub fn new(contract_id: [u8; 32], caller: [u8; 32]) -> Self {
        Self {
            contract_id,
            caller,
            value: None,
            input: Vec::new(),
            gas_limit: 10_000_000,
        }
    }

    /// Set value to send with call
    pub fn with_value(mut self, value: EncryptedBalance) -> Self {
        self.value = Some(value);
        self
    }

    /// Set input data
    pub fn with_input(mut self, input: Vec<u8>) -> Self {
        self.input = input;
        self
    }

    /// Set gas limit
    pub fn with_gas_limit(mut self, limit: u64) -> Self {
        self.gas_limit = limit;
        self
    }
}

/// Standard contract templates for common use cases
pub mod templates {
    use super::*;

    /// Create a simple token transfer contract
    ///
    /// This contract:
    /// 1. Stores balances in state slots (one per address hash)
    /// 2. Supports transfer between accounts
    /// 3. All amounts remain encrypted
    pub fn token_transfer() -> CompiledContract {
        // Simple transfer contract:
        // - Load sender balance from state[0]
        // - Subtract transfer amount
        // - Store new sender balance
        // - Load recipient balance from state[1]
        // - Add transfer amount
        // - Store new recipient balance
        // - Return

        let code = vec![
            // Load sender balance
            Instruction::new(Opcode::StateLoad, Some(Operand::Index(0))),
            // Subtract amount (assume amount is pushed by caller)
            // This is simplified - real implementation would parse input
            Instruction::simple(Opcode::Sub),
            // Store new sender balance
            Instruction::new(Opcode::StateStore, Some(Operand::Index(0))),
            // Load recipient balance
            Instruction::new(Opcode::StateLoad, Some(Operand::Index(1))),
            // Add amount (from memory/input)
            Instruction::simple(Opcode::Add),
            // Store new recipient balance
            Instruction::new(Opcode::StateStore, Some(Operand::Index(1))),
            // Return success
            Instruction::simple(Opcode::Return),
        ];

        CompiledContract::new(code)
    }

    /// Create a simple balance check contract
    ///
    /// Returns encrypted comparison result: balance >= threshold
    pub fn balance_check() -> CompiledContract {
        let code = vec![
            // Load balance from state[0]
            Instruction::new(Opcode::StateLoad, Some(Operand::Index(0))),
            // Load threshold from state[1]
            Instruction::new(Opcode::StateLoad, Some(Operand::Index(1))),
            // Compare: balance >= threshold
            Instruction::simple(Opcode::Ge),
            // Return result (encrypted bool as 0 or 1)
            Instruction::simple(Opcode::Return),
        ];

        CompiledContract::new(code)
    }

    /// Create a simple escrow contract
    ///
    /// Escrow holds funds until condition is met (external unlock)
    pub fn escrow() -> CompiledContract {
        let code = vec![
            // Load escrow balance from state[0]
            Instruction::new(Opcode::StateLoad, Some(Operand::Index(0))),
            // Load lock status from state[1] (0 = locked, 1 = unlocked)
            Instruction::new(Opcode::StateLoad, Some(Operand::Index(1))),
            // If unlocked (==1), proceed to transfer
            // (Simplified - real implementation would have proper branching)
            Instruction::simple(Opcode::Return),
        ];

        CompiledContract::new(code)
    }

    /// Create a private voting contract
    ///
    /// Each vote is encrypted, tallied homomorphically
    pub fn private_voting() -> CompiledContract {
        let code = vec![
            // Load current vote count from state[0]
            Instruction::new(Opcode::StateLoad, Some(Operand::Index(0))),
            // Add new vote (encrypted 1)
            Instruction::simple(Opcode::Add),
            // Store updated count
            Instruction::new(Opcode::StateStore, Some(Operand::Index(0))),
            // Return new count
            Instruction::new(Opcode::StateLoad, Some(Operand::Index(0))),
            Instruction::simple(Opcode::Return),
        ];

        CompiledContract::new(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_creation() {
        let id = [1u8; 32];
        let code_hash = [2u8; 32];
        let deployer = [3u8; 32];
        let contract = Contract::new(id, code_hash, deployer, 100);

        assert_eq!(contract.id, id);
        assert_eq!(contract.code_hash, code_hash);
        assert_eq!(contract.deployer, deployer);
        assert_eq!(contract.deployed_at, 100);
        assert!(contract.active);
    }

    #[test]
    fn test_contract_id_computation() {
        let deployer = [1u8; 32];
        let code_hash = [2u8; 32];

        let id1 = Contract::compute_id(&deployer, 0, &code_hash);
        let id2 = Contract::compute_id(&deployer, 1, &code_hash);

        // Different nonces should produce different IDs
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_contract_call_builder() {
        let contract_id = [1u8; 32];
        let caller = [2u8; 32];

        let call = ContractCall::new(contract_id, caller)
            .with_gas_limit(50_000)
            .with_input(vec![1, 2, 3, 4]);

        assert_eq!(call.contract_id, contract_id);
        assert_eq!(call.caller, caller);
        assert_eq!(call.gas_limit, 50_000);
        assert_eq!(call.input, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_template_contracts() {
        let transfer = templates::token_transfer();
        assert!(!transfer.code.is_empty());

        let balance = templates::balance_check();
        assert!(!balance.code.is_empty());

        let escrow = templates::escrow();
        assert!(!escrow.code.is_empty());

        let voting = templates::private_voting();
        assert!(!voting.code.is_empty());
    }

    #[test]
    fn test_contract_deployer() {
        let deployer = ContractDeployer::new();
        assert!(deployer.server_key.is_none());
    }
}
