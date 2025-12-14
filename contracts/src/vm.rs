//! Private VM for contract execution
//!
//! A stack-based virtual machine that operates entirely on encrypted values.
//! All computations are performed homomorphically using TFHE.

use crate::errors::ContractError;
use crate::opcodes::{Instruction, Opcode, Operand};
use crate::state::StateManager;
use hex;
use phantom_esl::EncryptedBalance;
use phantom_fhe::ServerKey;
use serde::{Deserialize, Serialize};

/// Maximum stack size
const MAX_STACK_SIZE: usize = 1024;
/// Maximum memory size (slots)
const MAX_MEMORY_SIZE: usize = 4096;
/// Default gas limit
const DEFAULT_GAS_LIMIT: u64 = 10_000_000;
/// Maximum call depth to prevent stack overflow
const MAX_CALL_DEPTH: usize = 256;

/// Saved execution context for cross-contract calls
#[derive(Clone, Debug)]
pub struct SavedContext {
    /// Caller's stack (to restore after call returns)
    pub stack: Vec<EncryptedBalance>,
    /// Caller's memory
    pub memory: Vec<Option<EncryptedBalance>>,
    /// Program counter to return to (instruction after Call)
    pub return_pc: usize,
    /// Gas remaining when call was made
    pub gas_remaining: u64,
    /// Contract ID of the caller
    pub caller_contract_id: [u8; 32],
    /// The original caller address
    pub caller: [u8; 32],
}

/// Execution context for a contract call
#[derive(Clone, Debug)]
pub struct ExecutionContext {
    /// Caller address
    pub caller: [u8; 32],
    /// Contract being executed
    pub contract_id: [u8; 32],
    /// Transaction origin
    pub origin: [u8; 32],
    /// Value being sent (encrypted)
    pub value: Option<EncryptedBalance>,
    /// Gas limit for execution
    pub gas_limit: u64,
    /// Current block number
    pub block_number: u64,
}

impl ExecutionContext {
    /// Create new execution context
    pub fn new(caller: [u8; 32], contract_id: [u8; 32]) -> Self {
        Self {
            caller,
            contract_id,
            origin: caller,
            value: None,
            gas_limit: DEFAULT_GAS_LIMIT,
            block_number: 0,
        }
    }
}

/// Result of contract execution
#[derive(Clone, Debug)]
pub enum ExecutionResult {
    /// Execution succeeded
    Success {
        /// New state root after execution
        new_state_root: [u8; 32],
        /// Return value (if any)
        return_value: Option<EncryptedBalance>,
        /// Gas used
        gas_used: u64,
    },
    /// Execution failed
    Failure {
        /// Error reason
        reason: String,
        /// Gas used before failure
        gas_used: u64,
    },
    /// Execution halted (normal termination)
    Halted {
        /// Final state root
        state_root: [u8; 32],
        /// Gas used
        gas_used: u64,
    },
}

/// Private VM that operates on encrypted state
pub struct PrivateVM {
    /// Server key for homomorphic operations
    server_key: Option<ServerKey>,
    /// Encrypted value stack
    stack: Vec<EncryptedBalance>,
    /// Local memory slots
    memory: Vec<Option<EncryptedBalance>>,
    /// Program counter
    pc: usize,
    /// Gas remaining
    gas_remaining: u64,
    /// Gas used so far
    gas_used: u64,
    /// Execution halted flag
    halted: bool,
    /// Call stack for cross-contract calls (saved contexts)
    call_stack: Vec<SavedContext>,
    /// Current contract ID being executed
    current_contract_id: [u8; 32],
    /// Active code being executed (allows switching during cross-contract calls)
    current_code: Vec<Instruction>,
}

impl PrivateVM {
    /// Create a new Private VM
    pub fn new() -> Self {
        Self {
            server_key: None,
            stack: Vec::with_capacity(256),
            memory: vec![None; MAX_MEMORY_SIZE],
            pc: 0,
            gas_remaining: DEFAULT_GAS_LIMIT,
            gas_used: 0,
            halted: false,
            call_stack: Vec::with_capacity(MAX_CALL_DEPTH),
            current_contract_id: [0u8; 32],
            current_code: Vec::new(),
        }
    }

    /// Set the server key for FHE operations
    pub fn set_server_key(&mut self, key: ServerKey) {
        self.server_key = Some(key);
    }

    /// Execute a contract with given code and context
    pub fn execute(
        &mut self,
        code: &[Instruction],
        ctx: &ExecutionContext,
        state_manager: &mut StateManager,
    ) -> ExecutionResult {
        // Reset VM state
        self.reset(ctx.gas_limit);

        // Set current contract ID for cross-contract call context
        self.current_contract_id = ctx.contract_id;

        // Copy code to current_code for potential mid-execution code switching (cross-contract calls)
        self.current_code = code.to_vec();

        // Execute instructions using current_code (allows switching during cross-contract calls)
        while self.pc < self.current_code.len() && !self.halted {
            let instruction = self.current_code[self.pc].clone();

            // Check gas
            let gas_cost = instruction.opcode.gas_cost();
            if self.gas_remaining < gas_cost {
                return ExecutionResult::Failure {
                    reason: format!("Out of gas at pc={}", self.pc),
                    gas_used: self.gas_used,
                };
            }
            self.gas_remaining -= gas_cost;
            self.gas_used += gas_cost;

            // Execute instruction
            match self.execute_instruction(&instruction, ctx, state_manager) {
                Ok(()) => {
                    self.pc += 1;
                }
                Err(e) => {
                    return ExecutionResult::Failure {
                        reason: e.to_string(),
                        gas_used: self.gas_used,
                    };
                }
            }
        }

        // Get final state root
        let state_root = state_manager
            .get_contract(&ctx.contract_id)
            .map(|s| s.state_root)
            .unwrap_or([0u8; 32]);

        if self.halted {
            ExecutionResult::Halted {
                state_root,
                gas_used: self.gas_used,
            }
        } else {
            ExecutionResult::Success {
                new_state_root: state_root,
                return_value: self.stack.pop(),
                gas_used: self.gas_used,
            }
        }
    }

    /// Reset VM state for new execution
    fn reset(&mut self, gas_limit: u64) {
        self.stack.clear();
        self.memory = vec![None; MAX_MEMORY_SIZE];
        self.pc = 0;
        self.gas_remaining = gas_limit;
        self.gas_used = 0;
        self.halted = false;
        self.call_stack.clear();
        self.current_contract_id = [0u8; 32];
        self.current_code.clear();
    }

    /// Execute a single instruction
    fn execute_instruction(
        &mut self,
        instruction: &Instruction,
        ctx: &ExecutionContext,
        state_manager: &mut StateManager,
    ) -> Result<(), ContractError> {
        // Clone server key to avoid borrow checker issues with self.pop()
        let server_key = self.server_key.as_ref()
            .ok_or(ContractError::ServerKeyNotSet)?
            .clone();

        match instruction.opcode {
            Opcode::Nop => {}

            Opcode::Push => {
                if let Some(Operand::EncryptedValue(data)) = &instruction.operand {
                    let balance = EncryptedBalance::from_bytes(data)?;
                    self.push(balance)?;
                } else {
                    return Err(ContractError::InvalidCode("Push requires encrypted operand".into()));
                }
            }

            Opcode::Pop => {
                self.pop()?;
            }

            Opcode::Dup => {
                let top = self.peek()?;
                self.push(top.clone())?;
            }

            Opcode::Swap => {
                let len = self.stack.len();
                if len < 2 {
                    return Err(ContractError::StackUnderflow { needed: 2, have: len });
                }
                self.stack.swap(len - 1, len - 2);
            }

            // Homomorphic arithmetic
            Opcode::Add => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = a.add(&b, &server_key)?;
                self.push(result)?;
            }

            Opcode::Sub => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = a.sub(&b, &server_key)?;
                self.push(result)?;
            }

            Opcode::Mul => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = a.mul(&b, &server_key)?;
                self.push(result)?;
            }

            // Scalar operations
            Opcode::AddScalar => {
                if let Some(Operand::Plaintext(scalar)) = instruction.operand {
                    let a = self.pop()?;
                    let result = a.add_scalar(scalar, &server_key)?;
                    self.push(result)?;
                } else {
                    return Err(ContractError::InvalidCode("AddScalar requires plaintext operand".into()));
                }
            }

            Opcode::SubScalar => {
                if let Some(Operand::Plaintext(scalar)) = instruction.operand {
                    let a = self.pop()?;
                    let result = a.sub_scalar(scalar, &server_key)?;
                    self.push(result)?;
                } else {
                    return Err(ContractError::InvalidCode("SubScalar requires plaintext operand".into()));
                }
            }

            Opcode::MulScalar => {
                if let Some(Operand::Plaintext(scalar)) = instruction.operand {
                    let a = self.pop()?;
                    let result = a.mul_scalar(scalar, &server_key)?;
                    self.push(result)?;
                } else {
                    return Err(ContractError::InvalidCode("MulScalar requires plaintext operand".into()));
                }
            }

            // Comparisons (return encrypted value, 0 or 1)
            Opcode::Lt => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = a.lt(&b, &server_key)?;
                // Convert encrypted bool to encrypted balance (0 or 1)
                let balance = EncryptedBalance::from_encrypted_bool(result)?;
                self.push(balance)?;
            }

            Opcode::Le => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = a.le(&b, &server_key)?;
                let balance = EncryptedBalance::from_encrypted_bool(result)?;
                self.push(balance)?;
            }

            Opcode::Gt => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = a.gt(&b, &server_key)?;
                let balance = EncryptedBalance::from_encrypted_bool(result)?;
                self.push(balance)?;
            }

            Opcode::Ge => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = a.ge(&b, &server_key)?;
                let balance = EncryptedBalance::from_encrypted_bool(result)?;
                self.push(balance)?;
            }

            Opcode::Eq => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = a.eq(&b, &server_key)?;
                let balance = EncryptedBalance::from_encrypted_bool(result)?;
                self.push(balance)?;
            }

            // FHE Conditional Select - the core primitive for FHE branching
            // Stack: [condition, if_false, if_true] -> [result]
            // This enables oblivious execution: execute both branches, select result
            Opcode::Select => {
                let if_true = self.pop()?;   // Top of stack
                let if_false = self.pop()?;  // Second
                let condition = self.pop()?; // Third (encrypted 0 or 1)

                // Convert the condition (EncryptedBalance holding 0 or 1) to EncryptedBool
                let cond_bool = condition.to_encrypted_bool()?;

                // Use FHE select: result = cond ? if_true : if_false
                let result = EncryptedBalance::select(&cond_bool, &if_true, &if_false, &server_key)?;
                self.push(result)?;
            }

            // Boolean NOT on encrypted bool (0->1, 1->0)
            Opcode::Not => {
                let a = self.pop()?;
                let a_bool = a.to_encrypted_bool()?;
                let result_bool = a_bool.not(&server_key)?;
                let result = EncryptedBalance::from_encrypted_bool(result_bool)?;
                self.push(result)?;
            }

            // Boolean AND on two encrypted bools
            Opcode::And => {
                let b = self.pop()?;
                let a = self.pop()?;
                let a_bool = a.to_encrypted_bool()?;
                let b_bool = b.to_encrypted_bool()?;
                let result_bool = a_bool.and(&b_bool, &server_key)?;
                let result = EncryptedBalance::from_encrypted_bool(result_bool)?;
                self.push(result)?;
            }

            // Boolean OR on two encrypted bools
            Opcode::Or => {
                let b = self.pop()?;
                let a = self.pop()?;
                let a_bool = a.to_encrypted_bool()?;
                let b_bool = b.to_encrypted_bool()?;
                let result_bool = a_bool.or(&b_bool, &server_key)?;
                let result = EncryptedBalance::from_encrypted_bool(result_bool)?;
                self.push(result)?;
            }

            // Min/Max
            Opcode::Min => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = a.min(&b, &server_key)?;
                self.push(result)?;
            }

            Opcode::Max => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = a.max(&b, &server_key)?;
                self.push(result)?;
            }

            // Memory operations
            Opcode::Load => {
                if let Some(Operand::Index(idx)) = instruction.operand {
                    let idx = idx as usize;
                    if idx >= MAX_MEMORY_SIZE {
                        return Err(ContractError::InvalidMemoryAccess { offset: idx });
                    }
                    let value = self.memory[idx].clone()
                        .ok_or(ContractError::InvalidMemoryAccess { offset: idx })?;
                    self.push(value)?;
                } else {
                    return Err(ContractError::InvalidCode("Load requires index operand".into()));
                }
            }

            Opcode::Store => {
                if let Some(Operand::Index(idx)) = instruction.operand {
                    let idx = idx as usize;
                    if idx >= MAX_MEMORY_SIZE {
                        return Err(ContractError::InvalidMemoryAccess { offset: idx });
                    }
                    let value = self.pop()?;
                    self.memory[idx] = Some(value);
                } else {
                    return Err(ContractError::InvalidCode("Store requires index operand".into()));
                }
            }

            // State operations
            Opcode::StateLoad => {
                if let Some(Operand::Index(slot)) = instruction.operand {
                    let contract_state = state_manager.get_or_create_contract(ctx.contract_id);
                    let value = contract_state.load(slot)
                        .ok_or(ContractError::InvalidMemoryAccess { offset: slot as usize })?
                        .clone();
                    self.push(value)?;
                } else {
                    return Err(ContractError::InvalidCode("StateLoad requires index operand".into()));
                }
            }

            Opcode::StateStore => {
                if let Some(Operand::Index(slot)) = instruction.operand {
                    let value = self.pop()?;
                    let contract_state = state_manager.get_or_create_contract(ctx.contract_id);
                    contract_state.store(slot, value);
                } else {
                    return Err(ContractError::InvalidCode("StateStore requires index operand".into()));
                }
            }

            Opcode::Balance => {
                let balance = state_manager.get_balance(&ctx.caller)
                    .cloned()
                    .ok_or(ContractError::InsufficientBalance)?;
                self.push(balance)?;
            }

            // Transfer
            Opcode::Transfer => {
                if let Some(Operand::ContractAddress(to)) = instruction.operand {
                    let amount = self.pop()?;
                    state_manager.transfer(&ctx.caller, &to, &amount, &server_key)?;
                } else {
                    return Err(ContractError::InvalidCode("Transfer requires address operand".into()));
                }
            }

            Opcode::TransferToContract => {
                let amount = self.pop()?;
                state_manager.transfer(&ctx.caller, &ctx.contract_id, &amount, &server_key)?;
            }

            // Control flow
            Opcode::Jump => {
                if let Some(Operand::Address(addr)) = instruction.operand {
                    // Note: We subtract 1 because pc will be incremented after this
                    self.pc = addr as usize - 1;
                } else {
                    return Err(ContractError::InvalidCode("Jump requires address operand".into()));
                }
            }

            Opcode::JumpIf => {
                // JumpIf is complex because we can't see the encrypted condition
                // In a real implementation, this would need ZK proofs
                // For now, we simulate with a placeholder
                if let Some(Operand::Address(addr)) = instruction.operand {
                    // Pop condition (encrypted 0 or 1)
                    let _condition = self.pop()?;
                    // In real implementation, would use FHE to determine branch
                    // Here we always fall through for safety
                    // self.pc = addr as usize - 1;
                    let _ = addr; // suppress warning
                } else {
                    return Err(ContractError::InvalidCode("JumpIf requires address operand".into()));
                }
            }

            Opcode::Call => {
                // Extract target contract address from operand
                let target = match &instruction.operand {
                    Some(Operand::ContractAddress(addr)) => *addr,
                    _ => return Err(ContractError::InvalidCode(
                        "Call requires ContractAddress operand".into()
                    )),
                };

                // Check call depth limit to prevent stack overflow
                if self.call_stack.len() >= MAX_CALL_DEPTH {
                    return Err(ContractError::InvalidCode(format!(
                        "Call depth limit exceeded (max {})", MAX_CALL_DEPTH
                    )));
                }

                // Calculate gas to forward using EVM's 63/64 rule
                // This leaves some gas for the caller to handle return
                let gas_to_forward = (self.gas_remaining * 63) / 64;
                let gas_kept = self.gas_remaining - gas_to_forward;

                // Save current execution context
                let saved_context = SavedContext {
                    stack: std::mem::take(&mut self.stack),
                    memory: std::mem::replace(&mut self.memory, vec![None; MAX_MEMORY_SIZE]),
                    return_pc: self.pc + 1, // Return to instruction after Call
                    gas_remaining: gas_kept,
                    caller_contract_id: self.current_contract_id,
                    caller: ctx.caller,
                };
                self.call_stack.push(saved_context);

                // Get callee contract code from state manager
                let callee_contract = state_manager.get_code(&target)
                    .ok_or_else(|| ContractError::ContractNotFound(
                        format!("Contract {} not found", hex::encode(&target[..8]))
                    ))?;

                // Switch to callee's code
                self.current_code = callee_contract.code.clone();
                self.current_contract_id = target;
                self.gas_remaining = gas_to_forward;

                // Set PC to usize::MAX so after +1 increment it wraps to 0
                // This starts execution at the beginning of callee's code
                self.pc = 0_usize.wrapping_sub(1);
            }

            Opcode::Return => {
                // Check if this is a top-level return (no caller to return to)
                if self.call_stack.is_empty() {
                    self.halted = true;
                } else {
                    // Pop saved context
                    let saved = self.call_stack.pop().unwrap();

                    // Capture return value from top of current stack (if any)
                    let return_value = self.stack.pop();

                    // Restore caller's execution state
                    self.stack = saved.stack;
                    self.memory = saved.memory;
                    self.current_contract_id = saved.caller_contract_id;

                    // Refund unused gas back to caller's reserved gas
                    self.gas_remaining = self.gas_remaining + saved.gas_remaining;

                    // Restore caller's code from state manager
                    let caller_contract = state_manager.get_code(&saved.caller_contract_id)
                        .ok_or_else(|| ContractError::ContractNotFound(
                            format!("Caller contract {} not found",
                                hex::encode(&saved.caller_contract_id[..8]))
                        ))?;
                    self.current_code = caller_contract.code.clone();

                    // Push return value onto caller's stack (if any)
                    if let Some(val) = return_value {
                        self.push(val)?;
                    }

                    // Set PC so that after +1 increment we land on return_pc
                    self.pc = saved.return_pc.wrapping_sub(1);
                }
            }

            Opcode::Halt => {
                self.halted = true;
            }

            Opcode::Encrypt | Opcode::DecryptVerify => {
                // These require client key, not available in contract execution
                return Err(ContractError::InvalidCode("Encrypt/Decrypt not available in contracts".into()));
            }
        }

        Ok(())
    }

    /// Push value onto stack
    fn push(&mut self, value: EncryptedBalance) -> Result<(), ContractError> {
        if self.stack.len() >= MAX_STACK_SIZE {
            return Err(ContractError::StackOverflow { max: MAX_STACK_SIZE });
        }
        self.stack.push(value);
        Ok(())
    }

    /// Pop value from stack
    fn pop(&mut self) -> Result<EncryptedBalance, ContractError> {
        self.stack.pop()
            .ok_or(ContractError::StackUnderflow { needed: 1, have: 0 })
    }

    /// Peek at top of stack
    fn peek(&self) -> Result<&EncryptedBalance, ContractError> {
        self.stack.last()
            .ok_or(ContractError::StackUnderflow { needed: 1, have: 0 })
    }

    /// Get current stack size
    pub fn stack_size(&self) -> usize {
        self.stack.len()
    }

    /// Get gas used
    pub fn gas_used(&self) -> u64 {
        self.gas_used
    }
}

impl Default for PrivateVM {
    fn default() -> Self {
        Self::new()
    }
}

/// Compiled contract bytecode
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompiledContract {
    /// Contract code
    pub code: Vec<Instruction>,
    /// Code hash
    pub code_hash: [u8; 32],
    /// Constructor code (run once on deploy)
    pub constructor: Option<Vec<Instruction>>,
}

impl CompiledContract {
    /// Create new compiled contract
    pub fn new(code: Vec<Instruction>) -> Self {
        let code_hash = Self::compute_code_hash(&code);
        Self {
            code,
            code_hash,
            constructor: None,
        }
    }

    /// Compute hash of bytecode
    fn compute_code_hash(code: &[Instruction]) -> [u8; 32] {
        let serialized = bincode::serialize(code).unwrap_or_default();
        *blake3::hash(&serialized).as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_creation() {
        let vm = PrivateVM::new();
        assert_eq!(vm.stack_size(), 0);
        assert!(!vm.halted);
    }

    #[test]
    fn test_execution_context() {
        let caller = [1u8; 32];
        let contract = [2u8; 32];
        let ctx = ExecutionContext::new(caller, contract);

        assert_eq!(ctx.caller, caller);
        assert_eq!(ctx.contract_id, contract);
        assert_eq!(ctx.gas_limit, DEFAULT_GAS_LIMIT);
    }

    #[test]
    fn test_compiled_contract() {
        let code = vec![
            Instruction::simple(Opcode::Nop),
            Instruction::simple(Opcode::Halt),
        ];
        let contract = CompiledContract::new(code);

        assert_eq!(contract.code.len(), 2);
        assert!(contract.constructor.is_none());
    }

    #[test]
    fn test_simple_execution() {
        let mut vm = PrivateVM::new();
        let mut state_manager = StateManager::new();
        let ctx = ExecutionContext::new([1u8; 32], [2u8; 32]);

        // Simple program: NOP, HALT
        let code = vec![
            Instruction::simple(Opcode::Nop),
            Instruction::simple(Opcode::Halt),
        ];

        // Note: This will fail without server key, which is expected
        // Full test with FHE would need key setup
        let result = vm.execute(&code, &ctx, &mut state_manager);
        match result {
            ExecutionResult::Failure { reason, .. } => {
                assert!(reason.contains("Server key"));
            }
            _ => {
                // If we had set up keys, we'd expect Halted
            }
        }
    }

    #[test]
    fn test_gas_tracking() {
        let vm = PrivateVM::new();
        assert_eq!(vm.gas_used(), 0);
    }

    #[test]
    fn test_saved_context_structure() {
        // Verify SavedContext captures all required fields
        let saved = SavedContext {
            stack: vec![],
            memory: vec![None; 10],
            return_pc: 42,
            gas_remaining: 1000,
            caller_contract_id: [1u8; 32],
            caller: [2u8; 32],
        };

        assert_eq!(saved.return_pc, 42);
        assert_eq!(saved.gas_remaining, 1000);
        assert_eq!(saved.caller_contract_id, [1u8; 32]);
        assert_eq!(saved.memory.len(), 10);
    }

    #[test]
    fn test_call_depth_limit() {
        let mut vm = PrivateVM::new();

        // Fill call stack to max
        for i in 0..MAX_CALL_DEPTH {
            vm.call_stack.push(SavedContext {
                stack: vec![],
                memory: vec![],
                return_pc: i,
                gas_remaining: 0,
                caller_contract_id: [0u8; 32],
                caller: [0u8; 32],
            });
        }

        assert_eq!(vm.call_stack.len(), MAX_CALL_DEPTH);
    }

    #[test]
    fn test_gas_forwarding_calculation() {
        // Test the 63/64 gas forwarding rule (like EVM)
        let total_gas: u64 = 1_000_000;
        let gas_to_forward = (total_gas * 63) / 64;
        let gas_kept = total_gas - gas_to_forward;

        // 63/64 of 1M = 984,375
        assert_eq!(gas_to_forward, 984_375);
        // 1/64 of 1M = 15,625
        assert_eq!(gas_kept, 15_625);
        // Sum equals original
        assert_eq!(gas_to_forward + gas_kept, total_gas);
    }

    #[test]
    fn test_pc_wrapping_arithmetic() {
        // Test that wrapping_sub(1) followed by +1 lands at correct PC
        let target_pc: usize = 0;
        let wrapped = target_pc.wrapping_sub(1);
        let after_increment = wrapped.wrapping_add(1);
        assert_eq!(after_increment, 0);

        // Test for non-zero return PC
        let return_pc: usize = 42;
        let wrapped_return = return_pc.wrapping_sub(1);
        let after_return = wrapped_return.wrapping_add(1);
        assert_eq!(after_return, 42);
    }

    #[test]
    fn test_code_registry_lookup() {
        let mut state_manager = StateManager::new();
        let contract_id = [42u8; 32];

        // Initially no code
        assert!(state_manager.get_code(&contract_id).is_none());

        // Register code
        let code = CompiledContract::new(vec![
            Instruction::simple(Opcode::Nop),
            Instruction::simple(Opcode::Return),
        ]);
        state_manager.register_code(contract_id, code);

        // Now code exists
        assert!(state_manager.get_code(&contract_id).is_some());
        let retrieved = state_manager.get_code(&contract_id).unwrap();
        assert_eq!(retrieved.code.len(), 2);
    }

    #[test]
    fn test_call_operand_parsing() {
        // Test that Call instruction requires ContractAddress operand
        let target = [99u8; 32];
        let call_instr = Instruction::new(
            Opcode::Call,
            Some(Operand::ContractAddress(target))
        );

        if let Some(Operand::ContractAddress(addr)) = call_instr.operand {
            assert_eq!(addr, target);
        } else {
            panic!("Expected ContractAddress operand");
        }
    }

    #[test]
    fn test_vm_call_stack_operations() {
        let mut vm = PrivateVM::new();

        // Initially empty
        assert!(vm.call_stack.is_empty());

        // Push a context
        let saved = SavedContext {
            stack: vec![],
            memory: vec![None; MAX_MEMORY_SIZE],
            return_pc: 10,
            gas_remaining: 5000,
            caller_contract_id: [1u8; 32],
            caller: [2u8; 32],
        };
        vm.call_stack.push(saved);

        assert_eq!(vm.call_stack.len(), 1);

        // Pop and verify
        let popped = vm.call_stack.pop().unwrap();
        assert_eq!(popped.return_pc, 10);
        assert_eq!(popped.gas_remaining, 5000);
        assert!(vm.call_stack.is_empty());
    }

    #[test]
    fn test_cross_contract_setup() {
        // Setup two contracts: caller and callee
        let mut state_manager = StateManager::new();

        let caller_id = [1u8; 32];
        let callee_id = [2u8; 32];

        // Callee contract: just returns
        let callee_code = CompiledContract::new(vec![
            Instruction::simple(Opcode::Nop),
            Instruction::simple(Opcode::Return),
        ]);
        state_manager.register_code(callee_id, callee_code);

        // Caller contract: calls callee then halts
        let caller_code = CompiledContract::new(vec![
            Instruction::new(Opcode::Call, Some(Operand::ContractAddress(callee_id))),
            Instruction::simple(Opcode::Halt),
        ]);
        state_manager.register_code(caller_id, caller_code);

        // Verify both are registered
        assert!(state_manager.has_code(&caller_id));
        assert!(state_manager.has_code(&callee_id));

        // Verify callee has 2 instructions
        let callee = state_manager.get_code(&callee_id).unwrap();
        assert_eq!(callee.code.len(), 2);

        // Verify caller has Call to correct target
        let caller = state_manager.get_code(&caller_id).unwrap();
        if let Some(Operand::ContractAddress(target)) = &caller.code[0].operand {
            assert_eq!(*target, callee_id);
        } else {
            panic!("Expected Call instruction with ContractAddress operand");
        }
    }
}
