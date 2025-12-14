//! PHANTOM Private Smart Contracts
//!
//! Smart contracts with encrypted state and ZK-verified execution.
//! All contract logic and state remain private using FHE.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │              Contract Execution Flow                 │
//! ├─────────────────────────────────────────────────────┤
//! │  Contract Code (Opcodes)                            │
//! │      ↓                                              │
//! │  PrivateVM (Stack-based, FHE operations)            │
//! │      ↓                                              │
//! │  ContractState (Encrypted storage slots)            │
//! │      ↓                                              │
//! │  StateManager (Global state, balances)              │
//! └─────────────────────────────────────────────────────┘
//! ```
//!
//! # Key Features
//!
//! - **Encrypted State**: All contract storage is FHE-encrypted
//! - **Homomorphic Operations**: Add, subtract, compare without decryption
//! - **Gas Metering**: Prevents infinite loops, charges for FHE operations
//! - **Contract Templates**: Pre-built token, escrow, voting contracts

pub mod abi;
pub mod errors;
pub mod opcodes;
pub mod state;
pub mod vm;
pub mod contract;

// Re-export main types
pub use abi::{ABIDecoder, ABIEncoder, ABIType, ABIValue, ContractABI, FunctionABI};
pub use errors::ContractError;
pub use opcodes::{Instruction, Opcode, Operand};
pub use state::{ContractState, StateManager};
pub use vm::{CompiledContract, ExecutionContext, ExecutionResult, PrivateVM};
pub use contract::{Contract, ContractCall, ContractDeployer};

/// Prelude for convenient imports
pub mod prelude {
    pub use crate::abi::{ABIDecoder, ABIEncoder, ABIType, ABIValue, ContractABI, FunctionABI};
    pub use crate::contract::{Contract, ContractCall, ContractDeployer};
    pub use crate::errors::ContractError;
    pub use crate::opcodes::{Instruction, Opcode, Operand};
    pub use crate::state::{ContractState, StateManager};
    pub use crate::vm::{CompiledContract, ExecutionContext, ExecutionResult, PrivateVM};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prelude_imports() {
        // Verify all prelude types are accessible
        let _ = ContractError::ServerKeyNotSet;
        let _ = Opcode::Nop;
        let _ = StateManager::new();
        let _ = PrivateVM::new();
    }
}
