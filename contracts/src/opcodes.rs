//! VM Opcodes for private smart contracts
//!
//! These opcodes operate on encrypted values using FHE.
//! All arithmetic is performed homomorphically.

use serde::{Deserialize, Serialize};

/// Opcodes for the private VM
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Opcode {
    // Stack operations
    /// Push encrypted constant to stack
    Push = 0x01,
    /// Pop value from stack
    Pop = 0x02,
    /// Duplicate top of stack
    Dup = 0x03,
    /// Swap top two stack values
    Swap = 0x04,

    // Homomorphic arithmetic (operates on encrypted values)
    /// Add top two encrypted values: result = a + b (encrypted)
    Add = 0x10,
    /// Subtract: result = a - b (encrypted)
    Sub = 0x11,
    /// Multiply: result = a * b (encrypted)
    Mul = 0x12,

    // Scalar operations (encrypted value with plaintext scalar)
    /// Add scalar: result = encrypted + plaintext
    AddScalar = 0x18,
    /// Subtract scalar: result = encrypted - plaintext
    SubScalar = 0x19,
    /// Multiply by scalar: result = encrypted * plaintext
    MulScalar = 0x1A,

    // Comparison operations (return encrypted boolean)
    /// Less than: result = (a < b) as encrypted bool
    Lt = 0x20,
    /// Less than or equal: result = (a <= b)
    Le = 0x21,
    /// Greater than: result = (a > b)
    Gt = 0x22,
    /// Greater than or equal: result = (a >= b)
    Ge = 0x23,
    /// Equal: result = (a == b)
    Eq = 0x24,
    /// Conditional select: if condition then if_true else if_false
    /// Stack: [condition, if_false, if_true] -> [result]
    /// This is the FHE-safe way to do conditionals (oblivious execution)
    Select = 0x25,
    /// Boolean NOT on encrypted bool (0->1, 1->0)
    Not = 0x26,
    /// Boolean AND on two encrypted bools
    And = 0x27,
    /// Boolean OR on two encrypted bools
    Or = 0x28,

    // Min/Max operations
    /// Minimum of two encrypted values
    Min = 0x2A,
    /// Maximum of two encrypted values
    Max = 0x2B,

    // Memory operations
    /// Load encrypted value from memory
    Load = 0x30,
    /// Store encrypted value to memory
    Store = 0x31,

    // State operations
    /// Load from contract state (encrypted)
    StateLoad = 0x40,
    /// Store to contract state (encrypted)
    StateStore = 0x41,
    /// Get caller's encrypted balance
    Balance = 0x42,

    // Transfer operations
    /// Transfer encrypted amount from caller to address
    Transfer = 0x50,
    /// Transfer encrypted amount to contract
    TransferToContract = 0x51,

    // Control flow
    /// Conditional jump (based on encrypted comparison)
    JumpIf = 0x60,
    /// Unconditional jump
    Jump = 0x61,
    /// Call another contract
    Call = 0x62,
    /// Return from contract
    Return = 0x70,

    // Special operations
    /// No operation
    Nop = 0x00,
    /// Halt execution
    Halt = 0xFF,

    // Encryption/Decryption (only for authorized parties)
    /// Encrypt plaintext value (requires public key)
    Encrypt = 0x80,
    /// Decrypt to verify (only with private key, leaves proof)
    DecryptVerify = 0x81,
}

impl Opcode {
    /// Parse opcode from byte
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Opcode::Nop),
            0x01 => Some(Opcode::Push),
            0x02 => Some(Opcode::Pop),
            0x03 => Some(Opcode::Dup),
            0x04 => Some(Opcode::Swap),
            0x10 => Some(Opcode::Add),
            0x11 => Some(Opcode::Sub),
            0x12 => Some(Opcode::Mul),
            0x18 => Some(Opcode::AddScalar),
            0x19 => Some(Opcode::SubScalar),
            0x1A => Some(Opcode::MulScalar),
            0x20 => Some(Opcode::Lt),
            0x21 => Some(Opcode::Le),
            0x22 => Some(Opcode::Gt),
            0x23 => Some(Opcode::Ge),
            0x24 => Some(Opcode::Eq),
            0x25 => Some(Opcode::Select),
            0x26 => Some(Opcode::Not),
            0x27 => Some(Opcode::And),
            0x28 => Some(Opcode::Or),
            0x2A => Some(Opcode::Min),
            0x2B => Some(Opcode::Max),
            0x30 => Some(Opcode::Load),
            0x31 => Some(Opcode::Store),
            0x40 => Some(Opcode::StateLoad),
            0x41 => Some(Opcode::StateStore),
            0x42 => Some(Opcode::Balance),
            0x50 => Some(Opcode::Transfer),
            0x51 => Some(Opcode::TransferToContract),
            0x60 => Some(Opcode::JumpIf),
            0x61 => Some(Opcode::Jump),
            0x62 => Some(Opcode::Call),
            0x70 => Some(Opcode::Return),
            0x80 => Some(Opcode::Encrypt),
            0x81 => Some(Opcode::DecryptVerify),
            0xFF => Some(Opcode::Halt),
            _ => None,
        }
    }

    /// Get gas cost for operation
    pub fn gas_cost(&self) -> u64 {
        match self {
            // Stack operations (cheap)
            Opcode::Nop => 1,
            Opcode::Push => 3,
            Opcode::Pop => 2,
            Opcode::Dup => 3,
            Opcode::Swap => 3,

            // Homomorphic operations (expensive)
            Opcode::Add => 100,
            Opcode::Sub => 100,
            Opcode::Mul => 500,
            Opcode::AddScalar => 50,
            Opcode::SubScalar => 50,
            Opcode::MulScalar => 100,

            // Comparisons
            Opcode::Lt => 200,
            Opcode::Le => 200,
            Opcode::Gt => 200,
            Opcode::Ge => 200,
            Opcode::Eq => 200,
            Opcode::Select => 300, // FHE select is moderately expensive
            Opcode::Not => 50,     // Boolean ops are cheaper
            Opcode::And => 100,
            Opcode::Or => 100,
            Opcode::Min => 250,
            Opcode::Max => 250,

            // Memory (moderate)
            Opcode::Load => 20,
            Opcode::Store => 20,
            Opcode::StateLoad => 200,
            Opcode::StateStore => 5000, // Storage is expensive
            Opcode::Balance => 100,

            // Transfers
            Opcode::Transfer => 21000,
            Opcode::TransferToContract => 21000,

            // Control flow
            Opcode::JumpIf => 10,
            Opcode::Jump => 8,
            Opcode::Call => 700,
            Opcode::Return => 5,

            // Crypto
            Opcode::Encrypt => 10000,
            Opcode::DecryptVerify => 10000,

            Opcode::Halt => 0,
        }
    }
}

/// A compiled instruction with its operands
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Instruction {
    pub opcode: Opcode,
    pub operand: Option<Operand>,
}

/// Operand types for instructions
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Operand {
    /// Immediate encrypted value (serialized ciphertext)
    EncryptedValue(Vec<u8>),
    /// Immediate plaintext value for scalar operations
    Plaintext(u64),
    /// Memory/state slot index
    Index(u32),
    /// Jump target address
    Address(u32),
    /// Contract address (32 bytes)
    ContractAddress([u8; 32]),
}

impl Instruction {
    /// Create a new instruction
    pub fn new(opcode: Opcode, operand: Option<Operand>) -> Self {
        Self { opcode, operand }
    }

    /// Create a simple instruction without operand
    pub fn simple(opcode: Opcode) -> Self {
        Self { opcode, operand: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_roundtrip() {
        for byte in 0..=255u8 {
            if let Some(opcode) = Opcode::from_byte(byte) {
                assert_eq!(byte, opcode as u8);
            }
        }
    }

    #[test]
    fn test_gas_costs() {
        assert!(Opcode::Mul.gas_cost() > Opcode::Add.gas_cost());
        assert!(Opcode::StateStore.gas_cost() > Opcode::StateLoad.gas_cost());
        assert!(Opcode::Transfer.gas_cost() > 0);
    }
}
