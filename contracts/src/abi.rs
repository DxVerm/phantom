//! Contract ABI (Application Binary Interface) for PHANTOM
//!
//! Provides function selectors, parameter encoding/decoding for private contracts.
//! Function selectors use first 4 bytes of blake3 hash (similar to EVM's keccak256).

use crate::errors::ContractError;
use phantom_esl::EncryptedBalance;
use serde::{Deserialize, Serialize};

/// Size of function selector in bytes (first 4 bytes of blake3 hash)
pub const SELECTOR_SIZE: usize = 4;

/// Maximum encoded parameter size (64KB per parameter)
pub const MAX_PARAM_SIZE: usize = 65536;

/// ABI type identifiers for encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ABIType {
    /// Unsigned 64-bit integer
    Uint64 = 0,
    /// Signed 64-bit integer
    Int64 = 1,
    /// Boolean value
    Bool = 2,
    /// 32-byte address/identifier
    Address = 3,
    /// Fixed-size bytes (32 bytes)
    Bytes32 = 4,
    /// Variable-size bytes
    Bytes = 5,
    /// Encrypted balance (FHE ciphertext)
    EncryptedUint64 = 6,
    /// Array of ABI values
    Array = 7,
}

impl ABIType {
    /// Convert byte to ABIType
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(ABIType::Uint64),
            1 => Some(ABIType::Int64),
            2 => Some(ABIType::Bool),
            3 => Some(ABIType::Address),
            4 => Some(ABIType::Bytes32),
            5 => Some(ABIType::Bytes),
            6 => Some(ABIType::EncryptedUint64),
            7 => Some(ABIType::Array),
            _ => None,
        }
    }

    /// Get canonical type string for signature
    pub fn type_string(&self) -> &'static str {
        match self {
            ABIType::Uint64 => "uint64",
            ABIType::Int64 => "int64",
            ABIType::Bool => "bool",
            ABIType::Address => "address",
            ABIType::Bytes32 => "bytes32",
            ABIType::Bytes => "bytes",
            ABIType::EncryptedUint64 => "encrypted_uint64",
            ABIType::Array => "array",
        }
    }
}

/// ABI value - typed parameter value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ABIValue {
    Uint64(u64),
    Int64(i64),
    Bool(bool),
    Address([u8; 32]),
    Bytes32([u8; 32]),
    Bytes(Vec<u8>),
    EncryptedUint64(EncryptedBalance),
    Array(Vec<ABIValue>),
}

impl ABIValue {
    /// Get the type of this value
    pub fn abi_type(&self) -> ABIType {
        match self {
            ABIValue::Uint64(_) => ABIType::Uint64,
            ABIValue::Int64(_) => ABIType::Int64,
            ABIValue::Bool(_) => ABIType::Bool,
            ABIValue::Address(_) => ABIType::Address,
            ABIValue::Bytes32(_) => ABIType::Bytes32,
            ABIValue::Bytes(_) => ABIType::Bytes,
            ABIValue::EncryptedUint64(_) => ABIType::EncryptedUint64,
            ABIValue::Array(_) => ABIType::Array,
        }
    }

    /// Extract u64 value
    pub fn as_uint64(&self) -> Result<u64, ContractError> {
        match self {
            ABIValue::Uint64(v) => Ok(*v),
            _ => Err(ContractError::ABIDecodingError(
                format!("Expected uint64, got {:?}", self.abi_type())
            )),
        }
    }

    /// Extract i64 value
    pub fn as_int64(&self) -> Result<i64, ContractError> {
        match self {
            ABIValue::Int64(v) => Ok(*v),
            _ => Err(ContractError::ABIDecodingError(
                format!("Expected int64, got {:?}", self.abi_type())
            )),
        }
    }

    /// Extract bool value
    pub fn as_bool(&self) -> Result<bool, ContractError> {
        match self {
            ABIValue::Bool(v) => Ok(*v),
            _ => Err(ContractError::ABIDecodingError(
                format!("Expected bool, got {:?}", self.abi_type())
            )),
        }
    }

    /// Extract address value
    pub fn as_address(&self) -> Result<[u8; 32], ContractError> {
        match self {
            ABIValue::Address(v) => Ok(*v),
            _ => Err(ContractError::ABIDecodingError(
                format!("Expected address, got {:?}", self.abi_type())
            )),
        }
    }

    /// Extract bytes32 value
    pub fn as_bytes32(&self) -> Result<[u8; 32], ContractError> {
        match self {
            ABIValue::Bytes32(v) => Ok(*v),
            _ => Err(ContractError::ABIDecodingError(
                format!("Expected bytes32, got {:?}", self.abi_type())
            )),
        }
    }

    /// Extract bytes value
    pub fn as_bytes(&self) -> Result<&[u8], ContractError> {
        match self {
            ABIValue::Bytes(v) => Ok(v),
            _ => Err(ContractError::ABIDecodingError(
                format!("Expected bytes, got {:?}", self.abi_type())
            )),
        }
    }

    /// Extract encrypted value
    pub fn as_encrypted(&self) -> Result<&EncryptedBalance, ContractError> {
        match self {
            ABIValue::EncryptedUint64(v) => Ok(v),
            _ => Err(ContractError::ABIDecodingError(
                format!("Expected encrypted_uint64, got {:?}", self.abi_type())
            )),
        }
    }

    /// Extract array value
    pub fn as_array(&self) -> Result<&[ABIValue], ContractError> {
        match self {
            ABIValue::Array(v) => Ok(v),
            _ => Err(ContractError::ABIDecodingError(
                format!("Expected array, got {:?}", self.abi_type())
            )),
        }
    }
}

/// Compute function selector from signature string
///
/// Uses first 4 bytes of blake3 hash of the canonical function signature.
/// Example: "transfer(address,uint64)" -> [0x12, 0x34, 0x56, 0x78]
pub fn compute_selector(signature: &str) -> [u8; SELECTOR_SIZE] {
    let hash = blake3::hash(signature.as_bytes());
    let bytes = hash.as_bytes();
    [bytes[0], bytes[1], bytes[2], bytes[3]]
}

/// Build canonical function signature from name and parameter types
pub fn build_signature(name: &str, param_types: &[ABIType]) -> String {
    let types: Vec<&str> = param_types.iter().map(|t| t.type_string()).collect();
    format!("{}({})", name, types.join(","))
}

/// Function ABI definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionABI {
    /// Function name
    pub name: String,
    /// 4-byte function selector
    pub selector: [u8; SELECTOR_SIZE],
    /// Input parameter types
    pub inputs: Vec<ABIType>,
    /// Output parameter types
    pub outputs: Vec<ABIType>,
    /// Whether function mutates state
    pub mutates: bool,
}

impl FunctionABI {
    /// Create new function ABI
    pub fn new(name: &str, inputs: Vec<ABIType>, outputs: Vec<ABIType>, mutates: bool) -> Self {
        let signature = build_signature(name, &inputs);
        let selector = compute_selector(&signature);
        Self {
            name: name.to_string(),
            selector,
            inputs,
            outputs,
            mutates,
        }
    }

    /// Get canonical signature string
    pub fn signature(&self) -> String {
        build_signature(&self.name, &self.inputs)
    }

    /// Check if selector matches
    pub fn matches_selector(&self, selector: &[u8]) -> bool {
        selector.len() >= SELECTOR_SIZE && self.selector == selector[..SELECTOR_SIZE]
    }

    /// Validate input parameters
    pub fn validate_inputs(&self, params: &[ABIValue]) -> Result<(), ContractError> {
        if params.len() != self.inputs.len() {
            return Err(ContractError::ParameterCountMismatch {
                expected: self.inputs.len(),
                got: params.len(),
            });
        }

        for (i, (param, expected_type)) in params.iter().zip(self.inputs.iter()).enumerate() {
            if param.abi_type() != *expected_type {
                return Err(ContractError::InvalidParameterType {
                    index: i,
                    message: format!(
                        "expected {:?}, got {:?}",
                        expected_type,
                        param.abi_type()
                    ),
                });
            }
        }

        Ok(())
    }
}

/// Contract ABI - collection of function ABIs
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContractABI {
    /// Contract name
    pub name: String,
    /// Function definitions
    pub functions: Vec<FunctionABI>,
}

impl ContractABI {
    /// Create new contract ABI
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            functions: Vec::new(),
        }
    }

    /// Add function to ABI
    pub fn add_function(&mut self, function: FunctionABI) {
        self.functions.push(function);
    }

    /// Find function by selector
    pub fn get_function_by_selector(&self, selector: &[u8]) -> Option<&FunctionABI> {
        self.functions.iter().find(|f| f.matches_selector(selector))
    }

    /// Find function by name
    pub fn get_function_by_name(&self, name: &str) -> Option<&FunctionABI> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Get all function selectors
    pub fn selectors(&self) -> Vec<[u8; SELECTOR_SIZE]> {
        self.functions.iter().map(|f| f.selector).collect()
    }
}

/// ABI Encoder - encodes typed parameters into bytes
pub struct ABIEncoder {
    buffer: Vec<u8>,
}

impl ABIEncoder {
    /// Create new encoder
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Create encoder with function selector prefix
    pub fn with_selector(selector: [u8; SELECTOR_SIZE]) -> Self {
        let mut encoder = Self::new();
        encoder.buffer.extend_from_slice(&selector);
        encoder
    }

    /// Encode a value
    pub fn encode(&mut self, value: &ABIValue) -> Result<(), ContractError> {
        // Write type tag
        self.buffer.push(value.abi_type() as u8);

        match value {
            ABIValue::Uint64(v) => {
                self.buffer.extend_from_slice(&v.to_le_bytes());
            }
            ABIValue::Int64(v) => {
                self.buffer.extend_from_slice(&v.to_le_bytes());
            }
            ABIValue::Bool(v) => {
                self.buffer.push(if *v { 1 } else { 0 });
            }
            ABIValue::Address(v) => {
                self.buffer.extend_from_slice(v);
            }
            ABIValue::Bytes32(v) => {
                self.buffer.extend_from_slice(v);
            }
            ABIValue::Bytes(v) => {
                if v.len() > MAX_PARAM_SIZE {
                    return Err(ContractError::ABIEncodingError(
                        format!("Bytes too large: {} > {}", v.len(), MAX_PARAM_SIZE)
                    ));
                }
                // Write length as u32
                self.buffer.extend_from_slice(&(v.len() as u32).to_le_bytes());
                self.buffer.extend_from_slice(v);
            }
            ABIValue::EncryptedUint64(v) => {
                // Serialize encrypted value using bincode
                let encoded = bincode::serialize(v)
                    .map_err(|e| ContractError::ABIEncodingError(e.to_string()))?;
                if encoded.len() > MAX_PARAM_SIZE {
                    return Err(ContractError::ABIEncodingError(
                        format!("Encrypted value too large: {} > {}", encoded.len(), MAX_PARAM_SIZE)
                    ));
                }
                self.buffer.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
                self.buffer.extend_from_slice(&encoded);
            }
            ABIValue::Array(values) => {
                // Write array length
                self.buffer.extend_from_slice(&(values.len() as u32).to_le_bytes());
                for v in values {
                    self.encode(v)?;
                }
            }
        }

        Ok(())
    }

    /// Encode multiple values
    pub fn encode_all(&mut self, values: &[ABIValue]) -> Result<(), ContractError> {
        for value in values {
            self.encode(value)?;
        }
        Ok(())
    }

    /// Get encoded bytes
    pub fn finish(self) -> Vec<u8> {
        self.buffer
    }

    /// Get current buffer length
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

impl Default for ABIEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// ABI Decoder - decodes bytes into typed parameters
pub struct ABIDecoder<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> ABIDecoder<'a> {
    /// Create new decoder
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    /// Create decoder skipping function selector
    pub fn skip_selector(data: &'a [u8]) -> Result<Self, ContractError> {
        if data.len() < SELECTOR_SIZE {
            return Err(ContractError::ABIDecodingError(
                "Data too short for selector".to_string()
            ));
        }
        Ok(Self {
            data,
            position: SELECTOR_SIZE,
        })
    }

    /// Read function selector
    pub fn read_selector(&mut self) -> Result<[u8; SELECTOR_SIZE], ContractError> {
        if self.remaining() < SELECTOR_SIZE {
            return Err(ContractError::ABIDecodingError(
                "Not enough data for selector".to_string()
            ));
        }
        let selector = [
            self.data[self.position],
            self.data[self.position + 1],
            self.data[self.position + 2],
            self.data[self.position + 3],
        ];
        self.position += SELECTOR_SIZE;
        Ok(selector)
    }

    /// Decode next value
    pub fn decode(&mut self) -> Result<ABIValue, ContractError> {
        // Read type tag
        if self.remaining() < 1 {
            return Err(ContractError::ABIDecodingError(
                "Not enough data for type tag".to_string()
            ));
        }
        let type_tag = self.data[self.position];
        self.position += 1;

        let abi_type = ABIType::from_byte(type_tag)
            .ok_or_else(|| ContractError::ABIDecodingError(
                format!("Unknown type tag: {}", type_tag)
            ))?;

        match abi_type {
            ABIType::Uint64 => {
                let bytes = self.read_bytes(8)?;
                let value = u64::from_le_bytes(bytes.try_into().unwrap());
                Ok(ABIValue::Uint64(value))
            }
            ABIType::Int64 => {
                let bytes = self.read_bytes(8)?;
                let value = i64::from_le_bytes(bytes.try_into().unwrap());
                Ok(ABIValue::Int64(value))
            }
            ABIType::Bool => {
                let byte = self.read_byte()?;
                Ok(ABIValue::Bool(byte != 0))
            }
            ABIType::Address => {
                let bytes = self.read_bytes(32)?;
                let mut addr = [0u8; 32];
                addr.copy_from_slice(bytes);
                Ok(ABIValue::Address(addr))
            }
            ABIType::Bytes32 => {
                let bytes = self.read_bytes(32)?;
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                Ok(ABIValue::Bytes32(arr))
            }
            ABIType::Bytes => {
                let len = self.read_u32()? as usize;
                if len > MAX_PARAM_SIZE {
                    return Err(ContractError::ABIDecodingError(
                        format!("Bytes too large: {}", len)
                    ));
                }
                let bytes = self.read_bytes(len)?;
                Ok(ABIValue::Bytes(bytes.to_vec()))
            }
            ABIType::EncryptedUint64 => {
                let len = self.read_u32()? as usize;
                if len > MAX_PARAM_SIZE {
                    return Err(ContractError::ABIDecodingError(
                        format!("Encrypted value too large: {}", len)
                    ));
                }
                let bytes = self.read_bytes(len)?;
                let value: EncryptedBalance = bincode::deserialize(bytes)
                    .map_err(|e| ContractError::ABIDecodingError(e.to_string()))?;
                Ok(ABIValue::EncryptedUint64(value))
            }
            ABIType::Array => {
                let count = self.read_u32()? as usize;
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    values.push(self.decode()?);
                }
                Ok(ABIValue::Array(values))
            }
        }
    }

    /// Decode multiple values
    pub fn decode_all(&mut self) -> Result<Vec<ABIValue>, ContractError> {
        let mut values = Vec::new();
        while self.remaining() > 0 {
            values.push(self.decode()?);
        }
        Ok(values)
    }

    /// Decode expected number of values
    pub fn decode_n(&mut self, count: usize) -> Result<Vec<ABIValue>, ContractError> {
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.decode()?);
        }
        Ok(values)
    }

    /// Get remaining bytes count
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    /// Check if at end
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Read single byte
    fn read_byte(&mut self) -> Result<u8, ContractError> {
        if self.remaining() < 1 {
            return Err(ContractError::ABIDecodingError(
                "Not enough data".to_string()
            ));
        }
        let byte = self.data[self.position];
        self.position += 1;
        Ok(byte)
    }

    /// Read n bytes
    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], ContractError> {
        if self.remaining() < n {
            return Err(ContractError::ABIDecodingError(
                format!("Not enough data: need {}, have {}", n, self.remaining())
            ));
        }
        let bytes = &self.data[self.position..self.position + n];
        self.position += n;
        Ok(bytes)
    }

    /// Read u32 length prefix
    fn read_u32(&mut self) -> Result<u32, ContractError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }
}

/// Encode function call with selector and parameters
pub fn encode_function_call(
    function: &FunctionABI,
    params: &[ABIValue],
) -> Result<Vec<u8>, ContractError> {
    function.validate_inputs(params)?;

    let mut encoder = ABIEncoder::with_selector(function.selector);
    encoder.encode_all(params)?;
    Ok(encoder.finish())
}

/// Decode function call to extract selector and parameters
pub fn decode_function_call(
    data: &[u8],
) -> Result<([u8; SELECTOR_SIZE], Vec<ABIValue>), ContractError> {
    let mut decoder = ABIDecoder::new(data);
    let selector = decoder.read_selector()?;
    let params = decoder.decode_all()?;
    Ok((selector, params))
}

/// Encode return values
pub fn encode_return(values: &[ABIValue]) -> Result<Vec<u8>, ContractError> {
    let mut encoder = ABIEncoder::new();
    encoder.encode_all(values)?;
    Ok(encoder.finish())
}

/// Decode return values
pub fn decode_return(data: &[u8]) -> Result<Vec<ABIValue>, ContractError> {
    let mut decoder = ABIDecoder::new(data);
    decoder.decode_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selector_computation() {
        let selector = compute_selector("transfer(address,uint64)");
        // Selectors should be deterministic
        let selector2 = compute_selector("transfer(address,uint64)");
        assert_eq!(selector, selector2);

        // Different signatures should have different selectors
        let selector3 = compute_selector("transfer(address,uint64,bool)");
        assert_ne!(selector, selector3);
    }

    #[test]
    fn test_build_signature() {
        let sig = build_signature("transfer", &[ABIType::Address, ABIType::Uint64]);
        assert_eq!(sig, "transfer(address,uint64)");

        let sig2 = build_signature("approve", &[]);
        assert_eq!(sig2, "approve()");
    }

    #[test]
    fn test_function_abi() {
        let func = FunctionABI::new(
            "transfer",
            vec![ABIType::Address, ABIType::Uint64],
            vec![ABIType::Bool],
            true,
        );

        assert_eq!(func.name, "transfer");
        assert_eq!(func.inputs.len(), 2);
        assert_eq!(func.outputs.len(), 1);
        assert!(func.mutates);

        // Check signature
        assert_eq!(func.signature(), "transfer(address,uint64)");

        // Check selector matching
        let call_data = [func.selector[0], func.selector[1], func.selector[2], func.selector[3], 0, 0];
        assert!(func.matches_selector(&call_data));
    }

    #[test]
    fn test_encode_decode_uint64() {
        let value = ABIValue::Uint64(12345678);
        let mut encoder = ABIEncoder::new();
        encoder.encode(&value).unwrap();
        let encoded = encoder.finish();

        let mut decoder = ABIDecoder::new(&encoded);
        let decoded = decoder.decode().unwrap();

        assert_eq!(decoded.as_uint64().unwrap(), 12345678);
    }

    #[test]
    fn test_encode_decode_int64() {
        let value = ABIValue::Int64(-42);
        let mut encoder = ABIEncoder::new();
        encoder.encode(&value).unwrap();
        let encoded = encoder.finish();

        let mut decoder = ABIDecoder::new(&encoded);
        let decoded = decoder.decode().unwrap();

        assert_eq!(decoded.as_int64().unwrap(), -42);
    }

    #[test]
    fn test_encode_decode_bool() {
        for expected in [true, false] {
            let value = ABIValue::Bool(expected);
            let mut encoder = ABIEncoder::new();
            encoder.encode(&value).unwrap();
            let encoded = encoder.finish();

            let mut decoder = ABIDecoder::new(&encoded);
            let decoded = decoder.decode().unwrap();

            assert_eq!(decoded.as_bool().unwrap(), expected);
        }
    }

    #[test]
    fn test_encode_decode_address() {
        let addr = [42u8; 32];
        let value = ABIValue::Address(addr);
        let mut encoder = ABIEncoder::new();
        encoder.encode(&value).unwrap();
        let encoded = encoder.finish();

        let mut decoder = ABIDecoder::new(&encoded);
        let decoded = decoder.decode().unwrap();

        assert_eq!(decoded.as_address().unwrap(), addr);
    }

    #[test]
    fn test_encode_decode_bytes() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let value = ABIValue::Bytes(data.clone());
        let mut encoder = ABIEncoder::new();
        encoder.encode(&value).unwrap();
        let encoded = encoder.finish();

        let mut decoder = ABIDecoder::new(&encoded);
        let decoded = decoder.decode().unwrap();

        assert_eq!(decoded.as_bytes().unwrap(), &data[..]);
    }

    #[test]
    fn test_encode_decode_array() {
        let arr = ABIValue::Array(vec![
            ABIValue::Uint64(1),
            ABIValue::Uint64(2),
            ABIValue::Uint64(3),
        ]);

        let mut encoder = ABIEncoder::new();
        encoder.encode(&arr).unwrap();
        let encoded = encoder.finish();

        let mut decoder = ABIDecoder::new(&encoded);
        let decoded = decoder.decode().unwrap();

        let values = decoded.as_array().unwrap();
        assert_eq!(values.len(), 3);
        assert_eq!(values[0].as_uint64().unwrap(), 1);
        assert_eq!(values[1].as_uint64().unwrap(), 2);
        assert_eq!(values[2].as_uint64().unwrap(), 3);
    }

    #[test]
    fn test_encode_decode_multiple() {
        let values = vec![
            ABIValue::Address([1u8; 32]),
            ABIValue::Uint64(1000),
            ABIValue::Bool(true),
        ];

        let mut encoder = ABIEncoder::new();
        encoder.encode_all(&values).unwrap();
        let encoded = encoder.finish();

        let mut decoder = ABIDecoder::new(&encoded);
        let decoded = decoder.decode_all().unwrap();

        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].as_address().unwrap(), [1u8; 32]);
        assert_eq!(decoded[1].as_uint64().unwrap(), 1000);
        assert_eq!(decoded[2].as_bool().unwrap(), true);
    }

    #[test]
    fn test_function_call_encoding() {
        let func = FunctionABI::new(
            "transfer",
            vec![ABIType::Address, ABIType::Uint64],
            vec![ABIType::Bool],
            true,
        );

        let params = vec![
            ABIValue::Address([42u8; 32]),
            ABIValue::Uint64(1000),
        ];

        let encoded = encode_function_call(&func, &params).unwrap();

        // Decode and verify
        let (selector, decoded_params) = decode_function_call(&encoded).unwrap();

        assert_eq!(selector, func.selector);
        assert_eq!(decoded_params.len(), 2);
        assert_eq!(decoded_params[0].as_address().unwrap(), [42u8; 32]);
        assert_eq!(decoded_params[1].as_uint64().unwrap(), 1000);
    }

    #[test]
    fn test_return_encoding() {
        let values = vec![
            ABIValue::Bool(true),
            ABIValue::Uint64(42),
        ];

        let encoded = encode_return(&values).unwrap();
        let decoded = decode_return(&encoded).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].as_bool().unwrap(), true);
        assert_eq!(decoded[1].as_uint64().unwrap(), 42);
    }

    #[test]
    fn test_contract_abi() {
        let mut abi = ContractABI::new("Token");

        abi.add_function(FunctionABI::new(
            "transfer",
            vec![ABIType::Address, ABIType::Uint64],
            vec![ABIType::Bool],
            true,
        ));

        abi.add_function(FunctionABI::new(
            "balance",
            vec![ABIType::Address],
            vec![ABIType::Uint64],
            false,
        ));

        assert_eq!(abi.functions.len(), 2);

        // Find by name
        let transfer = abi.get_function_by_name("transfer").unwrap();
        assert_eq!(transfer.name, "transfer");

        // Find by selector
        let balance = abi.get_function_by_selector(&abi.functions[1].selector).unwrap();
        assert_eq!(balance.name, "balance");

        // Get all selectors
        let selectors = abi.selectors();
        assert_eq!(selectors.len(), 2);
    }

    #[test]
    fn test_validation() {
        let func = FunctionABI::new(
            "transfer",
            vec![ABIType::Address, ABIType::Uint64],
            vec![ABIType::Bool],
            true,
        );

        // Valid params
        let valid = vec![
            ABIValue::Address([0u8; 32]),
            ABIValue::Uint64(100),
        ];
        assert!(func.validate_inputs(&valid).is_ok());

        // Wrong count
        let wrong_count = vec![ABIValue::Address([0u8; 32])];
        assert!(matches!(
            func.validate_inputs(&wrong_count),
            Err(ContractError::ParameterCountMismatch { .. })
        ));

        // Wrong type
        let wrong_type = vec![
            ABIValue::Uint64(42),  // Should be Address
            ABIValue::Uint64(100),
        ];
        assert!(matches!(
            func.validate_inputs(&wrong_type),
            Err(ContractError::InvalidParameterType { .. })
        ));
    }

    #[test]
    fn test_bytes32_encoding() {
        let data = [99u8; 32];
        let value = ABIValue::Bytes32(data);

        let mut encoder = ABIEncoder::new();
        encoder.encode(&value).unwrap();
        let encoded = encoder.finish();

        let mut decoder = ABIDecoder::new(&encoded);
        let decoded = decoder.decode().unwrap();

        assert_eq!(decoded.as_bytes32().unwrap(), data);
    }

    #[test]
    fn test_nested_array() {
        let inner1 = ABIValue::Array(vec![
            ABIValue::Uint64(1),
            ABIValue::Uint64(2),
        ]);
        let inner2 = ABIValue::Array(vec![
            ABIValue::Uint64(3),
            ABIValue::Uint64(4),
        ]);
        let outer = ABIValue::Array(vec![inner1, inner2]);

        let mut encoder = ABIEncoder::new();
        encoder.encode(&outer).unwrap();
        let encoded = encoder.finish();

        let mut decoder = ABIDecoder::new(&encoded);
        let decoded = decoder.decode().unwrap();

        let outer_arr = decoded.as_array().unwrap();
        assert_eq!(outer_arr.len(), 2);

        let inner1_arr = outer_arr[0].as_array().unwrap();
        assert_eq!(inner1_arr.len(), 2);
        assert_eq!(inner1_arr[0].as_uint64().unwrap(), 1);
        assert_eq!(inner1_arr[1].as_uint64().unwrap(), 2);
    }
}
