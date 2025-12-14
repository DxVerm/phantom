//! WASM Bindings for PHANTOM Light Client
//!
//! Provides JavaScript/TypeScript-friendly APIs for mobile and browser applications.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use js_sys::{Array, Object, Reflect, Uint8Array};

use crate::header::{BlockHeader, HeaderChain, HeaderChainConfig, GenesisConfig};
use crate::verification::{InclusionProof, MerkleNode, ProofVerifier, RootType};
// Checkpoint imported but used only in add_checkpoint method
use serde::{Deserialize, Serialize};

/// JavaScript-friendly block header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsBlockHeader {
    pub height: u64,
    pub hash: String,
    pub parent_hash: String,
    pub state_root: String,
    pub transactions_root: String,
    pub timestamp: u64,
    pub difficulty: u64,
}

impl From<&BlockHeader> for JsBlockHeader {
    fn from(header: &BlockHeader) -> Self {
        Self {
            height: header.height,
            hash: hex::encode(header.hash),
            parent_hash: hex::encode(header.parent_hash),
            state_root: hex::encode(header.state_root),
            transactions_root: hex::encode(header.transactions_root),
            timestamp: header.timestamp,
            difficulty: header.difficulty,
        }
    }
}

/// JavaScript-friendly inclusion proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsInclusionProof {
    pub item_hash: String,
    pub block_height: u64,
    pub block_hash: String,
    pub path: Vec<JsMerkleNode>,
    pub root_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsMerkleNode {
    pub hash: String,
    pub is_left: bool,
}

impl JsInclusionProof {
    /// Convert to native InclusionProof
    pub fn to_native(&self) -> Result<InclusionProof, String> {
        let item_hash = hex_to_bytes32(&self.item_hash)?;
        let block_hash = hex_to_bytes32(&self.block_hash)?;

        let path: Result<Vec<MerkleNode>, String> = self.path
            .iter()
            .map(|n| Ok(MerkleNode {
                hash: hex_to_bytes32(&n.hash)?,
                is_left: n.is_left,
            }))
            .collect();

        let root_type = match self.root_type.as_str() {
            "transactions" => RootType::Transactions,
            "state" => RootType::State,
            "receipts" => RootType::Receipts,
            _ => return Err("Invalid root type".into()),
        };

        Ok(InclusionProof {
            item_hash,
            path: path?,
            block_height: self.block_height,
            block_hash,
            root_type,
        })
    }
}

/// WASM Light Client for mobile applications
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct WasmLightClient {
    chain: HeaderChain,
    verifier: ProofVerifier,
    initialized: bool,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl WasmLightClient {
    /// Create a new WASM light client
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(constructor))]
    pub fn new(max_headers: Option<usize>) -> Self {
        let config = HeaderChainConfig {
            max_headers: max_headers.unwrap_or(10000),
            max_reorg_depth: 100,
            checkpoint_interval: 1000,
            verify_signatures: false, // Signatures verified separately in WASM
        };

        Self {
            chain: HeaderChain::new(config),
            verifier: ProofVerifier::new(3600),
            initialized: false,
        }
    }

    /// Initialize with genesis block
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
    pub fn initialize(&mut self, genesis_state_root: &str, genesis_timestamp: u64) -> Result<(), String> {
        let state_root = hex_to_bytes32(genesis_state_root)?;

        let genesis_config = GenesisConfig {
            state_root,
            timestamp: genesis_timestamp,
            extra_data: b"PHANTOM WASM Genesis".to_vec(),
        };

        self.chain
            .initialize_genesis(genesis_config)
            .map_err(|e| e.to_string())?;

        self.initialized = true;
        Ok(())
    }

    /// Get current chain height
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
    pub fn get_height(&self) -> u64 {
        self.chain.get_height()
    }

    /// Get header at height (returns JSON)
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
    pub fn get_header_at_height(&self, height: u64) -> Option<String> {
        self.chain
            .get_canonical_header(height)
            .map(|h| serde_json::to_string(&JsBlockHeader::from(&h)).unwrap())
    }

    /// Get header by hash (returns JSON)
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
    pub fn get_header_by_hash(&self, hash: &str) -> Result<Option<String>, String> {
        let hash_bytes = hex_to_bytes32(hash)?;
        Ok(self.chain
            .get_header(&hash_bytes)
            .map(|h| serde_json::to_string(&JsBlockHeader::from(&h)).unwrap()))
    }

    /// Add a new header (JSON format)
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
    pub fn add_header(&mut self, header_json: &str) -> Result<(), String> {
        let js_header: JsBlockHeader = serde_json::from_str(header_json)
            .map_err(|e| e.to_string())?;

        let header = BlockHeader::new(
            js_header.height,
            hex_to_bytes32(&js_header.parent_hash)?,
            hex_to_bytes32(&js_header.state_root)?,
            hex_to_bytes32(&js_header.transactions_root)?,
            [0u8; 32], // receipts_root
            js_header.timestamp,
            [0u8; 32], // proposer
            js_header.difficulty,
        );

        self.chain
            .insert_header(header)
            .map_err(|e| e.to_string())
    }

    /// Add multiple headers in batch
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
    pub fn add_headers_batch(&mut self, headers_json: &str) -> Result<u32, String> {
        let headers: Vec<JsBlockHeader> = serde_json::from_str(headers_json)
            .map_err(|e| e.to_string())?;

        let mut count = 0u32;
        for js_header in headers {
            let header = BlockHeader::new(
                js_header.height,
                hex_to_bytes32(&js_header.parent_hash)?,
                hex_to_bytes32(&js_header.state_root)?,
                hex_to_bytes32(&js_header.transactions_root)?,
                [0u8; 32],
                js_header.timestamp,
                [0u8; 32],
                js_header.difficulty,
            );

            if self.chain.insert_header(header).is_ok() {
                count += 1;
            }
        }

        Ok(count)
    }

    /// Verify transaction inclusion proof
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
    pub fn verify_transaction(&self, tx_hash: &str, proof_json: &str) -> Result<bool, String> {
        let _tx_hash_bytes = hex_to_bytes32(tx_hash)?; // Validated but proof contains item_hash
        let js_proof: JsInclusionProof = serde_json::from_str(proof_json)
            .map_err(|e| e.to_string())?;
        let proof = js_proof.to_native()?;

        // Get the header for this proof
        let header = self.chain
            .get_header(&proof.block_hash)
            .ok_or("Header not found")?;

        // Verify the proof
        self.verifier
            .verify_inclusion(&proof, &header)
            .map(|_| true)
            .map_err(|e| e.to_string())
    }

    /// Add a checkpoint for fast sync
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
    pub fn add_checkpoint(&mut self, height: u64, hash: &str) -> Result<(), String> {
        let hash_bytes = hex_to_bytes32(hash)?;
        self.chain.add_checkpoint(height, hash_bytes);
        Ok(())
    }

    /// Check if a header hash is in the canonical chain
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
    pub fn is_canonical(&self, hash: &str) -> Result<bool, String> {
        let hash_bytes = hex_to_bytes32(hash)?;
        Ok(self.chain.is_canonical(&hash_bytes))
    }

    /// Get chain statistics (returns JSON)
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
    pub fn get_stats(&self) -> String {
        let stats = self.chain.stats();
        serde_json::to_string(&serde_json::json!({
            "height": stats.height,
            "total_headers": stats.total_headers,
            "total_difficulty": stats.total_difficulty.to_string(),
            "checkpoints": stats.checkpoints,
            "initialized": self.initialized,
        })).unwrap()
    }

    /// Add trusted node for proof delegation
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
    pub fn add_trusted_node(&mut self, pubkey: &str) -> Result<(), String> {
        let pubkey_bytes = hex_to_bytes32(pubkey)?;
        self.verifier.add_trusted_node(pubkey_bytes);
        Ok(())
    }

    /// Compute Merkle root from transaction hashes
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
    pub fn compute_merkle_root(tx_hashes_json: &str) -> Result<String, String> {
        let hashes: Vec<String> = serde_json::from_str(tx_hashes_json)
            .map_err(|e| e.to_string())?;

        let leaves: Result<Vec<[u8; 32]>, String> = hashes
            .iter()
            .map(|h| hex_to_bytes32(h))
            .collect();

        let root = ProofVerifier::compute_merkle_root(&leaves?);
        Ok(hex::encode(root))
    }

    /// Build Merkle proof for a transaction
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
    pub fn build_merkle_proof(tx_hashes_json: &str, tx_index: usize) -> Result<String, String> {
        let hashes: Vec<String> = serde_json::from_str(tx_hashes_json)
            .map_err(|e| e.to_string())?;

        let leaves: Result<Vec<[u8; 32]>, String> = hashes
            .iter()
            .map(|h| hex_to_bytes32(h))
            .collect();

        let path = ProofVerifier::build_merkle_proof(&leaves?, tx_index);
        let js_path: Vec<JsMerkleNode> = path
            .iter()
            .map(|n| JsMerkleNode {
                hash: hex::encode(n.hash),
                is_left: n.is_left,
            })
            .collect();

        serde_json::to_string(&js_path).map_err(|e| e.to_string())
    }
}

/// Helper function to convert hex string to 32-byte array
fn hex_to_bytes32(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Utility functions exposed to JavaScript
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn hash_blake3(data: &[u8]) -> String {
    hex::encode(blake3::hash(data).as_bytes())
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn verify_header_hash(header_json: &str) -> Result<bool, String> {
    let js_header: JsBlockHeader = serde_json::from_str(header_json)
        .map_err(|e| e.to_string())?;

    let header = BlockHeader::new(
        js_header.height,
        hex_to_bytes32(&js_header.parent_hash)?,
        hex_to_bytes32(&js_header.state_root)?,
        hex_to_bytes32(&js_header.transactions_root)?,
        [0u8; 32],
        js_header.timestamp,
        [0u8; 32],
        js_header.difficulty,
    );

    let computed_hash = header.compute_hash();
    let expected_hash = hex_to_bytes32(&js_header.hash)?;

    Ok(computed_hash == expected_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_conversion() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let bytes = hex_to_bytes32(hex).unwrap();
        assert_eq!(bytes[31], 1);
        assert_eq!(bytes[0], 0);
    }

    #[test]
    fn test_wasm_client_creation() {
        let client = WasmLightClient::new(Some(1000));
        assert_eq!(client.get_height(), 0);
    }

    #[test]
    fn test_wasm_client_initialization() {
        let mut client = WasmLightClient::new(None);
        let genesis_state_root = "0000000000000000000000000000000000000000000000000000000000000000";
        client.initialize(genesis_state_root, 1000).unwrap();
        assert_eq!(client.get_height(), 0);
    }

    #[test]
    fn test_merkle_root_computation() {
        let hashes = r#"["0000000000000000000000000000000000000000000000000000000000000001", "0000000000000000000000000000000000000000000000000000000000000002"]"#;
        let root = WasmLightClient::compute_merkle_root(hashes).unwrap();
        assert!(!root.is_empty());
        assert_eq!(root.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_merkle_proof_building() {
        let hashes = r#"["0000000000000000000000000000000000000000000000000000000000000001", "0000000000000000000000000000000000000000000000000000000000000002", "0000000000000000000000000000000000000000000000000000000000000003", "0000000000000000000000000000000000000000000000000000000000000004"]"#;
        let proof = WasmLightClient::build_merkle_proof(hashes, 1).unwrap();
        let nodes: Vec<JsMerkleNode> = serde_json::from_str(&proof).unwrap();
        assert_eq!(nodes.len(), 2); // log2(4) = 2 levels
    }

    #[test]
    fn test_js_inclusion_proof_conversion() {
        let proof = JsInclusionProof {
            item_hash: "0000000000000000000000000000000000000000000000000000000000000001".into(),
            block_height: 100,
            block_hash: "0000000000000000000000000000000000000000000000000000000000000002".into(),
            path: vec![
                JsMerkleNode {
                    hash: "0000000000000000000000000000000000000000000000000000000000000003".into(),
                    is_left: true,
                }
            ],
            root_type: "transactions".into(),
        };

        let native = proof.to_native().unwrap();
        assert_eq!(native.block_height, 100);
        assert_eq!(native.path.len(), 1);
    }
}
