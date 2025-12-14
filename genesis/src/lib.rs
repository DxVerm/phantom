//! PHANTOM Genesis Configuration
//!
//! Provides genesis block configuration and chain initialization.
//!
//! # Networks
//!
//! - **Mainnet**: Production network with strict parameters
//! - **Testnet**: Test network with relaxed parameters
//! - **Local**: Single-node development network

mod config;
mod builder;
mod error;

pub use config::{GenesisConfig, NetworkConfig, ConsensusParams, ESLParams};
pub use builder::GenesisBuilder;
pub use error::{GenesisError, GenesisResult};

use serde::{Deserialize, Serialize};

/// Genesis block data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisBlock {
    /// Genesis configuration
    pub config: GenesisConfig,
    /// Genesis state root (computed from initial allocations)
    pub state_root: [u8; 32],
    /// Genesis block hash
    pub hash: [u8; 32],
}

impl GenesisBlock {
    /// Create genesis block from configuration
    pub fn from_config(config: GenesisConfig) -> Self {
        let state_root = config.compute_state_root();
        let hash = config.compute_hash();

        Self {
            config,
            state_root,
            hash,
        }
    }

    /// Load genesis from JSON file
    pub fn load_json<P: AsRef<std::path::Path>>(path: P) -> GenesisResult<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: GenesisConfig = serde_json::from_str(&content)?;
        Ok(Self::from_config(config))
    }

    /// Load genesis from TOML file
    pub fn load_toml<P: AsRef<std::path::Path>>(path: P) -> GenesisResult<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: GenesisConfig = toml::from_str(&content)?;
        Ok(Self::from_config(config))
    }

    /// Save genesis to JSON file
    pub fn save_json<P: AsRef<std::path::Path>>(&self, path: P) -> GenesisResult<()> {
        let content = serde_json::to_string_pretty(&self.config)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Save genesis to TOML file
    pub fn save_toml<P: AsRef<std::path::Path>>(&self, path: P) -> GenesisResult<()> {
        let content = toml::to_string_pretty(&self.config)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Get predefined mainnet genesis
    pub fn mainnet() -> Self {
        Self::from_config(GenesisConfig::mainnet())
    }

    /// Get predefined testnet genesis
    pub fn testnet() -> Self {
        Self::from_config(GenesisConfig::testnet())
    }

    /// Get predefined local genesis
    pub fn local() -> Self {
        Self::from_config(GenesisConfig::local())
    }
}

/// Initial account allocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Allocation {
    /// Account address (32 bytes, hex encoded)
    pub address: String,
    /// Initial balance
    pub balance: u64,
    /// Is this a validator account?
    #[serde(default)]
    pub is_validator: bool,
    /// Initial stake (for validators)
    #[serde(default)]
    pub stake: u64,
}

/// Initial validator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    /// Validator ID
    pub id: String,
    /// Public key (hex encoded)
    pub public_key: String,
    /// VRF public key (hex encoded)
    pub vrf_key: String,
    /// Initial stake
    pub stake: u64,
    /// Commission rate (basis points, 0-10000)
    #[serde(default = "default_commission")]
    pub commission: u16,
}

fn default_commission() -> u16 {
    1000 // 10%
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_genesis_mainnet() {
        let genesis = GenesisBlock::mainnet();
        assert_eq!(genesis.config.network.network_id, "phantom-mainnet");
        assert_eq!(genesis.config.network.chain_id, 1);
    }

    #[test]
    fn test_genesis_testnet() {
        let genesis = GenesisBlock::testnet();
        assert_eq!(genesis.config.network.network_id, "phantom-testnet");
        assert_eq!(genesis.config.network.chain_id, 2);
    }

    #[test]
    fn test_genesis_local() {
        let genesis = GenesisBlock::local();
        assert_eq!(genesis.config.network.network_id, "phantom-local");
        assert_eq!(genesis.config.network.chain_id, 1337);
    }

    #[test]
    fn test_genesis_save_load_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("genesis.json");

        let genesis = GenesisBlock::local();
        genesis.save_json(&path).unwrap();

        let loaded = GenesisBlock::load_json(&path).unwrap();
        assert_eq!(loaded.config.network.chain_id, genesis.config.network.chain_id);
        assert_eq!(loaded.hash, genesis.hash);
    }

    #[test]
    fn test_genesis_save_load_toml() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("genesis.toml");

        let genesis = GenesisBlock::testnet();
        genesis.save_toml(&path).unwrap();

        let loaded = GenesisBlock::load_toml(&path).unwrap();
        assert_eq!(loaded.config.network.chain_id, genesis.config.network.chain_id);
    }
}
