//! Node Configuration
//!
//! Handles loading and saving node configuration from TOML files.

use std::path::{Path, PathBuf};
use std::fs;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Configuration errors
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("Serialize error: {0}")]
    Serialize(#[from] toml::ser::Error),

    #[error("Config not found: {0}")]
    NotFound(PathBuf),

    #[error("Invalid config: {0}")]
    Invalid(String),
}

/// Full node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhantomConfig {
    /// General node settings
    #[serde(default)]
    pub node: NodeSettings,

    /// Network settings
    #[serde(default)]
    pub network: NetworkSettings,

    /// Consensus settings
    #[serde(default)]
    pub consensus: ConsensusSettings,

    /// RPC settings
    #[serde(default)]
    pub rpc: RpcSettings,

    /// Storage settings
    #[serde(default)]
    pub storage: StorageSettings,

    /// Logging settings
    #[serde(default)]
    pub logging: LoggingSettings,
}

impl Default for PhantomConfig {
    fn default() -> Self {
        Self {
            node: NodeSettings::default(),
            network: NetworkSettings::default(),
            consensus: ConsensusSettings::default(),
            rpc: RpcSettings::default(),
            storage: StorageSettings::default(),
            logging: LoggingSettings::default(),
        }
    }
}

impl PhantomConfig {
    /// Load configuration from a file
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Err(ConfigError::NotFound(path.to_path_buf()));
        }

        let content = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Save configuration to a file
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let content = toml::to_string_pretty(self)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, content)?;
        Ok(())
    }

    /// Create configuration for a specific network
    pub fn for_network(network: &str) -> Self {
        match network {
            "mainnet" => Self::mainnet(),
            "testnet" => Self::testnet(),
            _ => Self::local(),
        }
    }

    /// Local development configuration
    pub fn local() -> Self {
        Self {
            node: NodeSettings {
                network: "local".to_string(),
                ..Default::default()
            },
            network: NetworkSettings {
                listen_addr: "/ip4/127.0.0.1/tcp/9000".to_string(),
                enable_mdns: true,
                ..Default::default()
            },
            consensus: ConsensusSettings {
                witness_count: 5,
                threshold: 3,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Testnet configuration
    pub fn testnet() -> Self {
        Self {
            node: NodeSettings {
                network: "testnet".to_string(),
                ..Default::default()
            },
            network: NetworkSettings {
                listen_addr: "/ip4/0.0.0.0/tcp/9000".to_string(),
                bootnodes: vec![
                    "/dns/testnet-boot1.phantom.network/tcp/9000".to_string(),
                    "/dns/testnet-boot2.phantom.network/tcp/9000".to_string(),
                ],
                ..Default::default()
            },
            consensus: ConsensusSettings {
                witness_count: 21,
                threshold: 14,
                min_stake: 10_000,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Mainnet configuration
    pub fn mainnet() -> Self {
        Self {
            node: NodeSettings {
                network: "mainnet".to_string(),
                ..Default::default()
            },
            network: NetworkSettings {
                listen_addr: "/ip4/0.0.0.0/tcp/9000".to_string(),
                bootnodes: vec![
                    "/dns/boot1.phantom.network/tcp/9000".to_string(),
                    "/dns/boot2.phantom.network/tcp/9000".to_string(),
                    "/dns/boot3.phantom.network/tcp/9000".to_string(),
                ],
                max_peers: 100,
                ..Default::default()
            },
            consensus: ConsensusSettings {
                witness_count: 100,
                threshold: 67,
                min_stake: 100_000,
                timeout_ms: 3000,
            },
            rpc: RpcSettings {
                enabled: true,
                http_addr: "0.0.0.0:8545".to_string(),
                ws_addr: Some("0.0.0.0:8546".to_string()),
                cors_enabled: false,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Validate configuration
    fn validate(&self) -> Result<(), ConfigError> {
        if self.consensus.threshold > self.consensus.witness_count {
            return Err(ConfigError::Invalid(
                "Threshold cannot exceed witness count".to_string()
            ));
        }

        if self.consensus.threshold == 0 {
            return Err(ConfigError::Invalid(
                "Threshold must be greater than 0".to_string()
            ));
        }

        Ok(())
    }
}

/// General node settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSettings {
    /// Network name (local, testnet, mainnet)
    pub network: String,

    /// Node name for identification
    pub name: Option<String>,

    /// Whether this is a validator node
    pub is_validator: bool,

    /// Validator stake amount
    pub validator_stake: u64,

    /// ESL tree depth
    pub esl_tree_depth: usize,
}

impl Default for NodeSettings {
    fn default() -> Self {
        Self {
            network: "local".to_string(),
            name: None,
            is_validator: false,
            validator_stake: 0,
            esl_tree_depth: 32,
        }
    }
}

/// Network settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSettings {
    /// P2P listen address
    pub listen_addr: String,

    /// Bootstrap nodes
    pub bootnodes: Vec<String>,

    /// Maximum peer count
    pub max_peers: usize,

    /// Enable mDNS discovery
    pub enable_mdns: bool,

    /// Enable Kademlia DHT
    pub enable_dht: bool,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/tcp/9000".to_string(),
            bootnodes: vec![],
            max_peers: 50,
            enable_mdns: true,
            enable_dht: true,
        }
    }
}

/// Consensus settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusSettings {
    /// Number of witnesses per transaction
    pub witness_count: usize,

    /// Attestation threshold for finality
    pub threshold: usize,

    /// Minimum stake to be a validator
    pub min_stake: u64,

    /// Consensus timeout in milliseconds
    pub timeout_ms: u64,
}

impl Default for ConsensusSettings {
    fn default() -> Self {
        Self {
            witness_count: 100,
            threshold: 67,
            min_stake: 100_000,
            timeout_ms: 5000,
        }
    }
}

/// RPC settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcSettings {
    /// Enable RPC server
    pub enabled: bool,

    /// HTTP bind address
    pub http_addr: String,

    /// WebSocket bind address
    pub ws_addr: Option<String>,

    /// Enable CORS
    pub cors_enabled: bool,

    /// CORS allowed origins
    pub cors_origins: Vec<String>,

    /// Require admin authentication
    pub require_admin_auth: bool,

    /// Admin API key
    pub admin_api_key: Option<String>,
}

impl Default for RpcSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            http_addr: "127.0.0.1:8545".to_string(),
            ws_addr: Some("127.0.0.1:8546".to_string()),
            cors_enabled: true,
            cors_origins: vec!["*".to_string()],
            require_admin_auth: false,
            admin_api_key: None,
        }
    }
}

/// Storage settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSettings {
    /// Database backend (rocksdb, sled)
    pub backend: String,

    /// State cache size in MB
    pub cache_size_mb: usize,

    /// Enable compression
    pub compression: bool,

    /// Pruning mode (archive, pruned)
    pub pruning: String,
}

impl Default for StorageSettings {
    fn default() -> Self {
        Self {
            backend: "rocksdb".to_string(),
            cache_size_mb: 512,
            compression: true,
            pruning: "archive".to_string(),
        }
    }
}

/// Logging settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingSettings {
    /// Log level
    pub level: String,

    /// Output format (text, json)
    pub format: String,

    /// Log file path
    pub file: Option<PathBuf>,
}

impl Default for LoggingSettings {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "text".to_string(),
            file: None,
        }
    }
}

/// Get default data directory
pub fn default_data_dir(network: &str) -> PathBuf {
    let base = directories::ProjectDirs::from("network", "phantom", "phantom")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".phantom"));

    base.join(network)
}

/// Get default config file path
pub fn default_config_path(data_dir: &Path) -> PathBuf {
    data_dir.join("config.toml")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let config = PhantomConfig::default();
        assert_eq!(config.node.network, "local");
        assert_eq!(config.consensus.witness_count, 100);
    }

    #[test]
    fn test_local_config() {
        let config = PhantomConfig::local();
        assert_eq!(config.consensus.witness_count, 5);
        assert_eq!(config.consensus.threshold, 3);
    }

    #[test]
    fn test_testnet_config() {
        let config = PhantomConfig::testnet();
        assert_eq!(config.node.network, "testnet");
        assert!(!config.network.bootnodes.is_empty());
    }

    #[test]
    fn test_mainnet_config() {
        let config = PhantomConfig::mainnet();
        assert_eq!(config.node.network, "mainnet");
        assert_eq!(config.consensus.threshold, 67);
    }

    #[test]
    fn test_save_load_config() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let config = PhantomConfig::local();
        config.save(&path).unwrap();

        let loaded = PhantomConfig::load(&path).unwrap();
        assert_eq!(loaded.node.network, "local");
    }

    #[test]
    fn test_invalid_threshold() {
        let config = PhantomConfig {
            consensus: ConsensusSettings {
                witness_count: 5,
                threshold: 10, // Invalid: threshold > witness_count
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(config.validate().is_err());
    }
}
