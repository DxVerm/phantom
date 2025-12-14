//! Genesis configuration types

use serde::{Deserialize, Serialize};
use crate::{Allocation, ValidatorConfig};

/// Complete genesis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Network configuration
    pub network: NetworkConfig,
    /// Consensus parameters
    pub consensus: ConsensusParams,
    /// ESL (Encrypted State Ledger) parameters
    pub esl: ESLParams,
    /// Initial token allocations
    #[serde(default)]
    pub allocations: Vec<Allocation>,
    /// Initial validators
    #[serde(default)]
    pub validators: Vec<ValidatorConfig>,
    /// Genesis timestamp (Unix seconds)
    pub timestamp: u64,
    /// Extra data (for comments/notes)
    #[serde(default)]
    pub extra_data: String,
}

impl GenesisConfig {
    /// Create mainnet genesis configuration
    pub fn mainnet() -> Self {
        Self {
            network: NetworkConfig {
                network_id: "phantom-mainnet".to_string(),
                chain_id: 1,
                version: "1.0.0".to_string(),
            },
            consensus: ConsensusParams {
                witness_count: 21,
                threshold: 15,
                min_stake: 100_000,
                epoch_length: 1000,
                round_timeout_ms: 3000,
                finality_delay: 2,
            },
            esl: ESLParams {
                tree_depth: 32,
                max_accounts: 1_000_000_000,
                snapshot_interval: 100,
            },
            allocations: vec![
                // Foundation allocation
                Allocation {
                    address: "0x0000000000000000000000000000000000000001".to_string(),
                    balance: 100_000_000_000, // 100B tokens
                    is_validator: false,
                    stake: 0,
                },
                // Development fund
                Allocation {
                    address: "0x0000000000000000000000000000000000000002".to_string(),
                    balance: 50_000_000_000, // 50B tokens
                    is_validator: false,
                    stake: 0,
                },
            ],
            validators: vec![], // Validators added via governance
            timestamp: current_timestamp(),
            extra_data: "PHANTOM Mainnet Genesis".to_string(),
        }
    }

    /// Create testnet genesis configuration
    pub fn testnet() -> Self {
        Self {
            network: NetworkConfig {
                network_id: "phantom-testnet".to_string(),
                chain_id: 2,
                version: "1.0.0".to_string(),
            },
            consensus: ConsensusParams {
                witness_count: 7,
                threshold: 5,
                min_stake: 1_000,
                epoch_length: 100,
                round_timeout_ms: 2000,
                finality_delay: 1,
            },
            esl: ESLParams {
                tree_depth: 24,
                max_accounts: 10_000_000,
                snapshot_interval: 50,
            },
            allocations: vec![
                // Faucet
                Allocation {
                    address: "0x0000000000000000000000000000000000000001".to_string(),
                    balance: 1_000_000_000_000, // 1T tokens for faucet
                    is_validator: false,
                    stake: 0,
                },
            ],
            validators: vec![
                // Bootstrap validators
                ValidatorConfig {
                    id: "validator-1".to_string(),
                    public_key: "0".repeat(128),
                    vrf_key: "0".repeat(64),
                    stake: 10_000,
                    commission: 1000,
                },
                ValidatorConfig {
                    id: "validator-2".to_string(),
                    public_key: "1".repeat(128),
                    vrf_key: "1".repeat(64),
                    stake: 10_000,
                    commission: 1000,
                },
                ValidatorConfig {
                    id: "validator-3".to_string(),
                    public_key: "2".repeat(128),
                    vrf_key: "2".repeat(64),
                    stake: 10_000,
                    commission: 1000,
                },
            ],
            timestamp: current_timestamp(),
            extra_data: "PHANTOM Testnet Genesis".to_string(),
        }
    }

    /// Create local development genesis configuration
    pub fn local() -> Self {
        Self {
            network: NetworkConfig {
                network_id: "phantom-local".to_string(),
                chain_id: 1337,
                version: "1.0.0".to_string(),
            },
            consensus: ConsensusParams {
                witness_count: 3,
                threshold: 3,
                min_stake: 100,
                epoch_length: 10,
                round_timeout_ms: 1000,
                finality_delay: 0,
            },
            esl: ESLParams {
                tree_depth: 16,
                max_accounts: 100_000,
                snapshot_interval: 10,
            },
            allocations: vec![
                // Development account with lots of tokens
                Allocation {
                    address: "0x0000000000000000000000000000000000000001".to_string(),
                    balance: 1_000_000_000_000_000, // 1 quadrillion for testing
                    is_validator: false,
                    stake: 0,
                },
            ],
            validators: vec![
                // Single bootstrap validator
                ValidatorConfig {
                    id: "local-validator".to_string(),
                    public_key: "0".repeat(128),
                    vrf_key: "0".repeat(64),
                    stake: 1_000,
                    commission: 0,
                },
            ],
            timestamp: current_timestamp(),
            extra_data: "PHANTOM Local Development Genesis".to_string(),
        }
    }

    /// Compute state root from allocations
    pub fn compute_state_root(&self) -> [u8; 32] {
        // Serialize allocations and hash
        let data = serde_json::to_vec(&self.allocations).unwrap_or_default();
        blake3::hash(&data).into()
    }

    /// Compute genesis block hash
    pub fn compute_hash(&self) -> [u8; 32] {
        let data = serde_json::to_vec(self).unwrap_or_default();
        blake3::hash(&data).into()
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        // Check network config
        if self.network.network_id.is_empty() {
            return Err("Network ID cannot be empty".into());
        }

        // Check consensus params
        if self.consensus.witness_count < 3 {
            return Err("Witness count must be at least 3".into());
        }
        if self.consensus.threshold > self.consensus.witness_count {
            return Err("Threshold cannot exceed witness count".into());
        }
        if self.consensus.threshold < (self.consensus.witness_count * 2 / 3) + 1 {
            return Err("Threshold must be at least 2/3 + 1 of witness count".into());
        }

        // Check ESL params
        if self.esl.tree_depth < 8 || self.esl.tree_depth > 64 {
            return Err("ESL tree depth must be between 8 and 64".into());
        }

        // Check for duplicate allocations
        let mut addresses = std::collections::HashSet::new();
        for alloc in &self.allocations {
            if !addresses.insert(&alloc.address) {
                return Err(format!("Duplicate allocation for {}", alloc.address));
            }
        }

        // Check validators
        let mut validator_ids = std::collections::HashSet::new();
        for v in &self.validators {
            if !validator_ids.insert(&v.id) {
                return Err(format!("Duplicate validator ID: {}", v.id));
            }
            if v.stake < self.consensus.min_stake {
                return Err(format!(
                    "Validator {} stake {} below minimum {}",
                    v.id, v.stake, self.consensus.min_stake
                ));
            }
        }

        Ok(())
    }

    /// Get total initial supply
    pub fn total_supply(&self) -> u64 {
        self.allocations.iter().map(|a| a.balance).sum()
    }

    /// Get total staked
    pub fn total_staked(&self) -> u64 {
        self.validators.iter().map(|v| v.stake).sum()
    }
}

/// Network identification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network identifier (e.g., "phantom-mainnet")
    pub network_id: String,
    /// Chain ID for EIP-155
    pub chain_id: u64,
    /// Protocol version
    pub version: String,
}

/// Consensus parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusParams {
    /// Number of witnesses required per round
    pub witness_count: u32,
    /// Threshold for block finalization
    pub threshold: u32,
    /// Minimum stake to become validator
    pub min_stake: u64,
    /// Blocks per epoch
    pub epoch_length: u64,
    /// Round timeout in milliseconds
    pub round_timeout_ms: u64,
    /// Blocks before finality
    pub finality_delay: u32,
}

/// ESL (Encrypted State Ledger) parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ESLParams {
    /// Merkle tree depth
    pub tree_depth: u32,
    /// Maximum number of accounts
    pub max_accounts: u64,
    /// Snapshot interval (epochs)
    pub snapshot_interval: u64,
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_config() {
        let config = GenesisConfig::mainnet();
        assert!(config.validate().is_ok());
        assert_eq!(config.consensus.witness_count, 21);
        assert_eq!(config.consensus.threshold, 15);
    }

    #[test]
    fn test_testnet_config() {
        let config = GenesisConfig::testnet();
        assert!(config.validate().is_ok());
        assert_eq!(config.validators.len(), 3);
    }

    #[test]
    fn test_local_config() {
        let config = GenesisConfig::local();
        assert!(config.validate().is_ok());
        assert_eq!(config.consensus.witness_count, 3);
        assert_eq!(config.consensus.threshold, 3);
    }

    #[test]
    fn test_invalid_threshold() {
        let mut config = GenesisConfig::local();
        config.consensus.threshold = 10; // More than witness_count
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_duplicate_allocation() {
        let mut config = GenesisConfig::local();
        config.allocations.push(Allocation {
            address: "0x0000000000000000000000000000000000000001".to_string(),
            balance: 1000,
            is_validator: false,
            stake: 0,
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_total_supply() {
        let config = GenesisConfig::mainnet();
        assert_eq!(config.total_supply(), 150_000_000_000);
    }
}
