//! Genesis configuration builder

use crate::{
    Allocation, ConsensusParams, ESLParams, GenesisConfig, GenesisError, GenesisResult,
    NetworkConfig, ValidatorConfig,
};

/// Builder for genesis configuration
#[derive(Debug, Default)]
pub struct GenesisBuilder {
    network_id: Option<String>,
    chain_id: Option<u64>,
    version: Option<String>,
    witness_count: Option<u32>,
    threshold: Option<u32>,
    min_stake: Option<u64>,
    epoch_length: Option<u64>,
    round_timeout_ms: Option<u64>,
    finality_delay: Option<u32>,
    tree_depth: Option<u32>,
    max_accounts: Option<u64>,
    snapshot_interval: Option<u64>,
    allocations: Vec<Allocation>,
    validators: Vec<ValidatorConfig>,
    timestamp: Option<u64>,
    extra_data: Option<String>,
}

impl GenesisBuilder {
    /// Create new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set network ID
    pub fn network_id(mut self, id: impl Into<String>) -> Self {
        self.network_id = Some(id.into());
        self
    }

    /// Set chain ID
    pub fn chain_id(mut self, id: u64) -> Self {
        self.chain_id = Some(id);
        self
    }

    /// Set protocol version
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Set witness count
    pub fn witness_count(mut self, count: u32) -> Self {
        self.witness_count = Some(count);
        self
    }

    /// Set threshold
    pub fn threshold(mut self, threshold: u32) -> Self {
        self.threshold = Some(threshold);
        self
    }

    /// Set minimum stake
    pub fn min_stake(mut self, stake: u64) -> Self {
        self.min_stake = Some(stake);
        self
    }

    /// Set epoch length
    pub fn epoch_length(mut self, length: u64) -> Self {
        self.epoch_length = Some(length);
        self
    }

    /// Set round timeout
    pub fn round_timeout_ms(mut self, timeout: u64) -> Self {
        self.round_timeout_ms = Some(timeout);
        self
    }

    /// Set finality delay
    pub fn finality_delay(mut self, delay: u32) -> Self {
        self.finality_delay = Some(delay);
        self
    }

    /// Set ESL tree depth
    pub fn tree_depth(mut self, depth: u32) -> Self {
        self.tree_depth = Some(depth);
        self
    }

    /// Set max accounts
    pub fn max_accounts(mut self, max: u64) -> Self {
        self.max_accounts = Some(max);
        self
    }

    /// Set snapshot interval
    pub fn snapshot_interval(mut self, interval: u64) -> Self {
        self.snapshot_interval = Some(interval);
        self
    }

    /// Add allocation
    pub fn allocation(
        mut self,
        address: impl Into<String>,
        balance: u64,
    ) -> Self {
        self.allocations.push(Allocation {
            address: address.into(),
            balance,
            is_validator: false,
            stake: 0,
        });
        self
    }

    /// Add validator allocation
    pub fn validator_allocation(
        mut self,
        address: impl Into<String>,
        balance: u64,
        stake: u64,
    ) -> Self {
        self.allocations.push(Allocation {
            address: address.into(),
            balance,
            is_validator: true,
            stake,
        });
        self
    }

    /// Add validator
    pub fn validator(
        mut self,
        id: impl Into<String>,
        public_key: impl Into<String>,
        vrf_key: impl Into<String>,
        stake: u64,
    ) -> Self {
        self.validators.push(ValidatorConfig {
            id: id.into(),
            public_key: public_key.into(),
            vrf_key: vrf_key.into(),
            stake,
            commission: 1000, // 10% default
        });
        self
    }

    /// Add validator with commission
    pub fn validator_with_commission(
        mut self,
        id: impl Into<String>,
        public_key: impl Into<String>,
        vrf_key: impl Into<String>,
        stake: u64,
        commission: u16,
    ) -> Self {
        self.validators.push(ValidatorConfig {
            id: id.into(),
            public_key: public_key.into(),
            vrf_key: vrf_key.into(),
            stake,
            commission,
        });
        self
    }

    /// Set timestamp
    pub fn timestamp(mut self, ts: u64) -> Self {
        self.timestamp = Some(ts);
        self
    }

    /// Set extra data
    pub fn extra_data(mut self, data: impl Into<String>) -> Self {
        self.extra_data = Some(data.into());
        self
    }

    /// Build from local preset with modifications
    pub fn from_local() -> Self {
        let config = GenesisConfig::local();
        Self {
            network_id: Some(config.network.network_id),
            chain_id: Some(config.network.chain_id),
            version: Some(config.network.version),
            witness_count: Some(config.consensus.witness_count),
            threshold: Some(config.consensus.threshold),
            min_stake: Some(config.consensus.min_stake),
            epoch_length: Some(config.consensus.epoch_length),
            round_timeout_ms: Some(config.consensus.round_timeout_ms),
            finality_delay: Some(config.consensus.finality_delay),
            tree_depth: Some(config.esl.tree_depth),
            max_accounts: Some(config.esl.max_accounts),
            snapshot_interval: Some(config.esl.snapshot_interval),
            allocations: config.allocations,
            validators: config.validators,
            timestamp: Some(config.timestamp),
            extra_data: Some(config.extra_data),
        }
    }

    /// Build from testnet preset with modifications
    pub fn from_testnet() -> Self {
        let config = GenesisConfig::testnet();
        Self {
            network_id: Some(config.network.network_id),
            chain_id: Some(config.network.chain_id),
            version: Some(config.network.version),
            witness_count: Some(config.consensus.witness_count),
            threshold: Some(config.consensus.threshold),
            min_stake: Some(config.consensus.min_stake),
            epoch_length: Some(config.consensus.epoch_length),
            round_timeout_ms: Some(config.consensus.round_timeout_ms),
            finality_delay: Some(config.consensus.finality_delay),
            tree_depth: Some(config.esl.tree_depth),
            max_accounts: Some(config.esl.max_accounts),
            snapshot_interval: Some(config.esl.snapshot_interval),
            allocations: config.allocations,
            validators: config.validators,
            timestamp: Some(config.timestamp),
            extra_data: Some(config.extra_data),
        }
    }

    /// Build the genesis configuration
    pub fn build(self) -> GenesisResult<GenesisConfig> {
        let config = GenesisConfig {
            network: NetworkConfig {
                network_id: self.network_id
                    .ok_or_else(|| GenesisError::MissingField("network_id".into()))?,
                chain_id: self.chain_id
                    .ok_or_else(|| GenesisError::MissingField("chain_id".into()))?,
                version: self.version.unwrap_or_else(|| "1.0.0".into()),
            },
            consensus: ConsensusParams {
                witness_count: self.witness_count
                    .ok_or_else(|| GenesisError::MissingField("witness_count".into()))?,
                threshold: self.threshold
                    .ok_or_else(|| GenesisError::MissingField("threshold".into()))?,
                min_stake: self.min_stake.unwrap_or(1000),
                epoch_length: self.epoch_length.unwrap_or(100),
                round_timeout_ms: self.round_timeout_ms.unwrap_or(2000),
                finality_delay: self.finality_delay.unwrap_or(1),
            },
            esl: ESLParams {
                tree_depth: self.tree_depth.unwrap_or(24),
                max_accounts: self.max_accounts.unwrap_or(10_000_000),
                snapshot_interval: self.snapshot_interval.unwrap_or(100),
            },
            allocations: self.allocations,
            validators: self.validators,
            timestamp: self.timestamp.unwrap_or_else(current_timestamp),
            extra_data: self.extra_data.unwrap_or_default(),
        };

        // Validate the configuration
        config.validate().map_err(GenesisError::InvalidConfig)?;

        Ok(config)
    }
}

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
    fn test_builder_basic() {
        let config = GenesisBuilder::new()
            .network_id("test-network")
            .chain_id(999)
            .witness_count(5)
            .threshold(4)
            .min_stake(100)
            .allocation("0x1234", 1_000_000)
            .build()
            .unwrap();

        assert_eq!(config.network.network_id, "test-network");
        assert_eq!(config.network.chain_id, 999);
        assert_eq!(config.allocations.len(), 1);
    }

    #[test]
    fn test_builder_with_validators() {
        let config = GenesisBuilder::new()
            .network_id("test")
            .chain_id(1)
            .witness_count(3)
            .threshold(3)
            .min_stake(100)
            .validator("v1", "0".repeat(128), "0".repeat(64), 1000)
            .validator_with_commission("v2", "1".repeat(128), "1".repeat(64), 2000, 500)
            .build()
            .unwrap();

        assert_eq!(config.validators.len(), 2);
        assert_eq!(config.validators[0].commission, 1000);
        assert_eq!(config.validators[1].commission, 500);
    }

    #[test]
    fn test_builder_from_local() {
        let config = GenesisBuilder::from_local()
            .chain_id(9999)
            .allocation("0xtest", 1000)
            .build()
            .unwrap();

        assert_eq!(config.network.chain_id, 9999);
        assert_eq!(config.network.network_id, "phantom-local");
        // Original allocation + new one
        assert_eq!(config.allocations.len(), 2);
    }

    #[test]
    fn test_builder_missing_field() {
        let result = GenesisBuilder::new()
            .chain_id(1)
            .witness_count(3)
            .threshold(3)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_invalid_config() {
        let result = GenesisBuilder::new()
            .network_id("test")
            .chain_id(1)
            .witness_count(3)
            .threshold(5) // Invalid: threshold > witness_count
            .build();

        assert!(result.is_err());
    }
}
