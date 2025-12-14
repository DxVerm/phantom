//! Phase 4 Integration Tests
//!
//! Tests for storage, genesis, RPC server, node, and CLI components.

// ============================================================================
// Storage Tests
// ============================================================================

mod storage_tests {
    use phantom_storage::{
        Storage, StorageConfig,
        StoredBlock, StoredBlockHeader, StoredBlockBody,
        ChainMeta, StateSnapshot,
    };
    use phantom_storage::tx::{StoredTransaction, TransactionType, TransactionLocation};
    use phantom_storage::chain::{ValidatorSet, ValidatorEntry, Checkpoint};
    use tempfile::tempdir;

    fn create_test_storage() -> (Storage, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        let config = StorageConfig {
            path,
            max_size: 100 * 1024 * 1024, // 100MB
            enable_tx_cache: true,
            tx_cache_size: 1000,
            enable_snapshots: false,
            snapshot_interval: 1000,
        };
        let storage = Storage::with_config(config).unwrap();
        (storage, dir)
    }

    fn create_test_block(height: u64, prev_hash: [u8; 32]) -> StoredBlock {
        StoredBlock {
            header: StoredBlockHeader {
                height,
                hash: [height as u8; 32],
                prev_hash,
                state_root: [2u8; 32],
                tx_root: [3u8; 32],
                timestamp: 1700000000 + height,
                producer: [4u8; 32],
                attestation_count: 3,
            },
            body: StoredBlockBody {
                transactions: vec![],
            },
        }
    }

    fn create_test_transaction(nonce: u64) -> StoredTransaction {
        StoredTransaction {
            hash: [nonce as u8; 32],
            tx_type: TransactionType::Transfer,
            sender: vec![1u8; 32],
            recipient: vec![2u8; 32],
            amount_encrypted: vec![0u8; 16],
            fee: 100,
            nonce,
            proof: vec![0u8; 128],
            signature: vec![0u8; 64],
            timestamp: 1700000000,
        }
    }

    #[test]
    fn test_storage_creation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        let storage = Storage::open(&path).unwrap();
        // Storage opens successfully
        assert!(storage.blocks.count().unwrap() == 0);
    }

    #[test]
    fn test_storage_with_config() {
        let (storage, _dir) = create_test_storage();
        assert_eq!(storage.blocks.count().unwrap(), 0);
    }

    #[test]
    fn test_block_storage() {
        let (storage, _dir) = create_test_storage();

        let block = create_test_block(1, [0u8; 32]);

        // Store block
        storage.blocks.put(&block).unwrap();

        // Retrieve block by height
        let retrieved = storage.blocks.get(1).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().header.height, 1);
    }

    #[test]
    fn test_block_by_hash() {
        let (storage, _dir) = create_test_storage();

        let block = create_test_block(1, [0u8; 32]);
        let hash = block.hash();

        storage.blocks.put(&block).unwrap();

        let retrieved = storage.blocks.get_by_hash(&hash).unwrap();
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_block_not_found() {
        let (storage, _dir) = create_test_storage();

        let result = storage.blocks.get(999).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_multiple_blocks() {
        let (storage, _dir) = create_test_storage();

        // Store multiple blocks
        let mut parent = [0u8; 32];
        for i in 0..10u64 {
            let block = create_test_block(i, parent);
            parent = block.header.hash;
            storage.blocks.put(&block).unwrap();
        }

        // Verify count
        assert_eq!(storage.blocks.count().unwrap(), 10);

        // Verify retrieval
        for i in 0..10u64 {
            let block = storage.blocks.get(i).unwrap();
            assert!(block.is_some());
            assert_eq!(block.unwrap().header.height, i);
        }
    }

    #[test]
    fn test_latest_block_height() {
        let (storage, _dir) = create_test_storage();

        // Initially no blocks
        let height = storage.blocks.latest_height().unwrap();
        assert!(height.is_none());

        // Add blocks
        for i in 0..5u64 {
            let block = create_test_block(i, [0u8; 32]);
            storage.blocks.put(&block).unwrap();
        }

        let height = storage.blocks.latest_height().unwrap();
        assert_eq!(height, Some(4));
    }

    #[test]
    fn test_block_range() {
        let (storage, _dir) = create_test_storage();

        // Store 10 blocks
        for i in 0..10u64 {
            let block = create_test_block(i, [0u8; 32]);
            storage.blocks.put(&block).unwrap();
        }

        // Get range
        let range = storage.blocks.get_range(3, 7).unwrap();
        assert_eq!(range.len(), 5);
        assert_eq!(range[0].header.height, 3);
        assert_eq!(range[4].header.height, 7);
    }

    #[test]
    fn test_transaction_storage() {
        let (storage, _dir) = create_test_storage();

        let tx = create_test_transaction(1);
        let hash = tx.hash;
        let location = TransactionLocation { block_height: 1, tx_index: 0 };

        storage.transactions.put(&tx, &location).unwrap();

        let retrieved = storage.transactions.get(&hash).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().nonce, 1);
    }

    #[test]
    fn test_transaction_exists() {
        let (storage, _dir) = create_test_storage();

        let tx = create_test_transaction(1);
        let hash = tx.hash;

        assert!(!storage.transactions.exists(&hash).unwrap());

        let location = TransactionLocation { block_height: 1, tx_index: 0 };
        storage.transactions.put(&tx, &location).unwrap();

        assert!(storage.transactions.exists(&hash).unwrap());
    }

    #[test]
    fn test_transaction_batch() {
        let (storage, _dir) = create_test_storage();

        // Store multiple transactions
        let hashes: Vec<[u8; 32]> = (0..5)
            .map(|i| {
                let tx = create_test_transaction(i as u64);
                let hash = tx.hash;
                let location = TransactionLocation { block_height: 1, tx_index: i };
                storage.transactions.put(&tx, &location).unwrap();
                hash
            })
            .collect();

        // Verify all transactions can be retrieved individually
        for hash in &hashes {
            assert!(storage.transactions.get(hash).unwrap().is_some());
        }
        assert_eq!(storage.transactions.count().unwrap(), 5);
    }

    #[test]
    fn test_state_snapshot_storage() {
        let (storage, _dir) = create_test_storage();

        let snapshot = StateSnapshot {
            epoch: 1,
            height: 100,
            state_root: [1u8; 32],
            account_count: 1000,
            validator_set_hash: [2u8; 32],
            timestamp: 1700000000,
            tree_data: vec![0u8; 100],
        };

        storage.state.save_snapshot(&snapshot).unwrap();

        let retrieved = storage.state.get_snapshot(1).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().epoch, 1);
    }

    #[test]
    fn test_state_latest_root() {
        let (storage, _dir) = create_test_storage();

        let snapshot = StateSnapshot {
            epoch: 1,
            height: 100,
            state_root: [42u8; 32],
            account_count: 1000,
            validator_set_hash: [2u8; 32],
            timestamp: 1700000000,
            tree_data: vec![],
        };

        storage.state.save_snapshot(&snapshot).unwrap();

        let root = storage.state.get_latest_root().unwrap();
        assert!(root.is_some());
        assert_eq!(root.unwrap(), [42u8; 32]);
    }

    #[test]
    fn test_chain_meta() {
        let (storage, _dir) = create_test_storage();

        let meta = ChainMeta {
            genesis_hash: [1u8; 32],
            network_id: "testnet".to_string(),
            chain_id: 1337,
            genesis_timestamp: 1700000000,
            current_epoch: 5,
            current_round: 42,
            finalized_height: 90,
            finalized_hash: [2u8; 32],
            current_height: 100,
        };

        storage.chain.save_meta(&meta).unwrap();

        let retrieved = storage.chain.get_meta().unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.chain_id, 1337);
        assert_eq!(retrieved.current_height, 100);
    }

    #[test]
    fn test_validator_set() {
        let (storage, _dir) = create_test_storage();

        let validator_set = ValidatorSet {
            epoch: 1,
            validators: vec![
                ValidatorEntry {
                    id: [1u8; 32],
                    public_key: vec![0u8; 64],
                    stake: 100_000,
                    commission: 500, // 5% in basis points
                    active: true,
                },
                ValidatorEntry {
                    id: [2u8; 32],
                    public_key: vec![0u8; 64],
                    stake: 50_000,
                    commission: 300,
                    active: true,
                },
            ],
            total_stake: 150_000,
        };

        storage.chain.save_validator_set(&validator_set).unwrap();

        let retrieved = storage.chain.get_validator_set(1).unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.validators.len(), 2);
        assert_eq!(retrieved.total_stake, 150_000);
    }

    #[test]
    fn test_checkpoint() {
        let (storage, _dir) = create_test_storage();

        let checkpoint = Checkpoint {
            height: 1000,
            epoch: 10,
            round: 5,
            block_hash: [1u8; 32],
            state_root: [2u8; 32],
            validator_set_hash: [3u8; 32],
            timestamp: 1700000000,
        };

        storage.chain.save_checkpoint(&checkpoint).unwrap();

        let retrieved = storage.chain.get_checkpoint(1000).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().height, 1000);
    }
}

// ============================================================================
// Genesis Tests
// ============================================================================

mod genesis_tests {
    use phantom_genesis::{
        GenesisBlock, GenesisConfig, NetworkConfig, ConsensusParams, ESLParams,
        Allocation, ValidatorConfig,
    };
    use tempfile::tempdir;

    // Simple hex encoding for test data
    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn create_test_genesis_config() -> GenesisConfig {
        GenesisConfig {
            network: NetworkConfig {
                network_id: "test-network".to_string(),
                chain_id: 1337,
                version: "0.1.0".to_string(),
            },
            consensus: ConsensusParams {
                witness_count: 5,
                threshold: 3,
                min_stake: 1000,
                epoch_length: 100,
                round_timeout_ms: 12000,
                finality_delay: 6,
            },
            esl: ESLParams {
                tree_depth: 32,
                max_accounts: 1_000_000,
                snapshot_interval: 1000,
            },
            allocations: vec![
                Allocation {
                    address: "0x0101010101010101010101010101010101010101010101010101010101010101".to_string(),
                    balance: 1_000_000,
                    is_validator: false,
                    stake: 0,
                },
                Allocation {
                    address: "0x0202020202020202020202020202020202020202020202020202020202020202".to_string(),
                    balance: 500_000,
                    is_validator: false,
                    stake: 0,
                },
            ],
            validators: vec![
                ValidatorConfig {
                    id: "validator-1".to_string(),
                    public_key: "0x".to_string() + &hex_encode(&vec![0u8; 64]),
                    vrf_key: "0x".to_string() + &hex_encode(&[0u8; 32]),
                    stake: 100_000,
                    commission: 500, // 5%
                },
            ],
            timestamp: 1700000000,
            extra_data: "PHANTOM Test Genesis".to_string(),
        }
    }

    #[test]
    fn test_genesis_from_config() {
        let config = create_test_genesis_config();
        let genesis = GenesisBlock::from_config(config);

        assert_eq!(genesis.config.network.chain_id, 1337);
        assert_eq!(genesis.config.network.network_id, "test-network");
    }

    #[test]
    fn test_genesis_mainnet() {
        let genesis = GenesisBlock::mainnet();

        assert_eq!(genesis.config.network.chain_id, 1);
        assert_eq!(genesis.config.network.network_id, "phantom-mainnet");
    }

    #[test]
    fn test_genesis_testnet() {
        let genesis = GenesisBlock::testnet();

        assert_eq!(genesis.config.network.chain_id, 2);
        assert_eq!(genesis.config.network.network_id, "phantom-testnet");
    }

    #[test]
    fn test_genesis_local() {
        let genesis = GenesisBlock::local();

        assert_eq!(genesis.config.network.chain_id, 1337);
        assert_eq!(genesis.config.network.network_id, "phantom-local");
    }

    #[test]
    fn test_genesis_hash_determinism() {
        let config1 = create_test_genesis_config();
        let config2 = create_test_genesis_config();

        let genesis1 = GenesisBlock::from_config(config1);
        let genesis2 = GenesisBlock::from_config(config2);

        // Same config should produce same hash
        assert_eq!(genesis1.hash, genesis2.hash);
    }

    #[test]
    fn test_genesis_state_root() {
        let config = create_test_genesis_config();
        let genesis = GenesisBlock::from_config(config);

        // State root should be set
        assert_ne!(genesis.state_root, [0u8; 32]);
    }

    #[test]
    fn test_genesis_allocations() {
        let config = create_test_genesis_config();
        let genesis = GenesisBlock::from_config(config);

        assert_eq!(genesis.config.allocations.len(), 2);
        assert_eq!(genesis.config.allocations[0].balance, 1_000_000);
        assert_eq!(genesis.config.allocations[1].balance, 500_000);
    }

    #[test]
    fn test_genesis_validators() {
        let config = create_test_genesis_config();
        let genesis = GenesisBlock::from_config(config);

        assert_eq!(genesis.config.validators.len(), 1);
        assert_eq!(genesis.config.validators[0].stake, 100_000);
    }

    #[test]
    fn test_genesis_json_serialization() {
        let config = create_test_genesis_config();
        let genesis = GenesisBlock::from_config(config);

        let dir = tempdir().unwrap();
        let path = dir.path().join("genesis.json");

        // Save to JSON
        genesis.save_json(&path).unwrap();

        // Load from JSON
        let loaded = GenesisBlock::load_json(&path).unwrap();

        assert_eq!(loaded.config.network.chain_id, genesis.config.network.chain_id);
        assert_eq!(loaded.hash, genesis.hash);
    }

    #[test]
    fn test_genesis_toml_serialization() {
        let config = create_test_genesis_config();
        let genesis = GenesisBlock::from_config(config);

        let dir = tempdir().unwrap();
        let path = dir.path().join("genesis.toml");

        // Save to TOML
        genesis.save_toml(&path).unwrap();

        // Load from TOML
        let loaded = GenesisBlock::load_toml(&path).unwrap();

        assert_eq!(loaded.config.network.chain_id, genesis.config.network.chain_id);
    }

    #[test]
    fn test_genesis_with_empty_allocations() {
        let mut config = create_test_genesis_config();
        config.allocations = vec![];
        config.validators = vec![];

        let genesis = GenesisBlock::from_config(config);

        assert!(genesis.config.allocations.is_empty());
        assert!(genesis.config.validators.is_empty());
    }

    #[test]
    fn test_genesis_consensus_params() {
        let config = create_test_genesis_config();
        let genesis = GenesisBlock::from_config(config);

        assert_eq!(genesis.config.consensus.witness_count, 5);
        assert_eq!(genesis.config.consensus.threshold, 3);
        assert_eq!(genesis.config.consensus.min_stake, 1000);
    }

    #[test]
    fn test_genesis_esl_params() {
        let config = create_test_genesis_config();
        let genesis = GenesisBlock::from_config(config);

        assert_eq!(genesis.config.esl.tree_depth, 32);
    }
}

// ============================================================================
// RPC Server Tests
// ============================================================================

mod rpc_tests {
    use phantom_rpc::RpcConfig;

    fn create_test_rpc_config() -> RpcConfig {
        RpcConfig {
            http_addr: "127.0.0.1:0".parse().unwrap(),
            ws_addr: None,
            max_request_size: 10 * 1024 * 1024,
            cors_enabled: true,
            cors_origins: vec!["*".to_string()],
            require_admin_auth: false,
            admin_api_key: None,
            network: "test".to_string(),
            ..RpcConfig::default()
        }
    }

    #[test]
    fn test_rpc_config_creation() {
        let config = create_test_rpc_config();
        assert!(config.cors_enabled);
        assert_eq!(config.network, "test");
    }

    #[test]
    fn test_rpc_config_default() {
        let config = RpcConfig::default();
        assert!(config.cors_enabled);
    }

    #[test]
    fn test_rpc_config_with_ws() {
        let mut config = create_test_rpc_config();
        config.ws_addr = Some("127.0.0.1:8546".parse().unwrap());

        assert!(config.ws_addr.is_some());
    }

    #[test]
    fn test_rpc_config_admin_auth() {
        let mut config = create_test_rpc_config();
        config.require_admin_auth = true;
        config.admin_api_key = Some("secret-key".to_string());

        assert!(config.require_admin_auth);
        assert_eq!(config.admin_api_key, Some("secret-key".to_string()));
    }

    #[test]
    fn test_cors_origins() {
        let config = create_test_rpc_config();
        assert!(config.cors_origins.contains(&"*".to_string()));
    }

    #[test]
    fn test_max_request_size() {
        let config = create_test_rpc_config();
        assert_eq!(config.max_request_size, 10 * 1024 * 1024);
    }
}

// ============================================================================
// Node Tests
// ============================================================================

mod node_tests {
    use phantom_node::{NodeConfig, NodeError};

    #[test]
    fn test_node_config_local() {
        let config = NodeConfig::local();

        assert_eq!(config.network, "local");
        assert!(!config.validator);
    }

    #[test]
    fn test_node_config_testnet() {
        let config = NodeConfig::testnet();

        assert_eq!(config.network, "testnet");
    }

    #[test]
    fn test_node_config_mainnet() {
        let config = NodeConfig::mainnet();

        assert_eq!(config.network, "mainnet");
    }

    #[test]
    fn test_node_error_display() {
        let io_error = NodeError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert!(format!("{}", io_error).contains("IO"));

        let config_error = NodeError::Config("invalid setting".to_string());
        assert!(format!("{}", config_error).contains("Configuration"));

        let not_running = NodeError::NotRunning;
        assert!(format!("{}", not_running).contains("not running"));
    }

    #[test]
    fn test_node_error_not_validator() {
        let error = NodeError::NotValidator;
        assert!(format!("{}", error).contains("validator"));
    }

    #[test]
    fn test_node_error_invalid_block() {
        let error = NodeError::InvalidBlock("bad signature".to_string());
        assert!(format!("{}", error).contains("Invalid block"));
    }
}

// ============================================================================
// End-to-End Integration Tests
// ============================================================================

mod e2e_tests {
    use phantom_storage::{
        Storage, StorageConfig,
        StoredBlock, StoredBlockHeader, StoredBlockBody,
        ChainMeta,
    };
    use phantom_genesis::GenesisBlock;
    use tempfile::tempdir;

    fn create_storage() -> (Storage, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        let config = StorageConfig {
            path,
            max_size: 100 * 1024 * 1024,
            enable_tx_cache: true,
            tx_cache_size: 1000,
            enable_snapshots: false,
            snapshot_interval: 1000,
        };
        let storage = Storage::with_config(config).unwrap();
        (storage, dir)
    }

    fn create_block(height: u64, prev_hash: [u8; 32]) -> StoredBlock {
        StoredBlock {
            header: StoredBlockHeader {
                height,
                hash: [height as u8; 32],
                prev_hash,
                state_root: [2u8; 32],
                tx_root: [3u8; 32],
                timestamp: 1700000000 + height * 12,
                producer: [4u8; 32],
                attestation_count: 3,
            },
            body: StoredBlockBody {
                transactions: vec![],
            },
        }
    }

    #[test]
    fn test_genesis_to_storage() {
        let (storage, _dir) = create_storage();

        // Create genesis
        let genesis = GenesisBlock::local();

        // Store genesis as first block
        let genesis_block = StoredBlock {
            header: StoredBlockHeader {
                height: 0,
                hash: genesis.hash,
                prev_hash: [0u8; 32],
                state_root: genesis.state_root,
                tx_root: [0u8; 32],
                timestamp: genesis.config.timestamp,
                producer: [0u8; 32],
                attestation_count: 0,
            },
            body: StoredBlockBody {
                transactions: vec![],
            },
        };

        storage.blocks.put(&genesis_block).unwrap();

        // Store chain metadata
        let meta = ChainMeta {
            genesis_hash: genesis.hash,
            network_id: genesis.config.network.network_id.clone(),
            chain_id: genesis.config.network.chain_id,
            genesis_timestamp: genesis.config.timestamp,
            current_epoch: 0,
            current_round: 0,
            finalized_height: 0,
            finalized_hash: genesis.hash,
            current_height: 0,
        };
        storage.chain.save_meta(&meta).unwrap();

        // Verify
        let retrieved = storage.blocks.get(0).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().header.hash, genesis.hash);

        let chain_meta = storage.chain.get_meta().unwrap().unwrap();
        assert_eq!(chain_meta.genesis_hash, genesis.hash);
    }

    #[test]
    fn test_block_chain_storage() {
        let (storage, _dir) = create_storage();

        // Create genesis
        let genesis = create_block(0, [0u8; 32]);
        storage.blocks.put(&genesis).unwrap();

        // Build chain
        let mut prev_hash = genesis.header.hash;
        for height in 1..=10u64 {
            let block = create_block(height, prev_hash);
            prev_hash = block.header.hash;
            storage.blocks.put(&block).unwrap();
        }

        // Verify chain
        assert_eq!(storage.blocks.count().unwrap(), 11);

        let latest = storage.blocks.latest_height().unwrap();
        assert_eq!(latest, Some(10));
    }

    #[test]
    fn test_chain_meta_updates() {
        let (storage, _dir) = create_storage();

        // Initial meta
        let mut meta = ChainMeta {
            genesis_hash: [1u8; 32],
            network_id: "local".to_string(),
            chain_id: 31337,
            genesis_timestamp: 1700000000,
            current_epoch: 0,
            current_round: 0,
            finalized_height: 0,
            finalized_hash: [1u8; 32],
            current_height: 0,
        };
        storage.chain.save_meta(&meta).unwrap();

        // Update as blocks are added
        for height in 1..=5u64 {
            meta.current_height = height;
            meta.finalized_height = height.saturating_sub(1);
            storage.chain.save_meta(&meta).unwrap();
        }

        // Verify final state
        let retrieved = storage.chain.get_meta().unwrap().unwrap();
        assert_eq!(retrieved.current_height, 5);
        assert_eq!(retrieved.finalized_height, 4);
    }

    #[test]
    fn test_multiple_networks() {
        // Test mainnet genesis
        let mainnet = GenesisBlock::mainnet();
        assert_eq!(mainnet.config.network.chain_id, 1);

        // Test testnet genesis
        let testnet = GenesisBlock::testnet();
        assert_eq!(testnet.config.network.chain_id, 2);

        // Test local genesis
        let local = GenesisBlock::local();
        assert_eq!(local.config.network.chain_id, 1337);

        // All should have different hashes
        assert_ne!(mainnet.hash, testnet.hash);
        assert_ne!(testnet.hash, local.hash);
        assert_ne!(mainnet.hash, local.hash);
    }
}

// ============================================================================
// Performance Tests (Ignored by default)
// ============================================================================

mod performance_tests {
    use phantom_storage::{
        Storage, StorageConfig,
        StoredBlock, StoredBlockHeader, StoredBlockBody,
    };
    use tempfile::tempdir;
    use std::time::Instant;

    fn create_block(height: u64) -> StoredBlock {
        StoredBlock {
            header: StoredBlockHeader {
                height,
                hash: [height as u8; 32],
                prev_hash: [0u8; 32],
                state_root: [2u8; 32],
                tx_root: [3u8; 32],
                timestamp: 1700000000 + height,
                producer: [4u8; 32],
                attestation_count: 3,
            },
            body: StoredBlockBody {
                transactions: vec![],
            },
        }
    }

    #[test]
    #[ignore] // Run with: cargo test --test phase4_integration -- --ignored
    fn test_bulk_block_write_performance() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        let config = StorageConfig {
            path,
            max_size: 1024 * 1024 * 1024,
            enable_tx_cache: true,
            tx_cache_size: 10000,
            enable_snapshots: false,
            snapshot_interval: 1000,
        };
        let storage = Storage::with_config(config).unwrap();

        let num_blocks = 10_000u64;

        let start = Instant::now();

        for i in 0..num_blocks {
            let block = create_block(i);
            storage.blocks.put(&block).unwrap();
        }

        let duration = start.elapsed();
        let blocks_per_sec = num_blocks as f64 / duration.as_secs_f64();

        println!(
            "Wrote {} blocks in {:?} ({:.0} blocks/sec)",
            num_blocks, duration, blocks_per_sec
        );

        assert!(blocks_per_sec > 1000.0, "Should write at least 1000 blocks/sec");
    }

    #[test]
    #[ignore]
    fn test_bulk_state_snapshot_performance() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        let config = StorageConfig {
            path,
            max_size: 1024 * 1024 * 1024,
            enable_tx_cache: true,
            tx_cache_size: 10000,
            enable_snapshots: true,
            snapshot_interval: 1,
        };
        let storage = Storage::with_config(config).unwrap();

        let num_snapshots = 1000;

        let start = Instant::now();

        for i in 0..num_snapshots {
            let snapshot = phantom_storage::StateSnapshot {
                epoch: i,
                height: i * 100,
                state_root: [i as u8; 32],
                account_count: 1000 + i,
                validator_set_hash: [0u8; 32],
                timestamp: 1700000000 + i * 600,
                tree_data: vec![0u8; 100],
            };
            storage.state.save_snapshot(&snapshot).unwrap();
        }

        let duration = start.elapsed();
        let snapshots_per_sec = num_snapshots as f64 / duration.as_secs_f64();

        println!(
            "Wrote {} state snapshots in {:?} ({:.0} snapshots/sec)",
            num_snapshots, duration, snapshots_per_sec
        );

        assert!(snapshots_per_sec > 100.0, "Should write at least 100 snapshots/sec");
    }

    #[test]
    #[ignore]
    fn test_block_read_performance() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        let config = StorageConfig {
            path,
            max_size: 1024 * 1024 * 1024,
            enable_tx_cache: true,
            tx_cache_size: 10000,
            enable_snapshots: false,
            snapshot_interval: 1000,
        };
        let storage = Storage::with_config(config).unwrap();

        // Pre-populate
        let num_blocks = 10_000u64;
        for i in 0..num_blocks {
            let block = create_block(i);
            storage.blocks.put(&block).unwrap();
        }

        // Measure read performance
        let start = Instant::now();
        let num_reads = 50_000;

        for i in 0..num_reads {
            let height = (i % num_blocks) as u64;
            storage.blocks.get(height).unwrap();
        }

        let duration = start.elapsed();
        let reads_per_sec = num_reads as f64 / duration.as_secs_f64();

        println!(
            "Read {} blocks in {:?} ({:.0} reads/sec)",
            num_reads, duration, reads_per_sec
        );

        assert!(reads_per_sec > 10000.0, "Should read at least 10000 blocks/sec");
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

mod error_tests {
    use phantom_storage::{Storage, StorageError};
    use phantom_node::NodeError;

    #[test]
    fn test_storage_invalid_path() {
        let result = Storage::open("/nonexistent/deeply/nested/path/that/cannot/exist/test.db");
        // Should either succeed creating the path or fail gracefully
        // The actual behavior depends on implementation
        let _ = result;
    }

    #[test]
    fn test_node_error_from_io() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "test");
        let node_error = NodeError::Io(io_error);

        assert!(matches!(node_error, NodeError::Io(_)));
    }

    #[test]
    fn test_storage_error_block_not_found() {
        let error = StorageError::BlockNotFound(999);
        assert!(format!("{}", error).contains("999"));
    }

    #[test]
    fn test_storage_error_invalid_data() {
        let error = StorageError::InvalidData("corrupted".to_string());
        assert!(format!("{}", error).contains("Invalid data"));
    }
}
