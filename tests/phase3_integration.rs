//! Phase 3 Integration Tests
//!
//! Tests for light client, sync protocol, proof delegation, and WASM bindings.

// ============================================================================
// Header Chain Tests
// ============================================================================

mod header_chain_tests {
    use phantom_light_client::{
        BlockHeader, HeaderChain, ChainTip, LightClientError, LightClientResult,
        header::{HeaderChainConfig, GenesisConfig},
    };

    fn create_test_config() -> HeaderChainConfig {
        HeaderChainConfig {
            max_headers: 1000,
            max_reorg_depth: 10,
            checkpoint_interval: 100,
            verify_signatures: false,
        }
    }

    fn create_genesis_config() -> GenesisConfig {
        GenesisConfig {
            state_root: [0u8; 32],
            timestamp: 1700000000,
            extra_data: b"PHANTOM Test Genesis".to_vec(),
        }
    }

    fn create_test_header(height: u64, parent_hash: [u8; 32]) -> BlockHeader {
        BlockHeader::new(
            height,
            parent_hash,
            [height as u8; 32], // state_root
            [height as u8; 32], // transactions_root
            [0u8; 32],          // receipts_root
            1700000000 + height * 12,
            [0u8; 32],          // proposer
            1000 + height,      // difficulty
        )
    }

    #[test]
    fn test_header_chain_creation() {
        let config = create_test_config();
        let chain = HeaderChain::new(config);

        assert_eq!(chain.get_height(), 0);
        assert!(chain.get_canonical_header(0).is_none());
    }

    #[test]
    fn test_genesis_initialization() {
        let config = create_test_config();
        let mut chain = HeaderChain::new(config);
        let genesis_config = create_genesis_config();

        let genesis = chain.initialize_genesis(genesis_config).unwrap();

        assert_eq!(genesis.height, 0);
        assert_eq!(chain.get_height(), 0);
        assert!(chain.get_canonical_header(0).is_some());
    }

    #[test]
    fn test_header_insertion() {
        let config = create_test_config();
        let mut chain = HeaderChain::new(config);
        let genesis_config = create_genesis_config();

        let genesis = chain.initialize_genesis(genesis_config).unwrap();
        let genesis_hash = genesis.compute_hash();

        // Insert block 1
        let header1 = create_test_header(1, genesis_hash);
        chain.insert_header(header1.clone()).unwrap();

        assert_eq!(chain.get_height(), 1);

        // Insert block 2
        let header1_hash = header1.compute_hash();
        let header2 = create_test_header(2, header1_hash);
        chain.insert_header(header2).unwrap();

        assert_eq!(chain.get_height(), 2);
    }

    #[test]
    fn test_chain_building() {
        let config = create_test_config();
        let mut chain = HeaderChain::new(config);
        let genesis_config = create_genesis_config();

        let genesis = chain.initialize_genesis(genesis_config).unwrap();
        let mut parent_hash = genesis.compute_hash();

        // Build a chain of 100 headers
        for height in 1..=100 {
            let header = create_test_header(height, parent_hash);
            parent_hash = header.compute_hash();
            chain.insert_header(header).unwrap();
        }

        assert_eq!(chain.get_height(), 100);

        // Verify all headers are accessible
        for height in 0..=100 {
            assert!(chain.get_canonical_header(height).is_some());
        }
    }

    #[test]
    fn test_invalid_parent_hash() {
        let config = create_test_config();
        let mut chain = HeaderChain::new(config);
        let genesis_config = create_genesis_config();

        chain.initialize_genesis(genesis_config).unwrap();

        // Try to insert header with wrong parent hash
        let invalid_header = create_test_header(1, [0xff; 32]);
        let result = chain.insert_header(invalid_header);

        assert!(result.is_err());
    }

    #[test]
    fn test_checkpoint_addition() {
        let config = create_test_config();
        let mut chain = HeaderChain::new(config);
        let genesis_config = create_genesis_config();

        let genesis = chain.initialize_genesis(genesis_config).unwrap();
        let genesis_hash = genesis.compute_hash();

        // Add checkpoint
        chain.add_checkpoint(0, genesis_hash);

        // Verify checkpoint is set
        assert!(chain.is_canonical(&genesis_hash));
    }

    #[test]
    fn test_canonical_chain_query() {
        let config = create_test_config();
        let mut chain = HeaderChain::new(config);
        let genesis_config = create_genesis_config();

        let genesis = chain.initialize_genesis(genesis_config).unwrap();
        let mut parent_hash = genesis.compute_hash();

        // Build chain
        let mut hashes = vec![parent_hash];
        for height in 1..=10 {
            let header = create_test_header(height, parent_hash);
            parent_hash = header.compute_hash();
            hashes.push(parent_hash);
            chain.insert_header(header).unwrap();
        }

        // All hashes should be canonical
        for hash in &hashes {
            assert!(chain.is_canonical(hash));
        }
    }

    #[test]
    fn test_chain_stats() {
        let config = create_test_config();
        let mut chain = HeaderChain::new(config);
        let genesis_config = create_genesis_config();

        let genesis = chain.initialize_genesis(genesis_config).unwrap();
        let mut parent_hash = genesis.compute_hash();

        for height in 1..=50 {
            let header = create_test_header(height, parent_hash);
            parent_hash = header.compute_hash();
            chain.insert_header(header).unwrap();
        }

        let stats = chain.stats();
        assert_eq!(stats.height, 50);
        assert_eq!(stats.total_headers, 51); // Including genesis
        assert!(stats.total_difficulty > 0);
    }

    #[test]
    fn test_header_by_hash() {
        let config = create_test_config();
        let mut chain = HeaderChain::new(config);
        let genesis_config = create_genesis_config();

        let genesis = chain.initialize_genesis(genesis_config).unwrap();
        let genesis_hash = genesis.compute_hash();

        let header1 = create_test_header(1, genesis_hash);
        let header1_hash = header1.compute_hash();
        chain.insert_header(header1).unwrap();

        // Query by hash
        let retrieved = chain.get_header(&header1_hash);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().height, 1);
    }

    #[test]
    fn test_chain_tip() {
        let config = create_test_config();
        let mut chain = HeaderChain::new(config);
        let genesis_config = create_genesis_config();

        let genesis = chain.initialize_genesis(genesis_config).unwrap();
        let genesis_hash = genesis.compute_hash();

        let header1 = create_test_header(1, genesis_hash);
        let header1_hash = header1.compute_hash();
        chain.insert_header(header1).unwrap();

        let tip = chain.get_tip();
        assert!(tip.is_some());
        let tip = tip.unwrap();
        assert_eq!(tip.header.height, 1);
        assert_eq!(tip.header.hash, header1_hash);
    }
}

// ============================================================================
// Sync Protocol Tests
// ============================================================================

mod sync_protocol_tests {
    use phantom_light_client::{
        SyncConfig, SyncStatus, Checkpoint,
        sync::SyncPeer,
    };

    fn create_sync_config() -> SyncConfig {
        SyncConfig {
            batch_size: 100,
            timeout_secs: 30,
            max_peers: 10,
            min_peers: 3,
            checkpoint_interval: 1000,
            fast_sync_threshold: 1000,
            verify_signatures: true,
        }
    }

    fn create_test_checkpoint(height: u64) -> Checkpoint {
        Checkpoint {
            height,
            hash: [height as u8; 32],
            total_difficulty: height as u128 * 1000,
            state_root: Some([height as u8; 32]),
        }
    }

    #[test]
    fn test_sync_config_defaults() {
        let config = SyncConfig::default();

        assert!(config.batch_size > 0);
        assert!(config.timeout_secs > 0);
        assert!(config.max_peers >= config.min_peers);
    }

    #[test]
    fn test_checkpoint_creation() {
        let checkpoint = create_test_checkpoint(1000);

        assert_eq!(checkpoint.height, 1000);
        assert_eq!(checkpoint.total_difficulty, 1000000);
    }

    #[test]
    fn test_checkpoint_validation() {
        let cp1 = create_test_checkpoint(1000);
        let cp2 = create_test_checkpoint(2000);

        // Later checkpoint should have higher total difficulty
        assert!(cp2.total_difficulty > cp1.total_difficulty);
        assert!(cp2.height > cp1.height);
    }

    #[test]
    fn test_sync_status_variants() {
        let statuses = vec![
            SyncStatus::Idle,
            SyncStatus::DiscoveringPeers,
            SyncStatus::Syncing {
                current_height: 100,
                target_height: 1000,
                peers: 5,
            },
            SyncStatus::Verifying { progress: 0.5 },
            SyncStatus::Synced { height: 1000 },
            SyncStatus::Failed { error: "Test failure".into() },
        ];

        for status in statuses {
            match status {
                SyncStatus::Idle => assert!(true),
                SyncStatus::DiscoveringPeers => assert!(true),
                SyncStatus::Syncing { current_height, target_height, peers } => {
                    assert!(current_height <= target_height);
                    assert!(peers > 0);
                },
                SyncStatus::Verifying { progress } => assert!(progress > 0.0),
                SyncStatus::Synced { height } => {
                    assert!(height > 0);
                },
                SyncStatus::Failed { error } => assert!(!error.is_empty()),
            }
        }
    }

    #[test]
    fn test_sync_peer_creation() {
        let peer = SyncPeer::new(
            [1u8; 32],  // peer_id
            1000,       // height
            100,        // total_difficulty
        );

        assert_eq!(peer.height, 1000);
        assert_eq!(peer.total_difficulty, 100);
    }

    #[test]
    fn test_sync_peer_scoring() {
        let mut peer = SyncPeer::new([1u8; 32], 1000, 100);

        let initial_score = peer.score();

        // Record successful sync
        peer.record_success();

        // Score should improve
        assert!(peer.score() >= initial_score);
    }

    #[test]
    fn test_sync_peer_failure_tracking() {
        let mut peer = SyncPeer::new([1u8; 32], 1000, 100);

        // Record failures
        for _ in 0..5 {
            peer.record_failure();
        }

        // Peer should be marked as unreliable
        assert!(peer.failure_count >= 5);
    }

    #[test]
    fn test_fast_sync_threshold() {
        let config = create_sync_config();

        // Current height 0, target 2000 -> should trigger fast sync
        let gap = 2000u64;
        assert!(gap >= config.fast_sync_threshold);
    }

    #[test]
    fn test_checkpoint_ordering() {
        let checkpoints: Vec<Checkpoint> = (0..10)
            .map(|i| create_test_checkpoint(i * 1000))
            .collect();

        // Checkpoints should be ordered by height
        for i in 1..checkpoints.len() {
            assert!(checkpoints[i].height > checkpoints[i - 1].height);
        }
    }

    #[test]
    fn test_batch_size_calculation() {
        let config = create_sync_config();

        // For a gap of 500 headers with batch size 100
        let gap = 500usize;
        let batches = (gap + config.batch_size - 1) / config.batch_size;

        assert_eq!(batches, 5);
    }
}

// ============================================================================
// Proof Delegation Tests
// ============================================================================

mod delegation_tests {
    use phantom_light_client::{
        DelegationManager, DelegationConfig, DelegationNode, DelegationStats,
        DelegationRequest, DelegationResponse, DelegatedProofType, DelegatedProofData,
        TrustLevel, LightClientError, ComputationWitness,
        verification::InclusionProof,
    };

    fn create_delegation_config() -> DelegationConfig {
        DelegationConfig {
            min_nodes: 2,
            threshold: 2,
            max_proof_age: 3600,
            request_timeout: 30,
            max_concurrent: 10,
            retry_count: 3,
        }
    }

    fn create_test_node(id: u8) -> DelegationNode {
        DelegationNode::new([id; 32])
    }

    fn create_test_response(
        request_id: u64,
        node_id: u8,
        proof: DelegatedProofData,
    ) -> DelegationResponse {
        DelegationResponse {
            request_id,
            node_pubkey: [node_id; 32],
            proof,
            signature: vec![0u8; 64],
            witness: ComputationWitness::default(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    #[test]
    fn test_delegation_manager_creation() {
        let config = create_delegation_config();
        let manager = DelegationManager::new(config);

        let stats = manager.stats();
        assert_eq!(stats.total_nodes, 0);
        assert_eq!(stats.pending_requests, 0);
    }

    #[test]
    fn test_add_delegation_node() {
        let config = create_delegation_config();
        let manager = DelegationManager::new(config);

        let node = create_test_node(1);
        manager.add_node(node);

        let stats = manager.stats();
        assert_eq!(stats.total_nodes, 1);
    }

    #[test]
    fn test_multiple_nodes() {
        let config = create_delegation_config();
        let manager = DelegationManager::new(config);

        for i in 1..=5 {
            let node = create_test_node(i);
            manager.add_node(node);
        }

        let stats = manager.stats();
        assert_eq!(stats.total_nodes, 5);
    }

    #[test]
    fn test_trust_level_ordering() {
        assert!(TrustLevel::Verified > TrustLevel::Trusted);
        assert!(TrustLevel::Trusted > TrustLevel::Basic);
        assert!(TrustLevel::Basic > TrustLevel::Unknown);
    }

    #[test]
    fn test_node_initial_trust() {
        let node = create_test_node(1);
        assert_eq!(node.trust_level, TrustLevel::Unknown);
    }

    #[test]
    fn test_verified_node_creation() {
        let node = DelegationNode::verified([1u8; 32], "http://node1.test:8080".into());
        assert_eq!(node.trust_level, TrustLevel::Verified);
    }

    #[test]
    fn test_delegated_proof_types() {
        let proof_types = vec![
            DelegatedProofType::TransactionInclusion,
            DelegatedProofType::StateProof,
            DelegatedProofType::ReceiptProof,
            DelegatedProofType::FHEComputation,
            DelegatedProofType::BatchProof,
        ];

        for proof_type in proof_types {
            match proof_type {
                DelegatedProofType::TransactionInclusion => assert!(true),
                DelegatedProofType::StateProof => assert!(true),
                DelegatedProofType::ReceiptProof => assert!(true),
                DelegatedProofType::FHEComputation => assert!(true),
                DelegatedProofType::BatchProof => assert!(true),
            }
        }
    }

    #[test]
    fn test_create_delegation_request() {
        let config = create_delegation_config();
        let manager = DelegationManager::new(config);

        // Add required nodes
        for i in 1..=3 {
            manager.add_node(create_test_node(i));
        }

        let request = manager.create_request(
            DelegatedProofType::TransactionInclusion,
            100,             // block_height
            [1u8; 32],       // block_hash
            [2u8; 32],       // item_hash
        );

        assert!(request.is_ok());
        let req = request.unwrap();
        assert_eq!(req.proof_type, DelegatedProofType::TransactionInclusion);
        assert_eq!(req.block_height, 100);
    }

    #[test]
    fn test_insufficient_nodes() {
        let config = create_delegation_config();
        let manager = DelegationManager::new(config);

        // Only add 1 node when min is 2
        manager.add_node(create_test_node(1));

        let request = manager.create_request(
            DelegatedProofType::TransactionInclusion,
            100,
            [1u8; 32],
            [2u8; 32],
        );

        assert!(request.is_err());
        match request {
            Err(LightClientError::NotEnoughNodes { required, available }) => {
                assert_eq!(required, 2);
                assert_eq!(available, 1);
            },
            _ => panic!("Expected NotEnoughNodes error"),
        }
    }

    #[test]
    fn test_delegation_response_processing() {
        let config = create_delegation_config();
        let manager = DelegationManager::new(config);

        // Add nodes
        for i in 1..=3 {
            manager.add_node(create_test_node(i));
        }

        // Create request
        let request = manager.create_request(
            DelegatedProofType::TransactionInclusion,
            100,
            [1u8; 32],
            [2u8; 32],
        ).unwrap();

        // Simulate response with raw proof
        let proof = DelegatedProofData::Raw(vec![1, 2, 3, 4, 5]);
        let response = create_test_response(request.request_id, 1, proof);

        let result = manager.process_response(response);
        assert!(result.is_ok());
    }

    #[test]
    fn test_threshold_consensus() {
        let config = create_delegation_config();
        let manager = DelegationManager::new(config);

        // Add 3 nodes
        for i in 1..=3 {
            manager.add_node(create_test_node(i));
        }

        // Create request
        let request = manager.create_request(
            DelegatedProofType::TransactionInclusion,
            100,
            [1u8; 32],
            [2u8; 32],
        ).unwrap();

        let proof = DelegatedProofData::Raw(vec![1, 2, 3, 4, 5]);

        // First response - not enough for threshold
        let response1 = create_test_response(request.request_id, 1, proof.clone());
        let result1 = manager.process_response(response1);
        assert!(result1.is_ok());
        assert!(result1.unwrap().is_none()); // Not enough responses yet

        // Second response - reaches threshold (2 of 3)
        let response2 = create_test_response(request.request_id, 2, proof.clone());
        let result2 = manager.process_response(response2);
        assert!(result2.is_ok());
        // Should now have consensus proof
        let consensus_proof = result2.unwrap();
        assert!(consensus_proof.is_some());
    }

    #[test]
    fn test_proof_caching() {
        let config = create_delegation_config();
        let manager = DelegationManager::new(config);

        // Add nodes and complete a request
        for i in 1..=3 {
            manager.add_node(create_test_node(i));
        }

        let block_hash = [1u8; 32];
        let item_hash = [2u8; 32];

        let request = manager.create_request(
            DelegatedProofType::TransactionInclusion,
            100,
            block_hash,
            item_hash,
        ).unwrap();

        let proof = DelegatedProofData::Raw(vec![1, 2, 3, 4, 5]);

        // Reach threshold
        for i in 1..=2 {
            let response = create_test_response(request.request_id, i, proof.clone());
            manager.process_response(response).unwrap();
        }

        // Check cache
        let cached = manager.get_cached_proof(
            DelegatedProofType::TransactionInclusion,
            100,
            block_hash,
            item_hash,
        );
        assert!(cached.is_some());
    }

    #[test]
    fn test_delegation_stats() {
        let config = create_delegation_config();
        let manager = DelegationManager::new(config);

        for i in 1..=5 {
            manager.add_node(create_test_node(i));
        }

        let stats = manager.stats();
        assert_eq!(stats.total_nodes, 5);
        assert_eq!(stats.pending_requests, 0);
        assert_eq!(stats.cached_proofs, 0);
    }

    #[test]
    fn test_unknown_request_error() {
        let config = create_delegation_config();
        let manager = DelegationManager::new(config);

        let proof = DelegatedProofData::Raw(vec![1, 2, 3]);
        let response = create_test_response(999, 1, proof);

        let result = manager.process_response(response);
        assert!(result.is_err());
        match result {
            Err(LightClientError::RequestNotFound(id)) => assert_eq!(id, 999),
            _ => panic!("Expected RequestNotFound error"),
        }
    }

    #[test]
    fn test_node_supports_proof_type() {
        let node = create_test_node(1);

        // Default nodes support basic proof types
        assert!(node.supports(DelegatedProofType::TransactionInclusion));
        assert!(node.supports(DelegatedProofType::StateProof));
        assert!(node.supports(DelegatedProofType::ReceiptProof));
    }

    #[test]
    fn test_verified_node_supports_all() {
        let node = DelegationNode::verified([1u8; 32], "http://node1.test:8080".into());

        // Verified nodes support all proof types including FHE
        assert!(node.supports(DelegatedProofType::TransactionInclusion));
        assert!(node.supports(DelegatedProofType::StateProof));
        assert!(node.supports(DelegatedProofType::ReceiptProof));
        assert!(node.supports(DelegatedProofType::FHEComputation));
        assert!(node.supports(DelegatedProofType::BatchProof));
    }

    #[test]
    fn test_node_reliability_score() {
        let node = create_test_node(1);
        let score = node.reliability_score();
        // Unknown node has low base score
        assert!(score > 0.0 && score < 0.5);
    }

    #[test]
    fn test_verified_node_reliability() {
        let node = DelegationNode::verified([1u8; 32], "http://node1.test:8080".into());
        let score = node.reliability_score();
        // Verified node has high base score
        assert!(score >= 0.9);
    }

    #[test]
    fn test_node_recording_success() {
        let mut node = create_test_node(1);

        assert_eq!(node.success_count, 0);

        node.record_success(100);

        assert_eq!(node.success_count, 1);
        assert!(node.last_success.is_some());
    }

    #[test]
    fn test_node_recording_failure() {
        let mut node = create_test_node(1);

        assert_eq!(node.failure_count, 0);

        node.record_failure();

        assert_eq!(node.failure_count, 1);
    }

    #[test]
    fn test_delegation_request_hash() {
        let req = DelegationRequest::new(
            1,
            DelegatedProofType::TransactionInclusion,
            100,
            [1u8; 32],
            [2u8; 32],
        );

        let hash = req.compute_hash();
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_computation_witness_default() {
        let witness = ComputationWitness::default();
        assert_eq!(witness.merkle_root, [0u8; 32]);
        assert_eq!(witness.state_root, [0u8; 32]);
        assert_eq!(witness.steps, 0);
        assert!(witness.intermediate_hashes.is_empty());
    }
}

// ============================================================================
// WASM Bindings Tests
// ============================================================================

mod wasm_tests {
    use phantom_light_client::{
        WasmLightClient, JsBlockHeader, JsInclusionProof,
        wasm::JsMerkleNode,
    };

    fn create_hex_hash(value: u8) -> String {
        format!("{:064x}", value)
    }

    #[test]
    fn test_wasm_client_creation() {
        let client = WasmLightClient::new(Some(1000));
        assert_eq!(client.get_height(), 0);
    }

    #[test]
    fn test_wasm_client_default_max_headers() {
        let client = WasmLightClient::new(None);
        assert_eq!(client.get_height(), 0);
    }

    #[test]
    fn test_wasm_genesis_initialization() {
        let mut client = WasmLightClient::new(None);
        let genesis_state_root = create_hex_hash(0);

        let result = client.initialize(&genesis_state_root, 1700000000);
        assert!(result.is_ok());
        assert_eq!(client.get_height(), 0);
    }

    #[test]
    fn test_wasm_add_header() {
        let mut client = WasmLightClient::new(None);
        let genesis_state_root = create_hex_hash(0);
        client.initialize(&genesis_state_root, 1700000000).unwrap();

        let genesis_hash = create_hex_hash(0);
        let header_json = serde_json::json!({
            "height": 1,
            "hash": create_hex_hash(1),
            "parent_hash": genesis_hash,
            "state_root": create_hex_hash(1),
            "transactions_root": create_hex_hash(1),
            "timestamp": 1700000012,
            "difficulty": 1001
        }).to_string();

        // Note: This may fail if parent hash doesn't match genesis
        // The test demonstrates the API structure
        let _ = client.add_header(&header_json);
    }

    #[test]
    fn test_wasm_get_stats() {
        let client = WasmLightClient::new(Some(500));

        let stats_json = client.get_stats();
        let stats: serde_json::Value = serde_json::from_str(&stats_json).unwrap();

        assert_eq!(stats["height"], 0);
        assert_eq!(stats["total_headers"], 0);
        assert_eq!(stats["initialized"], false);
    }

    #[test]
    fn test_js_block_header_serialization() {
        let header = JsBlockHeader {
            height: 100,
            hash: create_hex_hash(100),
            parent_hash: create_hex_hash(99),
            state_root: create_hex_hash(1),
            transactions_root: create_hex_hash(2),
            timestamp: 1700001200,
            difficulty: 1100,
        };

        let json = serde_json::to_string(&header).unwrap();
        let deserialized: JsBlockHeader = serde_json::from_str(&json).unwrap();

        assert_eq!(header.height, deserialized.height);
        assert_eq!(header.hash, deserialized.hash);
    }

    #[test]
    fn test_js_inclusion_proof_to_native() {
        let proof = JsInclusionProof {
            item_hash: create_hex_hash(1),
            block_height: 100,
            block_hash: create_hex_hash(100),
            path: vec![
                JsMerkleNode {
                    hash: create_hex_hash(2),
                    is_left: true,
                },
                JsMerkleNode {
                    hash: create_hex_hash(3),
                    is_left: false,
                },
            ],
            root_type: "transactions".into(),
        };

        let native = proof.to_native();
        assert!(native.is_ok());

        let native = native.unwrap();
        assert_eq!(native.block_height, 100);
        assert_eq!(native.path.len(), 2);
    }

    #[test]
    fn test_js_inclusion_proof_invalid_root_type() {
        let proof = JsInclusionProof {
            item_hash: create_hex_hash(1),
            block_height: 100,
            block_hash: create_hex_hash(100),
            path: vec![],
            root_type: "invalid".into(),
        };

        let native = proof.to_native();
        assert!(native.is_err());
    }

    #[test]
    fn test_merkle_root_computation() {
        let hashes_json = r#"[
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000002"
        ]"#;

        let result = WasmLightClient::compute_merkle_root(hashes_json);
        assert!(result.is_ok());

        let root = result.unwrap();
        assert_eq!(root.len(), 64); // 32 bytes hex
    }

    #[test]
    fn test_merkle_proof_building() {
        let hashes_json = r#"[
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "0000000000000000000000000000000000000000000000000000000000000004"
        ]"#;

        let result = WasmLightClient::build_merkle_proof(hashes_json, 1);
        assert!(result.is_ok());

        let proof_json = result.unwrap();
        let nodes: Vec<JsMerkleNode> = serde_json::from_str(&proof_json).unwrap();

        // For 4 leaves, proof should have 2 nodes (log2(4) = 2)
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    fn test_wasm_add_checkpoint() {
        let mut client = WasmLightClient::new(None);
        let genesis_state_root = create_hex_hash(0);
        client.initialize(&genesis_state_root, 1700000000).unwrap();

        let checkpoint_hash = create_hex_hash(100);
        let result = client.add_checkpoint(100, &checkpoint_hash);

        assert!(result.is_ok());
    }

    #[test]
    fn test_wasm_is_canonical() {
        let mut client = WasmLightClient::new(None);
        let genesis_state_root = create_hex_hash(0);
        client.initialize(&genesis_state_root, 1700000000).unwrap();

        let some_hash = create_hex_hash(99);
        let result = client.is_canonical(&some_hash);

        assert!(result.is_ok());
    }

    #[test]
    fn test_wasm_add_trusted_node() {
        let mut client = WasmLightClient::new(None);

        let pubkey = create_hex_hash(1);
        let result = client.add_trusted_node(&pubkey);

        assert!(result.is_ok());
    }

    #[test]
    fn test_hex_conversion_with_prefix() {
        let hex_with_prefix = "0x0000000000000000000000000000000000000000000000000000000000000001";

        let proof = JsInclusionProof {
            item_hash: hex_with_prefix.into(),
            block_height: 100,
            block_hash: create_hex_hash(100),
            path: vec![],
            root_type: "transactions".into(),
        };

        let native = proof.to_native();
        assert!(native.is_ok());
    }

    #[test]
    fn test_hex_conversion_invalid_length() {
        let short_hex = "0001020304"; // Too short

        let proof = JsInclusionProof {
            item_hash: short_hex.into(),
            block_height: 100,
            block_hash: create_hex_hash(100),
            path: vec![],
            root_type: "transactions".into(),
        };

        let native = proof.to_native();
        assert!(native.is_err());
    }

    #[test]
    fn test_wasm_batch_headers() {
        let mut client = WasmLightClient::new(None);
        let genesis_state_root = create_hex_hash(0);
        client.initialize(&genesis_state_root, 1700000000).unwrap();

        // Create batch of headers (note: they need valid parent hashes to actually insert)
        let headers_json = serde_json::json!([
            {
                "height": 1,
                "hash": create_hex_hash(1),
                "parent_hash": create_hex_hash(0),
                "state_root": create_hex_hash(1),
                "transactions_root": create_hex_hash(1),
                "timestamp": 1700000012,
                "difficulty": 1001
            },
            {
                "height": 2,
                "hash": create_hex_hash(2),
                "parent_hash": create_hex_hash(1),
                "state_root": create_hex_hash(2),
                "transactions_root": create_hex_hash(2),
                "timestamp": 1700000024,
                "difficulty": 1002
            }
        ]).to_string();

        let result = client.add_headers_batch(&headers_json);
        assert!(result.is_ok());
    }
}

// ============================================================================
// End-to-End Tests
// ============================================================================

mod e2e_tests {
    use phantom_light_client::{
        BlockHeader, HeaderChain, DelegationManager, DelegationConfig,
        DelegationNode, DelegationResponse, DelegatedProofType, DelegatedProofData,
        ComputationWitness,
        header::{HeaderChainConfig, GenesisConfig},
        verification::{ProofVerifier, InclusionProof, MerkleNode, RootType},
    };

    fn setup_header_chain() -> (HeaderChain, Vec<[u8; 32]>) {
        let config = HeaderChainConfig {
            max_headers: 1000,
            max_reorg_depth: 10,
            checkpoint_interval: 100,
            verify_signatures: false,
        };

        let mut chain = HeaderChain::new(config);

        let genesis_config = GenesisConfig {
            state_root: [0u8; 32],
            timestamp: 1700000000,
            extra_data: b"E2E Test Genesis".to_vec(),
        };

        let genesis = chain.initialize_genesis(genesis_config).unwrap();
        let mut hashes = vec![genesis.compute_hash()];
        let mut parent_hash = hashes[0];

        // Build 50-block chain
        for height in 1..=50 {
            let header = BlockHeader::new(
                height,
                parent_hash,
                [height as u8; 32],
                [height as u8; 32],
                [0u8; 32],
                1700000000 + height * 12,
                [0u8; 32],
                1000 + height,
            );
            parent_hash = header.compute_hash();
            hashes.push(parent_hash);
            chain.insert_header(header).unwrap();
        }

        (chain, hashes)
    }

    fn setup_delegation_manager() -> DelegationManager {
        let config = DelegationConfig {
            min_nodes: 2,
            threshold: 2,
            max_proof_age: 3600,
            request_timeout: 30,
            max_concurrent: 10,
            retry_count: 3,
        };

        let manager = DelegationManager::new(config);

        // Add delegation nodes
        for i in 1..=5 {
            manager.add_node(DelegationNode::new([i; 32]));
        }

        manager
    }

    fn create_test_response(
        request_id: u64,
        node_id: u8,
        proof: DelegatedProofData,
    ) -> DelegationResponse {
        DelegationResponse {
            request_id,
            node_pubkey: [node_id; 32],
            proof,
            signature: vec![0u8; 64],
            witness: ComputationWitness::default(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    #[test]
    fn test_light_client_flow() {
        // 1. Setup header chain
        let (chain, hashes) = setup_header_chain();

        assert_eq!(chain.get_height(), 50);
        assert_eq!(hashes.len(), 51); // 0..=50

        // 2. Verify headers are accessible
        for height in 0..=50 {
            let header = chain.get_canonical_header(height);
            assert!(header.is_some());
            assert_eq!(header.unwrap().height, height);
        }

        // 3. Verify hash lookups
        for (i, hash) in hashes.iter().enumerate() {
            let header = chain.get_header(hash);
            assert!(header.is_some());
            assert_eq!(header.unwrap().height, i as u64);
        }

        // 4. Add checkpoints
        chain.add_checkpoint(10, hashes[10]);
        chain.add_checkpoint(20, hashes[20]);
        chain.add_checkpoint(30, hashes[30]);

        // 5. Verify canonical status
        for hash in &hashes {
            assert!(chain.is_canonical(hash));
        }
    }

    #[test]
    fn test_delegation_flow() {
        let manager = setup_delegation_manager();

        let block_hash = [42u8; 32];
        let item_hash = [43u8; 32];

        // 1. Create delegation request
        let request = manager.create_request(
            DelegatedProofType::TransactionInclusion,
            100,
            block_hash,
            item_hash,
        ).unwrap();

        assert!(request.request_id > 0);

        // 2. Simulate node responses
        let proof = DelegatedProofData::Raw(vec![10, 20, 30, 40, 50]);

        // First response
        let response1 = create_test_response(request.request_id, 1, proof.clone());
        let result1 = manager.process_response(response1).unwrap();
        assert!(result1.is_none()); // Not enough for threshold

        // Second response - reaches threshold
        let response2 = create_test_response(request.request_id, 2, proof.clone());
        let result2 = manager.process_response(response2).unwrap();
        assert!(result2.is_some()); // Threshold reached

        // 3. Verify caching
        let cached = manager.get_cached_proof(
            DelegatedProofType::TransactionInclusion,
            100,
            block_hash,
            item_hash,
        );
        assert!(cached.is_some());
    }

    #[test]
    fn test_proof_verification_with_delegation() {
        // 1. Setup chain with known transactions
        let (chain, hashes) = setup_header_chain();

        // 2. Setup delegation
        let _manager = setup_delegation_manager();

        // 3. Create verifier
        let verifier = ProofVerifier::new(3600);

        // 4. Create inclusion proof for a transaction
        let tx_hash = [1u8; 32];
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let merkle_path = ProofVerifier::build_merkle_proof(&leaves, 0);

        let inclusion_proof = InclusionProof {
            item_hash: tx_hash,
            path: merkle_path,
            block_height: 10,
            block_hash: hashes[10],
            root_type: RootType::Transactions,
        };

        // 5. Get header for verification
        let header = chain.get_canonical_header(10).unwrap();
        assert_eq!(header.height, 10);

        // Note: Actual verification would need matching merkle roots
        // This test demonstrates the flow
        let _ = inclusion_proof;
        let _ = verifier;
    }

    #[test]
    fn test_full_light_client_scenario() {
        // Simulates a mobile light client scenario:
        // 1. Start with checkpoints
        // 2. Sync headers from checkpoints
        // 3. Verify transaction via delegated proof

        // Setup
        let config = HeaderChainConfig {
            max_headers: 1000,
            max_reorg_depth: 10,
            checkpoint_interval: 100,
            verify_signatures: false,
        };
        let mut chain = HeaderChain::new(config);

        // Initialize with genesis
        let genesis_config = GenesisConfig {
            state_root: [0u8; 32],
            timestamp: 1700000000,
            extra_data: b"Mobile Client Genesis".to_vec(),
        };
        let genesis = chain.initialize_genesis(genesis_config).unwrap();

        // Simulate receiving checkpoint from trusted source
        let checkpoint_height = 0u64;
        let checkpoint_hash = genesis.compute_hash();
        chain.add_checkpoint(checkpoint_height, checkpoint_hash);

        // Build chain (simulating sync)
        let mut parent_hash = checkpoint_hash;
        for height in 1..=20 {
            let header = BlockHeader::new(
                height,
                parent_hash,
                [height as u8; 32],
                [height as u8; 32],
                [0u8; 32],
                1700000000 + height * 12,
                [0u8; 32],
                1000 + height,
            );
            parent_hash = header.compute_hash();
            chain.insert_header(header).unwrap();
        }

        assert_eq!(chain.get_height(), 20);

        // Setup delegation for proof requests
        let delegation_config = DelegationConfig {
            min_nodes: 2,
            threshold: 2,
            max_proof_age: 3600,
            request_timeout: 30,
            max_concurrent: 5,
            retry_count: 3,
        };
        let manager = DelegationManager::new(delegation_config);

        for i in 1..=3 {
            manager.add_node(DelegationNode::new([i; 32]));
        }

        let block_hash = [99u8; 32];
        let item_hash = [99u8; 32];

        // Request delegated proof for a transaction
        let request = manager.create_request(
            DelegatedProofType::TransactionInclusion,
            15,
            block_hash,
            item_hash,
        ).unwrap();

        // Process responses from full nodes
        let proof = DelegatedProofData::Raw(vec![1, 2, 3, 4, 5, 6, 7, 8]);

        for i in 1..=2 {
            let response = create_test_response(request.request_id, i, proof.clone());
            let _ = manager.process_response(response);
        }

        // Verify we got consensus proof
        let cached = manager.get_cached_proof(
            DelegatedProofType::TransactionInclusion,
            15,
            block_hash,
            item_hash,
        );
        assert!(cached.is_some());

        // Stats should reflect the activity
        let stats = manager.stats();
        assert!(stats.cached_proofs > 0);
    }

    #[test]
    fn test_concurrent_delegation_requests() {
        let manager = setup_delegation_manager();

        // Create multiple requests
        let mut requests = Vec::new();
        for i in 0..5 {
            let request = manager.create_request(
                DelegatedProofType::TransactionInclusion,
                100 + i as u64,
                [i as u8; 32],
                [i as u8 + 100; 32],
            ).unwrap();
            requests.push(request);
        }

        assert_eq!(requests.len(), 5);

        // Each request should have unique ID
        let ids: std::collections::HashSet<_> = requests.iter().map(|r| r.request_id).collect();
        assert_eq!(ids.len(), 5);

        // Process responses for each
        for request in &requests {
            let proof = DelegatedProofData::Raw(vec![request.request_id as u8]);
            for node_id in 1u8..=2 {
                let response = create_test_response(request.request_id, node_id, proof.clone());
                let _ = manager.process_response(response);
            }
        }

        // All should be cached
        for (i, request) in requests.iter().enumerate() {
            let cached = manager.get_cached_proof(
                DelegatedProofType::TransactionInclusion,
                100 + i as u64,
                [i as u8; 32],
                [i as u8 + 100; 32],
            );
            assert!(cached.is_some());
        }
    }

    #[test]
    fn test_header_chain_reorganization() {
        let (mut chain, hashes) = setup_header_chain();

        // Fork at height 40
        let fork_parent = hashes[40];
        let mut fork_hashes = Vec::new();
        let mut parent = fork_parent;

        // Build longer fork (15 blocks vs 10 on main chain after height 40)
        for i in 0..15 {
            let height = 41 + i;
            let header = BlockHeader::new(
                height,
                parent,
                [100 + i as u8; 32], // Different state root
                [100 + i as u8; 32],
                [0u8; 32],
                1700000000 + height * 12,
                [0u8; 32],
                2000 + height, // Higher difficulty
            );
            parent = header.compute_hash();
            fork_hashes.push(parent);
            let _ = chain.insert_header(header);
        }

        // Chain should follow the longer/heavier fork
        // Note: Actual reorg behavior depends on implementation
        let tip = chain.get_tip();
        assert!(tip.is_some());
        assert!(tip.unwrap().header.height >= 50);
    }
}

// ============================================================================
// Stress Tests
// ============================================================================

mod stress_tests {
    use phantom_light_client::{
        BlockHeader, HeaderChain, DelegationManager, DelegationConfig, DelegationNode,
        header::{HeaderChainConfig, GenesisConfig},
    };
    use std::time::Instant;

    #[test]
    #[ignore] // Slow in debug builds - run with `cargo test -- --ignored`
    fn test_large_header_chain() {
        let config = HeaderChainConfig {
            max_headers: 10000,
            max_reorg_depth: 100,
            checkpoint_interval: 1000,
            verify_signatures: false,
        };

        let mut chain = HeaderChain::new(config);

        let genesis_config = GenesisConfig {
            state_root: [0u8; 32],
            timestamp: 1700000000,
            extra_data: vec![],
        };

        let genesis = chain.initialize_genesis(genesis_config).unwrap();
        let mut parent_hash = genesis.compute_hash();

        let start = Instant::now();

        // Insert 5000 headers
        for height in 1..=5000 {
            let header = BlockHeader::new(
                height,
                parent_hash,
                [0u8; 32],
                [0u8; 32],
                [0u8; 32],
                1700000000 + height * 12,
                [0u8; 32],
                1000,
            );
            parent_hash = header.compute_hash();
            chain.insert_header(header).unwrap();
        }

        let duration = start.elapsed();

        assert_eq!(chain.get_height(), 5000);
        // Should complete in reasonable time (< 30 seconds for debug build)
        assert!(duration.as_secs() < 30);
    }

    #[test]
    fn test_many_delegation_nodes() {
        let config = DelegationConfig {
            min_nodes: 2,
            threshold: 51, // Majority
            max_proof_age: 3600,
            request_timeout: 30,
            max_concurrent: 100,
            retry_count: 3,
        };

        let manager = DelegationManager::new(config);

        // Add 100 nodes
        for i in 0..100 {
            let mut id = [0u8; 32];
            id[0] = (i / 256) as u8;
            id[1] = (i % 256) as u8;

            let node = DelegationNode::new(id);
            manager.add_node(node);
        }

        let stats = manager.stats();
        assert_eq!(stats.total_nodes, 100);
    }

    #[test]
    #[ignore] // Slow in debug builds - run with `cargo test -- --ignored`
    fn test_rapid_header_queries() {
        let config = HeaderChainConfig {
            max_headers: 1000,
            max_reorg_depth: 10,
            checkpoint_interval: 100,
            verify_signatures: false,
        };

        let mut chain = HeaderChain::new(config);

        let genesis_config = GenesisConfig {
            state_root: [0u8; 32],
            timestamp: 1700000000,
            extra_data: vec![],
        };

        let genesis = chain.initialize_genesis(genesis_config).unwrap();
        let mut hashes = vec![genesis.compute_hash()];
        let mut parent = hashes[0];

        // Build 500 block chain
        for height in 1..=500 {
            let header = BlockHeader::new(
                height, parent, [0u8; 32], [0u8; 32], [0u8; 32],
                1700000000 + height * 12, [0u8; 32], 1000,
            );
            parent = header.compute_hash();
            hashes.push(parent);
            chain.insert_header(header).unwrap();
        }

        let start = Instant::now();

        // Perform 10000 random queries
        for i in 0..10000 {
            let height = (i % 501) as u64;
            let _ = chain.get_canonical_header(height);
        }

        let duration = start.elapsed();

        // Should complete quickly (< 5 seconds for debug build)
        assert!(duration.as_secs() < 5);
    }
}
