//! Performance Benchmarks for PHANTOM Crypto Primitives
//!
//! Run with: cargo bench

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use phantom_pq::{kyber, dilithium, SecurityLevel};
use phantom_esl::nullifier::{Nullifier, NullifierSet, NullifierTree};
use phantom_cwa::{Validator, vrf::{vrf_evaluate, Committee}, threshold::{ThresholdScheme, KeyShare, PartialSignature}};
use phantom_fhe::{KeyPair, FHEUint64, FHEOps, FHEConfig};
use phantom_mixnet::{SphinxPacket, ProcessedPacket, MixNode, MixDirectory, MixNodeInfo, SURB};

// =============================================================================
// POST-QUANTUM BENCHMARKS
// =============================================================================

fn bench_kyber_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("kyber_keygen");

    for level in [SecurityLevel::Level1, SecurityLevel::Level3, SecurityLevel::Level5] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", level)),
            &level,
            |b, level| {
                b.iter(|| kyber::generate_keypair(*level).unwrap())
            }
        );
    }

    group.finish();
}

fn bench_kyber_encapsulate(c: &mut Criterion) {
    let mut group = c.benchmark_group("kyber_encapsulate");

    for level in [SecurityLevel::Level1, SecurityLevel::Level3, SecurityLevel::Level5] {
        let keypair = kyber::generate_keypair(level).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", level)),
            &keypair,
            |b, keypair| {
                b.iter(|| kyber::encapsulate(&keypair.public_key).unwrap())
            }
        );
    }

    group.finish();
}

fn bench_kyber_decapsulate(c: &mut Criterion) {
    let mut group = c.benchmark_group("kyber_decapsulate");

    for level in [SecurityLevel::Level1, SecurityLevel::Level3, SecurityLevel::Level5] {
        let keypair = kyber::generate_keypair(level).unwrap();
        let (ciphertext, _) = kyber::encapsulate(&keypair.public_key).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", level)),
            &(keypair, ciphertext),
            |b, (keypair, ciphertext)| {
                b.iter(|| kyber::decapsulate(&keypair.secret_key, ciphertext).unwrap())
            }
        );
    }

    group.finish();
}

fn bench_dilithium_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("dilithium_keygen");

    for level in [SecurityLevel::Level1, SecurityLevel::Level3, SecurityLevel::Level5] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", level)),
            &level,
            |b, level| {
                b.iter(|| dilithium::generate_keypair(*level).unwrap())
            }
        );
    }

    group.finish();
}

fn bench_dilithium_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("dilithium_sign");

    let message = vec![0u8; 256]; // 256-byte message

    for level in [SecurityLevel::Level1, SecurityLevel::Level3, SecurityLevel::Level5] {
        let keypair = dilithium::generate_keypair(level).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", level)),
            &keypair,
            |b, keypair| {
                b.iter(|| dilithium::sign(&keypair.secret_key, &message).unwrap())
            }
        );
    }

    group.finish();
}

fn bench_dilithium_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("dilithium_verify");

    let message = vec![0u8; 256];

    for level in [SecurityLevel::Level1, SecurityLevel::Level3, SecurityLevel::Level5] {
        let keypair = dilithium::generate_keypair(level).unwrap();
        let signature = dilithium::sign(&keypair.secret_key, &message).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", level)),
            &(keypair, signature),
            |b, (keypair, signature)| {
                b.iter(|| dilithium::verify(&keypair.public_key, &message, signature).unwrap())
            }
        );
    }

    group.finish();
}

// =============================================================================
// NULLIFIER BENCHMARKS
// =============================================================================

fn bench_nullifier_derive(c: &mut Criterion) {
    let secret = [0x42u8; 32];
    let commitment = [0xABu8; 32];

    c.bench_function("nullifier_derive", |b| {
        b.iter(|| Nullifier::derive(&secret, &commitment))
    });
}

fn bench_nullifier_set_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("nullifier_set_insert");

    for size in [100, 1000, 10000] {
        let mut set = NullifierSet::with_capacity(size);

        // Pre-populate with some nullifiers
        for i in 0..(size / 2) as u64 {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&i.to_le_bytes());
            set.insert(Nullifier::from_bytes(bytes)).unwrap();
        }

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &set,
            |b, set| {
                let mut counter = size as u64;
                let mut set = set.clone();
                b.iter(|| {
                    counter += 1;
                    let mut bytes = [0u8; 32];
                    bytes[..8].copy_from_slice(&counter.to_le_bytes());
                    set.insert(Nullifier::from_bytes(bytes)).unwrap();
                })
            }
        );
    }

    group.finish();
}

fn bench_nullifier_set_contains(c: &mut Criterion) {
    let mut group = c.benchmark_group("nullifier_set_contains");

    for size in [100, 1000, 10000, 100000] {
        let mut set = NullifierSet::with_capacity(size);

        for i in 0..size as u64 {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&i.to_le_bytes());
            set.insert(Nullifier::from_bytes(bytes)).unwrap();
        }

        // Create a nullifier to search for
        let mut search_bytes = [0u8; 32];
        search_bytes[..8].copy_from_slice(&(size as u64 / 2).to_le_bytes());
        let search_nullifier = Nullifier::from_bytes(search_bytes);

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &(set, search_nullifier),
            |b, (set, nullifier)| {
                b.iter(|| set.contains(nullifier))
            }
        );
    }

    group.finish();
}

fn bench_nullifier_tree_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("nullifier_tree_insert");

    for depth in [16, 32, 64] {
        let tree = NullifierTree::with_depth(depth);

        group.bench_with_input(
            BenchmarkId::from_parameter(depth),
            &tree,
            |b, tree| {
                let mut tree = tree.clone();
                let mut counter = 0u64;
                b.iter(|| {
                    counter += 1;
                    let mut bytes = [0u8; 32];
                    bytes[..8].copy_from_slice(&counter.to_le_bytes());
                    tree.insert(Nullifier::from_bytes(bytes)).unwrap();
                })
            }
        );
    }

    group.finish();
}

// =============================================================================
// CWA BENCHMARKS
// =============================================================================

fn bench_vrf_evaluate(c: &mut Criterion) {
    let secret_key = [0x42u8; 32];
    let input = b"benchmark input data";

    c.bench_function("vrf_evaluate", |b| {
        b.iter(|| vrf_evaluate(&secret_key, input))
    });
}

fn bench_committee_selection(c: &mut Criterion) {
    let mut group = c.benchmark_group("committee_selection");

    for num_validators in [10, 50, 100, 500] {
        let validators: Vec<Validator> = (0..num_validators)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = (i / 256) as u8;
                id[1] = (i % 256) as u8;
                Validator::new(id, vec![], [0u8; 32], 1_000_000 * (i as u64 + 1))
            })
            .collect();

        let randomness = [0x42u8; 32];

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(num_validators),
            &validators,
            |b, validators| {
                b.iter(|| Committee::select(1, validators, &randomness, 10, 7).unwrap())
            }
        );
    }

    group.finish();
}

fn bench_threshold_sign_aggregate(c: &mut Criterion) {
    let mut group = c.benchmark_group("threshold_signature");

    for (n, t) in [(10, 7), (20, 14), (50, 34)] {
        let (scheme, shares) = ThresholdScheme::new(n, t).unwrap();
        let message = b"benchmark transaction";

        // Bench partial signing
        group.bench_with_input(
            BenchmarkId::new("partial_sign", format!("{}_of_{}", t, n)),
            &(scheme.clone(), shares.clone()),
            |b, (scheme, shares): &(ThresholdScheme, Vec<KeyShare>)| {
                b.iter(|| scheme.partial_sign(&shares[0], message).unwrap())
            }
        );

        // Pre-compute partial signatures for aggregation bench
        let partials: Vec<_> = shares.iter()
            .take(t)
            .map(|s| scheme.partial_sign(s, message).unwrap())
            .collect();

        // Bench aggregation
        group.bench_with_input(
            BenchmarkId::new("aggregate", format!("{}_of_{}", t, n)),
            &(scheme.clone(), partials),
            |b, (scheme, partials): &(ThresholdScheme, Vec<PartialSignature>)| {
                b.iter(|| scheme.aggregate(partials).unwrap())
            }
        );
    }

    group.finish();
}

// =============================================================================
// FHE BENCHMARKS
// =============================================================================

fn bench_fhe_keygen(c: &mut Criterion) {
    let config = FHEConfig::default();

    c.bench_function("fhe_keygen", |b| {
        b.iter(|| KeyPair::generate(&config).unwrap())
    });
}

fn bench_fhe_encrypt(c: &mut Criterion) {
    let config = FHEConfig::default();
    let keypair = KeyPair::generate(&config).unwrap();

    c.bench_function("fhe_encrypt_u64", |b| {
        b.iter(|| FHEUint64::encrypt(1000, &keypair.client).unwrap())
    });
}

fn bench_fhe_homomorphic_add(c: &mut Criterion) {
    let config = FHEConfig::default();
    let keypair = KeyPair::generate(&config).unwrap();

    let ct_a = FHEUint64::encrypt(100, &keypair.client).unwrap();
    let ct_b = FHEUint64::encrypt(50, &keypair.client).unwrap();

    c.bench_function("fhe_homomorphic_add", |b| {
        b.iter(|| FHEOps::add(&ct_a, &ct_b, &keypair.server).unwrap())
    });
}

fn bench_fhe_comparison(c: &mut Criterion) {
    let config = FHEConfig::default();
    let keypair = KeyPair::generate(&config).unwrap();

    let ct_a = FHEUint64::encrypt(100, &keypair.client).unwrap();
    let ct_b = FHEUint64::encrypt(50, &keypair.client).unwrap();

    c.bench_function("fhe_less_than", |b| {
        b.iter(|| FHEOps::lt(&ct_a, &ct_b, &keypair.server).unwrap())
    });
}

// =============================================================================
// MIXNET BENCHMARKS
// =============================================================================

/// Helper to derive public key from secret (matching sphinx.rs implementation)
fn derive_public_key(secret: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::constants::X25519_BASEPOINT;

    // Clamp the secret for X25519 compatibility
    let mut clamped = *secret;
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;

    let secret_scalar = Scalar::from_bytes_mod_order(clamped);
    let public_point = secret_scalar * X25519_BASEPOINT;
    public_point.to_bytes()
}

fn create_test_directory(layers: usize, nodes_per_layer: usize) -> MixDirectory {
    let mut dir = MixDirectory::new(layers);

    for layer in 0..layers {
        for i in 0..nodes_per_layer {
            let mut id = [0u8; 32];
            id[0] = layer as u8;
            id[1] = i as u8;

            let node = MixNode::new(
                id,
                id,
                format!("127.0.0.1:{}", 10000 + layer * 100 + i),
                layer as u8,
            );
            dir.add_node(node);
        }
    }

    dir
}

/// Create a route with proper keypairs for end-to-end benchmarks
fn create_test_route_with_secrets(num_hops: usize) -> (Vec<MixNodeInfo>, Vec<[u8; 32]>) {
    let secrets: Vec<[u8; 32]> = (0..num_hops).map(|i| {
        let mut secret = [0u8; 32];
        secret[0] = (i + 1) as u8;
        secret
    }).collect();

    let route: Vec<MixNodeInfo> = secrets.iter().enumerate().map(|(i, secret)| {
        let public_key = derive_public_key(secret);
        let mut id = [0u8; 32];
        id[0] = (i + 1) as u8;
        MixNodeInfo { id, public_key }
    }).collect();

    (route, secrets)
}

fn bench_sphinx_packet_create(c: &mut Criterion) {
    let mut group = c.benchmark_group("sphinx_packet_create");

    for num_hops in [3, 5, 7] {
        let (route, _) = create_test_route_with_secrets(num_hops);
        let payload = vec![0u8; 256];
        let destination = [0xFFu8; 32];

        group.bench_with_input(
            BenchmarkId::from_parameter(num_hops),
            &(route, payload, destination),
            |b, (route, payload, destination)| {
                b.iter(|| SphinxPacket::create(payload, route, destination).unwrap())
            }
        );
    }

    group.finish();
}

fn bench_sphinx_packet_process(c: &mut Criterion) {
    let mut group = c.benchmark_group("sphinx_packet_process");

    for num_hops in [3, 5, 7] {
        let (route, secrets) = create_test_route_with_secrets(num_hops);
        let payload = vec![0u8; 256];
        let destination = [0xFFu8; 32];
        let packet = SphinxPacket::create(&payload, &route, &destination).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_hops_first_hop", num_hops)),
            &(packet.clone(), secrets[0]),
            |b, (packet, secret)| {
                b.iter(|| packet.process(secret).unwrap())
            }
        );
    }

    group.finish();
}

fn bench_sphinx_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("sphinx_end_to_end");

    for num_hops in [3, 5] {
        let (route, secrets) = create_test_route_with_secrets(num_hops);
        let payload = b"Secret message through the mixnet!";
        let destination = [0xFFu8; 32];

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_hops", num_hops)),
            &(route, secrets, destination),
            |b, (route, secrets, destination)| {
                b.iter(|| {
                    // Create packet
                    let mut packet = SphinxPacket::create(payload, route, destination).unwrap();

                    // Process through all hops
                    for (i, secret) in secrets.iter().enumerate() {
                        let result = packet.process(secret).unwrap();
                        match result {
                            ProcessedPacket::Forward { packet: next, .. } => {
                                packet = next;
                            }
                            ProcessedPacket::Final { .. } => {
                                assert_eq!(i, secrets.len() - 1);
                            }
                        }
                    }
                })
            }
        );
    }

    group.finish();
}

fn bench_sphinx_packet_serialize(c: &mut Criterion) {
    let (route, _) = create_test_route_with_secrets(5);
    let payload = vec![0u8; 256];
    let destination = [0xFFu8; 32];
    let packet = SphinxPacket::create(&payload, &route, &destination).unwrap();

    c.bench_function("sphinx_packet_serialize", |b| {
        b.iter(|| packet.to_bytes())
    });
}

fn bench_sphinx_packet_deserialize(c: &mut Criterion) {
    let (route, _) = create_test_route_with_secrets(5);
    let payload = vec![0u8; 256];
    let destination = [0xFFu8; 32];
    let packet = SphinxPacket::create(&payload, &route, &destination).unwrap();
    let bytes = packet.to_bytes();

    c.bench_function("sphinx_packet_deserialize", |b| {
        b.iter(|| SphinxPacket::from_bytes(&bytes).unwrap())
    });
}

fn bench_route_selection(c: &mut Criterion) {
    let mut group = c.benchmark_group("route_selection");

    for nodes_per_layer in [5, 10, 50, 100] {
        let directory = create_test_directory(5, nodes_per_layer);

        group.bench_with_input(
            BenchmarkId::from_parameter(nodes_per_layer),
            &directory,
            |b, directory| {
                b.iter(|| directory.select_route(5).unwrap())
            }
        );
    }

    group.finish();
}

// =============================================================================
// SURB BENCHMARKS
// =============================================================================

fn bench_surb_create(c: &mut Criterion) {
    let mut group = c.benchmark_group("surb_create");

    for num_hops in [3, 5, 7] {
        let (route, _) = create_test_route_with_secrets(num_hops);
        let destination_key = [99u8; 32];

        group.bench_with_input(
            BenchmarkId::from_parameter(num_hops),
            &route,
            |b, route| {
                b.iter(|| SURB::create(route, &destination_key).unwrap())
            }
        );
    }

    group.finish();
}

fn bench_surb_create_reply(c: &mut Criterion) {
    let mut group = c.benchmark_group("surb_create_reply");

    for num_hops in [3, 5, 7] {
        let (route, _) = create_test_route_with_secrets(num_hops);
        let destination_key = [99u8; 32];
        let surb = SURB::create(&route, &destination_key).unwrap();
        let payload = b"Reply message through SURB";

        group.bench_with_input(
            BenchmarkId::from_parameter(num_hops),
            &surb,
            |b, surb| {
                b.iter(|| surb.create_reply(payload).unwrap())
            }
        );
    }

    group.finish();
}

fn bench_surb_decrypt_reply(c: &mut Criterion) {
    let mut group = c.benchmark_group("surb_decrypt_reply");

    for num_hops in [3, 5, 7] {
        let (route, _) = create_test_route_with_secrets(num_hops);
        let destination_key = [99u8; 32];
        let surb = SURB::create(&route, &destination_key).unwrap();
        let payload = b"Reply message through SURB";
        let reply_packet = surb.create_reply(payload).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(num_hops),
            &(surb, reply_packet),
            |b, (surb, reply_packet)| {
                b.iter(|| surb.decrypt_reply(&reply_packet.payload).unwrap())
            }
        );
    }

    group.finish();
}

fn bench_surb_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("surb_end_to_end");

    for num_hops in [3, 5] {
        let (route, _) = create_test_route_with_secrets(num_hops);
        let destination_key = [99u8; 32];
        let payload = b"End-to-end SURB test";

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_hops", num_hops)),
            &route,
            |b, route| {
                b.iter(|| {
                    // Create SURB
                    let surb = SURB::create(route, &destination_key).unwrap();
                    // Create reply
                    let reply = surb.create_reply(payload).unwrap();
                    // Decrypt reply
                    surb.decrypt_reply(&reply.payload).unwrap()
                })
            }
        );
    }

    group.finish();
}

// =============================================================================
// BENCHMARK GROUPS
// =============================================================================

criterion_group!(
    post_quantum,
    bench_kyber_keygen,
    bench_kyber_encapsulate,
    bench_kyber_decapsulate,
    bench_dilithium_keygen,
    bench_dilithium_sign,
    bench_dilithium_verify,
);

criterion_group!(
    nullifiers,
    bench_nullifier_derive,
    bench_nullifier_set_insert,
    bench_nullifier_set_contains,
    bench_nullifier_tree_insert,
);

criterion_group!(
    cwa,
    bench_vrf_evaluate,
    bench_committee_selection,
    bench_threshold_sign_aggregate,
);

criterion_group!(
    fhe,
    bench_fhe_keygen,
    bench_fhe_encrypt,
    bench_fhe_homomorphic_add,
    bench_fhe_comparison,
);

criterion_group!(
    mixnet,
    bench_sphinx_packet_create,
    bench_sphinx_packet_process,
    bench_sphinx_end_to_end,
    bench_sphinx_packet_serialize,
    bench_sphinx_packet_deserialize,
    bench_route_selection,
);

criterion_group!(
    surb,
    bench_surb_create,
    bench_surb_create_reply,
    bench_surb_decrypt_reply,
    bench_surb_end_to_end,
);

criterion_main!(post_quantum, nullifiers, cwa, fhe, mixnet, surb);
