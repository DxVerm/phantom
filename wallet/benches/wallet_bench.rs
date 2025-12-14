//! Wallet performance benchmarks

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use phantom_wallet::{
    ViewKey, SpendKey, StealthAddress, OneTimeAddress,
    HDWallet, Mnemonic, DerivationPath,
    Note, NoteManager, OwnedNote,
};

fn bench_stealth_address_generation(c: &mut Criterion) {
    let view_key = ViewKey::generate().unwrap();
    let spend_key = SpendKey::generate().unwrap();
    let stealth = StealthAddress::new(&view_key, &spend_key);

    c.bench_function("stealth_address_derive", |b| {
        b.iter(|| {
            let _ = OneTimeAddress::derive_for_recipient(black_box(&stealth));
        });
    });
}

fn bench_stealth_address_scan(c: &mut Criterion) {
    let view_key = ViewKey::generate().unwrap();
    let spend_key = SpendKey::generate().unwrap();
    let stealth = StealthAddress::new(&view_key, &spend_key);
    let (ota, _) = OneTimeAddress::derive_for_recipient(&stealth).unwrap();

    c.bench_function("stealth_address_scan", |b| {
        b.iter(|| {
            let _ = ota.scan(black_box(&view_key), black_box(&spend_key));
        });
    });
}

fn bench_hd_key_derivation(c: &mut Criterion) {
    let mnemonic = Mnemonic::generate(12).unwrap();
    let wallet = HDWallet::from_mnemonic(mnemonic, None).unwrap();

    c.bench_function("hd_derive_account", |b| {
        b.iter(|| {
            let path = DerivationPath::account(black_box(0)).unwrap();
            let _ = wallet.derive(&path);
        });
    });
}

fn bench_note_nullifier(c: &mut Criterion) {
    let note = Note::new(1000, [1u8; 32], [2u8; 32]);

    c.bench_function("note_nullifier", |b| {
        b.iter(|| {
            let _ = black_box(&note).nullifier();
        });
    });
}

fn bench_note_manager_balance(c: &mut Criterion) {
    let mut manager = NoteManager::new();

    // Add 100 notes
    for i in 0..100 {
        let note = Note::new(1000, [i as u8; 32], [(i + 1) as u8; 32]);
        let view_key = ViewKey::generate().unwrap();
        let spend_key = SpendKey::generate().unwrap();
        let stealth = StealthAddress::new(&view_key, &spend_key);
        let (ota, _) = OneTimeAddress::derive_for_recipient(&stealth).unwrap();
        let (spending_key, _) = ota.recover(&view_key, &spend_key).unwrap();

        manager.add_note(OwnedNote {
            note,
            merkle_path: vec![[0u8; 32]; 32],
            merkle_indices: vec![false; 32],
            spending_key,
            block_height: i as u64,
        });
    }

    c.bench_function("note_manager_balance_100_notes", |b| {
        b.iter(|| {
            let _ = black_box(&manager).balance();
        });
    });
}

criterion_group!(
    benches,
    bench_stealth_address_generation,
    bench_stealth_address_scan,
    bench_hd_key_derivation,
    bench_note_nullifier,
    bench_note_manager_balance,
);

criterion_main!(benches);
