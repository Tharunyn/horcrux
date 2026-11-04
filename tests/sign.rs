//! End-to-end tests for Mode A signing: reconstruct a key from shards and sign
//! a Solana transfer entirely offline, verifying the sender address and that
//! the signature verifies against the serialized message.

use horcrux::error::Error;
use horcrux::qr;
use horcrux::tx::{TxParams, derive_address};
use horcrux::{SignedOutput, init_shards, sign_transaction_from_shards};
use k256::SecretKey;
use rand::rngs::OsRng;
use solana_hash::Hash;
use solana_transaction::Transaction;

fn key() -> SecretKey {
    SecretKey::random(&mut OsRng)
}

fn passwords(n: usize, seed: &str) -> Vec<String> {
    (0..n).map(|i| format!("{seed}-{i}")).collect()
}

fn seed_of(key: &SecretKey) -> [u8; 32] {
    key.to_bytes().into()
}

fn params_for(key: &SecretKey) -> TxParams {
    TxParams {
        from: derive_address(&seed_of(key)),
        to: derive_address(&[0x1b; 32]),
        lamports: 1_000_000,
        blockhash: Hash::new_from_array([0x42; 32]),
    }
}

fn verify_output(out: &SignedOutput) -> bool {
    let raw = bs58::decode(&out.raw_base58)
        .into_vec()
        .expect("valid base58 raw transaction");
    let tx: Transaction = bincode::deserialize(&raw).expect("valid bincode transaction");
    out.signature
        .verify(&out.from.to_bytes(), &tx.message.serialize())
}

#[test]
fn sign_from_two_of_three_shards_recovers_sender() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = key();
    let pws = passwords(3, "guardian");

    let paths = init_shards(&key, 2, 3, dir.path(), &pws).expect("init");
    let out = sign_transaction_from_shards(&paths[..2], &pws[..2], params_for(&key)).expect("sign");

    assert_eq!(
        out.from,
        derive_address(&seed_of(&key)),
        "signer address must match the reconstructed key"
    );
    assert!(
        verify_output(&out),
        "signature must verify against the serialized message"
    );
}

#[test]
fn signed_output_is_deterministic_for_same_inputs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = key();
    let pws = passwords(3, "guardian");
    let paths = init_shards(&key, 2, 3, dir.path(), &pws).expect("init");

    let a = sign_transaction_from_shards(&paths[..2], &pws[..2], params_for(&key)).expect("sign a");
    let b = sign_transaction_from_shards(&paths[..2], &pws[..2], params_for(&key)).expect("sign b");
    assert_eq!(a.from, b.from);
    assert_eq!(a.signature, b.signature);
    assert_eq!(a.raw_base58, b.raw_base58);
}

#[test]
fn sign_from_staged_qr_shards() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = key();
    let pws = passwords(3, "guardian");
    init_shards(&key, 2, 3, dir.path(), &pws).expect("init");

    let staged: Vec<_> = (1..=2)
        .map(|id| {
            qr::stage_shard_from_qr_png(&dir.path().join(format!("shard-{id}-qr-0.png")))
                .expect("stage shard qr")
        })
        .collect();

    let out = sign_transaction_from_shards(&staged, &pws[..2], params_for(&key)).expect("sign");
    assert_eq!(out.from, derive_address(&seed_of(&key)));
    assert!(verify_output(&out));

    for path in staged {
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn wrong_password_aborts_before_signing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = key();
    let pws = passwords(3, "guardian");
    let paths = init_shards(&key, 2, 3, dir.path(), &pws).expect("init");

    let bad = vec!["wrong".to_string(), pws[1].clone()];
    assert!(matches!(
        sign_transaction_from_shards(&paths[..2], &bad, params_for(&key)),
        Err(Error::Decrypt { .. })
    ));
}
