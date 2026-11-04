//! End-to-end tests for Mode B signing: dealer-split a key into FROST key
//! shares, sign a Solana transfer from any threshold subset of share files,
//! and verify the aggregated signature under plain Ed25519 — proving the key
//! is never reconstructed and the result is broadcastable.

use horcrux::error::Error;
use horcrux::mpc::{mpc_sign, mpc_split, mpc_split_to, shard_ids};
use horcrux::qr;
use horcrux::tx::{TxParams, derive_address};
use horcrux::{SignedOutput, init_shards, sign_transaction_from_mpc_shares};
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

fn verify_dalek(verifying_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    use ed25519_dalek::Verifier as _;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(verifying_key).expect("valid vk");
    vk.verify(message, &ed25519_dalek::Signature::from_bytes(signature))
        .is_ok()
}

#[test]
fn mpc_sign_from_any_two_of_three_recovers_sender() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = key();
    let pws = passwords(3, "guardian");

    let (paths, group) = mpc_split(&key, 2, 3, dir.path(), &pws).expect("split");
    assert_eq!(paths.len(), 3);
    assert_eq!(shard_ids(&paths).expect("ids"), vec![1, 2, 3]);

    for combo in [&[0usize, 1], &[0usize, 2], &[1usize, 2]] {
        let chosen: Vec<_> = combo.iter().map(|&i| paths[i].clone()).collect();
        let chosen_pws: Vec<_> = combo.iter().map(|&i| pws[i].clone()).collect();
        let out = sign_transaction_from_mpc_shares(&chosen, &chosen_pws, &group, params_for(&key))
            .expect("sign");
        assert_eq!(out.from, params_for(&key).from);
        assert!(verify_output(&out), "broadcastable transaction");
    }
}

#[test]
fn mpc_sign_from_staged_qr_shares() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = key();
    let pws = passwords(3, "guardian");
    let (_paths, group) = mpc_split(&key, 2, 3, dir.path(), &pws).expect("split");

    let staged: Vec<_> = (1..=2)
        .map(|id| {
            qr::stage_shard_from_qr_png(&dir.path().join(format!("mpc-{id}-qr-0.png")))
                .expect("stage share qr")
        })
        .collect();

    let out = sign_transaction_from_mpc_shares(&staged, &pws[..2], &group, params_for(&key))
        .expect("sign");
    assert_eq!(out.from, params_for(&key).from);
    assert!(verify_output(&out));

    for path in staged {
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn mpc_signature_verifies_under_standard_ed25519() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = key();
    let pws = passwords(3, "guardian");
    let (paths, group) = mpc_split(&key, 2, 3, dir.path(), &pws).expect("split");

    let message = b"a Solana message serialization";
    let sig = mpc_sign(&paths[..2], &pws[..2], &group, message, |_, _| {}).expect("sign");
    assert_eq!(sig.verifying_key, derive_address(&seed_of(&key)).to_bytes());
    assert!(
        verify_dalek(&sig.verifying_key, message, &sig.signature),
        "FROST signature must be an ordinary RFC 8032 Ed25519 signature"
    );
}

#[test]
fn group_key_matches_original_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = key();
    let pws = passwords(3, "guardian");
    let (paths, group) = mpc_split(&key, 2, 3, dir.path(), &pws).expect("split");

    // The group address equals the Mode A address of the same seed, so a
    // FROST-signed transaction spends from the same wallet.
    let vk = horcrux::mpc::group_verifying_key(&group).expect("vk");
    assert_eq!(vk, derive_address(&seed_of(&key)).to_bytes());
    assert_eq!(paths.len(), 3);
}

#[test]
fn one_share_cannot_sign() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = key();
    let pws = passwords(3, "guardian");
    let (paths, group) = mpc_split(&key, 2, 3, dir.path(), &pws).expect("split");
    assert!(matches!(
        sign_transaction_from_mpc_shares(&paths[..1], &pws[..1], &group, params_for(&key)),
        Err(Error::NotEnoughShares(..))
    ));
}

#[test]
fn wrong_password_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = key();
    let pws = passwords(3, "guardian");
    let (paths, group) = mpc_split(&key, 2, 3, dir.path(), &pws).expect("split");
    let bad = vec!["nope".to_string(), "guardian-1".to_string()];
    assert!(matches!(
        sign_transaction_from_mpc_shares(&paths[..2], &bad, &group, params_for(&key)),
        Err(Error::Decrypt { .. })
    ));
}

#[test]
fn mixed_sss_and_mpc_shares_are_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = key();
    let pws = passwords(3, "guardian");
    let mpc_paths = mpc_split(&key, 2, 3, dir.path(), &pws).expect("mpc").0;
    let sss_paths = init_shards(&key, 2, 3, dir.path(), &pws).expect("sss");

    // A FROST share file cannot be parsed as an SSS shard and vice versa.
    assert!(horcrux::shard::Shard::read(&mpc_paths[0]).is_err());
    assert!(horcrux::mpc::FrostShare::read(&sss_paths[0]).is_err());
}

#[test]
fn shares_can_be_written_to_separate_devices() {
    let dir = tempfile::tempdir().expect("tempdir");
    let group_dir = dir.path().join("coordinator");
    let device_a = dir.path().join("device-a");
    let device_b = dir.path().join("device-b");
    let device_c = dir.path().join("device-c");
    let key = key();
    let pws = passwords(3, "guardian");
    let destinations = vec![device_a.clone(), device_b.clone(), device_c.clone()];

    let (paths, group) =
        mpc_split_to(&key, 2, 3, &destinations, &group_dir, &pws).expect("split to devices");

    assert_eq!(paths.len(), 3);
    assert_eq!(group.parent(), Some(group_dir.as_path()));

    for (path, destination) in paths.iter().zip(&destinations) {
        assert_eq!(path.parent(), Some(destination.as_path()));
        assert!(path.is_file());
        assert!(
            destination
                .read_dir()
                .expect("device dir")
                .flatten()
                .any(|entry| entry.file_name().to_string_lossy().contains("-qr-"))
        );
    }

    let message = b"distributed share split";
    let sig = mpc_sign(&paths[..2], &pws[..2], &group, message, |_, _| {}).expect("sign");
    assert!(verify_dalek(&sig.verifying_key, message, &sig.signature));
}

#[test]
fn differing_signers_used_per_operation_still_aggregate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = key();
    let pws = passwords(4, "guardian");
    let (paths, group) = mpc_split(&key, 3, 4, dir.path(), &pws).expect("split");

    let message = b"rotate the guardians";
    let combo_a = vec![paths[0].clone(), paths[1].clone(), paths[2].clone()];
    let combo_b = vec![paths[1].clone(), paths[2].clone(), paths[3].clone()];
    let pw_a = vec![pws[0].clone(), pws[1].clone(), pws[2].clone()];
    let pw_b = vec![pws[1].clone(), pws[2].clone(), pws[3].clone()];

    for (combo, pw) in [(&combo_a, &pw_a), (&combo_b, &pw_b)] {
        let sig = mpc_sign(combo, pw, &group, message, |_, _| {}).expect("sign");
        assert!(verify_dalek(&sig.verifying_key, message, &sig.signature));
    }
}
