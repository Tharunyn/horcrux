//! End-to-end tests for the Phase 1 pipeline: split a key, encrypt shards to
//! files, reconstruct from any threshold subset, and verify every failure path
//! fails cleanly.

use horcrux::error::Error;
use horcrux::{SHARE_VALUE_LEN, TAG_LEN, init_shards, init_shards_to, reconstruct};
use k256::SecretKey;
use rand::rngs::OsRng;

fn key() -> SecretKey {
    SecretKey::random(&mut OsRng)
}

fn passwords(n: usize, seed: &str) -> Vec<String> {
    (0..n).map(|i| format!("{seed}-{i}")).collect()
}

#[test]
fn round_trip_any_two_of_three() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = key();
    let pws = passwords(3, "guardian");

    let paths = init_shards(&key, 2, 3, dir.path(), &pws).expect("init");
    assert_eq!(paths.len(), 3);

    for combo in [&[0usize, 1], &[0usize, 2], &[1usize, 2]] {
        let chosen: Vec<_> = combo.iter().map(|&i| paths[i].clone()).collect();
        let pws: Vec<_> = combo.iter().map(|&i| pws[i].clone()).collect();
        let recovered = reconstruct(&chosen, &pws).expect("reconstruct");
        assert_eq!(recovered.to_bytes(), key.to_bytes());
    }
}

#[test]
fn shards_can_be_written_to_separate_devices() {
    let dir = tempfile::tempdir().expect("tempdir");
    let device_a = dir.path().join("device-a");
    let device_b = dir.path().join("device-b");
    let device_c = dir.path().join("device-c");
    let key = key();
    let pws = passwords(3, "guardian");
    let destinations = vec![device_a.clone(), device_b.clone(), device_c.clone()];

    let paths = init_shards_to(&key, 2, 3, &destinations, &pws).expect("init to devices");
    assert_eq!(paths.len(), 3);

    for (path, destination) in paths.iter().zip(&destinations) {
        assert_eq!(path.parent(), Some(destination.as_path()));
        assert!(path.is_file());
    }

    let recovered = reconstruct(&paths[..2], &pws[..2]).expect("reconstruct");
    assert_eq!(recovered.to_bytes(), key.to_bytes());
}

#[test]
fn round_trip_three_of_five() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = key();
    let pws = passwords(5, "guardian");

    let paths = init_shards(&key, 3, 5, dir.path(), &pws).expect("init");
    assert_eq!(paths.len(), 5);

    let recovered = reconstruct(&paths[..3], &pws[..3]).expect("reconstruct");
    assert_eq!(recovered.to_bytes(), key.to_bytes());
}

#[test]
fn shards_are_binary_files_of_expected_size() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pws = passwords(3, "guardian");
    let paths = init_shards(&key(), 2, 3, dir.path(), &pws).expect("init");

    let expected = 7 + 16 + 12 + SHARE_VALUE_LEN + TAG_LEN;
    for path in &paths {
        let bytes = std::fs::read(path).expect("read");
        assert_eq!(
            bytes.len(),
            expected,
            "unexpected shard size for {}",
            path.display()
        );
        assert_eq!(&bytes[..3], b"HX1");
    }
}

#[test]
fn wrong_password_fails_with_decrypt_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = key();
    let pws = passwords(3, "guardian");
    let paths = init_shards(&key, 2, 3, dir.path(), &pws).expect("init");

    let bad = vec!["wrong".to_string(), pws[1].clone()];
    assert!(matches!(
        reconstruct(&paths[..2], &bad),
        Err(Error::Decrypt { .. })
    ));
}

#[test]
fn tampered_shard_fails_to_decrypt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = key();
    let pws = passwords(3, "guardian");
    let paths = init_shards(&key, 2, 3, dir.path(), &pws).expect("init");

    let mut bytes = std::fs::read(&paths[0]).expect("read");
    let idx = 7 + 16 + 12; // first ciphertext byte
    bytes[idx] ^= 0x01;
    std::fs::write(&paths[0], bytes).expect("rewrite");

    assert!(matches!(
        reconstruct(&paths[..2], &pws[..2]),
        Err(Error::Decrypt { .. })
    ));
}

#[test]
fn too_few_shards_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = key();
    let pws = passwords(3, "guardian");
    let paths = init_shards(&key, 2, 3, dir.path(), &pws).expect("init");

    assert!(matches!(
        reconstruct(&paths[..1], &pws[..1]),
        Err(Error::NotEnoughShares(2, 1))
    ));
}

#[test]
fn mixed_shards_from_different_splits_fail() {
    let dir_a = tempfile::tempdir().expect("tempdir a");
    let dir_b = tempfile::tempdir().expect("tempdir b");
    let key = key();
    let pws = passwords(3, "guardian");

    let set_a = init_shards(&key, 2, 3, dir_a.path(), &pws).expect("init a");
    let set_b = init_shards(&key, 3, 3, dir_b.path(), &pws).expect("init b");

    let mixed = vec![set_a[0].clone(), set_b[0].clone()];
    let pws = vec![pws[0].clone(), pws[1].clone()];
    assert!(matches!(
        reconstruct(&mixed, &pws),
        Err(Error::SplitMismatch { .. })
    ));
}

#[test]
fn password_count_must_match_shard_count() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = key();
    let pws = passwords(3, "guardian");
    let paths = init_shards(&key, 2, 3, dir.path(), &pws).expect("init");

    assert!(matches!(
        reconstruct(&paths[..2], &pws[..1]),
        Err(Error::InvalidParams(_))
    ));
}
