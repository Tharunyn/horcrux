//! End-to-end tests for `horcrux verify`: structural integrity checks on SSS
//! shards and FROST key shares, split-consistency reporting, and optional
//! AES-GCM auth-tag verification.

use horcrux::init_shards;
use horcrux::mpc::mpc_split;
use horcrux::qr::{self, Frame, MessageType};
use horcrux::verify::{Kind, consistency_error, verify_files};
use k256::SecretKey;
use rand::rngs::OsRng;

fn key() -> SecretKey {
    SecretKey::random(&mut OsRng)
}

fn passwords(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("guardian-{i}")).collect()
}

#[test]
fn verify_sss_shards_with_and_without_password() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pws = vec!["shared-password".to_string(); 3];
    let shards = init_shards(&key(), 2, 3, dir.path(), &pws).expect("init");

    let structural = verify_files(&shards, None);
    assert!(structural.iter().all(|r| r.ok), "{structural:?}");
    assert_eq!(consistency_error(&structural), None);

    let authed = verify_files(&shards, Some(&pws[0]));
    assert!(authed.iter().all(|r| r.ok), "{authed:?}");

    let wrong = verify_files(&shards, Some("wrong-password"));
    assert!(!wrong.iter().all(|r| r.ok));
}

#[test]
fn verify_frost_shares() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pws = passwords(3);
    let (shares, _group) = mpc_split(&key(), 2, 3, dir.path(), &pws).expect("split");

    let reports = verify_files(&shares, None);
    assert!(reports.iter().all(|r| r.ok));
    assert!(reports.iter().all(|r| r.kind == Some(Kind::Frost)));
    assert_eq!(consistency_error(&reports), None);
}

#[test]
fn tampered_shard_is_reported_invalid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pws = vec!["shared-password".to_string(); 3];
    let shards = init_shards(&key(), 2, 3, dir.path(), &pws).expect("init");

    let mut bytes = std::fs::read(&shards[0]).expect("read");
    let idx = 7 + 16 + 12; // first ciphertext byte
    bytes[idx] ^= 0x01;
    std::fs::write(&shards[0], bytes).expect("rewrite");

    let reports = verify_files(&shards, Some(&pws[0]));
    assert!(!reports[0].ok, "GCM tag must catch tampering");
    assert!(reports[1].ok && reports[2].ok);
}

#[test]
fn verify_generated_sss_qr_pngs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pws = vec!["shared-password".to_string(); 3];
    init_shards(&key(), 2, 3, dir.path(), &pws).expect("init");
    let qr_paths: Vec<_> = (1..=3)
        .map(|id| dir.path().join(format!("shard-{id}-qr-0.png")))
        .collect();

    let reports = verify_files(&qr_paths, None);
    assert!(reports.iter().all(|r| r.ok), "{reports:?}");
    assert!(reports.iter().all(|r| r.kind == Some(Kind::Sss)));
    assert!(reports.iter().all(|r| r.params == Some((2, 3))));
    assert_eq!(consistency_error(&reports), None);

    let authed = verify_files(&qr_paths[..2], Some(&pws[0]));
    assert!(authed.iter().all(|r| r.ok), "{authed:?}");
}

#[test]
fn verify_generated_frost_qr_pngs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pws = passwords(3);
    mpc_split(&key(), 2, 3, dir.path(), &pws).expect("split");
    let qr_paths: Vec<_> = (1..=3)
        .map(|id| dir.path().join(format!("mpc-{id}-qr-0.png")))
        .collect();

    let reports = verify_files(&qr_paths, None);
    assert!(reports.iter().all(|r| r.ok), "{reports:?}");
    assert!(reports.iter().all(|r| r.kind == Some(Kind::Frost)));
    assert!(reports.iter().all(|r| r.params == Some((2, 3))));
    assert_eq!(consistency_error(&reports), None);
}

#[test]
fn verify_rejects_non_shard_qr_pngs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let wrong_type = dir.path().join("wrong-type.png");
    qr::write_qr_png(
        &Frame {
            message_type: MessageType::Request,
            session: [0x42; qr::SESSION_LEN],
            index: 0,
            total: 1,
            payload: b"not a shard".to_vec(),
        },
        &wrong_type,
        4,
    )
    .expect("write wrong-type qr");

    let multi_frame = dir.path().join("multi-frame.png");
    qr::write_qr_png(
        &Frame {
            message_type: MessageType::EncryptedShard,
            session: [0x42; qr::SESSION_LEN],
            index: 0,
            total: 2,
            payload: b"first half".to_vec(),
        },
        &multi_frame,
        4,
    )
    .expect("write multi-frame qr");

    let reports = verify_files(&[wrong_type, multi_frame], None);
    assert!(reports.iter().all(|r| !r.ok), "{reports:?}");
}
