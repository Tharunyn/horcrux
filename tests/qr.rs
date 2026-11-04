//! End-to-end test for the air-gapped QR transport (Mode B over HX3/PNG
//! frames): run the full 4-message FROST protocol (request, commitment,
//! signing package, signature share) through real QR-code PNG files on disk,
//! for every 2-of-3 participant combination, and confirm the aggregated
//! signature verifies under plain Ed25519 against the group's public key —
//! proving the on-disk QR transport carries the protocol correctly end to
//! end, with no in-process shortcut.

use horcrux::mpc::mpc_split;
use horcrux::qr::{self, MessageType, Transport};
use horcrux::qr_mpc::{self, CommitmentData, RequestData, SignatureShareData};
use k256::SecretKey;
use rand::rngs::OsRng;

fn key() -> SecretKey {
    SecretKey::random(&mut OsRng)
}

fn passwords(n: usize, seed: &str) -> Vec<String> {
    (0..n).map(|i| format!("{seed}-{i}")).collect()
}

fn verify_dalek(verifying_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    use ed25519_dalek::Verifier as _;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(verifying_key).expect("valid vk");
    vk.verify(message, &ed25519_dalek::Signature::from_bytes(signature))
        .is_ok()
}

/// Run the full air-gapped protocol for one `signers` subset of participants,
/// entirely through QR PNG files under `dir`, and return the aggregated
/// signature.
fn run_qr_protocol(
    dir: &std::path::Path,
    group_pub: &[u8],
    share_paths: &[std::path::PathBuf],
    pws: &[String],
    message: &[u8],
) -> horcrux::mpc::MpcSignature {
    // Coordinator: build and emit the signing request.
    let request = qr_mpc::mpc_sign_request(group_pub, message).expect("build request");
    qr::write_message_transport(
        dir,
        "request",
        Transport::Qr,
        MessageType::Request,
        request.session,
        &request.to_payload(),
    )
    .expect("write request");

    // Each participant: accept the request, decrypt its share, commit.
    let mut nonces_by_id = std::collections::BTreeMap::new();
    for (path, pw) in share_paths.iter().zip(pws) {
        let (ty, session, payload) =
            qr::read_message_transport(dir, "request").expect("read request");
        assert_eq!(ty, MessageType::Request);
        let request = RequestData::from_payload(session, &payload).expect("parse request");

        let participant =
            qr_mpc::load_participant(&request, path, pw, |_, _| {}).expect("load participant");
        let (commitment, nonces) =
            qr_mpc::produce_commitment(&participant.key_package, &mut OsRng).expect("commit");
        nonces_by_id.insert(commitment.participant_id, nonces);

        let prefix = format!("commit-{}", commitment.participant_id);
        qr::write_message_transport(
            dir,
            &prefix,
            Transport::Qr,
            MessageType::Commitment,
            session,
            &commitment.to_payload(),
        )
        .expect("write commitment");
    }

    // Coordinator: collect every commitment present and build the package.
    let (_, session, req_payload) =
        qr::read_message_transport(dir, "request").expect("read request");
    let request = RequestData::from_payload(session, &req_payload).expect("parse request");
    let ids = qr::list_participant_ids(dir, "commit").expect("list commit ids");
    assert_eq!(ids.len(), share_paths.len());
    let commitments: Vec<CommitmentData> = ids
        .iter()
        .map(|id| {
            let prefix = format!("commit-{id}");
            let (ty, s, payload) =
                qr::read_message_transport(dir, &prefix).expect("read commitment");
            assert_eq!(ty, MessageType::Commitment);
            assert_eq!(s, session);
            CommitmentData::from_payload(&payload).expect("parse commitment")
        })
        .collect();
    let package_bytes = qr_mpc::mpc_sign_package(&request, &commitments).expect("build package");
    qr::write_message_transport(
        dir,
        "package",
        Transport::Qr,
        MessageType::SigningPackage,
        session,
        &package_bytes,
    )
    .expect("write package");

    // Each participant: accept the package, produce its signature share.
    for (path, pw) in share_paths.iter().zip(pws) {
        let (ty, s, payload) = qr::read_message_transport(dir, "request").expect("read request");
        assert_eq!(ty, MessageType::Request);
        let request = RequestData::from_payload(s, &payload).expect("parse request");

        let (pkg_ty, pkg_session, package_bytes) =
            qr::read_message_transport(dir, "package").expect("read package");
        assert_eq!(pkg_ty, MessageType::SigningPackage);
        assert_eq!(pkg_session, session);

        let participant =
            qr_mpc::load_participant(&request, path, pw, |_, _| {}).expect("load participant");
        let nonces = nonces_by_id
            .remove(&horcrux::mpc::FrostShare::read(path).expect("read share").id)
            .expect("nonces for this participant");

        let sig_share = qr_mpc::produce_signature_share(
            &request,
            &package_bytes,
            &participant.key_package,
            nonces,
        )
        .expect("produce signature share");

        let prefix = format!("share-{}", sig_share.participant_id);
        qr::write_message_transport(
            dir,
            &prefix,
            Transport::Qr,
            MessageType::SignatureShare,
            session,
            &sig_share.to_payload(),
        )
        .expect("write signature share");
    }

    // Coordinator: collect every signature share present and finalize.
    let (pkg_ty, pkg_session, package_bytes) =
        qr::read_message_transport(dir, "package").expect("read package");
    assert_eq!(pkg_ty, MessageType::SigningPackage);
    let ids = qr::list_participant_ids(dir, "share").expect("list share ids");
    assert_eq!(ids.len(), share_paths.len());
    let shares: Vec<SignatureShareData> = ids
        .iter()
        .map(|id| {
            let prefix = format!("share-{id}");
            let (ty, s, payload) = qr::read_message_transport(dir, &prefix).expect("read share");
            assert_eq!(ty, MessageType::SignatureShare);
            assert_eq!(s, pkg_session);
            SignatureShareData::from_payload(&payload).expect("parse signature share")
        })
        .collect();

    qr_mpc::finalize_signature(&package_bytes, &shares, &request.group_pub).expect("finalize")
}

#[test]
fn qr_protocol_signs_and_verifies_for_every_threshold_pair() {
    let split_dir = tempfile::tempdir().expect("split tempdir");
    let key = key();
    let pws = passwords(3, "guardian");
    let (paths, group_path) = mpc_split(&key, 2, 3, split_dir.path(), &pws).expect("split");
    let group_pub = std::fs::read(&group_path).expect("read group.pub");
    let message = b"pay Alice 1 SOL over the air gap";

    for combo in [&[0usize, 1], &[0usize, 2], &[1usize, 2]] {
        let dir = tempfile::tempdir().expect("qr tempdir");
        let chosen_paths: Vec<_> = combo.iter().map(|&i| paths[i].clone()).collect();
        let chosen_pws: Vec<_> = combo.iter().map(|&i| pws[i].clone()).collect();

        let sig = run_qr_protocol(dir.path(), &group_pub, &chosen_paths, &chosen_pws, message);

        let expected_vk = horcrux::mpc::group_verifying_key(&group_path).expect("group vk");
        assert_eq!(sig.verifying_key, expected_vk);
        assert!(
            verify_dalek(&sig.verifying_key, message, &sig.signature),
            "aggregated signature (combo {combo:?}) must verify under plain Ed25519"
        );
    }
}

#[test]
fn share_qr_png_bytes_extract_payload_and_stage() {
    let split_dir = tempfile::tempdir().expect("split tempdir");
    let key = key();
    let pws = passwords(3, "guardian");
    let (paths, _group) = mpc_split(&key, 2, 3, split_dir.path(), &pws).expect("split");
    let png = std::fs::read(split_dir.path().join("mpc-1-qr-0.png")).expect("read qr png");

    let payload = qr::shard_payload_from_qr_png_bytes(&png).expect("extract payload");
    assert_eq!(payload, std::fs::read(&paths[0]).expect("read share"));

    let staged = qr::stage_shard_from_qr_png_bytes(&png).expect("stage qr png");
    assert_eq!(
        std::fs::read(&staged).expect("read staged share"),
        std::fs::read(&paths[0]).expect("read share")
    );
    let _ = std::fs::remove_file(staged);
}

#[test]
fn commitment_and_share_files_are_real_qr_pngs() {
    let split_dir = tempfile::tempdir().expect("split tempdir");
    let key = key();
    let pws = passwords(3, "guardian");
    let (paths, group_path) = mpc_split(&key, 2, 3, split_dir.path(), &pws).expect("split");
    let group_pub = std::fs::read(&group_path).expect("read group.pub");

    let dir = tempfile::tempdir().expect("qr tempdir");
    run_qr_protocol(
        dir.path(),
        &group_pub,
        &paths[..2],
        &pws[..2],
        b"qr png check",
    );

    for name in [
        "request-0.png",
        "commit-1-0.png",
        "package-0.png",
        "share-1-0.png",
    ] {
        let path = dir.path().join(name);
        let bytes = std::fs::read(&path).unwrap_or_else(|_| panic!("{name} must exist"));
        assert_eq!(
            &bytes[..8],
            b"\x89PNG\r\n\x1a\n",
            "{name} must be a real PNG image"
        );
    }
}
