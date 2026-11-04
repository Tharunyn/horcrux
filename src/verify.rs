//! Passive shard/share verification (Phase 5).
//!
//! `horcrux verify` checks that shard files are structurally sound without
//! touching any key material: magic, format version, length, and — when a
//! password is supplied — the AES-256-GCM authentication tag. Unlike
//! reconstruction or signing, verification never decrypts into the clear and
//! never writes to the access log.
//!
//! Both file formats are recognized by their magic: `HX1` SSS shards
//! ([`crate::shard::Shard`]) and `HX2` FROST key shares
//! ([`crate::mpc::FrostShare`]). A mixed set is rejected, as are shards from
//! different splits/groups (inconsistent threshold and share count).

use std::path::Path;

/// The recognized file kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A Shamir secret-sharing shard (`HX1`).
    Sss,
    /// A FROST key share (`HX2`).
    Frost,
}

/// The result of verifying a single file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The file path that was checked.
    pub path: String,
    /// The recognized kind, when the file is valid.
    pub kind: Option<Kind>,
    /// Threshold and total share count recorded in the file metadata.
    pub params: Option<(u8, u8)>,
    /// Whether all checks passed (including the auth tag, if `password` was
    /// supplied).
    pub ok: bool,
}

impl Report {
    fn ok(path: &Path, kind: Kind, t: u8, n: u8) -> Self {
        Self {
            path: path.display().to_string(),
            kind: Some(kind),
            params: Some((t, n)),
            ok: true,
        }
    }

    fn invalid(path: &Path) -> Self {
        Self {
            path: path.display().to_string(),
            kind: None,
            params: None,
            ok: false,
        }
    }
}

/// Verify every file in `paths`. Returns one [`Report`] per file; any failure
/// is reflected in the report rather than returned as an `Err`, so the CLI can
/// report every broken file in one pass. Structural errors (bad magic, wrong
/// length, bad version) still abort early for that file.
pub fn verify_files(paths: &[std::path::PathBuf], password: Option<&str>) -> Vec<Report> {
    paths.iter().map(|p| verify_one(p, password)).collect()
}

/// Verify a single file, detecting its kind from the magic bytes. PNG QR
/// images are decoded to the encrypted shard/share payload they carry first,
/// so the same checks apply to on-disk files and QR transports.
fn verify_one(path: &Path, password: Option<&str>) -> Report {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("{}: I/O error: {e}", path.display());
            return Report::invalid(path);
        }
    };

    let bytes = if is_png(path, &bytes) {
        match crate::qr::decode_qr_png_bytes(&bytes)
            .and_then(|frame| crate::qr::shard_payload_from_frame(&frame))
        {
            Ok(payload) => payload,
            Err(e) => {
                eprintln!("{}: {e}", path.display());
                return Report::invalid(path);
            }
        }
    } else {
        bytes
    };

    match magic_of(&bytes) {
        Some(Kind::Sss) => verify_sss(path, &bytes, password),
        Some(Kind::Frost) => verify_frost(path, &bytes, password),
        None => {
            eprintln!(
                "{}: bad magic bytes; not a horcrux shard or share",
                path.display()
            );
            Report::invalid(path)
        }
    }
}

/// Verify an `HX1` SSS shard.
fn verify_sss(path: &Path, bytes: &[u8], password: Option<&str>) -> Report {
    let shard = match crate::shard::Shard::from_bytes(bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}: {e}", path.display());
            return Report::invalid(path);
        }
    };

    if let Some(pw) = password
        && let Err(e) = shard.decrypt(pw)
    {
        eprintln!("{}: {e}", path.display());
        return Report::invalid(path);
    }

    Report::ok(path, Kind::Sss, shard.threshold, shard.share_count)
}

/// Verify an `HX2` FROST key share.
fn verify_frost(path: &Path, bytes: &[u8], password: Option<&str>) -> Report {
    let share = match crate::mpc::FrostShare::from_bytes(bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}: {e}", path.display());
            return Report::invalid(path);
        }
    };

    if let Some(pw) = password
        && let Err(e) = share.decrypt(pw)
    {
        eprintln!("{}: {e}", path.display());
        return Report::invalid(path);
    }

    Report::ok(path, Kind::Frost, share.min_signers, share.max_signers)
}

/// Cross-file consistency: every file must be the same kind with the same
/// (threshold, share count) parameters. Returns the reason a set is
/// inconsistent, if any.
pub fn consistency_error(reports: &[Report]) -> Option<String> {
    let first = reports.iter().next()?;
    if !first.ok {
        return Some("cannot check consistency of invalid files".to_string());
    }
    for r in &reports[1..] {
        if r.kind != first.kind {
            return Some(format!(
                "mixed file types: {} is {:?} but {} is {:?}",
                first.path, first.kind, r.path, r.kind
            ));
        }
        if r.params != first.params {
            return Some(format!(
                "{} and {} have different split parameters ({:?} vs {:?})",
                first.path, r.path, first.params, r.params
            ));
        }
    }
    None
}

/// The file kind implied by the magic bytes, if any.
fn is_png(path: &Path, bytes: &[u8]) -> bool {
    const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";
    let by_content = bytes.len() >= PNG_MAGIC.len() && &bytes[..PNG_MAGIC.len()] == PNG_MAGIC;
    let by_extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("png"));
    by_content || by_extension
}

fn magic_of(bytes: &[u8]) -> Option<Kind> {
    if bytes.len() >= 3 {
        if &bytes[..3] == crate::SHARD_MAGIC {
            return Some(Kind::Sss);
        }
        if &bytes[..3] == crate::mpc::FROST_MAGIC {
            return Some(Kind::Frost);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init_shards;
    use crate::mpc::mpc_split;
    use k256::SecretKey;
    use rand::rngs::OsRng;
    use std::fs;

    fn key() -> SecretKey {
        SecretKey::random(&mut OsRng)
    }

    fn passwords(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("guardian-{i}")).collect()
    }

    fn paths(reports: &[Report]) -> Vec<String> {
        reports.iter().map(|r| r.path.clone()).collect()
    }

    #[test]
    fn verifies_valid_sss_shards() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pws = passwords(3);
        let shards = init_shards(&key(), 2, 3, dir.path(), &pws).expect("init");

        let reports = verify_files(&shards, None);
        assert!(reports.iter().all(|r| r.ok));
        assert!(reports.iter().all(|r| r.kind == Some(Kind::Sss)));
        assert!(reports.iter().all(|r| r.params == Some((2, 3))));
        assert_eq!(consistency_error(&reports), None);
    }

    #[test]
    fn verifies_valid_frost_shares() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pws = passwords(3);
        let (shares, _group) = mpc_split(&key(), 2, 3, dir.path(), &pws).expect("split");

        let reports = verify_files(&shares, None);
        assert!(reports.iter().all(|r| r.ok));
        assert!(reports.iter().all(|r| r.kind == Some(Kind::Frost)));
        assert_eq!(consistency_error(&reports), None);
    }

    #[test]
    fn corrupt_magic_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pws = passwords(3);
        let shards = init_shards(&key(), 2, 3, dir.path(), &pws).expect("init");

        let mut bytes = fs::read(&shards[0]).expect("read");
        bytes[0] = b'X';
        fs::write(&shards[0], bytes).expect("rewrite");

        let reports = verify_files(&shards, None);
        assert!(!reports[0].ok);
        assert!(reports[1].ok && reports[2].ok);
    }

    #[test]
    fn truncated_file_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pws = passwords(3);
        let shards = init_shards(&key(), 2, 3, dir.path(), &pws).expect("init");

        let bytes = fs::read(&shards[0]).expect("read");
        fs::write(&shards[0], &bytes[..bytes.len() - 5]).expect("rewrite");

        let reports = verify_files(&shards, None);
        assert!(!reports[0].ok);
    }

    #[test]
    fn mixed_sss_and_frost_files_are_inconsistent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pws = passwords(3);
        let shards = init_shards(&key(), 2, 3, dir.path(), &pws).expect("init");
        let (shares, _group) = mpc_split(&key(), 2, 3, dir.path(), &pws).expect("split");

        let mut mixed = shards[..1].to_vec();
        mixed.push(shares[0].clone());
        let reports = verify_files(&mixed, None);
        assert!(reports.iter().all(|r| r.ok));
        assert!(
            consistency_error(&reports)
                .expect("mixed kinds must be reported")
                .contains("mixed file types")
        );
    }

    #[test]
    fn shards_from_different_splits_are_inconsistent() {
        let dir_a = tempfile::tempdir().expect("tempdir a");
        let dir_b = tempfile::tempdir().expect("tempdir b");
        let pws = passwords(3);
        let a = init_shards(&key(), 2, 3, dir_a.path(), &pws).expect("init a");
        let b = init_shards(&key(), 3, 3, dir_b.path(), &pws).expect("init b");

        let mut mixed = a[..1].to_vec();
        mixed.push(b[0].clone());
        let reports = verify_files(&mixed, None);
        assert!(reports.iter().all(|r| r.ok));
        assert!(
            consistency_error(&reports)
                .expect("different splits must be reported")
                .contains("different split parameters")
        );
    }

    #[test]
    fn password_checks_the_auth_tag() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pws = vec!["shared-password".to_string(); 3];
        let shards = init_shards(&key(), 2, 3, dir.path(), &pws).expect("init");

        let ok = verify_files(&shards, Some(&pws[0]));
        assert!(ok.iter().all(|r| r.ok));

        let bad = verify_files(&shards, Some("wrong-password"));
        assert!(!bad.iter().all(|r| r.ok));
        assert!(bad[0].kind.is_none());
    }

    #[test]
    fn missing_file_is_reported_invalid() {
        let reports = verify_files(&[std::path::PathBuf::from("/nonexistent/nope.hx")], None);
        assert_eq!(reports.len(), 1);
        assert!(!reports[0].ok);
        assert_eq!(paths(&reports), vec!["/nonexistent/nope.hx"]);
    }
}
