// JSON API handlers backing the web UI.
// Each endpoint wraps the same library functions the CLI and TUI call.

use axum::Json;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use horcrux::audit::{AccessLog, Entry, EntryKind, Scorer, Verdict};
use horcrux::error::Error;
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    body: Value,
}

impl ApiError {
    fn message(status: StatusCode, msg: impl Into<String>) -> Self {
        Self {
            status,
            body: json!({ "error": msg.into() }),
        }
    }

    fn blocked(reasons: Vec<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            body: json!({ "error": "blocked", "reasons": reasons }),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        ApiError::message(StatusCode::BAD_REQUEST, e.to_string())
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        ApiError::message(StatusCode::BAD_REQUEST, e.to_string())
    }
}

fn join_err(e: tokio::task::JoinError) -> ApiError {
    ApiError::message(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("worker task panicked: {e}"),
    )
}

/// Split operations require one non-empty password for every generated
/// shard/share. Passwords are matched to files by array position.
fn validate_passwords(
    passwords: &[String],
    expected: usize,
    item_name: &str,
) -> Result<(), ApiError> {
    if passwords.len() != expected {
        return Err(ApiError::message(
            StatusCode::BAD_REQUEST,
            format!(
                "expected exactly {expected} password(s) for {expected} {item_name}(s), received {}",
                passwords.len()
            ),
        ));
    }

    if passwords.iter().any(|password| password.is_empty()) {
        return Err(ApiError::message(
            StatusCode::BAD_REQUEST,
            format!("every generated {item_name} must have a non-empty password"),
        ));
    }

    Ok(())
}

/// For signing, keep only files whose corresponding password is non-empty.
/// The cryptographic library enforces the actual threshold.
fn select_passworded_files(
    paths: Vec<PathBuf>,
    passwords: Vec<String>,
    item_name: &str,
) -> Result<(Vec<PathBuf>, Vec<String>), ApiError> {
    if paths.len() != passwords.len() {
        return Err(ApiError::message(
            StatusCode::BAD_REQUEST,
            format!(
                "the number of {item_name} paths ({}) must match the number of password fields ({})",
                paths.len(),
                passwords.len()
            ),
        ));
    }

    let mut selected_paths = Vec::new();
    let mut selected_passwords = Vec::new();

    for (path, password) in paths.into_iter().zip(passwords) {
        if !password.is_empty() {
            selected_paths.push(path);
            selected_passwords.push(password);
        }
    }

    if selected_paths.is_empty() {
        return Err(ApiError::message(
            StatusCode::BAD_REQUEST,
            format!("enter passwords for at least the required number of {item_name}s"),
        ));
    }

    Ok((selected_paths, selected_passwords))
}

#[derive(Clone, Copy)]
enum QrPayloadKind {
    Shard,
    Share,
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QrTransportFormat {
    #[default]
    Qr,
    Hx3,
}

impl From<QrTransportFormat> for horcrux::qr::Transport {
    fn from(value: QrTransportFormat) -> Self {
        match value {
            QrTransportFormat::Qr => horcrux::qr::Transport::Qr,
            QrTransportFormat::Hx3 => horcrux::qr::Transport::Hx3,
        }
    }
}

fn read_artifacts(paths: &[PathBuf]) -> Result<Vec<Value>, ApiError> {
    paths
        .iter()
        .map(|path| {
            let bytes = std::fs::read(path)?;
            let mime = if is_png_path(path) {
                "image/png"
            } else {
                "application/octet-stream"
            };

            Ok(json!({
                "path": path.display().to_string(),
                "filename": path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("artifact"),
                "mime": mime,
                "data_base64": BASE64.encode(bytes),
            }))
        })
        .collect()
}

fn default_qr_nonce_path(share: &std::path::Path) -> PathBuf {
    let mut name = share.as_os_str().to_owned();
    name.push(".qr-nonce");
    PathBuf::from(name)
}

fn qr_dir(value: &str) -> PathBuf {
    let value = value.trim();
    PathBuf::from(if value.is_empty() { "qr" } else { value })
}

/// Resolve the per-shard write directory for a split. An empty selection keeps
/// every shard in `base`; otherwise each device root gets a folder named after
/// `base` and receives exactly one shard. The local computer is represented by
/// an empty id so it writes to `base` unchanged.
fn split_destinations(
    base: &std::path::Path,
    devices: &[String],
    count: usize,
    item_name: &str,
) -> Result<Vec<PathBuf>, ApiError> {
    if devices.is_empty() {
        return Ok(vec![base.to_path_buf(); count]);
    }
    if devices.len() != count {
        return Err(ApiError::message(
            StatusCode::BAD_REQUEST,
            format!(
                "expected {count} destination device(s) for {count} {item_name}(s), received {}",
                devices.len()
            ),
        ));
    }

    let folder = base
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("horcrux");

    let mut destinations = Vec::with_capacity(count);
    for device in devices {
        let device = device.trim();
        if device.is_empty() || device.eq_ignore_ascii_case("local") {
            destinations.push(base.to_path_buf());
            continue;
        }

        let root = PathBuf::from(device);
        if !root.is_dir() {
            return Err(ApiError::message(
                StatusCode::BAD_REQUEST,
                format!("destination device {} is not available", root.display()),
            ));
        }
        destinations.push(root.join(folder));
    }
    Ok(destinations)
}

fn is_png_bytes(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x89PNG\r\n\x1a\n")
}

fn remove_alternate_transport(dir: &std::path::Path, prefix: &str, keep: horcrux::qr::Transport) {
    match keep {
        horcrux::qr::Transport::Hx3 => {
            let png_prefix = format!("{prefix}-");
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };

            for entry in entries.flatten() {
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if name.starts_with(&png_prefix) && name.ends_with(".png") {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        horcrux::qr::Transport::Qr => {
            let _ = std::fs::remove_file(dir.join(format!("{prefix}.hx3")));
        }
    }
}

fn is_png_path(path: &std::path::Path) -> bool {
    const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";
    let by_extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("png"));
    by_extension
        || std::fs::read(path).is_ok_and(|bytes| {
            bytes.len() >= PNG_MAGIC.len() && &bytes[..PNG_MAGIC.len()] == PNG_MAGIC
        })
}

fn import_encrypted_qr(
    qr_path: &std::path::Path,
    temp_dir: &std::path::Path,
    kind: QrPayloadKind,
) -> Result<PathBuf, ApiError> {
    let payload = horcrux::qr::shard_payload_from_qr_png(qr_path).map_err(ApiError::from)?;

    match kind {
        QrPayloadKind::Shard => horcrux::shard::Shard::from_bytes(&payload).map(|_| ())?,
        QrPayloadKind::Share => horcrux::mpc::FrostShare::from_bytes(&payload).map(|_| ())?,
    }

    horcrux::qr::stage_shard_payload(&payload, temp_dir).map_err(ApiError::from)
}
fn collect_qr_images(paths: &[PathBuf]) -> Result<Vec<Value>, ApiError> {
    let mut images = Vec::new();

    for shard_path in paths {
        let parent = shard_path.parent().unwrap_or(std::path::Path::new("."));

        let stem = shard_path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| ApiError::message(StatusCode::BAD_REQUEST, "invalid shard filename"))?;

        let prefix = format!("{stem}-qr-");

        for entry in std::fs::read_dir(parent)? {
            let entry = entry?;
            let path = entry.path();

            let Some(filename) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };

            if filename.starts_with(&prefix) && filename.ends_with(".png") {
                images.push(json!({
                    "shard_path": shard_path.display().to_string(),
                    "path": path.display().to_string(),
                    "filename": filename,
                }));
            }
        }
    }

    images.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));

    Ok(images)
}

/// Parse a hex-encoded private key, or generate a disposable test key.
fn resolve_key(
    key_hex: Option<&str>,
    generate: bool,
) -> Result<(k256::SecretKey, Option<String>), ApiError> {
    match (key_hex.filter(|s| !s.is_empty()), generate) {
        (Some(hex_key), _) => Ok((parse_key(hex_key)?, None)),
        (None, true) => {
            let key = k256::SecretKey::random(&mut rand::rngs::OsRng);
            let hex = hex::encode(key.to_bytes());
            Ok((key, Some(hex)))
        }
        (None, false) => Err(ApiError::message(
            StatusCode::BAD_REQUEST,
            "provide either key_hex or generate",
        )),
    }
}

fn parse_key(hex_key: &str) -> Result<k256::SecretKey, Error> {
    let stripped = hex_key.strip_prefix("0x").unwrap_or(hex_key);
    let bytes =
        hex::decode(stripped).map_err(|e| Error::InvalidKey(format!("not valid hex: {e}")))?;

    if bytes.len() != 32 {
        return Err(Error::InvalidKey(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }

    k256::SecretKey::from_slice(&bytes).map_err(|e| Error::InvalidKey(e.to_string()))
}

/// Audit preflight for a proposed attempt.
fn preflight(ids: Vec<u8>, force: bool) -> Result<(AccessLog, u64, Vec<String>), ApiError> {
    let log = AccessLog::open(horcrux::audit::resolve_log_path(None));
    let history = log.read_all()?;
    let now = horcrux::audit::now_ms();
    let attempt: u64 = rand::random();

    let warnings = match Scorer::new().assess(&history, &ids, now) {
        Verdict::Block(reasons) => {
            log.append(&Entry::blocked(now, attempt))?;

            if !force {
                return Err(ApiError::blocked(reasons));
            }

            reasons
                .into_iter()
                .map(|r| format!("BLOCKED, overridden by force: {r}"))
                .collect()
        }
        Verdict::Warn(reasons) => reasons,
        Verdict::Allow => Vec::new(),
    };

    Ok((log, attempt, warnings))
}

fn entry_kind_str(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::DecryptOk => "decrypt_ok",
        EntryKind::DecryptFail => "decrypt_fail",
        EntryKind::Blocked => "blocked",
        EntryKind::Signed => "signed",
    }
}

#[derive(Deserialize)]
pub struct LogQuery {
    tail: Option<usize>,
}

pub async fn log(Query(q): Query<LogQuery>) -> Result<Json<Value>, ApiError> {
    let log = AccessLog::open(horcrux::audit::resolve_log_path(None));

    let entries = match q.tail {
        Some(n) => log.tail(n)?,
        None => log.read_all()?,
    };

    let items: Vec<Value> = entries
        .iter()
        .map(|e| {
            json!({
                "ts": e.ts,
                "ts_utc": horcrux::audit::format_utc(e.ts),
                "attempt": e.attempt,
                "shard_id": e.shard_id,
                "kind": entry_kind_str(e.kind),
            })
        })
        .collect();

    Ok(Json(json!({ "entries": items })))
}

/// Run an advisory AI security check against the latest 50 access-log entries.
pub async fn ai_check() -> Result<Json<Value>, ApiError> {
    let api_key = std::env::var("OPENROUTER_API_KEY").map_err(|_| {
        ApiError::message(
            StatusCode::SERVICE_UNAVAILABLE,
            "OpenRouter API key is not configured. Run ai-setup first.",
        )
    })?;

    let model = std::env::var("HORCRUX_AI_MODEL").ok();

    let log = AccessLog::open(horcrux::audit::resolve_log_path(None));
    let entries = log.tail(50)?;
    let entries_analyzed = entries.len();

    let verdict = horcrux::ai_anomaly::check(&entries, &api_key, model.as_deref())
        .await
        .map_err(|e| {
            ApiError::message(
                StatusCode::BAD_GATEWAY,
                format!("AI security check failed: {e}"),
            )
        })?;

    Ok(Json(json!({
        "anomaly": verdict.anomaly,
        "summary": verdict.summary,
        "model": verdict.model,
        "entries_analyzed": entries_analyzed,
    })))
}

/// Return a deterministic, advisory risk assessment of the access log.
pub async fn risk_assessment() -> Result<Json<horcrux::risk::RiskAssessment>, ApiError> {
    let log = AccessLog::open(horcrux::audit::resolve_log_path(None));
    let entries = log.read_all()?;

    let assessment = horcrux::risk::assess(&entries);

    Ok(Json(assessment))
}

pub async fn devices() -> Json<Value> {
    Json(json!({ "devices": super::devices::list() }))
}

#[derive(Deserialize)]
pub struct VerifyReq {
    files: Vec<String>,
    password: Option<String>,
}

pub async fn verify(Json(req): Json<VerifyReq>) -> Result<Json<Value>, ApiError> {
    let paths: Vec<PathBuf> = req.files.iter().map(PathBuf::from).collect();

    let reports = horcrux::verify::verify_files(&paths, req.password.as_deref());
    let consistency_error = horcrux::verify::consistency_error(&reports);
    let all_ok = consistency_error.is_none() && reports.iter().all(|r| r.ok);

    let items: Vec<Value> = reports
        .iter()
        .map(|r| {
            json!({
                "path": r.path,
                "ok": r.ok,
                "kind": r.kind.map(|k| match k {
                    horcrux::verify::Kind::Sss => "sss",
                    horcrux::verify::Kind::Frost => "frost",
                }),
                "threshold": r.params.map(|(t, _)| t),
                "shares": r.params.map(|(_, n)| n),
            })
        })
        .collect();

    Ok(Json(json!({
        "reports": items,
        "consistency_error": consistency_error,
        "all_ok": all_ok,
    })))
}

// ============================================================
// MODE A: SPLIT
// ============================================================

#[derive(Deserialize)]
pub struct InitReq {
    threshold: u8,
    shares: u8,
    key_hex: Option<String>,
    generate: bool,
    out_dir: String,
    passwords: Vec<String>,
    #[serde(default)]
    devices: Vec<String>,
}

pub async fn init(Json(req): Json<InitReq>) -> Result<Json<Value>, ApiError> {
    validate_passwords(&req.passwords, req.shares as usize, "shard")?;

    let (key, generated_key_hex) = resolve_key(req.key_hex.as_deref(), req.generate)?;

    let out_dir = PathBuf::from(if req.out_dir.trim().is_empty() {
        "shards"
    } else {
        req.out_dir.trim()
    });

    let out_dir_display = out_dir.display().to_string();
    let destinations = split_destinations(&out_dir, &req.devices, req.shares as usize, "shard")?;
    let shares = req.shares;
    let threshold = req.threshold;
    let passwords = req.passwords;

    let paths = tokio::task::spawn_blocking(move || {
        horcrux::init_shards_to(&key, threshold, shares, &destinations, &passwords)
    })
    .await
    .map_err(join_err)??;

    let qr_images = collect_qr_images(&paths)?;

    Ok(Json(json!({
        "generated_key_hex": generated_key_hex,
        "out_dir": out_dir_display,
        "paths": paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "qr_images": qr_images,
    })))
}

// ============================================================
// MODE B: FROST SPLIT
// ============================================================

#[derive(Deserialize)]
pub struct MpcSplitReq {
    threshold: u8,
    shares: u8,
    key_hex: Option<String>,
    generate: bool,
    out_dir: String,
    passwords: Vec<String>,
    #[serde(default)]
    devices: Vec<String>,
}

pub async fn mpc_split(Json(req): Json<MpcSplitReq>) -> Result<Json<Value>, ApiError> {
    validate_passwords(&req.passwords, req.shares as usize, "share")?;

    let (key, generated_key_hex) = resolve_key(req.key_hex.as_deref(), req.generate)?;

    let out_dir = PathBuf::from(if req.out_dir.trim().is_empty() {
        "mpc"
    } else {
        req.out_dir.trim()
    });

    let destinations = split_destinations(&out_dir, &req.devices, req.shares as usize, "share")?;
    let shares = req.shares;
    let threshold = req.threshold;
    let passwords = req.passwords;

    let (paths, group_path) = tokio::task::spawn_blocking(move || {
        horcrux::mpc::mpc_split_to(&key, threshold, shares, &destinations, &out_dir, &passwords)
    })
    .await
    .map_err(join_err)??;

    let qr_images = collect_qr_images(&paths)?;

    Ok(Json(json!({
        "generated_key_hex": generated_key_hex,
        "paths": paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "group_path": group_path.display().to_string(),
        "qr_images": qr_images,
    })))
}

// ============================================================
// MODE A: SIGN
// ============================================================

#[derive(Deserialize)]
pub struct SignReq {
    shards: Vec<String>,
    passwords: Vec<String>,
    to: String,
    lamports: u64,
    blockhash: Option<String>,
    broadcast: bool,
    rpc_url: Option<String>,
    #[serde(default)]
    force: bool,
}

pub async fn sign(Json(req): Json<SignReq>) -> Result<Json<Value>, ApiError> {
    let SignReq {
        shards,
        passwords,
        to,
        lamports,
        blockhash,
        broadcast,
        rpc_url,
        force,
    } = req;

    let shard_paths: Vec<PathBuf> = shards.iter().map(PathBuf::from).collect();

    if shard_paths.is_empty() {
        return Err(ApiError::message(
            StatusCode::BAD_REQUEST,
            "select at least one shard",
        ));
    }

    let (selected_paths, passwords) = select_passworded_files(shard_paths, passwords, "shard")?;

    let temp_dir = tempfile::tempdir()?;
    let mut resolved_paths = Vec::with_capacity(selected_paths.len());

    for path in &selected_paths {
        if is_png_path(path) {
            let imported = import_encrypted_qr(path, temp_dir.path(), QrPayloadKind::Shard)?;
            resolved_paths.push(imported);
        } else {
            resolved_paths.push(path.clone());
        }
    }

    let shard_paths = resolved_paths;

    let to: solana_pubkey::Pubkey = to.trim().parse().map_err(|e| {
        ApiError::message(
            StatusCode::BAD_REQUEST,
            format!("invalid recipient address: {e}"),
        )
    })?;

    let ids = horcrux::audit::shard_ids(&shard_paths)?;
    let (log, attempt, warnings) = preflight(ids, force)?;

    let rpc_url = rpc_url.unwrap_or_else(horcrux::chain::default_rpc_url);

    let chain = if broadcast {
        Some(horcrux::chain::Chain::connect(&rpc_url))
    } else {
        None
    };

    let blockhash: solana_hash::Hash = match blockhash.as_deref().filter(|s| !s.is_empty()) {
        Some(bh) => bh.parse().map_err(|e| {
            ApiError::message(StatusCode::BAD_REQUEST, format!("invalid blockhash: {e}"))
        })?,
        None => {
            let chain = chain.as_ref().ok_or_else(|| {
                ApiError::message(
                    StatusCode::BAD_REQUEST,
                    "offline signing requires a blockhash (or turn on broadcast to fetch one)",
                )
            })?;

            chain.latest_blockhash().await?
        }
    };

    let signed: horcrux::tx::SignedTx = tokio::task::spawn_blocking(move || {
        let key = horcrux::reconstruct_with_audit(&shard_paths, &passwords, &log, attempt)?;

        let seed = horcrux::key_seed(&key);
        let from = horcrux::tx::derive_address(&seed);

        let tx_params = horcrux::tx::TxParams {
            from,
            to,
            lamports,
            blockhash,
        };

        let seed_bytes: [u8; 32] = *seed;

        horcrux::tx::sign_transaction(seed_bytes, tx_params)
    })
    .await
    .map_err(join_err)??;

    let mut result = json!({
        "from": signed.from().to_string(),
        "signature": signed.signature().to_string(),
        "raw_base58": signed.raw_base58(),
        "warnings": warnings,
    });

    if broadcast {
        let chain = chain.expect("broadcast implies chain was connected above");

        match chain.balance(&signed.from()).await {
            Ok(balance) if balance > 0 => {
                match horcrux::chain::broadcast(
                    chain.client(),
                    signed.tx(),
                    Duration::from_secs(1),
                    60,
                )
                .await
                {
                    Ok(sig) => result["mined_signature"] = json!(sig.to_string()),
                    Err(e) => result["broadcast_error"] = json!(e.to_string()),
                }
            }
            Ok(_) => {
                result["broadcast_error"] = json!(format!(
                    "sender {} is unfunded; airdrop lamports first",
                    signed.from()
                ));
            }
            Err(e) => {
                result["broadcast_error"] = json!(e.to_string());
            }
        }
    }

    Ok(Json(result))
}

// ============================================================
// RECONSTRUCT
// ============================================================

#[derive(Deserialize)]
pub struct ReconstructReq {
    shards: Vec<String>,
    passwords: Vec<String>,
    #[serde(default)]
    force: bool,
}

pub async fn reconstruct(Json(req): Json<ReconstructReq>) -> Result<Json<Value>, ApiError> {
    let ReconstructReq {
        shards,
        passwords,
        force,
    } = req;

    let shard_paths: Vec<PathBuf> = shards.iter().map(PathBuf::from).collect();

    if shard_paths.is_empty() {
        return Err(ApiError::message(
            StatusCode::BAD_REQUEST,
            "select at least one shard",
        ));
    }

    let (selected_paths, passwords) = select_passworded_files(shard_paths, passwords, "shard")?;

    let temp_dir = tempfile::tempdir()?;
    let mut resolved_paths = Vec::with_capacity(selected_paths.len());

    for path in &selected_paths {
        if is_png_path(path) {
            let imported = import_encrypted_qr(path, temp_dir.path(), QrPayloadKind::Shard)?;
            resolved_paths.push(imported);
        } else {
            resolved_paths.push(path.clone());
        }
    }

    let shard_paths = resolved_paths;

    let ids = horcrux::audit::shard_ids(&shard_paths)?;
    let (log, attempt, warnings) = preflight(ids, force)?;

    let key_hex = tokio::task::spawn_blocking(move || -> Result<(String, String), ApiError> {
        let key = horcrux::reconstruct_with_audit(&shard_paths, &passwords, &log, attempt)?;
        let address = horcrux::tx::derive_address(&horcrux::key_seed(&key)).to_string();
        Ok((format!("0x{}", hex::encode(key.to_bytes())), address))
    })
    .await
    .map_err(join_err)??;

    Ok(Json(json!({
        "key_hex": key_hex.0,
        "address": key_hex.1,
        "warnings": warnings,
    })))
}

// ============================================================
// MODE B: FROST SIGN
// ============================================================

#[derive(Deserialize)]
pub struct MpcSignReq {
    shares: Vec<String>,
    group_dir: String,
    passwords: Vec<String>,
    to: String,
    lamports: u64,
    blockhash: Option<String>,
    broadcast: bool,
    rpc_url: Option<String>,
    #[serde(default)]
    force: bool,
}

pub async fn mpc_sign(Json(req): Json<MpcSignReq>) -> Result<Json<Value>, ApiError> {
    let MpcSignReq {
        shares,
        group_dir,
        passwords,
        to,
        lamports,
        blockhash,
        broadcast,
        rpc_url,
        force,
    } = req;

    let share_paths: Vec<PathBuf> = shares.iter().map(PathBuf::from).collect();

    if share_paths.is_empty() {
        return Err(ApiError::message(
            StatusCode::BAD_REQUEST,
            "select at least one key share",
        ));
    }

    let (selected_paths, passwords) = select_passworded_files(share_paths, passwords, "share")?;

    let temp_dir = tempfile::tempdir()?;
    let mut resolved_paths = Vec::with_capacity(selected_paths.len());
    for path in &selected_paths {
        if is_png_path(path) {
            let imported = import_encrypted_qr(path, temp_dir.path(), QrPayloadKind::Share)?;
            resolved_paths.push(imported);
        } else {
            resolved_paths.push(path.clone());
        }
    }
    let share_paths = resolved_paths;

    let group_dir = PathBuf::from(if group_dir.trim().is_empty() {
        "mpc"
    } else {
        group_dir.trim()
    });

    let group_pub = group_dir.join(horcrux::mpc::GROUP_PUB_FILENAME);

    let to: solana_pubkey::Pubkey = to.trim().parse().map_err(|e| {
        ApiError::message(
            StatusCode::BAD_REQUEST,
            format!("invalid recipient address: {e}"),
        )
    })?;

    let ids = horcrux::mpc::shard_ids(&share_paths)?;
    let (log, attempt, warnings) = preflight(ids, force)?;

    let verifying_key: [u8; 32] = horcrux::mpc::group_verifying_key(&group_pub)?;

    let from = solana_pubkey::Pubkey::from(verifying_key);

    let rpc_url = rpc_url.unwrap_or_else(horcrux::chain::default_rpc_url);

    let chain = if broadcast {
        Some(horcrux::chain::Chain::connect(&rpc_url))
    } else {
        None
    };

    let blockhash: solana_hash::Hash = match blockhash.as_deref().filter(|s| !s.is_empty()) {
        Some(bh) => bh.parse().map_err(|e| {
            ApiError::message(StatusCode::BAD_REQUEST, format!("invalid blockhash: {e}"))
        })?,
        None => {
            let chain = chain.as_ref().ok_or_else(|| {
                ApiError::message(
                    StatusCode::BAD_REQUEST,
                    "offline signing requires a blockhash (or turn on broadcast to fetch one)",
                )
            })?;

            chain.latest_blockhash().await?
        }
    };

    if let Some(chain) = &chain {
        let balance = chain.balance(&from).await?;

        if balance == 0 {
            return Err(ApiError::message(
                StatusCode::BAD_REQUEST,
                format!("sender {from} is unfunded; airdrop lamports first"),
            ));
        }
    }

    let params = horcrux::tx::TxParams {
        from,
        to,
        lamports,
        blockhash,
    };

    let signed: horcrux::tx::SignedTx = tokio::task::spawn_blocking(move || {
        let message = horcrux::tx::transaction_message(&params);
        let message_bytes = message.serialize();

        let sig = horcrux::mpc::mpc_sign_with_audit(
            &share_paths,
            &passwords,
            &group_pub,
            &message_bytes,
            &log,
            attempt,
        )?;

        horcrux::tx::sign_transaction_with_signature(params, sig.signature, sig.verifying_key)
    })
    .await
    .map_err(join_err)??;

    let mut result = json!({
        "from": signed.from().to_string(),
        "signature": signed.signature().to_string(),
        "raw_base58": signed.raw_base58(),
        "warnings": warnings,
    });

    if broadcast {
        let chain = chain.expect("broadcast implies chain was connected above");

        match horcrux::chain::broadcast(chain.client(), signed.tx(), Duration::from_secs(1), 60)
            .await
        {
            Ok(sig) => result["mined_signature"] = json!(sig.to_string()),
            Err(e) => result["broadcast_error"] = json!(e.to_string()),
        }
    }

    Ok(Json(result))
}

#[derive(Deserialize)]
pub struct QrRequestReq {
    group_dir: String,
    to: String,
    lamports: u64,
    blockhash: String,
    dir: String,
    #[serde(default)]
    format: QrTransportFormat,
}

pub async fn qr_request(Json(req): Json<QrRequestReq>) -> Result<Json<Value>, ApiError> {
    let result = tokio::task::spawn_blocking(move || -> Result<Value, ApiError> {
        let to: solana_pubkey::Pubkey = req.to.trim().parse().map_err(|e| {
            ApiError::message(
                StatusCode::BAD_REQUEST,
                format!("invalid recipient address: {e}"),
            )
        })?;
        let blockhash: solana_hash::Hash = req.blockhash.trim().parse().map_err(|e| {
            ApiError::message(StatusCode::BAD_REQUEST, format!("invalid blockhash: {e}"))
        })?;

        let group_dir = PathBuf::from(if req.group_dir.trim().is_empty() {
            "mpc"
        } else {
            req.group_dir.trim()
        });
        let group_pub_path = group_dir.join(horcrux::mpc::GROUP_PUB_FILENAME);
        let group_pub_bytes = std::fs::read(&group_pub_path)?;
        let verifying_key = horcrux::mpc::group_verifying_key(&group_pub_path)?;
        let from = solana_pubkey::Pubkey::from(verifying_key);

        let params = horcrux::tx::TxParams {
            from,
            to,
            lamports: req.lamports,
            blockhash,
        };
        let message = horcrux::tx::transaction_message(&params);
        let message_bytes = message.serialize();

        let request = horcrux::qr_mpc::mpc_sign_request(&group_pub_bytes, &message_bytes)?;
        let dir = qr_dir(&req.dir);
        let paths = horcrux::qr::write_message_transport(
            &dir,
            "request",
            req.format.into(),
            horcrux::qr::MessageType::Request,
            request.session,
            &request.to_payload(),
        )?;

        Ok(json!({
            "from": from.to_string(),
            "to": to.to_string(),
            "lamports": req.lamports,
            "session": hex::encode(request.session),
            "dir": dir.display().to_string(),
            "artifacts": read_artifacts(&paths)?,
        }))
    })
    .await
    .map_err(join_err)??;

    Ok(Json(result))
}

#[derive(Deserialize)]
pub struct QrCommitReq {
    share: String,
    password: String,
    dir: String,
    nonce_file: Option<String>,
    #[serde(default)]
    format: QrTransportFormat,
    #[serde(default)]
    force: bool,
}

pub async fn qr_commit(Json(req): Json<QrCommitReq>) -> Result<Json<Value>, ApiError> {
    if req.password.is_empty() {
        return Err(ApiError::message(
            StatusCode::BAD_REQUEST,
            "enter the share password",
        ));
    }

    let result = tokio::task::spawn_blocking(move || -> Result<Value, ApiError> {
        let dir = qr_dir(&req.dir);
        let temp_dir = tempfile::tempdir()?;
        let mut share = PathBuf::from(req.share.trim());

        if is_png_path(&share) {
            share = import_encrypted_qr(&share, temp_dir.path(), QrPayloadKind::Share)?;
        }

        let (msg_type, session, payload) = horcrux::qr::read_message_transport(&dir, "request")?;
        if msg_type != horcrux::qr::MessageType::Request {
            return Err(ApiError::message(
                StatusCode::BAD_REQUEST,
                format!("expected a signing request in {}", dir.display()),
            ));
        }
        let request = horcrux::qr_mpc::RequestData::from_payload(session, &payload)?;

        let share_id = horcrux::mpc::FrostShare::read(&share)?.id;
        let (log, attempt, warnings) = preflight(vec![share_id], req.force)?;
        let ts = horcrux::audit::now_ms();
        let participant =
            horcrux::qr_mpc::load_participant(&request, &share, &req.password, |id, ok| {
                let entry = if ok {
                    Entry::ok(ts, attempt, id)
                } else {
                    Entry::fail(ts, attempt, id)
                };
                let _ = log.append(&entry);
            })?;

        let mut rng = rand::rngs::OsRng;
        let (commitment, nonces) =
            horcrux::qr_mpc::produce_commitment(&participant.key_package, &mut rng)?;

        let nonce_path = req
            .nonce_file
            .as_deref()
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| default_qr_nonce_path(&share));
        horcrux::qr_mpc::save_nonces(&nonce_path, &req.password, &session, &nonces)?;

        let prefix = format!("commit-{}", commitment.participant_id);
        let paths = horcrux::qr::write_message_transport(
            &dir,
            &prefix,
            req.format.into(),
            horcrux::qr::MessageType::Commitment,
            session,
            &commitment.to_payload(),
        )?;

        Ok(json!({
            "participant_id": commitment.participant_id,
            "session": hex::encode(session),
            "nonce_path": nonce_path.display().to_string(),
            "warnings": warnings,
            "artifacts": read_artifacts(&paths)?,
        }))
    })
    .await
    .map_err(join_err)??;

    Ok(Json(result))
}

#[derive(Deserialize)]
pub struct QrPackageReq {
    dir: String,
    #[serde(default)]
    format: QrTransportFormat,
}

pub async fn qr_package(Json(req): Json<QrPackageReq>) -> Result<Json<Value>, ApiError> {
    let result = tokio::task::spawn_blocking(move || -> Result<Value, ApiError> {
        let dir = qr_dir(&req.dir);
        let (msg_type, session, payload) = horcrux::qr::read_message_transport(&dir, "request")?;
        if msg_type != horcrux::qr::MessageType::Request {
            return Err(ApiError::message(
                StatusCode::BAD_REQUEST,
                format!("expected a signing request in {}", dir.display()),
            ));
        }
        let request = horcrux::qr_mpc::RequestData::from_payload(session, &payload)?;

        let ids = horcrux::qr::list_participant_ids(&dir, "commit")?;
        if ids.is_empty() {
            return Err(ApiError::message(
                StatusCode::BAD_REQUEST,
                format!("no commitments found in {}", dir.display()),
            ));
        }

        let mut commitments = Vec::with_capacity(ids.len());
        for id in &ids {
            let prefix = format!("commit-{id}");
            let (t, s, payload) = horcrux::qr::read_message_transport(&dir, &prefix)?;
            if t != horcrux::qr::MessageType::Commitment || s != session {
                return Err(ApiError::message(
                    StatusCode::BAD_REQUEST,
                    format!("{prefix} does not belong to this signing session"),
                ));
            }
            commitments.push(horcrux::qr_mpc::CommitmentData::from_payload(&payload)?);
        }

        let package_bytes = horcrux::qr_mpc::mpc_sign_package(&request, &commitments)?;
        let paths = horcrux::qr::write_message_transport(
            &dir,
            "package",
            req.format.into(),
            horcrux::qr::MessageType::SigningPackage,
            session,
            &package_bytes,
        )?;

        Ok(json!({
            "ids": ids,
            "session": hex::encode(session),
            "artifacts": read_artifacts(&paths)?,
        }))
    })
    .await
    .map_err(join_err)??;

    Ok(Json(result))
}

#[derive(Deserialize)]
pub struct QrShareReq {
    share: String,
    password: String,
    dir: String,
    nonce_file: Option<String>,
    #[serde(default)]
    format: QrTransportFormat,
    #[serde(default)]
    force: bool,
}

pub async fn qr_share(Json(req): Json<QrShareReq>) -> Result<Json<Value>, ApiError> {
    if req.password.is_empty() {
        return Err(ApiError::message(
            StatusCode::BAD_REQUEST,
            "enter the share password",
        ));
    }

    let result = tokio::task::spawn_blocking(move || -> Result<Value, ApiError> {
        let dir = qr_dir(&req.dir);
        let temp_dir = tempfile::tempdir()?;
        let mut share = PathBuf::from(req.share.trim());

        if is_png_path(&share) {
            share = import_encrypted_qr(&share, temp_dir.path(), QrPayloadKind::Share)?;
        }

        let (msg_type, session, payload) = horcrux::qr::read_message_transport(&dir, "request")?;
        if msg_type != horcrux::qr::MessageType::Request {
            return Err(ApiError::message(
                StatusCode::BAD_REQUEST,
                format!("expected a signing request in {}", dir.display()),
            ));
        }
        let request = horcrux::qr_mpc::RequestData::from_payload(session, &payload)?;

        let (pkg_type, pkg_session, package_bytes) =
            horcrux::qr::read_message_transport(&dir, "package")?;
        if pkg_type != horcrux::qr::MessageType::SigningPackage || pkg_session != session {
            return Err(ApiError::message(
                StatusCode::BAD_REQUEST,
                format!(
                    "signing package in {} does not match this request",
                    dir.display()
                ),
            ));
        }

        let share_id = horcrux::mpc::FrostShare::read(&share)?.id;
        let (log, attempt, warnings) = preflight(vec![share_id], req.force)?;
        let ts = horcrux::audit::now_ms();
        let participant =
            horcrux::qr_mpc::load_participant(&request, &share, &req.password, |id, ok| {
                let entry = if ok {
                    Entry::ok(ts, attempt, id)
                } else {
                    Entry::fail(ts, attempt, id)
                };
                let _ = log.append(&entry);
            })?;

        let nonce_path = req
            .nonce_file
            .as_deref()
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| default_qr_nonce_path(&share));
        let nonces = horcrux::qr_mpc::load_nonces(&nonce_path, &req.password, &session)?;

        let sig_share = horcrux::qr_mpc::produce_signature_share(
            &request,
            &package_bytes,
            &participant.key_package,
            nonces,
        )?;
        let _ = std::fs::remove_file(&nonce_path);
        let _ = log.append(&Entry::signed(horcrux::audit::now_ms(), attempt));

        let prefix = format!("share-{}", sig_share.participant_id);
        let paths = horcrux::qr::write_message_transport(
            &dir,
            &prefix,
            req.format.into(),
            horcrux::qr::MessageType::SignatureShare,
            session,
            &sig_share.to_payload(),
        )?;

        Ok(json!({
            "participant_id": sig_share.participant_id,
            "session": hex::encode(session),
            "nonce_path": nonce_path.display().to_string(),
            "warnings": warnings,
            "artifacts": read_artifacts(&paths)?,
        }))
    })
    .await
    .map_err(join_err)??;

    Ok(Json(result))
}

#[derive(Deserialize)]
pub struct QrFinalizeReq {
    dir: String,
    rpc_url: Option<String>,
    #[serde(default)]
    broadcast: bool,
}

pub async fn qr_finalize(Json(req): Json<QrFinalizeReq>) -> Result<Json<Value>, ApiError> {
    let QrFinalizeReq {
        dir,
        rpc_url,
        broadcast,
    } = req;

    let signed = tokio::task::spawn_blocking(move || -> Result<horcrux::tx::SignedTx, ApiError> {
        let dir = qr_dir(&dir);
        let (msg_type, session, req_payload) =
            horcrux::qr::read_message_transport(&dir, "request")?;
        if msg_type != horcrux::qr::MessageType::Request {
            return Err(ApiError::message(
                StatusCode::BAD_REQUEST,
                format!("expected a signing request in {}", dir.display()),
            ));
        }
        let request = horcrux::qr_mpc::RequestData::from_payload(session, &req_payload)?;

        let (pkg_type, pkg_session, package_bytes) =
            horcrux::qr::read_message_transport(&dir, "package")?;
        if pkg_type != horcrux::qr::MessageType::SigningPackage || pkg_session != session {
            return Err(ApiError::message(
                StatusCode::BAD_REQUEST,
                format!(
                    "signing package in {} does not match this request",
                    dir.display()
                ),
            ));
        }

        let ids = horcrux::qr::list_participant_ids(&dir, "share")?;
        if ids.is_empty() {
            return Err(ApiError::message(
                StatusCode::BAD_REQUEST,
                format!("no signature shares found in {}", dir.display()),
            ));
        }

        let mut shares = Vec::with_capacity(ids.len());
        for id in &ids {
            let prefix = format!("share-{id}");
            let (t, s, payload) = horcrux::qr::read_message_transport(&dir, &prefix)?;
            if t != horcrux::qr::MessageType::SignatureShare || s != session {
                return Err(ApiError::message(
                    StatusCode::BAD_REQUEST,
                    format!("{prefix} does not belong to this signing session"),
                ));
            }
            shares.push(horcrux::qr_mpc::SignatureShareData::from_payload(&payload)?);
        }

        let sig = horcrux::qr_mpc::finalize_signature(&package_bytes, &shares, &request.group_pub)?;
        let message: solana_message::Message =
            bincode::deserialize(&request.message).map_err(|e| {
                ApiError::message(
                    StatusCode::BAD_REQUEST,
                    format!("failed to decode the signed message: {e}"),
                )
            })?;

        horcrux::tx::assemble_signed_transaction(message, sig.signature, sig.verifying_key)
            .map_err(ApiError::from)
    })
    .await
    .map_err(join_err)??;

    let mut result = json!({
        "from": signed.from().to_string(),
        "signature": signed.signature().to_string(),
        "raw_base58": signed.raw_base58(),
    });

    if broadcast {
        let rpc_url = rpc_url.unwrap_or_else(horcrux::chain::default_rpc_url);
        let chain = horcrux::chain::Chain::connect(&rpc_url);

        match horcrux::chain::broadcast(chain.client(), signed.tx(), Duration::from_secs(1), 60)
            .await
        {
            Ok(sig) => result["mined_signature"] = json!(sig.to_string()),
            Err(e) => result["broadcast_error"] = json!(e.to_string()),
        }
    }

    Ok(Json(result))
}

#[derive(Deserialize)]
pub struct QrImportFile {
    filename: String,
    data_base64: String,
}

#[derive(Deserialize)]
pub struct QrImportReq {
    dir: String,
    files: Vec<QrImportFile>,
}

struct ImportGroup {
    frames: Vec<horcrux::qr::Frame>,
    from_hx3: bool,
}

pub async fn qr_import(Json(req): Json<QrImportReq>) -> Result<Json<Value>, ApiError> {
    if req.files.is_empty() {
        return Err(ApiError::message(
            StatusCode::BAD_REQUEST,
            "choose at least one QR PNG or .hx3 file",
        ));
    }

    let result = tokio::task::spawn_blocking(move || -> Result<Value, ApiError> {
        let dir = qr_dir(&req.dir);
        let mut groups: Vec<ImportGroup> = Vec::new();

        for file in req.files {
            let bytes = BASE64.decode(file.data_base64.trim()).map_err(|e| {
                ApiError::message(
                    StatusCode::BAD_REQUEST,
                    format!("invalid base64 in {}: {e}", file.filename),
                )
            })?;
            let from_hx3 = !is_png_bytes(&bytes);
            let frames = if from_hx3 {
                horcrux::qr::deserialize_frames(&bytes)?
            } else {
                vec![horcrux::qr::decode_qr_png_bytes(&bytes)?]
            };

            for frame in frames {
                if frame.message_type == horcrux::qr::MessageType::EncryptedShard {
                    return Err(ApiError::message(
                        StatusCode::BAD_REQUEST,
                        "encrypted shard/share QRs are imported on the Sign or MPC page",
                    ));
                }

                let matching = groups.iter_mut().find(|group| {
                    let first = &group.frames[0];
                    frame.total > 1
                        && first.message_type == frame.message_type
                        && first.session == frame.session
                        && first.total == frame.total
                });

                if let Some(group) = matching {
                    group.frames.push(frame);
                    group.from_hx3 |= from_hx3;
                } else {
                    groups.push(ImportGroup {
                        frames: vec![frame],
                        from_hx3,
                    });
                }
            }
        }

        let mut messages = Vec::with_capacity(groups.len());
        let mut destination_prefixes = std::collections::BTreeSet::new();

        for group in groups {
            let (message_type, session, payload) = horcrux::qr::assemble_message(&group.frames)?;

            let (prefix, participant_id, label) = match message_type {
                horcrux::qr::MessageType::Request => {
                    horcrux::qr_mpc::RequestData::from_payload(session, &payload)?;
                    ("request".to_string(), None, "Signing request".to_string())
                }
                horcrux::qr::MessageType::Commitment => {
                    let commitment = horcrux::qr_mpc::CommitmentData::from_payload(&payload)?;
                    (
                        format!("commit-{}", commitment.participant_id),
                        Some(commitment.participant_id),
                        format!("Commitment from participant {}", commitment.participant_id),
                    )
                }
                horcrux::qr::MessageType::SigningPackage => {
                    ("package".to_string(), None, "Signing package".to_string())
                }
                horcrux::qr::MessageType::SignatureShare => {
                    let share = horcrux::qr_mpc::SignatureShareData::from_payload(&payload)?;
                    (
                        format!("share-{}", share.participant_id),
                        Some(share.participant_id),
                        format!("Signature share from participant {}", share.participant_id),
                    )
                }
                horcrux::qr::MessageType::EncryptedShard => {
                    return Err(ApiError::message(
                        StatusCode::BAD_REQUEST,
                        "encrypted shard/share QRs are imported on the Sign or MPC page",
                    ));
                }
            };

            if !destination_prefixes.insert(prefix.clone()) {
                return Err(ApiError::message(
                    StatusCode::BAD_REQUEST,
                    format!("more than one imported message would overwrite {prefix}"),
                ));
            }

            let transport = if group.from_hx3 {
                horcrux::qr::Transport::Hx3
            } else {
                horcrux::qr::Transport::Qr
            };
            remove_alternate_transport(&dir, &prefix, transport);

            let paths = horcrux::qr::write_message_transport(
                &dir,
                &prefix,
                transport,
                message_type,
                session,
                &payload,
            )?;

            messages.push(json!({
                "label": label,
                "message_type": match message_type {
                    horcrux::qr::MessageType::Request => "request",
                    horcrux::qr::MessageType::Commitment => "commitment",
                    horcrux::qr::MessageType::SigningPackage => "signing_package",
                    horcrux::qr::MessageType::SignatureShare => "signature_share",
                    horcrux::qr::MessageType::EncryptedShard => "encrypted_shard",
                },
                "session": hex::encode(session),
                "participant_id": participant_id,
                "paths": paths.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
                "artifacts": read_artifacts(&paths)?,
            }));
        }

        Ok(json!({ "dir": dir.display().to_string(), "messages": messages }))
    })
    .await
    .map_err(join_err)??;

    Ok(Json(result))
}

#[derive(Deserialize)]
pub struct QrImageQuery {
    path: String,
}

pub async fn qr_image(Query(q): Query<QrImageQuery>) -> Result<Response, ApiError> {
    let path = PathBuf::from(q.path);

    if path.extension().and_then(|e| e.to_str()) != Some("png") {
        return Err(ApiError::message(
            StatusCode::BAD_REQUEST,
            "requested file is not a PNG image",
        ));
    }

    let bytes = tokio::fs::read(path).await?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "image/png")
        .header(axum::http::header::CACHE_CONTROL, "no-store")
        .body(axum::body::Body::from(bytes))
        .map_err(|e| ApiError::message(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(response)
}

#[derive(Deserialize)]
pub struct ShardQrReq {
    path: String,
}

/// Render an encrypted shard/share file on disk as base64 PNG QR frames.
pub async fn shard_qr(Json(req): Json<ShardQrReq>) -> Result<Json<Value>, ApiError> {
    let path = PathBuf::from(req.path);
    let frames_b64 = tokio::task::spawn_blocking(move || -> Result<Vec<String>, Error> {
        let bytes = std::fs::read(path).map_err(Error::Io)?;
        let session: [u8; horcrux::qr::SESSION_LEN] = rand::random();
        let frames =
            horcrux::qr::encode_message(horcrux::qr::MessageType::EncryptedShard, session, &bytes)?;
        frames
            .iter()
            .map(|frame| Ok(BASE64.encode(horcrux::qr::encode_qr_png_bytes(frame, 6)?)))
            .collect()
    })
    .await
    .map_err(join_err)??;

    Ok(Json(json!({ "frames": frames_b64 })))
}

#[derive(Deserialize)]
pub struct ShardQrImportReq {
    png_base64: String,
}

/// Decode a single-frame shard/share QR PNG and stage its payload to a temp
/// `.hx` file, returning that path for the existing path-based forms.
pub async fn shard_qr_import(Json(req): Json<ShardQrImportReq>) -> Result<Json<Value>, ApiError> {
    let bytes = BASE64
        .decode(req.png_base64.trim())
        .map_err(|e| ApiError::message(StatusCode::BAD_REQUEST, format!("invalid base64: {e}")))?;

    let path = tokio::task::spawn_blocking(move || -> Result<PathBuf, Error> {
        let payload = horcrux::qr::shard_payload_from_qr_png_bytes(&bytes)?;
        horcrux::qr::stage_shard_payload(&payload, &std::env::temp_dir())
    })
    .await
    .map_err(join_err)??;

    Ok(Json(json!({ "path": path.display().to_string() })))
}

#[cfg(test)]
mod tests {
    use super::split_destinations;

    #[test]
    fn empty_selection_keeps_all_items_together() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path().join("shards");
        let destinations = split_destinations(&base, &[], 3, "shard").expect("destinations");
        assert_eq!(destinations, vec![base.clone(), base.clone(), base]);
    }

    #[test]
    fn each_device_gets_a_subfolder_of_the_base_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path().join("shards");
        let usb_a = dir.path().join("usb-a");
        let usb_b = dir.path().join("usb-b");
        std::fs::create_dir(&usb_a).expect("usb a");
        std::fs::create_dir(&usb_b).expect("usb b");

        let devices = vec![
            usb_a.display().to_string(),
            String::new(),
            usb_b.display().to_string(),
        ];
        let destinations = split_destinations(&base, &devices, 3, "shard").expect("destinations");

        assert_eq!(destinations[0], usb_a.join("shards"));
        assert_eq!(destinations[1], base);
        assert_eq!(destinations[2], usb_b.join("shards"));
    }

    #[test]
    fn device_count_must_match_item_count() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path().join("shards");
        let error = split_destinations(&base, &[String::new()], 2, "shard")
            .expect_err("mismatch should fail");
        assert_eq!(error.status, axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn unavailable_device_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path().join("shards");
        let missing = dir.path().join("missing-usb");

        let error = split_destinations(&base, &[missing.display().to_string()], 1, "shard")
            .expect_err("missing device should fail");
        assert_eq!(error.status, axum::http::StatusCode::BAD_REQUEST);
    }
}
