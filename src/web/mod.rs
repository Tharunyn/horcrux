//! A local, loopback-only HTTP UI covering the same Solana MVP flows as the
//! TUI (`src/tui`) — Access log, Verify, Init (Mode A split), Sign (Mode A),
//! standalone Reconstruct, MPC split/sign (Mode B), and the air-gapped QR
//! `qr-*` protocol — for guardians who would rather use a browser than a
//! terminal.
//!
//! Security model, deliberately narrower than a general-purpose web app:
//!
//! - The listener only ever binds `127.0.0.1` — never `0.0.0.0` — so nothing
//!   off this machine can reach it, matching the project's offline-first
//!   posture.
//! - Every `/api/*` request must carry a random per-run bearer token (printed
//!   once at startup and pre-filled into the page's URL) in the
//!   `X-Horcrux-Token` header. A custom header forces the browser to run a
//!   CORS preflight, which this server does not answer for other origins, so
//!   a malicious page cannot forge these requests even by guessing the port.
//! - The static shell (`/`, `/app.js`, `/styles.css`) carries no secrets and
//!   is served without the token so the page itself can load before it knows
//!   the token from its own URL.
//! - Exactly like the CLI and TUI, an audit `Block` verdict refuses the
//!   operation unless the request explicitly sets `force`; a `Warn` verdict
//!   proceeds but the warnings are returned alongside the result.
//! - Signing and MPC responses never include a reconstructed private key or
//!   seed. The only exceptions are a freshly **generated** disposable test key
//!   on Init/MPC-split, and the explicit standalone Reconstruct action (which
//!   requires the shard passwords and is clearly labelled), both returned once
//!   and never persisted by the server.

pub(crate) mod devices;
mod handlers;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use rand::RngCore;
use std::sync::Arc;

pub struct AppState {
    pub token: String,
}

const INDEX_HTML: &str = include_str!("assets/index.html");
const APP_JS: &str = include_str!("assets/app.js");
const STYLES_CSS: &str = include_str!("assets/styles.css");

/// Generate a random 32-byte token, hex-encoded.
fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Constant-time string comparison (the token is short-lived and local-only,
/// but there is no reason not to avoid a timing oracle for free).
fn tokens_match(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn require_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let supplied = headers
        .get("x-horcrux-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if tokens_match(supplied, &state.token) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            "missing or invalid X-Horcrux-Token",
        )
            .into_response()
    }
}

async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX_HTML,
    )
}

async fn app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        APP_JS,
    )
}

async fn styles_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        STYLES_CSS,
    )
}

/// Start the local web UI and block until the process is interrupted.
pub async fn run(port: u16) -> anyhow::Result<()> {
    let token = generate_token();
    let state = Arc::new(AppState {
        token: token.clone(),
    });

    let api = Router::new()
        // Existing endpoints
        .route("/log", get(handlers::log))
        .route("/ai-check", get(handlers::ai_check))
        .route("/risk-assessment", get(handlers::risk_assessment))
        .route("/devices", get(handlers::devices))
        .route("/verify", post(handlers::verify))
        .route("/reconstruct", post(handlers::reconstruct))
        .route("/init", post(handlers::init))
        .route("/sign", post(handlers::sign))
        .route("/mpc-split", post(handlers::mpc_split))
        .route("/mpc-sign", post(handlers::mpc_sign))
        .route("/qr-request", post(handlers::qr_request))
        .route("/qr-commit", post(handlers::qr_commit))
        .route("/qr-package", post(handlers::qr_package))
        .route("/qr-share", post(handlers::qr_share))
        .route("/qr-finalize", post(handlers::qr_finalize))
        .route("/qr-import", post(handlers::qr_import))
        .route("/qr-image", get(handlers::qr_image))
        .route("/shard-qr", post(handlers::shard_qr))
        .route("/shard-qr-import", post(handlers::shard_qr_import))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token))
        .with_state(state.clone());

    let app = Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/styles.css", get(styles_css))
        .nest("/api", api);

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;

    println!("HORCRUX web UI (loopback-only, matches the TUI's Solana MVP scope)");
    println!();
    println!("  http://{bound}/?token={token}");
    println!();
    println!(
        "Open that URL in a browser on this machine. The token above is required for every\n\
         action; anyone or anything that reaches this port without it gets 401. Nothing\n\
         beyond 127.0.0.1 can reach this server. Press Ctrl+C to stop."
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    println!("\nShutting down the web UI.");
}
