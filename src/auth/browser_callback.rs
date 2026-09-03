// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Browser-based authentication callback flow (AUTH-022).
//!
//! # Flow
//! 1. Bind a TCP listener on `127.0.0.1:0` (OS assigns a free port).
//! 2. Generate a PKCE `code_verifier` / `code_challenge` (S256) and a random
//!    `state` token (32 random bytes, hex-encoded) using UUID v4 as the
//!    entropy source (no additional `rand` dependency needed).
//! 3. Construct the console `/auth/cli` URL and open it in the default browser
//!    by shelling out to `open` (macOS), `xdg-open` (Linux), or
//!    `cmd /C start` (Windows).
//! 4. Spin up a minimal Axum server that handles a single `GET /callback`
//!    request. The handler sends the received `code` + `state` through a
//!    oneshot channel and signals the server to shut down.
//! 5. Wait up to [`CALLBACK_TIMEOUT`] for the callback; validate the state.
//! 6. Redeem the code via `POST /v1/auth/handoff/redeem` (includes the
//!    `code_verifier` for PKCE verification on the server).
//! 7. Return the [`LoginResponse`] — the caller is responsible for persisting
//!    the credential and printing the success message.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    extract::{Query, State},
    routing::get,
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use crate::auth::login::LoginResponse;
use crate::error::CliError;
use crate::i18n;

/// Hard timeout for waiting for the browser callback.
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

/// Default console base URL used when no override is supplied.
#[doc(hidden)]
pub const DEFAULT_CONSOLE_URL: &str = "https://console.verdictan.com";

// ── Success / error HTML served to the browser after the callback ─────────────

static CALLBACK_SUCCESS_HTML: &str = concat!(
    "<!DOCTYPE html><html><head><title>Verdictan CLI</title>",
    "<style>body{font-family:sans-serif;max-width:520px;margin:60px auto;color:#222}",
    "h2{color:#0a7d3a}</style></head><body>",
    "<h2>&#x2714; Authentication complete</h2>",
    "<p>You can close this tab and return to your terminal.</p>",
    "</body></html>"
);

static CALLBACK_ERROR_HTML: &str = concat!(
    "<!DOCTYPE html><html><head><title>Verdictan CLI — Error</title>",
    "<style>body{font-family:sans-serif;max-width:520px;margin:60px auto;color:#222}",
    "h2{color:#c0392b}</style></head><body>",
    "<h2>&#x2716; Authentication error</h2>",
    "<p>An error was returned. Please check your terminal for details.</p>",
    "</body></html>"
);

// ── Axum handler state ────────────────────────────────────────────────────────

/// Result forwarded from the callback handler to the waiting flow.
#[derive(Debug, PartialEq, Eq)]
enum CallbackPayload {
    Success {
        code: String,
        state: String,
    },
    Error {
        error: String,
        state: Option<String>,
    },
}

#[derive(Clone)]
struct CallbackState {
    /// Oneshot sender for the code+state pair. Wrapped in `Option` so the
    /// handler can `take` it; the `Arc<Mutex<…>>` makes it `Clone + Send`.
    code_tx: Arc<Mutex<Option<oneshot::Sender<CallbackPayload>>>>,
    /// Notified once the callback has been handled so the server can shut down.
    shutdown: Arc<tokio::sync::Notify>,
}

async fn callback_handler(
    State(state): State<CallbackState>,
    Query(params): Query<HashMap<String, String>>,
) -> axum::response::Html<&'static str> {
    let result = match (params.get("code"), params.get("state"), params.get("error")) {
        (Some(code), Some(st), _) => CallbackPayload::Success {
            code: code.clone(),
            state: st.clone(),
        },
        (_, _, Some(error)) => {
            let state_value = params.get("state").cloned();
            warn!(
                error = %error,
                has_state = state_value.is_some(),
                "browser callback received error parameters"
            );
            CallbackPayload::Error {
                error: error.clone(),
                state: state_value,
            }
        }
        _ => {
            let error = "missing code or state in callback".to_string();
            let state_value = params.get("state").cloned();
            warn!(
                error = %error,
                has_state = state_value.is_some(),
                "browser callback was missing expected parameters"
            );
            CallbackPayload::Error {
                error,
                state: state_value,
            }
        }
    };

    let is_err = matches!(result, CallbackPayload::Error { .. });

    if let Ok(mut guard) = state.code_tx.lock() {
        if let Some(tx) = guard.take() {
            let _ = tx.send(result);
        }
    }

    // Signal the server to begin graceful shutdown regardless of success/error.
    state.shutdown.notify_one();

    if is_err {
        axum::response::Html(CALLBACK_ERROR_HTML)
    } else {
        axum::response::Html(CALLBACK_SUCCESS_HTML)
    }
}

// ── PKCE helpers ──────────────────────────────────────────────────────────────

/// Generate 32 random bytes using two UUID v4 values as entropy.
/// Returns the bytes as a base64url-encoded string (no padding), suitable
/// for use as a PKCE `code_verifier` (RFC 7636 §4.1).
fn pkce_verifier() -> String {
    let a = *uuid::Uuid::new_v4().as_bytes();
    let b = *uuid::Uuid::new_v4().as_bytes();
    let bytes: Vec<u8> = a.iter().chain(b.iter()).copied().collect();
    URL_SAFE_NO_PAD.encode(&bytes)
}

/// Derive `code_challenge` from `code_verifier` using SHA-256 (S256 method).
fn pkce_challenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

/// Generate a random state token (32 bytes, hex-encoded = 64 hex chars).
fn random_state() -> String {
    let a = *uuid::Uuid::new_v4().as_bytes();
    let b = *uuid::Uuid::new_v4().as_bytes();
    let bytes: Vec<u8> = a.iter().chain(b.iter()).copied().collect();
    hex::encode(&bytes)
}

// ── Browser opener ────────────────────────────────────────────────────────────

fn open_browser(url: &str) -> Result<(), CliError> {
    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("open").arg(url).spawn();

    #[cfg(target_os = "linux")]
    let result = std::process::Command::new("xdg-open").arg(url).spawn();

    #[cfg(target_os = "windows")]
    let result = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn();

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let result: std::io::Result<std::process::Child> = Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "unsupported platform — please open the URL manually",
    ));

    result
        .map(|_| ())
        .map_err(|e| CliError::internal(format!("failed to open browser: {e}")))
}

fn is_localhost_host(host: &str) -> bool {
    host == "127.0.0.1" || host.eq_ignore_ascii_case("localhost")
}

fn console_host_matches_api(console_host: &str, api_host: &str) -> bool {
    if is_localhost_host(console_host) {
        return is_localhost_host(api_host);
    }

    // When the API itself is on localhost (dev/test), any console origin is
    // acceptable — there is no production domain pair to enforce.
    if is_localhost_host(api_host) {
        return true;
    }

    if console_host.eq_ignore_ascii_case(api_host) {
        return true;
    }

    api_host
        .strip_prefix("api.")
        .map(|suffix| console_host.eq_ignore_ascii_case(&format!("console.{suffix}")))
        .unwrap_or(false)
}

fn normalize_console_url(console_url: &str, api_url: &str) -> Result<String, CliError> {
    let locale = i18n::global();
    let parsed = reqwest::Url::parse(console_url.trim())
        .map_err(|_| CliError::user(i18n::t(locale, "auth.console_url_invalid")))?;
    let api = reqwest::Url::parse(api_url.trim())
        .map_err(|_| CliError::internal("configured api url is not a valid absolute URL"))?;
    let console_host = parsed.host_str().unwrap_or_default();
    let api_host = api.host_str().unwrap_or_default();

    match parsed.scheme() {
        "https" => {}
        "http" => {
            if !is_localhost_host(console_host) {
                return Err(CliError::user(i18n::t(
                    locale,
                    "auth.console_url_https_required",
                )));
            }
        }
        _ => {
            return Err(CliError::user(i18n::t(locale, "auth.console_url_invalid")));
        }
    }

    if !console_host_matches_api(console_host, api_host) {
        return Err(CliError::user(i18n::t(
            locale,
            "auth.console_url_host_mismatch",
        )));
    }

    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

// ── API redeem call ───────────────────────────────────────────────────────────

async fn redeem_handoff_code(
    api_url: &str,
    code: &str,
    code_verifier: &str,
    state: &str,
) -> Result<LoginResponse, CliError> {
    let url = {
        let base = api_url.trim_end_matches('/');
        format!("{base}/v1/auth/handoff/redeem")
    };

    let payload = serde_json::json!({
        "code": code,
        "code_verifier": code_verifier,
        "state": state,
    });

    debug!(url = %url, "redeeming handoff code");

    let response = reqwest::Client::new()
        .post(&url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| {
            if e.is_connect() {
                CliError::network(i18n::t(i18n::global(), "network.failed_to_connect_api"))
            } else {
                CliError::network(i18n::t_fmt(
                    i18n::global(),
                    "network.http_error",
                    &[&e.to_string()],
                ))
            }
        })?;

    let status = response.status();
    if !status.is_success() {
        let locale = i18n::global();
        return Err(if status.as_u16() == 401 {
            CliError::auth(i18n::t(locale, "auth.handoff_redeem_failed_401"))
        } else if status.as_u16() == 422 {
            CliError::user(i18n::t(locale, "auth.handoff_redeem_invalid_422"))
        } else {
            CliError::network(i18n::t_fmt(
                locale,
                "network.api_request_failed_status",
                &[&status.as_u16().to_string()],
            ))
        });
    }

    response
        .json::<HandoffRedeemResponse>()
        .await
        .map(Into::into)
        .map_err(|e| CliError::internal(format!("failed to parse handoff redeem response: {e}")))
}

#[derive(Debug, Deserialize)]
struct HandoffRedeemResponse {
    organization: HandoffRedeemOrganization,
    user: HandoffRedeemUser,
    session: HandoffRedeemSession,
    project_id: String,
}

#[derive(Debug, Deserialize)]
struct HandoffRedeemOrganization {
    id: String,
    slug: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct HandoffRedeemUser {
    id: String,
    email: String,
    display_name: String,
    role: String,
    #[serde(default)]
    team_ids: Vec<String>,
    #[serde(default)]
    capabilities: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct HandoffRedeemSession {
    token: String,
    expires_at: String,
}

impl From<HandoffRedeemResponse> for LoginResponse {
    fn from(payload: HandoffRedeemResponse) -> Self {
        Self {
            token: payload.session.token,
            expires_at: payload.session.expires_at,
            org_id: payload.organization.id,
            org_name: payload.organization.name,
            org_slug: Some(payload.organization.slug),
            project_id: payload.project_id,
            role: payload.user.role,
            authz_version: 0,
            user_id: Some(payload.user.id),
            email: Some(payload.user.email),
            display_name: Some(payload.user.display_name),
            team_ids: payload.user.team_ids,
            capabilities: payload.user.capabilities,
        }
    }
}

#[doc(hidden)]
pub async fn run_browser_auth_with_opener<F>(
    api_url: &str,
    console_url: &str,
    open_browser_fn: F,
) -> Result<LoginResponse, CliError>
where
    F: FnOnce(&str) -> Result<(), CliError>,
{
    let locale = i18n::global();

    // ── 1. Bind local listener ────────────────────────────────────────────────
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| CliError::internal(format!("failed to bind local callback server: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| CliError::internal(format!("failed to get local port: {e}")))?
        .port();
    debug!(port = port, "local callback listener bound");

    // ── 2. Cryptographic material ─────────────────────────────────────────────
    let state_token = random_state();
    let code_verifier = pkce_verifier();
    let code_challenge = pkce_challenge(&code_verifier);

    // ── 3. Build browser URL ──────────────────────────────────────────────────
    let callback_url = format!("http://127.0.0.1:{port}/callback");
    let console_url = normalize_console_url(console_url, api_url)?;
    let browser_url = format!(
        "{console_url}/auth/cli?callback={callback}&state={state}&code_challenge={challenge}&code_challenge_method=S256",
        console_url = console_url,
        callback = urlencoding::encode(&callback_url),
        state = urlencoding::encode(&state_token),
        challenge = urlencoding::encode(&code_challenge),
    );

    // ── 4. Set up callback server ─────────────────────────────────────────────
    let (code_tx, code_rx) = oneshot::channel::<CallbackPayload>();
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());

    let cb_state = CallbackState {
        code_tx: Arc::new(Mutex::new(Some(code_tx))),
        shutdown: Arc::clone(&shutdown_notify),
    };

    let app = Router::new()
        .route("/callback", get(callback_handler))
        .with_state(cb_state);

    let shutdown_clone = Arc::clone(&shutdown_notify);
    let serve_future = axum::serve(listener, app).with_graceful_shutdown(async move {
        shutdown_clone.notified().await;
    });
    tokio::spawn(async move {
        if let Err(e) = serve_future.await {
            warn!(error = %e, "local callback server error");
        }
    });

    // ── 5. Open browser ───────────────────────────────────────────────────────
    eprintln!("{}", i18n::t(locale, "auth.browser_opening"));
    info!(url = %browser_url, "opening browser for authentication");

    if let Err(e) = open_browser_fn(&browser_url) {
        warn!(error = %e, "could not auto-open browser");
        eprintln!(
            "{}",
            i18n::t_fmt(locale, "auth.browser_manual_open", &[&browser_url])
        );
    }

    // ── 6. Wait for callback ──────────────────────────────────────────────────
    eprintln!("{}", i18n::t(locale, "auth.browser_waiting"));

    let callback_result = tokio::time::timeout(CALLBACK_TIMEOUT, code_rx)
        .await
        .map_err(|_| CliError::auth(i18n::t(locale, "auth.browser_timeout")))?
        .map_err(|_| CliError::internal("callback server closed before receiving a response"))?;

    // Ensure the local server has had time to finish the HTTP response.
    shutdown_notify.notify_one();

    // ── 7. Validate state and callback outcome ────────────────────────────────
    let received_state = match &callback_result {
        CallbackPayload::Success { state, .. } => Some(state.as_str()),
        CallbackPayload::Error { state, .. } => state.as_deref(),
    };
    if received_state != Some(state_token.as_str()) {
        return Err(CliError::auth(i18n::t(
            locale,
            "auth.browser_state_mismatch",
        )));
    }
    debug!("state parameter validated");

    let received_code = match callback_result {
        CallbackPayload::Success { code, .. } => code,
        CallbackPayload::Error { error, .. } => {
            let message = match error.as_str() {
                "access_denied" => i18n::t(locale, "auth.browser_access_denied").to_string(),
                _ => i18n::t_fmt(locale, "auth.browser_failed_reason", &[&error]),
            };
            return Err(CliError::auth(message));
        }
    };

    // ── 8. Redeem code ────────────────────────────────────────────────────────
    let login_response =
        redeem_handoff_code(api_url, &received_code, &code_verifier, &state_token).await?;
    info!("handoff code redeemed successfully");

    Ok(login_response)
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Run the full browser authentication flow.
///
/// # Parameters
/// - `api_url`: base URL of the Verdictan API (e.g. `https://api.verdictan.com`)
/// - `console_url`: base URL of the Verdictan Console (e.g. `https://console.verdictan.com`)
///
/// # Returns
/// A [`LoginResponse`] that the caller should persist via `credential_store::save`.
pub(crate) async fn run_browser_auth(
    api_url: &str,
    console_url: &str,
) -> Result<LoginResponse, CliError> {
    run_browser_auth_with_opener(api_url, console_url, open_browser).await
}

#[cfg(test)]
mod tests {
    #![allow(
        dead_code,
        clippy::approx_constant,
        clippy::assertions_on_constants,
        clippy::assign_op_pattern,
        clippy::await_holding_lock,
        clippy::bool_assert_comparison,
        clippy::clone_on_copy,
        clippy::cloned_ref_to_slice_refs,
        clippy::const_is_empty,
        clippy::derivable_impls,
        clippy::err_expect,
        clippy::expect_fun_call,
        clippy::expect_used,
        clippy::field_reassign_with_default,
        clippy::large_enum_variant,
        clippy::len_zero,
        clippy::manual_contains,
        clippy::manual_range_contains,
        clippy::needless_borrow,
        clippy::needless_borrows_for_generic_args,
        clippy::panic,
        clippy::print_stderr,
        clippy::type_complexity,
        clippy::unnecessary_literal_unwrap,
        clippy::unnecessary_map_or,
        clippy::unwrap_used,
        clippy::useless_conversion,
        clippy::useless_vec,
        unused_imports,
        unused_macros,
        unused_mut,
        unused_variables,
        clippy::nonminimal_bool,
        clippy::overly_complex_bool_expr,
        clippy::needless_update,
        clippy::unnecessary_get_then_check
    )]

    use super::*;
    use axum::{
        extract::{Query, State},
        http::StatusCode,
        response::{Html, IntoResponse},
        routing::post,
        Json, Router,
    };
    use serde_json::Value;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct RedeemServerState {
        requests: Arc<Mutex<Vec<Value>>>,
        status: StatusCode,
        body: Value,
    }

    async fn redeem_handler(
        State(state): State<RedeemServerState>,
        Json(payload): Json<Value>,
    ) -> impl IntoResponse {
        state.requests.lock().expect("request lock").push(payload);
        (state.status, Json(state.body.clone()))
    }

    async fn spawn_redeem_server(
        status: StatusCode,
        body: Value,
    ) -> (String, Arc<Mutex<Vec<Value>>>, tokio::task::JoinHandle<()>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let state = RedeemServerState {
            requests: Arc::clone(&requests),
            status,
            body,
        };
        let app = Router::new()
            .route("/v1/auth/handoff/redeem", post(redeem_handler))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind redeem listener");
        let addr = listener.local_addr().expect("redeem listener addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("redeem server");
        });

        (format!("http://{addr}"), requests, handle)
    }

    fn spawn_browser_callback(browser_url: &str, query_suffix: &str) {
        let parsed = reqwest::Url::parse(browser_url).expect("browser url");
        let callback = parsed
            .query_pairs()
            .find(|(key, _)| key == "callback")
            .map(|(_, value)| value.into_owned())
            .expect("callback url");
        let request_url = format!("{callback}{query_suffix}");
        tokio::runtime::Handle::current().spawn(async move {
            let response = reqwest::get(&request_url).await.expect("callback request");
            assert_eq!(response.status(), reqwest::StatusCode::OK);
        });
    }

    #[test]
    fn pkce_challenge_matches_known_rfc_example() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            pkce_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn console_host_matching_covers_verdictan_and_localhost_cases() {
        assert!(console_host_matches_api(
            "console.verdictan.com",
            "api.verdictan.com"
        ));
        assert!(console_host_matches_api("localhost", "127.0.0.1"));
        assert!(console_host_matches_api(
            "attacker.example.com",
            "127.0.0.1"
        ));
        assert!(!console_host_matches_api(
            "console.other.com",
            "api.verdictan.com"
        ));
    }

    #[test]
    fn normalize_console_url_enforces_scheme_host_and_trailing_slash_rules() {
        assert_eq!(
            normalize_console_url(
                "https://console.verdictan.com/",
                "https://api.verdictan.com"
            )
            .unwrap(),
            "https://console.verdictan.com"
        );
        assert_eq!(
            normalize_console_url("http://localhost:3000/", "http://127.0.0.1:8080").unwrap(),
            "http://localhost:3000"
        );

        let insecure =
            normalize_console_url("http://console.verdictan.com", "https://api.verdictan.com")
                .unwrap_err();
        assert_eq!(insecure.error_code(), "cli.config_invalid");

        let mismatch = normalize_console_url(
            "https://console.attacker.example",
            "https://api.verdictan.com",
        )
        .unwrap_err();
        assert_eq!(mismatch.error_code(), "cli.config_invalid");
    }

    #[test]
    fn handoff_redeem_response_maps_to_login_response() {
        let response = HandoffRedeemResponse {
            organization: HandoffRedeemOrganization {
                id: "org_test".to_string(),
                slug: "org-slug".to_string(),
                name: "Org".to_string(),
            },
            user: HandoffRedeemUser {
                id: "user_test".to_string(),
                email: "user@example.com".to_string(),
                display_name: "User".to_string(),
                role: "owner".to_string(),
                team_ids: vec!["team_a".to_string()],
                capabilities: vec!["can_manage_users".to_string()],
            },
            session: HandoffRedeemSession {
                token: "jwt_token".to_string(),
                expires_at: "2026-07-01T00:00:00Z".to_string(),
            },
            project_id: "project_test".to_string(),
        };

        let mapped = LoginResponse::from(response);
        assert_eq!(mapped.token, "jwt_token");
        assert_eq!(mapped.org_slug.as_deref(), Some("org-slug"));
        assert_eq!(mapped.project_id, "project_test");
        assert_eq!(mapped.role, "owner");
        assert_eq!(mapped.team_ids, vec!["team_a"]);
        assert_eq!(mapped.capabilities, vec!["can_manage_users"]);
        assert_eq!(mapped.authz_version, 0);
    }

    #[tokio::test]
    async fn callback_handler_success_sends_payload_and_success_html() {
        let (tx, rx) = oneshot::channel();
        let state = CallbackState {
            code_tx: Arc::new(Mutex::new(Some(tx))),
            shutdown: Arc::new(tokio::sync::Notify::new()),
        };
        let mut params = HashMap::new();
        params.insert("code".to_string(), "auth-code".to_string());
        params.insert("state".to_string(), "expected-state".to_string());

        let Html(body) = callback_handler(State(state), Query(params)).await;
        assert_eq!(body, CALLBACK_SUCCESS_HTML);

        let payload = rx.await.expect("callback payload");
        assert_eq!(
            payload,
            CallbackPayload::Success {
                code: "auth-code".to_string(),
                state: "expected-state".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn callback_handler_error_sends_payload_and_error_html() {
        let (tx, rx) = oneshot::channel();
        let state = CallbackState {
            code_tx: Arc::new(Mutex::new(Some(tx))),
            shutdown: Arc::new(tokio::sync::Notify::new()),
        };
        let mut params = HashMap::new();
        params.insert("error".to_string(), "access_denied".to_string());
        params.insert("state".to_string(), "expected-state".to_string());

        let Html(body) = callback_handler(State(state), Query(params)).await;
        assert_eq!(body, CALLBACK_ERROR_HTML);

        let payload = rx.await.expect("callback payload");
        assert_eq!(
            payload,
            CallbackPayload::Error {
                error: "access_denied".to_string(),
                state: Some("expected-state".to_string()),
            }
        );
    }

    #[tokio::test]
    async fn callback_handler_missing_code_reports_error_payload() {
        let (tx, rx) = oneshot::channel();
        let state = CallbackState {
            code_tx: Arc::new(Mutex::new(Some(tx))),
            shutdown: Arc::new(tokio::sync::Notify::new()),
        };

        let Html(body) = callback_handler(State(state), Query(HashMap::new())).await;
        assert_eq!(body, CALLBACK_ERROR_HTML);

        let payload = rx.await.expect("callback payload");
        assert_eq!(
            payload,
            CallbackPayload::Error {
                error: "missing code or state in callback".to_string(),
                state: None,
            }
        );
    }

    #[tokio::test]
    async fn redeem_handoff_code_maps_success_payload() {
        let (api_url, requests, handle) = spawn_redeem_server(
            StatusCode::OK,
            serde_json::json!({
                "organization": {
                    "id": "org_live",
                    "slug": "org-live",
                    "name": "Live Org"
                },
                "user": {
                    "id": "user_live",
                    "email": "owner@example.com",
                    "display_name": "Owner",
                    "role": "owner",
                    "team_ids": ["team_live"],
                    "capabilities": ["gateway:write"]
                },
                "session": {
                    "token": "jwt_live",
                    "expires_at": "2030-01-01T00:00:00Z"
                },
                "project_id": "proj_live"
            }),
        )
        .await;

        let response = redeem_handoff_code(&api_url, "code-123", "verifier-123", "state-123")
            .await
            .expect("redeem success");
        assert_eq!(response.token, "jwt_live");
        assert_eq!(response.org_id, "org_live");
        assert_eq!(response.org_slug.as_deref(), Some("org-live"));
        assert_eq!(response.project_id, "proj_live");
        assert_eq!(response.team_ids, vec!["team_live"]);

        let seen = requests.lock().expect("request lock");
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0]["code"], "code-123");
        assert_eq!(seen[0]["code_verifier"], "verifier-123");
        assert_eq!(seen[0]["state"], "state-123");

        handle.abort();
    }

    #[tokio::test]
    async fn redeem_handoff_code_maps_status_errors_and_parse_failures() {
        let unauthorized = spawn_redeem_server(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"error": "denied"}),
        )
        .await;
        let unauthorized_err = redeem_handoff_code(&unauthorized.0, "code", "verifier", "state")
            .await
            .expect_err("401 should fail");
        assert_eq!(unauthorized_err.error_code(), "cli.auth_failed");
        unauthorized.2.abort();

        let invalid = spawn_redeem_server(StatusCode::OK, serde_json::json!("not-an-object")).await;
        let invalid_err = redeem_handoff_code(&invalid.0, "code", "verifier", "state")
            .await
            .expect_err("invalid payload should fail");
        assert_eq!(invalid_err.error_code(), "cli.internal");
        invalid.2.abort();
    }

    #[tokio::test]
    async fn worker6_redeem_handoff_code_maps_422_and_generic_status_errors() {
        let invalid = spawn_redeem_server(
            StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::json!({"error": "invalid"}),
        )
        .await;
        let invalid_err = redeem_handoff_code(&invalid.0, "code", "verifier", "state")
            .await
            .expect_err("422 should fail");
        assert_eq!(invalid_err.error_code(), "cli.config_invalid");
        invalid.2.abort();

        let failed = spawn_redeem_server(
            StatusCode::BAD_GATEWAY,
            serde_json::json!({"error": "upstream failed"}),
        )
        .await;
        let failed_err = redeem_handoff_code(&failed.0, "code", "verifier", "state")
            .await
            .expect_err("502 should fail");
        assert_eq!(failed_err.error_code(), "cli.network_error");
        failed.2.abort();
    }

    #[tokio::test]
    async fn run_browser_auth_with_opener_completes_happy_path() {
        let (api_url, requests, handle) = spawn_redeem_server(
            StatusCode::OK,
            serde_json::json!({
                "organization": {
                    "id": "org_test",
                    "slug": "org-test",
                    "name": "Verdictan Test"
                },
                "user": {
                    "id": "user_test",
                    "email": "owner@example.com",
                    "display_name": "Owner",
                    "role": "owner",
                    "team_ids": ["team_1"],
                    "capabilities": ["gateway:write"]
                },
                "session": {
                    "token": "jwt_token",
                    "expires_at": "2030-01-01T00:00:00Z"
                },
                "project_id": "proj_test"
            }),
        )
        .await;

        let opener = |browser_url: &str| {
            let parsed = reqwest::Url::parse(browser_url).expect("browser url");
            let state = parsed
                .query_pairs()
                .find(|(key, _)| key == "state")
                .map(|(_, value)| value.into_owned())
                .expect("state");
            assert_eq!(
                parsed
                    .query_pairs()
                    .find(|(key, _)| key == "code_challenge_method")
                    .map(|(_, value)| value.into_owned())
                    .as_deref(),
                Some("S256")
            );
            spawn_browser_callback(browser_url, &format!("?code=auth-code&state={state}"));
            Ok(())
        };

        let response = run_browser_auth_with_opener(&api_url, DEFAULT_CONSOLE_URL, opener)
            .await
            .expect("browser auth");
        assert_eq!(response.token, "jwt_token");
        assert_eq!(response.org_id, "org_test");
        assert_eq!(response.project_id, "proj_test");

        let seen = requests.lock().expect("request lock");
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0]["code"], "auth-code");
        assert!(
            seen[0]["code_verifier"]
                .as_str()
                .expect("code verifier")
                .len()
                >= 43
        );
        assert!(!seen[0]["state"].as_str().expect("state").is_empty());

        handle.abort();
    }

    #[tokio::test]
    async fn run_browser_auth_with_opener_rejects_state_mismatch() {
        let (api_url, requests, handle) =
            spawn_redeem_server(StatusCode::OK, serde_json::json!({"unexpected": true})).await;

        let opener = |browser_url: &str| {
            spawn_browser_callback(browser_url, "?code=auth-code&state=wrong-state");
            Ok(())
        };

        let error = run_browser_auth_with_opener(&api_url, DEFAULT_CONSOLE_URL, opener)
            .await
            .expect_err("state mismatch should fail");
        assert_eq!(error.error_code(), "cli.auth_failed");
        assert!(requests.lock().expect("request lock").is_empty());

        handle.abort();
    }

    #[tokio::test]
    async fn run_browser_auth_with_opener_surfaces_callback_errors_and_manual_open_fallback() {
        let (api_url, requests, handle) =
            spawn_redeem_server(StatusCode::OK, serde_json::json!({"unexpected": true})).await;

        let opener = |browser_url: &str| {
            let parsed = reqwest::Url::parse(browser_url).expect("browser url");
            let state = parsed
                .query_pairs()
                .find(|(key, _)| key == "state")
                .map(|(_, value)| value.into_owned())
                .expect("state");
            spawn_browser_callback(browser_url, &format!("?error=access_denied&state={state}"));
            Err(CliError::internal("simulated browser launch failure"))
        };

        let error = run_browser_auth_with_opener(&api_url, DEFAULT_CONSOLE_URL, opener)
            .await
            .expect_err("callback error should fail");
        assert_eq!(error.error_code(), "cli.auth_failed");
        assert!(requests.lock().expect("request lock").is_empty());

        handle.abort();
    }

    #[tokio::test]
    async fn worker6_run_browser_auth_with_opener_surfaces_unknown_callback_reason() {
        let (api_url, requests, handle) =
            spawn_redeem_server(StatusCode::OK, serde_json::json!({"unexpected": true})).await;

        let opener = |browser_url: &str| {
            let parsed = reqwest::Url::parse(browser_url).expect("browser url");
            let state = parsed
                .query_pairs()
                .find(|(key, _)| key == "state")
                .map(|(_, value)| value.into_owned())
                .expect("state");
            spawn_browser_callback(
                browser_url,
                &format!("?error=temporarily_unavailable&state={state}"),
            );
            Ok(())
        };

        let error = run_browser_auth_with_opener(&api_url, DEFAULT_CONSOLE_URL, opener)
            .await
            .expect_err("callback error should fail");
        assert_eq!(error.error_code(), "cli.auth_failed");
        assert!(error.to_string().contains("temporarily_unavailable"));
        assert!(requests.lock().expect("request lock").is_empty());

        handle.abort();
    }
}
