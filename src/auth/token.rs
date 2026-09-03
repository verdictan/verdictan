// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde::{Deserialize, Serialize};

use crate::error::CliError;
use crate::i18n;

use super::credential_store::StoredCredentials;

pub const API_TOKEN_ENV: &str = "VERDICTAN_API_TOKEN";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoamiResolvedRole {
    pub role_id: String,
    pub role_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_display_name: Option<String>,
    /// Populated when the API returns the assignment-level format.
    #[serde(default)]
    pub assignment_level: Option<String>,
    /// Populated when the API returns the assignment-level format.
    #[serde(default)]
    pub assignment_target_id: Option<String>,
    /// Populated when the API returns the binding-kind format.
    #[serde(default)]
    pub binding_kind: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoamiTokenScope {
    pub principal_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_user_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoamiResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub org_id: String,
    pub org_name: String,
    pub project_id: String,
    pub role: String,
    pub auth_method: String,
    #[serde(default)]
    pub team_ids: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub resolved_roles: Vec<WhoamiResolvedRole>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_scope: Option<WhoamiTokenScope>,
}

#[derive(Debug, Serialize)]
pub struct CreateTokenRequest {
    pub name: String,
    /// Principal type for the new token. Serialized as `principal_type` to
    /// match the current API contract.
    #[serde(rename = "principal_type")]
    pub principal_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub role_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenRoleSummary {
    pub role_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub is_system: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenRecord {
    pub token_id: String,
    pub name: String,
    pub token_prefix: String,
    pub principal_type: String,
    pub team_id: Option<String>,
    pub subject_user_id: Option<String>,
    pub created_by: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
    pub roles: Vec<TokenRoleSummary>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListTokensResponse {
    pub tokens: Vec<TokenRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTokenResponse {
    pub token: TokenRecord,
    pub token_value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeTokenResponse {
    pub revoked: bool,
}

pub async fn create_token_async(
    base_url: &str,
    bearer_token: &str,
    request: &CreateTokenRequest,
) -> Result<CreateTokenResponse, CliError> {
    let client = build_client_async(bearer_token)?;
    let response = client
        .post(join_url(base_url, "/v1/tokens"))
        .json(request)
        .send()
        .await
        .map_err(map_reqwest_error)?;
    parse_json_response_async(response).await
}

pub async fn list_tokens_async(
    base_url: &str,
    bearer_token: &str,
) -> Result<ListTokensResponse, CliError> {
    let client = build_client_async(bearer_token)?;
    let response = client
        .get(join_url(base_url, "/v1/tokens"))
        .send()
        .await
        .map_err(map_reqwest_error)?;
    parse_json_response_async(response).await
}

pub async fn revoke_token_async(
    base_url: &str,
    bearer_token: &str,
    token_id: &str,
) -> Result<RevokeTokenResponse, CliError> {
    let client = build_client_async(bearer_token)?;
    let response = client
        .delete(join_url(base_url, &format!("/v1/tokens/{token_id}")))
        .send()
        .await
        .map_err(map_reqwest_error)?;
    parse_json_response_async(response).await
}

pub async fn whoami_async(base_url: &str, bearer_token: &str) -> Result<WhoamiResponse, CliError> {
    let client = build_client_async(bearer_token)?;
    let response = client
        .get(join_url(base_url, "/v1/whoami"))
        .send()
        .await
        .map_err(map_reqwest_error)?;
    parse_json_response_async(response).await
}

pub fn load_api_token_from_env() -> Result<Option<String>, CliError> {
    Ok(std::env::var(API_TOKEN_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty()))
}

pub fn resolve_api_token(
    explicit_token: Option<String>,
    stored_credentials: Option<&StoredCredentials>,
) -> Result<String, CliError> {
    if let Some(token) = explicit_token
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return Ok(token);
    }

    if let Some(token) = load_api_token_from_env()? {
        return Ok(token);
    }

    if let Some(credentials) = stored_credentials {
        if !credentials.api_token.trim().is_empty() {
            if stored_credentials_expired(credentials)? {
                return Err(CliError::auth(
                    "stored api token has expired; run `verdictan auth login` again",
                ));
            }
            return Ok(credentials.api_token.clone());
        }
    }

    Err(CliError::auth(i18n::t(
        i18n::global(),
        "auth.missing_api_token",
    )))
}

fn stored_credentials_expired(credentials: &StoredCredentials) -> Result<bool, CliError> {
    let Some(expires_at) = credentials.expires_at.as_deref() else {
        return Ok(false);
    };
    let expires_at = chrono::DateTime::parse_from_rfc3339(expires_at).map_err(|error| {
        CliError::auth(format!(
            "stored credential expiry is invalid; run `verdictan auth login` again: {error}"
        ))
    })?;

    #[cfg(verdictan_cli_e2e)]
    let now = std::env::var("VERDICTAN_TEST_NOW_RFC3339")
        .ok()
        .map(|value| chrono::DateTime::parse_from_rfc3339(&value))
        .transpose()
        .map_err(|error| CliError::internal(format!("invalid injected CLI test time: {error}")))?
        .map(|value| value.with_timezone(&chrono::Utc))
        .unwrap_or_else(chrono::Utc::now);
    #[cfg(not(verdictan_cli_e2e))]
    let now = chrono::Utc::now();

    Ok(expires_at <= now)
}

fn build_client_async(bearer_token: &str) -> Result<reqwest::Client, CliError> {
    let locale = i18n::global();
    let mut headers = reqwest::header::HeaderMap::new();
    let value = format!("Bearer {bearer_token}");
    let auth_value = reqwest::header::HeaderValue::from_str(&value)
        .map_err(|_| CliError::user(i18n::t(locale, "user.token_invalid_header_characters")))?;
    headers.insert(reqwest::header::AUTHORIZATION, auth_value);

    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .map_err(|error| {
            CliError::internal(i18n::t_fmt(
                locale,
                "internal.failed_to_build_http_client",
                &[&error.to_string()],
            ))
        })
}

fn join_url(base_url: &str, path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    format!("{base}/{path}")
}

async fn parse_json_response_async<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> Result<T, CliError> {
    let status = response.status();
    if !status.is_success() {
        return Err(map_http_status(status));
    }

    response.json::<T>().await.map_err(map_reqwest_error)
}

fn map_http_status(status: reqwest::StatusCode) -> CliError {
    let locale = i18n::global();
    let code = status.as_u16();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return CliError::auth(i18n::t(locale, "auth.api_authentication_failed_401"))
            .with_http_status(code);
    }
    if status == reqwest::StatusCode::FORBIDDEN {
        return CliError::auth(i18n::t(locale, "auth.api_authorization_failed_403"))
            .with_http_status(code);
    }
    if status == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
        return CliError::user(i18n::t(locale, "user.api_validation_failed_422"))
            .with_http_status(code);
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        return CliError::user(i18n::t(locale, "user.api_resource_not_found_404"))
            .with_http_status(code);
    }
    CliError::network(i18n::t_fmt(
        locale,
        "network.api_request_failed_status",
        &[&code.to_string()],
    ))
    .with_http_status(code)
}

fn map_reqwest_error(error: reqwest::Error) -> CliError {
    let locale = i18n::global();
    if error.is_timeout() {
        return CliError::network(i18n::t(locale, "network.request_timed_out"));
    }
    if error.is_connect() {
        return CliError::network(i18n::t(locale, "network.failed_to_connect_api"));
    }
    CliError::network(i18n::t_fmt(
        locale,
        "network.http_error",
        &[&error.to_string()],
    ))
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
        extract::{Path, State},
        http::HeaderMap,
        response::IntoResponse,
        routing::{delete, get, post},
        Json, Router,
    };
    use reqwest::StatusCode;
    use serde_json::Value;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct TokenServerState {
        seen_auth_headers: Arc<Mutex<Vec<String>>>,
    }

    fn auth_header(headers: &HeaderMap) -> String {
        headers
            .get(reqwest::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    async fn create_token_handler(
        State(state): State<TokenServerState>,
        headers: HeaderMap,
        Json(payload): Json<Value>,
    ) -> impl IntoResponse {
        state
            .seen_auth_headers
            .lock()
            .expect("auth header lock")
            .push(auth_header(&headers));
        assert_eq!(payload["name"], "Build Token");
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "token": {
                    "token_id": "tok_123",
                    "name": payload["name"].clone(),
                    "token_prefix": "vdt_live",
                    "principal_type": "service_account",
                    "team_id": null,
                    "subject_user_id": null,
                    "created_by": "user_123",
                    "created_at": "2030-01-01T00:00:00Z",
                    "expires_at": null,
                    "last_used_at": null,
                    "revoked_at": null,
                    "roles": [{
                        "role_id": "role_owner",
                        "name": "owner",
                        "identifier": "org_owner",
                        "display_name": "Org Owner",
                        "is_system": true
                    }]
                },
                "token_value": "live-secret-token"
            })),
        )
    }

    async fn list_tokens_handler(
        State(state): State<TokenServerState>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        state
            .seen_auth_headers
            .lock()
            .expect("auth header lock")
            .push(auth_header(&headers));
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "tokens": [{
                    "token_id": "tok_123",
                    "name": "Build Token",
                    "token_prefix": "vdt_live",
                    "principal_type": "service_account",
                    "team_id": null,
                    "subject_user_id": null,
                    "created_by": "user_123",
                    "created_at": "2030-01-01T00:00:00Z",
                    "expires_at": null,
                    "last_used_at": null,
                    "revoked_at": null,
                    "roles": []
                }]
            })),
        )
    }

    async fn revoke_token_handler(
        State(state): State<TokenServerState>,
        headers: HeaderMap,
        Path(token_id): Path<String>,
    ) -> impl IntoResponse {
        state
            .seen_auth_headers
            .lock()
            .expect("auth header lock")
            .push(auth_header(&headers));
        assert_eq!(token_id, "tok_123");
        (StatusCode::OK, Json(serde_json::json!({ "revoked": true })))
    }

    async fn whoami_handler(
        State(state): State<TokenServerState>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        state
            .seen_auth_headers
            .lock()
            .expect("auth header lock")
            .push(auth_header(&headers));
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "user_id": "user_123",
                "email": "owner@example.com",
                "display_name": "Owner",
                "org_id": "org_123",
                "org_name": "Verdictan",
                "project_id": "proj_123",
                "role": "owner",
                "auth_method": "api_token",
                "team_ids": ["team_1"],
                "capabilities": ["gateway:write"],
                "resolved_roles": [{
                    "role_id": "role_owner",
                    "role_name": "owner",
                    "role_display_name": "Org Owner",
                    "assignment_level": "org",
                    "assignment_target_id": "org_123",
                    "binding_kind": "direct"
                }],
                "token_scope": {
                    "principal_type": "service_account",
                    "team_id": null,
                    "subject_user_id": null
                }
            })),
        )
    }

    async fn unauthorized_handler() -> impl IntoResponse {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized"})),
        )
    }

    async fn spawn_token_server() -> (String, TokenServerState, tokio::task::JoinHandle<()>) {
        let state = TokenServerState::default();
        let app = Router::new()
            .route(
                "/v1/tokens",
                post(create_token_handler).get(list_tokens_handler),
            )
            .route("/v1/tokens/:token_id", delete(revoke_token_handler))
            .route("/v1/whoami", get(whoami_handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind token listener");
        let addr = listener.local_addr().expect("token addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("token server");
        });
        (format!("http://{addr}"), state, handle)
    }

    async fn spawn_unauthorized_server() -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new().route("/v1/tokens", post(unauthorized_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind unauthorized listener");
        let addr = listener.local_addr().expect("unauthorized addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("unauthorized token server");
        });
        (format!("http://{addr}"), handle)
    }

    #[test]
    fn join_url_basic() {
        assert_eq!(
            join_url("https://api.example.com", "/v1/users"),
            "https://api.example.com/v1/users"
        );
    }

    #[test]
    fn join_url_trims_trailing_slash() {
        assert_eq!(
            join_url("https://api.example.com/", "/v1/users"),
            "https://api.example.com/v1/users"
        );
    }

    #[test]
    fn join_url_trims_leading_slash() {
        assert_eq!(
            join_url("https://api.example.com", "v1/users"),
            "https://api.example.com/v1/users"
        );
    }

    #[test]
    fn join_url_both_slashes() {
        assert_eq!(
            join_url("https://api.example.com/", "/v1/users"),
            "https://api.example.com/v1/users"
        );
    }

    #[test]
    fn join_url_no_slashes() {
        assert_eq!(
            join_url("https://api.example.com", "v1/users"),
            "https://api.example.com/v1/users"
        );
    }

    #[test]
    fn map_http_status_401() {
        let err = map_http_status(reqwest::StatusCode::UNAUTHORIZED);
        assert!(err.to_string().len() > 0);
        assert_eq!(err.http_status(), Some(401));
    }

    #[test]
    fn map_http_status_403() {
        let err = map_http_status(reqwest::StatusCode::FORBIDDEN);
        assert!(err.to_string().len() > 0);
        assert_eq!(err.http_status(), Some(403));
    }

    #[test]
    fn map_http_status_404() {
        let err = map_http_status(reqwest::StatusCode::NOT_FOUND);
        assert!(err.to_string().len() > 0);
        assert_eq!(err.http_status(), Some(404));
    }

    #[test]
    fn map_http_status_422() {
        let err = map_http_status(reqwest::StatusCode::UNPROCESSABLE_ENTITY);
        assert!(err.to_string().len() > 0);
        assert_eq!(err.http_status(), Some(422));
    }

    #[test]
    fn map_http_status_500() {
        let err = map_http_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(err.to_string().len() > 0);
        assert_eq!(err.http_status(), Some(500));
    }

    #[tokio::test]
    async fn token_api_helpers_round_trip_against_local_server() {
        let (base_url, state, handle) = spawn_token_server().await;

        let created = create_token_async(
            &base_url,
            "token_123",
            &CreateTokenRequest {
                name: "Build Token".to_string(),
                principal_type: "service_account".to_string(),
                team_id: None,
                subject_user_id: None,
                expires_at: None,
                role_ids: vec!["role_owner".to_string()],
            },
        )
        .await
        .expect("create token");
        assert_eq!(created.token.token_id, "tok_123");
        assert_eq!(created.token_value, "live-secret-token");

        let listed = list_tokens_async(&base_url, "token_123")
            .await
            .expect("list tokens");
        assert_eq!(listed.tokens.len(), 1);
        assert_eq!(listed.tokens[0].name, "Build Token");

        let revoked = revoke_token_async(&base_url, "token_123", "tok_123")
            .await
            .expect("revoke token");
        assert!(revoked.revoked);

        let whoami = whoami_async(&base_url, "token_123").await.expect("whoami");
        assert_eq!(whoami.org_id, "org_123");
        assert_eq!(whoami.team_ids, vec!["team_1"]);
        assert_eq!(whoami.capabilities, vec!["gateway:write"]);
        assert_eq!(
            whoami.token_scope.expect("token scope").principal_type,
            "service_account"
        );

        let seen = state.seen_auth_headers.lock().expect("auth header lock");
        assert_eq!(
            seen.as_slice(),
            &[
                "Bearer token_123",
                "Bearer token_123",
                "Bearer token_123",
                "Bearer token_123"
            ]
        );

        handle.abort();
    }

    #[tokio::test]
    async fn token_api_helpers_map_unauthorized_statuses() {
        let (base_url, handle) = spawn_unauthorized_server().await;
        let error = create_token_async(
            &base_url,
            "token_123",
            &CreateTokenRequest {
                name: "Build Token".to_string(),
                principal_type: "service_account".to_string(),
                team_id: None,
                subject_user_id: None,
                expires_at: None,
                role_ids: vec!["role_owner".to_string()],
            },
        )
        .await
        .expect_err("unauthorized create should fail");
        assert_eq!(error.error_code(), "cli.auth_failed");

        handle.abort();
    }
}
