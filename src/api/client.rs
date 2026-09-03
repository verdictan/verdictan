// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

#![allow(clippy::items_after_test_module)]

use std::sync::OnceLock;
use std::time::Duration;

use crate::i18n;
use crate::CliError;

const CLIENT_SURFACE: &str = "cli";

static SHARED_API_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HttpTimeouts {
    pub(crate) connect: Duration,
    pub(crate) request: Duration,
    pub(crate) overall: Duration,
}

impl HttpTimeouts {
    pub(crate) fn from_millis(connect: u64, request: u64, overall: u64) -> Self {
        Self {
            connect: Duration::from_millis(connect),
            request: Duration::from_millis(request),
            overall: Duration::from_millis(overall),
        }
    }
}

fn configured_http_timeouts() -> HttpTimeouts {
    let defaults = HttpTimeouts::from_millis(10_000, 30_000, 30_000);
    #[cfg(verdictan_cli_e2e)]
    return HttpTimeouts {
        connect: test_duration_from_env("VERDICTAN_TEST_CONNECT_TIMEOUT_MS")
            .unwrap_or(defaults.connect),
        request: test_duration_from_env("VERDICTAN_TEST_REQUEST_TIMEOUT_MS")
            .unwrap_or(defaults.request),
        overall: test_duration_from_env("VERDICTAN_TEST_HTTP_TIMEOUT_MS")
            .unwrap_or(defaults.overall),
    };
    #[cfg(not(verdictan_cli_e2e))]
    defaults
}

#[allow(clippy::expect_used)] // static singleton; reqwest builder with fixed config cannot fail
fn shared_api_http_client() -> &'static reqwest::Client {
    SHARED_API_CLIENT.get_or_init(|| {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::HeaderName::from_static("x-client-surface"),
            reqwest::header::HeaderValue::from_static(CLIENT_SURFACE),
        );

        let timeouts = configured_http_timeouts();
        reqwest::Client::builder()
            .default_headers(headers)
            .timeout(timeouts.overall)
            .connect_timeout(timeouts.connect)
            .read_timeout(timeouts.request)
            .user_agent(concat!("verdictan-cli/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("shared API HTTP client must build")
    })
}

#[cfg(verdictan_cli_e2e)]
fn test_duration_from_env(name: &str) -> Option<Duration> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_millis)
}

pub struct AsyncApiClient {
    base_url: String,
    auth_header: reqwest::header::HeaderValue,
    region: Option<String>,
}

impl AsyncApiClient {
    pub fn new(base_url: impl Into<String>, api_token: impl AsRef<str>) -> Result<Self, CliError> {
        let locale = i18n::global();
        let base_url = base_url.into();
        if base_url.trim().is_empty() {
            return Err(CliError::user(i18n::t(locale, "user.api_base_url_empty")));
        }

        let value = format!("Bearer {}", api_token.as_ref());
        let auth_header = reqwest::header::HeaderValue::from_str(&value).map_err(|_| {
            CliError::user(i18n::t(locale, "user.api_token_invalid_header_characters"))
        })?;

        Ok(Self {
            base_url,
            auth_header,
            region: None,
        })
    }

    /// Set the region for all subsequent API calls. When set, the client sends
    /// the `X-Verdictan-Region` header with every request.
    pub fn with_region(mut self, region: Option<String>) -> Self {
        self.region = region;
        self
    }

    /// Return the currently configured region, if any.
    pub fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }

    fn authed_request(&self, method: reqwest::Method, url: String) -> reqwest::RequestBuilder {
        let mut builder = shared_api_http_client()
            .request(method, url)
            .header(reqwest::header::AUTHORIZATION, self.auth_header.clone());
        if let Some(ref region) = self.region {
            builder = builder.header("x-verdictan-region", region.as_str());
        }
        builder
    }

    async fn send_idempotent_get(&self, url: &str) -> Result<reqwest::Response, CliError> {
        let policy = crate::retry::RetryPolicy::default();
        #[cfg(verdictan_cli_e2e)]
        let policy = {
            let mut policy = policy;
            if let Ok(value) = std::env::var("VERDICTAN_TEST_MAX_RETRIES") {
                policy.max_retries = value.parse::<u32>().map_err(|error| {
                    CliError::internal(format!("invalid injected retry count: {error}"))
                })?;
            }
            policy
        };

        let mut retry = 0u32;
        loop {
            let response = self
                .authed_request(reqwest::Method::GET, url.to_owned())
                .send()
                .await;
            match response {
                Ok(response) if response.status().is_success() => return Ok(response),
                Ok(response) => {
                    let status = response.status();
                    if crate::retry::classify_status(status.as_u16())
                        == crate::retry::RetryClassification::Permanent
                        || retry >= policy.max_retries
                    {
                        return Err(map_http_status(status));
                    }
                    retry += 1;
                    let delay = retry_delay_for_response(&policy, retry, response.headers());
                    sleep_before_retry(delay).await;
                }
                Err(error) => {
                    let error = map_reqwest_error(error);
                    if retry >= policy.max_retries {
                        return Err(error);
                    }
                    retry += 1;
                    let delay = crate::retry::compute_delay(&policy, retry);
                    sleep_before_retry(delay).await;
                }
            }
        }
    }

    pub async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, CliError> {
        let url = self.join_url(path);
        let response = self.send_idempotent_get(&url).await?;

        response.json::<T>().await.map_err(map_reqwest_error)
    }

    pub async fn get_json_value(&self, path: &str) -> Result<serde_json::Value, CliError> {
        let url = self.join_url(path);
        let response = self.send_idempotent_get(&url).await?;

        response
            .json::<serde_json::Value>()
            .await
            .map_err(map_reqwest_error)
    }

    pub(crate) async fn get_json_value_once(
        &self,
        path: &str,
    ) -> Result<serde_json::Value, CliError> {
        let url = self.join_url(path);
        let response = self
            .authed_request(reqwest::Method::GET, url)
            .send()
            .await
            .map_err(map_reqwest_error)?;
        let status = response.status();
        if !status.is_success() {
            return Err(map_http_status(status));
        }
        response
            .json::<serde_json::Value>()
            .await
            .map_err(map_reqwest_error)
    }

    pub async fn post_json_value(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, CliError> {
        let url = self.join_url(path);
        let response = self
            .authed_request(reqwest::Method::POST, url)
            .json(body)
            .send()
            .await
            .map_err(map_reqwest_error)?;

        let status = response.status();
        if !status.is_success() {
            return Err(map_http_status(status));
        }

        response
            .json::<serde_json::Value>()
            .await
            .map_err(map_reqwest_error)
    }

    pub async fn post_multipart_json_value(
        &self,
        path: &str,
        form: reqwest::multipart::Form,
    ) -> Result<serde_json::Value, CliError> {
        let url = self.join_url(path);
        let response = self
            .authed_request(reqwest::Method::POST, url)
            .multipart(form)
            .send()
            .await
            .map_err(map_reqwest_error)?;

        let status = response.status();
        if !status.is_success() {
            return Err(map_http_status(status));
        }

        response
            .json::<serde_json::Value>()
            .await
            .map_err(map_reqwest_error)
    }

    pub async fn put_json_value(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, CliError> {
        let url = self.join_url(path);
        let response = self
            .authed_request(reqwest::Method::PUT, url)
            .json(body)
            .send()
            .await
            .map_err(map_reqwest_error)?;

        let status = response.status();
        if !status.is_success() {
            return Err(map_http_status(status));
        }

        response
            .json::<serde_json::Value>()
            .await
            .map_err(map_reqwest_error)
    }

    pub async fn patch_json_value(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, CliError> {
        let url = self.join_url(path);
        let response = self
            .authed_request(reqwest::Method::PATCH, url)
            .json(body)
            .send()
            .await
            .map_err(map_reqwest_error)?;

        let status = response.status();
        if !status.is_success() {
            return Err(map_http_status(status));
        }

        response
            .json::<serde_json::Value>()
            .await
            .map_err(map_reqwest_error)
    }

    pub async fn post_bytes_json_value(
        &self,
        path: &str,
        bytes: Vec<u8>,
        content_type: &str,
    ) -> Result<serde_json::Value, CliError> {
        let url = self.join_url(path);
        let response = self
            .authed_request(reqwest::Method::POST, url)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(bytes)
            .send()
            .await
            .map_err(map_reqwest_error)?;

        let status = response.status();
        if !status.is_success() {
            return Err(map_http_status(status));
        }

        response
            .json::<serde_json::Value>()
            .await
            .map_err(map_reqwest_error)
    }

    pub async fn delete_json_value(&self, path: &str) -> Result<serde_json::Value, CliError> {
        let url = self.join_url(path);
        let response = self
            .authed_request(reqwest::Method::DELETE, url)
            .send()
            .await
            .map_err(map_reqwest_error)?;

        let status = response.status();
        if !status.is_success() {
            return Err(map_http_status(status));
        }

        let bytes = response.bytes().await.map_err(map_reqwest_error)?;
        if bytes.is_empty() {
            return Ok(serde_json::json!({"deleted": true}));
        }
        serde_json::from_slice::<serde_json::Value>(&bytes)
            .map_err(|e| CliError::internal(format!("failed to decode delete response: {e}")))
    }

    pub async fn get_bytes(&self, path: &str) -> Result<(reqwest::StatusCode, Vec<u8>), CliError> {
        let url = self.join_url(path);
        let response = self
            .authed_request(reqwest::Method::GET, url)
            .send()
            .await
            .map_err(map_reqwest_error)?;

        let status = response.status();
        let bytes = response.bytes().await.map_err(map_reqwest_error)?.to_vec();
        Ok((status, bytes))
    }

    /// Return the shared reqwest client and the auth header for fire-and-forget
    /// scenarios (e.g. audit event emission inside `tokio::spawn`).
    pub fn http_client_with_auth(&self) -> (reqwest::Client, reqwest::header::HeaderValue) {
        (shared_api_http_client().clone(), self.auth_header.clone())
    }

    #[doc(hidden)]
    pub fn join_url(&self, path: &str) -> String {
        let base = self.base_url.trim_end_matches('/');
        let path = path.trim_start_matches('/');
        format!("{base}/{path}")
    }
}

pub(crate) fn retry_delay_for_response(
    policy: &crate::retry::RetryPolicy,
    attempt: u32,
    headers: &reqwest::header::HeaderMap,
) -> Duration {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| crate::retry::compute_delay(policy, attempt))
}

async fn sleep_before_retry(delay: Duration) {
    #[cfg(verdictan_cli_e2e)]
    if std::env::var_os("VERDICTAN_TEST_SKIP_RETRY_SLEEP").is_some() {
        return;
    }
    tokio::time::sleep(delay).await;
}

#[doc(hidden)]
pub fn map_http_status(status: reqwest::StatusCode) -> CliError {
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

    if status == reqwest::StatusCode::CONFLICT {
        return CliError::user(i18n::t(locale, "user.api_conflict_409")).with_http_status(code);
    }

    CliError::network(i18n::t_fmt(
        locale,
        "network.api_request_failed_status",
        &[&code.to_string()],
    ))
    .with_http_status(code)
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

    // ── AsyncApiClient::new ─────────────────────────────────────────────

    #[test]
    fn new_with_valid_inputs() {
        let client = AsyncApiClient::new("https://api.example.com", "tok_abc123");
        assert!(client.is_ok());
    }

    #[test]
    fn new_with_trailing_slash_in_url() {
        let client = AsyncApiClient::new("https://api.example.com/", "tok_abc123");
        assert!(client.is_ok());
    }

    #[test]
    fn new_with_empty_url_returns_error() {
        let result = AsyncApiClient::new("", "tok_abc");
        assert!(result.is_err());
    }

    #[test]
    fn new_with_whitespace_url_returns_error() {
        let result = AsyncApiClient::new("   ", "tok_abc");
        assert!(result.is_err());
    }

    #[test]
    fn new_with_invalid_header_token_returns_error() {
        let result = AsyncApiClient::new("https://api.example.com", "tok\r\ninjection");
        assert!(result.is_err());
    }

    // ── join_url ──────────────────────────────────────────────────────

    #[test]
    fn join_url_simple_path() {
        let client = AsyncApiClient::new("https://api.example.com", "tok").unwrap();
        assert_eq!(
            client.join_url("/v1/events"),
            "https://api.example.com/v1/events"
        );
    }

    #[test]
    fn join_url_strips_double_slash() {
        let client = AsyncApiClient::new("https://api.example.com/", "tok").unwrap();
        assert_eq!(
            client.join_url("/v1/events"),
            "https://api.example.com/v1/events"
        );
    }

    #[test]
    fn join_url_no_leading_slash_on_path() {
        let client = AsyncApiClient::new("https://api.example.com", "tok").unwrap();
        assert_eq!(
            client.join_url("v1/events"),
            "https://api.example.com/v1/events"
        );
    }

    #[test]
    fn join_url_both_trailing_and_leading_slash() {
        let client = AsyncApiClient::new("https://api.example.com/", "tok").unwrap();
        assert_eq!(
            client.join_url("/v1/events"),
            "https://api.example.com/v1/events"
        );
    }

    #[test]
    fn join_url_with_query_string() {
        let client = AsyncApiClient::new("https://api.example.com", "tok").unwrap();
        assert_eq!(
            client.join_url("/v1/events?limit=10"),
            "https://api.example.com/v1/events?limit=10"
        );
    }

    #[test]
    fn join_url_empty_path() {
        let client = AsyncApiClient::new("https://api.example.com", "tok").unwrap();
        assert_eq!(client.join_url(""), "https://api.example.com/");
    }

    // ── with_region / region ──────────────────────────────────────────

    #[test]
    fn default_region_is_none() {
        let client = AsyncApiClient::new("https://api.example.com", "tok").unwrap();
        assert!(client.region().is_none());
    }

    #[test]
    fn with_region_sets_region() {
        let client = AsyncApiClient::new("https://api.example.com", "tok")
            .unwrap()
            .with_region(Some("eu-west-1".to_string()));
        assert_eq!(client.region(), Some("eu-west-1"));
    }

    #[test]
    fn with_region_none_clears_region() {
        let client = AsyncApiClient::new("https://api.example.com", "tok")
            .unwrap()
            .with_region(Some("us-east-1".to_string()))
            .with_region(None);
        assert!(client.region().is_none());
    }

    // ── http_client_with_auth ──────────────────────────────────────────

    #[test]
    fn http_client_with_auth_returns_cloned_client() {
        let client = AsyncApiClient::new("https://api.example.com", "tok_test").unwrap();
        let (http, auth) = client.http_client_with_auth();
        let _ = http;
        assert!(auth.to_str().unwrap().starts_with("Bearer "));
    }

    // ── map_http_status ────────────────────────────────────────────────

    #[test]
    fn map_http_status_401_is_auth_error() {
        let err = map_http_status(reqwest::StatusCode::UNAUTHORIZED);
        assert!(err.is_auth());
        assert_eq!(err.http_status, Some(401));
    }

    #[test]
    fn map_http_status_403_is_auth_error() {
        let err = map_http_status(reqwest::StatusCode::FORBIDDEN);
        assert!(err.is_auth());
        assert_eq!(err.http_status, Some(403));
    }

    #[test]
    fn map_http_status_422_is_user_error() {
        let err = map_http_status(reqwest::StatusCode::UNPROCESSABLE_ENTITY);
        assert!(!err.is_auth());
        assert_eq!(err.http_status, Some(422));
        assert_eq!(err.exit_code(), crate::error::EXIT_USER);
    }

    #[test]
    fn map_http_status_409_is_user_error() {
        let err = map_http_status(reqwest::StatusCode::CONFLICT);
        assert_eq!(err.exit_code(), crate::error::EXIT_USER);
        assert_eq!(err.http_status, Some(409));
    }

    #[test]
    fn map_http_status_500_is_network_error() {
        let err = map_http_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.exit_code(), crate::error::EXIT_NETWORK);
        assert_eq!(err.http_status, Some(500));
    }

    #[test]
    fn map_http_status_502_is_network_error() {
        let err = map_http_status(reqwest::StatusCode::BAD_GATEWAY);
        assert_eq!(err.exit_code(), crate::error::EXIT_NETWORK);
        assert_eq!(err.http_status, Some(502));
    }
}

fn map_reqwest_error(err: reqwest::Error) -> CliError {
    let locale = i18n::global();
    if err.is_timeout() {
        return CliError::network(i18n::t(locale, "network.request_timed_out"));
    }

    if err.is_connect() {
        return CliError::network(i18n::t(locale, "network.failed_to_connect_api"));
    }

    CliError::network(i18n::t_fmt(
        locale,
        "network.http_error",
        &[&err.to_string()],
    ))
}
