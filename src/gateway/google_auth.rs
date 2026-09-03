// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Google credential resolver for Vertex AI and other Google Cloud APIs.
//!
//! Resolves an OAuth2 bearer token using the following priority order:
//!
//!   1. Explicit OAuth2 config from the provider target (handled by the caller
//!      in `provider_auth::build_vertex_auth` before this resolver is invoked).
//!   2. Explicit bearer token set via `api_key` on the provider target.
//!   3. `GOOGLE_VERTEX_ACCESS_TOKEN` environment variable.
//!   4. Application Default Credentials (ADC) — GCE instance metadata server.
//!   5. Service account JSON from the `GOOGLE_APPLICATION_CREDENTIALS` env var.
//!
//! The ADC metadata base URL can be overridden via `GCE_METADATA_ROOT` for
//! local testing and CI (e.g. point it at a mock server).
//!
//! Security note: this resolver MUST NOT shell out to `gcloud` or any other
//! external binary. All credential resolution is performed via HTTP or file I/O.

use anyhow::Context;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

/// Resolves a Google OAuth2 access token for provider targets with no explicit
/// OAuth2 configuration. Handles env-var, ADC, and service-account flows.
#[derive(Clone)]
pub(crate) struct GoogleAuthResolver {
    /// Resolved API key (bearer token) from the provider target `api_key` field.
    api_key: String,
    /// Provider target ID — used in error messages.
    target_id: String,
}

impl GoogleAuthResolver {
    pub(crate) fn new(api_key: String, target_id: String) -> Self {
        Self { api_key, target_id }
    }

    /// Resolve a Google OAuth2 access token.
    pub(crate) async fn resolve_token(&self) -> anyhow::Result<String> {
        // Priority 2: explicit bearer token from the provider target.
        if !self.api_key.is_empty() {
            return Ok(self.api_key.clone());
        }

        // Priority 3: GOOGLE_VERTEX_ACCESS_TOKEN env var.
        if let Ok(token) = std::env::var("GOOGLE_VERTEX_ACCESS_TOKEN") {
            let trimmed = token.trim().to_string();
            if !trimmed.is_empty() {
                return Ok(trimmed);
            }
        }

        // Priority 4: ADC instance metadata server.
        match self.try_adc_metadata().await {
            Ok(token) => Ok(token),
            Err(adc_error) => {
                // Priority 5: service account JSON from GOOGLE_APPLICATION_CREDENTIALS.
                match self.try_service_account().await {
                    Ok(token) => Ok(token),
                    Err(service_account_error)
                        if std::env::var_os("GOOGLE_APPLICATION_CREDENTIALS").is_some() =>
                    {
                        Err(service_account_error)
                    }
                    Err(service_account_error) => Err(anyhow::anyhow!(
                        "provider '{}': google-vertex requires credentials. \
                     Set api_key, GOOGLE_VERTEX_ACCESS_TOKEN, GOOGLE_APPLICATION_CREDENTIALS, \
                     or configure oauth2 on the provider target. \
                     For GCE instances, ensure the instance metadata server is reachable. \
                     ADC metadata attempt failed: {adc_error}. \
                     Service account attempt failed: {service_account_error}.",
                        self.target_id
                    )),
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // ADC — GCE instance metadata server
    // -----------------------------------------------------------------------

    async fn try_adc_metadata(&self) -> anyhow::Result<String> {
        let url = adc_token_url();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .context("failed to build ADC HTTP client")?;

        let response = client
            .get(&url)
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .with_context(|| format!("ADC metadata request to {url} failed"))?;

        if !response.status().is_success() {
            anyhow::bail!(
                "ADC metadata server at {url} returned {}",
                response.status()
            );
        }

        let token: AdcTokenResponse = response
            .json()
            .await
            .context("failed to parse ADC metadata server token response")?;
        Ok(token.access_token)
    }

    // -----------------------------------------------------------------------
    // Service account JSON
    // -----------------------------------------------------------------------

    async fn try_service_account(&self) -> anyhow::Result<String> {
        let cred_path = std::env::var("GOOGLE_APPLICATION_CREDENTIALS")
            .context("GOOGLE_APPLICATION_CREDENTIALS not set")?;

        let json_content = std::fs::read_to_string(&cred_path)
            .with_context(|| format!("failed to read service account file: {cred_path}"))?;

        self.exchange_service_account_token(&json_content).await
    }

    /// Parse a service account JSON credential and exchange it for an access token.
    ///
    /// The flow follows RFC 7523 (JWT Bearer Token Profile):
    /// 1. Construct a self-signed JWT with the service account's RSA private key.
    /// 2. POST the assertion to the Google OAuth2 token endpoint.
    /// 3. Return the resulting access token.
    pub(crate) async fn exchange_service_account_token(
        &self,
        json_content: &str,
    ) -> anyhow::Result<String> {
        let creds: ServiceAccountCredentials =
            serde_json::from_str(json_content).context("invalid service account JSON")?;

        let token_uri = creds
            .token_uri
            .as_deref()
            .unwrap_or("https://oauth2.googleapis.com/token")
            .to_string();

        let jwt = build_service_account_jwt(&creds, &token_uri)
            .context("failed to build service account JWT")?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("failed to build service account token HTTP client")?;

        let response = client
            .post(&token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await
            .with_context(|| {
                format!("service account token exchange request to {token_uri} failed")
            })?;

        let payload: serde_json::Value = response
            .json()
            .await
            .context("invalid service account token response")?;

        payload["access_token"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "service account token response from {token_uri} did not include access_token; \
                     response: {}",
                    payload
                )
            })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the ADC instance metadata token URL, honouring the `GCE_METADATA_ROOT`
/// override used by the Google Cloud client libraries and test harnesses.
fn adc_token_url() -> String {
    let root = std::env::var("GCE_METADATA_ROOT")
        .unwrap_or_else(|_| "http://metadata.google.internal".to_string());
    format!("{root}/computeMetadata/v1/instance/service-accounts/default/token")
}

/// Build a signed RS256 JWT for the service account credential exchange.
fn build_service_account_jwt(
    creds: &ServiceAccountCredentials,
    token_uri: &str,
) -> anyhow::Result<String> {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    let now = chrono::Utc::now().timestamp();
    let claims = ServiceAccountClaims {
        iss: creds.client_email.clone(),
        scope: "https://www.googleapis.com/auth/cloud-platform".to_string(),
        aud: token_uri.to_string(),
        exp: now + 3600,
        iat: now,
    };

    let encoding_key = EncodingKey::from_rsa_pem(creds.private_key.as_bytes())
        .context("failed to parse RSA private key from service account JSON")?;

    let header = Header::new(Algorithm::RS256);
    encode(&header, &claims, &encoding_key).context("failed to sign service account JWT")
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AdcTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
pub(crate) struct ServiceAccountCredentials {
    pub client_email: String,
    pub private_key: String,
    #[serde(rename = "private_key_id")]
    pub _private_key_id: Option<String>,
    pub token_uri: Option<String>,
}

#[derive(Serialize)]
struct ServiceAccountClaims {
    iss: String,
    scope: String,
    aud: String,
    exp: i64,
    iat: i64,
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

    #[test]
    fn adc_token_url_default() {
        let _guard = crate::test_support::env_lock().lock().unwrap();
        std::env::remove_var("GCE_METADATA_ROOT");
        let url = adc_token_url();
        assert!(url.starts_with("http://metadata.google.internal"));
        assert!(url.contains("/computeMetadata/v1/instance/service-accounts/default/token"));
    }

    #[test]
    fn adc_token_url_override() {
        let _guard = crate::test_support::env_lock().lock().unwrap();
        std::env::set_var("GCE_METADATA_ROOT", "http://localhost:9090");
        let url = adc_token_url();
        assert!(url.starts_with("http://localhost:9090"));
        std::env::remove_var("GCE_METADATA_ROOT");
    }

    #[test]
    fn resolver_new() {
        let resolver = GoogleAuthResolver::new("sk-test".to_string(), "prov-1".to_string());
        assert_eq!(resolver.api_key, "sk-test");
        assert_eq!(resolver.target_id, "prov-1");
    }

    #[test]
    fn service_account_credentials_parse() {
        let json = r#"{
            "client_email": "test@project.iam.gserviceaccount.com",
            "private_key": "not-a-real-private-key",
            "private_key_id": "key-1",
            "token_uri": "https://oauth2.googleapis.com/token"
        }"#;
        let creds: ServiceAccountCredentials = serde_json::from_str(json).unwrap();
        assert_eq!(creds.client_email, "test@project.iam.gserviceaccount.com");
        assert_eq!(
            creds.token_uri.as_deref(),
            Some("https://oauth2.googleapis.com/token")
        );
    }

    #[test]
    fn service_account_credentials_minimal() {
        let json = r#"{
            "client_email": "test@gcp.com",
            "private_key": "fake-key"
        }"#;
        let creds: ServiceAccountCredentials = serde_json::from_str(json).unwrap();
        assert!(creds.token_uri.is_none());
        assert!(creds._private_key_id.is_none());
    }

    #[tokio::test]
    async fn resolve_token_returns_api_key_when_present() {
        let resolver = GoogleAuthResolver::new("my-token".to_string(), "target-1".to_string());
        let token = resolver.resolve_token().await.unwrap();
        assert_eq!(token, "my-token");
    }

    #[test]
    fn service_account_claims_serializes() {
        let claims = ServiceAccountClaims {
            iss: "test@gcp.com".to_string(),
            scope: "https://www.googleapis.com/auth/cloud-platform".to_string(),
            aud: "https://oauth2.googleapis.com/token".to_string(),
            exp: 1700003600,
            iat: 1700000000,
        };
        let json = serde_json::to_value(&claims).unwrap();
        assert_eq!(json["iss"], "test@gcp.com");
        assert_eq!(json["exp"], 1700003600);
    }

    #[tokio::test]
    async fn resolve_token_empty_api_key_tries_env() {
        let _guard = crate::test_support::env_lock().lock().unwrap();
        std::env::set_var("GOOGLE_VERTEX_ACCESS_TOKEN", "env-token-123");
        std::env::remove_var("GCE_METADATA_ROOT");
        std::env::remove_var("GOOGLE_APPLICATION_CREDENTIALS");

        let resolver = GoogleAuthResolver::new(String::new(), "target-1".to_string());
        let token = resolver.resolve_token().await.unwrap();
        assert_eq!(token, "env-token-123");

        std::env::remove_var("GOOGLE_VERTEX_ACCESS_TOKEN");
    }

    #[tokio::test]
    async fn resolve_token_empty_env_skipped() {
        let _guard = crate::test_support::env_lock().lock().unwrap();
        std::env::set_var("GOOGLE_VERTEX_ACCESS_TOKEN", "   ");
        std::env::remove_var("GCE_METADATA_ROOT");
        std::env::remove_var("GOOGLE_APPLICATION_CREDENTIALS");

        let resolver = GoogleAuthResolver::new(String::new(), "target-1".to_string());
        let result = resolver.resolve_token().await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("requires credentials"));

        std::env::remove_var("GOOGLE_VERTEX_ACCESS_TOKEN");
    }

    #[tokio::test]
    async fn exchange_service_account_token_invalid_json() {
        let resolver = GoogleAuthResolver::new(String::new(), "t".to_string());
        let result = resolver.exchange_service_account_token("not json").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid service account JSON"));
    }

    #[tokio::test]
    async fn exchange_service_account_token_invalid_key() {
        let resolver = GoogleAuthResolver::new(String::new(), "t".to_string());
        let json = r#"{
            "client_email": "test@gcp.com",
            "private_key": "not-a-real-key"
        }"#;
        let result = resolver.exchange_service_account_token(json).await;
        assert!(result.is_err());
        let err_chain = format!("{:#}", result.unwrap_err());
        assert!(
            err_chain.contains("RSA private key") || err_chain.contains("service account JWT"),
            "unexpected error: {err_chain}"
        );
    }

    #[tokio::test]
    async fn try_adc_metadata_with_mock_server() {
        let _guard = crate::test_support::env_lock().lock().unwrap();

        let app = axum::Router::new().route(
            "/computeMetadata/v1/instance/service-accounts/default/token",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({"access_token": "adc-mock-token"}))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        std::env::set_var("GCE_METADATA_ROOT", format!("http://{addr}"));
        std::env::remove_var("GOOGLE_VERTEX_ACCESS_TOKEN");
        std::env::remove_var("GOOGLE_APPLICATION_CREDENTIALS");

        let resolver = GoogleAuthResolver::new(String::new(), "target-1".to_string());
        let token = resolver.resolve_token().await.unwrap();
        assert_eq!(token, "adc-mock-token");

        std::env::remove_var("GCE_METADATA_ROOT");
    }

    #[tokio::test]
    async fn try_adc_metadata_non_success_status() {
        let _guard = crate::test_support::env_lock().lock().unwrap();

        let app = axum::Router::new().route(
            "/computeMetadata/v1/instance/service-accounts/default/token",
            axum::routing::get(|| async { axum::http::StatusCode::FORBIDDEN }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        std::env::set_var("GCE_METADATA_ROOT", format!("http://{addr}"));
        std::env::remove_var("GOOGLE_VERTEX_ACCESS_TOKEN");
        std::env::remove_var("GOOGLE_APPLICATION_CREDENTIALS");

        let resolver = GoogleAuthResolver::new(String::new(), "target-1".to_string());
        let result = resolver.resolve_token().await;
        assert!(result.is_err());

        std::env::remove_var("GCE_METADATA_ROOT");
    }

    #[test]
    fn adc_token_url_various_roots() {
        let _guard = crate::test_support::env_lock().lock().unwrap();

        std::env::set_var("GCE_METADATA_ROOT", "http://custom:8080");
        let url = adc_token_url();
        assert!(url.starts_with("http://custom:8080"));

        std::env::remove_var("GCE_METADATA_ROOT");
    }

    #[test]
    fn resolver_clone() {
        let r = GoogleAuthResolver::new("key".into(), "t".into());
        let cloned = r.clone();
        assert_eq!(cloned.api_key, "key");
        assert_eq!(cloned.target_id, "t");
    }

    #[test]
    fn adc_token_response_deserialization() {
        let json = serde_json::json!({"access_token": "test-token"});
        let resp: AdcTokenResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.access_token, "test-token");
    }
}
