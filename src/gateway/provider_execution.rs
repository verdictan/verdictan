// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Upstream provider execution with customer-owned credentials.
//!
//! This module owns the credential value that the gateway sends upstream, the
//! normalized request that a provider adapter translates, the request options
//! that the adapter applies, the token usage that the response reports, and the
//! upstream call itself. The gateway resolves the credential from a customer
//! source before it calls into this module.

use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use std::time::Duration;

const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

static UPSTREAM_CLIENT: LazyLock<Result<reqwest::Client, String>> = LazyLock::new(|| {
    reqwest::Client::builder()
        .connect_timeout(UPSTREAM_CONNECT_TIMEOUT)
        .pool_idle_timeout(Duration::from_secs(90))
        .user_agent(concat!("verdictan-gateway/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| error.to_string())
});

/// Errors that stop the gateway from completing an upstream provider call.
#[derive(Debug, thiserror::Error)]
pub enum ProviderExecutionError {
    #[error("Rate limit exceeded")]
    RateLimitExceeded { retry_after_ms: u64 },
    #[error("Upstream request failed: {0}")]
    Upstream(String),
}

/// The provider credential that the gateway sends upstream for one request.
///
/// The organization owns this value. The gateway resolves it from an
/// organization secret store reference, a local environment source, or a
/// supported workload identity.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderCredential {
    /// Identifier of the resolved credential record.
    pub credential_id: String,
    /// Provider identifier.
    pub provider: String,
    /// Provider API key (held in memory only, never logged).
    pub api_key: String,
    /// Region the credential covers.
    pub region: Option<String>,
    /// Whether this credential is ZDR-eligible.
    pub zdr_eligible: bool,
}

/// Token usage extracted from a provider response.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub cached_input_tokens: Option<u64>,
}

impl TokenUsage {
    pub fn is_empty(&self) -> bool {
        self.total_tokens == 0 && self.input_tokens == 0 && self.output_tokens == 0
    }
}

/// A normalized gateway request before provider translation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRequest {
    /// Target model ID (e.g., "gpt-5.5", "claude-opus-4-8").
    pub model: String,
    /// Target provider (resolved from model or explicit header).
    pub provider: String,
    /// The raw request body (provider-native format).
    pub body: serde_json::Value,
    /// Whether streaming is requested.
    pub stream: bool,
    /// Whether to force store=false (ZDR override).
    pub force_no_store: bool,
    /// Org ID for the requesting tenant.
    pub org_id: String,
    /// User ID (for spend attribution).
    pub user_id: Option<String>,
}

/// Options passed to the provider adapter.
#[derive(Debug, Clone)]
pub struct RequestOptions {
    /// Whether to override store=false (ZDR).
    pub zdr_override: bool,
    /// Request timeout.
    pub timeout: Duration,
}

impl Default for RequestOptions {
    fn default() -> Self {
        Self {
            zdr_override: false,
            timeout: Duration::from_secs(300),
        }
    }
}

/// Response from an upstream provider call.
#[derive(Debug, Clone)]
pub struct ProviderResponse {
    pub status: u16,
    pub body: serde_json::Value,
    pub usage: Option<TokenUsage>,
}

fn upstream_client() -> Result<reqwest::Client, ProviderExecutionError> {
    UPSTREAM_CLIENT
        .as_ref()
        .cloned()
        .map_err(|error| ProviderExecutionError::Upstream(error.clone()))
}

/// Execute an upstream provider call with a customer-owned credential.
async fn execute_upstream_provider_request(
    request: &ProviderRequest,
    credential: &ProviderCredential,
    options: &RequestOptions,
    adapter: &dyn super::provider_adapters::ProviderAdapter,
    format: super::provider_adapters::ApiFormat,
) -> Result<ProviderResponse, ProviderExecutionError> {
    let upstream_req = adapter
        .build_upstream_request(&request.body, credential, options, format)
        .map_err(|e| ProviderExecutionError::Upstream(e.to_string()))?;

    let client = upstream_client()?;
    let mut req_builder = client.post(&upstream_req.url).timeout(options.timeout);

    for (key, value) in &upstream_req.headers {
        req_builder = req_builder.header(key.as_str(), value.as_str());
    }

    let resp = req_builder
        .json(&upstream_req.body)
        .send()
        .await
        .map_err(|e| ProviderExecutionError::Upstream(e.to_string()))?;

    let status = resp.status().as_u16();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| ProviderExecutionError::Upstream(e.to_string()))?;

    let usage = adapter.extract_usage(&body);

    Ok(ProviderResponse {
        status,
        body,
        usage,
    })
}

// ─── Tests ───────────────────────────────────────────────────────────────────

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
    use crate::gateway::provider_adapters::{
        AdapterError, ApiFormat, ProviderAdapter, UpstreamRequest,
    };
    use axum::{
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::post,
        Json, Router,
    };
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct TestAdapter {
        url: String,
        headers: Vec<(String, String)>,
        body: serde_json::Value,
        usage: Option<TokenUsage>,
        build_error: Option<&'static str>,
    }

    impl ProviderAdapter for TestAdapter {
        fn provider_id(&self) -> &str {
            "test-adapter"
        }

        fn supported_formats(&self) -> &[ApiFormat] {
            &[ApiFormat::OpenAiChatCompletions]
        }

        fn build_upstream_request(
            &self,
            _body: &serde_json::Value,
            _credential: &ProviderCredential,
            _options: &RequestOptions,
            _format: ApiFormat,
        ) -> Result<UpstreamRequest, AdapterError> {
            if let Some(message) = self.build_error {
                return Err(AdapterError::InvalidRequest(message.to_string()));
            }

            Ok(UpstreamRequest {
                url: self.url.clone(),
                method: "POST".to_string(),
                headers: self.headers.clone(),
                body: self.body.clone(),
            })
        }

        fn extract_usage(&self, _response_body: &serde_json::Value) -> Option<TokenUsage> {
            self.usage.clone()
        }

        fn apply_zdr_overrides(&self, _body: &mut serde_json::Value) {}
    }

    #[derive(Clone, Debug, Default, PartialEq)]
    struct RecordedUpstreamRequest {
        headers: Vec<(String, String)>,
        body: serde_json::Value,
    }

    async fn start_upstream_json_server(
        status: StatusCode,
        payload: serde_json::Value,
    ) -> (
        String,
        Arc<Mutex<Vec<RecordedUpstreamRequest>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let recorded_for_handler = Arc::clone(&recorded);
        let app = Router::new()
            .route(
                "/upstream",
                post(
                    move |State(recorded): State<Arc<Mutex<Vec<RecordedUpstreamRequest>>>>,
                          headers: HeaderMap,
                          Json(body): Json<serde_json::Value>| {
                        let payload = payload.clone();
                        async move {
                            let mut rendered_headers = headers
                                .iter()
                                .filter_map(|(name, value)| {
                                    value
                                        .to_str()
                                        .ok()
                                        .map(|value| (name.as_str().to_string(), value.to_string()))
                                })
                                .collect::<Vec<_>>();
                            rendered_headers.sort_unstable();
                            recorded.lock().expect("recorded upstream lock").push(
                                RecordedUpstreamRequest {
                                    headers: rendered_headers,
                                    body,
                                },
                            );
                            (status, Json(payload))
                        }
                    },
                ),
            )
            .with_state(recorded_for_handler);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream server");
        let addr = listener.local_addr().expect("upstream addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve upstream");
        });

        (format!("http://{addr}/upstream"), recorded, handle)
    }

    async fn start_upstream_text_server(
        status: StatusCode,
        body: &'static str,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new().route("/upstream", post(move || async move { (status, body) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream server");
        let addr = listener.local_addr().expect("upstream addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve upstream");
        });

        (format!("http://{addr}/upstream"), handle)
    }

    #[test]
    fn upstream_client_and_request_option_defaults_are_stable() {
        assert!(upstream_client().is_ok());
        assert_eq!(UPSTREAM_CONNECT_TIMEOUT, Duration::from_secs(10));

        let request_options = RequestOptions::default();
        assert!(!request_options.zdr_override);
        assert_eq!(request_options.timeout, Duration::from_secs(300));
    }

    #[test]
    fn token_usage_reports_empty_state() {
        assert!(TokenUsage::default().is_empty());
        let usage = TokenUsage {
            input_tokens: 1,
            ..Default::default()
        };
        assert!(!usage.is_empty());
    }

    #[tokio::test]
    async fn execute_upstream_provider_request_posts_adapter_request_and_extracts_usage() {
        let (url, recorded, handle) = start_upstream_json_server(
            StatusCode::CREATED,
            json!({"ok": true, "provider": "openai"}),
        )
        .await;
        let adapter = TestAdapter {
            url,
            headers: vec![
                (
                    "authorization".to_string(),
                    "Bearer resolved-key".to_string(),
                ),
                ("x-extra".to_string(), "tenant-a".to_string()),
            ],
            body: json!({"translated": true}),
            usage: Some(TokenUsage {
                input_tokens: 12,
                output_tokens: 7,
                total_tokens: 19,
                cached_input_tokens: Some(3),
            }),
            build_error: None,
        };
        let request = ProviderRequest {
            model: "gpt-5.4-mini".to_string(),
            provider: "openai".to_string(),
            body: json!({"messages": [{"role": "user", "content": "hi"}]}),
            stream: false,
            force_no_store: false,
            org_id: "org-1".to_string(),
            user_id: Some("user-1".to_string()),
        };
        let credential = ProviderCredential {
            credential_id: "cred-1".to_string(),
            provider: "openai".to_string(),
            api_key: "resolved-key".to_string(),
            region: Some("us".to_string()),
            zdr_eligible: true,
        };

        let response = execute_upstream_provider_request(
            &request,
            &credential,
            &RequestOptions::default(),
            &adapter,
            ApiFormat::OpenAiChatCompletions,
        )
        .await
        .expect("upstream execution should succeed");

        handle.abort();

        assert_eq!(response.status, StatusCode::CREATED.as_u16());
        assert_eq!(response.body["ok"], json!(true));
        let usage = response.usage.expect("usage should be extracted");
        assert_eq!(usage.input_tokens, 12);
        assert_eq!(usage.output_tokens, 7);
        assert_eq!(usage.total_tokens, 19);
        assert_eq!(usage.cached_input_tokens, Some(3));

        let recorded = recorded.lock().expect("recorded upstream lock");
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].body, json!({"translated": true}));
        assert!(recorded[0].headers.contains(&(
            "authorization".to_string(),
            "Bearer resolved-key".to_string()
        )));
        assert!(recorded[0]
            .headers
            .contains(&("x-extra".to_string(), "tenant-a".to_string())));
    }

    #[tokio::test]
    async fn execute_upstream_provider_request_surfaces_adapter_build_errors() {
        let adapter = TestAdapter {
            url: "http://127.0.0.1:9/upstream".to_string(),
            headers: Vec::new(),
            body: json!({}),
            usage: None,
            build_error: Some("adapter rejected body"),
        };
        let request = ProviderRequest {
            model: "gpt-5.4-mini".to_string(),
            provider: "openai".to_string(),
            body: json!({}),
            stream: false,
            force_no_store: false,
            org_id: "org-1".to_string(),
            user_id: None,
        };
        let credential = ProviderCredential {
            credential_id: "cred-1".to_string(),
            provider: "openai".to_string(),
            api_key: "resolved-key".to_string(),
            region: None,
            zdr_eligible: true,
        };

        let error = execute_upstream_provider_request(
            &request,
            &credential,
            &RequestOptions::default(),
            &adapter,
            ApiFormat::OpenAiChatCompletions,
        )
        .await
        .expect_err("adapter build error should surface");

        assert!(
            matches!(error, ProviderExecutionError::Upstream(message) if message == "Invalid request: adapter rejected body")
        );
    }

    #[tokio::test]
    async fn execute_upstream_provider_request_rejects_non_json_responses() {
        let (url, handle) = start_upstream_text_server(StatusCode::OK, "not-json").await;
        let adapter = TestAdapter {
            url,
            headers: Vec::new(),
            body: json!({"translated": true}),
            usage: None,
            build_error: None,
        };
        let request = ProviderRequest {
            model: "gpt-5.4-mini".to_string(),
            provider: "openai".to_string(),
            body: json!({}),
            stream: false,
            force_no_store: false,
            org_id: "org-1".to_string(),
            user_id: None,
        };
        let credential = ProviderCredential {
            credential_id: "cred-1".to_string(),
            provider: "openai".to_string(),
            api_key: "resolved-key".to_string(),
            region: None,
            zdr_eligible: true,
        };

        let error = execute_upstream_provider_request(
            &request,
            &credential,
            &RequestOptions::default(),
            &adapter,
            ApiFormat::OpenAiChatCompletions,
        )
        .await
        .expect_err("non-json upstream body should fail");

        handle.abort();

        assert!(matches!(error, ProviderExecutionError::Upstream(message) if !message.is_empty()));
    }
}
