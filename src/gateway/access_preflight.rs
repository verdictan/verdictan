// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! BYOK access preflight client used by connected gateway admission.
//!
//! The organization owns every upstream provider credential. The control plane
//! evaluates the organization provider-key policy for one agent and returns
//! `ready_byok` as its only ready state. Every other outcome is `inactive` with
//! a status reason. The client rejects any other readiness value, because the
//! gateway must not act on a state that it cannot enforce.

use crate::error::CliError;
use serde::{Deserialize, Deserializer, Serialize};

/// The only ready readiness state of the access preflight contract.
pub const ACCESS_PREFLIGHT_READY_BYOK: &str = "ready_byok";
/// Readiness state that reports that no organization provider key is usable.
pub const ACCESS_PREFLIGHT_INACTIVE: &str = "inactive";

#[derive(Debug, Clone, Serialize)]
#[doc(hidden)]
pub struct AccessPreflightRequest {
    pub org_id: String,
    /// The control plane evaluates the provider-key policy for this agent.
    pub agent_id: String,
    pub provider: String,
    pub model: String,
}

/// Accept only the readiness states of the BYOK access-preflight contract.
///
/// The field keeps its wire representation so that call sites can log and
/// compare the value. Unknown states fail the response, which keeps the
/// gateway closed instead of continuing on an unenforceable state.
fn deserialize_readiness<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let status = String::deserialize(deserializer)?;
    match status.as_str() {
        ACCESS_PREFLIGHT_READY_BYOK | ACCESS_PREFLIGHT_INACTIVE => Ok(status),
        other => Err(serde::de::Error::custom(format!(
            "unknown access preflight readiness state: {other}"
        ))),
    }
}

#[derive(Debug, Clone, Deserialize)]
#[doc(hidden)]
pub struct AccessPreflightResponse {
    #[serde(deserialize_with = "deserialize_readiness")]
    pub status: String,
    pub status_reason: String,
    #[serde(default)]
    pub resolved_api_key: Option<String>,
    #[serde(default)]
    pub org_authz_version: Option<i64>,
    #[serde(default)]
    pub remaining_budget: Option<f64>,
    #[serde(default)]
    pub budget_limit: Option<f64>,
    #[serde(default)]
    pub spend_so_far: Option<f64>,
    #[serde(default)]
    pub budget_period: Option<String>,
    /// Decimal price string from the control-plane model catalog.
    #[serde(default)]
    pub cost_per_1k_input_tokens: Option<String>,
    /// Decimal price string from the control-plane model catalog.
    #[serde(default)]
    pub cost_per_1k_output_tokens: Option<String>,
}

impl AccessPreflightResponse {
    /// Returns `true` only for the `ready_byok` state.
    fn is_ready(&self) -> bool {
        self.status == ACCESS_PREFLIGHT_READY_BYOK
    }

    /// Input price for each 1000 tokens as a number, when the catalog has one.
    pub fn cost_per_1k_input_tokens_usd(&self) -> Option<f64> {
        parse_price(self.cost_per_1k_input_tokens.as_deref())
    }

    /// Output price for each 1000 tokens as a number, when the catalog has one.
    pub fn cost_per_1k_output_tokens_usd(&self) -> Option<f64> {
        parse_price(self.cost_per_1k_output_tokens.as_deref())
    }
}

fn parse_price(value: Option<&str>) -> Option<f64> {
    value.map(str::trim).and_then(|price| price.parse().ok())
}

#[doc(hidden)]
pub async fn access_preflight(
    client: &reqwest::Client,
    api_base_url: &str,
    payload: &AccessPreflightRequest,
) -> Result<AccessPreflightResponse, CliError> {
    let url = format!(
        "{}/v1/gateway/access/preflight",
        api_base_url.trim_end_matches('/')
    );
    let response = client
        .post(&url)
        .json(payload)
        .send()
        .await
        .map_err(|error| CliError::user(format!("access preflight request failed: {error}")))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(CliError::user(format!(
            "access preflight failed: status={status} body={body}"
        )));
    }
    response
        .json::<AccessPreflightResponse>()
        .await
        .map_err(|error| CliError::user(format!("invalid access preflight response: {error}")))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stderr
    )]
    use super::*;
    use crate::gateway::removed_provider_access_contract::{
        REMOVED_PREFLIGHT_READY_STATE, REMOVED_PREFLIGHT_REQUEST_FIELDS,
    };
    use axum::{
        extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router,
    };
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};

    async fn start_server(router: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("test server addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve test server");
        });
        (format!("http://{addr}"), handle)
    }

    fn sample_request() -> AccessPreflightRequest {
        AccessPreflightRequest {
            org_id: "org-1".to_string(),
            agent_id: "agent-abc".to_string(),
            provider: "openai".to_string(),
            model: "gpt-5.4".to_string(),
        }
    }

    #[test]
    fn preflight_request_serializes_the_byok_contract() {
        let body = serde_json::to_value(sample_request()).unwrap();
        assert_eq!(body["org_id"], "org-1");
        assert_eq!(body["agent_id"], "agent-abc");
        assert_eq!(body["provider"], "openai");
        assert_eq!(body["model"], "gpt-5.4");
        for removed in REMOVED_PREFLIGHT_REQUEST_FIELDS {
            assert!(
                body.get(removed).is_none(),
                "the request must not carry the retired field {removed}"
            );
        }
        assert_eq!(
            body.as_object().map(|fields| fields.len()),
            Some(4),
            "the request carries only the BYOK contract fields"
        );
    }

    #[test]
    fn preflight_response_deserializes_full_payload() {
        let body = json!({
            "status": "ready_byok",
            "status_reason": "provider_key_ready",
            "resolved_api_key": "sk-test-key",
            "org_authz_version": 7,
            "remaining_budget": 42.50,
            "budget_limit": 100.0,
            "spend_so_far": 57.5,
            "budget_period": "monthly",
            "cost_per_1k_input_tokens": "0.003",
            "cost_per_1k_output_tokens": "0.015",
        });
        let response: AccessPreflightResponse = serde_json::from_value(body).unwrap();
        assert!(response.is_ready());
        assert_eq!(response.status_reason, "provider_key_ready");
        assert_eq!(response.resolved_api_key.as_deref(), Some("sk-test-key"));
        assert_eq!(response.org_authz_version, Some(7));
        assert!((response.remaining_budget.unwrap() - 42.50).abs() < 1e-9);
        assert!((response.budget_limit.unwrap() - 100.0).abs() < 1e-9);
        assert!((response.spend_so_far.unwrap() - 57.5).abs() < 1e-9);
        assert_eq!(response.budget_period.as_deref(), Some("monthly"));
        assert!((response.cost_per_1k_input_tokens_usd().unwrap() - 0.003).abs() < 1e-9);
        assert!((response.cost_per_1k_output_tokens_usd().unwrap() - 0.015).abs() < 1e-9);
    }

    #[test]
    fn preflight_response_deserializes_minimal_inactive_payload() {
        let body = json!({
            "status": "inactive",
            "status_reason": "provider_key_not_configured",
        });
        let response: AccessPreflightResponse = serde_json::from_value(body).unwrap();
        assert!(!response.is_ready());
        assert_eq!(response.status_reason, "provider_key_not_configured");
        assert!(response.resolved_api_key.is_none());
        assert!(response.org_authz_version.is_none());
        assert!(response.remaining_budget.is_none());
        assert!(response.budget_limit.is_none());
        assert!(response.spend_so_far.is_none());
        assert!(response.budget_period.is_none());
        assert!(response.cost_per_1k_input_tokens_usd().is_none());
        assert!(response.cost_per_1k_output_tokens_usd().is_none());
    }

    #[test]
    fn preflight_response_rejects_unknown_readiness_states() {
        for unknown in [REMOVED_PREFLIGHT_READY_STATE, "ready", "ok", ""] {
            let body = json!({ "status": unknown, "status_reason": "any" });
            let error = serde_json::from_value::<AccessPreflightResponse>(body)
                .expect_err("unknown readiness state must fail");
            assert!(
                error
                    .to_string()
                    .contains("unknown access preflight readiness state"),
                "unexpected error for {unknown}: {error}"
            );
        }
    }

    #[test]
    fn unparseable_price_strings_have_no_number() {
        let body = json!({
            "status": "ready_byok",
            "status_reason": "provider_key_ready",
            "cost_per_1k_input_tokens": "not-a-price",
        });
        let response: AccessPreflightResponse = serde_json::from_value(body).unwrap();
        assert!(response.cost_per_1k_input_tokens_usd().is_none());
    }

    #[tokio::test]
    async fn access_preflight_uses_access_route() {
        let captured = Arc::new(Mutex::new(Vec::<Value>::new()));
        let app =
            Router::new()
                .route(
                    "/v1/gateway/access/preflight",
                    post(
                        |State(captured): State<Arc<Mutex<Vec<Value>>>>,
                         Json(body): Json<Value>| async move {
                            captured.lock().unwrap().push(body);
                            (
                                StatusCode::OK,
                                Json(json!({
                                    "status": "inactive",
                                    "status_reason": "provider_key_not_configured",
                                })),
                            )
                                .into_response()
                        },
                    ),
                )
                .with_state(Arc::clone(&captured));
        let (base_url, handle) = start_server(app).await;
        let client = reqwest::Client::new();

        let result = access_preflight(&client, &format!("{base_url}/"), &sample_request()).await;
        assert!(result.is_ok());
        let bodies = captured.lock().unwrap();
        let last = bodies.last().expect("captured request body");
        assert_eq!(last["org_id"], "org-1");
        assert_eq!(last["agent_id"], "agent-abc");
        for removed in REMOVED_PREFLIGHT_REQUEST_FIELDS {
            assert!(last.get(removed).is_none(), "{removed} must stay absent");
        }

        handle.abort();
    }

    #[tokio::test]
    async fn preflight_returns_ready_byok_on_200() {
        let app = Router::new().route(
            "/v1/gateway/access/preflight",
            post(|| async {
                (
                    StatusCode::OK,
                    Json(json!({
                        "status": "ready_byok",
                        "status_reason": "provider_key_ready",
                        "remaining_budget": 50.0,
                    })),
                )
                    .into_response()
            }),
        );
        let (base_url, handle) = start_server(app).await;
        let client = reqwest::Client::new();

        let response = access_preflight(&client, &base_url, &sample_request())
            .await
            .expect("preflight succeeds");
        assert!(response.is_ready());
        assert!((response.remaining_budget.unwrap() - 50.0).abs() < 1e-9);

        handle.abort();
    }

    #[tokio::test]
    async fn preflight_rejects_a_managed_readiness_state() {
        let app = Router::new().route(
            "/v1/gateway/access/preflight",
            post(|| async {
                (
                    StatusCode::OK,
                    Json(json!({
                        "status": REMOVED_PREFLIGHT_READY_STATE,
                        "status_reason": "platform_credential",
                    })),
                )
                    .into_response()
            }),
        );
        let (base_url, handle) = start_server(app).await;
        let client = reqwest::Client::new();

        let error = access_preflight(&client, &base_url, &sample_request())
            .await
            .expect_err("a managed readiness state must fail");
        assert!(error
            .to_string()
            .contains("invalid access preflight response"));

        handle.abort();
    }

    #[tokio::test]
    async fn preflight_returns_error_on_non_success_status() {
        let app = Router::new().route(
            "/v1/gateway/access/preflight",
            post(|| async { (StatusCode::FORBIDDEN, "access denied").into_response() }),
        );
        let (base_url, handle) = start_server(app).await;
        let client = reqwest::Client::new();

        let error = access_preflight(&client, &base_url, &sample_request())
            .await
            .expect_err("a rejected preflight must fail");
        let message = error.to_string();
        assert!(message.contains("access preflight failed"));
        assert!(message.contains("403"));

        handle.abort();
    }

    #[tokio::test]
    async fn preflight_returns_error_on_unparseable_json() {
        let app = Router::new().route(
            "/v1/gateway/access/preflight",
            post(|| async { (StatusCode::OK, "not-json").into_response() }),
        );
        let (base_url, handle) = start_server(app).await;
        let client = reqwest::Client::new();

        let error = access_preflight(&client, &base_url, &sample_request())
            .await
            .expect_err("an unparseable response must fail");
        assert!(error
            .to_string()
            .contains("invalid access preflight response"));

        handle.abort();
    }
}
