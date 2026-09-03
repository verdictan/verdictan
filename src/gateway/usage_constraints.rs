// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Gateway-side agent usage-constraint check and increment helpers.
//!
//! `check_agent_usage` is called on the hot path (before forwarding) and
//! returns a `UsageCheckResult` that the caller translates into a 429 or
//! continues normally. `increment_agent_usage` returns delivery failures to
//! the caller and uses an idempotency key for safe bounded retry.

use serde::Deserialize;
use std::time::Duration;

// ── Public result types ───────────────────────────────────────────────────────

#[derive(Debug)]
pub enum UsageCheckResult {
    Allowed,
    Rejected {
        constraint_type: String,
        interval: String,
        enforcement_mode: String,
        resets_at: String,
        retry_after_secs: Option<u64>,
    },
}

// ── Internal response shapes ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct UsageCheckBody {
    #[allow(dead_code)]
    pub allowed: bool,
    pub constraint_type: Option<String>,
    pub interval: Option<String>,
    pub enforcement_mode: Option<String>,
    pub resets_at: Option<String>,
    pub retry_after_secs: Option<u64>,
}

fn finops_retry_policy() -> crate::retry::RetryPolicy {
    crate::retry::RetryPolicy {
        max_retries: 2,
        base_delay: Duration::from_millis(100),
        multiplier: 2.0,
        max_delay: Duration::from_millis(500),
        jitter: 0.2,
    }
}

fn should_retry_status(status: reqwest::StatusCode) -> bool {
    crate::retry::classify_status(status.as_u16()) == crate::retry::RetryClassification::Transient
}

fn should_retry_transport(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect()
}

// ── Public functions ──────────────────────────────────────────────────────────

/// Call `GET /v1/gateway/agents/{agent_id}/usage-check`.
///
/// Returns `Ok(UsageCheckResult::Rejected {.. })` when the API responds with
/// 429. Any transport or unexpected API error is returned as `Err`; connected
/// gateway callers must fail closed rather than dispatching without a check.
///
/// If `service_token` is non-empty it is written as `Authorization: Bearer
/// <token>`, overriding any default header the client may carry.
#[allow(clippy::too_many_arguments)]
pub async fn check_agent_usage(
    client: &reqwest::Client,
    api_base_url: &str,
    service_token: &str,
    agent_id: &str,
    org_id: &str,
    provider: &str,
    model: &str,
    estimated_prompt_tokens: u64,
    max_completion_tokens: u64,
) -> Result<UsageCheckResult, anyhow::Error> {
    let url_str = format!(
        "{}/v1/gateway/agents/{}/usage-check",
        api_base_url.trim_end_matches('/'),
        urlencoding::encode(agent_id),
    );
    let mut url = reqwest::Url::parse(&url_str)?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("org_id", org_id);
        q.append_pair("provider", provider);
        q.append_pair("model", model);
        q.append_pair(
            "estimated_prompt_tokens",
            &estimated_prompt_tokens.to_string(),
        );
        q.append_pair("max_completion_tokens", &max_completion_tokens.to_string());
    }

    let mut request = client.get(url);
    if !service_token.is_empty() {
        request = request.header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        );
    }
    let response = request.send().await?;

    let status = response.status();

    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        // Parse best-effort; default to a conservative "reject" posture if
        // the body is malformed.
        let body: UsageCheckBody = response.json().await.unwrap_or(UsageCheckBody {
            allowed: false,
            constraint_type: Some("unknown".to_string()),
            interval: Some("unknown".to_string()),
            enforcement_mode: Some("reject".to_string()),
            resets_at: Some(String::new()),
            retry_after_secs: None,
        });
        return Ok(UsageCheckResult::Rejected {
            constraint_type: body.constraint_type.unwrap_or_default(),
            interval: body.interval.unwrap_or_default(),
            enforcement_mode: body
                .enforcement_mode
                .unwrap_or_else(|| "reject".to_string()),
            resets_at: body.resets_at.unwrap_or_default(),
            retry_after_secs: body.retry_after_secs,
        });
    }

    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("usage check failed: status={status} body={body}");
    }

    Ok(UsageCheckResult::Allowed)
}

/// Call `POST /v1/gateway/agents/{agent_id}/usage-increment`.
///
/// When `idempotency_key` is present, transient failures are retried safely;
/// otherwise the first failed delivery is returned because the mutation cannot
/// be replayed without risking a duplicate counter increment.
#[allow(clippy::too_many_arguments)]
pub async fn increment_agent_usage(
    client: &reqwest::Client,
    api_base_url: &str,
    service_token: &str,
    agent_id: &str,
    org_id: &str,
    provider: &str,
    model: &str,
    actual_input_tokens: u64,
    actual_cached_input_tokens: u64,
    actual_completion_tokens: u64,
    response_count_increment: u64,
    idempotency_key: Option<&str>,
) -> Result<(), anyhow::Error> {
    let url = format!(
        "{}/v1/gateway/agents/{}/usage-increment",
        api_base_url.trim_end_matches('/'),
        urlencoding::encode(agent_id),
    );

    let payload = serde_json::json!({
        "org_id": org_id,
        "provider": provider,
        "model": model,
        "actual_input_tokens": actual_input_tokens,
        "actual_cached_input_tokens": actual_cached_input_tokens,
        "actual_completion_tokens": actual_completion_tokens,
        "response_count_increment": response_count_increment,
        "idempotency_key": idempotency_key,
    });

    let retry_policy = finops_retry_policy();
    let max_attempt = if idempotency_key.is_some() {
        retry_policy.max_retries
    } else {
        0
    };
    for attempt in 0..=max_attempt {
        let mut request = client.post(&url);
        if !service_token.is_empty() {
            request = request.header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {service_token}"),
            );
        }

        match request.json(&payload).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                let retryable = should_retry_status(status) && attempt < max_attempt;
                if retryable {
                    let delay = crate::retry::compute_delay(&retry_policy, attempt + 1);
                    tracing::warn!(
                        agent_id = %agent_id,
                        status = %status,
                        retry_after_ms = delay.as_millis() as u64,
                        "usage increment transient non-2xx; retrying"
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
                anyhow::bail!("usage increment returned status={status} body={body}");
            }
            Err(err) => {
                let retryable = should_retry_transport(&err) && attempt < max_attempt;
                if retryable {
                    let delay = crate::retry::compute_delay(&retry_policy, attempt + 1);
                    tracing::warn!(
                        agent_id = %agent_id,
                        error = %err,
                        retry_after_ms = delay.as_millis() as u64,
                        "usage increment transport failure; retrying"
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
                return Err(anyhow::anyhow!("usage increment request failed: {err}"));
            }
        };
    }

    anyhow::bail!("usage increment exhausted retries")
}

// ── Unit tests ────────────────────────────────────────────────────────────────

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
    fn finops_retry_policy_values() {
        let policy = finops_retry_policy();
        assert_eq!(policy.max_retries, 2);
        assert_eq!(policy.base_delay, Duration::from_millis(100));
        assert_eq!(policy.multiplier, 2.0);
        assert_eq!(policy.max_delay, Duration::from_millis(500));
        assert_eq!(policy.jitter, 0.2);
    }

    #[test]
    fn should_retry_status_transient_codes() {
        assert!(should_retry_status(reqwest::StatusCode::TOO_MANY_REQUESTS));
        assert!(should_retry_status(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR
        ));
        assert!(should_retry_status(reqwest::StatusCode::BAD_GATEWAY));
        assert!(should_retry_status(
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        ));
        assert!(should_retry_status(reqwest::StatusCode::GATEWAY_TIMEOUT));
    }

    #[test]
    fn should_retry_status_permanent_codes() {
        assert!(!should_retry_status(reqwest::StatusCode::BAD_REQUEST));
        assert!(!should_retry_status(reqwest::StatusCode::UNAUTHORIZED));
        assert!(!should_retry_status(reqwest::StatusCode::FORBIDDEN));
        assert!(!should_retry_status(reqwest::StatusCode::NOT_FOUND));
        assert!(!should_retry_status(reqwest::StatusCode::OK));
    }

    #[test]
    fn usage_check_body_deserialization() {
        let json = serde_json::json!({
            "allowed": false,
            "constraint_type": "budget",
            "interval": "monthly",
            "enforcement_mode": "reject",
            "resets_at": "2025-02-01T00:00:00Z",
            "retry_after_secs": 3600
        });
        let body: UsageCheckBody = serde_json::from_value(json).unwrap();
        assert_eq!(body.constraint_type.as_deref(), Some("budget"));
        assert_eq!(body.interval.as_deref(), Some("monthly"));
        assert_eq!(body.enforcement_mode.as_deref(), Some("reject"));
        assert_eq!(body.resets_at.as_deref(), Some("2025-02-01T00:00:00Z"));
        assert_eq!(body.retry_after_secs, Some(3600));
    }

    #[test]
    fn usage_check_body_minimal_deserialization() {
        let json = serde_json::json!({"allowed": true});
        let body: UsageCheckBody = serde_json::from_value(json).unwrap();
        assert!(body.constraint_type.is_none());
        assert!(body.interval.is_none());
        assert!(body.enforcement_mode.is_none());
        assert!(body.resets_at.is_none());
        assert!(body.retry_after_secs.is_none());
    }

    #[tokio::test]
    async fn check_agent_usage_allowed() {
        let app = axum::Router::new().route(
            "/v1/gateway/agents/:agent_id/usage-check",
            axum::routing::get(|| async { axum::Json(serde_json::json!({"allowed": true})) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();
        let result = check_agent_usage(
            &client,
            &format!("http://{addr}"),
            "tok",
            "agent-1",
            "org-1",
            "openai",
            "gpt-4",
            100,
            200,
        )
        .await
        .unwrap();

        assert!(matches!(result, UsageCheckResult::Allowed));
    }

    #[tokio::test]
    async fn check_agent_usage_rejected_429() {
        let app = axum::Router::new().route(
            "/v1/gateway/agents/:agent_id/usage-check",
            axum::routing::get(|| async {
                (
                    axum::http::StatusCode::TOO_MANY_REQUESTS,
                    axum::Json(serde_json::json!({
                        "allowed": false,
                        "constraint_type": "budget",
                        "interval": "monthly",
                        "enforcement_mode": "reject",
                        "resets_at": "2025-02-01T00:00:00Z",
                        "retry_after_secs": 3600
                    })),
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();
        let result = check_agent_usage(
            &client,
            &format!("http://{addr}"),
            "tok",
            "agent-1",
            "org-1",
            "openai",
            "gpt-4",
            100,
            200,
        )
        .await
        .unwrap();

        match result {
            UsageCheckResult::Rejected {
                constraint_type,
                interval,
                enforcement_mode,
                resets_at,
                retry_after_secs,
            } => {
                assert_eq!(constraint_type, "budget");
                assert_eq!(interval, "monthly");
                assert_eq!(enforcement_mode, "reject");
                assert_eq!(resets_at, "2025-02-01T00:00:00Z");
                assert_eq!(retry_after_secs, Some(3600));
            }
            _ => panic!("expected Rejected"),
        }
    }

    #[tokio::test]
    async fn check_agent_usage_429_malformed_body() {
        let app = axum::Router::new().route(
            "/v1/gateway/agents/:agent_id/usage-check",
            axum::routing::get(|| async {
                (axum::http::StatusCode::TOO_MANY_REQUESTS, "not json")
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();
        let result = check_agent_usage(
            &client,
            &format!("http://{addr}"),
            "",
            "agent-1",
            "org-1",
            "openai",
            "gpt-4",
            100,
            200,
        )
        .await
        .unwrap();

        match result {
            UsageCheckResult::Rejected {
                constraint_type,
                enforcement_mode,
                ..
            } => {
                assert_eq!(constraint_type, "unknown");
                assert_eq!(enforcement_mode, "reject");
            }
            _ => panic!("expected Rejected with defaults"),
        }
    }

    #[tokio::test]
    async fn check_agent_usage_non_success_non_429() {
        let app = axum::Router::new().route(
            "/v1/gateway/agents/:agent_id/usage-check",
            axum::routing::get(|| async {
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "broken")
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();
        let result = check_agent_usage(
            &client,
            &format!("http://{addr}"),
            "tok",
            "a",
            "o",
            "p",
            "m",
            0,
            0,
        )
        .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("500"));
    }

    #[tokio::test]
    async fn increment_agent_usage_success() {
        let app = axum::Router::new().route(
            "/v1/gateway/agents/:agent_id/usage-increment",
            axum::routing::post(|| async { axum::http::StatusCode::OK }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();
        let result = increment_agent_usage(
            &client,
            &format!("http://{addr}"),
            "tok",
            "agent-1",
            "org-1",
            "openai",
            "gpt-4",
            100,
            10,
            50,
            1,
            Some("idem-1"),
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn increment_agent_usage_permanent_failure_without_idempotency() {
        let app = axum::Router::new().route(
            "/v1/gateway/agents/:agent_id/usage-increment",
            axum::routing::post(|| async { (axum::http::StatusCode::BAD_REQUEST, "bad") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();
        let result = increment_agent_usage(
            &client,
            &format!("http://{addr}"),
            "tok",
            "a",
            "o",
            "p",
            "m",
            0,
            0,
            0,
            1,
            None,
        )
        .await;
        assert!(result.is_err());
    }

    #[test]
    fn usage_check_result_debug() {
        let allowed = UsageCheckResult::Allowed;
        assert!(format!("{:?}", allowed).contains("Allowed"));

        let rejected = UsageCheckResult::Rejected {
            constraint_type: "budget".into(),
            interval: "monthly".into(),
            enforcement_mode: "reject".into(),
            resets_at: "2025-01-01".into(),
            retry_after_secs: Some(60),
        };
        assert!(format!("{:?}", rejected).contains("Rejected"));
    }
}
