// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::time::{Duration, SystemTime};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Default)]
pub struct ProviderHealthConfig {
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default = "default_interval_seconds")]
    pub interval_seconds: u64,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ProbeResult {
    pub healthy: bool,
    pub status_code: Option<u16>,
    pub latency_ms: Option<u64>,
    pub checked_at_unix: u64,
}

fn default_interval_seconds() -> u64 {
    30
}

fn default_timeout_ms() -> u64 {
    2_000
}

pub async fn probe_endpoint(endpoint: &str, timeout_ms: u64) -> ProbeResult {
    let started = std::time::Instant::now();
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms.max(1)))
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            return ProbeResult {
                healthy: false,
                status_code: None,
                latency_ms: None,
                checked_at_unix: unix_now(),
            }
        }
    };

    match client.get(endpoint).send().await {
        Ok(response) => ProbeResult {
            healthy: response.status().is_success(),
            status_code: Some(response.status().as_u16()),
            latency_ms: Some(started.elapsed().as_millis() as u64),
            checked_at_unix: unix_now(),
        },
        Err(_) => ProbeResult {
            healthy: false,
            status_code: None,
            latency_ms: Some(started.elapsed().as_millis() as u64),
            checked_at_unix: unix_now(),
        },
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
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
    fn provider_health_config_defaults() {
        let config = ProviderHealthConfig::default();
        assert!(config.endpoint.is_none());
        assert_eq!(config.interval_seconds, 0);
        assert_eq!(config.timeout_ms, 0);
    }

    #[test]
    fn provider_health_config_serde_defaults() {
        let config: ProviderHealthConfig = serde_json::from_str("{}").unwrap();
        assert!(config.endpoint.is_none());
        assert_eq!(config.interval_seconds, 30);
        assert_eq!(config.timeout_ms, 2000);
    }

    #[test]
    fn provider_health_config_custom() {
        let json =
            r#"{"endpoint": "http://health.check", "interval_seconds": 60, "timeout_ms": 5000}"#;
        let config: ProviderHealthConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.endpoint.unwrap(), "http://health.check");
        assert_eq!(config.interval_seconds, 60);
        assert_eq!(config.timeout_ms, 5000);
    }

    #[test]
    fn default_interval_seconds_value() {
        assert_eq!(default_interval_seconds(), 30);
    }

    #[test]
    fn default_timeout_ms_value() {
        assert_eq!(default_timeout_ms(), 2000);
    }

    #[test]
    fn unix_now_returns_reasonable_value() {
        let now = unix_now();
        assert!(now > 1_700_000_000);
    }

    #[test]
    fn probe_result_serialization() {
        let result = ProbeResult {
            healthy: true,
            status_code: Some(200),
            latency_ms: Some(42),
            checked_at_unix: 1700000000,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["healthy"], true);
        assert_eq!(json["status_code"], 200);
        assert_eq!(json["latency_ms"], 42);
        assert_eq!(json["checked_at_unix"], 1700000000_u64);
    }

    #[test]
    fn probe_result_unhealthy_serialization() {
        let result = ProbeResult {
            healthy: false,
            status_code: None,
            latency_ms: None,
            checked_at_unix: 0,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["healthy"], false);
        assert!(json["status_code"].is_null());
    }

    #[tokio::test]
    async fn probe_endpoint_with_mock_server() {
        let app = axum::Router::new().route("/health", axum::routing::get(|| async { "ok" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let result = probe_endpoint(&format!("http://{addr}/health"), 2000).await;
        assert!(result.healthy);
        assert_eq!(result.status_code, Some(200));
        assert!(result.latency_ms.is_some());
    }

    #[tokio::test]
    async fn probe_endpoint_404_is_unhealthy() {
        let app = axum::Router::new().route(
            "/health",
            axum::routing::get(|| async { (axum::http::StatusCode::NOT_FOUND, "not found") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let result = probe_endpoint(&format!("http://{addr}/health"), 2000).await;
        assert!(!result.healthy);
        assert_eq!(result.status_code, Some(404));
    }

    #[test]
    fn provider_health_config_partial_serde() {
        let json = r#"{"endpoint": "http://test"}"#;
        let config: ProviderHealthConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.endpoint.as_deref(), Some("http://test"));
        assert_eq!(config.interval_seconds, 30);
        assert_eq!(config.timeout_ms, 2000);
    }
}
