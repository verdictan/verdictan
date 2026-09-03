// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Background task that periodically pushes a telemetry snapshot to the API.
//!
//! Collects provider metrics, health state, and aggregate counters from the
//! in-process `GatewayState` and POSTs them to either:
//! - `POST /v1/gateways/:id/telemetry` for hosted gateways, or
//! - `POST /v1/gateway/heartbeat` plus
//!   `POST /v1/gateway/runtime-versions/heartbeat`
//!   for connected gateway runtime instances.

use chrono::Utc;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

use super::provider_metrics::ProviderMetrics;

/// Configuration read from the gateway declarative config or environment.
#[derive(Clone, Debug)]
pub(crate) struct TelemetryReporterConfig {
    pub api_base_url: String,
    pub runtime_registration_id: String,
    pub gateway_id: Option<Arc<str>>,
    pub connected_read_model: super::server::SharedConnectedGatewayReadModel,
    pub interval: Duration,
    pub client: reqwest::Client,
    pub gateway_service_token: Option<String>,
    pub rollout_grade: bool,
    pub rollout_grade_reasons: Vec<String>,
    pub version: String,
    pub config_sha256: String,
    /// The bound listen address of this gateway instance, reported in heartbeats
    /// so the API can discover how to reach this gateway.
    pub listen_address: Option<String>,
    /// The relay endpoint this gateway advertises to peers for request relay.
    pub relay_endpoint: Option<String>,
    pub service_manager: String,
    pub upgrade_status: String,
    pub last_restart_at: Option<String>,
    pub active_binary_path: Option<String>,
    pub target_version: Option<String>,
    pub target_binary_path: Option<String>,
    pub image_digest: Option<String>,
    pub build_digest: Option<String>,
}

/// Spawn the background telemetry reporter loop.
///
/// The loop runs every `config.interval` and is best-effort: a failed push
/// is logged and retried on the next tick. The task is non-critical and must
/// never crash the proxy.
pub(crate) fn spawn_telemetry_reporter(
    config: TelemetryReporterConfig,
    provider_metrics: Arc<ProviderMetrics>,
    start_instant: std::time::Instant,
    active_config: super::server::SharedGatewayConfig,
) {
    tokio::spawn(async move {
        // Use interval for drift-resistant periodic heartbeats.
        // The first tick completes immediately so the gateway is marked live on startup.
        let mut interval = tokio::time::interval(config.interval);
        // Consume the immediate first tick and apply a short warm-up delay
        // so the first real heartbeat has meaningful data.
        interval.tick().await;
        tokio::time::sleep(Duration::from_secs(5)).await;

        loop {
            if !telemetry_allowed(&active_config.snapshot()) {
                interval.tick().await;
                continue;
            }
            let uptime_secs = start_instant.elapsed().as_secs() as i64;
            let providers = provider_metrics.snapshot_json();
            let connected_read_model = config.connected_read_model.snapshot();
            let now = Utc::now();

            let heartbeat_url = format!(
                "{}/v1/gateway/heartbeat",
                config.api_base_url.trim_end_matches('/'),
            );
            let heartbeat_payload = build_heartbeat_payload(
                &config,
                uptime_secs,
                &providers,
                &connected_read_model,
                now,
            );

            send_json(
                &config,
                &heartbeat_url,
                &heartbeat_payload,
                uptime_secs,
                "heartbeat pushed",
            )
            .await;

            if config.gateway_service_token.is_some() {
                let runtime_versions_url = format!(
                    "{}/v1/gateway/runtime-versions/heartbeat",
                    config.api_base_url.trim_end_matches('/'),
                );
                let runtime_versions_payload = build_runtime_versions_payload(&config);
                send_json(
                    &config,
                    &runtime_versions_url,
                    &runtime_versions_payload,
                    uptime_secs,
                    "runtime version heartbeat pushed",
                )
                .await;
            }

            interval.tick().await;
        }
    });
}

fn build_heartbeat_payload(
    config: &TelemetryReporterConfig,
    uptime_secs: i64,
    providers: &serde_json::Value,
    connected_read_model: &super::server::ConnectedGatewayReadModelSnapshot,
    now: chrono::DateTime<Utc>,
) -> serde_json::Value {
    serde_json::json!({
        "instance_id": config.runtime_registration_id,
        "version": config.version,
        "readiness": "ready",
        "status": "active",
        "uptime_secs": uptime_secs,
        "providers": providers,
        "listen_address": config.listen_address,
        "relay_endpoint": config.relay_endpoint,
        "metadata": {
            "rollout_grade": config.rollout_grade,
            "rollout_grade_reasons": config.rollout_grade_reasons,
            "region_key": connected_read_model.region_key,
            "publication_catalog": connected_read_model.publication_catalog,
            "routing_compatibility": connected_read_model.routing_compatibility,
            "read_model_freshness": {
                "publication_catalog": {
                    "status": connected_read_model.publication_catalog_status(now),
                    "stale_after_secs": connected_read_model.stale_after_secs(),
                    "age_secs": connected_read_model.publication_catalog_age_seconds(now),
                    "last_successful_refresh_at": connected_read_model
                        .publication_catalog_last_successful_refresh_at
                        .map(|value| value.to_rfc3339()),
                    "last_refresh_error": connected_read_model
                        .publication_catalog_last_refresh_error,
                },
                "routing_compatibility": {
                    "status": connected_read_model.routing_compatibility_status(now),
                    "stale_after_secs": connected_read_model.stale_after_secs(),
                    "age_secs": connected_read_model.routing_compatibility_age_seconds(now),
                    "last_successful_refresh_at": connected_read_model
                        .routing_compatibility_last_successful_refresh_at
                        .map(|value| value.to_rfc3339()),
                    "last_refresh_error": connected_read_model
                        .routing_compatibility_last_refresh_error,
                },
            },
        }
    })
}

async fn send_json(
    config: &TelemetryReporterConfig,
    url: &str,
    payload: &serde_json::Value,
    uptime_secs: i64,
    success_message: &'static str,
) {
    let request = if let Some(service_token) = config.gateway_service_token.as_ref() {
        config
            .client
            .post(url)
            .bearer_auth(service_token)
            .json(payload)
    } else {
        config.client.post(url).json(payload)
    };

    match request.send().await {
        Ok(resp) if resp.status().is_success() || resp.status().as_u16() == 201 => {
            debug!(
                gateway_id = ?config.gateway_id,
                runtime_registration_id = %config.runtime_registration_id,
                uptime_secs,
                "{}", success_message
            );
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(
                gateway_id = ?config.gateway_id,
                runtime_registration_id = %config.runtime_registration_id,
                url = %url,
                %status,
                body = %body,
                "heartbeat push non-success",
            );
        }
        Err(err) => {
            warn!(
                gateway_id = ?config.gateway_id,
                runtime_registration_id = %config.runtime_registration_id,
                url = %url,
                error = %err,
                "heartbeat push failed",
            );
        }
    }
}

fn build_runtime_versions_payload(config: &TelemetryReporterConfig) -> serde_json::Value {
    serde_json::json!({
        "instance_id": config.runtime_registration_id,
        "binary_version": config.version,
        "config_sha256": config.config_sha256,
        "service_manager": config.service_manager,
        "last_restart_at": config.last_restart_at,
        "upgrade_status": config.upgrade_status,
        "active_binary_path": config.active_binary_path,
        "target_version": config.target_version,
        "target_binary_path": config.target_binary_path,
        "metadata": {
            "listen_address": config.listen_address,
            "relay_endpoint": config.relay_endpoint,
            "image_digest": config.image_digest,
            "build_digest": config.build_digest,
        }
    })
}

fn telemetry_allowed(config: &super::declarative_config::LoadedDeclarativeConfig) -> bool {
    !config
        .resolved_silent_engine_config()
        .is_some_and(|value| value.gateway_telemetry_disabled())
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

    #[test]
    fn silent_engine_disables_periodic_gateway_telemetry() {
        let config = crate::gateway::declarative_config::LoadedDeclarativeConfig::from_bytes(
            br#"
silent_engine:
  enabled: true
"#,
        )
        .expect("parse config");
        assert!(!super::telemetry_allowed(&config));
    }

    #[test]
    fn telemetry_remains_enabled_without_silent_engine_disable_flag() {
        let config = crate::gateway::declarative_config::LoadedDeclarativeConfig::from_bytes(
            br#"
pack:
  name: telemetry-test
  version: "0.1.0"
"#,
        )
        .expect("parse config");
        assert!(super::telemetry_allowed(&config));
    }

    #[test]
    fn command_helper_coverage_build_heartbeat_payload_includes_runtime_metadata() {
        let now = chrono::Utc::now();
        let read_model =
            crate::gateway::server::SharedConnectedGatewayReadModel::default().snapshot();

        let config = super::TelemetryReporterConfig {
            api_base_url: "https://api.example.com".to_string(),
            runtime_registration_id: "runtime-123".to_string(),
            gateway_id: None,
            connected_read_model: crate::gateway::server::SharedConnectedGatewayReadModel::default(
            ),
            interval: std::time::Duration::from_secs(30),
            client: reqwest::Client::new(),
            gateway_service_token: Some("service-token".to_string()),
            rollout_grade: true,
            rollout_grade_reasons: vec!["ready".to_string()],
            version: "1.2.3".to_string(),
            config_sha256: "sha256:abc".to_string(),
            listen_address: Some("127.0.0.1:8080".to_string()),
            relay_endpoint: Some("relay.example.com:443".to_string()),
            service_manager: "systemd_user".to_string(),
            upgrade_status: "succeeded".to_string(),
            last_restart_at: Some("2026-07-05T01:02:03Z".to_string()),
            active_binary_path: Some("/opt/verdictan/bin/verdictan".to_string()),
            target_version: Some("1.2.3".to_string()),
            target_binary_path: Some("/opt/verdictan/bin/verdictan".to_string()),
            image_digest: Some("sha256:image".to_string()),
            build_digest: Some("sha256:build".to_string()),
        };

        let payload = super::build_heartbeat_payload(
            &config,
            42,
            &serde_json::json!({"openai": {"requests": 3}}),
            &read_model,
            now,
        );

        assert_eq!(payload["instance_id"], "runtime-123");
        assert_eq!(payload["uptime_secs"], 42);
        assert_eq!(payload["listen_address"], "127.0.0.1:8080");
        assert_eq!(payload["metadata"]["rollout_grade"], true);
        assert!(
            payload["metadata"]["read_model_freshness"]["publication_catalog"]["status"]
                .is_string()
        );

        let runtime_payload = super::build_runtime_versions_payload(&config);
        assert_eq!(runtime_payload["config_sha256"], "sha256:abc");
        assert_eq!(runtime_payload["service_manager"], "systemd_user");
        assert_eq!(runtime_payload["upgrade_status"], "succeeded");
        assert_eq!(runtime_payload["metadata"]["image_digest"], "sha256:image");
        assert_eq!(runtime_payload["metadata"]["build_digest"], "sha256:build");
    }
}
