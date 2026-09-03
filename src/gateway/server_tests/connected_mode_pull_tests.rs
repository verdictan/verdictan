// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

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
use crate::gateway::fail_mode::FailMode;
use axum::{response::IntoResponse, routing::get, Json, Router};

fn runtime_config() -> crate::runtime::RuntimeInstanceConfig {
    crate::runtime::RuntimeInstanceConfig::new(
        None,
        "127.0.0.1:41002".parse().expect("listen addr"),
        "http://example.test".to_string(),
        None,
        FailMode::Block,
        LoadedDeclarativeConfig::empty(),
        16,
        true,
        None,
    )
}

#[test]
fn build_pulled_gateway_config_preserves_identity_without_yaml() {
    let pulled = build_pulled_gateway_config(
        Some(" gateway-1 ".to_string()),
        Some(" runtime-1 ".to_string()),
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        None,
        None,
    )
    .expect("pull parses");

    assert_eq!(pulled.gateway_id.as_deref(), Some("gateway-1"));
    assert_eq!(pulled.runtime_registration_id.as_deref(), Some("runtime-1"));
    assert!(pulled.loaded_config.is_none());
}

#[test]
fn gateway_config_pull_url_omits_runtime_registration_id_when_missing() {
    let url = gateway_config_pull_url("https://api.verdictan.example/", None, None);
    assert_eq!(url, "https://api.verdictan.example/v1/gateway/config/pull");
}

#[test]
fn gateway_config_pull_url_includes_runtime_registration_id_when_present() {
    let url = gateway_config_pull_url(
        "https://api.verdictan.example/",
        Some("11111111-1111-1111-1111-111111111111"),
        None,
    );
    assert_eq!(
            url,
            "https://api.verdictan.example/v1/gateway/config/pull?runtime_registration_id=11111111-1111-1111-1111-111111111111"
        );
}

#[test]
fn gateway_config_pull_url_includes_region_when_present() {
    let url = gateway_config_pull_url(
        "https://api.verdictan.example/",
        Some("rid-1"),
        Some("eu-west"),
    );
    assert!(url.contains("region=eu-west"));
    assert!(url.contains("runtime_registration_id=rid-1"));
}

#[test]
fn gateway_config_pull_url_region_only() {
    let url = gateway_config_pull_url("https://api.verdictan.example/", None, Some("us-east"));
    assert_eq!(
        url,
        "https://api.verdictan.example/v1/gateway/config/pull?region=us-east"
    );
}

#[tokio::test]
async fn fetch_runtime_routing_settings_prefers_gateway_machine_route_when_available() {
    async fn machine_settings(headers: axum::http::HeaderMap) -> axum::response::Response {
        let auth = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if auth != "Bearer machine-token" {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "wrong token"})),
            )
                .into_response();
        }

        (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({
                "default_provider_policy": {
                    "allow_fallbacks": false,
                    "require_parameters": true,
                    "data_collection": "deny",
                    "zdr": true
                },
                "cache_defaults": {
                    "allow_cache_control": true,
                    "sticky_routing": false,
                    "allow_session_id": true,
                    "session_header_name": "x-machine-session"
                },
                "plugin_governance": {
                    "defaults": [],
                    "forced_on": [],
                    "prevent_overrides": []
                },
                "shadow_routing": {
                    "enabled": false,
                    "evaluation_mode": "asynchronous",
                    "capture_mode": "metadata_only"
                }
            })),
        )
            .into_response()
    }

    async fn user_settings() -> axum::response::Response {
        (
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": {
                    "code": "auth.insufficient_permissions"
                }
            })),
        )
            .into_response()
    }

    let app = Router::new()
        .route(
            "/v1/gateway/settings/runtime-routing",
            get(machine_settings),
        )
        .route("/v1/settings/runtime-routing", get(user_settings));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock api");
    let addr = listener.local_addr().expect("mock api addr");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve mock api");
    });

    let sink = EventSink::from_config(EventSinkConfig {
        base_url: format!("http://{addr}"),
        api_token: "user-token".to_string(),
        gateway_service_token: Some("machine-token".to_string()),
    })
    .expect("event sink");

    let settings = sink
        .fetch_runtime_routing_settings(Some("org-1"))
        .await
        .expect("runtime routing settings");

    assert!(!settings.default_provider_policy.allow_fallbacks);
    assert_eq!(settings.default_provider_policy.data_collection, "deny");
    assert_eq!(
        settings.cache_defaults.session_header_name,
        "x-machine-session"
    );

    handle.abort();
}

#[tokio::test]
async fn pull_config_from_api_preserves_active_publication_region_group() {
    async fn pull_config(headers: axum::http::HeaderMap) -> axum::response::Response {
        let auth = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if auth != "Bearer machine-token" {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "wrong token"})),
            )
                .into_response();
        }

        (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({
                "gateway_id": "gateway-eu-1",
                "runtime_registration_id": "runtime-eu-1",
                "publication_catalog": {
                    "publications": [{
                        "family_key": "eu",
                        "publication_key": "pub_eu",
                        "published_hostname": "pub123eu0001.ai.eu.verdictan.com",
                        "publication_state": "published",
                        "active_revision_id": "rev-active",
                        "locality_mode": "region_pinned",
                        "serving_fleet_class": "connected_cell_pool"
                    }]
                },
                "routing_compatibility": {
                    "region_key": "eu-sovereign",
                    "publications": [{
                        "publication_key": "pub_eu",
                        "active_revision_id": "rev-active",
                        "primary_region_group_key": "eu",
                        "readiness_state": "active",
                        "compatibility_digest": "compat-digest-active",
                        "auth_digest": "auth-digest-active",
                        "policy_digest": "policy-digest-active",
                        "runtime_manifest_digest": "runtime-manifest-digest-active",
                        "admitted_members": [{
                            "runtime_registration_id": "runtime-eu-1",
                            "admitted": true,
                            "materialized": true,
                            "healthy": true
                        }]
                    }]
                },
                "yaml": null
            })),
        )
            .into_response()
    }

    let app = Router::new().route("/v1/gateway/config/pull", get(pull_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock api");
    let addr = listener.local_addr().expect("mock api addr");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve mock api");
    });

    let sink = EventSink::from_config(EventSinkConfig {
        base_url: format!("http://{addr}"),
        api_token: "user-token".to_string(),
        gateway_service_token: Some("machine-token".to_string()),
    })
    .expect("event sink");

    let pulled = pull_config_from_api(&sink, Some("runtime-eu-1"))
        .await
        .expect("pull config");

    assert_eq!(pulled.gateway_id.as_deref(), Some("gateway-eu-1"));
    assert_eq!(pulled.region_key.as_deref(), Some("eu-sovereign"));
    assert_eq!(pulled.publication_catalog.len(), 1);
    assert_eq!(
        pulled.publication_catalog[0].active_revision_id.as_deref(),
        Some("rev-active")
    );
    assert_eq!(
        pulled.routing_compatibility[0]
            .primary_region_group_key
            .as_deref(),
        Some("eu")
    );
    assert_eq!(
        pulled.routing_compatibility[0].readiness_state.as_deref(),
        Some("active")
    );
    assert_eq!(
        pulled.routing_compatibility[0].auth_digest.as_deref(),
        Some("auth-digest-active")
    );
    assert_eq!(
        pulled.routing_compatibility[0].policy_digest.as_deref(),
        Some("policy-digest-active")
    );
    assert_eq!(pulled.routing_compatibility.len(), 1);
    assert_eq!(
        pulled.routing_compatibility[0]
            .compatibility_digest
            .as_deref(),
        Some("compat-digest-active")
    );
    assert_eq!(
        pulled.routing_compatibility[0]
            .runtime_manifest_digest
            .as_deref(),
        Some("runtime-manifest-digest-active")
    );
    assert!(pulled.routing_compatibility[0]
        .active_revision_pool_membership_issue
        .is_none());

    handle.abort();
}

#[tokio::test]
async fn pull_config_from_api_parses_model_catalog_request_metadata() {
    async fn pull_config(_headers: axum::http::HeaderMap) -> axum::response::Response {
        (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({
                "catalog_version": 44,
                "gateway_id": "gateway-eu-1",
                "runtime_registration_id": "runtime-eu-1",
                "model_catalog": [{
                    "id": "claude-sonnet-4.5",
                    "provider_id": "anthropic",
                    "model_type": "chat",
                    "max_output_tokens": 4096,
                    "input_token_price": "0.00007499999999999999",
                    "output_token_price": "0",
                    "cached_input_read_price": null,
                    "supported_features": ["tools", "json_schema"],
                    "parameter_overrides": {
                        "tool_choice": "auto"
                    },
                    "removed_params": ["top_p"]
                }],
                "yaml": null
            })),
        )
            .into_response()
    }

    let app = Router::new().route("/v1/gateway/config/pull", get(pull_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock api");
    let addr = listener.local_addr().expect("mock api addr");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve mock api");
    });

    let sink = EventSink::from_config(EventSinkConfig {
        base_url: format!("http://{addr}"),
        api_token: "user-token".to_string(),
        gateway_service_token: Some("machine-token".to_string()),
    })
    .expect("event sink");

    let pulled = pull_config_from_api(&sink, Some("runtime-eu-1"))
        .await
        .expect("pull config");

    let catalog_snapshot = pulled.catalog_snapshot.expect("catalog snapshot");
    assert_eq!(catalog_snapshot.version, 44);
    assert_eq!(catalog_snapshot.models.len(), 1);
    assert_eq!(catalog_snapshot.models[0].provider_id, "anthropic");
    assert_eq!(catalog_snapshot.models[0].id, "claude-sonnet-4.5");
    assert_eq!(catalog_snapshot.models[0].max_output_tokens, Some(4096));
    assert_eq!(
        catalog_snapshot.models[0].input_token_price.as_deref(),
        Some("0.00007499999999999999")
    );
    assert_eq!(
        catalog_snapshot.models[0].output_token_price.as_deref(),
        Some("0")
    );
    assert!(catalog_snapshot.models[0].cached_input_read_price.is_none());
    assert_eq!(
        catalog_snapshot.models[0].supported_features,
        vec!["tools".to_string(), "json_schema".to_string()]
    );
    assert_eq!(
        catalog_snapshot.models[0]
            .parameter_overrides
            .get("tool_choice"),
        Some(&serde_json::json!("auto"))
    );
    assert_eq!(catalog_snapshot.models[0].removed_params, vec!["top_p"]);

    handle.abort();
}

#[tokio::test]
async fn pull_config_from_api_rejects_noncanonical_catalog_price() {
    async fn pull_config() -> axum::response::Response {
        (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({
                "catalog_version": 44,
                "gateway_id": "gateway-eu-1",
                "runtime_registration_id": "runtime-eu-1",
                "model_catalog": [{
                    "id": "claude-sonnet-4.5",
                    "provider_id": "anthropic",
                    "model_type": "chat",
                    "input_token_price": "0.0000700",
                    "output_token_price": "0.00045"
                }],
                "yaml": null
            })),
        )
            .into_response()
    }

    let app = Router::new().route("/v1/gateway/config/pull", get(pull_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock api");
    let addr = listener.local_addr().expect("mock api addr");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve mock api");
    });
    let sink = EventSink::from_config(EventSinkConfig {
        base_url: format!("http://{addr}"),
        api_token: "user-token".to_string(),
        gateway_service_token: Some("machine-token".to_string()),
    })
    .expect("event sink");

    let error = pull_config_from_api(&sink, Some("runtime-eu-1"))
        .await
        .expect_err("noncanonical price must fail the entire pull");
    let message = error.to_string();
    assert!(message.contains("input_token_price"));
    assert!(message.contains("canonical non-negative"));

    handle.abort();
}

#[tokio::test]
async fn pull_config_from_api_accepts_split_edge_feeds() {
    async fn pull_config(_headers: axum::http::HeaderMap) -> axum::response::Response {
        (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({
                "gateway_id": "gateway-eu-1",
                "runtime_registration_id": "runtime-eu-1",
                "publication_catalog": {
                    "updated_at": "2026-06-08T18:00:00Z",
                    "publications": [{
                        "family_key": "eu",
                        "publication_key": "pub_eu",
                        "published_hostname": "pub123eu0001.ai.eu.verdictan.com",
                        "publication_state": "published",
                        "active_revision_id": "rev-active",
                        "locality_mode": "region_pinned",
                        "serving_fleet_class": "connected_cell_pool"
                    }]
                },
                "routing_compatibility": {
                    "updated_at": "2026-06-08T18:00:01Z",
                    "region_key": "eu-sovereign",
                    "publications": [{
                        "publication_key": "pub_eu",
                        "active_revision_id": "rev-active",
                        "primary_region_group_key": "eu",
                        "compatibility_digest": "compat-digest-active",
                        "auth_digest": "auth-digest-active",
                        "policy_digest": "policy-digest-active",
                        "runtime_manifest_digest": "runtime-manifest-digest-active",
                        "readiness_state": "active",
                        "admitted_members": [{
                            "runtime_registration_id": "runtime-eu-1",
                            "admitted": true,
                            "materialized": true,
                            "healthy": true
                        }]
                    }]
                },
                "yaml": null
            })),
        )
            .into_response()
    }

    let app = Router::new().route("/v1/gateway/config/pull", get(pull_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock api");
    let addr = listener.local_addr().expect("mock api addr");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve mock api");
    });

    let sink = EventSink::from_config(EventSinkConfig {
        base_url: format!("http://{addr}"),
        api_token: "user-token".to_string(),
        gateway_service_token: Some("machine-token".to_string()),
    })
    .expect("event sink");

    let pulled = pull_config_from_api(&sink, Some("runtime-eu-1"))
        .await
        .expect("pull config");

    assert_eq!(pulled.region_key.as_deref(), Some("eu-sovereign"));
    assert_eq!(pulled.publication_catalog.len(), 1);
    assert_eq!(
        pulled.publication_catalog[0].active_revision_id.as_deref(),
        Some("rev-active")
    );
    assert_eq!(pulled.routing_compatibility.len(), 1);
    assert_eq!(
        pulled.routing_compatibility[0]
            .primary_region_group_key
            .as_deref(),
        Some("eu")
    );
    assert_eq!(
        pulled.routing_compatibility[0]
            .compatibility_digest
            .as_deref(),
        Some("compat-digest-active")
    );
    assert_eq!(
        pulled.routing_compatibility[0]
            .runtime_manifest_digest
            .as_deref(),
        Some("runtime-manifest-digest-active")
    );

    handle.abort();
}

#[tokio::test]
async fn pull_config_from_api_marks_connected_cell_pool_publication_unadmitted() {
    async fn pull_config(_headers: axum::http::HeaderMap) -> axum::response::Response {
        (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({
                "gateway_id": "gateway-eu-1",
                "runtime_registration_id": "runtime-eu-1",
                "publication_catalog": {
                    "publications": [{
                        "family_key": "eu",
                        "publication_key": "pub_eu",
                        "published_hostname": "pub123eu0001.ai.eu.verdictan.com",
                        "publication_state": "published",
                        "active_revision_id": "rev-active",
                        "locality_mode": "region_pinned",
                        "serving_fleet_class": "connected_cell_pool"
                    }]
                },
                "routing_compatibility": {
                    "region_key": "eu-sovereign",
                    "publications": [{
                        "publication_key": "pub_eu",
                        "active_revision_id": "rev-active",
                        "primary_region_group_key": "eu",
                        "readiness_state": "active",
                        "auth_digest": "auth-digest-active",
                        "policy_digest": "policy-digest-active",
                        "admitted_members": [{
                            "runtime_registration_id": "runtime-us-9",
                            "admitted": true,
                            "materialized": true,
                            "healthy": true
                        }]
                    }]
                },
                "yaml": null
            })),
        )
            .into_response()
    }

    let app = Router::new().route("/v1/gateway/config/pull", get(pull_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock api");
    let addr = listener.local_addr().expect("mock api addr");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve mock api");
    });

    let sink = EventSink::from_config(EventSinkConfig {
        base_url: format!("http://{addr}"),
        api_token: "user-token".to_string(),
        gateway_service_token: Some("machine-token".to_string()),
    })
    .expect("event sink");

    let pulled = pull_config_from_api(&sink, Some("runtime-eu-1"))
        .await
        .expect("pull config");

    assert_eq!(
        pulled.routing_compatibility[0]
            .active_revision_pool_membership_issue
            .as_deref(),
        Some("current_gateway_not_admitted")
    );

    handle.abort();
}

#[tokio::test]
async fn pull_config_from_api_does_not_guess_active_revision_metadata() {
    async fn pull_config(_headers: axum::http::HeaderMap) -> axum::response::Response {
        (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({
                "gateway_id": "gateway-eu-1",
                "runtime_registration_id": "runtime-eu-1",
                "publication_catalog": {
                    "publications": [{
                        "family_key": "eu",
                        "publication_key": "pub_eu",
                        "published_hostname": "pub123eu0001.ai.eu.verdictan.com",
                        "publication_state": "published",
                        "locality_mode": "region_pinned",
                        "serving_fleet_class": "connected_cell_pool"
                    }]
                },
                "routing_compatibility": {
                    "region_key": "eu-sovereign",
                    "publications": [{
                        "publication_key": "pub_eu",
                        "active_revision_id": "rev-only",
                        "primary_region_group_key": "eu",
                        "readiness_state": "active",
                        "auth_digest": "auth-digest-active",
                        "policy_digest": "policy-digest-active"
                    }]
                },
                "yaml": null
            })),
        )
            .into_response()
    }

    let app = Router::new().route("/v1/gateway/config/pull", get(pull_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock api");
    let addr = listener.local_addr().expect("mock api addr");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve mock api");
    });

    let sink = EventSink::from_config(EventSinkConfig {
        base_url: format!("http://{addr}"),
        api_token: "user-token".to_string(),
        gateway_service_token: Some("machine-token".to_string()),
    })
    .expect("event sink");

    let pulled = pull_config_from_api(&sink, Some("runtime-eu-1"))
        .await
        .expect("pull config");

    assert_eq!(pulled.publication_catalog.len(), 1);
    assert!(pulled.publication_catalog[0].active_revision_id.is_none());
    assert_eq!(pulled.routing_compatibility.len(), 1);
    assert_eq!(
        pulled.routing_compatibility[0]
            .active_revision_id
            .as_deref(),
        Some("rev-only")
    );
    assert_eq!(
        pulled.routing_compatibility[0].auth_digest.as_deref(),
        Some("auth-digest-active")
    );
    assert_eq!(
        pulled.routing_compatibility[0].policy_digest.as_deref(),
        Some("policy-digest-active")
    );

    handle.abort();
}

#[test]
fn apply_connected_control_plane_pull_sets_gateway_identity_without_config() {
    let mut config = runtime_config();
    let local_hosted_gateway = Some(
        super::super::declarative_config::HostedGatewayRuntimeConfig {
            local_access: super::super::declarative_config::HostedGatewayLocalAccessConfig::default(
            ),
        },
    );

    let loaded = apply_connected_control_plane_pull(
        &mut config,
        &local_hosted_gateway,
        PulledGatewayConfig {
            gateway_id: Some("gateway-1".to_string()),
            runtime_registration_id: Some("runtime-1".to_string()),
            region_key: None,
            publication_catalog: Vec::new(),
            routing_compatibility: Vec::new(),
            peer_gateways: Vec::new(),
            relay_hmac_secret: None,
            catalog_snapshot: None,
            loaded_config: None,
        },
    );

    assert!(!loaded);
    assert_eq!(config.gateway_id.as_deref(), Some("gateway-1"));
    assert_eq!(config.runtime_registration_id.as_deref(), Some("runtime-1"));
    assert_eq!(
        config
            .loaded_config
            .hosted_gateway
            .as_ref()
            .map(|gateway| gateway.local_access.enabled),
        Some(local_hosted_gateway.unwrap().local_access.enabled)
    );
    assert!(config.loaded_config.provider_registry.is_none());
}

#[test]
fn connected_read_model_snapshot_is_stale_without_successful_refresh() {
    let snapshot = ConnectedGatewayReadModelSnapshot {
        region_key: None,
        publication_catalog: Vec::new(),
        publication_catalog_shards: HashMap::new(),
        publication_catalog_last_successful_refresh_at: None,
        publication_catalog_last_refresh_error: Some("startup pull failed".to_string()),
        routing_compatibility: Vec::new(),
        routing_compatibility_index: HashMap::new(),
        routing_compatibility_last_successful_refresh_at: None,
        routing_compatibility_last_refresh_error: Some("startup pull failed".to_string()),
        auth_verification_material: None,
        auth_verification_material_last_successful_refresh_at: None,
        auth_verification_material_last_refresh_error: Some("startup pull failed".to_string()),
        registry_metadata: RegistryMetadataFeed::default(),
        registry_metadata_last_successful_refresh_at: None,
        registry_metadata_last_refresh_error: Some("startup pull failed".to_string()),
        capacity_health: CapacityHealthFeed::default(),
        capacity_health_last_successful_refresh_at: None,
        capacity_health_last_refresh_error: Some("startup pull failed".to_string()),
        peer_gateways: Vec::new(),
        relay_hmac_secret: None,
        managed_public_endpoint_negative_cache: Arc::new(std::sync::Mutex::new(HashMap::new())),
        stale_after_secs: CONNECTED_READ_MODEL_DEFAULT_STALE_AFTER_SECS,
    };

    assert!(snapshot.publication_catalog_is_stale(Utc::now()));
    assert_eq!(snapshot.publication_catalog_status(Utc::now()), "stale");
    assert!(snapshot.routing_compatibility_is_stale(Utc::now()));
    assert_eq!(snapshot.routing_compatibility_status(Utc::now()), "stale");
}

#[tokio::test]
async fn refresh_connected_read_model_once_updates_publication_catalog_and_freshness() {
    async fn pull_config(_headers: axum::http::HeaderMap) -> axum::response::Response {
        (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({
                "publication_catalog": {
                    "publications": [{
                        "family_key": "eu",
                        "publication_key": "pub_eu",
                        "published_hostname": "pub123eu0001.ai.eu.verdictan.com",
                        "publication_state": "published",
                        "active_revision_id": "rev-active",
                        "locality_mode": "region_pinned",
                        "serving_fleet_class": "connected_cell_pool"
                    }]
                },
                "routing_compatibility": {
                    "region_key": "eu-sovereign",
                    "publications": [{
                        "publication_key": "pub_eu",
                        "active_revision_id": "rev-active",
                        "primary_region_group_key": "eu",
                        "readiness_state": "active",
                        "compatibility_digest": "compat-digest-active",
                        "auth_digest": "auth-digest-active",
                        "policy_digest": "policy-digest-active",
                        "runtime_manifest_digest": "runtime-manifest-digest-active"
                    }]
                },
                "model_catalog": [{
                    "id": "claude-sonnet-4.5",
                    "provider_id": "anthropic",
                    "model_type": "chat",
                    "max_output_tokens": 4096,
                    "supported_features": ["tools", "json_schema"],
                    "parameter_overrides": {
                        "tool_choice": "auto"
                    },
                    "removed_params": ["top_p"]
                }],
                "yaml": null
            })),
        )
            .into_response()
    }

    let app = Router::new().route("/v1/gateway/config/pull", get(pull_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock api");
    let addr = listener.local_addr().expect("mock api addr");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve mock api");
    });

    let sink = EventSink::from_config(EventSinkConfig {
        base_url: format!("http://{addr}"),
        api_token: "user-token".to_string(),
        gateway_service_token: Some("machine-token".to_string()),
    })
    .expect("event sink");
    let connected_read_model =
        SharedConnectedGatewayReadModel::new(None, Vec::new(), None, Vec::new(), None);
    let catalog_resolver = super::super::provider_catalog::CatalogBackedProviderResolver::new();
    let active_config = SharedGatewayConfig::new(LoadedDeclarativeConfig::empty());
    let reload_guard = Arc::new(tokio::sync::Mutex::new(()));

    refresh_connected_read_model_once(
        &sink,
        "runtime-eu-1",
        &None,
        &active_config,
        &connected_read_model,
        &catalog_resolver,
        &reload_guard,
    )
    .await
    .expect("refresh succeeds");

    let snapshot = connected_read_model.snapshot();
    assert_eq!(snapshot.region_key.as_deref(), Some("eu-sovereign"));
    assert_eq!(snapshot.publication_catalog.len(), 1);
    assert_eq!(
        snapshot.routing_compatibility[0]
            .primary_region_group_key
            .as_deref(),
        Some("eu")
    );
    assert_eq!(
        snapshot.routing_compatibility[0].readiness_state.as_deref(),
        Some("active")
    );
    assert_eq!(
        snapshot.routing_compatibility[0].auth_digest.as_deref(),
        Some("auth-digest-active")
    );
    assert_eq!(
        snapshot.routing_compatibility[0].policy_digest.as_deref(),
        Some("policy-digest-active")
    );
    assert_eq!(snapshot.routing_compatibility.len(), 1);
    assert_eq!(
        snapshot.routing_compatibility[0]
            .compatibility_digest
            .as_deref(),
        Some("compat-digest-active")
    );
    assert_eq!(
        snapshot.routing_compatibility[0]
            .runtime_manifest_digest
            .as_deref(),
        Some("runtime-manifest-digest-active")
    );
    assert!(snapshot
        .publication_catalog_last_successful_refresh_at
        .is_some());
    assert!(snapshot
        .routing_compatibility_last_successful_refresh_at
        .is_some());
    assert_eq!(snapshot.publication_catalog_status(Utc::now()), "fresh");
    assert_eq!(snapshot.routing_compatibility_status(Utc::now()), "fresh");
    let catalog_snapshot = catalog_resolver.cached_snapshot();
    assert_eq!(catalog_snapshot.models.len(), 1);
    assert_eq!(catalog_snapshot.models[0].id, "claude-sonnet-4.5");
    assert_eq!(catalog_snapshot.models[0].max_output_tokens, Some(4096));
    assert_eq!(
        catalog_snapshot.models[0].supported_features,
        vec!["tools".to_string(), "json_schema".to_string()]
    );
    assert_eq!(catalog_snapshot.models[0].removed_params, vec!["top_p"]);

    handle.abort();
}

#[tokio::test]
async fn refresh_connected_read_model_once_records_failure_without_clearing_catalog() {
    async fn pull_config() -> axum::response::Response {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": { "code": "boom" }
            })),
        )
            .into_response()
    }

    let app = Router::new().route("/v1/gateway/config/pull", get(pull_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock api");
    let addr = listener.local_addr().expect("mock api addr");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve mock api");
    });

    let sink = EventSink::from_config(EventSinkConfig {
        base_url: format!("http://{addr}"),
        api_token: "user-token".to_string(),
        gateway_service_token: Some("machine-token".to_string()),
    })
    .expect("event sink");
    let connected_read_model = SharedConnectedGatewayReadModel::new(
        Some("eu-sovereign".to_string()),
        vec![
            crate::runtime::ConnectedGatewayPublicationCatalogDescriptor {
                family_key: "eu".to_string(),
                publication_key: "pub_eu".to_string(),
                published_hostname: Some("pub123eu0001.ai.eu.verdictan.com".to_string()),
                publication_state: "published".to_string(),
                active_revision_id: Some("rev-active".to_string()),
                locality_mode: "region_pinned".to_string(),
                serving_fleet_class: "connected_cell_pool".to_string(),
                agent_id: None,
            },
        ],
        Some(Utc::now()),
        vec![
            crate::runtime::ConnectedGatewayRoutingCompatibilityDescriptor {
                publication_key: "pub_eu".to_string(),
                active_revision_id: Some("rev-active".to_string()),
                primary_region_group_key: Some("eu".to_string()),
                readiness_state: Some("active".to_string()),
                compatibility_digest: None,
                auth_digest: Some("auth-digest-active".to_string()),
                policy_digest: Some("policy-digest-active".to_string()),
                runtime_manifest_digest: None,
                active_revision_pool_membership_issue: None,
            },
        ],
        Some(Utc::now()),
    );
    let catalog_resolver = super::super::provider_catalog::CatalogBackedProviderResolver::new();
    let active_config = SharedGatewayConfig::new(LoadedDeclarativeConfig::empty());
    let reload_guard = Arc::new(tokio::sync::Mutex::new(()));

    let error = refresh_connected_read_model_once(
        &sink,
        "runtime-eu-1",
        &None,
        &active_config,
        &connected_read_model,
        &catalog_resolver,
        &reload_guard,
    )
    .await
    .expect_err("refresh should fail");
    assert!(error.to_string().contains("config pull failed"));

    let snapshot = connected_read_model.snapshot();
    assert_eq!(snapshot.region_key.as_deref(), Some("eu-sovereign"));
    assert_eq!(snapshot.publication_catalog.len(), 1);
    assert!(snapshot
        .publication_catalog_last_successful_refresh_at
        .is_some());
    assert!(snapshot.publication_catalog_last_refresh_error.is_some());
    assert!(snapshot
        .routing_compatibility_last_successful_refresh_at
        .is_some());
    assert!(snapshot.routing_compatibility_last_refresh_error.is_some());

    handle.abort();
}
