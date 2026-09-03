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
use axum::http::HeaderMap;
use serde_json::json;

async fn response_json(response: Response<Body>) -> serde_json::Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body bytes");
    serde_json::from_slice(&body).expect("response json")
}

async fn prepared_response_json(response: PreparedStreamingResponse) -> serde_json::Value {
    let body = collect_prepared_stream_body(response.body).await;
    serde_json::from_slice(&body).expect("prepared response json")
}

fn make_provider_target(
    id: &str,
    provider: &str,
    model: &str,
) -> super::super::providers::ProviderTarget {
    super::super::providers::ProviderTarget {
        id: id.into(),
        provider: provider.into(),
        model: model.into(),
        execution_target: None,
        mcp_bridge: None,
        description: None,
        base_url: "https://example.com".into(),
        api_key: String::new(),
        api_key_header: "Authorization".into(),
        api_key_prefix: "Bearer ".into(),
        secret_key_ref: None,
        path_template: None,
        headers: Default::default(),
        timeout: std::time::Duration::from_secs(30),
        stream_timeout: None,
        max_context_tokens: None,
        max_messages: None,
        data_policy: None,
        pricing: None,
        models: vec![],
        data_collection: None,
        zdr: false,
        region: None,
        quantizations: None,
        weight: None,
        provider_type: None,
        format: None,
        anthropic_version: None,
        aws_region: None,
        aws_profile: None,
        bedrock_model_family: None,
        watsonx_api_version: None,
        watsonx_project_id: None,
        watsonx_space_id: None,
        gcp_project: None,
        gcp_region: None,
        azure_api_version: None,
        azure_deployment: None,
        oauth2: None,
        health_probe: None,
        allow_insecure_tls: false,
        escalation_routing: None,
        required: false,
        data_residency: None,
        certifications: None,
    }
}

fn make_provider_model_entry(
    model_id: &str,
    enabled: bool,
) -> super::super::providers::ProviderModelEntry {
    super::super::providers::ProviderModelEntry {
        model_id: model_id.into(),
        aliases: vec![],
        enabled,
        pricing: None,
        supported_features: vec![],
        max_output_tokens: None,
        parameter_overrides: serde_json::Map::new(),
        removed_params: vec![],
        description: None,
        escalation_routing: None,
    }
}

fn make_runtime_routing_gateway_state() -> GatewayState {
    GatewayState {
        gateway_id: Some(Arc::from("gateway-routing-test")),
        crdt_replica_id: Arc::from("gateway-routing-test"),
        crdt_auth_client: None,
        crdt_auth_shutdown: None,
        runtime_registration_id: None,
        connected_read_model: Default::default(),
        catalog_resolver: super::super::provider_catalog::CatalogBackedProviderResolver::new(),
        source_config_path: None,
        upstream_base: "http://example.test".to_string(),
        upstream_auth: None,
        fail_mode: FailMode::Block,
        client: reqwest::Client::new(),
        api_base_url: None,
        admin_bearer_token: None,
        event_sink: None,
        mcp_sessions: crate::mcp::transport::streamable_http::StreamableHttpState::default(),
        crdt_sync_runtime: SharedCrdtSyncRuntime::default(),
        agent_context_service: None,
        history_service: None,
        admin_local_only: false,
        active_config: SharedGatewayConfig::new(LoadedDeclarativeConfig::empty()),
        rate_limiter: Arc::new(super::super::rate_limit::AdaptiveConcurrencyLimiter::new(
            "provider".to_string(),
            "scope".to_string(),
            32,
        )),
        provider_cache: Arc::new(super::super::cache::ProviderResponseCache::memory_for_test()),
        provider_metrics: Arc::new(super::super::provider_metrics::ProviderMetrics::new(60, 1)),
        global_rate_limiter: None,
        ip_rate_limiter: None,
        token_rate_limiter: None,
        size_limit: None,
        user_rate_limiter: None,
        key_rate_limiter: Arc::new(super::super::rate_limit::TokenRateLimiter::new()),
        key_request_tracker: Arc::new(
            super::super::token_rate_limit::TokenRequestTracker::default(),
        ),
        key_budget_tracker: Arc::new(super::super::token_rate_limit::TokenBudgetTracker::default()),
        ip_allowlist: None,
        ip_allowlist_trusted_proxies: Arc::new(Vec::new()),
        connected_mode: false,
        prometheus_sink: None,
        callback_router: None,
        distributed_state: None,
        token_validation_cache: Arc::new(
            super::super::token_validation_cache::TokenValidationCache::new(
                32,
                Duration::from_secs(2),
            ),
        ),
        gateway_runtime_metrics: Arc::new(GatewayRuntimeMetrics::default()),
        rollout_grade: true,
        rollout_grade_required: false,
        rollout_grade_reasons: Arc::new(Vec::new()),
        reload_guard: Arc::new(tokio::sync::Mutex::new(())),
        in_flight_tasks: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        admission_controller: super::super::admission_control::AdmissionController::new(
            None, None, None,
        ),
        health_monitor: Arc::new(super::super::health_monitor::ProviderHealthMonitor::new()),
        ai_usage_capture_config: Default::default(),
        mcp_outbox: Arc::new(crate::mcp::audit::McpOutboxHandle::from_env()),
    }
}

fn make_runtime_routing_state() -> ActiveGatewayStateView<'static> {
    let state = Box::leak(Box::new(make_runtime_routing_gateway_state()));
    ActiveGatewayStateView::from_state(state, LoadedDeclarativeConfig::empty())
}

fn sticky_routing_winner(state: &ActiveGatewayStateView<'_>, candidates: &[usize]) -> usize {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    state
        .session_id
        .as_deref()
        .expect("sticky routing requires a session_id")
        .hash(&mut hasher);
    state.gateway_id.hash(&mut hasher);
    state
        .request_finops
        .as_ref()
        .and_then(|finops| finops.org_id.as_ref())
        .hash(&mut hasher);
    state
        .request_finops
        .as_ref()
        .and_then(|finops| finops.key_id.as_ref())
        .hash(&mut hasher);
    (hasher.finish() as usize) % candidates.len()
}

#[derive(serde::Deserialize)]
struct TokenModelFilterHolder {
    #[serde(default, deserialize_with = "deserialize_token_model_filters")]
    model_filter: Vec<String>,
}

// ── derive_usage_category ─────────────────────────────────────────

#[test]
fn usage_category_export_source() {
    let meta = json!({"source": "export"});
    assert_eq!(derive_usage_category(&meta, None, None), "exports");
}

#[test]
fn usage_category_policy_processing_source() {
    let meta = json!({"source": "policy_processing"});
    assert_eq!(
        derive_usage_category(&meta, None, None),
        "policy_processing"
    );
}

#[test]
fn usage_category_workflow_id_present() {
    let meta = json!({});
    assert_eq!(
        derive_usage_category(&meta, Some("wf-1"), None),
        "workflows"
    );
}

#[test]
fn usage_category_agent_id_present() {
    let meta = json!({});
    assert_eq!(derive_usage_category(&meta, None, Some("ag-1")), "agents");
}

#[test]
fn usage_category_default_gateway_llm() {
    let meta = json!({});
    assert_eq!(derive_usage_category(&meta, None, None), "gateway_llm");
}

#[test]
fn mcp_client_prefers_publication_region_group_over_gateway_region_key() {
    let gateway_state = Box::leak(Box::new(make_runtime_routing_gateway_state()));
    gateway_state.api_base_url = Some("https://api.verdictan.test".to_string());
    let mut state =
        ActiveGatewayStateView::from_state(gateway_state, LoadedDeclarativeConfig::empty());
    state.region_key = Some("us-east".to_string());
    let publication_key = format!("{}{}", "fixture-publication-", "01");
    state.current_publication = Some(crate::runtime::ConnectedGatewayPublicationDescriptor {
        family_key: "family-1".to_string(),
        publication_key,
        published_hostname: Some("managed-public.ai.eu.verdictan.com".to_string()),
        publication_state: "published".to_string(),
        active_revision_id: Some("rev-1".to_string()),
        active_revision_readiness_state: Some("ready".to_string()),
        active_revision_auth_digest: Some("auth-digest".to_string()),
        active_revision_policy_digest: Some("policy-digest".to_string()),
        active_revision_pool_membership_issue: None,
        locality_mode: "region_pinned".to_string(),
        serving_fleet_class: "connected_cell_pool".to_string(),
        primary_region_group_key: Some("eu".to_string()),
    });

    let client = build_gateway_mcp_client(
        gateway_state,
        &state,
        "vdt_valid_token",
        "req-1",
        "00-00000000000000000000000000000000-0000000000000000-01",
    )
    .expect("mcp client");
    assert_eq!(client.region(), Some("eu"));
}

#[tokio::test]
async fn mcp_post_requires_published_hostname_context() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer vdt_valid"),
    );

    let mut config = LoadedDeclarativeConfig::empty();
    config.mcp_server = Some(super::super::declarative_config::McpServerConfig {
        enabled: Some(true),
        path: None,
        allowed_tools: None,
        allowed_resources: None,
        max_request_body_bytes: None,
        auth_mode: None,
        default_capture_mode: None,
        session_limits: None,
        tool_servers: None,
    });
    let mut state = make_runtime_routing_gateway_state();
    state.active_config = SharedGatewayConfig::new(config);

    let response = mcp_post(
        State(state),
        ConnectInfo(([127, 0, 0, 1], 3100).into()),
        headers,
        Request::builder()
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                }))
                .expect("json body"),
            ))
            .expect("request"),
    )
    .await
    .expect("mcp response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response_json(response).await;
    assert_eq!(body["error"]["code"], "mcp_publication_required");
}

fn crdt_entry_fields(
    content: &str,
    repo: &str,
    branch: &str,
    schema_key: &str,
) -> BTreeMap<String, serde_json::Value> {
    BTreeMap::from([
        ("content".to_string(), json!(content)),
        ("repo".to_string(), json!(repo)),
        ("branch".to_string(), json!(branch)),
        ("schema_key".to_string(), json!(schema_key)),
        ("topic".to_string(), json!("schema")),
    ])
}

const CRDT_TEST_PEER_GATEWAY_ID: &str = "peer-gateway";

fn crdt_multi_gateway_context_fabric() -> super::super::declarative_config::ContextFabricConfig {
    super::super::declarative_config::ContextFabricConfig {
        multi_gateway: Some(
            super::super::declarative_config::ContextFabricMultiGatewayConfig {
                enabled: Some(true),
                peers: Some(vec![
                    super::super::declarative_config::ContextFabricPeerConfig {
                        gateway_id: CRDT_TEST_PEER_GATEWAY_ID.to_string(),
                        endpoint: "http://127.0.0.1:1/internal/crdt/sync".to_string(),
                    },
                ]),
                // Keep the retry worker idle so the test never depends on timing.
                sync_interval_ms: Some(3_600_000),
                max_partition_buffer_age: Some("24h".to_string()),
            },
        ),
        ..Default::default()
    }
}

async fn crdt_peer_envelope_bytes(entry_id: &str, content: &str) -> Vec<u8> {
    let peer_state = Arc::new(tokio::sync::RwLock::new(
        super::super::crdt::ContextCrdt::new(CRDT_TEST_PEER_GATEWAY_ID).expect("peer replica"),
    ));
    let peer_driver = super::super::crdt_sync::CrdtSyncDriver::new(
        peer_state,
        super::super::crdt_sync::PeerSyncConfig::default(),
    )
    .expect("peer sync driver");
    peer_driver
        .apply_local_mutation(super::super::crdt::CrdtMutation::UpsertEntry {
            entry_id: entry_id.to_string(),
            fields: crdt_entry_fields(content, "verdictan", "feature/a", "users"),
            now_ms: Some(10_000),
        })
        .await
        .expect("local mutation")
        .expect("sync envelope")
        .encode()
        .expect("encoded envelope")
}

#[tokio::test]
async fn crdt_sync_post_merges_authenticated_peer_state_when_enabled() {
    let jwks_server = crate::testing::gateway_jwt::start_jwks_server().await;
    let state = make_runtime_routing_gateway_state();
    let auth_client = Arc::new(super::super::jwt_auth::GatewayAuthClient::new(
        "opaque-token".to_string(),
        jwks_server.url(),
        "org-1".to_string(),
        state.crdt_replica_id.to_string(),
    ));
    auth_client.refresh_jwks().await.expect("peer jwks");

    state.connected_read_model.record_peer_gateway_refresh(
        vec![crate::runtime::PeerGatewayDescriptor {
            agent_id: "agent-1".to_string(),
            gateway_id: CRDT_TEST_PEER_GATEWAY_ID.to_string(),
            relay_endpoint: None,
            readiness: "ready".to_string(),
            region: None,
        }],
        chrono::Utc::now(),
    );
    state
        .crdt_sync_runtime
        .replace(
            state.crdt_replica_id.as_ref(),
            Some(&crdt_multi_gateway_context_fabric()),
            Some(auth_client),
            Some(state.connected_read_model.clone()),
        )
        .expect("enable crdt sync");

    let mut claims = crate::testing::gateway_jwt::machine_claims_for_test(
        super::super::jwt_auth::OneOrMany::One(super::super::jwt_auth::gateway_audience(
            state.crdt_replica_id.as_ref(),
        )),
        crate::testing::gateway_jwt::unix_now() + 300,
        "org-1",
        "jti-crdt-sync",
    );
    claims.scope = "gateway:crdt:sync".to_string();
    claims.gateway_id = Some(CRDT_TEST_PEER_GATEWAY_ID.to_string());
    let peer_token = crate::testing::gateway_jwt::sign_machine_token(
        &claims,
        Some(crate::testing::gateway_jwt::TEST_RSA_KID),
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {peer_token}").parse().expect("auth header"),
    );

    let envelope = crdt_peer_envelope_bytes("schema-users", "users schema").await;
    let response = crdt_sync_post(State(state.clone()), headers, Bytes::from(envelope)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["replica_id"], "gateway-routing-test");
    assert_eq!(body["state_changed"], true);

    let driver = state
        .crdt_sync_runtime
        .current()
        .expect("runtime driver should exist");
    let local_state = driver.state();
    let replica = local_state.read().await;
    let entry = replica
        .get_local_entry("schema-users")
        .expect("merged entry should exist");
    assert_eq!(entry.field_str("content"), Some("users schema"));
}

#[tokio::test]
async fn crdt_sync_post_refuses_ingress_when_peer_authenticator_is_missing() {
    let state = make_runtime_routing_gateway_state();
    // `build_crdt_sync_driver` now refuses this combination, so the unauthenticated driver is
    // installed directly to prove the ingress handler also refuses it.
    let driver = super::super::crdt_sync::CrdtSyncDriver::new(
        Arc::new(tokio::sync::RwLock::new(
            super::super::crdt::ContextCrdt::new(state.crdt_replica_id.as_ref())
                .expect("local replica"),
        )),
        super::super::crdt_sync::PeerSyncConfig {
            enabled: true,
            ..Default::default()
        },
    )
    .expect("unauthenticated sync driver");
    let local_state = driver.state();
    {
        let mut guard = state
            .crdt_sync_runtime
            .inner
            .write()
            .expect("crdt sync runtime lock");
        *guard = Some(Arc::new(driver));
    }

    let envelope = crdt_peer_envelope_bytes("schema-users", "users schema").await;
    let response = crdt_sync_post(
        State(state.clone()),
        HeaderMap::new(),
        Bytes::from(envelope),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response_json(response).await;
    assert_eq!(body["code"], "crdt_sync_authenticator_unavailable");

    let replica = local_state.read().await;
    assert_eq!(replica.state().visible_len(), 0);
    assert!(replica.get_local_entry("schema-users").is_none());
}

#[test]
fn build_crdt_sync_driver_requires_peer_authenticator_when_multi_gateway_is_enabled() {
    let error = build_crdt_sync_driver(
        "gateway-routing-test",
        Some(&crdt_multi_gateway_context_fabric()),
        None,
        None,
    )
    .map(|driver| driver.is_some())
    .expect_err("enabled multi-gateway sync must require peer authentication material");
    let message = error.to_string();
    assert!(
        message.contains("CRDT peer authentication material"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("Restart the gateway"),
        "unexpected error: {message}"
    );
}

#[test]
fn build_crdt_sync_driver_returns_none_when_multi_gateway_is_disabled() {
    let context_fabric = super::super::declarative_config::ContextFabricConfig {
        multi_gateway: Some(
            super::super::declarative_config::ContextFabricMultiGatewayConfig {
                enabled: Some(false),
                ..Default::default()
            },
        ),
        ..Default::default()
    };
    let driver = build_crdt_sync_driver("gateway-routing-test", Some(&context_fabric), None, None)
        .expect("disabled multi-gateway sync must not fail");
    assert!(driver.is_none());
}

#[tokio::test]
async fn crdt_sync_post_returns_not_found_when_disabled() {
    let response = crdt_sync_post(
        State(make_runtime_routing_gateway_state()),
        HeaderMap::new(),
        Bytes::from_static(b"payload"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response_json(response).await;
    assert_eq!(body["code"], "crdt_sync_disabled");
}

#[test]
fn usage_category_empty_workflow_id_falls_through() {
    let meta = json!({});
    assert_eq!(derive_usage_category(&meta, Some(""), None), "gateway_llm");
}

// ── normalize_request_agent_id ──────────────────────────────────────

#[test]
fn agent_id_none_returns_none() {
    assert_eq!(normalize_request_agent_id(None).unwrap(), None);
}

#[test]
fn agent_id_empty_returns_none() {
    assert_eq!(normalize_request_agent_id(Some("  ")).unwrap(), None);
}

#[test]
fn agent_id_valid_returned_trimmed() {
    assert_eq!(
        normalize_request_agent_id(Some("  my-agent-1  ")).unwrap(),
        Some("my-agent-1".to_string())
    );
}

#[test]
fn agent_id_too_long_rejected() {
    let long = "a".repeat(129);
    assert!(normalize_request_agent_id(Some(&long)).is_err());
}

#[test]
fn agent_id_invalid_chars_rejected() {
    assert!(normalize_request_agent_id(Some("agent@bad")).is_err());
}

// ── validated_key_gateway_binding / validated_key_agent_binding ──────

#[test]
fn gateway_binding_from_personal_gateway_id() {
    let meta = json!({"personal_gateway_id": "gw-123"});
    assert_eq!(validated_key_gateway_binding(&meta), Some("gw-123"));
}

#[test]
fn gateway_binding_falls_back_to_gateway_id() {
    let meta = json!({"gateway_id": "gw-456"});
    assert_eq!(validated_key_gateway_binding(&meta), Some("gw-456"));
}

#[test]
fn gateway_binding_none_when_empty() {
    let meta = json!({"personal_gateway_id": " "});
    assert_eq!(validated_key_gateway_binding(&meta), None);
}

#[test]
fn agent_binding_extracts_agent_id() {
    let meta = json!({"agent_id": "ag-1"});
    assert_eq!(validated_key_agent_binding(&meta), Some("ag-1"));
}

#[test]
fn agent_binding_none_when_missing() {
    let meta = json!({});
    assert_eq!(validated_key_agent_binding(&meta), None);
}

// ── normalize_optional_text ─────────────────────────────────────────

#[test]
fn optional_text_trims_and_returns() {
    assert_eq!(
        normalize_optional_text(Some("  hello  ")),
        Some("hello".to_string())
    );
}

#[test]
fn optional_text_empty_returns_none() {
    assert_eq!(normalize_optional_text(Some("  ")), None);
    assert_eq!(normalize_optional_text(None), None);
}

// ── deserialize_token_model_filters ────────────────────────────────

#[test]
fn token_model_filter_deserializer_trims_strings_lists_and_nulls() {
    let single: TokenModelFilterHolder =
        serde_json::from_value(json!({"model_filter": "  gpt-4o-mini  "}))
            .expect("single string model filter");
    assert_eq!(single.model_filter, vec!["gpt-4o-mini"]);

    let many: TokenModelFilterHolder = serde_json::from_value(json!({
        "model_filter": [" gpt-4o-mini ", "", "gpt-5"]
    }))
    .expect("many model filters");
    assert_eq!(many.model_filter, vec!["gpt-4o-mini", "gpt-5"]);

    let empty_single: TokenModelFilterHolder =
        serde_json::from_value(json!({"model_filter": "   "})).expect("empty single model filter");
    assert!(empty_single.model_filter.is_empty());

    let null_value: TokenModelFilterHolder =
        serde_json::from_value(json!({"model_filter": null})).expect("null model filter");
    assert!(null_value.model_filter.is_empty());
}

// ── normalize_text_scope_values ─────────────────────────────────────

#[test]
fn text_scope_deduplicates_and_sorts() {
    let values = vec![
        " b ".to_string(),
        "a".to_string(),
        "b".to_string(),
        "".to_string(),
    ];
    assert_eq!(normalize_text_scope_values(&values), vec!["a", "b"]);
}

// ── intersect_scope_values ──────────────────────────────────────────

#[test]
fn intersect_both_empty_returns_empty() {
    let result = intersect_scope_values(&[], &[], normalize_text_scope_values);
    assert!(result.is_empty());
}

#[test]
fn intersect_one_empty_returns_other() {
    let result = intersect_scope_values(&["a".to_string()], &[], normalize_text_scope_values);
    assert_eq!(result, vec!["a"]);
}

#[test]
fn intersect_both_present_returns_common() {
    let result = intersect_scope_values(
        &["a".to_string(), "b".to_string()],
        &["b".to_string(), "c".to_string()],
        normalize_text_scope_values,
    );
    assert_eq!(result, vec!["b"]);
}

// ── extract_trace_correlation ───────────────────────────────────────

#[test]
fn trace_correlation_from_verdictan_trace() {
    let body = json!({
        "verdictan": {
            "trace": {
                "evaluation_id": "eval-1",
                "test_case_id": "tc-1"
            }
        }
    });
    let tc = extract_trace_correlation(&body);
    assert_eq!(tc.evaluation_id.as_deref(), Some("eval-1"));
    assert_eq!(tc.test_case_id.as_deref(), Some("tc-1"));
}

#[test]
fn trace_correlation_empty_when_absent() {
    let body = json!({"messages": []});
    let tc = extract_trace_correlation(&body);
    assert!(tc.is_empty());
}

// ── extract_request_telemetry_hints ─────────────────────────────────

#[test]
fn telemetry_hints_nested_prompt_label() {
    let body = json!({
        "verdictan": {
            "prompt": {"label": "my-prompt"},
            "test": {"index": 3}
        }
    });
    let hints = extract_request_telemetry_hints(&body);
    assert_eq!(hints.prompt_label.as_deref(), Some("my-prompt"));
    assert_eq!(hints.test_index, Some(3));
}

#[test]
fn telemetry_hints_flat_keys() {
    let body = json!({
        "verdictan": {
            "prompt_label": "flat-label",
            "test_index": 7
        }
    });
    let hints = extract_request_telemetry_hints(&body);
    assert_eq!(hints.prompt_label.as_deref(), Some("flat-label"));
    assert_eq!(hints.test_index, Some(7));
}

// ── extract_request_team_slugs ──────────────────────────────────────

#[test]
fn team_slugs_comma_separated() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-team",
        "team-a, team-b,  team-c".parse().unwrap(),
    );
    let slugs = extract_request_team_slugs(&headers);
    assert_eq!(slugs, vec!["team-a", "team-b", "team-c"]);
}

#[test]
fn team_slugs_empty_when_absent() {
    let headers = HeaderMap::new();
    assert!(extract_request_team_slugs(&headers).is_empty());
}

// ── ingress_marks_managed_public_endpoint ───────────────────────────

#[test]
fn ingress_marker_true_variants() {
    for value in ["1", "true", "yes", "managed", " True ", " MANAGED "] {
        let mut headers = HeaderMap::new();
        headers.insert("x-verdictan-public-endpoint", value.parse().unwrap());
        assert!(
            ingress_marks_managed_public_endpoint(&headers),
            "expected true for {value:?}"
        );
    }
}

#[test]
fn ingress_marker_false_when_absent_or_other() {
    let headers = HeaderMap::new();
    assert!(!ingress_marks_managed_public_endpoint(&headers));

    let mut headers = HeaderMap::new();
    headers.insert("x-verdictan-public-endpoint", "no".parse().unwrap());
    assert!(!ingress_marks_managed_public_endpoint(&headers));
}

#[test]
fn strip_managed_public_ingress_headers_removes_all_marks() {
    let mut headers = HeaderMap::new();
    headers.insert("x-verdictan-public-endpoint", "true".parse().unwrap());
    headers.insert(
        "x-verdictan-public-hostname",
        "host.example".parse().unwrap(),
    );
    headers.insert("x-verdictan-requested-region-group", "eu".parse().unwrap());
    headers.insert("x-verdictan-endpoint-scope", "regional".parse().unwrap());
    headers.insert("authorization", "Bearer keep".parse().unwrap());

    strip_managed_public_ingress_headers(&mut headers);

    assert!(!has_managed_public_ingress_headers(&headers));
    assert!(headers.contains_key("authorization"));
    assert!(!ingress_marks_managed_public_endpoint(&headers));
}

// ── normalize_managed_public_endpoint_host ──────────────────────────

#[test]
fn endpoint_host_strips_port() {
    assert_eq!(
        normalize_managed_public_endpoint_host("Example.com:8080"),
        Some("example.com".to_string())
    );
}

#[test]
fn endpoint_host_strips_trailing_dot() {
    assert_eq!(
        normalize_managed_public_endpoint_host("example.com."),
        Some("example.com".to_string())
    );
}

#[test]
fn endpoint_host_empty_returns_none() {
    assert_eq!(normalize_managed_public_endpoint_host("  "), None);
}

// ── publication_state_accepts_public_traffic ────────────────────────

#[test]
fn publication_state_accepts_published_and_draining() {
    assert!(publication_state_accepts_public_traffic("published"));
    assert!(publication_state_accepts_public_traffic("draining"));
    assert!(publication_state_accepts_public_traffic("  Published  "));
    assert!(!publication_state_accepts_public_traffic("draft"));
}

// ── is_api_token ────────────────────────────────────────────────────

#[test]
fn api_token_prefix_valid() {
    assert!(is_api_token("vdt_abc123"));
}

#[test]
fn api_token_gk_prefix_valid() {
    assert!(is_api_token("vdt_gk_abc123"));
}

#[test]
fn api_token_other_prefix_rejected() {
    assert!(!is_api_token("sk_abc123"));
}

// ── extract_bearer_token ────────────────────────────────────────────

#[test]
fn bearer_token_extracted() {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Bearer vdt_test_token".parse().unwrap());
    assert_eq!(
        extract_bearer_token(&headers),
        Some("vdt_test_token".to_string())
    );
}

#[test]
fn bearer_lowercase_extracted() {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", "bearer vdt_test".parse().unwrap());
    assert_eq!(extract_bearer_token(&headers), Some("vdt_test".to_string()));
}

#[test]
fn bearer_missing_returns_none() {
    let headers = HeaderMap::new();
    assert_eq!(extract_bearer_token(&headers), None);
}

// ── runtime_error_id ────────────────────────────────────────────────

#[test]
fn error_id_strips_req_prefix() {
    assert_eq!(runtime_error_id("req_abc"), "err_abc");
}

#[test]
fn error_id_without_prefix() {
    assert_eq!(runtime_error_id("plain"), "err_plain");
}

// ── parse_runtime_cache_ttl ─────────────────────────────────────────

#[test]
fn cache_ttl_seconds_suffix() {
    assert_eq!(
        parse_runtime_cache_ttl("30s").unwrap(),
        Duration::from_secs(30)
    );
}

#[test]
fn cache_ttl_minutes_suffix() {
    assert_eq!(
        parse_runtime_cache_ttl("5m").unwrap(),
        Duration::from_secs(300)
    );
}

#[test]
fn cache_ttl_hours_suffix() {
    assert_eq!(
        parse_runtime_cache_ttl("1h").unwrap(),
        Duration::from_secs(3600)
    );
}

#[test]
fn cache_ttl_bare_integer() {
    assert_eq!(
        parse_runtime_cache_ttl("60").unwrap(),
        Duration::from_secs(60)
    );
}

#[test]
fn cache_ttl_empty_rejected() {
    assert!(parse_runtime_cache_ttl("").is_err());
}

// ── normalize_runtime_plugin_id ─────────────────────────────────────

#[test]
fn plugin_id_normalizes() {
    assert_eq!(
        normalize_runtime_plugin_id("My_Plugin ").unwrap(),
        "my-plugin"
    );
}

#[test]
fn plugin_id_empty_rejected() {
    assert!(normalize_runtime_plugin_id("").is_err());
}

#[test]
fn plugin_id_special_chars_rejected() {
    assert!(normalize_runtime_plugin_id("bad@plugin").is_err());
}

// ── normalize_runtime_data_collection ───────────────────────────────

#[test]
fn data_collection_allow_and_deny() {
    assert_eq!(normalize_runtime_data_collection("Allow").unwrap(), "allow");
    assert_eq!(normalize_runtime_data_collection("DENY").unwrap(), "deny");
}

#[test]
fn data_collection_invalid_rejected() {
    assert!(normalize_runtime_data_collection("maybe").is_err());
}

// ── resolve_runtime_request_settings ────────────────────────────────

#[test]
fn runtime_request_settings_reject_session_hint_when_disabled() {
    let mut state = make_runtime_routing_state();
    state
        .runtime_routing_settings
        .cache_defaults
        .allow_session_id = false;

    let mut headers = HeaderMap::new();
    headers.insert("x-session-id", "session-1".parse().unwrap());

    let mut body = json!({});
    let error = resolve_runtime_request_settings(&mut state, &headers, &mut body)
        .expect_err("disabled session hints must fail closed");

    assert_eq!(error.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error.code(), "session_id_not_allowed");
}

#[test]
fn runtime_request_settings_reject_mismatched_session_hints() {
    let mut state = make_runtime_routing_state();

    let mut headers = HeaderMap::new();
    headers.insert("x-session-id", "header-session".parse().unwrap());

    let mut body = json!({
        "session_id": "body-session"
    });
    let error = resolve_runtime_request_settings(&mut state, &headers, &mut body)
        .expect_err("mismatched session hints must fail closed");

    assert_eq!(error.code(), "session_id_mismatch");
}

#[test]
fn runtime_request_settings_reject_cache_control_when_disabled() {
    let mut state = make_runtime_routing_state();
    state
        .runtime_routing_settings
        .cache_defaults
        .allow_cache_control = false;

    let mut body = json!({
        "cache_control": {
            "type": "ephemeral"
        }
    });
    let error = resolve_runtime_request_settings(&mut state, &HeaderMap::new(), &mut body)
        .expect_err("disabled cache control hints must fail closed");

    assert_eq!(error.code(), "cache_control_not_allowed");
}

#[test]
fn runtime_request_settings_reject_non_ephemeral_cache_type() {
    let mut state = make_runtime_routing_state();

    let mut body = json!({
        "cache_control": {
            "type": "persistent"
        }
    });
    let error = resolve_runtime_request_settings(&mut state, &HeaderMap::new(), &mut body)
        .expect_err("unsupported cache types must fail closed");

    assert_eq!(error.code(), "invalid_cache_control_type");
}

#[test]
fn runtime_request_settings_reject_governed_plugin_overrides() {
    let mut state = make_runtime_routing_state();
    state.runtime_routing_settings.plugin_governance.defaults = vec![RuntimePluginSetting {
        id: "pdf-inputs".to_string(),
        enabled: true,
        options: Some(json!({"mode": "safe"})),
    }];
    state
        .runtime_routing_settings
        .plugin_governance
        .prevent_overrides = vec!["pdf-inputs".to_string()];

    let mut body = json!({
        "plugins": [{
            "id": "pdf-inputs",
            "enabled": false,
            "options": { "mode": "unsafe" }
        }]
    });
    let error = resolve_runtime_request_settings(&mut state, &HeaderMap::new(), &mut body)
        .expect_err("governed plugin overrides must fail closed");

    assert_eq!(error.code(), "plugin_override_forbidden");
    assert!(error.browser_safe_message().contains("pdf-inputs"));
}

#[test]
fn runtime_request_settings_reject_explicit_web_search_under_privacy_policy() {
    let mut state = make_runtime_routing_state();

    let mut body = json!({
        "provider": {
            "data_collection": "deny"
        },
        "plugins": [{
            "id": "web-search",
            "enabled": true
        }]
    });
    let error = resolve_runtime_request_settings(&mut state, &HeaderMap::new(), &mut body)
        .expect_err("privacy-restricted requests must fail closed on web-search");

    assert_eq!(error.code(), "privacy_incompatible_plugin");
}

#[test]
fn runtime_request_settings_reject_forced_web_search_under_privacy_policy() {
    let mut state = make_runtime_routing_state();
    state.runtime_routing_settings.plugin_governance.forced_on = vec![RuntimePluginSetting {
        id: "web-search".to_string(),
        enabled: true,
        options: None,
    }];

    let mut body = json!({
        "provider": {
            "zdr": true
        }
    });
    let error = resolve_runtime_request_settings(&mut state, &HeaderMap::new(), &mut body)
        .expect_err("forced privacy-incompatible plugins must fail closed");

    assert_eq!(error.code(), "privacy_incompatible_plugin");
}

#[test]
fn runtime_request_settings_reject_plugins_when_silent_engine_is_enabled() {
    let mut state = make_runtime_routing_state();
    state.silent_engine = Some(super::super::declarative_config::SilentEngineConfig {
        enabled: true,
        ..Default::default()
    });

    let mut body = json!({
        "plugins": [{
            "id": "pdf-inputs",
            "enabled": true
        }]
    });
    let error = resolve_runtime_request_settings(&mut state, &HeaderMap::new(), &mut body)
        .expect_err("silent engine must fail closed when plugins are requested");

    assert_eq!(error.code(), "silent_engine_plugin_incompatible");
}

// ── runtime_routing_filter_targets ──────────────────────────────────

#[test]
fn runtime_routing_filter_targets_rejects_when_privacy_filter_removes_all_targets() {
    let mut state = make_runtime_routing_state();
    state.runtime_privacy_restricted = true;

    let mut collecting = make_provider_target("collecting", "openai", "gpt-5.4-mini");
    collecting.data_collection = Some(super::super::providers::DataCollectionPolicy::Allow);
    collecting.zdr = true;

    let mut retaining = make_provider_target("retaining", "openai", "gpt-5.4-mini");
    retaining.data_collection = Some(super::super::providers::DataCollectionPolicy::Deny);

    let targets = vec![collecting, retaining];
    let error = runtime_routing_filter_targets(&state, &targets, &[0, 1], "req-privacy")
        .expect_err("privacy filter should fail closed when no target is eligible");

    assert_eq!(error.code(), "routing.no_eligible_provider");
}

#[test]
fn runtime_routing_filter_targets_applies_privacy_filter_before_sticky_routing() {
    let mut state = make_runtime_routing_state();
    state.runtime_privacy_restricted = true;
    state.runtime_allow_fallbacks = true;
    state.session_id = Some("sticky-session".to_string());
    state.request_finops = Some(RequestFinopsContext {
        org_id: Some("org-1".to_string()),
        key_id: Some("key-1".to_string()),
        ..Default::default()
    });

    let mut first = make_provider_target("first", "openai", "gpt-5.4-mini");
    first.data_collection = Some(super::super::providers::DataCollectionPolicy::Deny);
    first.zdr = true;

    let mut filtered_out = make_provider_target("filtered-out", "openai", "gpt-5.4-mini");
    filtered_out.data_collection = Some(super::super::providers::DataCollectionPolicy::Allow);
    filtered_out.zdr = true;

    let mut second = make_provider_target("second", "openai", "gpt-5.4-mini");
    second.data_collection = Some(super::super::providers::DataCollectionPolicy::Deny);
    second.data_policy = Some(super::super::providers::DataPolicy {
        zero_data_retention: true,
        training_opt_out: true,
        retention_days: Some(0),
        ..Default::default()
    });

    let targets = vec![first, filtered_out, second];
    let eligible = vec![0_usize, 2_usize];
    let expected_first = eligible[sticky_routing_winner(&state, &eligible)];

    let filtered = runtime_routing_filter_targets(&state, &targets, &[0, 1, 2], "req-sticky")
        .expect("eligible privacy-safe targets should remain routable");

    assert_eq!(filtered.len(), 2);
    assert_eq!(filtered[0], expected_first);
    assert!(!filtered.contains(&1));
    assert_eq!(
        filtered
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
        eligible.into_iter().collect()
    );
}

// ── gateway_identity_matches_candidate ──────────────────────────────

#[test]
fn gateway_identity_matches_registration_id() {
    assert!(gateway_identity_matches_candidate(
        "gw-1",
        Some("gw-1"),
        None
    ));
}

#[test]
fn gateway_identity_matches_gateway_id() {
    assert!(gateway_identity_matches_candidate(
        "gw-1",
        None,
        Some("gw-1")
    ));
}

#[test]
fn gateway_identity_empty_candidate_no_match() {
    assert!(!gateway_identity_matches_candidate("", Some("gw-1"), None));
}

// ── admitted_member_status_allows_public_traffic ─────────────────────

#[test]
fn admitted_member_all_true_allows_traffic() {
    let member = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(
        r#"{"admitted": true, "healthy": true, "status": "active"}"#,
    )
    .unwrap();
    assert!(admitted_member_status_allows_public_traffic(&member));
}

#[test]
fn admitted_member_explicit_false_blocks_traffic() {
    let member = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(
        r#"{"admitted": false}"#,
    )
    .unwrap();
    assert!(!admitted_member_status_allows_public_traffic(&member));
}

#[test]
fn admitted_member_bad_status_blocks_traffic() {
    let member = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(
        r#"{"status": "draining"}"#,
    )
    .unwrap();
    assert!(!admitted_member_status_allows_public_traffic(&member));
}

// ── telemetry_verdictan_metadata ───────────────────────────────────

#[test]
fn telemetry_metadata_with_prompt_label() {
    let hints = RequestTelemetryHints {
        prompt_label: Some("my-prompt".to_string()),
        test_index: None,
    };
    let map = telemetry_verdictan_metadata(&hints).unwrap();
    assert_eq!(
        map.get("prompt_label").and_then(|v| v.as_str()),
        Some("my-prompt")
    );
}

#[test]
fn telemetry_metadata_none_when_empty() {
    let hints = RequestTelemetryHints {
        prompt_label: None,
        test_index: None,
    };
    assert!(telemetry_verdictan_metadata(&hints).is_none());
}

// ── serving_fleet_class_requires_public_pool_membership ─────────────

#[test]
fn fleet_class_connected_cell_pool_requires_membership() {
    assert!(serving_fleet_class_requires_public_pool_membership(
        "connected_cell_pool"
    ));
    assert!(serving_fleet_class_requires_public_pool_membership(
        " Connected_Cell_Pool "
    ));
    assert!(!serving_fleet_class_requires_public_pool_membership(
        "standard"
    ));
}

// ── canonical_runtime_execution_surface ──────────────────────────────

#[test]
fn execution_surface_runner_session_variants() {
    assert_eq!(
        canonical_runtime_execution_surface(Some("runner_session"), None),
        "runner_session"
    );
    assert_eq!(
        canonical_runtime_execution_surface(Some("gateway_execution_session"), None),
        "runner_session"
    );
}

#[test]
fn execution_surface_interactive_chat_variants() {
    assert_eq!(
        canonical_runtime_execution_surface(Some("interactive_chat"), None),
        "interactive_chat"
    );
    assert_eq!(
        canonical_runtime_execution_surface(Some("gateway"), None),
        "interactive_chat"
    );
}

#[test]
fn execution_surface_none_with_session_id() {
    assert_eq!(
        canonical_runtime_execution_surface(None, Some("session-1")),
        "runner_session"
    );
}

#[test]
fn execution_surface_none_without_session_id() {
    assert_eq!(
        canonical_runtime_execution_surface(None, None),
        "interactive_chat"
    );
}

#[test]
fn execution_surface_empty_string_treated_as_none() {
    assert_eq!(
        canonical_runtime_execution_surface(Some("  "), None),
        "interactive_chat"
    );
}

// ── normalize_optional_string_value ──────────────────────────────────

#[test]
fn optional_string_value_extracts_trimmed() {
    let value = serde_json::Value::String("  hello  ".to_string());
    assert_eq!(
        normalize_optional_string_value(Some(&value)),
        Some("hello".to_string())
    );
}

#[test]
fn optional_string_value_none_for_empty() {
    let value = serde_json::Value::String("  ".to_string());
    assert_eq!(normalize_optional_string_value(Some(&value)), None);
}

#[test]
fn optional_string_value_none_for_non_string() {
    let value = serde_json::Value::Number(42.into());
    assert_eq!(normalize_optional_string_value(Some(&value)), None);
}

#[test]
fn optional_string_value_none_when_absent() {
    assert_eq!(normalize_optional_string_value(None), None);
}

// ── parse_expiry_timestamp ───────────────────────────────────────────

#[test]
fn expiry_timestamp_valid_rfc3339() {
    let result = parse_expiry_timestamp(Some("2025-01-15T12:00:00Z"));
    assert!(result.is_some());
    assert_eq!(result.unwrap().timestamp(), 1736942400);
}

#[test]
fn expiry_timestamp_none_when_absent() {
    assert!(parse_expiry_timestamp(None).is_none());
}

#[test]
fn expiry_timestamp_none_for_invalid_string() {
    assert!(parse_expiry_timestamp(Some("not-a-date")).is_none());
}

// ── non_empty_str ───────────────────────────────────────────────────

#[test]
fn non_empty_str_trims_and_returns() {
    assert_eq!(non_empty_str(Some("  hello  ")), Some("hello"));
}

#[test]
fn non_empty_str_returns_none_for_whitespace() {
    assert_eq!(non_empty_str(Some("   ")), None);
}

#[test]
fn non_empty_str_returns_none_for_none() {
    assert_eq!(non_empty_str(None), None);
}

// ── default_* helpers ───────────────────────────────────────────────

#[test]
fn default_true_returns_true() {
    assert!(default_true());
}

#[test]
fn default_data_collection_is_allow() {
    assert_eq!(default_data_collection_allow(), "allow");
}

#[test]
fn default_session_header_is_x_session_id() {
    assert_eq!(default_session_header_name(), "x-session-id");
}

#[test]
fn default_shadow_evaluation_mode_is_asynchronous() {
    assert_eq!(default_shadow_evaluation_mode(), "asynchronous");
}

#[test]
fn default_shadow_capture_mode_is_metadata_only() {
    assert_eq!(default_shadow_capture_mode(), "metadata_only");
}

#[test]
fn default_runtime_provider_policy_has_expected_values() {
    let policy = default_runtime_provider_policy();
    assert!(policy.allow_fallbacks);
    assert!(policy.require_parameters);
    assert_eq!(policy.data_collection, "allow");
    assert!(!policy.zdr);
}

#[test]
fn default_runtime_cache_defaults_has_expected_values() {
    let defaults = default_runtime_cache_defaults();
    assert!(defaults.allow_cache_control);
    assert!(defaults.sticky_routing);
    assert!(defaults.allow_session_id);
    assert_eq!(defaults.session_header_name, "x-session-id");
}

#[test]
fn default_runtime_shadow_routing_disabled() {
    let shadow = default_runtime_shadow_routing();
    assert!(!shadow.enabled);
    assert_eq!(shadow.evaluation_mode, "asynchronous");
    assert_eq!(shadow.capture_mode, "metadata_only");
}

// ── locality_scope_fragment ──────────────────────────────────────────

#[test]
fn locality_scope_both_present() {
    assert_eq!(
        locality_scope_fragment(Some("us-east"), Some("api.example.com")),
        Some("region_group:us-east:host:api.example.com".to_string())
    );
}

#[test]
fn locality_scope_region_only() {
    assert_eq!(
        locality_scope_fragment(Some("eu-west"), None),
        Some("region_group:eu-west".to_string())
    );
}

#[test]
fn locality_scope_host_only() {
    assert_eq!(
        locality_scope_fragment(None, Some("api.example.com")),
        Some("host:api.example.com".to_string())
    );
}

#[test]
fn locality_scope_both_none() {
    assert_eq!(locality_scope_fragment(None, None), None);
}

#[test]
fn locality_scope_empty_strings_treated_as_none() {
    assert_eq!(locality_scope_fragment(Some("  "), Some("  ")), None);
}

// ── managed_public_endpoint_host ─────────────────────────────────────

#[test]
fn managed_public_endpoint_host_from_custom_header() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-public-hostname",
        "Api.Example.Com".parse().unwrap(),
    );
    assert_eq!(
        managed_public_endpoint_host(&headers),
        Some("api.example.com".to_string())
    );
}

#[test]
fn managed_public_endpoint_host_fallback_to_host_header() {
    let mut headers = HeaderMap::new();
    headers.insert("host", "Fallback.COM:3000".parse().unwrap());
    assert_eq!(
        managed_public_endpoint_host(&headers),
        Some("fallback.com".to_string())
    );
}

#[test]
fn managed_public_endpoint_host_none_when_absent() {
    let headers = HeaderMap::new();
    assert_eq!(managed_public_endpoint_host(&headers), None);
}

// ── managed_public_endpoint_requested_region_group ────────────────────

#[test]
fn requested_region_group_extracted() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-requested-region-group",
        "us-east-1".parse().unwrap(),
    );
    assert_eq!(
        managed_public_endpoint_requested_region_group(&headers),
        Some("us-east-1".to_string())
    );
}

#[test]
fn requested_region_group_none_when_empty() {
    let mut headers = HeaderMap::new();
    headers.insert("x-verdictan-requested-region-group", "  ".parse().unwrap());
    assert_eq!(
        managed_public_endpoint_requested_region_group(&headers),
        None
    );
}

#[test]
fn requested_region_group_none_when_absent() {
    let headers = HeaderMap::new();
    assert_eq!(
        managed_public_endpoint_requested_region_group(&headers),
        None
    );
}

// ── strip_runtime_contract_fields ────────────────────────────────────

#[test]
fn strip_contract_fields_removes_expected_keys() {
    let mut value = json!({
        "model": "gpt-4",
        "provider": {"name": "openai"},
        "cache_control": {"type": "ephemeral"},
        "session_id": "s-1",
        "plugins": ["plugin-a"],
        "messages": []
    });
    strip_runtime_contract_fields(&mut value);
    assert!(value.get("model").is_some());
    assert!(value.get("messages").is_some());
    assert!(value.get("provider").is_none());
    assert!(value.get("cache_control").is_none());
    assert!(value.get("session_id").is_none());
    assert!(value.get("plugins").is_none());
}

#[test]
fn strip_contract_fields_noop_for_non_object() {
    let mut value = json!("string");
    strip_runtime_contract_fields(&mut value);
    assert_eq!(value, json!("string"));
}

// ── strip_runtime_contract_fields_bytes ──────────────────────────────

#[test]
fn strip_contract_fields_bytes_removes_keys() {
    let input = serde_json::to_vec(&json!({
        "model": "gpt-4",
        "provider": {"name": "openai"},
        "session_id": "s-1"
    }))
    .unwrap();
    let result = strip_runtime_contract_fields_bytes(&Bytes::from(input));
    let parsed: serde_json::Value = serde_json::from_slice(&result).unwrap();
    assert!(parsed.get("model").is_some());
    assert!(parsed.get("provider").is_none());
    assert!(parsed.get("session_id").is_none());
}

#[test]
fn strip_contract_fields_bytes_invalid_json_passthrough() {
    let input = Bytes::from_static(b"not-json");
    let result = strip_runtime_contract_fields_bytes(&input);
    assert_eq!(result, input);
}

// ── runtime_error_envelope ───────────────────────────────────────────

#[test]
fn runtime_error_envelope_structure() {
    let envelope = runtime_error_envelope(
        StatusCode::BAD_REQUEST,
        "req_abc",
        "bad_input",
        "Bad",
        json!({}),
    );
    let error = envelope.get("error").unwrap();
    assert_eq!(error["status"], 400);
    assert_eq!(error["code"], "bad_input");
    assert_eq!(error["message"], "Bad");
    assert_eq!(error["error_id"], "err_abc");
    assert_eq!(error["request_id"], "req_abc");
}

// ── runtime_error_body_bytes ─────────────────────────────────────────

#[test]
fn runtime_error_body_bytes_is_valid_json() {
    let bytes = runtime_error_body_bytes(
        StatusCode::INTERNAL_SERVER_ERROR,
        "req_xyz",
        "server_error",
        "boom",
        json!({}),
    );
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed["error"]["code"], "server_error");
}

// ── parse_runtime_json_body ──────────────────────────────────────────

#[test]
fn parse_runtime_json_body_valid() {
    let bytes = Bytes::from(r#"{"model":"gpt-4"}"#);
    let result = parse_runtime_json_body(&bytes);
    assert!(result.is_ok());
    assert_eq!(result.unwrap()["model"], "gpt-4");
}

#[test]
fn parse_runtime_json_body_invalid() {
    let bytes = Bytes::from(b"not-json".to_vec());
    let result = parse_runtime_json_body(&bytes);
    assert!(result.is_err());
}

// ── required_string_field ────────────────────────────────────────────

#[test]
fn required_string_field_present() {
    let body = json!({"model": "gpt-4"});
    assert_eq!(required_string_field(&body, "/model").unwrap(), "gpt-4");
}

#[test]
fn required_string_field_missing() {
    let body = json!({"other": 1});
    assert!(required_string_field(&body, "/model").is_err());
}

#[test]
fn required_string_field_empty_rejected() {
    let body = json!({"model": "  "});
    assert!(required_string_field(&body, "/model").is_err());
}

// ── voice_is_safe_identifier ─────────────────────────────────────────

#[test]
fn voice_safe_identifier_valid() {
    assert!(voice_is_safe_identifier("alloy"));
    assert!(voice_is_safe_identifier("my-voice_1"));
}

#[test]
fn voice_safe_identifier_empty_rejected() {
    assert!(!voice_is_safe_identifier(""));
    assert!(!voice_is_safe_identifier("   "));
}

#[test]
fn voice_safe_identifier_special_chars_rejected() {
    assert!(!voice_is_safe_identifier("voice@bad"));
    assert!(!voice_is_safe_identifier("voice/path"));
}

#[test]
fn voice_safe_identifier_too_long_rejected() {
    let long = "a".repeat(65);
    assert!(!voice_is_safe_identifier(&long));
}

// ── normalized_audio_speech_output_format ─────────────────────────────

#[test]
fn audio_speech_output_format_valid() {
    assert_eq!(
        normalized_audio_speech_output_format(&json!({"response_format": "MP3"})).unwrap(),
        "mp3"
    );
    assert_eq!(
        normalized_audio_speech_output_format(&json!({"response_format": "wav"})).unwrap(),
        "wav"
    );
}

#[test]
fn audio_speech_output_format_default_mp3() {
    assert_eq!(
        normalized_audio_speech_output_format(&json!({})).unwrap(),
        "mp3"
    );
}

#[test]
fn audio_speech_output_format_invalid_rejected() {
    assert!(normalized_audio_speech_output_format(&json!({"response_format": "avi"})).is_err());
}

// ── inject_identity_headers_from_finops ──────────────────────────────

#[test]
fn inject_identity_headers_adds_missing() {
    let mut headers = HeaderMap::new();
    let ctx = RequestFinopsContext {
        org_id: Some("org-1".to_string()),
        user_id: Some("user-1".to_string()),
        team_id: Some("team-1".to_string()),
        key_id: Some("key-1".to_string()),
        ..Default::default()
    };
    inject_identity_headers_from_finops(&mut headers, Some(&ctx));
    assert_eq!(headers.get("X-Org-ID").unwrap().to_str().unwrap(), "org-1");
    assert_eq!(
        headers.get("X-User-ID").unwrap().to_str().unwrap(),
        "user-1"
    );
    assert_eq!(
        headers.get("X-Team-ID").unwrap().to_str().unwrap(),
        "team-1"
    );
    assert_eq!(headers.get("X-Key-ID").unwrap().to_str().unwrap(), "key-1");
}

#[test]
fn inject_identity_headers_overwrites_spoofed_when_authoritative() {
    let mut headers = HeaderMap::new();
    headers.insert("X-Org-ID", "existing".parse().unwrap());
    let ctx = RequestFinopsContext {
        org_id: Some("new".to_string()),
        ..Default::default()
    };
    inject_identity_headers_from_finops(&mut headers, Some(&ctx));
    assert_eq!(headers.get("X-Org-ID").unwrap().to_str().unwrap(), "new");
}

#[test]
fn inject_identity_headers_noop_when_none() {
    let mut headers = HeaderMap::new();
    inject_identity_headers_from_finops(&mut headers, None);
    assert!(headers.is_empty());
}

// ── policy_input_headers ─────────────────────────────────────────────

#[test]
fn policy_input_headers_strips_and_injects() {
    let mut req_headers = HeaderMap::new();
    req_headers.insert("X-Org-ID", "spoofed".parse().unwrap());
    req_headers.insert("X-User-ID", "spoofed".parse().unwrap());
    req_headers.insert("X-Key-ID", "spoofed".parse().unwrap());
    req_headers.insert("x-custom", "keep".parse().unwrap());

    let ctx = RequestFinopsContext {
        org_id: Some("real-org".to_string()),
        user_id: Some("real-user".to_string()),
        key_id: Some("real-key".to_string()),
        ..Default::default()
    };
    let result = policy_input_headers(&req_headers, Some(&ctx));
    assert_eq!(
        result.get("X-Org-ID").unwrap().to_str().unwrap(),
        "real-org"
    );
    assert_eq!(
        result.get("X-User-ID").unwrap().to_str().unwrap(),
        "real-user"
    );
    assert_eq!(
        result.get("X-Key-ID").unwrap().to_str().unwrap(),
        "real-key"
    );
    assert_eq!(result.get("x-custom").unwrap().to_str().unwrap(), "keep");
}

// ── shadow_sampled boundary tests ────────────────────────────────────

#[test]
fn shadow_sampled_always_true_at_1() {
    assert!(shadow_sampled(1.0));
    assert!(shadow_sampled(2.0));
}

#[test]
fn shadow_sampled_always_false_at_0() {
    assert!(!shadow_sampled(0.0));
    assert!(!shadow_sampled(-1.0));
}

// ── normalize_provider_scope_values ───────────────────────────────────

#[test]
fn provider_scope_normalizes_and_deduplicates() {
    let values = vec![
        "OpenAI".to_string(),
        " openai ".to_string(),
        "Anthropic".to_string(),
    ];
    let result = normalize_provider_scope_values(&values);
    assert!(result.len() >= 1);
    assert!(result.iter().all(|v| v == v.to_ascii_lowercase().trim()));
}

// ── TraceCorrelation::is_empty / to_json ─────────────────────────────

#[test]
fn trace_correlation_default_is_empty() {
    let tc = TraceCorrelation::default();
    assert!(tc.is_empty());
}

#[test]
fn trace_correlation_with_evaluation_id_not_empty() {
    let tc = TraceCorrelation {
        evaluation_id: Some("eval-1".to_string()),
        ..Default::default()
    };
    assert!(!tc.is_empty());
}

#[test]
fn trace_correlation_to_json_present_when_not_empty() {
    let tc = TraceCorrelation {
        evaluation_id: Some("eval-1".to_string()),
        test_case_id: Some("tc-1".to_string()),
        ..Default::default()
    };
    let json = tc.as_event_json();
    assert!(json.is_some());
    let map = json.unwrap();
    assert_eq!(map["evaluation_id"], "eval-1");
}

#[test]
fn trace_correlation_to_json_none_when_empty() {
    let tc = TraceCorrelation::default();
    assert!(tc.as_event_json().is_none());
}

// ── RuntimePreflightError constructors ───────────────────────────────

#[test]
fn preflight_error_validation_failed_is_bad_request() {
    let err = RuntimePreflightError::validation_failed("test", json!({"field": "model"}));
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert_eq!(err.code, "request.validation_failed");
}

#[test]
fn preflight_error_new_custom_status() {
    let err = RuntimePreflightError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        "too_large",
        "payload too large",
        json!({}),
    );
    assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(err.code, "too_large");
}

// ── normalize_managed_public_endpoint_host edge cases ────────────────

#[test]
fn endpoint_host_ipv6_preserved() {
    let result = normalize_managed_public_endpoint_host("[::1]:8080");
    assert!(result.is_some());
    assert!(result.unwrap().contains("::1"));
}

#[test]
fn endpoint_host_plain_no_port() {
    assert_eq!(
        normalize_managed_public_endpoint_host("example.com"),
        Some("example.com".to_string())
    );
}

// ── normalized_audio_transcription_format ─────────────────────────────

#[test]
fn audio_transcription_format_valid_formats() {
    for fmt in &["wav", "mp3", "mp4", "mpeg", "mpga", "m4a", "webm", "ogg"] {
        let body = json!({"model": "whisper", "input_audio": {"data": "AA==", "format": fmt}});
        assert!(
            normalized_audio_transcription_format(&body).is_ok(),
            "format {fmt} should be accepted"
        );
    }
}

#[test]
fn audio_transcription_format_invalid_rejected() {
    let body = json!({"model": "whisper", "input_audio": {"data": "AA==", "format": "avi"}});
    assert!(normalized_audio_transcription_format(&body).is_err());
}

// ── request_agent_id_header_value ─────────────────────────────────────

#[test]
fn request_agent_id_header_extracted() {
    let mut headers = HeaderMap::new();
    headers.insert("x-verdictan-agent-id", "my-agent".parse().unwrap());
    assert_eq!(request_agent_id_header_value(&headers), Some("my-agent"));
}

#[test]
fn request_agent_id_header_legacy_fallback_extracted() {
    let mut headers = HeaderMap::new();
    headers.insert("x-agent-id", "legacy-agent".parse().unwrap());
    assert_eq!(
        request_agent_id_header_value(&headers),
        Some("legacy-agent")
    );
}

#[test]
fn request_agent_id_header_prefers_verdictan_header() {
    let mut headers = HeaderMap::new();
    headers.insert("x-agent-id", "legacy-agent".parse().unwrap());
    headers.insert("x-verdictan-agent-id", "canonical-agent".parse().unwrap());
    assert_eq!(
        request_agent_id_header_value(&headers),
        Some("canonical-agent")
    );
}

#[test]
fn request_agent_id_header_absent() {
    let headers = HeaderMap::new();
    assert_eq!(request_agent_id_header_value(&headers), None);
}

// ── normalize_text_scope_values extra tests ──────────────────────────

#[test]
fn text_scope_empty_input() {
    assert!(normalize_text_scope_values(&[]).is_empty());
}

#[test]
fn text_scope_whitespace_only_filtered() {
    let values = vec!["  ".to_string(), "".to_string()];
    assert!(normalize_text_scope_values(&values).is_empty());
}

// ── default_usage_category_cli ─────────────────────────────────────

#[test]
fn default_usage_category_cli_is_gateway_llm() {
    assert_eq!(default_usage_category_cli(), "gateway_llm");
}

// ── ConnectedPostDispatchUsageSource ────────────────────────────────

#[test]
fn post_dispatch_usage_source_labels_and_estimation_flags() {
    assert_eq!(
        ConnectedPostDispatchUsageSource::UpstreamReported.as_str(),
        "provider_reported"
    );
    assert_eq!(
        ConnectedPostDispatchUsageSource::PromptOnlyFallback.as_str(),
        "prompt_only_fallback"
    );
    assert_eq!(
        ConnectedPostDispatchUsageSource::StreamingEstimate.as_str(),
        "streaming_estimate"
    );
    assert!(!ConnectedPostDispatchUsageSource::UpstreamReported.is_estimated());
    assert!(ConnectedPostDispatchUsageSource::PromptOnlyFallback.is_estimated());
    assert!(ConnectedPostDispatchUsageSource::StreamingEstimate.is_estimated());
}

#[test]
fn connected_access_outcome_keeps_only_the_primary_byok_result() {
    let primary = super::super::access_preflight::AccessPreflightResponse {
        status: "ready_byok".to_string(),
        status_reason: "ok".to_string(),
        resolved_api_key: Some("sk-org-owned".to_string()),
        org_authz_version: Some(4),
        remaining_budget: None,
        budget_limit: None,
        spend_so_far: None,
        budget_period: None,
        cost_per_1k_input_tokens: None,
        cost_per_1k_output_tokens: None,
    };

    let outcome = ConnectedAccessPreflightOutcome {
        primary,
        org_authz_version: Some(4),
        local_budget_tracker: None,
    };
    assert_eq!(outcome.primary.status, "ready_byok");
    assert_eq!(
        outcome.primary.resolved_api_key.as_deref(),
        Some("sk-org-owned")
    );
    assert_eq!(outcome.org_authz_version, Some(4));
}

// ── LocalBudgetTracker ──────────────────────────────────────────────

#[test]
fn local_budget_tracker_reserves_and_credits_back() {
    let tracker = LocalBudgetTracker::new(10.0, Some(1.0), Some(2.0), Some(20.0), None);

    assert!(tracker.has_pricing());
    let reserved = tracker
        .try_reserve(1_000, 2_000)
        .expect("reservation should succeed");
    assert_eq!(reserved, 5.0);
    assert!(tracker.try_reserve(6_000, 0).is_err());

    tracker.credit_back(2.5);
    assert_eq!(tracker.try_reserve(2_000, 0).expect("credit restored"), 2.0);
}

#[test]
fn local_budget_tracker_without_pricing_returns_zero_cost() {
    let tracker = LocalBudgetTracker::new(1.0, None, None, None, Some("monthly".to_string()));

    assert!(!tracker.has_pricing());
    assert_eq!(tracker.try_reserve(1_000, 1_000), Ok(0.0));
    assert_eq!(tracker.budget_period.as_deref(), Some("monthly"));
    assert_eq!(tracker.budget_limit, None);
}

#[test]
fn token_depletion_accessors_prefer_validation_overrides_and_fallback_cleanly() {
    let key = TokenRecord {
        id: "tok_3".to_string(),
        gateway_id: None,
        provider: Some("openai".to_string()),
        model_filter: vec![],
        team_id: None,
        user_id: None,
        max_budget: Some(9.5),
        current_spend: 4.25,
        key_class: None,
        resource_id: None,
        resource_vrn: None,
        expires_at: None,
        metadata: json!({}),
        rate_limit_rpm: None,
    };
    let with_overrides = TokenValidationResponse {
        valid: true,
        authenticated_identity: None,
        reason: None,
        status: None,
        token_id: None,
        org_id: None,
        key_id: None,
        key_class: None,
        expires_at: None,
        team_id: None,
        user_id: None,
        agent_id: None,
        agent_gateway_group_id: None,
        attached_policy_ids: vec![],
        depletion: Some(TokenDepletionState {
            max_budget: Some(5.0),
            current_spend: Some(1.5),
            remaining_budget: Some(3.5),
            max_requests: Some(20),
            current_requests: Some(7),
            remaining_requests: Some(13),
        }),
        ip_restrictions: None,
        entitlements: vec![],
        history: None,
        created_by: None,
        key: None,
        gateway_controls: None,
        org_authz_version: None,
    };
    let without_overrides = TokenValidationResponse {
        depletion: None,
        ..with_overrides.clone()
    };

    assert_eq!(token_current_spend(&key, &with_overrides), 1.5);
    assert_eq!(token_max_budget(&key, &with_overrides), Some(5.0));
    assert_eq!(token_current_requests(&with_overrides), 7);
    assert_eq!(token_max_requests(&with_overrides), Some(20));

    assert_eq!(token_current_spend(&key, &without_overrides), 4.25);
    assert_eq!(token_max_budget(&key, &without_overrides), Some(9.5));
    assert_eq!(token_current_requests(&without_overrides), 0);
    assert_eq!(token_max_requests(&without_overrides), None);
}

#[test]
fn budget_helpers_choose_tightest_non_negative_remaining_amount() {
    assert_eq!(tighter_remaining_budget(Some(4.0), Some(6.5)), Some(4.0));
    assert_eq!(tighter_remaining_budget(Some(4.0), None), Some(4.0));
    assert_eq!(tighter_remaining_budget(None, Some(6.5)), Some(6.5));
    assert_eq!(tighter_remaining_budget(None, None), None);

    assert_eq!(remaining_budget_from_records(&[]), None);
    assert_eq!(
        remaining_budget_from_records(&[
            GatewayBudgetRecord {
                max_budget: 10.0,
                current_spend: 3.5,
            },
            GatewayBudgetRecord {
                max_budget: 5.0,
                current_spend: 9.0,
            },
            GatewayBudgetRecord {
                max_budget: 12.0,
                current_spend: 2.0,
            },
        ]),
        Some(0.0)
    );
    assert_eq!(
        remaining_budget_from_records(&[
            GatewayBudgetRecord {
                max_budget: 10.0,
                current_spend: 3.5,
            },
            GatewayBudgetRecord {
                max_budget: 6.0,
                current_spend: 2.0,
            },
        ]),
        Some(4.0)
    );
}

#[test]
fn connected_read_model_feed_helpers_floor_future_ages_and_respect_thresholds() {
    let now = DateTime::parse_from_rfc3339("2026-01-01T00:00:15Z")
        .expect("now")
        .with_timezone(&Utc);
    let future = DateTime::parse_from_rfc3339("2026-01-01T00:00:20Z")
        .expect("future")
        .with_timezone(&Utc);
    let at_threshold = DateTime::parse_from_rfc3339("2026-01-01T00:00:05Z")
        .expect("threshold")
        .with_timezone(&Utc);
    let stale = DateTime::parse_from_rfc3339("2025-12-31T23:59:59Z")
        .expect("stale")
        .with_timezone(&Utc);

    assert_eq!(
        ConnectedGatewayReadModelSnapshot::feed_age_seconds(Some(future), now),
        Some(0)
    );
    assert_eq!(
        ConnectedGatewayReadModelSnapshot::feed_age_seconds(Some(at_threshold), now),
        Some(10)
    );
    assert_eq!(
        ConnectedGatewayReadModelSnapshot::feed_age_seconds(None, now),
        None
    );

    assert!(
        !ConnectedGatewayReadModelSnapshot::feed_is_stale_with_budget(Some(at_threshold), now, 10,)
    );
    assert!(ConnectedGatewayReadModelSnapshot::feed_is_stale_with_budget(Some(stale), now, 10,));
    assert!(ConnectedGatewayReadModelSnapshot::feed_is_stale_with_budget(None, now, 10,));

    assert_eq!(
        ConnectedGatewayReadModelSnapshot::feed_status_with_budget(Some(at_threshold), now, 10),
        "fresh"
    );
    assert_eq!(
        ConnectedGatewayReadModelSnapshot::feed_status_with_budget(Some(stale), now, 10),
        "stale"
    );
}

// ── Cache replay helpers ────────────────────────────────────────────

#[test]
fn cache_tier_and_replay_metadata_render_expected_strings() {
    assert_eq!(CacheTier::PrivateEdge.as_str(), "private_edge_cache");
    assert_eq!(CacheTier::OrgShared.as_str(), "org_shared_cache");
    assert_eq!(CacheReplayOutcome::ExactHit.as_str(), "exact_hit");
    assert_eq!(
        CacheReplayOutcome::SemanticCandidate.hit_type(),
        "semantic_candidate"
    );
    assert_eq!(CacheReplayOutcome::DeniedReplay.hit_type(), "exact");
    assert_eq!(
        CacheReplayOutcome::SemanticRevalidated.hit_type(),
        "semantic_revalidated"
    );
    assert_eq!(
        CacheReplayOutcome::SemanticReplayed.hit_type(),
        "semantic_replayed"
    );
    assert_eq!(CacheReplayOutcome::StaleMiss.hit_type(), "exact");

    let json = CacheReplayMetadata {
        outcome: CacheReplayOutcome::SemanticReplayed,
        cache_tier: CacheTier::OrgShared,
        cache_key_digest: Some("digest-1".to_string()),
        selected_fabric_artifact_ids: vec!["artifact-1".to_string()],
        selected_fabric_source_digests: vec!["source-1".to_string()],
    }
    .to_json();

    assert_eq!(json["outcome"], "semantic_replayed");
    assert_eq!(json["cache_tier"], "org_shared_cache");
    assert_eq!(json["cache_key_digest"], "digest-1");
    assert_eq!(json["selected_fabric_artifact_ids"][0], "artifact-1");
}

// ── RequestFinopsContext helpers ────────────────────────────────────

#[test]
fn finops_identity_context_requires_non_empty_identity() {
    let empty = RequestFinopsContext {
        key_id: Some("   ".to_string()),
        ..Default::default()
    };
    assert!(!empty.has_token_identity());
    assert!(empty.identity_context_json().is_none());

    let identified = RequestFinopsContext {
        key_id: Some("key-1".to_string()),
        org_id: Some("org-1".to_string()),
        user_id: Some("user-1".to_string()),
        team_id: Some("team-1".to_string()),
        ..Default::default()
    };
    assert!(identified.has_token_identity());
    let json = identified
        .identity_context_json()
        .expect("identity context");
    assert_eq!(json["key_id"], "key-1");
    assert_eq!(json["org_id"], "org-1");
    assert_eq!(json["user_id"], "user-1");
    assert_eq!(json["team_id"], "team-1");
}

#[test]
fn finops_context_selection_round_trips_selection_telemetry() {
    let mut finops = RequestFinopsContext::default();
    assert!(finops.context_selection_json().is_none());

    let selection = crate::gateway::agent_context::ContextSelectionTelemetry {
        plan_hash: "plan-123".to_string(),
        context_policy_version: 7,
        selected_item_ids: vec!["item-1".to_string(), "item-2".to_string()],
        selected_items: vec![
            crate::gateway::agent_context::SelectedContextItemTelemetry {
                item_id: "item-1".to_string(),
                item_type: "working_context".to_string(),
                source_history_session_id: Some("session-1".to_string()),
                hierarchy_lane: Some("task_fingerprint".to_string()),
                receipt_id: Some("receipt-1".to_string()),
                receipt_confidence_score: Some(0.98),
                receipt_verification_status: Some("verified".to_string()),
            },
        ],
        selected_hierarchy_lanes: vec!["task_fingerprint".to_string()],
        selected_receipt_ids: vec!["receipt-1".to_string()],
        citation_required_count: 2,
        pack_hash: Some("pack-1".to_string()),
        tokens: crate::gateway::agent_context::ContextTokenBreakdown {
            max_context_tokens: 4_096,
            estimated_tokens: 900,
            injected_tokens: 640,
            working_context_tokens: 128,
        },
        manifest_hash: Some("manifest-1".to_string()),
        ranking_policy_version: Some("rank-v1".to_string()),
        visibility_digest: Some("vis-1".to_string()),
    };
    finops.apply_context_selection(&selection);

    let json = finops
        .context_selection_json()
        .expect("context selection json");
    assert_eq!(json["plan_hash"], "plan-123");
    assert_eq!(json["pack_hash"], "pack-1");
    assert_eq!(json["context_policy_version"], 7);
    assert_eq!(json["selected_item_ids"][0], "item-1");
    assert_eq!(json["selected_items"][0]["item_id"], "item-1");
    assert_eq!(json["selected_items"][0]["item_type"], "working_context");
    assert_eq!(
        json["selected_items"][0]["source_history_session_id"],
        "session-1"
    );
    assert_eq!(json["citation_required_count"], 2);
    assert_eq!(json["max_context_tokens"], 4096);
    assert_eq!(json["estimated_context_tokens"], 900);
    assert_eq!(json["injected_context_tokens"], 640);
    assert_eq!(json["working_context_tokens"], 128);
}

// ── response and error builders ─────────────────────────────────────

#[tokio::test]
async fn request_error_response_sets_headers_and_error_body() {
    let response = build_request_error_response(
        StatusCode::BAD_REQUEST,
        "req_123",
        "00-trace",
        "bad request",
        "invalid_request_error",
        "bad_input",
    );

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    assert_eq!(
        response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        Some("req_123")
    );
    assert_eq!(
        response
            .headers()
            .get("traceparent")
            .and_then(|value| value.to_str().ok()),
        Some("00-trace")
    );

    let json = response_json(response).await;
    assert_eq!(json["error"]["message"], "bad request");
    assert_eq!(json["error"]["type"], "invalid_request_error");
    assert_eq!(json["error"]["code"], "bad_input");
}

#[tokio::test]
async fn runtime_routing_and_preflight_responses_share_runtime_error_envelope() {
    let routing = runtime_routing_error_response(
        &RuntimeRoutingError::invalid_request("invalid_plugin_id", "Plugin is invalid"),
        "req_route",
        "00-route",
    );
    let routing_json = response_json(routing).await;
    assert_eq!(routing_json["error"]["code"], "invalid_plugin_id");
    assert_eq!(routing_json["error"]["type"], "invalid_request_error");
    assert_eq!(routing_json["error"]["message"], "Plugin is invalid");

    let runtime = build_runtime_json_response(
        StatusCode::UNPROCESSABLE_ENTITY,
        "req_runtime",
        "00-runtime",
        "runtime.bad_input",
        "Bad runtime payload",
        json!({"field": "model"}),
    );
    let runtime_json = response_json(runtime).await;
    assert_eq!(runtime_json["error"]["request_id"], "req_runtime");
    assert_eq!(runtime_json["error"]["details"]["field"], "model");

    let preflight = build_runtime_preflight_response(
        "req_preflight",
        "00-preflight",
        &RuntimePreflightError::validation_failed("Missing field", json!({"field": "messages"})),
    );
    let preflight_json = response_json(preflight).await;
    assert_eq!(preflight_json["error"]["status"], 400);
    assert_eq!(preflight_json["error"]["code"], "request.validation_failed");
    assert_eq!(preflight_json["error"]["details"]["field"], "messages");
}

#[tokio::test]
async fn runtime_capability_responses_encode_unprocessable_entity_contract() {
    let error = crate::gateway::runtime_capabilities::RuntimeCapabilityError::UnsupportedFamily {
        family: crate::gateway::runtime_capabilities::RequestFamily::Messages,
    };

    let buffered = build_runtime_capability_buffered_response(&error, "req_cap");
    assert_eq!(buffered.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let buffered_json: serde_json::Value =
        serde_json::from_slice(buffered.body()).expect("buffered capability json");
    assert_eq!(
        buffered_json["error"]["code"],
        "capability.unsupported_family"
    );
    assert_eq!(buffered_json["error"]["request_id"], "req_cap");

    let streaming = build_runtime_capability_streaming_response(&error, "req_cap_stream");
    let streaming_json = prepared_response_json(streaming).await;
    assert_eq!(
        streaming_json["error"]["code"],
        "capability.unsupported_family"
    );
    assert_eq!(streaming_json["error"]["request_id"], "req_cap_stream");
}

#[test]
fn budget_filter_rejection_constructors_preserve_status_type_and_code() {
    let access_denied = BudgetFilterRejection::access_denied("blocked", "gateway_scope");
    assert_eq!(access_denied.status, StatusCode::FORBIDDEN);
    assert_eq!(access_denied.error_type, "access_denied");
    assert_eq!(access_denied.code, "gateway_scope");
    assert_eq!(access_denied.message, "blocked");

    let unavailable =
        BudgetFilterRejection::service_unavailable("retry later", "budget_lookup_failed");
    assert_eq!(unavailable.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(unavailable.error_type, "service_unavailable");
    assert_eq!(unavailable.code, "budget_lookup_failed");
    assert_eq!(unavailable.message, "retry later");
}

#[tokio::test]
async fn token_validation_error_response_distinguishes_misconfiguration_and_transient_failure() {
    let unauthorized = build_token_validation_error_response(
        "req_auth",
        "00-auth",
        &TokenValidationError::Unauthorized {
            body: "denied".to_string(),
        },
    );
    let unauthorized_json = response_json(unauthorized).await;
    assert_eq!(
            unauthorized_json["error"]["message"],
            "API token validation is misconfigured: set VERDICTAN_API_TOKEN so the runtime can reach the control plane"
        );

    let transient = build_token_validation_error_response(
        "req_transient",
        "00-transient",
        &TokenValidationError::UnexpectedStatus {
            status: StatusCode::BAD_GATEWAY,
            body: "boom".to_string(),
        },
    );
    let transient_json = response_json(transient).await;
    assert_eq!(
        transient_json["error"]["message"],
        "API token validation is temporarily unavailable"
    );
}

#[tokio::test]
async fn budget_and_provider_auth_responses_share_json_shape() {
    let rejection = BudgetFilterRejection::forbidden("Budget exceeded", "budget_exceeded");
    let body_json: serde_json::Value =
        serde_json::from_slice(&build_budget_filter_body(&rejection)).expect("budget body");
    assert_eq!(body_json["error"]["message"], "Budget exceeded");
    assert_eq!(body_json["error"]["code"], "budget_exceeded");

    let buffered = build_budget_filter_buffered_response(&rejection);
    assert_eq!(buffered.status(), StatusCode::FORBIDDEN);
    let buffered_json: serde_json::Value =
        serde_json::from_slice(buffered.body()).expect("budget buffered json");
    assert_eq!(buffered_json["error"]["type"], "cost_budget_exceeded");

    let streaming = build_budget_filter_streaming_response(&rejection);
    let streaming_json = prepared_response_json(streaming).await;
    assert_eq!(streaming_json["error"]["message"], "Budget exceeded");

    let auth_body: serde_json::Value =
        serde_json::from_slice(&build_provider_auth_body("missing key"))
            .expect("provider auth body");
    assert_eq!(auth_body["error"]["code"], "provider_auth_failed");

    let auth_buffered = build_provider_auth_buffered_response("missing key");
    assert_eq!(auth_buffered.status(), StatusCode::BAD_GATEWAY);
    let auth_buffered_json: serde_json::Value =
        serde_json::from_slice(auth_buffered.body()).expect("provider auth buffered json");
    assert_eq!(auth_buffered_json["error"]["message"], "missing key");

    let auth_streaming = build_provider_auth_streaming_response("missing key");
    let auth_streaming_json = prepared_response_json(auth_streaming).await;
    assert_eq!(auth_streaming_json["error"]["message"], "missing key");
}

#[tokio::test]
async fn access_inactive_helpers_encode_reason_and_status() {
    assert_eq!(
        access_inactive_status("provider_key_policy_denied"),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        access_inactive_status("unsupported_provider"),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        access_inactive_status("other"),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(
        access_inactive_message("provider_key_not_configured", "openai-primary")
            .contains("provider key is not configured")
    );

    let body_json: serde_json::Value = serde_json::from_slice(&build_access_inactive_body(
        "access inactive",
        "provider_key_not_configured",
    ))
    .expect("access inactive body");
    assert_eq!(body_json["error"]["type"], "access_inactive");
    assert_eq!(body_json["error"]["code"], "provider_key_not_configured");

    let buffered = build_access_inactive_buffered_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "access inactive",
        "provider_key_not_configured",
    );
    assert_eq!(buffered.status(), StatusCode::SERVICE_UNAVAILABLE);

    let streaming = build_access_inactive_streaming_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "access inactive",
        "provider_key_not_configured",
    );
    let streaming_json = prepared_response_json(streaming).await;
    assert_eq!(streaming_json["error"]["message"], "access inactive");
}

// ── upstream contract helpers ───────────────────────────────────────

#[test]
fn requested_anthropic_beta_headers_adds_extended_thinking_header_once() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "anthropic-beta",
        "existing-beta, interleaved-thinking-2025-05-14, existing-beta"
            .parse()
            .unwrap(),
    );
    let body = json!({
        "messages": [{
            "role": "assistant",
            "content": [{"type": "thinking", "text": "step by step"}]
        }]
    });

    let values = requested_anthropic_beta_headers("/v1/messages", &headers, &body);

    assert_eq!(
        values,
        vec![
            "existing-beta".to_string(),
            "interleaved-thinking-2025-05-14".to_string(),
        ]
    );
}

#[test]
fn merge_provider_extra_header_replaces_existing_and_ignores_invalid_inputs() {
    let mut extra_headers = vec![(
        reqwest::header::HeaderName::from_static("x-test"),
        reqwest::header::HeaderValue::from_static("old"),
    )];

    merge_provider_extra_header(&mut extra_headers, "x-test", "new");
    merge_provider_extra_header(&mut extra_headers, "bad header", "ignored");
    merge_provider_extra_header(&mut extra_headers, "x-bad-value", "bad\nvalue");

    assert_eq!(extra_headers.len(), 1);
    assert_eq!(extra_headers[0].0.as_str(), "x-test");
    assert_eq!(extra_headers[0].1.to_str().unwrap(), "new");
}

#[test]
fn success_shape_validation_checks_route_specific_contracts() {
    assert!(success_shape_valid_for_path(
        "/v1/chat/completions",
        br#"{"choices":[{"message":{"role":"assistant","content":"ok"}}]}"#
    ));
    assert!(!success_shape_valid_for_path(
        "/v1/chat/completions",
        br#"{"output":[{"type":"text"}]}"#
    ));
    assert!(success_shape_valid_for_path(
        "/v1/messages",
        br#"{"type":"message","content":[{"type":"text","text":"ok"}]}"#
    ));
    assert!(!success_shape_valid_for_path(
        "/v1/responses",
        br#"not-json"#
    ));
    assert!(success_shape_valid_for_path(
        "/v1/audio/speech",
        b"audio-bytes"
    ));
}

#[test]
fn invalid_success_shape_buffered_response_is_bad_gateway_json() {
    let response = invalid_success_shape_buffered_response("/v1/messages");
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body: serde_json::Value =
        serde_json::from_slice(response.body()).expect("invalid-shape json");
    assert_eq!(body["error"]["code"], "invalid_upstream_success_shape");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("/v1/messages"));
}

// ── provider scope and rate-limit helpers ───────────────────────────

#[test]
fn provider_name_and_scope_key_are_deterministic() {
    assert_eq!(
        provider_name_from_upstream("https://api.openai.com/v1/chat/completions"),
        "api.openai.com"
    );

    let base = provider_scope_key("https://api.openai.com", Some(b"secret"));
    let same = provider_scope_key("https://api.openai.com", Some(b"secret"));
    let changed = provider_scope_key("https://api.openai.com", Some(b"other"));
    assert_eq!(base, same);
    assert_ne!(base, changed);
    assert!(base.starts_with("scope:"));
    assert_eq!(base.len(), "scope:".len() + 16);
}

#[test]
fn optional_owned_and_provider_alias_lists_normalize_stably() {
    assert_eq!(
        normalize_optional_owned(Some("  gateway-a  ".to_string())),
        Some("gateway-a".to_string())
    );
    assert_eq!(normalize_optional_owned(Some("   ".to_string())), None);
    assert_eq!(normalize_optional_owned(None), None);

    let values = vec![
        " OpenAI ".to_string(),
        "openai".to_string(),
        "Anthropic".to_string(),
    ];
    assert_eq!(
        normalize_provider_alias_list(&values),
        vec!["anthropic".to_string(), "openai".to_string()]
    );
}

#[test]
fn runtime_routing_conversion_maps_declarative_fields_and_none_defaults() {
    let defaults = runtime_routing_from_declarative(None);
    assert!(defaults.default_provider_policy.allow_fallbacks);
    assert_eq!(defaults.cache_defaults.session_header_name, "x-session-id");
    assert!(!defaults.shadow_routing.enabled);

    let converted = runtime_routing_from_declarative(Some(
        super::super::declarative_config::RuntimeRoutingConfig {
            default_provider_policy:
                super::super::declarative_config::RuntimeProviderPolicyConfig {
                    allow_fallbacks: false,
                    require_parameters: false,
                    data_collection: "deny".to_string(),
                    zdr: true,
                },
            cache_defaults: super::super::declarative_config::RuntimeCacheDefaultsConfig {
                allow_cache_control: false,
                sticky_routing: false,
                allow_session_id: false,
                session_header_name: "x-custom-session".to_string(),
            },
            plugin_governance: super::super::declarative_config::RuntimePluginGovernanceConfig {
                defaults: vec![
                    super::super::declarative_config::RuntimePluginSettingConfig {
                        id: "web-search".to_string(),
                        enabled: true,
                        options: Some(json!({"mode": "safe"})),
                    },
                ],
                forced_on: vec![
                    super::super::declarative_config::RuntimePluginSettingConfig {
                        id: "pdf-inputs".to_string(),
                        enabled: false,
                        options: None,
                    },
                ],
                prevent_overrides: vec!["pdf-inputs".to_string()],
            },
            shadow_routing: super::super::declarative_config::RuntimeShadowRoutingConfig {
                enabled: true,
                evaluation_mode: "synchronous".to_string(),
                capture_mode: "full_body".to_string(),
            },
        },
    ));

    assert!(!converted.default_provider_policy.allow_fallbacks);
    assert!(!converted.default_provider_policy.require_parameters);
    assert_eq!(converted.default_provider_policy.data_collection, "deny");
    assert!(converted.default_provider_policy.zdr);
    assert!(!converted.cache_defaults.allow_cache_control);
    assert!(!converted.cache_defaults.sticky_routing);
    assert!(!converted.cache_defaults.allow_session_id);
    assert_eq!(
        converted.cache_defaults.session_header_name,
        "x-custom-session"
    );
    assert_eq!(converted.plugin_governance.defaults.len(), 1);
    assert_eq!(converted.plugin_governance.defaults[0].id, "web-search");
    assert_eq!(
        converted.plugin_governance.defaults[0]
            .options
            .as_ref()
            .and_then(|value| value.get("mode"))
            .and_then(serde_json::Value::as_str),
        Some("safe")
    );
    assert_eq!(converted.plugin_governance.forced_on.len(), 1);
    assert_eq!(converted.plugin_governance.forced_on[0].id, "pdf-inputs");
    assert_eq!(
        converted.plugin_governance.prevent_overrides,
        vec!["pdf-inputs".to_string()]
    );
    assert!(converted.shadow_routing.enabled);
    assert_eq!(converted.shadow_routing.evaluation_mode, "synchronous");
    assert_eq!(converted.shadow_routing.capture_mode, "full_body");
}

#[test]
fn gateway_runtime_metrics_counters_render_as_json() {
    let metrics = GatewayRuntimeMetrics::default();
    metrics.record_token_validation_cache_hit();
    metrics.record_token_validation_cache_miss();
    metrics.record_runtime_controls_cache_hit();
    metrics.record_runtime_controls_cache_miss();
    metrics.record_manifest_fetch();
    metrics.record_yaml_fetch();
    metrics.record_runtime_build_failure();

    let json = metrics.as_json();
    assert_eq!(json["token_validation_cache_hits"], 1);
    assert_eq!(json["token_validation_cache_misses"], 1);
    assert_eq!(json["runtime_controls_cache_hits"], 1);
    assert_eq!(json["runtime_controls_cache_misses"], 1);
    assert_eq!(json["manifest_fetches"], 1);
    assert_eq!(json["yaml_fetches"], 1);
    assert_eq!(json["runtime_build_failures"], 1);
}

#[test]
fn event_sink_config_from_env_and_sink_helpers_trim_and_require_service_token() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    let previous_api_url = std::env::var("VERDICTAN_API_URL").ok();
    let previous_api_token = std::env::var("VERDICTAN_API_TOKEN").ok();

    std::env::remove_var("VERDICTAN_API_URL");
    std::env::remove_var("VERDICTAN_API_TOKEN");
    assert!(EventSinkConfig::from_env().expect("missing env").is_none());

    std::env::set_var("VERDICTAN_API_URL", "   ");
    std::env::set_var("VERDICTAN_API_TOKEN", "vdt_env_token");
    assert!(EventSinkConfig::from_env().expect("blank url").is_none());

    std::env::set_var("VERDICTAN_API_URL", "https://api.verdictan.test/");
    std::env::remove_var("VERDICTAN_API_TOKEN");
    assert!(EventSinkConfig::from_env()
        .expect("missing token")
        .is_none());

    std::env::set_var("VERDICTAN_API_TOKEN", "  vdt_env_token  ");
    let config = EventSinkConfig::from_env()
        .expect("env config result")
        .expect("configured event sink");
    assert_eq!(config.base_url, "https://api.verdictan.test/");
    assert_eq!(config.api_token, "vdt_env_token");
    assert_eq!(
        config.gateway_service_token.as_deref(),
        Some("vdt_env_token")
    );

    let sink_without_machine = EventSink::from_config(EventSinkConfig {
        base_url: "https://api.verdictan.test///".to_string(),
        api_token: "vdt_direct".to_string(),
        gateway_service_token: None,
    })
    .expect("sink without machine client");
    assert_eq!(
        sink_without_machine.base_url(),
        "https://api.verdictan.test"
    );
    assert_eq!(
        sink_without_machine.join_url("/v1/events"),
        "https://api.verdictan.test/v1/events"
    );
    assert!(sink_without_machine.machine_client().is_err());

    let sink_with_machine = EventSink::from_config(EventSinkConfig {
        base_url: "https://api.verdictan.test".to_string(),
        api_token: "vdt_direct".to_string(),
        gateway_service_token: Some("vdt_service".to_string()),
    })
    .expect("sink with machine client")
    .with_redact_bodies(true);
    assert!(sink_with_machine.redact_message_bodies);
    assert!(sink_with_machine.machine_client().is_ok());

    match previous_api_url {
        Some(value) => std::env::set_var("VERDICTAN_API_URL", value),
        None => std::env::remove_var("VERDICTAN_API_URL"),
    }
    match previous_api_token {
        Some(value) => std::env::set_var("VERDICTAN_API_TOKEN", value),
        None => std::env::remove_var("VERDICTAN_API_TOKEN"),
    }
}

#[test]
fn merged_token_scopes_intersects_bindings_with_policy_controls() {
    let key = TokenRecord {
        id: "tok_1".to_string(),
        gateway_id: None,
        provider: Some(" OpenAI ".to_string()),
        model_filter: vec![" gpt-4o-mini ".to_string(), "gpt-4o-mini".to_string()],
        team_id: None,
        user_id: None,
        max_budget: None,
        current_spend: 0.0,
        key_class: None,
        resource_id: None,
        resource_vrn: None,
        expires_at: None,
        metadata: json!({"personal_gateway_id": " gw-a "}),
        rate_limit_rpm: None,
    };
    let controls = GatewayControlsPayload {
        fail_closed: false,
        allowed_providers: vec!["anthropic".to_string(), "openai".to_string()],
        allowed_models: vec!["gpt-4o-mini".to_string(), "gpt-5".to_string()],
        allowed_gateways: vec!["gw-a".to_string(), "gw-b".to_string()],
        disabled_providers: vec![],
    };

    let scopes = merged_token_scopes(&key, Some(&controls), &["policy-1".to_string()])
        .expect("policy-backed scopes");

    assert_eq!(
        scopes,
        EffectiveTokenScopes {
            allowed_providers: vec!["openai".to_string()],
            allowed_models: vec!["gpt-4o-mini".to_string()],
            allowed_gateways: vec!["gw-a".to_string()],
        }
    );
}

#[test]
fn merged_token_scopes_fail_closed_when_policies_exist_without_controls() {
    let key = TokenRecord {
        id: "tok_2".to_string(),
        gateway_id: Some("gw-a".to_string()),
        provider: None,
        model_filter: Vec::new(),
        team_id: None,
        user_id: None,
        max_budget: None,
        current_spend: 0.0,
        key_class: None,
        resource_id: None,
        resource_vrn: None,
        expires_at: None,
        metadata: json!({}),
        rate_limit_rpm: None,
    };

    assert_eq!(
        merged_token_scopes(&key, None, &["policy-1".to_string()]),
        Err(TokenScopeMergeError::PolicyResolutionFailed)
    );
}

#[test]
fn message_extractors_handle_chat_and_responses_shapes() {
    let chat_body = json!({
        "messages": [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": ["assistant-text"]},
            {"role": "system"}
        ],
        "input": "should not be used"
    });
    let chat_messages = extract_messages_from_value(Some(&chat_body));
    assert_eq!(chat_messages.len(), 2);
    assert_eq!(chat_messages[0].role, "user");
    assert_eq!(chat_messages[0].content, "hello");
    assert_eq!(chat_messages[1].role, "assistant");
    assert_eq!(chat_messages[1].content, "assistant-text");

    let preferred = extract_messages_for_responses(Some(&chat_body));
    assert_eq!(preferred.len(), 2);
    assert_eq!(preferred[0].content, "hello");
    assert_eq!(preferred[1].content, "assistant-text");

    let responses_body = json!({
        "input": [
            "first prompt",
            {"role": "assistant", "content": "reply"},
            {"content": "implicit user"},
            "   "
        ]
    });
    let responses_messages = extract_messages_for_responses(Some(&responses_body));
    assert_eq!(responses_messages.len(), 3);
    assert_eq!(responses_messages[0].role, "user");
    assert_eq!(responses_messages[0].content, "first prompt");
    assert_eq!(responses_messages[1].role, "assistant");
    assert_eq!(responses_messages[1].content, "reply");
    assert_eq!(responses_messages[2].role, "user");
    assert_eq!(responses_messages[2].content, "implicit user");
}

#[test]
fn error_and_rate_limit_helpers_emit_expected_contracts() {
    assert_eq!(decision_event_id("req_123"), "vdt_decision_req_123");

    let error = error_json("bad request", "invalid_request_error", "bad_input");
    assert_eq!(error["message"], "bad request");
    assert_eq!(error["type"], "invalid_request_error");
    assert!(error["param"].is_null());
    assert_eq!(error["code"], "bad_input");

    let message = format_upstream_unreachable_message(
        "openai",
        "https://api.openai.com/v1/chat/completions",
        &"connection reset",
    );
    assert!(message.contains("Provider 'openai'"));
    assert!(message.contains("connection reset"));
    assert!(message.contains("status.openai.com"));

    let headers = ratelimit_headers(10, 4, 30, Some(1_000), Some(250));
    assert_eq!(
        headers,
        vec![
            ("x-ratelimit-limit-requests", "10".to_string()),
            ("x-ratelimit-remaining-requests", "4".to_string()),
            ("Retry-After", "30".to_string()),
            ("x-ratelimit-limit-tokens", "1000".to_string()),
            ("x-ratelimit-remaining-tokens", "250".to_string()),
        ]
    );
}

#[test]
fn output_extractors_and_regex_escape_are_deterministic() {
    let chat_output = extract_openai_chat_output(&json!({
        "choices": [
            {"message": {"content": "first"}},
            {"message": {"content": "  "}},
            {"message": {"content": "second"}}
        ]
    }));
    assert_eq!(chat_output.as_deref(), Some("first\nsecond"));

    let responses_string_output = extract_openai_responses_output(&json!({
        "output": "string output"
    }));
    assert_eq!(responses_string_output.as_deref(), Some("string output"));

    let responses_array_output = extract_openai_responses_output(&json!({
        "output": [{
            "content": [
                {"type": "reasoning", "text": "ignore"},
                {"type": "output_text", "text": "first"},
                {"type": "output_text", "text": "second"}
            ]
        }]
    }));
    assert_eq!(responses_array_output.as_deref(), Some("first\nsecond"));

    assert_eq!(
        regex_escape_literal("  a+b(c)[d]{e}?^$.|\\\\  "),
        "a\\+b\\(c\\)\\[d\\]\\{e\\}\\?\\^\\$\\.\\|\\\\\\\\"
    );
}

#[test]
fn quality_score_filter_keeps_public_fields_and_renames_accuracy() {
    let filtered = filter_quality_scores_for_event(&json!({
        "output_chars": 42,
        "metrics": {
            "aggregate": 0.9,
            "faithfulness": 0.8,
            "relevancy": null,
            "nli_entailment": 0.7
        },
        "judge": {
            "provider": "openai"
        }
    }));

    assert_eq!(filtered["output_chars"], 42);
    assert_eq!(filtered["sentence_count"], serde_json::Value::Null);
    assert_eq!(filtered["aggregate"], 0.9);
    assert_eq!(filtered["faithfulness"], 0.8);
    assert_eq!(filtered["accuracy"], 0.7);
    assert_eq!(filtered["judge"]["provider"], "openai");
    assert!(filtered.get("relevancy").is_none());
}

#[test]
fn streaming_helper_paths_cover_labels_and_buffering_rules() {
    assert_eq!(streaming_mode_label(false, false), "passthrough");
    assert_eq!(streaming_mode_label(true, false), "buffered_policy");
    assert_eq!(streaming_mode_label(false, true), "buffered_redaction");

    let mut redaction_blocks = crate::gateway::PolicyBlocks::new();
    redaction_blocks.insert("pii-detector".to_string(), json!({}));
    assert!(streaming_requires_buffering(
        &["pii-detector".to_string()],
        &redaction_blocks
    ));

    let mut disabled_redaction_blocks = crate::gateway::PolicyBlocks::new();
    disabled_redaction_blocks.insert("pii-detector".to_string(), json!({"action": "off"}));
    assert!(!streaming_requires_buffering(
        &["pii-detector".to_string()],
        &disabled_redaction_blocks
    ));

    let empty_blocks = crate::gateway::PolicyBlocks::new();
    assert!(streaming_requires_buffering(
        &["quality-scorer".to_string()],
        &empty_blocks
    ));
    assert!(!streaming_requires_buffering(
        &["custom-policy".to_string()],
        &empty_blocks
    ));
}

#[test]
fn provider_pin_and_model_routing_helpers_encode_expected_errors() {
    let unknown_provider: serde_json::Value =
        serde_json::from_slice(&build_unknown_provider_pin_body("missing"))
            .expect("unknown provider json");
    assert_eq!(unknown_provider["error"]["code"], "unknown_provider");
    assert_eq!(unknown_provider["error"]["type"], "invalid_provider_pin");

    let no_compliant: serde_json::Value =
        serde_json::from_slice(&build_no_compliant_provider_body())
            .expect("no compliant provider json");
    assert_eq!(no_compliant["error"]["code"], "no_compliant_provider");
    assert_eq!(
        no_compliant["error"]["type"],
        "data_routing_policy_violation"
    );

    let failure = ModelRoutingFailure {
        requested_model: "missing-model".to_string(),
        patterns: vec![
            "openai:*".to_string(),
            "anthropic:[claude-sonnet-4.5]".to_string(),
        ],
        providers: vec![
            "openai-primary".to_string(),
            "anthropic-primary".to_string(),
        ],
    };
    let message = build_model_routing_failure_message(&failure);
    assert!(message.contains("missing-model"));
    assert!(message.contains("openai:*"));
    assert!(message.contains("anthropic-primary"));

    let body: serde_json::Value =
        serde_json::from_slice(&build_model_routing_failure_body(&failure))
            .expect("model routing failure json");
    assert_eq!(body["error"]["type"], "model_routing_failure");
    assert_eq!(body["error"]["code"], "no_matching_provider");
    assert_eq!(body["error"]["message"], message);
}

#[test]
fn target_pattern_and_provider_order_status_are_stable() {
    let explicit = make_provider_target("openai-explicit", "openai", "gpt-4o");
    assert_eq!(target_model_pattern(&explicit), "openai-explicit:gpt-4o");

    let wildcard = make_provider_target("openai-wildcard", "openai", "*");
    assert_eq!(target_model_pattern(&wildcard), "openai-wildcard:*");

    let mut catalog = make_provider_target("catalog", "anthropic", "ignored");
    catalog.models = vec![
        make_provider_model_entry("claude-sonnet-4.5", true),
        make_provider_model_entry("claude-haiku-3.5", false),
        make_provider_model_entry("claude-opus-4.1", true),
    ];
    assert_eq!(
        target_model_pattern(&catalog),
        "catalog:[claude-sonnet-4.5, claude-opus-4.1]"
    );

    assert_eq!(
        provider_order_filter_status(&ProviderOrderFilterError::CostBudgetExceeded),
        StatusCode::FORBIDDEN
    );
}

/// Two scorable auto-routing candidates plus the usage-authorization denied set
/// and price ceiling under test. Targets carry no pricing metadata, so a
/// `Some(ceiling)` excludes both (fail closed) while `None` keeps both.
fn auto_ordering_fixture(
    denied: &[&str],
    max_price_per_1m_tokens: Option<f64>,
) -> (
    ActiveGatewayStateView<'static>,
    super::super::providers::ProviderRegistry,
) {
    let registry = super::super::providers::ProviderRegistry {
        targets: vec![
            make_provider_target("auto-cheap", "openai", "gpt-cheap"),
            make_provider_target("auto-premium", "openai", "gpt-premium"),
        ],
        ..Default::default()
    };
    let mut state = make_runtime_routing_state();
    state.auto_provider.routing.max_price_per_1m_tokens = max_price_per_1m_tokens;
    state.ua_denied_target_ids = denied.iter().map(|id| (*id).to_string()).collect();
    (state, registry)
}

#[test]
fn auto_ordering_fails_closed_when_usage_authorization_denies_every_candidate() {
    let (state, registry) = auto_ordering_fixture(&["auto-cheap", "auto-premium"], None);
    let body = json!({ "model": "auto" });

    let error = apply_auto_provider_ordering(&state, &registry, &[0, 1], &body, "req-1", false)
        .expect_err("an all-denied auto request must not fall back to the unfiltered order");

    assert!(matches!(
        error,
        ProviderOrderFilterError::UsageAuthorizationDeniedAllCandidates
    ));
    assert_eq!(provider_order_filter_status(&error), StatusCode::FORBIDDEN);
    let payload: serde_json::Value =
        serde_json::from_slice(&build_provider_order_filter_body(&error))
            .expect("provider order filter body json");
    assert_eq!(payload["error"]["code"], "no_eligible_provider");
    assert_eq!(payload["error"]["type"], "usage_authorization_denied");
}

#[test]
fn auto_ordering_routes_to_the_remaining_allowed_candidate() {
    let (state, registry) = auto_ordering_fixture(&["auto-cheap"], None);
    let body = json!({ "model": "auto" });

    let ordered = apply_auto_provider_ordering(&state, &registry, &[0, 1], &body, "req-2", false)
        .expect("a partially denied auto request still has an allowed candidate");

    assert_eq!(ordered, vec![1]);
}

#[test]
fn auto_ordering_without_denials_keeps_every_candidate() {
    let (state, registry) = auto_ordering_fixture(&[], None);
    let body = json!({ "model": "auto" });

    let ordered = apply_auto_provider_ordering(&state, &registry, &[0, 1], &body, "req-3", false)
        .expect("an auto request with no denial has candidates");

    assert_eq!(ordered.len(), 2);
}

#[test]
fn auto_ordering_fails_closed_when_the_price_ceiling_excludes_every_candidate() {
    // The scored set is also empty when the eligibility ceiling excludes
    // every candidate. score_targets_with_denied documents that its caller
    // must surface no_eligible_provider, so this must block too — and it
    // must be reported as a ceiling violation, NOT as a usage-authorization
    // denial, including when an unrelated denied entry happens to be
    // present. That second case is what proves the UA branch cannot
    // over-fire and mislabel an ordinary ineligibility as a policy denial.
    for denied in [&[][..], &["some-other-target"][..]] {
        let (state, registry) = auto_ordering_fixture(denied, Some(1.0));
        let body = json!({ "model": "auto" });

        let error = apply_auto_provider_ordering(&state, &registry, &[0, 1], &body, "req-4", false)
            .expect_err("an ineligible auto request must not fall back to every provider");

        assert!(matches!(
            error,
            ProviderOrderFilterError::AutoRoutingNoEligibleProvider
        ));
        assert_eq!(provider_order_filter_status(&error), StatusCode::FORBIDDEN);
        let payload: serde_json::Value =
            serde_json::from_slice(&build_provider_order_filter_body(&error))
                .expect("provider order filter body json");
        assert_eq!(payload["error"]["code"], "no_eligible_provider");
        assert_eq!(
            payload["error"]["type"],
            "auto_routing_constraint_violation"
        );
    }
}

#[test]
fn auto_ordering_passes_through_an_already_empty_candidate_list() {
    // An empty input was never narrowed by this stage, so there is nothing
    // to refuse; the stage must stay transparent rather than invent a block.
    let (state, registry) = auto_ordering_fixture(&[], None);
    let body = json!({ "model": "auto" });

    let ordered = apply_auto_provider_ordering(&state, &registry, &[], &body, "req-5", false)
        .expect("an empty candidate list is passed through unchanged");

    assert!(ordered.is_empty());
}

/// Drives the REAL production composition (resolve_prefiltered_provider_order,
/// the single function every dispatch path funnels through) and asserts the
/// class-wide invariant: a usage-authorization-denied target can never appear in
/// an accepted provider order. Returns the result so each path can also
/// assert its own typed refusal.
fn resolve_order_asserting_no_denied_target_survives(
    state: &ActiveGatewayStateView<'_>,
    registry: &super::super::providers::ProviderRegistry,
    ordered: &[usize],
    body: &serde_json::Value,
    request_id: &str,
) -> Result<Vec<usize>, ProviderOrderFilterError> {
    let result =
        resolve_prefiltered_provider_order(registry, state, ordered, body, request_id, false);
    if let Ok(accepted) = &result {
        for &index in accepted {
            let target_id = &registry.targets[index].id;
            assert!(
                !state.ua_denied_target_ids.contains(target_id),
                "provider ordering restored a usage-authorization denied target ({target_id})"
            );
        }
    }
    result
}

#[test]
fn context_window_path_blocks_instead_of_restoring_denied_targets() {
    let (mut state, mut registry) = auto_ordering_fixture(&["auto-cheap", "auto-premium"], None);
    registry.routing.enable_pre_call_checks = true;
    for target in &mut registry.targets {
        target.max_context_tokens = Some(1);
    }
    // Not an auto request: this proves the context-window stage refuses on
    // its own, without relying on the auto stage that runs after it.
    state.auto_provider.enabled = false;
    let body = json!({
        "model": "gpt-cheap",
        "messages": [{ "role": "user", "content": "a prompt far larger than one token" }]
    });

    let error = resolve_order_asserting_no_denied_target_survives(
        &state,
        &registry,
        &[0, 1],
        &body,
        "req-ctx",
    )
    .expect_err("a prompt that fits in no context window must not be dispatched anyway");

    assert!(matches!(
        error,
        ProviderOrderFilterError::NoContextWindowCapacity { .. }
    ));
    assert_eq!(provider_order_filter_status(&error), StatusCode::FORBIDDEN);
    let payload: serde_json::Value =
        serde_json::from_slice(&build_provider_order_filter_body(&error))
            .expect("provider order filter body json");
    assert_eq!(payload["error"]["code"], "no_eligible_provider");
    assert_eq!(
        payload["error"]["type"],
        "context_window_constraint_violation"
    );
}

#[test]
fn model_group_path_blocks_instead_of_restoring_denied_targets() {
    let (mut state, mut registry) = auto_ordering_fixture(&["auto-cheap", "auto-premium"], None);
    // The group's only member is auto-premium (index 1), but a prior
    // constraint already narrowed the candidates to auto-cheap (index 0),
    // so the group chain resolves empty.
    registry.model_groups = vec![super::super::providers::ModelGroup {
        name: "premium-only".to_string(),
        targets: vec!["auto-premium".to_string()],
        aliases: vec![],
        description: None,
        fallback_group: None,
    }];
    state.auto_provider.enabled = false;
    let body = json!({ "model": "premium-only" });

    let error = resolve_order_asserting_no_denied_target_survives(
        &state,
        &registry,
        &[0],
        &body,
        "req-group",
    )
    .expect_err("an empty model-group chain must not route outside the group");

    assert!(
        matches!(&error, ProviderOrderFilterError::ModelGroupChainEmpty(group) if group == "premium-only")
    );
    assert_eq!(provider_order_filter_status(&error), StatusCode::FORBIDDEN);
    let payload: serde_json::Value =
        serde_json::from_slice(&build_provider_order_filter_body(&error))
            .expect("provider order filter body json");
    assert_eq!(payload["error"]["code"], "no_eligible_provider");
    assert_eq!(payload["error"]["type"], "model_group_constraint_violation");
}

#[test]
fn auto_path_blocks_through_the_full_pipeline_when_usage_authorization_denies_everything() {
    let (state, registry) = auto_ordering_fixture(&["auto-cheap", "auto-premium"], None);
    let body = json!({ "model": "auto" });

    let error = resolve_order_asserting_no_denied_target_survives(
        &state,
        &registry,
        &[0, 1],
        &body,
        "req-auto",
    )
    .expect_err("an all-denied auto request must be refused by the whole pipeline");

    assert!(matches!(
        error,
        ProviderOrderFilterError::UsageAuthorizationDeniedAllCandidates
    ));
}

#[test]
fn every_ordering_stage_that_can_empty_the_candidate_set_reports_a_typed_refusal() {
    // Guards the class as a whole: each refusal maps to 403 with the single
    // agreed client-facing code, so no stage can quietly answer 200 with a
    // restored candidate list.
    for error in [
        ProviderOrderFilterError::CostBudgetExceeded,
        ProviderOrderFilterError::NoMatchingRegion("eu-west".to_string()),
        ProviderOrderFilterError::NoMatchingQuantization,
        ProviderOrderFilterError::NoContextWindowCapacity {
            estimated_tokens: 42,
        },
        ProviderOrderFilterError::ModelGroupChainEmpty("grp".to_string()),
        ProviderOrderFilterError::AutoRoutingNoEligibleProvider,
        ProviderOrderFilterError::UsageAuthorizationDeniedAllCandidates,
    ] {
        assert_eq!(provider_order_filter_status(&error), StatusCode::FORBIDDEN);
        let payload: serde_json::Value =
            serde_json::from_slice(&build_provider_order_filter_body(&error))
                .expect("provider order filter body json");
        assert_eq!(
            payload["error"]["code"], "no_eligible_provider",
            "unexpected code for {error:?}"
        );
    }

    // The residency refusal is the one member of the class that answers 451
    // instead of 403, because it is a compliance refusal rather than a
    // capacity, budget, or capability refusal. It still must never answer 200.
    let residency =
        ProviderOrderFilterError::DataResidencyExcludedAllCandidates("eu-west".to_string());
    assert_eq!(
        provider_order_filter_status(&residency),
        StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&build_provider_order_filter_body(&residency))
            .expect("provider order filter body json");
    assert_eq!(payload["error"]["code"], "no_compliant_provider");
    assert_eq!(payload["error"]["type"], "data_residency_constraint");
}

/// Registry with the live region stage armed: `providers.routing.require_region`
/// is set and each entry of `residency` becomes one target that either declares
/// a `data_residency` block or declares nothing at all.
///
/// The auto provider is disabled so every assertion proves the region stage
/// refuses on its own, without help from the auto stage that runs after it.
fn data_residency_fixture(
    require_region: Option<&str>,
    residency: &[Option<&[&str]>],
) -> (
    ActiveGatewayStateView<'static>,
    super::super::providers::ProviderRegistry,
) {
    let targets = residency
        .iter()
        .enumerate()
        .map(|(index, regions)| {
            let mut target =
                make_provider_target(&format!("residency-{index}"), "openai", "gpt-residency");
            target.data_residency =
                regions.map(|regions| super::super::providers::DataResidencyPolicy {
                    regions: regions.iter().map(|region| (*region).to_string()).collect(),
                    data_center_locations: Vec::new(),
                    sovereignty_compliant: true,
                });
            target
        })
        .collect();
    let mut registry = super::super::providers::ProviderRegistry {
        targets,
        ..Default::default()
    };
    registry.routing.require_region = require_region.map(str::to_string);
    let mut state = make_runtime_routing_state();
    state.auto_provider.enabled = false;
    (state, registry)
}

fn residency_request_body() -> serde_json::Value {
    json!({ "model": "gpt-residency" })
}

#[test]
fn data_residency_keeps_only_the_target_pinned_to_the_required_region() {
    let (state, registry) = data_residency_fixture(
        Some("eu-west"),
        &[Some(&["eu-west"][..]), Some(&["us-east"][..])],
    );

    let ordered = resolve_prefiltered_provider_order(
        &registry,
        &state,
        &[0, 1],
        &residency_request_body(),
        "req-residency-allow",
        false,
    )
    .expect("the eu-west target satisfies the pinned region");

    assert_eq!(
        ordered,
        vec![0],
        "only the target whose data_residency covers eu-west may serve the request"
    );
}

#[test]
fn data_residency_pin_wins_over_a_conflicting_region_label() {
    // The target advertises region us-east but pins its data to eu-west. The
    // residency block is the compliance statement, so a us-east request must
    // not reach it just because the looser label agrees.
    let (state, mut registry) = data_residency_fixture(Some("us-east"), &[Some(&["eu-west"][..])]);
    registry.targets[0].region = Some("us-east".to_string());

    let error = resolve_prefiltered_provider_order(
        &registry,
        &state,
        &[0],
        &residency_request_body(),
        "req-residency-conflict",
        false,
    )
    .expect_err("a residency pin that excludes the region must not be widened by the label");

    assert!(matches!(
        error,
        ProviderOrderFilterError::DataResidencyExcludedAllCandidates(ref region)
            if region == "us-east"
    ));
}

#[test]
fn data_residency_blocks_the_request_when_every_target_is_out_of_region() {
    let (state, registry) = data_residency_fixture(
        Some("eu-west"),
        &[Some(&["us-east"][..]), Some(&["ap-south"][..])],
    );

    let error = resolve_prefiltered_provider_order(
        &registry,
        &state,
        &[0, 1],
        &residency_request_body(),
        "req-residency-deny",
        false,
    )
    .expect_err("an out-of-region pool must be refused, never routed out of region");

    assert!(matches!(
        error,
        ProviderOrderFilterError::DataResidencyExcludedAllCandidates(ref region)
            if region == "eu-west"
    ));
    assert_eq!(
        provider_order_filter_status(&error),
        StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&build_provider_order_filter_body(&error))
            .expect("provider order filter body json");
    assert_eq!(payload["error"]["code"], "no_compliant_provider");
    assert_eq!(payload["error"]["type"], "data_residency_constraint");
    assert_eq!(
        payload["error"]["message"],
        "no provider endpoint satisfies data residency for region 'eu-west'"
    );
}

#[test]
fn region_denial_without_any_residency_policy_keeps_its_existing_shape() {
    // No target declares data_residency, so the pre-existing region refusal
    // must be reported unchanged: 403 with no_eligible_provider.
    let (state, mut registry) = data_residency_fixture(Some("eu-west"), &[None, None]);
    registry.targets[0].region = Some("us-east".to_string());
    registry.targets[1].region = Some("ap-south".to_string());

    let error = resolve_prefiltered_provider_order(
        &registry,
        &state,
        &[0, 1],
        &residency_request_body(),
        "req-region-only-deny",
        false,
    )
    .expect_err("a region mismatch still blocks");

    assert!(matches!(
        error,
        ProviderOrderFilterError::NoMatchingRegion(ref region) if region == "eu-west"
    ));
    assert_eq!(provider_order_filter_status(&error), StatusCode::FORBIDDEN);
    let payload: serde_json::Value =
        serde_json::from_slice(&build_provider_order_filter_body(&error))
            .expect("provider order filter body json");
    assert_eq!(payload["error"]["code"], "no_eligible_provider");
    assert_eq!(payload["error"]["type"], "region_provider_constraint");
}

#[test]
fn a_configuration_without_data_residency_orders_exactly_as_before() {
    // Inertness guard. Neither an unset require_region nor a matching region
    // label may change the accepted order for a config that never mentions
    // data_residency.
    let (state, unconstrained) = data_residency_fixture(None, &[None, None]);
    let ordered = resolve_prefiltered_provider_order(
        &unconstrained,
        &state,
        &[0, 1],
        &residency_request_body(),
        "req-residency-inert-unset",
        false,
    )
    .expect("an unset require_region constrains nothing");
    assert_eq!(ordered, vec![0, 1]);

    let (state, mut labelled) = data_residency_fixture(Some("eu-west"), &[None, None]);
    labelled.targets[0].region = Some("eu-west".to_string());
    labelled.targets[1].region = Some("eu-west".to_string());
    let ordered = resolve_prefiltered_provider_order(
        &labelled,
        &state,
        &[0, 1],
        &residency_request_body(),
        "req-residency-inert-labelled",
        false,
    )
    .expect("matching region labels still satisfy require_region");
    assert_eq!(ordered, vec![0, 1]);
}

#[test]
fn shadow_egress_is_allowed_only_for_an_accepted_mirror_target() {
    let (state, registry) = auto_ordering_fixture(&[], None);

    assert_eq!(
        shadow_egress_decision(
            &registry,
            &[0, 1],
            &state.ua_denied_target_ids,
            "auto-premium",
            "auto-cheap",
        ),
        ShadowEgressDecision::Dispatch { target_index: 1 }
    );
}

#[test]
fn shadow_egress_is_refused_for_a_usage_authorization_denied_mirror() {
    // The mirror is still in the accepted order, so this isolates the
    // usage-authorization arm from the accepted-order arm.
    let (state, registry) = auto_ordering_fixture(&["auto-premium"], None);

    assert_eq!(
        shadow_egress_decision(
            &registry,
            &[0, 1],
            &state.ua_denied_target_ids,
            "auto-premium",
            "auto-cheap",
        ),
        ShadowEgressDecision::Skip(ShadowSkipReason::UsageAuthorizationDenied)
    );
}

#[test]
fn shadow_egress_is_refused_for_a_mirror_outside_the_accepted_order() {
    // Configured and not denied, but dropped by some other eligibility
    // control (price, region, quantization, capability, routing.only,...).
    let (state, registry) = auto_ordering_fixture(&[], None);

    assert_eq!(
        shadow_egress_decision(
            &registry,
            &[0],
            &state.ua_denied_target_ids,
            "auto-premium",
            "auto-cheap",
        ),
        ShadowEgressDecision::Skip(ShadowSkipReason::NotInAcceptedProviderOrder)
    );
}

#[test]
fn shadow_egress_is_refused_for_an_unconfigured_or_self_mirror() {
    let (state, registry) = auto_ordering_fixture(&[], None);

    assert_eq!(
        shadow_egress_decision(
            &registry,
            &[0, 1],
            &state.ua_denied_target_ids,
            "not-a-configured-target",
            "auto-cheap",
        ),
        ShadowEgressDecision::Skip(ShadowSkipReason::TargetNotConfigured)
    );
    assert_eq!(
        shadow_egress_decision(
            &registry,
            &[0, 1],
            &state.ua_denied_target_ids,
            "auto-cheap",
            "auto-cheap",
        ),
        ShadowEgressDecision::Skip(ShadowSkipReason::MirrorsPrimaryTarget)
    );
}

#[test]
fn every_shadow_skip_reason_has_a_bounded_non_secret_reason_code() {
    for reason in [
        ShadowSkipReason::MirrorsPrimaryTarget,
        ShadowSkipReason::TargetNotConfigured,
        ShadowSkipReason::UsageAuthorizationDenied,
        ShadowSkipReason::NotInAcceptedProviderOrder,
    ] {
        let code = reason.reason_code();
        assert!(
            code.starts_with("shadow_skip."),
            "unexpected reason code {code}"
        );
        assert!(code.len() <= 64, "reason code must stay bounded: {code}");
    }
}

#[test]
fn accepted_order_exhaustion_returns_typed_terminal_outcomes() {
    // No accepted candidate was dispatched at all.
    let buffered = build_no_accepted_candidate_buffered_response();
    assert_eq!(buffered.status(), StatusCode::SERVICE_UNAVAILABLE);
    let payload: serde_json::Value =
        serde_json::from_slice(buffered.body()).expect("exhaustion body json");
    assert_eq!(payload["error"]["code"], "provider_candidates_exhausted");
    assert_eq!(payload["error"]["type"], "provider_unavailable");

    // Every accepted candidate failed at the transport layer.
    assert_eq!(
        transport_failure_status(TransportFailureKind::Timeout),
        StatusCode::GATEWAY_TIMEOUT
    );
    assert_eq!(
        transport_failure_status(TransportFailureKind::Unreachable),
        StatusCode::SERVICE_UNAVAILABLE
    );
    for kind in [
        TransportFailureKind::Timeout,
        TransportFailureKind::Unreachable,
    ] {
        let payload: serde_json::Value =
            serde_json::from_slice(&build_transport_failure_body(kind))
                .expect("transport failure body json");
        assert_eq!(payload["error"]["code"], "provider_candidates_exhausted");
        assert_eq!(payload["error"]["type"], "provider_transport_error");
        let message = payload["error"]["message"]
            .as_str()
            .expect("transport failure message");
        assert!(
            !message.contains("http") && !message.contains("://"),
            "client text must not carry an upstream URL: {message}"
        );
    }
}

#[test]
fn provider_canonicalization_and_inference_helpers_cover_known_variants() {
    assert_eq!(
        canonical_provider_from_provider_id("mistralai:primary", ""),
        Some("mistral".to_string())
    );
    assert_eq!(
        canonical_provider_from_provider_id("aws-bedrock", "claude-sonnet-4.5"),
        Some("anthropic".to_string())
    );
    assert_eq!(
        infer_provider_from_model("openai/gpt-5.4-mini"),
        Some("openai".to_string())
    );
    assert_eq!(
        infer_provider_from_model("claude-sonnet-4.5"),
        Some("anthropic".to_string())
    );
    assert_eq!(
        infer_provider_from_upstream("https://models.github.ai/inference"),
        "github"
    );
    assert_eq!(infer_provider_from_upstream("https://api.x.ai/v1"), "xai");

    let mut target = make_provider_target("bedrock", "aws-bedrock", "*");
    target.provider_type = Some(super::super::provider_auth::ProviderType::AwsBedrock);
    assert_eq!(
        canonical_provider_from_target(&target, "claude-sonnet-4.5"),
        Some("anthropic".to_string())
    );
    assert_eq!(
        canonical_provider_slug(Some(&target), "https://api.openai.com", "claude-sonnet-4.5"),
        "anthropic"
    );
    assert_eq!(
        canonical_provider_slug(None, "https://api.cohere.ai/v1", ""),
        "cohere"
    );
}

#[test]
fn provider_prefixed_model_helpers_and_supported_features_are_case_insensitive() {
    assert_eq!(
        split_provider_prefixed_model_reference(" OpenAI / gpt-5.4-mini "),
        Some(("OpenAI", "gpt-5.4-mini"))
    );
    assert_eq!(
        split_provider_prefixed_model_reference("bad!/gpt-5.4-mini"),
        None
    );

    let target = make_provider_target("openai-target", "OpenAI", "*");
    assert_eq!(
        provider_prefixed_model_name_for_target(&target, "openai/gpt-5.4-mini"),
        Some("gpt-5.4-mini")
    );
    assert_eq!(
        provider_prefixed_model_name_for_target(&target, "anthropic/claude-sonnet-4.5"),
        None
    );

    let features = vec!["Tools".to_string(), "Json_Schema".to_string()];
    assert!(supported_features_contain(&features, "tools"));
    assert!(supported_features_contain(&features, "JSON_SCHEMA"));
    assert!(!supported_features_contain(&features, "audio"));
}

#[tokio::test]
async fn inject_ratelimit_info_only_applies_to_successful_responses() {
    let ok = build_response(
        StatusCode::OK,
        HeaderValue::from_static("application/json"),
        "req_ok".to_string(),
        "00-ok".to_string(),
        Bytes::from_static(b"{}"),
        false,
        None,
    );
    let ok = inject_ratelimit_info(
        ok,
        &[
            ("x-ratelimit-limit-requests", "10".to_string()),
            ("bad header", "ignored".to_string()),
        ],
    );
    assert_eq!(
        ok.headers()
            .get("x-ratelimit-limit-requests")
            .and_then(|value| value.to_str().ok()),
        Some("10")
    );
    assert_eq!(ok.headers().len(), 4);

    let not_ok = build_response(
        StatusCode::TOO_MANY_REQUESTS,
        HeaderValue::from_static("application/json"),
        "req_not_ok".to_string(),
        "00-not-ok".to_string(),
        Bytes::from_static(b"{}"),
        false,
        None,
    );
    let not_ok = inject_ratelimit_info(not_ok, &[("x-ratelimit-limit-requests", "10".to_string())]);
    assert_eq!(not_ok.headers().len(), 3);
}

// ── build_response and streaming helpers ────────────────────────────

#[tokio::test]
async fn build_response_sets_common_headers_and_degraded_flag() {
    let response = build_response(
        StatusCode::ACCEPTED,
        HeaderValue::from_static("application/json"),
        "req_hdr".to_string(),
        "00-hdr".to_string(),
        Bytes::from_static(br#"{"ok":true}"#),
        true,
        Some(vec![(
            axum::http::HeaderName::from_static("x-extra"),
            HeaderValue::from_static("value"),
        )]),
    );

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        response
            .headers()
            .get("x-verdictan-degraded")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
    assert_eq!(
        response
            .headers()
            .get("x-extra")
            .and_then(|value| value.to_str().ok()),
        Some("value")
    );

    let json = response_json(response).await;
    assert_eq!(json["ok"], true);
}

#[tokio::test]
async fn response_helpers_include_server_timing_when_request_scoped() {
    let response = REQUEST_STAGE_TIMINGS
        .scope(Arc::new(RequestStageTimings::default()), async move {
            record_request_stage_timing(
                RequestStageTiming::RuntimeRoutingLookup,
                Duration::from_millis(12),
                Some(false),
            );
            record_request_stage_timing(
                RequestStageTiming::UpstreamSend,
                Duration::from_millis(34),
                None,
            );
            build_response(
                StatusCode::OK,
                HeaderValue::from_static("application/json"),
                "req_timing".to_string(),
                "00-timing".to_string(),
                Bytes::from_static(br#"{"ok":true}"#),
                false,
                None,
            )
        })
        .await;
    assert_eq!(
        response
            .headers()
            .get("server-timing")
            .and_then(|value| value.to_str().ok()),
        Some("runtime-routing;dur=12.0, upstream-send;dur=34.0")
    );

    let prepared_response = REQUEST_STAGE_TIMINGS
        .scope(Arc::new(RequestStageTimings::default()), async move {
            record_request_stage_timing(
                RequestStageTiming::TokenValidation,
                Duration::from_millis(5),
                Some(true),
            );
            prepared_streaming_response_to_http_response(
                prepared_streaming_json_response(
                    StatusCode::OK,
                    Bytes::from_static(br#"{"ok":true}"#),
                    HeaderValue::from_static("application/json"),
                ),
                "req_prepared",
                "00-prepared",
            )
        })
        .await;
    assert_eq!(
        prepared_response
            .headers()
            .get("server-timing")
            .and_then(|value| value.to_str().ok()),
        Some("token-validation;dur=5.0")
    );
}

#[tokio::test]
async fn prepared_streaming_and_streaming_response_collect_expected_bytes() {
    let prepared = prepared_streaming_json_response(
        StatusCode::BAD_GATEWAY,
        Bytes::from_static(br#"{"stream":"prepared"}"#),
        HeaderValue::from_static("application/json"),
    );
    let prepared_json = prepared_response_json(prepared).await;
    assert_eq!(prepared_json["stream"], "prepared");

    let (tx, rx) = tokio::sync::mpsc::channel(2);
    tx.send(Ok(Bytes::from_static(b"chunk-1")))
        .await
        .expect("send first chunk");
    tx.send(Ok(Bytes::from_static(b"chunk-2")))
        .await
        .expect("send second chunk");
    drop(tx);

    let response = build_streaming_response(
        StatusCode::OK,
        HeaderValue::from_static("text/plain"),
        "req_stream".to_string(),
        "00-stream".to_string(),
        ReceiverStream::new(rx),
        false,
        Some(vec![(
            axum::http::HeaderName::from_static("x-streaming"),
            HeaderValue::from_static("true"),
        )]),
    );
    assert_eq!(
        response
            .headers()
            .get("x-streaming")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("streaming body");
    assert_eq!(body, Bytes::from_static(b"chunk-1chunk-2"));
}

// ── upstream URL helpers ────────────────────────────────────────────

#[test]
fn join_and_rewrite_upstream_paths_handle_github_models() {
    assert_eq!(
        join_upstream("https://api.openai.com/", "/v1/chat/completions"),
        "https://api.openai.com/v1/chat/completions"
    );
    assert_eq!(
        rewrite_upstream_path("https://models.github.ai/inference", "/v1/chat/completions"),
        "/inference/chat/completions"
    );
    assert_eq!(
        rewrite_upstream_path("https://api.openai.com", "/v1/chat/completions"),
        "/v1/chat/completions"
    );
}

#[test]
fn github_models_api_version_header_uses_override_or_default() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    std::env::remove_var("VERDICTAN_GITHUB_MODELS_API_VERSION");
    assert_eq!(
        github_models_api_version_header(),
        GITHUB_MODELS_DEFAULT_API_VERSION
    );

    std::env::set_var("VERDICTAN_GITHUB_MODELS_API_VERSION", " 2026-06-01 ");
    assert_eq!(github_models_api_version_header(), "2026-06-01");
    std::env::remove_var("VERDICTAN_GITHUB_MODELS_API_VERSION");
}
