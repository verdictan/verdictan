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
use serde_json::json;

// ── derive_usage_category ─────────────────────────────────────────

#[test]
fn usage_category_export() {
    assert_eq!(
        derive_usage_category(&json!({"source": "export"}), None, None),
        "exports"
    );
}

#[test]
fn usage_category_policy_processing() {
    assert_eq!(
        derive_usage_category(&json!({"source": "policy_processing"}), None, None),
        "policy_processing"
    );
}

#[test]
fn usage_category_unknown_source_with_workflow() {
    assert_eq!(
        derive_usage_category(&json!({"source": "other"}), Some("wf-1"), None),
        "workflows"
    );
}

#[test]
fn usage_category_workflow_priority_over_agent() {
    assert_eq!(
        derive_usage_category(&json!({}), Some("wf-1"), Some("a-1")),
        "workflows"
    );
}

#[test]
fn usage_category_agent() {
    assert_eq!(
        derive_usage_category(&json!({}), None, Some("a-1")),
        "agents"
    );
}

#[test]
fn usage_category_empty_agent_falls_through() {
    assert_eq!(
        derive_usage_category(&json!({}), None, Some("")),
        "gateway_llm"
    );
}

#[test]
fn usage_category_empty_workflow_falls_through() {
    assert_eq!(
        derive_usage_category(&json!({}), Some(""), Some("a")),
        "agents"
    );
}

#[test]
fn usage_category_fallback() {
    assert_eq!(derive_usage_category(&json!({}), None, None), "gateway_llm");
    assert_eq!(
        derive_usage_category(&json!(null), None, None),
        "gateway_llm"
    );
}

#[test]
fn default_usage_category_cli_stable() {
    assert_eq!(default_usage_category_cli(), "gateway_llm");
}

// ── normalize_request_agent_id ──────────────────────────────────────

#[test]
fn agent_id_none_is_ok_none() {
    assert_eq!(normalize_request_agent_id(None), Ok(None));
}

#[test]
fn agent_id_empty_is_ok_none() {
    assert_eq!(normalize_request_agent_id(Some("")), Ok(None));
    assert_eq!(normalize_request_agent_id(Some("   ")), Ok(None));
}

#[test]
fn agent_id_valid_ascii_alphanumeric_with_hyphens() {
    assert_eq!(
        normalize_request_agent_id(Some("abc-123")),
        Ok(Some("abc-123".to_string()))
    );
}

#[test]
fn agent_id_trims_whitespace() {
    assert_eq!(
        normalize_request_agent_id(Some("  x  ")),
        Ok(Some("x".to_string()))
    );
}

#[test]
fn agent_id_rejects_over_128() {
    let long = "a".repeat(129);
    assert!(normalize_request_agent_id(Some(&long)).is_err());
}

#[test]
fn agent_id_allows_exactly_128() {
    let exact = "a".repeat(128);
    assert!(normalize_request_agent_id(Some(&exact)).is_ok());
}

#[test]
fn agent_id_rejects_underscores_dots_slashes_spaces() {
    assert!(normalize_request_agent_id(Some("a_b")).is_err());
    assert!(normalize_request_agent_id(Some("a.b")).is_err());
    assert!(normalize_request_agent_id(Some("a/b")).is_err());
    assert!(normalize_request_agent_id(Some("a b")).is_err());
}

// ── request_agent_id_header_value ───────────────────────────────────

#[test]
fn agent_header_prefers_verdictan_prefix() {
    let mut h = HeaderMap::new();
    h.insert("x-verdictan-agent-id", "verdictan".parse().unwrap());
    h.insert("x-agent-id", "generic".parse().unwrap());
    assert_eq!(request_agent_id_header_value(&h), Some("verdictan"));
}

#[test]
fn agent_header_falls_back_to_x_agent_id() {
    let mut h = HeaderMap::new();
    h.insert("x-agent-id", "generic".parse().unwrap());
    assert_eq!(request_agent_id_header_value(&h), Some("generic"));
}

#[test]
fn agent_header_none_when_absent() {
    assert_eq!(request_agent_id_header_value(&HeaderMap::new()), None);
}

// ── normalize_optional_text ─────────────────────────────────────────

#[test]
fn opt_text_some() {
    assert_eq!(normalize_optional_text(Some("x")), Some("x".to_string()));
}

#[test]
fn opt_text_trims() {
    assert_eq!(
        normalize_optional_text(Some("  x  ")),
        Some("x".to_string())
    );
}

#[test]
fn opt_text_empty_after_trim() {
    assert_eq!(normalize_optional_text(Some("   ")), None);
}

#[test]
fn opt_text_none() {
    assert_eq!(normalize_optional_text(None), None);
}

// ── canonical_runtime_execution_surface ─────────────────────────────

#[test]
fn exec_surface_runner_session() {
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
fn exec_surface_interactive() {
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
fn exec_surface_unknown_with_session_implies_runner() {
    assert_eq!(
        canonical_runtime_execution_surface(Some("custom"), Some("s")),
        "runner_session"
    );
    assert_eq!(
        canonical_runtime_execution_surface(None, Some("s")),
        "runner_session"
    );
}

#[test]
fn exec_surface_default_interactive() {
    assert_eq!(
        canonical_runtime_execution_surface(None, None),
        "interactive_chat"
    );
    assert_eq!(
        canonical_runtime_execution_surface(Some(""), None),
        "interactive_chat"
    );
    assert_eq!(
        canonical_runtime_execution_surface(Some("  "), None),
        "interactive_chat"
    );
}

// ── CacheTier ───────────────────────────────────────────────────────

#[test]
fn cache_tier_as_str() {
    assert_eq!(CacheTier::PrivateEdge.as_str(), "private_edge_cache");
    assert_eq!(CacheTier::OrgShared.as_str(), "org_shared_cache");
}

// ── CacheReplayOutcome ──────────────────────────────────────────────

#[test]
fn cache_replay_as_str() {
    assert_eq!(CacheReplayOutcome::ExactHit.as_str(), "exact_hit");
    assert_eq!(
        CacheReplayOutcome::SemanticCandidate.as_str(),
        "semantic_candidate"
    );
    assert_eq!(
        CacheReplayOutcome::SemanticRevalidated.as_str(),
        "semantic_revalidated"
    );
    assert_eq!(
        CacheReplayOutcome::SemanticReplayed.as_str(),
        "semantic_replayed"
    );
    assert_eq!(CacheReplayOutcome::StaleMiss.as_str(), "stale_miss");
    assert_eq!(CacheReplayOutcome::DeniedReplay.as_str(), "denied_replay");
}

#[test]
fn cache_replay_hit_type() {
    assert_eq!(CacheReplayOutcome::ExactHit.hit_type(), "exact");
    assert_eq!(
        CacheReplayOutcome::SemanticCandidate.hit_type(),
        "semantic_candidate"
    );
    assert_eq!(
        CacheReplayOutcome::SemanticRevalidated.hit_type(),
        "semantic_revalidated"
    );
    assert_eq!(
        CacheReplayOutcome::SemanticReplayed.hit_type(),
        "semantic_replayed"
    );
    assert_eq!(CacheReplayOutcome::StaleMiss.hit_type(), "exact");
    assert_eq!(CacheReplayOutcome::DeniedReplay.hit_type(), "exact");
}

// ── CacheReplayMetadata ─────────────────────────────────────────────

#[test]
fn cache_replay_metadata_to_json() {
    let m = CacheReplayMetadata {
        outcome: CacheReplayOutcome::ExactHit,
        cache_tier: CacheTier::PrivateEdge,
        cache_key_digest: Some("abc123".to_string()),
        selected_fabric_artifact_ids: vec!["art-1".to_string()],
        selected_fabric_source_digests: vec!["dig-1".to_string()],
    };
    let j = m.to_json();
    assert_eq!(j["outcome"], "exact_hit");
    assert_eq!(j["cache_tier"], "private_edge_cache");
    assert_eq!(j["cache_key_digest"], "abc123");
    assert_eq!(j["selected_fabric_artifact_ids"][0], "art-1");
}

// ── PricingSource serde ─────────────────────────────────────────────

#[test]
fn pricing_source_serde() {
    assert_eq!(
        serde_json::to_string(&PricingSource::Upstream).unwrap(),
        "\"upstream\""
    );
    assert_eq!(
        serde_json::to_string(&PricingSource::ConfigDeclared).unwrap(),
        "\"config_declared\""
    );
}

// ── validated_key_gateway_binding ────────────────────────────────────

#[test]
fn key_gw_binding_personal_gateway_id() {
    assert_eq!(
        validated_key_gateway_binding(&json!({"personal_gateway_id": "gw-1"})),
        Some("gw-1")
    );
}

#[test]
fn key_gw_binding_gateway_id_fallback() {
    assert_eq!(
        validated_key_gateway_binding(&json!({"gateway_id": "gw-2"})),
        Some("gw-2")
    );
}

#[test]
fn key_gw_binding_personal_priority() {
    assert_eq!(
        validated_key_gateway_binding(&json!({"personal_gateway_id": "p", "gateway_id": "g"})),
        Some("p")
    );
}

#[test]
fn key_gw_binding_empty_skipped() {
    assert_eq!(
        validated_key_gateway_binding(&json!({"personal_gateway_id": "", "gateway_id": "  "})),
        None
    );
}

#[test]
fn key_gw_binding_missing() {
    assert_eq!(validated_key_gateway_binding(&json!({})), None);
}

// ── validated_key_agent_binding ──────────────────────────────────────

#[test]
fn key_agent_binding_present() {
    assert_eq!(
        validated_key_agent_binding(&json!({"agent_id": "a"})),
        Some("a")
    );
}

#[test]
fn key_agent_binding_empty_or_missing() {
    assert_eq!(validated_key_agent_binding(&json!({"agent_id": ""})), None);
    assert_eq!(
        validated_key_agent_binding(&json!({"agent_id": "  "})),
        None
    );
    assert_eq!(validated_key_agent_binding(&json!({})), None);
}

// ── parse_expiry_timestamp ──────────────────────────────────────────

#[test]
fn parse_expiry_valid_rfc3339() {
    assert!(parse_expiry_timestamp(Some("2025-06-01T12:00:00Z")).is_some());
    assert!(parse_expiry_timestamp(Some("2025-06-01T12:00:00+05:30")).is_some());
}

#[test]
fn parse_expiry_invalid_or_none() {
    assert!(parse_expiry_timestamp(Some("not-a-date")).is_none());
    assert!(parse_expiry_timestamp(None).is_none());
    assert!(parse_expiry_timestamp(Some("")).is_none());
}

// ── normalize_text_scope_values ─────────────────────────────────────

#[test]
fn text_scope_sorts_deduplicates_filters() {
    assert_eq!(
        normalize_text_scope_values(&["b".into(), "a".into(), "b".into()]),
        vec!["a", "b"]
    );
    assert_eq!(
        normalize_text_scope_values(&["a".into(), "".into(), "  ".into()]),
        vec!["a"]
    );
    assert_eq!(normalize_text_scope_values(&["  x  ".into()]), vec!["x"]);
}

// ── intersect_scope_values ──────────────────────────────────────────

#[test]
fn intersect_both_empty() {
    assert!(intersect_scope_values(&[], &[], normalize_text_scope_values).is_empty());
}

#[test]
fn intersect_binding_only() {
    let r = intersect_scope_values(&["a".into(), "b".into()], &[], normalize_text_scope_values);
    assert_eq!(r, vec!["a", "b"]);
}

#[test]
fn intersect_policy_only() {
    let r = intersect_scope_values(&[], &["x".into()], normalize_text_scope_values);
    assert_eq!(r, vec!["x"]);
}

#[test]
fn intersect_overlapping() {
    let r = intersect_scope_values(
        &["a".into(), "b".into()],
        &["b".into(), "c".into()],
        normalize_text_scope_values,
    );
    assert_eq!(r, vec!["b"]);
}

#[test]
fn intersect_disjoint() {
    let r = intersect_scope_values(&["a".into()], &["b".into()], normalize_text_scope_values);
    assert!(r.is_empty());
}

// ── GatewayRuntimeMetrics ───────────────────────────────────────────

#[test]
fn runtime_metrics_initial_zero_and_increments() {
    let m = GatewayRuntimeMetrics::default();
    assert_eq!(m.as_json()["token_validation_cache_hits"], 0);

    m.record_token_validation_cache_hit();
    m.record_token_validation_cache_hit();
    m.record_token_validation_cache_miss();
    m.record_runtime_controls_cache_hit();
    m.record_runtime_controls_cache_miss();
    m.record_manifest_fetch();
    m.record_yaml_fetch();
    m.record_runtime_build_failure();

    let j = m.as_json();
    assert_eq!(j["token_validation_cache_hits"], 2);
    assert_eq!(j["token_validation_cache_misses"], 1);
    assert_eq!(j["runtime_controls_cache_hits"], 1);
    assert_eq!(j["runtime_controls_cache_misses"], 1);
    assert_eq!(j["manifest_fetches"], 1);
    assert_eq!(j["yaml_fetches"], 1);
    assert_eq!(j["runtime_build_failures"], 1);
}

// ── BudgetFilterRejection ───────────────────────────────────────────

#[test]
fn budget_rejection_forbidden() {
    let r = BudgetFilterRejection::forbidden("msg", "code");
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.error_type, "cost_budget_exceeded");
}

#[test]
fn budget_rejection_access_denied() {
    let r = BudgetFilterRejection::access_denied("msg", "code");
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.error_type, "access_denied");
}

#[test]
fn budget_rejection_service_unavailable() {
    let r = BudgetFilterRejection::service_unavailable("msg", "code");
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.error_type, "service_unavailable");
}

#[test]
fn build_budget_filter_body_is_valid_json() {
    let r = BudgetFilterRejection::forbidden("test", "c");
    let body = build_budget_filter_body(&r);
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(parsed.get("error").is_some());
}

// ── TokenValidationError Display ────────────────────────────────────

#[test]
fn token_val_error_display_all_variants() {
    let e1 = TokenValidationError::Unauthorized { body: "b".into() };
    assert!(e1.to_string().contains("unauthorized"));
    let e2 = TokenValidationError::Forbidden { body: "b".into() };
    assert!(e2.to_string().contains("forbidden"));
    let e3 = TokenValidationError::UnexpectedStatus {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        body: "b".into(),
    };
    assert!(e3.to_string().contains("500"));
}

// ── TokenDepletionState ─────────────────────────────────────────────

#[test]
fn token_depletion_state_defaults_and_full() {
    let empty: TokenDepletionState = serde_json::from_value(json!({})).unwrap();
    assert!(empty.max_budget.is_none());
    assert!(empty.current_spend.is_none());

    let full: TokenDepletionState = serde_json::from_value(json!({
        "max_budget": 100.0, "current_spend": 42.5, "remaining_budget": 57.5,
        "max_requests": 1000, "current_requests": 500, "remaining_requests": 500
    }))
    .unwrap();
    assert_eq!(full.max_budget, Some(100.0));
    assert_eq!(full.max_requests, Some(1000));
}

// ── RequestFinopsContext ────────────────────────────────────────────

#[test]
fn finops_context_has_token_identity() {
    let mut ctx = RequestFinopsContext::default();
    assert!(!ctx.has_token_identity());
    ctx.key_id = Some("k".into());
    assert!(ctx.has_token_identity());
    ctx.key_id = Some("".into());
    assert!(!ctx.has_token_identity());
    ctx.key_id = Some("   ".into());
    assert!(!ctx.has_token_identity());
}

// ── EventSinkConfig::from_env ───────────────────────────────────────

#[test]
fn event_sink_config_none_without_vars() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    std::env::remove_var("VERDICTAN_API_URL");
    std::env::remove_var("VERDICTAN_API_TOKEN");
    assert!(EventSinkConfig::from_env().unwrap().is_none());
}

#[test]
fn event_sink_config_none_for_empty_url() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    std::env::set_var("VERDICTAN_API_URL", "   ");
    std::env::remove_var("VERDICTAN_API_TOKEN");
    assert!(EventSinkConfig::from_env().unwrap().is_none());
    std::env::remove_var("VERDICTAN_API_URL");
}

#[test]
fn event_sink_config_none_without_token() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    std::env::set_var("VERDICTAN_API_URL", "http://localhost");
    std::env::remove_var("VERDICTAN_API_TOKEN");
    assert!(EventSinkConfig::from_env().unwrap().is_none());
    std::env::remove_var("VERDICTAN_API_URL");
}

#[test]
fn event_sink_config_some_with_both() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    std::env::set_var("VERDICTAN_API_URL", "http://api.test");
    std::env::set_var("VERDICTAN_API_TOKEN", "tok-1");
    let config = EventSinkConfig::from_env().unwrap().unwrap();
    assert_eq!(config.base_url, "http://api.test");
    assert_eq!(config.api_token, "tok-1");
    assert_eq!(config.gateway_service_token.as_deref(), Some("tok-1"));
    std::env::remove_var("VERDICTAN_API_URL");
    std::env::remove_var("VERDICTAN_API_TOKEN");
}

// ── optional_env ────────────────────────────────────────────────────

#[test]
fn optional_env_missing() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    std::env::remove_var("__COVERAGE_TEST_MISSING");
    assert!(optional_env("__COVERAGE_TEST_MISSING").is_none());
}

#[test]
fn optional_env_empty() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    std::env::set_var("__COVERAGE_TEST_EMPTY", "   ");
    assert!(optional_env("__COVERAGE_TEST_EMPTY").is_none());
    std::env::remove_var("__COVERAGE_TEST_EMPTY");
}

#[test]
fn optional_env_present() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    std::env::set_var("__COVERAGE_TEST_PRESENT", " val ");
    assert_eq!(
        optional_env("__COVERAGE_TEST_PRESENT"),
        Some("val".to_string())
    );
    std::env::remove_var("__COVERAGE_TEST_PRESENT");
}

// ── normalize_provider_alias_list ────────────────────────────────────

#[test]
fn provider_alias_list_sorts_deduplicates_filters() {
    let input = vec![
        "OpenAI".into(),
        "openai".into(),
        "".into(),
        "anthropic".into(),
    ];
    let result = normalize_provider_alias_list(&input);
    assert!(result.contains(&"openai".to_string()));
    assert!(result.contains(&"anthropic".to_string()));
    assert!(!result.contains(&"".to_string()));
    let unique_count = result
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len();
    assert_eq!(unique_count, result.len());
}

// ── GatewayControlsPayload deserialization ──────────────────────────

#[test]
fn gateway_controls_payload_defaults() {
    let p: GatewayControlsPayload = serde_json::from_value(json!({})).unwrap();
    assert!(!p.fail_closed);
    assert!(p.allowed_providers.is_empty());
    assert!(p.allowed_models.is_empty());
    assert!(p.allowed_gateways.is_empty());
    assert!(p.disabled_providers.is_empty());
}

#[test]
fn gateway_controls_payload_full() {
    let p: GatewayControlsPayload = serde_json::from_value(json!({
        "fail_closed": true,
        "allowed_providers": ["openai"],
        "allowed_models": ["gpt-4"],
        "allowed_gateways": ["gw-1"],
        "disabled_providers": ["azure"]
    }))
    .unwrap();
    assert!(p.fail_closed);
    assert_eq!(p.allowed_providers, vec!["openai"]);
    assert_eq!(p.disabled_providers, vec!["azure"]);
}

// ── GatewayIpRestrictions ───────────────────────────────────────────

#[test]
fn gateway_ip_restrictions_deserialization() {
    let r: GatewayIpRestrictions =
        serde_json::from_value(json!({"cidrs": ["10.0.0.0/8"]})).unwrap();
    assert_eq!(r.cidrs, vec!["10.0.0.0/8"]);
}

// ── TokenHistoryDefaults ────────────────────────────────────────────

#[test]
fn token_history_defaults_deserialization() {
    let h: TokenHistoryDefaults = serde_json::from_value(json!({
        "capture_mode": "full",
        "previous_sessions_max": 5,
        "previous_allowed_requests_max": 10
    }))
    .unwrap();
    assert_eq!(h.capture_mode, "full");
    assert_eq!(h.previous_sessions_max, 5);
    assert_eq!(h.previous_allowed_requests_max, 10);
}

// ── ControlPlaneBudgetQueryCacheKey / ControlPlaneProviderBudgetQueryCacheKey ─

#[test]
fn budget_query_cache_key_equality_and_hash() {
    let k1 = ControlPlaneBudgetQueryCacheKey {
        org_id: "org".into(),
        target_type: "team".into(),
        target_id: Some("t".into()),
        team_id: None,
        user_id: None,
        key_id: None,
    };
    let k2 = k1.clone();
    assert_eq!(k1, k2);

    let mut set = std::collections::HashSet::new();
    set.insert(k1);
    assert!(set.contains(&k2));
}

#[test]
fn provider_budget_query_cache_key_equality() {
    let k1 = ControlPlaneProviderBudgetQueryCacheKey {
        org_id: "o".into(),
        provider: "p".into(),
        model: Some("m".into()),
        team_id: None,
        user_id: None,
        key_id: None,
    };
    let k2 = k1.clone();
    assert_eq!(k1, k2);
}

// ── SpendLogPayload serde ───────────────────────────────────────────

#[test]
fn spend_log_payload_serialization() {
    let p = SpendLogPayload {
        provider: "openai".into(),
        model: "gpt".into(),
        usage_category: "gateway_llm".into(),
        pricing_source: Some(PricingSource::Upstream),
        prompt_tokens: 100,
        completion_tokens: 50,
        total_tokens: 150,
        cached_input_tokens: 10,
        prompt_cost: 0.003,
        completion_cost: 0.002,
        cached_input_cost: 0.0,
        total_cost: 0.005,
        currency: "USD".into(),
        key_id: None,
        user_id: None,
        team_id: None,
        provider_target_id: None,
        model_id: None,
        requested_model: None,
        requested_provider: None,
        pricing_snapshot: None,
        metadata: serde_json::json!({}),
        gateway_id: None,
        configuration_id: None,
        configuration_version_id: None,
        agent_id: None,
        gateway_execution_session_id: None,
        execution_surface: None,
        request_bytes: 0,
        response_bytes: 0,
        processing_units: 0,
        conversation_id: None,
        catalog_input_price: None,
        catalog_output_price: None,
        catalog_model_id: None,
        catalog_provider_id: None,
        catalog_pricing_source: None,
    };
    let j = serde_json::to_value(&p).unwrap();
    assert_eq!(j["provider"], "openai");
    assert_eq!(j["pricing_source"], "upstream");
    assert_eq!(j["total_cost"], 0.005);
}

// ── build_token_validation_error_response ───────────────────────────

#[test]
fn token_validation_error_response_unauthorized() {
    let e = TokenValidationError::Unauthorized { body: "bad".into() };
    let r = build_token_validation_error_response("req-1", "tp-1", &e);
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn token_validation_error_response_request_error() {
    let client = reqwest::Client::new();
    let err = client.get("http://[invalid-ipv6").build().unwrap_err();
    let e = TokenValidationError::Request(err);
    let r = build_token_validation_error_response("req-1", "tp-1", &e);
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
}
