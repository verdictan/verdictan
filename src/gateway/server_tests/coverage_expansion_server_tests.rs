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
        derive_usage_category(&meta, Some("wf-123"), None),
        "workflows"
    );
}

#[test]
fn usage_category_agent_id_present() {
    let meta = json!({});
    assert_eq!(
        derive_usage_category(&meta, None, Some("agent-1")),
        "agents"
    );
}

#[test]
fn usage_category_empty_workflow_id_fallthrough() {
    let meta = json!({});
    assert_eq!(derive_usage_category(&meta, Some(""), None), "gateway_llm");
}

#[test]
fn usage_category_empty_agent_id_fallthrough() {
    let meta = json!({});
    assert_eq!(derive_usage_category(&meta, None, Some("")), "gateway_llm");
}

#[test]
fn usage_category_unknown_source_falls_through() {
    let meta = json!({"source": "unknown_src"});
    assert_eq!(derive_usage_category(&meta, None, None), "gateway_llm");
}

#[test]
fn usage_category_null_metadata() {
    let meta = json!(null);
    assert_eq!(derive_usage_category(&meta, None, None), "gateway_llm");
}

#[test]
fn usage_category_workflow_takes_priority_over_agent() {
    let meta = json!({});
    assert_eq!(
        derive_usage_category(&meta, Some("wf-1"), Some("agent-1")),
        "workflows"
    );
}

#[test]
fn usage_category_export_takes_priority_over_workflow() {
    let meta = json!({"source": "export"});
    assert_eq!(
        derive_usage_category(&meta, Some("wf-1"), Some("agent-1")),
        "exports"
    );
}

// ── normalize_request_agent_id ──────────────────────────────────────

#[test]
fn normalize_agent_id_none_input() {
    assert_eq!(normalize_request_agent_id(None).unwrap(), None);
}

#[test]
fn normalize_agent_id_empty_string() {
    assert_eq!(normalize_request_agent_id(Some("")).unwrap(), None);
}

#[test]
fn normalize_agent_id_whitespace_only() {
    assert_eq!(normalize_request_agent_id(Some("   ")).unwrap(), None);
}

#[test]
fn normalize_agent_id_valid() {
    assert_eq!(
        normalize_request_agent_id(Some("my-agent-123")).unwrap(),
        Some("my-agent-123".to_string())
    );
}

#[test]
fn normalize_agent_id_too_long() {
    let long_id = "a".repeat(129);
    assert!(normalize_request_agent_id(Some(&long_id)).is_err());
}

#[test]
fn normalize_agent_id_invalid_chars() {
    assert!(normalize_request_agent_id(Some("agent_with_underscore")).is_err());
}

#[test]
fn normalize_agent_id_max_length_boundary() {
    let max_id = "a".repeat(128);
    assert_eq!(
        normalize_request_agent_id(Some(&max_id)).unwrap(),
        Some(max_id)
    );
}

#[test]
fn normalize_agent_id_trims_whitespace() {
    assert_eq!(
        normalize_request_agent_id(Some("  abc  ")).unwrap(),
        Some("abc".to_string())
    );
}

// ── request_agent_id_header_value ───────────────────────────────────

#[test]
fn request_agent_id_header_prefers_verdictan_header() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-agent-id",
        HeaderValue::from_static("verdictan-agent"),
    );
    headers.insert("x-agent-id", HeaderValue::from_static("generic-agent"));
    assert_eq!(
        request_agent_id_header_value(&headers),
        Some("verdictan-agent")
    );
}

#[test]
fn request_agent_id_header_fallback_to_generic() {
    let mut headers = HeaderMap::new();
    headers.insert("x-agent-id", HeaderValue::from_static("generic-agent"));
    assert_eq!(
        request_agent_id_header_value(&headers),
        Some("generic-agent")
    );
}

#[test]
fn request_agent_id_header_missing_both() {
    let headers = HeaderMap::new();
    assert_eq!(request_agent_id_header_value(&headers), None);
}

// ── LocalBudgetTracker ──────────────────────────────────────────────

#[test]
fn local_budget_tracker_try_reserve_sufficient() {
    let tracker = LocalBudgetTracker::new(1.0, Some(0.01), Some(0.03), Some(1.0), None);
    let result = tracker.try_reserve(100, 100);
    assert!(result.is_ok());
    let cost = result.unwrap();
    assert!((cost - 0.004).abs() < 0.001);
}

#[test]
fn local_budget_tracker_try_reserve_insufficient() {
    let tracker = LocalBudgetTracker::new(0.001, Some(0.01), Some(0.03), Some(0.001), None);
    let result = tracker.try_reserve(1000, 1000);
    assert!(result.is_err());
}

#[test]
fn local_budget_tracker_try_reserve_zero_cost() {
    let tracker = LocalBudgetTracker::new(1.0, None, None, Some(1.0), None);
    let result = tracker.try_reserve(100, 100);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0.0);
}

#[test]
fn local_budget_tracker_credit_back() {
    let tracker = LocalBudgetTracker::new(0.5, Some(0.01), Some(0.03), Some(1.0), None);
    let _ = tracker.try_reserve(100, 100);
    tracker.credit_back(2.0);
    let remaining = *tracker.remaining.lock().unwrap();
    assert!(remaining > 0.0);
}

#[test]
fn local_budget_tracker_credit_back_zero() {
    let tracker = LocalBudgetTracker::new(1.0, Some(0.01), None, None, None);
    let before = *tracker.remaining.lock().unwrap();
    tracker.credit_back(0.0);
    let after = *tracker.remaining.lock().unwrap();
    assert_eq!(before, after);
}

#[test]
fn local_budget_tracker_credit_back_negative() {
    let tracker = LocalBudgetTracker::new(1.0, Some(0.01), None, None, None);
    let before = *tracker.remaining.lock().unwrap();
    tracker.credit_back(-5.0);
    let after = *tracker.remaining.lock().unwrap();
    assert_eq!(before, after);
}

#[test]
fn local_budget_tracker_has_pricing_with_input() {
    let tracker = LocalBudgetTracker::new(1.0, Some(0.01), None, None, None);
    assert!(tracker.has_pricing());
}

#[test]
fn local_budget_tracker_has_pricing_with_output() {
    let tracker = LocalBudgetTracker::new(1.0, None, Some(0.03), None, None);
    assert!(tracker.has_pricing());
}

#[test]
fn local_budget_tracker_no_pricing() {
    let tracker = LocalBudgetTracker::new(1.0, None, None, None, None);
    assert!(!tracker.has_pricing());
}

// ── CacheTier ───────────────────────────────────────────────────────

#[test]
fn cache_tier_as_str() {
    assert_eq!(CacheTier::PrivateEdge.as_str(), "private_edge_cache");
    assert_eq!(CacheTier::OrgShared.as_str(), "org_shared_cache");
}

// ── CacheReplayOutcome ──────────────────────────────────────────────

#[test]
fn cache_replay_outcome_as_str() {
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
fn cache_replay_outcome_hit_type() {
    assert_eq!(CacheReplayOutcome::ExactHit.hit_type(), "exact");
    assert_eq!(
        CacheReplayOutcome::SemanticCandidate.hit_type(),
        "semantic_candidate"
    );
    assert_eq!(
        CacheReplayOutcome::SemanticRevalidated.hit_type(),
        "semantic_revalidated"
    );
    assert_eq!(CacheReplayOutcome::StaleMiss.hit_type(), "exact");
    assert_eq!(CacheReplayOutcome::DeniedReplay.hit_type(), "exact");
}

// ── CacheReplayMetadata ─────────────────────────────────────────────

#[test]
fn cache_replay_metadata_to_json() {
    let meta = CacheReplayMetadata {
        outcome: CacheReplayOutcome::ExactHit,
        cache_tier: CacheTier::PrivateEdge,
        cache_key_digest: Some("abc123".to_string()),
        selected_fabric_artifact_ids: vec!["art-1".to_string()],
        selected_fabric_source_digests: vec!["dig-1".to_string()],
    };
    let j = meta.to_json();
    assert_eq!(j["outcome"], "exact_hit");
    assert_eq!(j["cache_tier"], "private_edge_cache");
    assert_eq!(j["cache_key_digest"], "abc123");
}

// ── canonical_runtime_execution_surface ──────────────────────────────

#[test]
fn execution_surface_runner_session() {
    assert_eq!(
        canonical_runtime_execution_surface(Some("runner_session"), None),
        "runner_session"
    );
}

#[test]
fn execution_surface_gateway_execution_session() {
    assert_eq!(
        canonical_runtime_execution_surface(Some("gateway_execution_session"), None),
        "runner_session"
    );
}

#[test]
fn execution_surface_interactive_chat() {
    assert_eq!(
        canonical_runtime_execution_surface(Some("interactive_chat"), None),
        "interactive_chat"
    );
}

#[test]
fn execution_surface_gateway_alias() {
    assert_eq!(
        canonical_runtime_execution_surface(Some("gateway"), None),
        "interactive_chat"
    );
}

#[test]
fn execution_surface_none_with_session_id() {
    assert_eq!(
        canonical_runtime_execution_surface(None, Some("sess-123")),
        "runner_session"
    );
}

#[test]
fn execution_surface_none_no_session_id() {
    assert_eq!(
        canonical_runtime_execution_surface(None, None),
        "interactive_chat"
    );
}

#[test]
fn execution_surface_unknown_with_session_id() {
    assert_eq!(
        canonical_runtime_execution_surface(Some("unknown"), Some("sess-1")),
        "runner_session"
    );
}

#[test]
fn execution_surface_empty_string() {
    assert_eq!(
        canonical_runtime_execution_surface(Some("  "), None),
        "interactive_chat"
    );
}

// ── ConnectedPostDispatchUsageSource ─────────────────────────────────

#[test]
fn usage_source_as_str() {
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
}

#[test]
fn usage_source_is_estimated() {
    assert!(!ConnectedPostDispatchUsageSource::UpstreamReported.is_estimated());
    assert!(ConnectedPostDispatchUsageSource::PromptOnlyFallback.is_estimated());
    assert!(ConnectedPostDispatchUsageSource::StreamingEstimate.is_estimated());
}

// ── ConnectedAccessPreflightOutcome ─────────────────────────────────

#[test]
fn preflight_outcome_carries_ready_byok_key_material() {
    let outcome = ConnectedAccessPreflightOutcome {
        primary: super::super::access_preflight::AccessPreflightResponse {
            status: "ready_byok".to_string(),
            status_reason: String::new(),
            resolved_api_key: Some("sk-org-owned".to_string()),
            org_authz_version: Some(9),
            remaining_budget: None,
            cost_per_1k_input_tokens: None,
            cost_per_1k_output_tokens: None,
            budget_limit: None,
            spend_so_far: None,
            budget_period: None,
        },
        org_authz_version: Some(9),
        local_budget_tracker: None,
    };
    assert_eq!(outcome.primary.status, "ready_byok");
    assert_eq!(
        outcome.primary.resolved_api_key.as_deref(),
        Some("sk-org-owned")
    );
}

#[test]
fn preflight_outcome_without_ready_byok_carries_no_key() {
    let outcome = ConnectedAccessPreflightOutcome {
        primary: super::super::access_preflight::AccessPreflightResponse {
            status: "inactive".to_string(),
            status_reason: "provider_key_missing".to_string(),
            resolved_api_key: None,
            org_authz_version: None,
            remaining_budget: None,
            cost_per_1k_input_tokens: None,
            cost_per_1k_output_tokens: None,
            budget_limit: None,
            spend_so_far: None,
            budget_period: None,
        },
        org_authz_version: None,
        local_budget_tracker: None,
    };
    assert_ne!(outcome.primary.status, "ready_byok");
    assert!(outcome.primary.resolved_api_key.is_none());
}

// ── normalize_optional_text ──────────────────────────────────────────

#[test]
fn normalize_optional_text_some_value() {
    assert_eq!(
        normalize_optional_text(Some("  hello  ")),
        Some("hello".to_string())
    );
}

#[test]
fn normalize_optional_text_empty_after_trim() {
    assert_eq!(normalize_optional_text(Some("   ")), None);
}

#[test]
fn normalize_optional_text_none() {
    assert_eq!(normalize_optional_text(None), None);
}

// ── normalize_text_scope_values ──────────────────────────────────────

#[test]
fn normalize_text_scope_values_deduplicates_and_sorts() {
    let values = vec![
        " b ".to_string(),
        "a".to_string(),
        "b".to_string(),
        "".to_string(),
    ];
    let result = normalize_text_scope_values(&values);
    assert_eq!(result, vec!["a", "b"]);
}

// ── intersect_scope_values ───────────────────────────────────────────

#[test]
fn intersect_scope_both_empty() {
    let result = intersect_scope_values(&[], &[], normalize_text_scope_values);
    assert!(result.is_empty());
}

#[test]
fn intersect_scope_binding_only() {
    let binding = vec!["a".to_string(), "b".to_string()];
    let result = intersect_scope_values(&binding, &[], normalize_text_scope_values);
    assert_eq!(result, vec!["a", "b"]);
}

#[test]
fn intersect_scope_policy_only() {
    let policy = vec!["x".to_string(), "y".to_string()];
    let result = intersect_scope_values(&[], &policy, normalize_text_scope_values);
    assert_eq!(result, vec!["x", "y"]);
}

#[test]
fn intersect_scope_intersection() {
    let binding = vec!["a".to_string(), "b".to_string(), "c".to_string()];
    let policy = vec!["b".to_string(), "c".to_string(), "d".to_string()];
    let result = intersect_scope_values(&binding, &policy, normalize_text_scope_values);
    assert_eq!(result, vec!["b", "c"]);
}

#[test]
fn intersect_scope_no_overlap() {
    let binding = vec!["a".to_string()];
    let policy = vec!["b".to_string()];
    let result = intersect_scope_values(&binding, &policy, normalize_text_scope_values);
    assert!(result.is_empty());
}

// ── token helpers ───────────────────────────────────────────────────

#[test]
fn token_current_spend_from_depletion() {
    let key = TokenRecord {
        id: "k1".into(),
        gateway_id: None,
        provider: None,
        model_filter: vec![],
        team_id: None,
        user_id: None,
        max_budget: None,
        current_spend: 5.0,
        key_class: None,
        resource_id: None,
        resource_vrn: None,
        expires_at: None,
        metadata: json!({}),
        rate_limit_rpm: None,
    };
    let validation = TokenValidationResponse {
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
            max_budget: Some(100.0),
            current_spend: Some(42.0),
            remaining_budget: Some(58.0),
            max_requests: None,
            current_requests: None,
            remaining_requests: None,
        }),
        ip_restrictions: None,
        entitlements: vec![],
        history: None,
        created_by: None,
        key: None,
        gateway_controls: None,
        org_authz_version: None,
    };
    assert_eq!(token_current_spend(&key, &validation), 42.0);
}

#[test]
fn token_current_spend_fallback_to_key() {
    let key = TokenRecord {
        id: "k1".into(),
        gateway_id: None,
        provider: None,
        model_filter: vec![],
        team_id: None,
        user_id: None,
        max_budget: None,
        current_spend: 7.5,
        key_class: None,
        resource_id: None,
        resource_vrn: None,
        expires_at: None,
        metadata: json!({}),
        rate_limit_rpm: None,
    };
    let validation = TokenValidationResponse {
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
        depletion: None,
        ip_restrictions: None,
        entitlements: vec![],
        history: None,
        created_by: None,
        key: None,
        gateway_controls: None,
        org_authz_version: None,
    };
    assert_eq!(token_current_spend(&key, &validation), 7.5);
}

// ── parse_expiry_timestamp ───────────────────────────────────────────

#[test]
fn parse_expiry_valid_rfc3339() {
    let result = parse_expiry_timestamp(Some("2026-01-15T10:30:00Z"));
    assert!(result.is_some());
}

#[test]
fn parse_expiry_invalid_format() {
    let result = parse_expiry_timestamp(Some("not-a-date"));
    assert!(result.is_none());
}

#[test]
fn parse_expiry_none() {
    let result = parse_expiry_timestamp(None);
    assert!(result.is_none());
}

// ── BudgetFilterRejection ───────────────────────────────────────────

#[test]
fn budget_filter_rejection_forbidden() {
    let rejection = BudgetFilterRejection::forbidden("over budget", "budget_exceeded");
    assert_eq!(rejection.status, StatusCode::FORBIDDEN);
    assert_eq!(rejection.error_type, "cost_budget_exceeded");
    assert_eq!(rejection.code, "budget_exceeded");
    assert_eq!(rejection.message, "over budget");
}

#[test]
fn budget_filter_rejection_access_denied() {
    let rejection = BudgetFilterRejection::access_denied("not allowed", "denied");
    assert_eq!(rejection.status, StatusCode::FORBIDDEN);
    assert_eq!(rejection.error_type, "access_denied");
}

#[test]
fn budget_filter_rejection_service_unavailable() {
    let rejection = BudgetFilterRejection::service_unavailable("down", "billing_unavailable");
    assert_eq!(rejection.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(rejection.error_type, "service_unavailable");
}

// ── RequestFinopsContext ────────────────────────────────────────────

#[test]
fn request_finops_has_token_identity_true() {
    let ctx = RequestFinopsContext {
        key_id: Some("key-123".to_string()),
        ..Default::default()
    };
    assert!(ctx.has_token_identity());
}

#[test]
fn request_finops_has_token_identity_false_empty() {
    let ctx = RequestFinopsContext {
        key_id: Some("  ".to_string()),
        ..Default::default()
    };
    assert!(!ctx.has_token_identity());
}

#[test]
fn request_finops_has_token_identity_false_none() {
    let ctx = RequestFinopsContext::default();
    assert!(!ctx.has_token_identity());
}

#[test]
fn request_finops_identity_context_json_populated() {
    let ctx = RequestFinopsContext {
        key_id: Some("k1".to_string()),
        org_id: Some("org-1".to_string()),
        user_id: Some("u1".to_string()),
        team_id: Some("t1".to_string()),
        ..Default::default()
    };
    let json = ctx.identity_context_json().unwrap();
    assert_eq!(json["key_id"], "k1");
    assert_eq!(json["org_id"], "org-1");
}

#[test]
fn request_finops_identity_context_json_empty() {
    let ctx = RequestFinopsContext::default();
    assert!(ctx.identity_context_json().is_none());
}

#[test]
fn request_finops_context_selection_json_present() {
    let ctx = RequestFinopsContext {
        context_plan_hash: Some("hash123".to_string()),
        context_policy_version: Some(3),
        context_selected_item_ids: vec!["item-1".to_string()],
        context_citation_required_count: Some(2),
        context_max_tokens: Some(4096),
        context_estimated_tokens: Some(1000),
        context_injected_tokens: Some(500),
        working_context_tokens: Some(200),
        ..Default::default()
    };
    let json = ctx.context_selection_json().unwrap();
    assert_eq!(json["plan_hash"], "hash123");
}

#[test]
fn request_finops_context_selection_json_empty_hash() {
    let ctx = RequestFinopsContext {
        context_plan_hash: Some("  ".to_string()),
        ..Default::default()
    };
    assert!(ctx.context_selection_json().is_none());
}

// ── GatewayRuntimeMetrics ───────────────────────────────────────────

#[test]
fn runtime_metrics_as_json() {
    let metrics = GatewayRuntimeMetrics::default();
    metrics.record_token_validation_cache_hit();
    metrics.record_token_validation_cache_hit();
    metrics.record_token_validation_cache_miss();
    metrics.record_runtime_controls_cache_hit();
    metrics.record_runtime_controls_cache_miss();
    metrics.record_manifest_fetch();
    metrics.record_yaml_fetch();
    metrics.record_runtime_build_failure();
    let j = metrics.as_json();
    assert_eq!(j["token_validation_cache_hits"], 2);
    assert_eq!(j["token_validation_cache_misses"], 1);
    assert_eq!(j["runtime_controls_cache_hits"], 1);
    assert_eq!(j["runtime_controls_cache_misses"], 1);
    assert_eq!(j["manifest_fetches"], 1);
    assert_eq!(j["yaml_fetches"], 1);
    assert_eq!(j["runtime_build_failures"], 1);
}

// ── validated_key_gateway_binding ────────────────────────────────────

#[test]
fn validated_key_gateway_binding_personal() {
    let meta = json!({"personal_gateway_id": "gw-1"});
    assert_eq!(validated_key_gateway_binding(&meta), Some("gw-1"));
}

#[test]
fn validated_key_gateway_binding_fallback() {
    let meta = json!({"gateway_id": "gw-2"});
    assert_eq!(validated_key_gateway_binding(&meta), Some("gw-2"));
}

#[test]
fn validated_key_gateway_binding_empty() {
    let meta = json!({"personal_gateway_id": "  "});
    assert_eq!(validated_key_gateway_binding(&meta), None);
}

#[test]
fn validated_key_gateway_binding_none() {
    let meta = json!({});
    assert_eq!(validated_key_gateway_binding(&meta), None);
}

// ── validated_key_agent_binding ──────────────────────────────────────

#[test]
fn validated_key_agent_binding_present() {
    let meta = json!({"agent_id": "agent-a"});
    assert_eq!(validated_key_agent_binding(&meta), Some("agent-a"));
}

#[test]
fn validated_key_agent_binding_empty() {
    let meta = json!({"agent_id": ""});
    assert_eq!(validated_key_agent_binding(&meta), None);
}

#[test]
fn validated_key_agent_binding_missing() {
    let meta = json!({});
    assert_eq!(validated_key_agent_binding(&meta), None);
}

// ── PricingSource serialization ─────────────────────────────────────

#[test]
fn pricing_source_serde() {
    let upstream = serde_json::to_value(PricingSource::Upstream).unwrap();
    assert_eq!(upstream, json!("upstream"));
    let config = serde_json::to_value(PricingSource::ConfigDeclared).unwrap();
    assert_eq!(config, json!("config_declared"));
}

// ── TokenValidationError Display ────────────────────────────────────

#[test]
fn token_validation_error_display_unauthorized() {
    let err = TokenValidationError::Unauthorized {
        body: "bad token".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("unauthorized"));
    assert!(msg.contains("bad token"));
}

#[test]
fn token_validation_error_display_forbidden() {
    let err = TokenValidationError::Forbidden {
        body: "access denied".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("forbidden"));
}

#[test]
fn token_validation_error_display_unexpected_status() {
    let err = TokenValidationError::UnexpectedStatus {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        body: "server error".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("500"));
}

// ── deserialize_token_model_filters ──────────────────────────────────

#[test]
fn deserialize_token_model_filters_single_string() {
    let data = json!({"model_filter": "gpt-5.4"});
    let holder: TokenModelFilterHolder = serde_json::from_value(data).unwrap();
    assert_eq!(holder.model_filter, vec!["gpt-5.4"]);
}

#[test]
fn deserialize_token_model_filters_array() {
    let data = json!({"model_filter": ["gpt-5.4", "claude-4"]});
    let holder: TokenModelFilterHolder = serde_json::from_value(data).unwrap();
    assert_eq!(holder.model_filter, vec!["gpt-5.4", "claude-4"]);
}

#[test]
fn deserialize_token_model_filters_null() {
    let data = json!({"model_filter": null});
    let holder: TokenModelFilterHolder = serde_json::from_value(data).unwrap();
    assert!(holder.model_filter.is_empty());
}

#[test]
fn deserialize_token_model_filters_empty_string() {
    let data = json!({"model_filter": "  "});
    let holder: TokenModelFilterHolder = serde_json::from_value(data).unwrap();
    assert!(holder.model_filter.is_empty());
}

#[derive(serde::Deserialize)]
struct TokenModelFilterHolder {
    #[serde(default, deserialize_with = "deserialize_token_model_filters")]
    model_filter: Vec<String>,
}
