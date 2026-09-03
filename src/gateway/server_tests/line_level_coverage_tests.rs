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
use axum::{
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

// ── helper: minimal TokenRecord ──────────────────────────────────────
fn bare_token_record() -> TokenRecord {
    TokenRecord {
        id: "tok-test".into(),
        gateway_id: None,
        provider: None,
        model_filter: vec![],
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
    }
}

fn bare_token_validation() -> TokenValidationResponse {
    TokenValidationResponse {
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
    }
}

fn make_publication(
    publication_state: &str,
    hostname: Option<&str>,
) -> crate::runtime::ConnectedGatewayPublicationDescriptor {
    crate::runtime::ConnectedGatewayPublicationDescriptor {
        family_key: "fam".into(),
        publication_key: "pub-1".into(),
        published_hostname: hostname.map(ToOwned::to_owned),
        publication_state: publication_state.into(),
        active_revision_id: Some("rev-1".into()),
        active_revision_readiness_state: Some("active".into()),
        active_revision_auth_digest: Some("digest-auth".into()),
        active_revision_policy_digest: Some("digest-policy".into()),
        active_revision_pool_membership_issue: None,
        locality_mode: "regional".into(),
        serving_fleet_class: "standard".into(),
        primary_region_group_key: None,
    }
}

// ═══════════════════════════════════════════════════════════════════
// normalize_request_agent_id — all branches
// ═══════════════════════════════════════════════════════════════════

#[test]
fn agent_id_none_returns_none() {
    assert_eq!(normalize_request_agent_id(None), Ok(None));
}

#[test]
fn agent_id_empty_returns_none() {
    assert_eq!(normalize_request_agent_id(Some("")), Ok(None));
}

#[test]
fn agent_id_whitespace_returns_none() {
    assert_eq!(normalize_request_agent_id(Some("   ")), Ok(None));
}

#[test]
fn agent_id_valid_short() {
    assert_eq!(
        normalize_request_agent_id(Some("agent-1")),
        Ok(Some("agent-1".to_string()))
    );
}

#[test]
fn agent_id_exactly_128_chars() {
    let id = "a".repeat(128);
    assert_eq!(normalize_request_agent_id(Some(&id)), Ok(Some(id)));
}

#[test]
fn agent_id_too_long() {
    let id = "a".repeat(129);
    assert!(normalize_request_agent_id(Some(&id)).is_err());
}

#[test]
fn agent_id_invalid_chars() {
    assert!(normalize_request_agent_id(Some("agent_1")).is_err());
    assert!(normalize_request_agent_id(Some("agent.1")).is_err());
    assert!(normalize_request_agent_id(Some("agent 1")).is_err());
    assert!(normalize_request_agent_id(Some("agent/1")).is_err());
}

#[test]
fn agent_id_valid_with_hyphens_digits() {
    assert_eq!(
        normalize_request_agent_id(Some("my-Agent-123")),
        Ok(Some("my-Agent-123".to_string()))
    );
}

// ═══════════════════════════════════════════════════════════════════
// request_agent_id_header_value — header fallback chain
// ═══════════════════════════════════════════════════════════════════

#[test]
fn agent_id_header_prefers_verdictan_header() {
    let mut headers = HeaderMap::new();
    headers.insert("x-verdictan-agent-id", "verdictan-agent".parse().unwrap());
    headers.insert("x-agent-id", "generic-agent".parse().unwrap());
    assert_eq!(
        request_agent_id_header_value(&headers),
        Some("verdictan-agent")
    );
}

#[test]
fn agent_id_header_falls_back_to_x_agent_id() {
    let mut headers = HeaderMap::new();
    headers.insert("x-agent-id", "generic-agent".parse().unwrap());
    assert_eq!(
        request_agent_id_header_value(&headers),
        Some("generic-agent")
    );
}

#[test]
fn agent_id_header_missing() {
    let headers = HeaderMap::new();
    assert_eq!(request_agent_id_header_value(&headers), None);
}

// ═══════════════════════════════════════════════════════════════════
// extract_trace_correlation — nested lookup paths
// ═══════════════════════════════════════════════════════════════════

#[test]
fn trace_correlation_empty_body() {
    let body = json!({});
    let result = extract_trace_correlation(&body);
    assert!(result.is_empty());
}

#[test]
fn trace_correlation_via_verdictan_trace() {
    let body = json!({
        "verdictan": {
            "trace": {
                "evaluation_id": "eval-1",
                "evaluation_run_id": "run-1",
                "test_case_id": "case-1",
                "test_run_id": "trun-1"
            }
        }
    });
    let result = extract_trace_correlation(&body);
    assert_eq!(result.evaluation_id.as_deref(), Some("eval-1"));
    assert_eq!(result.evaluation_run_id.as_deref(), Some("run-1"));
    assert_eq!(result.test_case_id.as_deref(), Some("case-1"));
    assert_eq!(result.test_run_id.as_deref(), Some("trun-1"));
    assert!(!result.is_empty());
}

#[test]
fn trace_correlation_via_verdictan_correlation() {
    let body = json!({
        "verdictan": {
            "correlation": {
                "evaluation_id": "eval-2"
            }
        }
    });
    let result = extract_trace_correlation(&body);
    assert_eq!(result.evaluation_id.as_deref(), Some("eval-2"));
}

#[test]
fn trace_correlation_via_verdictan_root() {
    let body = json!({
        "verdictan": {
            "evaluation_id": "eval-3"
        }
    });
    let result = extract_trace_correlation(&body);
    assert_eq!(result.evaluation_id.as_deref(), Some("eval-3"));
}

#[test]
fn trace_correlation_trims_whitespace_and_ignores_empty() {
    let body = json!({
        "verdictan": {
            "trace": {
                "evaluation_id": "  ",
                "test_case_id": " tc-1 "
            }
        }
    });
    let result = extract_trace_correlation(&body);
    assert_eq!(result.evaluation_id, None);
    assert_eq!(result.test_case_id.as_deref(), Some("tc-1"));
}

#[test]
fn trace_correlation_as_event_json_non_empty() {
    let corr = TraceCorrelation {
        evaluation_id: Some("e1".into()),
        evaluation_run_id: None,
        test_case_id: None,
        test_run_id: None,
    };
    let json = corr.as_event_json().unwrap();
    assert_eq!(json["evaluation_id"], "e1");
    assert!(json["evaluation_run_id"].is_null());
}

#[test]
fn trace_correlation_as_event_json_empty_returns_none() {
    let corr = TraceCorrelation::default();
    assert!(corr.as_event_json().is_none());
}

// ═══════════════════════════════════════════════════════════════════
// extract_request_telemetry_hints — all lookup paths
// ═══════════════════════════════════════════════════════════════════

#[test]
fn telemetry_hints_empty_body() {
    let body = json!({});
    let result = extract_request_telemetry_hints(&body);
    assert!(result.prompt_label.is_none());
    assert!(result.test_index.is_none());
}

#[test]
fn telemetry_hints_via_prompt_label_nested() {
    let body = json!({
        "verdictan": { "prompt": { "label": "classify-intent" } }
    });
    let result = extract_request_telemetry_hints(&body);
    assert_eq!(result.prompt_label.as_deref(), Some("classify-intent"));
}

#[test]
fn telemetry_hints_via_prompt_label_flat() {
    let body = json!({
        "verdictan": { "prompt_label": "flat-label" }
    });
    let result = extract_request_telemetry_hints(&body);
    assert_eq!(result.prompt_label.as_deref(), Some("flat-label"));
}

#[test]
fn telemetry_hints_via_test_index_nested() {
    let body = json!({
        "verdictan": { "test": { "index": 42 } }
    });
    let result = extract_request_telemetry_hints(&body);
    assert_eq!(result.test_index, Some(42));
}

#[test]
fn telemetry_hints_via_test_index_flat() {
    let body = json!({
        "verdictan": { "test_index": 7 }
    });
    let result = extract_request_telemetry_hints(&body);
    assert_eq!(result.test_index, Some(7));
}

#[test]
fn telemetry_hints_combined() {
    let body = json!({
        "verdictan": {
            "prompt": { "label": "combined" },
            "test": { "index": 99 }
        }
    });
    let result = extract_request_telemetry_hints(&body);
    assert_eq!(result.prompt_label.as_deref(), Some("combined"));
    assert_eq!(result.test_index, Some(99));
}

// ═══════════════════════════════════════════════════════════════════
// telemetry_verdictan_metadata — conditional construction
// ═══════════════════════════════════════════════════════════════════

#[test]
fn telemetry_metadata_returns_none_when_both_absent() {
    let hints = RequestTelemetryHints {
        prompt_label: None,
        test_index: None,
    };
    assert!(telemetry_verdictan_metadata(&hints).is_none());
}

#[test]
fn telemetry_metadata_prompt_label_only() {
    let hints = RequestTelemetryHints {
        prompt_label: Some("my-prompt".into()),
        test_index: None,
    };
    let map = telemetry_verdictan_metadata(&hints).unwrap();
    assert_eq!(map["prompt_label"], "my-prompt");
    assert!(!map.contains_key("test_index"));
}

#[test]
fn telemetry_metadata_test_index_only() {
    let hints = RequestTelemetryHints {
        prompt_label: None,
        test_index: Some(5),
    };
    let map = telemetry_verdictan_metadata(&hints).unwrap();
    assert_eq!(map["test_index"], 5);
    assert!(!map.contains_key("prompt_label"));
}

#[test]
fn telemetry_metadata_both_present() {
    let hints = RequestTelemetryHints {
        prompt_label: Some("label".into()),
        test_index: Some(3),
    };
    let map = telemetry_verdictan_metadata(&hints).unwrap();
    assert_eq!(map["prompt_label"], "label");
    assert_eq!(map["test_index"], 3);
}

// ═══════════════════════════════════════════════════════════════════
// normalize_runtime_plugin_id — all validation paths
// ═══════════════════════════════════════════════════════════════════

#[test]
fn plugin_id_valid_lowercase() {
    assert_eq!(
        normalize_runtime_plugin_id("web-search").unwrap(),
        "web-search"
    );
}

#[test]
fn plugin_id_normalizes_uppercase_and_underscores() {
    assert_eq!(
        normalize_runtime_plugin_id("Web_Search").unwrap(),
        "web-search"
    );
}

#[test]
fn plugin_id_rejects_empty() {
    assert!(normalize_runtime_plugin_id("").is_err());
    assert!(normalize_runtime_plugin_id("  ").is_err());
}

#[test]
fn plugin_id_rejects_special_chars() {
    assert!(normalize_runtime_plugin_id("web.search").is_err());
    assert!(normalize_runtime_plugin_id("web/search").is_err());
    assert!(normalize_runtime_plugin_id("web search").is_err());
}

#[test]
fn plugin_id_digits_and_hyphens() {
    assert_eq!(
        normalize_runtime_plugin_id("plugin-123").unwrap(),
        "plugin-123"
    );
}

// ═══════════════════════════════════════════════════════════════════
// normalize_runtime_data_collection — all branches
// ═══════════════════════════════════════════════════════════════════

#[test]
fn data_collection_allow() {
    assert_eq!(normalize_runtime_data_collection("allow").unwrap(), "allow");
}

#[test]
fn data_collection_deny() {
    assert_eq!(normalize_runtime_data_collection("deny").unwrap(), "deny");
}

#[test]
fn data_collection_case_insensitive() {
    assert_eq!(normalize_runtime_data_collection("ALLOW").unwrap(), "allow");
    assert_eq!(normalize_runtime_data_collection("Deny").unwrap(), "deny");
}

#[test]
fn data_collection_trims_whitespace() {
    assert_eq!(
        normalize_runtime_data_collection("  allow  ").unwrap(),
        "allow"
    );
}

#[test]
fn data_collection_rejects_invalid() {
    assert!(normalize_runtime_data_collection("maybe").is_err());
    assert!(normalize_runtime_data_collection("").is_err());
}

// ═══════════════════════════════════════════════════════════════════
// parse_runtime_cache_ttl — suffix parsing and error paths
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cache_ttl_bare_seconds() {
    assert_eq!(
        parse_runtime_cache_ttl("60").unwrap(),
        Duration::from_secs(60)
    );
}

#[test]
fn cache_ttl_suffix_s() {
    assert_eq!(
        parse_runtime_cache_ttl("30s").unwrap(),
        Duration::from_secs(30)
    );
}

#[test]
fn cache_ttl_suffix_m() {
    assert_eq!(
        parse_runtime_cache_ttl("5m").unwrap(),
        Duration::from_secs(300)
    );
}

#[test]
fn cache_ttl_suffix_h() {
    assert_eq!(
        parse_runtime_cache_ttl("2h").unwrap(),
        Duration::from_secs(7200)
    );
}

#[test]
fn cache_ttl_min_one_second() {
    assert_eq!(
        parse_runtime_cache_ttl("0s").unwrap(),
        Duration::from_secs(1)
    );
}

#[test]
fn cache_ttl_rejects_empty() {
    assert!(parse_runtime_cache_ttl("").is_err());
    assert!(parse_runtime_cache_ttl("  ").is_err());
}

#[test]
fn cache_ttl_rejects_non_numeric() {
    assert!(parse_runtime_cache_ttl("abc").is_err());
    assert!(parse_runtime_cache_ttl("10x").is_err());
}

// ═══════════════════════════════════════════════════════════════════
// intersect_scope_values — all 4 match arms
// ═══════════════════════════════════════════════════════════════════

#[test]
fn intersect_both_empty() {
    let result = intersect_scope_values(&[], &[], normalize_text_scope_values);
    assert!(result.is_empty());
}

#[test]
fn intersect_binding_only() {
    let result =
        intersect_scope_values(&["a".into(), "b".into()], &[], normalize_text_scope_values);
    assert_eq!(result, vec!["a", "b"]);
}

#[test]
fn intersect_policy_only() {
    let result =
        intersect_scope_values(&[], &["x".into(), "y".into()], normalize_text_scope_values);
    assert_eq!(result, vec!["x", "y"]);
}

#[test]
fn intersect_both_present() {
    let result = intersect_scope_values(
        &["a".into(), "b".into(), "c".into()],
        &["b".into(), "c".into(), "d".into()],
        normalize_text_scope_values,
    );
    assert_eq!(result, vec!["b", "c"]);
}

#[test]
fn intersect_no_overlap() {
    let result = intersect_scope_values(&["a".into()], &["b".into()], normalize_text_scope_values);
    assert!(result.is_empty());
}

// ═══════════════════════════════════════════════════════════════════
// merged_token_scopes — complex merge logic
// ═══════════════════════════════════════════════════════════════════

#[test]
fn merged_scopes_no_policies_no_controls() {
    let key = bare_token_record();
    let result = merged_token_scopes(&key, None, &[]).unwrap();
    assert!(result.allowed_providers.is_empty());
    assert!(result.allowed_models.is_empty());
    assert!(result.allowed_gateways.is_empty());
}

#[test]
fn merged_scopes_policy_ids_without_controls_fails() {
    let key = bare_token_record();
    let result = merged_token_scopes(&key, None, &["policy-1".into()]);
    assert!(result.is_err());
}

#[test]
fn merged_scopes_binding_from_key_fields() {
    let mut key = bare_token_record();
    key.gateway_id = Some("gw-1".into());
    key.provider = Some("openai".into());
    key.model_filter = vec!["gpt-4".into()];
    let result = merged_token_scopes(&key, None, &[]).unwrap();
    assert_eq!(result.allowed_gateways, vec!["gw-1"]);
    assert!(!result.allowed_providers.is_empty());
    assert_eq!(result.allowed_models, vec!["gpt-4"]);
}

#[test]
fn merged_scopes_binding_from_metadata_gateway() {
    let mut key = bare_token_record();
    key.metadata = json!({"personal_gateway_id": "meta-gw"});
    let result = merged_token_scopes(&key, None, &[]).unwrap();
    assert_eq!(result.allowed_gateways, vec!["meta-gw"]);
}

#[test]
fn merged_scopes_with_controls_intersects() {
    let mut key = bare_token_record();
    key.provider = Some("openai".into());
    let controls = GatewayControlsPayload {
        fail_closed: false,
        allowed_providers: vec!["openai".into(), "anthropic".into()],
        allowed_models: vec!["gpt-4".into()],
        allowed_gateways: vec![],
        disabled_providers: vec![],
    };
    let result = merged_token_scopes(&key, Some(&controls), &["policy-1".into()]).unwrap();
    assert!(!result.allowed_providers.is_empty());
    assert_eq!(result.allowed_models, vec!["gpt-4"]);
}

// ═══════════════════════════════════════════════════════════════════
// token spend/budget/request helpers — depletion fallback paths
// ═══════════════════════════════════════════════════════════════════

#[test]
fn token_current_spend_from_depletion() {
    let key = bare_token_record();
    let mut validation = bare_token_validation();
    validation.depletion = Some(TokenDepletionState {
        current_spend: Some(42.5),
        ..Default::default()
    });
    assert!((token_current_spend(&key, &validation) - 42.5).abs() < f64::EPSILON);
}

#[test]
fn token_current_spend_falls_back_to_key() {
    let mut key = bare_token_record();
    key.current_spend = 10.0;
    let validation = bare_token_validation();
    assert!((token_current_spend(&key, &validation) - 10.0).abs() < f64::EPSILON);
}

#[test]
fn token_max_budget_from_depletion() {
    let key = bare_token_record();
    let mut validation = bare_token_validation();
    validation.depletion = Some(TokenDepletionState {
        max_budget: Some(100.0),
        ..Default::default()
    });
    assert_eq!(token_max_budget(&key, &validation), Some(100.0));
}

#[test]
fn token_max_budget_falls_back_to_key() {
    let mut key = bare_token_record();
    key.max_budget = Some(50.0);
    let validation = bare_token_validation();
    assert_eq!(token_max_budget(&key, &validation), Some(50.0));
}

#[test]
fn token_max_budget_none_when_both_absent() {
    let key = bare_token_record();
    let validation = bare_token_validation();
    assert_eq!(token_max_budget(&key, &validation), None);
}

#[test]
fn token_current_requests_from_depletion() {
    let mut validation = bare_token_validation();
    validation.depletion = Some(TokenDepletionState {
        current_requests: Some(99),
        ..Default::default()
    });
    assert_eq!(token_current_requests(&validation), 99);
}

#[test]
fn token_current_requests_default_zero() {
    let validation = bare_token_validation();
    assert_eq!(token_current_requests(&validation), 0);
}

#[test]
fn token_max_requests_from_depletion() {
    let mut validation = bare_token_validation();
    validation.depletion = Some(TokenDepletionState {
        max_requests: Some(1000),
        ..Default::default()
    });
    assert_eq!(token_max_requests(&validation), Some(1000));
}

#[test]
fn token_max_requests_none_when_absent() {
    let validation = bare_token_validation();
    assert_eq!(token_max_requests(&validation), None);
}

// ═══════════════════════════════════════════════════════════════════
// parse_expiry_timestamp — date parsing
// ═══════════════════════════════════════════════════════════════════

#[test]
fn parse_expiry_valid_rfc3339() {
    let result = parse_expiry_timestamp(Some("2025-01-01T00:00:00Z"));
    assert!(result.is_some());
    assert_eq!(chrono::Datelike::year(&result.unwrap()), 2025);
}

#[test]
fn parse_expiry_invalid_format() {
    assert!(parse_expiry_timestamp(Some("not-a-date")).is_none());
}

#[test]
fn parse_expiry_none() {
    assert!(parse_expiry_timestamp(None).is_none());
}

#[test]
fn parse_expiry_with_offset() {
    let result = parse_expiry_timestamp(Some("2025-06-15T12:00:00+02:00"));
    assert!(result.is_some());
}

// ═══════════════════════════════════════════════════════════════════
// publication_state_accepts_public_traffic — all match arms
// ═══════════════════════════════════════════════════════════════════

#[test]
fn pub_state_published() {
    assert!(publication_state_accepts_public_traffic("published"));
    assert!(publication_state_accepts_public_traffic("Published"));
    assert!(publication_state_accepts_public_traffic("  PUBLISHED  "));
}

#[test]
fn pub_state_draining() {
    assert!(publication_state_accepts_public_traffic("draining"));
    assert!(publication_state_accepts_public_traffic("Draining"));
}

#[test]
fn pub_state_rejects_other() {
    assert!(!publication_state_accepts_public_traffic("draft"));
    assert!(!publication_state_accepts_public_traffic("unpublished"));
    assert!(!publication_state_accepts_public_traffic(""));
}

// ═══════════════════════════════════════════════════════════════════
// normalize_managed_public_endpoint_host — host parsing
// ═══════════════════════════════════════════════════════════════════

#[test]
fn normalize_host_simple() {
    assert_eq!(
        normalize_managed_public_endpoint_host("example.com"),
        Some("example.com".into())
    );
}

#[test]
fn normalize_host_with_port() {
    assert_eq!(
        normalize_managed_public_endpoint_host("example.com:8080"),
        Some("example.com".into())
    );
}

#[test]
fn normalize_host_trailing_dot() {
    assert_eq!(
        normalize_managed_public_endpoint_host("example.com."),
        Some("example.com".into())
    );
}

#[test]
fn normalize_host_uppercase() {
    assert_eq!(
        normalize_managed_public_endpoint_host("EXAMPLE.COM"),
        Some("example.com".into())
    );
}

#[test]
fn normalize_host_empty() {
    assert_eq!(normalize_managed_public_endpoint_host(""), None);
    assert_eq!(normalize_managed_public_endpoint_host("  "), None);
    assert_eq!(normalize_managed_public_endpoint_host("."), None);
}

#[test]
fn normalize_host_ipv6_preserves_brackets() {
    let result = normalize_managed_public_endpoint_host("[::1]:8080");
    assert!(result.is_some());
}

// ═══════════════════════════════════════════════════════════════════
// ingress_marks_managed_public_endpoint — header matching
// ═══════════════════════════════════════════════════════════════════

#[test]
fn ingress_marks_true_values() {
    for value in &["1", "true", "yes", "managed", "True", "YES", "MANAGED"] {
        let mut headers = HeaderMap::new();
        headers.insert("x-verdictan-public-endpoint", value.parse().unwrap());
        assert!(
            ingress_marks_managed_public_endpoint(&headers),
            "expected true for '{value}'"
        );
    }
}

#[test]
fn ingress_marks_false_values() {
    for value in &["0", "false", "no", ""] {
        let mut headers = HeaderMap::new();
        headers.insert("x-verdictan-public-endpoint", value.parse().unwrap());
        assert!(
            !ingress_marks_managed_public_endpoint(&headers),
            "expected false for '{value}'"
        );
    }
}

#[test]
fn ingress_marks_missing_header() {
    assert!(!ingress_marks_managed_public_endpoint(&HeaderMap::new()));
}

// ═══════════════════════════════════════════════════════════════════
// managed_public_endpoint_host — header extraction
// ═══════════════════════════════════════════════════════════════════

#[test]
fn managed_host_prefers_verdictan_header() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-public-hostname",
        "verdictan-host.com".parse().unwrap(),
    );
    headers.insert(header::HOST, "other.com".parse().unwrap());
    assert_eq!(
        managed_public_endpoint_host(&headers),
        Some("verdictan-host.com".into())
    );
}

#[test]
fn managed_host_falls_back_to_host_header() {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "fallback.com".parse().unwrap());
    assert_eq!(
        managed_public_endpoint_host(&headers),
        Some("fallback.com".into())
    );
}

#[test]
fn managed_host_missing() {
    assert_eq!(managed_public_endpoint_host(&HeaderMap::new()), None);
}

// ═══════════════════════════════════════════════════════════════════
// managed_public_endpoint_requested_region_group
// ═══════════════════════════════════════════════════════════════════

#[test]
fn region_group_present() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-requested-region-group",
        "eu-west".parse().unwrap(),
    );
    assert_eq!(
        managed_public_endpoint_requested_region_group(&headers),
        Some("eu-west".into())
    );
}

#[test]
fn region_group_empty_returns_none() {
    let mut headers = HeaderMap::new();
    headers.insert("x-verdictan-requested-region-group", "  ".parse().unwrap());
    assert_eq!(
        managed_public_endpoint_requested_region_group(&headers),
        None
    );
}

#[test]
fn region_group_missing() {
    assert_eq!(
        managed_public_endpoint_requested_region_group(&HeaderMap::new()),
        None
    );
}

// ═══════════════════════════════════════════════════════════════════
// admitted_member_status_allows_public_traffic — all status checks
// ═══════════════════════════════════════════════════════════════════

#[test]
fn admitted_member_all_true_allows() {
    let member = json!({"admitted": true, "eligible": true})
        .as_object()
        .unwrap()
        .clone();
    assert!(admitted_member_status_allows_public_traffic(&member));
}

#[test]
fn admitted_member_any_false_rejects() {
    for key in [
        "admitted",
        "eligible",
        "materialized",
        "healthy",
        "ready",
        "is_admitted",
    ] {
        let mut member = serde_json::Map::new();
        member.insert(key.to_string(), json!(false));
        assert!(
            !admitted_member_status_allows_public_traffic(&member),
            "expected rejection for {key}=false"
        );
    }
}

#[test]
fn admitted_member_active_status_allows() {
    for status in &["active", "admitted", "healthy", "materialized", "ready"] {
        let member = json!({"status": status}).as_object().unwrap().clone();
        assert!(
            admitted_member_status_allows_public_traffic(&member),
            "expected allow for status={status}"
        );
    }
}

#[test]
fn admitted_member_unknown_status_rejects() {
    let member = json!({"status": "suspended"}).as_object().unwrap().clone();
    assert!(!admitted_member_status_allows_public_traffic(&member));
}

#[test]
fn admitted_member_empty_status_allows() {
    let member = json!({"status": ""}).as_object().unwrap().clone();
    assert!(admitted_member_status_allows_public_traffic(&member));
}

#[test]
fn admitted_member_empty_object_allows() {
    let member = serde_json::Map::new();
    assert!(admitted_member_status_allows_public_traffic(&member));
}

// ═══════════════════════════════════════════════════════════════════
// gateway_identity_matches_candidate
// ═══════════════════════════════════════════════════════════════════

#[test]
fn identity_matches_registration() {
    assert!(gateway_identity_matches_candidate(
        "reg-1",
        Some("reg-1"),
        None
    ));
}

#[test]
fn identity_matches_gateway_id() {
    assert!(gateway_identity_matches_candidate(
        "gw-1",
        None,
        Some("gw-1")
    ));
}

#[test]
fn identity_case_insensitive() {
    assert!(gateway_identity_matches_candidate(
        "REG-1",
        Some("reg-1"),
        None
    ));
}

#[test]
fn identity_no_match() {
    assert!(!gateway_identity_matches_candidate(
        "other",
        Some("reg-1"),
        Some("gw-1")
    ));
}

#[test]
fn identity_empty_candidate() {
    assert!(!gateway_identity_matches_candidate("", Some("reg-1"), None));
    assert!(!gateway_identity_matches_candidate(
        "  ",
        Some("reg-1"),
        None
    ));
}

// ═══════════════════════════════════════════════════════════════════
// evaluate_connected_cell_pool_admitted_members — recursive JSON
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cell_pool_null_returns_missing() {
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(&json!(null), Some("reg-1"), None),
        ConnectedCellPoolAdmissionMatch::Missing
    );
}

#[test]
fn cell_pool_string_match() {
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(&json!("reg-1"), Some("reg-1"), None),
        ConnectedCellPoolAdmissionMatch::Matched
    );
}

#[test]
fn cell_pool_string_no_match() {
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(&json!("other"), Some("reg-1"), None),
        ConnectedCellPoolAdmissionMatch::NotMatched
    );
}

#[test]
fn cell_pool_empty_array() {
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(&json!([]), Some("reg-1"), None),
        ConnectedCellPoolAdmissionMatch::NotMatched
    );
}

#[test]
fn cell_pool_array_with_match() {
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(
            &json!(["other", "reg-1"]),
            Some("reg-1"),
            None
        ),
        ConnectedCellPoolAdmissionMatch::Matched
    );
}

#[test]
fn cell_pool_array_no_match() {
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(&json!(["a", "b"]), Some("reg-1"), None),
        ConnectedCellPoolAdmissionMatch::NotMatched
    );
}

#[test]
fn cell_pool_object_with_members_field() {
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(
            &json!({"members": ["reg-1"]}),
            Some("reg-1"),
            None
        ),
        ConnectedCellPoolAdmissionMatch::Matched
    );
}

#[test]
fn cell_pool_object_with_admitted_members_field() {
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(
            &json!({"admitted_members": ["gw-1"]}),
            None,
            Some("gw-1")
        ),
        ConnectedCellPoolAdmissionMatch::Matched
    );
}

#[test]
fn cell_pool_object_with_identity_fields_matched() {
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(
            &json!({"runtime_registration_id": "reg-1", "admitted": true}),
            Some("reg-1"),
            None
        ),
        ConnectedCellPoolAdmissionMatch::Matched
    );
}

#[test]
fn cell_pool_object_with_identity_field_not_matched() {
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(
            &json!({"runtime_registration_id": "other"}),
            Some("reg-1"),
            None
        ),
        ConnectedCellPoolAdmissionMatch::NotMatched
    );
}

#[test]
fn cell_pool_object_with_identity_field_status_rejected() {
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(
            &json!({"runtime_registration_id": "reg-1", "admitted": false}),
            Some("reg-1"),
            None
        ),
        ConnectedCellPoolAdmissionMatch::NotMatched
    );
}

#[test]
fn cell_pool_object_with_gateway_id_field() {
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(
            &json!({"gateway_id": "gw-1"}),
            None,
            Some("gw-1")
        ),
        ConnectedCellPoolAdmissionMatch::Matched
    );
}

#[test]
fn cell_pool_object_with_member_id_field() {
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(
            &json!({"member_id": "reg-1"}),
            Some("reg-1"),
            None
        ),
        ConnectedCellPoolAdmissionMatch::Matched
    );
}

#[test]
fn cell_pool_object_with_id_field() {
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(&json!({"id": "gw-1"}), None, Some("gw-1")),
        ConnectedCellPoolAdmissionMatch::Matched
    );
}

#[test]
fn cell_pool_object_unsupported_shape() {
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(
            &json!({"unknown_key": "value"}),
            Some("reg-1"),
            None
        ),
        ConnectedCellPoolAdmissionMatch::Unsupported
    );
}

#[test]
fn cell_pool_boolean_unsupported() {
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(&json!(true), Some("reg-1"), None),
        ConnectedCellPoolAdmissionMatch::Unsupported
    );
}

#[test]
fn cell_pool_array_of_objects_with_mixed_results() {
    let members = json!([
        {"runtime_registration_id": "other", "admitted": true},
        {"runtime_registration_id": "reg-1", "admitted": true}
    ]);
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(&members, Some("reg-1"), None),
        ConnectedCellPoolAdmissionMatch::Matched
    );
}

#[test]
fn cell_pool_nested_object_container_keys() {
    for key in [
        "gateways",
        "pool_members",
        "runtime_registration_ids",
        "gateway_ids",
        "ids",
    ] {
        let mut obj = serde_json::Map::new();
        obj.insert(key.to_string(), json!(["reg-1"]));
        let data = serde_json::Value::Object(obj);
        assert_eq!(
            evaluate_connected_cell_pool_admitted_members(&data, Some("reg-1"), None),
            ConnectedCellPoolAdmissionMatch::Matched,
            "expected Matched for container key '{key}'"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// active_revision_pool_membership_issue_for_gateway
// ═══════════════════════════════════════════════════════════════════

#[test]
fn pool_membership_not_required_for_standard_fleet() {
    assert_eq!(
        active_revision_pool_membership_issue_for_gateway(
            "standard",
            Some("reg-1"),
            Some("gw-1"),
            Some(&json!(["reg-1"])),
        ),
        None
    );
}

#[test]
fn pool_membership_missing_identity() {
    assert_eq!(
        active_revision_pool_membership_issue_for_gateway(
            "connected_cell_pool",
            None,
            None,
            Some(&json!(["reg-1"])),
        ),
        Some("runtime_pool_identity_missing")
    );
}

#[test]
fn pool_membership_matched() {
    assert_eq!(
        active_revision_pool_membership_issue_for_gateway(
            "connected_cell_pool",
            Some("reg-1"),
            None,
            Some(&json!(["reg-1"])),
        ),
        None
    );
}

#[test]
fn pool_membership_not_matched() {
    assert_eq!(
        active_revision_pool_membership_issue_for_gateway(
            "connected_cell_pool",
            Some("reg-1"),
            None,
            Some(&json!(["other"])),
        ),
        Some("current_gateway_not_admitted")
    );
}

#[test]
fn pool_membership_missing_admitted_members() {
    assert_eq!(
        active_revision_pool_membership_issue_for_gateway(
            "connected_cell_pool",
            Some("reg-1"),
            None,
            None,
        ),
        Some("active_revision_admitted_members_missing")
    );
}

#[test]
fn pool_membership_unsupported_format() {
    assert_eq!(
        active_revision_pool_membership_issue_for_gateway(
            "connected_cell_pool",
            Some("reg-1"),
            None,
            Some(&json!(42)),
        ),
        Some("active_revision_admitted_members_unrecognized")
    );
}

// ═══════════════════════════════════════════════════════════════════
// publication_active_revision_accepts_public_traffic
// ═══════════════════════════════════════════════════════════════════

#[test]
fn revision_traffic_published_active() {
    assert!(publication_active_revision_accepts_public_traffic(
        "published",
        "active"
    ));
}

#[test]
fn revision_traffic_draining_draining() {
    assert!(publication_active_revision_accepts_public_traffic(
        "draining", "draining"
    ));
}

#[test]
fn revision_traffic_case_insensitive() {
    assert!(publication_active_revision_accepts_public_traffic(
        "Published",
        "Active"
    ));
}

#[test]
fn revision_traffic_rejects_invalid_combos() {
    assert!(!publication_active_revision_accepts_public_traffic(
        "published",
        "draining"
    ));
    assert!(!publication_active_revision_accepts_public_traffic(
        "draining", "active"
    ));
    assert!(!publication_active_revision_accepts_public_traffic(
        "draft", "active"
    ));
}

// ═══════════════════════════════════════════════════════════════════
// publication_public_admission_issue — all early return paths
// ═══════════════════════════════════════════════════════════════════

#[test]
fn admission_issue_missing_revision_id() {
    let mut pub_desc = make_publication("published", Some("host.com"));
    pub_desc.active_revision_id = None;
    assert_eq!(
        publication_public_admission_issue(&pub_desc).as_deref(),
        Some("active_revision_id_missing")
    );
}

#[test]
fn admission_issue_missing_readiness_state() {
    let mut pub_desc = make_publication("published", Some("host.com"));
    pub_desc.active_revision_readiness_state = None;
    assert_eq!(
        publication_public_admission_issue(&pub_desc).as_deref(),
        Some("active_revision_readiness_state_missing")
    );
}

#[test]
fn admission_issue_missing_auth_digest() {
    let mut pub_desc = make_publication("published", Some("host.com"));
    pub_desc.active_revision_auth_digest = None;
    assert_eq!(
        publication_public_admission_issue(&pub_desc).as_deref(),
        Some("active_revision_auth_digest_missing")
    );
}

#[test]
fn admission_issue_missing_policy_digest() {
    let mut pub_desc = make_publication("published", Some("host.com"));
    pub_desc.active_revision_policy_digest = None;
    assert_eq!(
        publication_public_admission_issue(&pub_desc).as_deref(),
        Some("active_revision_policy_digest_missing")
    );
}

#[test]
fn admission_issue_not_ready() {
    let mut pub_desc = make_publication("published", Some("host.com"));
    pub_desc.active_revision_readiness_state = Some("pending".into());
    assert_eq!(
        publication_public_admission_issue(&pub_desc).as_deref(),
        Some("active_revision_not_ready_for_public_traffic")
    );
}

#[test]
fn admission_issue_pool_membership_problem() {
    let mut pub_desc = make_publication("published", Some("host.com"));
    pub_desc.active_revision_pool_membership_issue = Some("not_admitted".into());
    assert_eq!(
        publication_public_admission_issue(&pub_desc).as_deref(),
        Some("not_admitted")
    );
}

#[test]
fn admission_issue_none_when_all_valid() {
    let pub_desc = make_publication("published", Some("host.com"));
    assert!(publication_public_admission_issue(&pub_desc).is_none());
}

// ═══════════════════════════════════════════════════════════════════
// publication_public_binding_issue
// ═══════════════════════════════════════════════════════════════════

#[test]
fn binding_issue_non_public_state_returns_none() {
    let pub_desc = make_publication("draft", Some("host.com"));
    assert!(publication_public_binding_issue(&pub_desc).is_none());
}

#[test]
fn binding_issue_missing_hostname() {
    let pub_desc = make_publication("published", None);
    assert_eq!(
        publication_public_binding_issue(&pub_desc).as_deref(),
        Some("published_hostname_missing")
    );
}

#[test]
fn binding_issue_delegates_to_admission_issue() {
    let mut pub_desc = make_publication("published", Some("host.com"));
    pub_desc.active_revision_id = None;
    assert_eq!(
        publication_public_binding_issue(&pub_desc).as_deref(),
        Some("active_revision_id_missing")
    );
}

#[test]
fn binding_issue_none_when_valid() {
    let pub_desc = make_publication("published", Some("host.com"));
    assert!(publication_public_binding_issue(&pub_desc).is_none());
}

// ═══════════════════════════════════════════════════════════════════
// publication_admits_requested_region_group
// ═══════════════════════════════════════════════════════════════════

#[test]
fn region_group_no_request_always_admits() {
    let pub_desc = make_publication("published", Some("host.com"));
    assert!(publication_admits_requested_region_group(&pub_desc, None));
}

#[test]
fn region_group_global_always_admits() {
    let pub_desc = make_publication("published", Some("host.com"));
    assert!(publication_admits_requested_region_group(
        &pub_desc,
        Some("global")
    ));
    assert!(publication_admits_requested_region_group(
        &pub_desc,
        Some("Global")
    ));
}

#[test]
fn region_group_matching() {
    let mut pub_desc = make_publication("published", Some("host.com"));
    pub_desc.primary_region_group_key = Some("eu-west".into());
    assert!(publication_admits_requested_region_group(
        &pub_desc,
        Some("eu-west")
    ));
}

#[test]
fn region_group_non_matching() {
    let mut pub_desc = make_publication("published", Some("host.com"));
    pub_desc.primary_region_group_key = Some("eu-west".into());
    assert!(!publication_admits_requested_region_group(
        &pub_desc,
        Some("us-east")
    ));
}

#[test]
fn region_group_empty_request_admits() {
    let pub_desc = make_publication("published", Some("host.com"));
    assert!(publication_admits_requested_region_group(
        &pub_desc,
        Some("")
    ));
    assert!(publication_admits_requested_region_group(
        &pub_desc,
        Some("  ")
    ));
}

// ═══════════════════════════════════════════════════════════════════
// publication_region_scope_admissible
// ═══════════════════════════════════════════════════════════════════

#[test]
fn region_scope_no_pub_region_admits() {
    let pub_desc = make_publication("published", Some("host.com"));
    assert!(publication_region_scope_admissible(&pub_desc, None));
}

#[test]
fn region_scope_no_gw_region_rejects() {
    let mut pub_desc = make_publication("published", Some("host.com"));
    pub_desc.primary_region_group_key = Some("eu-west".into());
    assert!(!publication_region_scope_admissible(&pub_desc, None));
}

#[test]
fn region_scope_matching_regions() {
    let mut pub_desc = make_publication("published", Some("host.com"));
    pub_desc.primary_region_group_key = Some("eu-west".into());
    assert!(publication_region_scope_admissible(
        &pub_desc,
        Some("eu-west")
    ));
}

#[test]
fn region_scope_non_matching_regions() {
    let mut pub_desc = make_publication("published", Some("host.com"));
    pub_desc.primary_region_group_key = Some("eu-west".into());
    assert!(!publication_region_scope_admissible(
        &pub_desc,
        Some("us-east")
    ));
}

// ═══════════════════════════════════════════════════════════════════
// publication_region_vrn_resource
// ═══════════════════════════════════════════════════════════════════

#[test]
fn region_vrn_no_pub_region_returns_none() {
    let pub_desc = make_publication("published", Some("host.com"));
    assert!(publication_region_vrn_resource(&pub_desc, None).is_none());
}

#[test]
fn region_vrn_matching_regions() {
    let mut pub_desc = make_publication("published", Some("host.com"));
    pub_desc.primary_region_group_key = Some("eu-west".into());
    assert_eq!(
        publication_region_vrn_resource(&pub_desc, Some("eu-west")),
        Some("publication/pub-1".into())
    );
}

#[test]
fn region_vrn_no_gw_region_still_returns() {
    let mut pub_desc = make_publication("published", Some("host.com"));
    pub_desc.primary_region_group_key = Some("eu-west".into());
    assert_eq!(
        publication_region_vrn_resource(&pub_desc, None),
        Some("publication/pub-1".into())
    );
}

#[test]
fn region_vrn_mismatched_regions_returns_none() {
    let mut pub_desc = make_publication("published", Some("host.com"));
    pub_desc.primary_region_group_key = Some("eu-west".into());
    assert!(publication_region_vrn_resource(&pub_desc, Some("us-east")).is_none());
}

// ═══════════════════════════════════════════════════════════════════
// locality_scope_fragment — all 4 combos
// ═══════════════════════════════════════════════════════════════════

#[test]
fn locality_both_present() {
    assert_eq!(
        locality_scope_fragment(Some("eu-west"), Some("host.com")),
        Some("region_group:eu-west:host:host.com".into())
    );
}

#[test]
fn locality_region_only() {
    assert_eq!(
        locality_scope_fragment(Some("eu-west"), None),
        Some("region_group:eu-west".into())
    );
}

#[test]
fn locality_host_only() {
    assert_eq!(
        locality_scope_fragment(None, Some("host.com")),
        Some("host:host.com".into())
    );
}

#[test]
fn locality_neither() {
    assert_eq!(locality_scope_fragment(None, None), None);
}

#[test]
fn locality_empty_values_treated_as_none() {
    assert_eq!(locality_scope_fragment(Some(""), Some("  ")), None);
}

// ═══════════════════════════════════════════════════════════════════
// should_run_shadow_evaluation — all conditions
// ═══════════════════════════════════════════════════════════════════

fn make_traffic_mirror(
    enabled: bool,
    mirror_target: Option<&str>,
    sample_rate: f64,
) -> super::super::providers::TrafficMirrorConfig {
    super::super::providers::TrafficMirrorConfig {
        enabled,
        mirror_target: mirror_target.map(ToOwned::to_owned),
        sample_rate,
        ..Default::default()
    }
}

#[test]
fn shadow_eval_all_conditions_met() {
    let routing = EffectiveShadowRouting {
        enabled: true,
        capture_mode: "full".into(),
    };
    let mirror = make_traffic_mirror(true, Some("mirror-1"), 0.5);
    assert!(should_run_shadow_evaluation(&routing, &mirror));
}

#[test]
fn shadow_eval_disabled_routing() {
    let routing = EffectiveShadowRouting {
        enabled: false,
        capture_mode: "full".into(),
    };
    let mirror = make_traffic_mirror(true, Some("mirror-1"), 1.0);
    assert!(!should_run_shadow_evaluation(&routing, &mirror));
}

#[test]
fn shadow_eval_disabled_mirror() {
    let routing = EffectiveShadowRouting {
        enabled: true,
        capture_mode: "full".into(),
    };
    let mirror = make_traffic_mirror(false, Some("mirror-1"), 1.0);
    assert!(!should_run_shadow_evaluation(&routing, &mirror));
}

#[test]
fn shadow_eval_no_mirror_target() {
    let routing = EffectiveShadowRouting {
        enabled: true,
        capture_mode: "full".into(),
    };
    let mirror = make_traffic_mirror(true, None, 1.0);
    assert!(!should_run_shadow_evaluation(&routing, &mirror));
}

#[test]
fn shadow_eval_zero_sample_rate() {
    let routing = EffectiveShadowRouting {
        enabled: true,
        capture_mode: "full".into(),
    };
    let mirror = make_traffic_mirror(true, Some("mirror-1"), 0.0);
    assert!(!should_run_shadow_evaluation(&routing, &mirror));
}

// ═══════════════════════════════════════════════════════════════════
// shadow_sampled — boundary conditions
// ═══════════════════════════════════════════════════════════════════

#[test]
fn shadow_sampled_full_rate() {
    assert!(shadow_sampled(1.0));
    assert!(shadow_sampled(1.5));
}

#[test]
fn shadow_sampled_zero_rate() {
    assert!(!shadow_sampled(0.0));
    assert!(!shadow_sampled(-0.5));
}

// ═══════════════════════════════════════════════════════════════════
// strip_runtime_contract_fields — field removal
// ═══════════════════════════════════════════════════════════════════

#[test]
fn strip_removes_contract_fields() {
    let mut value = json!({
        "model": "gpt-4",
        "provider": {"allow_fallbacks": true},
        "cache_control": {"type": "ephemeral"},
        "session_id": "sess-1",
        "plugins": [{"id": "web-search"}],
        "messages": [{"role": "user", "content": "hello"}]
    });
    strip_runtime_contract_fields(&mut value);
    assert!(value.get("provider").is_none());
    assert!(value.get("cache_control").is_none());
    assert!(value.get("session_id").is_none());
    assert!(value.get("plugins").is_none());
    assert_eq!(value["model"], "gpt-4");
    assert!(value.get("messages").is_some());
}

#[test]
fn strip_non_object_is_noop() {
    let mut value = json!("not an object");
    strip_runtime_contract_fields(&mut value);
    assert_eq!(value, json!("not an object"));
}

#[test]
fn strip_bytes_valid_json() {
    let input = Bytes::from(
        serde_json::to_vec(&json!({"model":"gpt-4","provider":{},"session_id":"s1"})).unwrap(),
    );
    let output = strip_runtime_contract_fields_bytes(&input);
    let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(parsed.get("provider").is_none());
    assert!(parsed.get("session_id").is_none());
    assert_eq!(parsed["model"], "gpt-4");
}

#[test]
fn strip_bytes_invalid_json_returns_original() {
    let input = Bytes::from_static(b"not json");
    let output = strip_runtime_contract_fields_bytes(&input);
    assert_eq!(output, input);
}

// ═══════════════════════════════════════════════════════════════════
// runtime_error_id — prefix stripping
// ═══════════════════════════════════════════════════════════════════

#[test]
fn error_id_strips_req_prefix() {
    assert_eq!(runtime_error_id("req_abc123"), "err_abc123");
}

#[test]
fn error_id_without_prefix() {
    assert_eq!(runtime_error_id("abc123"), "err_abc123");
}

// ═══════════════════════════════════════════════════════════════════
// runtime_error_envelope — structure
// ═══════════════════════════════════════════════════════════════════

#[test]
fn error_envelope_structure() {
    let envelope = runtime_error_envelope(
        StatusCode::BAD_REQUEST,
        "req_test",
        "validation.failed",
        "bad input",
        json!({"field": "model"}),
    );
    let error = &envelope["error"];
    assert_eq!(error["status"], 400);
    assert_eq!(error["code"], "validation.failed");
    assert_eq!(error["message"], "bad input");
    assert_eq!(error["request_id"], "req_test");
    assert_eq!(error["error_id"], "err_test");
    assert_eq!(error["details"]["field"], "model");
}

// ═══════════════════════════════════════════════════════════════════
// voice_is_safe_identifier — all validation paths
// ═══════════════════════════════════════════════════════════════════

#[test]
fn voice_safe_valid() {
    assert!(voice_is_safe_identifier("alloy"));
    assert!(voice_is_safe_identifier("voice-1"));
    assert!(voice_is_safe_identifier("voice_2"));
    assert!(voice_is_safe_identifier("abc123"));
}

#[test]
fn voice_safe_empty() {
    assert!(!voice_is_safe_identifier(""));
    assert!(!voice_is_safe_identifier("  "));
}

#[test]
fn voice_safe_too_long() {
    assert!(!voice_is_safe_identifier(&"a".repeat(65)));
}

#[test]
fn voice_safe_exactly_64() {
    assert!(voice_is_safe_identifier(&"a".repeat(64)));
}

#[test]
fn voice_safe_special_chars() {
    assert!(!voice_is_safe_identifier("voice.1"));
    assert!(!voice_is_safe_identifier("voice 1"));
    assert!(!voice_is_safe_identifier("voice/1"));
}

// ═══════════════════════════════════════════════════════════════════
// validated_key_gateway_binding — metadata lookup
// ═══════════════════════════════════════════════════════════════════

#[test]
fn gateway_binding_personal_gateway_id() {
    let metadata = json!({"personal_gateway_id": "pgw-1"});
    assert_eq!(validated_key_gateway_binding(&metadata), Some("pgw-1"));
}

#[test]
fn gateway_binding_gateway_id_fallback() {
    let metadata = json!({"gateway_id": "gw-1"});
    assert_eq!(validated_key_gateway_binding(&metadata), Some("gw-1"));
}

#[test]
fn gateway_binding_personal_preferred() {
    let metadata = json!({
        "personal_gateway_id": "pgw-1",
        "gateway_id": "gw-1"
    });
    assert_eq!(validated_key_gateway_binding(&metadata), Some("pgw-1"));
}

#[test]
fn gateway_binding_empty_value_returns_none() {
    let metadata = json!({"personal_gateway_id": "  "});
    assert_eq!(validated_key_gateway_binding(&metadata), None);
}

#[test]
fn gateway_binding_missing() {
    let metadata = json!({});
    assert_eq!(validated_key_gateway_binding(&metadata), None);
}

// ═══════════════════════════════════════════════════════════════════
// validated_key_agent_binding — metadata lookup
// ═══════════════════════════════════════════════════════════════════

#[test]
fn agent_binding_present() {
    let metadata = json!({"agent_id": "agent-1"});
    assert_eq!(validated_key_agent_binding(&metadata), Some("agent-1"));
}

#[test]
fn agent_binding_empty() {
    let metadata = json!({"agent_id": " "});
    assert_eq!(validated_key_agent_binding(&metadata), None);
}

#[test]
fn agent_binding_missing() {
    let metadata = json!({});
    assert_eq!(validated_key_agent_binding(&metadata), None);
}

// ═══════════════════════════════════════════════════════════════════
// normalize_optional_text — trimming and filtering
// ═══════════════════════════════════════════════════════════════════

#[test]
fn optional_text_some_value() {
    assert_eq!(
        normalize_optional_text(Some(" hello ")),
        Some("hello".into())
    );
}

#[test]
fn optional_text_empty_returns_none() {
    assert_eq!(normalize_optional_text(Some("")), None);
    assert_eq!(normalize_optional_text(Some("  ")), None);
}

#[test]
fn optional_text_none() {
    assert_eq!(normalize_optional_text(None), None);
}

// ═══════════════════════════════════════════════════════════════════
// normalize_optional_string_value — JSON value extraction
// ═══════════════════════════════════════════════════════════════════

#[test]
fn optional_string_value_string() {
    let val = json!(" hello ");
    assert_eq!(
        normalize_optional_string_value(Some(&val)),
        Some("hello".into())
    );
}

#[test]
fn optional_string_value_not_string() {
    let val = json!(42);
    assert_eq!(normalize_optional_string_value(Some(&val)), None);
}

#[test]
fn optional_string_value_empty() {
    let val = json!("  ");
    assert_eq!(normalize_optional_string_value(Some(&val)), None);
}

#[test]
fn optional_string_value_none() {
    assert_eq!(normalize_optional_string_value(None), None);
}

// ═══════════════════════════════════════════════════════════════════
// non_empty_str — trimming and filtering
// ═══════════════════════════════════════════════════════════════════

#[test]
fn non_empty_str_value() {
    assert_eq!(non_empty_str(Some(" hello ")), Some("hello"));
}

#[test]
fn non_empty_str_empty() {
    assert_eq!(non_empty_str(Some("")), None);
    assert_eq!(non_empty_str(Some("  ")), None);
}

#[test]
fn non_empty_str_none() {
    assert_eq!(non_empty_str(None), None);
}

// ═══════════════════════════════════════════════════════════════════
// canonical_runtime_execution_surface — all match arms
// ═══════════════════════════════════════════════════════════════════

#[test]
fn execution_surface_runner_session() {
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
fn execution_surface_interactive_chat() {
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
fn execution_surface_unknown_with_session() {
    assert_eq!(
        canonical_runtime_execution_surface(Some("unknown"), Some("session-1")),
        "runner_session"
    );
}

#[test]
fn execution_surface_none_with_session() {
    assert_eq!(
        canonical_runtime_execution_surface(None, Some("session-1")),
        "runner_session"
    );
}

#[test]
fn execution_surface_none_without_session() {
    assert_eq!(
        canonical_runtime_execution_surface(None, None),
        "interactive_chat"
    );
}

#[test]
fn execution_surface_empty_is_none() {
    assert_eq!(
        canonical_runtime_execution_surface(Some(""), None),
        "interactive_chat"
    );
}

// ═══════════════════════════════════════════════════════════════════
// normalize_text_scope_values
// ═══════════════════════════════════════════════════════════════════

#[test]
fn text_scope_trims_dedup_sorts() {
    let values = vec![" b ".into(), "a".into(), "b".into(), "".into(), "c".into()];
    let result = normalize_text_scope_values(&values);
    assert_eq!(result, vec!["a", "b", "c"]);
}

// ═══════════════════════════════════════════════════════════════════
// normalize_provider_alias_list
// ═══════════════════════════════════════════════════════════════════

#[test]
fn provider_alias_list_dedup_sorts() {
    let values = vec!["openai".into(), "OPENAI".into(), "anthropic".into()];
    let result = normalize_provider_alias_list(&values);
    assert!(result.len() <= 2);
    assert!(result.windows(2).all(|w| w[0] <= w[1]));
}

// ═══════════════════════════════════════════════════════════════════
// serving_fleet_class_requires_public_pool_membership
// ═══════════════════════════════════════════════════════════════════

#[test]
fn fleet_class_connected_cell_pool() {
    assert!(serving_fleet_class_requires_public_pool_membership(
        "connected_cell_pool"
    ));
    assert!(serving_fleet_class_requires_public_pool_membership(
        "Connected_Cell_Pool"
    ));
}

#[test]
fn fleet_class_standard() {
    assert!(!serving_fleet_class_requires_public_pool_membership(
        "standard"
    ));
    assert!(!serving_fleet_class_requires_public_pool_membership(""));
}

// ═══════════════════════════════════════════════════════════════════
// RuntimeRoutingError helpers
// ═══════════════════════════════════════════════════════════════════

#[test]
fn routing_error_invalid_request() {
    let err = RuntimeRoutingError::invalid_request("test_code", "test message");
    assert_eq!(err.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(err.code(), "test_code");
    assert_eq!(err.browser_safe_message(), "test message");
}

// ═══════════════════════════════════════════════════════════════════
// BudgetFilterRejection constructors
// ═══════════════════════════════════════════════════════════════════

#[test]
fn budget_rejection_forbidden() {
    let rejection = BudgetFilterRejection::forbidden("over budget", "budget_exceeded");
    assert_eq!(rejection.status, StatusCode::FORBIDDEN);
    assert_eq!(rejection.error_type, "cost_budget_exceeded");
    assert_eq!(rejection.code, "budget_exceeded");
    assert_eq!(rejection.message, "over budget");
}

#[test]
fn budget_rejection_access_denied() {
    let rejection = BudgetFilterRejection::access_denied("no access", "denied");
    assert_eq!(rejection.status, StatusCode::FORBIDDEN);
    assert_eq!(rejection.error_type, "access_denied");
    assert_eq!(rejection.code, "denied");
    assert_eq!(rejection.message, "no access");
}

#[test]
fn budget_rejection_service_unavailable() {
    let rejection = BudgetFilterRejection::service_unavailable("service down", "svc_unavailable");
    assert_eq!(rejection.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(rejection.error_type, "service_unavailable");
}

// ═══════════════════════════════════════════════════════════════════
// GatewayRuntimeMetrics — counter operations and JSON
// ═══════════════════════════════════════════════════════════════════

#[test]
fn runtime_metrics_counters_and_json() {
    let metrics = GatewayRuntimeMetrics::default();
    metrics.record_token_validation_cache_hit();
    metrics.record_token_validation_cache_hit();
    metrics.record_token_validation_cache_miss();
    metrics.record_runtime_controls_cache_hit();
    metrics.record_runtime_controls_cache_miss();
    metrics.record_manifest_fetch();
    metrics.record_yaml_fetch();
    metrics.record_runtime_build_failure();

    let json = metrics.as_json();
    assert_eq!(json["token_validation_cache_hits"], 2);
    assert_eq!(json["token_validation_cache_misses"], 1);
    assert_eq!(json["runtime_controls_cache_hits"], 1);
    assert_eq!(json["runtime_controls_cache_misses"], 1);
    assert_eq!(json["manifest_fetches"], 1);
    assert_eq!(json["yaml_fetches"], 1);
    assert_eq!(json["runtime_build_failures"], 1);
}

// ═══════════════════════════════════════════════════════════════════
// derive_usage_category — exhaustive priority chain
// ═══════════════════════════════════════════════════════════════════

#[test]
fn usage_category_unknown_source_falls_through() {
    let meta = json!({"source": "unknown"});
    assert_eq!(derive_usage_category(&meta, None, None), "gateway_llm");
}

#[test]
fn usage_category_empty_workflow_not_workflows() {
    let meta = json!({});
    assert_eq!(derive_usage_category(&meta, Some(""), None), "gateway_llm");
}

#[test]
fn usage_category_empty_agent_not_agents() {
    let meta = json!({});
    assert_eq!(derive_usage_category(&meta, None, Some("")), "gateway_llm");
}

#[test]
fn usage_category_source_takes_priority_over_workflow() {
    let meta = json!({"source": "export"});
    assert_eq!(
        derive_usage_category(&meta, Some("wf-1"), Some("ag-1")),
        "exports"
    );
}

#[test]
fn usage_category_workflow_takes_priority_over_agent() {
    let meta = json!({});
    assert_eq!(
        derive_usage_category(&meta, Some("wf-1"), Some("ag-1")),
        "workflows"
    );
}

// ═══════════════════════════════════════════════════════════════════
// TraceCorrelation is_empty
// ═══════════════════════════════════════════════════════════════════

#[test]
fn trace_correlation_partial_is_not_empty() {
    let corr = TraceCorrelation {
        evaluation_id: None,
        evaluation_run_id: None,
        test_case_id: Some("tc-1".into()),
        test_run_id: None,
    };
    assert!(!corr.is_empty());
}

// ═══════════════════════════════════════════════════════════════════
// RuntimePreflightError constructors
// ═══════════════════════════════════════════════════════════════════

#[test]
fn preflight_error_validation_failed() {
    let err = RuntimePreflightError::validation_failed("test message", json!({"field": "model"}));
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert_eq!(err.code, "request.validation_failed");
    assert_eq!(err.details["field"], "model");
}

#[test]
fn preflight_error_custom_status() {
    let err = RuntimePreflightError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        "runtime.too_large",
        "payload too large",
        json!({}),
    );
    assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(err.code, "runtime.too_large");
}

// ═══════════════════════════════════════════════════════════════════
// required_string_field — validation paths
// ═══════════════════════════════════════════════════════════════════

#[test]
fn required_string_present() {
    let body = json!({"model": "gpt-4"});
    assert_eq!(required_string_field(&body, "/model").unwrap(), "gpt-4");
}

#[test]
fn required_string_missing() {
    let body = json!({});
    let err = required_string_field(&body, "/model").unwrap_err();
    assert_eq!(err.details["field"], "model");
}

#[test]
fn required_string_empty() {
    let body = json!({"model": "  "});
    assert!(required_string_field(&body, "/model").is_err());
}

#[test]
fn required_string_not_string() {
    let body = json!({"model": 42});
    assert!(required_string_field(&body, "/model").is_err());
}

#[test]
fn required_string_nested() {
    let body = json!({"input_audio": {"data": "base64data"}});
    assert_eq!(
        required_string_field(&body, "/input_audio/data").unwrap(),
        "base64data"
    );
}

// ═══════════════════════════════════════════════════════════════════
// parse_runtime_json_body
// ═══════════════════════════════════════════════════════════════════

#[test]
fn parse_json_body_valid() {
    let body = Bytes::from(r#"{"model":"gpt-4"}"#);
    let parsed = parse_runtime_json_body(&body).unwrap();
    assert_eq!(parsed["model"], "gpt-4");
}

#[test]
fn parse_json_body_invalid() {
    let body = Bytes::from(b"not json".to_vec());
    let err = parse_runtime_json_body(&body).unwrap_err();
    assert_eq!(err.code, "request.validation_failed");
}

// ═══════════════════════════════════════════════════════════════════
// normalized_audio_transcription_format
// ═══════════════════════════════════════════════════════════════════

#[test]
fn audio_format_valid_formats() {
    for format in &["wav", "mp3", "mp4", "mpeg", "mpga", "m4a", "webm", "ogg"] {
        let body = json!({"input_audio": {"format": format, "data": "dGVzdA=="}});
        assert!(
            normalized_audio_transcription_format(&body).is_ok(),
            "expected ok for format '{format}'"
        );
    }
}

#[test]
fn audio_format_case_insensitive() {
    let body = json!({"input_audio": {"format": "MP3", "data": "dGVzdA=="}});
    assert!(normalized_audio_transcription_format(&body).is_ok());
}

#[test]
fn audio_format_unsupported() {
    let body = json!({"input_audio": {"format": "aiff", "data": "dGVzdA=="}});
    let err = normalized_audio_transcription_format(&body).unwrap_err();
    assert_eq!(err.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[test]
fn audio_format_missing() {
    let body = json!({"input_audio": {"data": "dGVzdA=="}});
    assert!(normalized_audio_transcription_format(&body).is_err());
}

// ═══════════════════════════════════════════════════════════════════
// normalized_audio_speech_output_format
// ═══════════════════════════════════════════════════════════════════

#[test]
fn speech_output_format_valid() {
    for format in &["mp3", "wav", "opus", "aac", "flac", "pcm"] {
        let body = json!({"response_format": format});
        assert!(
            normalized_audio_speech_output_format(&body).is_ok(),
            "expected ok for format '{format}'"
        );
    }
}

#[test]
fn speech_output_format_default_mp3() {
    let body = json!({});
    assert_eq!(normalized_audio_speech_output_format(&body).unwrap(), "mp3");
}

#[test]
fn speech_output_format_unsupported() {
    let body = json!({"response_format": "raw"});
    let err = normalized_audio_speech_output_format(&body).unwrap_err();
    assert_eq!(err.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// ═══════════════════════════════════════════════════════════════════
// validate_audio_transcription_request — deep branches
// ═══════════════════════════════════════════════════════════════════

#[test]
fn transcription_missing_model() {
    let body = json!({"input_audio": {"data": "dGVzdA==", "format": "mp3"}});
    let err = validate_audio_transcription_request(&body).unwrap_err();
    assert_eq!(err.code, "request.validation_failed");
}

#[test]
fn transcription_missing_audio_data() {
    let body = json!({"model": "whisper", "input_audio": {"format": "mp3"}});
    assert!(validate_audio_transcription_request(&body).is_err());
}

#[test]
fn transcription_invalid_language_type() {
    let body = json!({
        "model": "whisper",
        "input_audio": {"data": "dGVzdA==", "format": "mp3"},
        "language": 42
    });
    assert!(validate_audio_transcription_request(&body).is_err());
}

#[test]
fn transcription_empty_language_rejected() {
    let body = json!({
        "model": "whisper",
        "input_audio": {"data": "dGVzdA==", "format": "mp3"},
        "language": ""
    });
    assert!(validate_audio_transcription_request(&body).is_err());
}

#[test]
fn transcription_valid_language_accepted() {
    let body = json!({
        "model": "whisper",
        "input_audio": {"data": "dGVzdA==", "format": "mp3"},
        "language": "en"
    });
    assert!(validate_audio_transcription_request(&body).is_ok());
}

#[test]
fn transcription_invalid_base64() {
    let body = json!({
        "model": "whisper",
        "input_audio": {"data": "not-valid-base64!!!", "format": "mp3"}
    });
    let err = validate_audio_transcription_request(&body).unwrap_err();
    assert_eq!(err.code, "request.validation_failed");
}

// ═══════════════════════════════════════════════════════════════════
// validate_audio_speech_request — deep branches
// ═══════════════════════════════════════════════════════════════════

fn make_test_gateway_state() -> GatewayState {
    GatewayState {
        gateway_id: Some(Arc::from("gw-line-level-test")),
        crdt_replica_id: Arc::from("gw-line-level-test"),
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

fn make_test_view() -> ActiveGatewayStateView<'static> {
    let state = Box::leak(Box::new(make_test_gateway_state()));
    ActiveGatewayStateView::from_state(state, LoadedDeclarativeConfig::empty())
}

#[test]
fn speech_missing_model() {
    let view = make_test_view();
    let body = json!({"input": "hello", "voice": "alloy"});
    assert!(validate_audio_speech_request(&view, &body).is_err());
}

#[test]
fn speech_missing_input() {
    let view = make_test_view();
    let body = json!({"model": "tts-1", "voice": "alloy"});
    assert!(validate_audio_speech_request(&view, &body).is_err());
}

#[test]
fn speech_missing_voice() {
    let view = make_test_view();
    let body = json!({"model": "tts-1", "input": "hello"});
    assert!(validate_audio_speech_request(&view, &body).is_err());
}

#[test]
fn speech_input_too_large() {
    let view = make_test_view();
    let body = json!({
        "model": "tts-1",
        "input": "x".repeat(AUDIO_SPEECH_INPUT_MAX_BYTES + 1),
        "voice": "alloy"
    });
    let err = validate_audio_speech_request(&view, &body).unwrap_err();
    assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[test]
fn speech_invalid_voice_chars() {
    let view = make_test_view();
    let body = json!({
        "model": "tts-1",
        "input": "hello",
        "voice": "invalid voice!"
    });
    assert!(validate_audio_speech_request(&view, &body).is_err());
}

#[test]
fn speech_invalid_speed_type() {
    let view = make_test_view();
    let body = json!({
        "model": "tts-1",
        "input": "hello",
        "voice": "alloy",
        "speed": "fast"
    });
    assert!(validate_audio_speech_request(&view, &body).is_err());
}

#[test]
fn speech_speed_out_of_range_low() {
    let view = make_test_view();
    let body = json!({
        "model": "tts-1",
        "input": "hello",
        "voice": "alloy",
        "speed": 0.1
    });
    assert!(validate_audio_speech_request(&view, &body).is_err());
}

#[test]
fn speech_speed_out_of_range_high() {
    let view = make_test_view();
    let body = json!({
        "model": "tts-1",
        "input": "hello",
        "voice": "alloy",
        "speed": 5.0
    });
    assert!(validate_audio_speech_request(&view, &body).is_err());
}

#[test]
fn speech_valid_request() {
    let view = make_test_view();
    let body = json!({
        "model": "tts-1",
        "input": "hello world",
        "voice": "alloy"
    });
    assert!(validate_audio_speech_request(&view, &body).is_ok());
}

#[test]
fn speech_valid_with_speed() {
    let view = make_test_view();
    let body = json!({
        "model": "tts-1",
        "input": "hello world",
        "voice": "alloy",
        "speed": 1.5
    });
    assert!(validate_audio_speech_request(&view, &body).is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// PricingSource and ConnectedPostDispatchUsageSource
// ═══════════════════════════════════════════════════════════════════

#[test]
fn pricing_source_serialization() {
    let upstream = serde_json::to_value(PricingSource::Upstream).unwrap();
    assert_eq!(upstream, "upstream");
    let config_declared = serde_json::to_value(PricingSource::ConfigDeclared).unwrap();
    assert_eq!(config_declared, "config_declared");
}

#[test]
fn post_dispatch_usage_source_as_str() {
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
fn post_dispatch_usage_source_is_estimated() {
    assert!(!ConnectedPostDispatchUsageSource::UpstreamReported.is_estimated());
    assert!(ConnectedPostDispatchUsageSource::PromptOnlyFallback.is_estimated());
    assert!(ConnectedPostDispatchUsageSource::StreamingEstimate.is_estimated());
}

// ═══════════════════════════════════════════════════════════════════
// CacheTier and CacheReplayOutcome
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cache_tier_as_str() {
    assert_eq!(CacheTier::PrivateEdge.as_str(), "private_edge_cache");
    assert_eq!(CacheTier::OrgShared.as_str(), "org_shared_cache");
}

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
    assert_eq!(
        CacheReplayOutcome::SemanticReplayed.hit_type(),
        "semantic_replayed"
    );
    assert_eq!(CacheReplayOutcome::StaleMiss.hit_type(), "exact");
    assert_eq!(CacheReplayOutcome::DeniedReplay.hit_type(), "exact");
}

#[test]
fn cache_replay_metadata_to_json() {
    let metadata = CacheReplayMetadata {
        outcome: CacheReplayOutcome::ExactHit,
        cache_tier: CacheTier::PrivateEdge,
        cache_key_digest: Some("digest-1".into()),
        selected_fabric_artifact_ids: vec!["art-1".into()],
        selected_fabric_source_digests: vec!["src-1".into()],
    };
    let json = metadata.to_json();
    assert_eq!(json["outcome"], "exact_hit");
    assert_eq!(json["cache_tier"], "private_edge_cache");
    assert_eq!(json["cache_key_digest"], "digest-1");
}

// ═══════════════════════════════════════════════════════════════════
// RequestFinopsContext — identity helpers
// ═══════════════════════════════════════════════════════════════════

#[test]
fn finops_has_token_identity_with_key_id() {
    let ctx = RequestFinopsContext {
        key_id: Some("key-1".into()),
        ..Default::default()
    };
    assert!(ctx.has_token_identity());
}

#[test]
fn finops_has_no_token_identity() {
    let ctx = RequestFinopsContext::default();
    assert!(!ctx.has_token_identity());
}

#[test]
fn finops_has_no_token_identity_empty_key() {
    let ctx = RequestFinopsContext {
        key_id: Some("  ".into()),
        ..Default::default()
    };
    assert!(!ctx.has_token_identity());
}

#[test]
fn finops_identity_context_json_with_fields() {
    let ctx = RequestFinopsContext {
        key_id: Some("key-1".into()),
        user_id: Some("user-1".into()),
        team_id: Some("team-1".into()),
        org_id: Some("org-1".into()),
        created_by: Some("creator-1".into()),
        agent_id: Some("agent-1".into()),
        ..Default::default()
    };
    let json = ctx.identity_context_json().unwrap();
    assert_eq!(json["key_id"], "key-1");
    assert_eq!(json["user_id"], "user-1");
    assert_eq!(json["team_id"], "team-1");
    assert_eq!(json["org_id"], "org-1");
}

#[test]
fn finops_identity_context_json_none_when_no_identity() {
    let ctx = RequestFinopsContext::default();
    assert!(ctx.identity_context_json().is_none());
}

// ═══════════════════════════════════════════════════════════════════
// runtime_routing_from_declarative — conversion
// ═══════════════════════════════════════════════════════════════════

#[test]
fn routing_from_declarative_none_returns_default() {
    let result = runtime_routing_from_declarative(None);
    assert!(result.default_provider_policy.allow_fallbacks);
    assert!(result.cache_defaults.allow_cache_control);
    assert!(!result.shadow_routing.enabled);
}

// ═══════════════════════════════════════════════════════════════════
// EffectiveShadowRouting default
// ═══════════════════════════════════════════════════════════════════

#[test]
fn shadow_routing_default() {
    let sr = EffectiveShadowRouting::default();
    assert!(!sr.enabled);
    assert_eq!(sr.capture_mode, "metadata_only");
}

// ═══════════════════════════════════════════════════════════════════
// RuntimeRoutingSettings defaults and serde
// ═══════════════════════════════════════════════════════════════════

#[test]
fn runtime_routing_settings_default() {
    let s = RuntimeRoutingSettings::default();
    assert!(s.default_provider_policy.allow_fallbacks);
    assert!(s.default_provider_policy.require_parameters);
    assert_eq!(s.default_provider_policy.data_collection, "allow");
    assert!(!s.default_provider_policy.zdr);
    assert!(s.cache_defaults.allow_cache_control);
    assert!(s.cache_defaults.sticky_routing);
    assert!(s.cache_defaults.allow_session_id);
    assert_eq!(s.cache_defaults.session_header_name, "x-session-id");
    assert!(s.plugin_governance.defaults.is_empty());
    assert!(s.plugin_governance.forced_on.is_empty());
    assert!(s.plugin_governance.prevent_overrides.is_empty());
    assert!(!s.shadow_routing.enabled);
}

#[test]
fn runtime_routing_settings_deserialize_empty() {
    let s: RuntimeRoutingSettings = serde_json::from_str("{}").unwrap();
    assert!(s.default_provider_policy.allow_fallbacks);
}

// ═══════════════════════════════════════════════════════════════════
// EventSinkConfig from_env branch coverage
// ═══════════════════════════════════════════════════════════════════

#[test]
fn optional_env_returns_none_for_absent() {
    assert!(optional_env("VERDICTAN_NONEXISTENT_TEST_VAR_12345").is_none());
}

// ═══════════════════════════════════════════════════════════════════
// SharedGatewayConfig operations
// ═══════════════════════════════════════════════════════════════════

#[test]
fn shared_gateway_config_snapshot_and_replace() {
    let config = SharedGatewayConfig::new(LoadedDeclarativeConfig::empty());
    let snap1 = config.snapshot();
    let initial_version = snap1.config_version.clone();

    let mut replacement = LoadedDeclarativeConfig::empty();
    replacement.config_version = format!("{initial_version}_replaced");
    let expected = replacement.config_version.clone();
    config.replace(replacement);

    let snap2 = config.snapshot();
    assert_eq!(snap2.config_version, expected);
}

// ═══════════════════════════════════════════════════════════════════
// TokenValidationError Display
// ═══════════════════════════════════════════════════════════════════

#[test]
fn token_validation_error_display() {
    let err = TokenValidationError::Unauthorized {
        body: "bad token".into(),
    };
    assert!(format!("{err}").contains("unauthorized"));

    let err = TokenValidationError::Forbidden {
        body: "forbidden".into(),
    };
    assert!(format!("{err}").contains("forbidden"));

    let err = TokenValidationError::UnexpectedStatus {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        body: "error".into(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("500"));
}

// ═══════════════════════════════════════════════════════════════════
// publication_has_publicly_admissible_active_revision
// ═══════════════════════════════════════════════════════════════════

#[test]
fn pub_has_admissible_revision_true() {
    let pub_desc = make_publication("published", Some("host.com"));
    assert!(publication_has_publicly_admissible_active_revision(
        &pub_desc
    ));
}

#[test]
fn pub_has_admissible_revision_false() {
    let mut pub_desc = make_publication("published", Some("host.com"));
    pub_desc.active_revision_id = None;
    assert!(!publication_has_publicly_admissible_active_revision(
        &pub_desc
    ));
}

// ═══════════════════════════════════════════════════════════════════
// default_usage_category_cli
// ═══════════════════════════════════════════════════════════════════

#[test]
fn default_usage_category() {
    assert_eq!(default_usage_category_cli(), "gateway_llm");
}

// ═══════════════════════════════════════════════════════════════════
// ConnectedAccessRequestStatus
// ═══════════════════════════════════════════════════════════════════

#[test]
fn billing_request_status_default() {
    let status = ConnectedAccessRequestStatus::default();
    assert_eq!(status.admission_credential_source, None);
    assert!(!status.dispatch_precluded);
}

// ═══════════════════════════════════════════════════════════════════
// deserialize_token_model_filters — various JSON shapes
// ═══════════════════════════════════════════════════════════════════

#[test]
fn token_model_filter_single_string() {
    let record: TokenRecord = serde_json::from_value(json!({
        "id": "tok-1",
        "current_spend": 0.0,
        "model_filter": "gpt-4"
    }))
    .unwrap();
    assert_eq!(record.model_filter, vec!["gpt-4"]);
}

#[test]
fn token_model_filter_array() {
    let record: TokenRecord = serde_json::from_value(json!({
        "id": "tok-1",
        "current_spend": 0.0,
        "model_filter": ["gpt-4", "gpt-3.5"]
    }))
    .unwrap();
    assert_eq!(record.model_filter, vec!["gpt-4", "gpt-3.5"]);
}

#[test]
fn token_model_filter_null() {
    let record: TokenRecord = serde_json::from_value(json!({
        "id": "tok-1",
        "current_spend": 0.0,
        "model_filter": null
    }))
    .unwrap();
    assert!(record.model_filter.is_empty());
}

#[test]
fn token_model_filter_missing() {
    let record: TokenRecord = serde_json::from_value(json!({
        "id": "tok-1",
        "current_spend": 0.0
    }))
    .unwrap();
    assert!(record.model_filter.is_empty());
}

// ═══════════════════════════════════════════════════════════════════
// publication_matches_requested_managed_public_endpoint
// ═══════════════════════════════════════════════════════════════════

#[test]
fn pub_matches_endpoint_matching_host() {
    let pub_desc = crate::runtime::ConnectedGatewayPublicationCatalogDescriptor {
        family_key: "fam".into(),
        publication_key: "pub-1".into(),
        published_hostname: Some("api.example.com".into()),
        publication_state: "published".into(),
        active_revision_id: Some("rev-1".into()),
        locality_mode: "regional".into(),
        serving_fleet_class: "standard".into(),
        agent_id: None,
    };
    assert!(publication_matches_requested_managed_public_endpoint(
        &pub_desc,
        "api.example.com"
    ));
}

#[test]
fn pub_matches_endpoint_non_matching_host() {
    let pub_desc = crate::runtime::ConnectedGatewayPublicationCatalogDescriptor {
        family_key: "fam".into(),
        publication_key: "pub-1".into(),
        published_hostname: Some("api.example.com".into()),
        publication_state: "published".into(),
        active_revision_id: Some("rev-1".into()),
        locality_mode: "regional".into(),
        serving_fleet_class: "standard".into(),
        agent_id: None,
    };
    assert!(!publication_matches_requested_managed_public_endpoint(
        &pub_desc,
        "other.example.com"
    ));
}

#[test]
fn pub_matches_endpoint_draft_state_rejects() {
    let pub_desc = crate::runtime::ConnectedGatewayPublicationCatalogDescriptor {
        family_key: "fam".into(),
        publication_key: "pub-1".into(),
        published_hostname: Some("api.example.com".into()),
        publication_state: "draft".into(),
        active_revision_id: Some("rev-1".into()),
        locality_mode: "regional".into(),
        serving_fleet_class: "standard".into(),
        agent_id: None,
    };
    assert!(!publication_matches_requested_managed_public_endpoint(
        &pub_desc,
        "api.example.com"
    ));
}

#[test]
fn pub_matches_endpoint_no_hostname() {
    let pub_desc = crate::runtime::ConnectedGatewayPublicationCatalogDescriptor {
        family_key: "fam".into(),
        publication_key: "pub-1".into(),
        published_hostname: None,
        publication_state: "published".into(),
        active_revision_id: Some("rev-1".into()),
        locality_mode: "regional".into(),
        serving_fleet_class: "standard".into(),
        agent_id: None,
    };
    assert!(!publication_matches_requested_managed_public_endpoint(
        &pub_desc,
        "api.example.com"
    ));
}

fn runtime_routing_settings_response(
    allow_fallbacks: bool,
    data_collection: &str,
    session_header_name: &str,
) -> serde_json::Value {
    json!({
        "default_provider_policy": {
            "allow_fallbacks": allow_fallbacks,
            "require_parameters": true,
            "data_collection": data_collection,
            "zdr": false
        },
        "cache_defaults": {
            "allow_cache_control": true,
            "sticky_routing": true,
            "allow_session_id": true,
            "session_header_name": session_header_name
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
    })
}

#[tokio::test]
async fn event_sink_runtime_auth_contract_probe_uses_machine_route_and_accepts_valid_false() {
    let machine_hits = Arc::new(AtomicUsize::new(0));
    let user_hits = Arc::new(AtomicUsize::new(0));

    let machine_hits_handler = machine_hits.clone();
    let user_hits_handler = user_hits.clone();
    let app = Router::new()
        .route(
            "/v1/gateway/tokens/validate",
            post(
                move |headers: HeaderMap, Json(payload): Json<serde_json::Value>| {
                    let machine_hits = machine_hits_handler.clone();
                    async move {
                        machine_hits.fetch_add(1, Ordering::SeqCst);
                        let auth = headers
                            .get(axum::http::header::AUTHORIZATION)
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default();
                        if auth != "Bearer machine-token" {
                            return (
                                StatusCode::UNAUTHORIZED,
                                Json(json!({"error": "wrong machine token"})),
                            )
                                .into_response();
                        }

                        assert_eq!(payload["token"], "vdt_probe_invalid");
                        (
                            StatusCode::OK,
                            Json(json!({
                                "valid": false,
                                "reason": "probe invalid"
                            })),
                        )
                            .into_response()
                    }
                },
            ),
        )
        .route(
            "/v1/tokens/validate",
            post(move || {
                let user_hits = user_hits_handler.clone();
                async move {
                    user_hits.fetch_add(1, Ordering::SeqCst);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "user route should not be used"})),
                    )
                        .into_response()
                }
            }),
        );

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

    sink.probe_token_validation()
        .await
        .expect("probe should succeed on 200 valid=false");

    assert_eq!(machine_hits.load(Ordering::SeqCst), 1);
    assert_eq!(user_hits.load(Ordering::SeqCst), 0);

    handle.abort();
}

#[tokio::test]
async fn event_sink_runtime_auth_contract_validate_token_uses_user_route_without_machine_client() {
    let user_hits = Arc::new(AtomicUsize::new(0));
    let user_hits_handler = user_hits.clone();
    let app = Router::new().route(
        "/v1/tokens/validate",
        post(
            move |headers: HeaderMap, Json(payload): Json<serde_json::Value>| {
                let user_hits = user_hits_handler.clone();
                async move {
                    user_hits.fetch_add(1, Ordering::SeqCst);
                    let auth = headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default();
                    if auth != "Bearer user-token" {
                        return (
                            StatusCode::UNAUTHORIZED,
                            Json(json!({"error": "wrong user token"})),
                        )
                            .into_response();
                    }

                    assert_eq!(payload["token"], "vdt_user_route");
                    (
                        StatusCode::OK,
                        Json(json!({
                            "valid": true,
                            "org_id": "org-user"
                        })),
                    )
                        .into_response()
                }
            },
        ),
    );

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
        gateway_service_token: None,
    })
    .expect("event sink");

    let response = sink
        .validate_token("vdt_user_route")
        .await
        .expect("user route validation");

    assert!(response.valid);
    assert_eq!(response.org_id.as_deref(), Some("org-user"));
    assert_eq!(user_hits.load(Ordering::SeqCst), 1);

    handle.abort();
}

#[tokio::test]
async fn event_sink_runtime_auth_contract_validate_token_maps_fail_closed_statuses_and_request_errors(
) {
    let invalid_json_hits = Arc::new(AtomicUsize::new(0));
    let invalid_json_hits_handler = invalid_json_hits.clone();
    let app = Router::new().route(
        "/v1/tokens/validate",
        post(move |Json(payload): Json<serde_json::Value>| {
            let invalid_json_hits = invalid_json_hits_handler.clone();
            async move {
                match payload.get("token").and_then(|value| value.as_str()) {
                    Some("unauthorized") => {
                        (StatusCode::UNAUTHORIZED, Json(json!({"error": "bad_auth"})))
                            .into_response()
                    }
                    Some("forbidden") => {
                        (StatusCode::FORBIDDEN, Json(json!({"error": "denied"}))).into_response()
                    }
                    Some("unexpected") => (
                        StatusCode::BAD_GATEWAY,
                        Json(json!({"error": "upstream_bad_gateway"})),
                    )
                        .into_response(),
                    Some("invalid-json") => {
                        invalid_json_hits.fetch_add(1, Ordering::SeqCst);
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(axum::http::header::CONTENT_TYPE, "application/json")
                            .body(Body::from("{not valid json"))
                            .expect("invalid json response")
                    }
                    _ => (
                        StatusCode::OK,
                        Json(json!({
                            "valid": true
                        })),
                    )
                        .into_response(),
                }
            }
        }),
    );

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
        gateway_service_token: None,
    })
    .expect("event sink");

    match sink.validate_token("unauthorized").await {
        Err(TokenValidationError::Unauthorized { body }) => {
            assert!(body.contains("bad_auth"));
        }
        other => panic!("expected unauthorized error, got {other:?}"),
    }

    match sink.validate_token("forbidden").await {
        Err(TokenValidationError::Forbidden { body }) => {
            assert!(body.contains("denied"));
        }
        other => panic!("expected forbidden error, got {other:?}"),
    }

    match sink.validate_token("unexpected").await {
        Err(TokenValidationError::UnexpectedStatus { status, body }) => {
            assert_eq!(status, StatusCode::BAD_GATEWAY);
            assert!(body.contains("upstream_bad_gateway"));
        }
        other => panic!("expected unexpected-status error, got {other:?}"),
    }

    match sink.validate_token("invalid-json").await {
        Err(TokenValidationError::Request(_)) => {}
        other => panic!("expected request/json parse error, got {other:?}"),
    }

    assert_eq!(invalid_json_hits.load(Ordering::SeqCst), 3);

    handle.abort();
}

#[tokio::test]
async fn event_sink_runtime_auth_contract_fetch_runtime_routing_uses_user_route_and_caches_default_key(
) {
    let user_hits = Arc::new(AtomicUsize::new(0));
    let machine_hits = Arc::new(AtomicUsize::new(0));

    let user_hits_handler = user_hits.clone();
    let machine_hits_handler = machine_hits.clone();
    let app = Router::new()
        .route(
            "/v1/settings/runtime-routing",
            get(move |headers: HeaderMap| {
                let user_hits = user_hits_handler.clone();
                async move {
                    user_hits.fetch_add(1, Ordering::SeqCst);
                    let auth = headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default();
                    if auth != "Bearer user-token" {
                        return (
                            StatusCode::UNAUTHORIZED,
                            Json(json!({"error": "wrong user token"})),
                        )
                            .into_response();
                    }

                    (
                        StatusCode::OK,
                        Json(runtime_routing_settings_response(
                            false,
                            "deny",
                            "x-user-session",
                        )),
                    )
                        .into_response()
                }
            }),
        )
        .route(
            "/v1/gateway/settings/runtime-routing",
            get(move || {
                let machine_hits = machine_hits_handler.clone();
                async move {
                    machine_hits.fetch_add(1, Ordering::SeqCst);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "machine route should not be used"})),
                    )
                        .into_response()
                }
            }),
        );

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
        gateway_service_token: None,
    })
    .expect("event sink");

    let first = sink
        .fetch_runtime_routing_settings(Some("   "))
        .await
        .expect("first runtime routing fetch");
    let second = sink
        .fetch_runtime_routing_settings(None)
        .await
        .expect("cached runtime routing fetch");

    assert!(!first.default_provider_policy.allow_fallbacks);
    assert_eq!(first.default_provider_policy.data_collection, "deny");
    assert_eq!(first.cache_defaults.session_header_name, "x-user-session");
    assert_eq!(second.cache_defaults.session_header_name, "x-user-session");
    assert_eq!(user_hits.load(Ordering::SeqCst), 1);
    assert_eq!(machine_hits.load(Ordering::SeqCst), 0);

    handle.abort();
}

#[tokio::test]
async fn event_sink_runtime_auth_contract_fetch_runtime_routing_reports_fail_closed_errors() {
    let app = Router::new().route(
        "/v1/settings/runtime-routing",
        get(|| async move {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "runtime_routing_unavailable"})),
            )
                .into_response()
        }),
    );

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
        gateway_service_token: None,
    })
    .expect("event sink");

    let error = sink
        .fetch_runtime_routing_settings(Some("org-1"))
        .await
        .expect_err("runtime routing failure should bubble");
    let message = error.to_string();
    assert!(message.contains("status=503"), "{message}");
    assert!(message.contains("runtime_routing_unavailable"), "{message}");

    handle.abort();
}

#[test]
fn runtime_tool_result_graph_ingestion_extracts_openai_tool_messages() {
    let payload = json!({
        "messages": [
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "schema_lookup",
                        "arguments": "{\"table\":\"payments\"}"
                    }
                }]
            },
            {
                "role": "tool",
                "tool_call_id": "call_1",
                "content": "{\"table\":\"payments\",\"columns\":[{\"name\":\"id\",\"type\":\"uuid\",\"nullable\":false}]}"
            }
        ]
    });

    let results = extract_runtime_tool_results(&payload);

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].tool_name, "schema_lookup");
    assert_eq!(results[0].arguments["table"], "payments");
    assert_eq!(results[0].output["table"], "payments");
    assert_eq!(results[0].output["columns"][0]["name"], "id");
}

#[test]
fn runtime_tool_result_graph_ingestion_extracts_responses_function_call_outputs() {
    let payload = json!({
        "input": [
            {
                "type": "function_call",
                "call_id": "call_1",
                "name": "schema_lookup",
                "arguments": "{\"table\":\"payments\"}"
            },
            {
                "type": "function_call_output",
                "call_id": "call_1",
                "output": "{\"table\":\"payments\",\"columns\":[{\"name\":\"user_id\",\"type\":\"uuid\",\"nullable\":false}]}"
            }
        ]
    });

    let results = extract_runtime_tool_results(&payload);

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].tool_name, "schema_lookup");
    assert_eq!(results[0].arguments["table"], "payments");
    assert_eq!(results[0].output["columns"][0]["name"], "user_id");
}

#[tokio::test]
async fn runtime_tool_result_graph_ingestion_posts_graph_upsert_from_history_success_path() {
    let (payload_tx, payload_rx) = tokio::sync::oneshot::channel::<serde_json::Value>();
    let payload_sender = Arc::new(std::sync::Mutex::new(Some(payload_tx)));
    let payload_sender_handler = payload_sender.clone();
    let app = Router::new().route(
        "/v1/context/graph/upsert",
        post(
            move |headers: HeaderMap, Json(payload): Json<serde_json::Value>| {
                let payload_sender = payload_sender_handler.clone();
                async move {
                    let auth = headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default();
                    assert_eq!(auth, "Bearer user-token");
                    payload_sender
                        .lock()
                        .expect("payload sender lock")
                        .take()
                        .expect("payload sender available")
                        .send(payload.clone())
                        .expect("payload delivered");
                    (StatusCode::OK, Json(json!({"nodes": [], "edges": []}))).into_response()
                }
            },
        ),
    );

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
        gateway_service_token: None,
    })
    .expect("event sink");

    let session_context = crate::gateway::session::GatewaySessionContext {
        session_id: "session-1".to_string(),
        scope: "team".to_string(),
        _org_id: Some("org-1".to_string()),
        team_id: Some("team-1".to_string()),
        git_context: Some(crate::gateway::session::GatewayGitContext {
            repo: Some("verdictan/verdictan".to_string()),
            branch: Some("feature/graph".to_string()),
            commit: Some("abc123".to_string()),
        }),
        ..Default::default()
    };
    let request_body = Bytes::from(
            serde_json::to_vec(&json!({
                "messages": [{
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_1",
                            "name": "schema_lookup",
                            "input": {"table": "payments"}
                        },
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_1",
                            "content": [{
                                "type": "text",
                                "text": "{\"table\":\"payments\",\"columns\":[{\"name\":\"id\",\"type\":\"uuid\",\"nullable\":false}]}"
                            }]
                        }
                    ]
                }]
            }))
            .expect("serialize request body"),
        );

    emit_history_writeback_detached(
        Some(sink),
        None,
        None,
        Some(RequestFinopsContext {
            team_id: Some("team-1".to_string()),
            ..Default::default()
        }),
        Some("disabled".to_string()),
        "req-123",
        "trace-123",
        Some(session_context),
        &request_body,
        json!({"ok": true}),
        &Verdict::Allow,
        None,
        None,
        Some(42),
    );

    let payload = tokio::time::timeout(Duration::from_secs(2), payload_rx)
        .await
        .expect("graph upsert request received in time")
        .expect("graph upsert payload delivered");

    assert_eq!(payload["repo"], "verdictan/verdictan");
    assert_eq!(payload["branch"], "feature/graph");
    assert_eq!(payload["team_id"], "team-1");
    assert!(
        payload["nodes"]
            .as_array()
            .is_some_and(|nodes| !nodes.is_empty()),
        "schema-bearing tool result should produce graph nodes"
    );
    assert_eq!(payload["nodes"][0]["source_type"], "database");

    handle.abort();
}
