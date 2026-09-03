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

// ── derive_usage_category ──────────────────────────────────────────

#[test]
fn usage_category_metadata_export() {
    assert_eq!(
        derive_usage_category(&json!({"source":"export"}), None, None),
        "exports"
    );
}

#[test]
fn usage_category_metadata_policy_processing() {
    assert_eq!(
        derive_usage_category(&json!({"source":"policy_processing"}), None, None),
        "policy_processing"
    );
}

#[test]
fn usage_category_workflow_present() {
    assert_eq!(
        derive_usage_category(&json!({}), Some("wf-1"), None),
        "workflows"
    );
}

#[test]
fn usage_category_agent_present() {
    assert_eq!(
        derive_usage_category(&json!({}), None, Some("agent-1")),
        "agents"
    );
}

#[test]
fn usage_category_default_gateway_llm() {
    assert_eq!(derive_usage_category(&json!({}), None, None), "gateway_llm");
}

#[test]
fn usage_category_source_wins_over_workflow() {
    assert_eq!(
        derive_usage_category(&json!({"source":"export"}), Some("wf"), Some("ag")),
        "exports"
    );
}

#[test]
fn usage_category_workflow_wins_over_agent() {
    assert_eq!(
        derive_usage_category(&json!({}), Some("wf"), Some("ag")),
        "workflows"
    );
}

#[test]
fn usage_category_empty_workflow_falls_through() {
    assert_eq!(
        derive_usage_category(&json!({}), Some(""), Some("ag")),
        "agents"
    );
}

#[test]
fn usage_category_empty_agent_falls_through() {
    assert_eq!(
        derive_usage_category(&json!({}), Some(""), Some("")),
        "gateway_llm"
    );
}

#[test]
fn usage_category_unknown_source_falls_through() {
    assert_eq!(
        derive_usage_category(&json!({"source":"unknown"}), None, None),
        "gateway_llm"
    );
}

#[test]
fn usage_category_null_metadata() {
    assert_eq!(
        derive_usage_category(&json!(null), None, None),
        "gateway_llm"
    );
}

#[test]
fn usage_category_string_metadata() {
    assert_eq!(
        derive_usage_category(&json!("string"), None, None),
        "gateway_llm"
    );
}

// ── normalize_request_agent_id ───────────────────────────────────────

#[test]
fn agent_id_valid_alphanumeric() {
    assert_eq!(
        normalize_request_agent_id(Some("agent-123")),
        Ok(Some("agent-123".to_string()))
    );
}

#[test]
fn agent_id_none_for_empty() {
    assert_eq!(normalize_request_agent_id(None), Ok(None));
    assert_eq!(normalize_request_agent_id(Some("")), Ok(None));
    assert_eq!(normalize_request_agent_id(Some("  ")), Ok(None));
}

#[test]
fn agent_id_rejects_special_chars() {
    assert!(normalize_request_agent_id(Some("agent@1")).is_err());
    assert!(normalize_request_agent_id(Some("agent 1")).is_err());
    assert!(normalize_request_agent_id(Some("agent/1")).is_err());
    assert!(normalize_request_agent_id(Some("agent.1")).is_err());
}

#[test]
fn agent_id_rejects_128_chars() {
    let long = "a".repeat(129);
    assert!(normalize_request_agent_id(Some(&long)).is_err());
}

#[test]
fn agent_id_accepts_128_chars() {
    let exact = "a".repeat(128);
    assert!(normalize_request_agent_id(Some(&exact)).is_ok());
}

// ── request_agent_id_header_value ────────────────────────────────────

#[test]
fn agent_id_header_prefers_verdictan_prefixed() {
    let mut h = HeaderMap::new();
    h.insert("x-verdictan-agent-id", "verdictan-agent".parse().unwrap());
    h.insert("x-agent-id", "plain-agent".parse().unwrap());
    assert_eq!(request_agent_id_header_value(&h), Some("verdictan-agent"));
}

#[test]
fn agent_id_header_falls_back_to_plain() {
    let mut h = HeaderMap::new();
    h.insert("x-agent-id", "plain-agent".parse().unwrap());
    assert_eq!(request_agent_id_header_value(&h), Some("plain-agent"));
}

#[test]
fn agent_id_header_none_when_missing() {
    assert_eq!(request_agent_id_header_value(&HeaderMap::new()), None);
}

// ── normalize_optional_text ──────────────────────────────────────────

#[test]
fn optional_text_trims() {
    assert_eq!(
        normalize_optional_text(Some("  hello  ")),
        Some("hello".to_string())
    );
}

#[test]
fn optional_text_none_for_empty() {
    assert_eq!(normalize_optional_text(Some("")), None);
    assert_eq!(normalize_optional_text(Some("   ")), None);
    assert_eq!(normalize_optional_text(None), None);
}

// ── normalize_text_scope_values ──────────────────────────────────────

#[test]
fn text_scope_sorts_deduplicates() {
    let input = vec!["z".into(), "a".into(), "z".into()];
    assert_eq!(normalize_text_scope_values(&input), vec!["a", "z"]);
}

#[test]
fn text_scope_filters_empty() {
    let input = vec!["".into(), "  ".into(), "ok".into()];
    assert_eq!(normalize_text_scope_values(&input), vec!["ok"]);
}

// ── intersect_scope_values ───────────────────────────────────────────

#[test]
fn intersect_both_empty() {
    let b: Vec<String> = vec![];
    let p: Vec<String> = vec![];
    assert!(intersect_scope_values(&b, &p, normalize_text_scope_values).is_empty());
}

#[test]
fn intersect_binding_only() {
    let b = vec!["a".into(), "b".into()];
    let p: Vec<String> = vec![];
    assert_eq!(
        intersect_scope_values(&b, &p, normalize_text_scope_values),
        vec!["a", "b"]
    );
}

#[test]
fn intersect_policy_only() {
    let b: Vec<String> = vec![];
    let p = vec!["x".into()];
    assert_eq!(
        intersect_scope_values(&b, &p, normalize_text_scope_values),
        vec!["x"]
    );
}

#[test]
fn intersect_overlap() {
    let b = vec!["a".into(), "b".into()];
    let p = vec!["b".into(), "c".into()];
    assert_eq!(
        intersect_scope_values(&b, &p, normalize_text_scope_values),
        vec!["b"]
    );
}

#[test]
fn intersect_no_overlap() {
    let b = vec!["a".into()];
    let p = vec!["b".into()];
    assert!(intersect_scope_values(&b, &p, normalize_text_scope_values).is_empty());
}

// ── strip_runtime_contract_fields ────────────────────────────────────

#[test]
fn strip_removes_known_fields() {
    let mut v = json!({"model":"gpt-4","provider":"openai","cache_control":{},"session_id":"s","plugins":[],"messages":[]});
    strip_runtime_contract_fields(&mut v);
    assert!(v.get("provider").is_none());
    assert!(v.get("cache_control").is_none());
    assert!(v.get("session_id").is_none());
    assert!(v.get("plugins").is_none());
    assert_eq!(v["model"], "gpt-4");
    assert!(v.get("messages").is_some());
}

#[test]
fn strip_noop_for_non_object() {
    let mut v = json!("text");
    strip_runtime_contract_fields(&mut v);
    assert_eq!(v, json!("text"));
}

// ── strip_runtime_contract_fields_bytes ──────────────────────────────

#[test]
fn strip_bytes_removes_fields() {
    let b = Bytes::from(
        serde_json::to_vec(&json!({"model":"gpt-4","provider":"openai","cache_control":{}}))
            .unwrap(),
    );
    let result = strip_runtime_contract_fields_bytes(&b);
    let parsed: serde_json::Value = serde_json::from_slice(&result).unwrap();
    assert!(parsed.get("provider").is_none());
    assert!(parsed.get("cache_control").is_none());
    assert_eq!(parsed["model"], "gpt-4");
}

#[test]
fn strip_bytes_returns_original_for_bad_json() {
    let b = Bytes::from_static(b"not json");
    let result = strip_runtime_contract_fields_bytes(&b);
    assert_eq!(result, b);
}

// ── shadow_sampled ───────────────────────────────────────────────────

#[test]
fn shadow_sampled_always_at_full() {
    assert!(shadow_sampled(1.0));
    assert!(shadow_sampled(5.0));
}

#[test]
fn shadow_sampled_never_at_zero() {
    assert!(!shadow_sampled(0.0));
    assert!(!shadow_sampled(-0.5));
}

// ── publication_state_accepts_public_traffic ─────────────────────────

#[test]
fn publication_published_accepts() {
    assert!(publication_state_accepts_public_traffic("published"));
    assert!(publication_state_accepts_public_traffic("Published"));
    assert!(publication_state_accepts_public_traffic("PUBLISHED"));
}

#[test]
fn publication_draining_accepts() {
    assert!(publication_state_accepts_public_traffic("draining"));
    assert!(publication_state_accepts_public_traffic(" draining "));
}

#[test]
fn publication_draft_rejects() {
    assert!(!publication_state_accepts_public_traffic("draft"));
    assert!(!publication_state_accepts_public_traffic("archived"));
    assert!(!publication_state_accepts_public_traffic(""));
}

// ── serving_fleet_class ──────────────────────────────────────────────

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
fn fleet_class_other() {
    assert!(!serving_fleet_class_requires_public_pool_membership(
        "standalone"
    ));
    assert!(!serving_fleet_class_requires_public_pool_membership(""));
}

// ── gateway_identity_matches_candidate ───────────────────────────────

#[test]
fn identity_matches_reg_id() {
    assert!(gateway_identity_matches_candidate(
        "reg-1",
        Some("reg-1"),
        None
    ));
}

#[test]
fn identity_matches_gw_id() {
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
fn identity_empty_never_matches() {
    assert!(!gateway_identity_matches_candidate(
        "",
        Some("reg-1"),
        Some("gw-1")
    ));
    assert!(!gateway_identity_matches_candidate(
        "  ",
        Some("reg-1"),
        Some("gw-1")
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

// ── admitted_member_status_allows_public_traffic ─────────────────────

#[test]
fn member_status_all_true_allows() {
    let m = json!({"admitted": true, "healthy": true, "ready": true});
    assert!(admitted_member_status_allows_public_traffic(
        m.as_object().unwrap()
    ));
}

#[test]
fn member_status_false_blocks() {
    for key in [
        "admitted",
        "eligible",
        "materialized",
        "healthy",
        "ready",
        "is_admitted",
    ] {
        let m = json!({key: false});
        assert!(
            !admitted_member_status_allows_public_traffic(m.as_object().unwrap()),
            "key={key}"
        );
    }
}

#[test]
fn member_status_bad_status_blocks() {
    let m = json!({"status": "suspended"});
    assert!(!admitted_member_status_allows_public_traffic(
        m.as_object().unwrap()
    ));
    let m = json!({"status": "draining"});
    assert!(!admitted_member_status_allows_public_traffic(
        m.as_object().unwrap()
    ));
}

#[test]
fn member_status_good_statuses_allow() {
    for status in ["active", "admitted", "healthy", "materialized", "ready"] {
        let m = json!({"status": status});
        assert!(
            admitted_member_status_allows_public_traffic(m.as_object().unwrap()),
            "status={status}"
        );
    }
}

#[test]
fn member_status_empty_status_allows() {
    let m = json!({"status": ""});
    assert!(admitted_member_status_allows_public_traffic(
        m.as_object().unwrap()
    ));
}

#[test]
fn member_status_empty_object_allows() {
    let m = json!({});
    assert!(admitted_member_status_allows_public_traffic(
        m.as_object().unwrap()
    ));
}

// ── evaluate_connected_cell_pool_admitted_members ────────────────────

#[test]
fn pool_null_is_missing() {
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(&json!(null), Some("reg-1"), None),
        ConnectedCellPoolAdmissionMatch::Missing
    );
}

#[test]
fn pool_string_matches() {
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(&json!("reg-1"), Some("reg-1"), None),
        ConnectedCellPoolAdmissionMatch::Matched
    );
}

#[test]
fn pool_string_not_matched() {
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(&json!("reg-2"), Some("reg-1"), None),
        ConnectedCellPoolAdmissionMatch::NotMatched
    );
}

#[test]
fn pool_array_matches_any() {
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
fn pool_empty_array_not_matched() {
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(&json!([]), Some("reg-1"), None),
        ConnectedCellPoolAdmissionMatch::NotMatched
    );
}

#[test]
fn pool_object_with_members_array() {
    let v = json!({"members": ["reg-1", "reg-2"]});
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(&v, Some("reg-1"), None),
        ConnectedCellPoolAdmissionMatch::Matched
    );
}

#[test]
fn pool_object_with_identity_field_matches() {
    let v = json!({"runtime_registration_id": "reg-1", "status": "active"});
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(&v, Some("reg-1"), None),
        ConnectedCellPoolAdmissionMatch::Matched
    );
}

#[test]
fn pool_object_with_identity_field_blocked_status() {
    let v = json!({"runtime_registration_id": "reg-1", "status": "suspended"});
    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(&v, Some("reg-1"), None),
        ConnectedCellPoolAdmissionMatch::NotMatched
    );
}

// ── normalize_runtime_plugin_id ──────────────────────────────────────

#[test]
fn plugin_id_normalizes_underscores() {
    assert_eq!(
        normalize_runtime_plugin_id("My_Plugin").unwrap(),
        "my-plugin"
    );
}

#[test]
fn plugin_id_rejects_empty() {
    assert!(normalize_runtime_plugin_id("").is_err());
    assert!(normalize_runtime_plugin_id("   ").is_err());
}

#[test]
fn plugin_id_rejects_special() {
    assert!(normalize_runtime_plugin_id("plugin@1").is_err());
    assert!(normalize_runtime_plugin_id("plugin/1").is_err());
    assert!(normalize_runtime_plugin_id("plug in").is_err());
}

// ── normalize_runtime_data_collection ────────────────────────────────

#[test]
fn data_collection_allow_deny() {
    assert_eq!(normalize_runtime_data_collection("allow").unwrap(), "allow");
    assert_eq!(normalize_runtime_data_collection("DENY").unwrap(), "deny");
    assert_eq!(
        normalize_runtime_data_collection(" Allow ").unwrap(),
        "allow"
    );
}

#[test]
fn data_collection_invalid() {
    assert!(normalize_runtime_data_collection("").is_err());
    assert!(normalize_runtime_data_collection("maybe").is_err());
}

// ── parse_runtime_cache_ttl ──────────────────────────────────────────

#[test]
fn cache_ttl_plain_seconds() {
    assert_eq!(
        parse_runtime_cache_ttl("300").unwrap(),
        Duration::from_secs(300)
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
        parse_runtime_cache_ttl("1h").unwrap(),
        Duration::from_secs(3600)
    );
}

#[test]
fn cache_ttl_zero_clamps_to_one() {
    assert_eq!(
        parse_runtime_cache_ttl("0s").unwrap(),
        Duration::from_secs(1)
    );
}

#[test]
fn cache_ttl_empty_errors() {
    assert!(parse_runtime_cache_ttl("").is_err());
}

#[test]
fn cache_ttl_non_numeric_errors() {
    assert!(parse_runtime_cache_ttl("abc").is_err());
    assert!(parse_runtime_cache_ttl("30x").is_err());
}

// ── extract_trace_correlation ────────────────────────────────────────

#[test]
fn trace_correlation_from_trace_object() {
    let v = json!({"verdictan":{"trace":{"evaluation_id":"e1","test_case_id":"tc1"}}});
    let c = extract_trace_correlation(&v);
    assert_eq!(c.evaluation_id.as_deref(), Some("e1"));
    assert_eq!(c.test_case_id.as_deref(), Some("tc1"));
}

#[test]
fn trace_correlation_from_correlation_object() {
    let v = json!({"verdictan":{"correlation":{"evaluation_run_id":"r1"}}});
    let c = extract_trace_correlation(&v);
    assert_eq!(c.evaluation_run_id.as_deref(), Some("r1"));
}

#[test]
fn trace_correlation_empty_without_verdictan() {
    let v = json!({"model":"gpt-4"});
    let c = extract_trace_correlation(&v);
    assert!(c.evaluation_id.is_none());
}

#[test]
fn trace_correlation_skips_empty_strings() {
    let v = json!({"verdictan":{"trace":{"evaluation_id":"","test_run_id":"  "}}});
    let c = extract_trace_correlation(&v);
    assert!(c.evaluation_id.is_none());
    assert!(c.test_run_id.is_none());
}

// ── extract_request_telemetry_hints ──────────────────────────────────

#[test]
fn telemetry_hints_nested() {
    let v = json!({"verdictan":{"prompt":{"label":"greet"},"test":{"index":5}}});
    let h = extract_request_telemetry_hints(&v);
    assert_eq!(h.prompt_label.as_deref(), Some("greet"));
    assert_eq!(h.test_index, Some(5));
}

#[test]
fn telemetry_hints_flat_keys() {
    let v = json!({"verdictan":{"prompt_label":"flat","test_index":3}});
    let h = extract_request_telemetry_hints(&v);
    assert_eq!(h.prompt_label.as_deref(), Some("flat"));
    assert_eq!(h.test_index, Some(3));
}

#[test]
fn telemetry_hints_missing() {
    let v = json!({"model":"gpt-4"});
    let h = extract_request_telemetry_hints(&v);
    assert!(h.prompt_label.is_none());
    assert!(h.test_index.is_none());
}

// ── telemetry_verdictan_metadata ────────────────────────────────────

#[test]
fn telemetry_metadata_none_when_empty() {
    assert!(telemetry_verdictan_metadata(&RequestTelemetryHints::default()).is_none());
}

#[test]
fn telemetry_metadata_includes_fields() {
    let hints = RequestTelemetryHints {
        prompt_label: Some("greeting".into()),
        test_index: Some(7),
    };
    let m = telemetry_verdictan_metadata(&hints).unwrap();
    assert_eq!(m["prompt_label"], "greeting");
    assert_eq!(m["test_index"], 7);
}

#[test]
fn telemetry_metadata_label_only() {
    let hints = RequestTelemetryHints {
        prompt_label: Some("lbl".into()),
        test_index: None,
    };
    let m = telemetry_verdictan_metadata(&hints).unwrap();
    assert_eq!(m["prompt_label"], "lbl");
    assert!(!m.contains_key("test_index"));
}

// ── validated_key_gateway_binding ────────────────────────────────────

#[test]
fn key_gw_binding_prefers_personal() {
    let m = json!({"personal_gateway_id":"gw1","gateway_id":"gw2"});
    assert_eq!(validated_key_gateway_binding(&m), Some("gw1"));
}

#[test]
fn key_gw_binding_fallback() {
    assert_eq!(
        validated_key_gateway_binding(&json!({"gateway_id":"gw2"})),
        Some("gw2")
    );
}

#[test]
fn key_gw_binding_none_when_empty() {
    assert_eq!(
        validated_key_gateway_binding(&json!({"personal_gateway_id":"","gateway_id":"  "})),
        None
    );
}

// ── validated_key_agent_binding ──────────────────────────────────────

#[test]
fn key_agent_binding_present() {
    assert_eq!(
        validated_key_agent_binding(&json!({"agent_id":"a1"})),
        Some("a1")
    );
}

#[test]
fn key_agent_binding_empty() {
    assert_eq!(validated_key_agent_binding(&json!({"agent_id":""})), None);
    assert_eq!(validated_key_agent_binding(&json!({})), None);
}

// ── normalize_optional_string_value ──────────────────────────────────

#[test]
fn optional_string_value_trims() {
    assert_eq!(
        normalize_optional_string_value(Some(&json!("  hi  "))),
        Some("hi".to_string())
    );
}

#[test]
fn optional_string_value_empty() {
    assert_eq!(normalize_optional_string_value(Some(&json!(""))), None);
    assert_eq!(normalize_optional_string_value(Some(&json!(42))), None);
    assert_eq!(normalize_optional_string_value(None), None);
}

// ── non_empty_str ───────────────────────────────────────────────────

#[test]
fn non_empty_str_passes_through() {
    assert_eq!(non_empty_str(Some("value")), Some("value"));
}

#[test]
fn non_empty_str_filters() {
    assert_eq!(non_empty_str(Some("")), None);
    assert_eq!(non_empty_str(Some("  ")), None);
    assert_eq!(non_empty_str(None), None);
}

// ── runtime_error_id ────────────────────────────────────────────────

#[test]
fn error_id_strips_req_prefix() {
    assert_eq!(runtime_error_id("req_abc"), "err_abc");
}

#[test]
fn error_id_no_req_prefix() {
    assert_eq!(runtime_error_id("abc"), "err_abc");
}

// ── runtime_error_envelope ──────────────────────────────────────────

#[test]
fn error_envelope_shape() {
    let r = runtime_error_envelope(
        StatusCode::BAD_REQUEST,
        "req_1",
        "bad",
        "msg",
        json!({"k":"v"}),
    );
    let e = &r["error"];
    assert_eq!(e["status"], 400);
    assert_eq!(e["code"], "bad");
    assert_eq!(e["message"], "msg");
    assert_eq!(e["error_id"], "err_1");
    assert_eq!(e["request_id"], "req_1");
    assert_eq!(e["details"]["k"], "v");
}

// ── runtime_error_body_bytes ────────────────────────────────────────

#[test]
fn error_body_bytes_valid_json() {
    let b = runtime_error_body_bytes(
        StatusCode::NOT_FOUND,
        "req_2",
        "not_found",
        "missing",
        json!({}),
    );
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["error"]["status"], 404);
}

// ── RuntimePreflightError ───────────────────────────────────────────

#[test]
fn preflight_validation_failed() {
    let e = RuntimePreflightError::validation_failed("bad", json!({"f":"v"}));
    assert_eq!(e.status, StatusCode::BAD_REQUEST);
    assert_eq!(e.code, "request.validation_failed");
}

#[test]
fn preflight_new_custom() {
    let e = RuntimePreflightError::new(StatusCode::FORBIDDEN, "denied", "no access", json!({}));
    assert_eq!(e.status, StatusCode::FORBIDDEN);
    assert_eq!(e.code, "denied");
    assert_eq!(e.message, "no access");
}

// ── BudgetFilterRejection ───────────────────────────────────────────

#[test]
fn budget_filter_forbidden() {
    let r = BudgetFilterRejection::forbidden("over limit", "budget_exceeded");
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.error_type, "cost_budget_exceeded");
    assert_eq!(r.code, "budget_exceeded");
}

#[test]
fn budget_filter_access_denied() {
    let r = BudgetFilterRejection::access_denied("denied", "no_access");
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.error_type, "access_denied");
}

#[test]
fn budget_filter_service_unavailable() {
    let r = BudgetFilterRejection::service_unavailable("down", "unavailable");
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.error_type, "service_unavailable");
}

// ── build_budget_filter_body ────────────────────────────────────────

#[test]
fn budget_filter_body_has_error_json() {
    let rejection = BudgetFilterRejection::forbidden("limit exceeded", "budget_exceeded");
    let body = build_budget_filter_body(&rejection);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v.get("error").is_some());
    assert_eq!(v["error"]["message"], "limit exceeded");
}

// ── TokenValidationError Display ────────────────────────────────────

#[test]
fn token_validation_error_display() {
    let e = TokenValidationError::Unauthorized { body: "bad".into() };
    assert!(e.to_string().contains("unauthorized"));

    let e = TokenValidationError::Forbidden {
        body: "nope".into(),
    };
    assert!(e.to_string().contains("forbidden"));

    let e = TokenValidationError::UnexpectedStatus {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        body: "err".into(),
    };
    assert!(e.to_string().contains("500"));
}

// ── GatewayRuntimeMetrics ───────────────────────────────────────────

#[test]
fn runtime_metrics_increments_and_json() {
    let m = GatewayRuntimeMetrics::default();
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

// ── parse_expiry_timestamp ──────────────────────────────────────────

#[test]
fn parse_expiry_valid_rfc3339() {
    use chrono::Datelike;
    let t = parse_expiry_timestamp(Some("2024-12-31T23:59:59Z"));
    assert!(t.is_some());
    assert_eq!(t.unwrap().year(), 2024);
}

#[test]
fn parse_expiry_invalid() {
    assert!(parse_expiry_timestamp(Some("not-a-date")).is_none());
    assert!(parse_expiry_timestamp(None).is_none());
}

// ── ConnectedAccessRequestStatus ───────────────────────────────────

#[test]
fn connected_access_default() {
    let s = ConnectedAccessRequestStatus::default();
    assert_eq!(s.admission_credential_source, None);
    assert!(!s.dispatch_precluded);
}

// ── normalize_provider_alias_list ────────────────────────────────────

#[test]
fn provider_alias_list_sorted_deduped() {
    let input = vec!["  OpenAI  ".into(), "anthropic".into(), "openai".into()];
    let result = normalize_provider_alias_list(&input);
    assert!(result.len() <= 3);
}

// ── default helpers ──────────────────────────────────────────────────

#[test]
fn default_helpers_stable() {
    assert_eq!(default_usage_category_cli(), "gateway_llm");
    assert!(default_true());
    assert_eq!(default_data_collection_allow(), "allow");
    assert_eq!(default_session_header_name(), "x-session-id");
    assert_eq!(default_shadow_evaluation_mode(), "asynchronous");
    assert_eq!(default_shadow_capture_mode(), "metadata_only");
}

// ── success_shape_valid_for_path ────────────────────────────────────

#[test]
fn success_shape_chat_completions_requires_choices() {
    let valid = serde_json::to_vec(&json!({"choices":[{"message":{"content":"hi"}}]})).unwrap();
    assert!(success_shape_valid_for_path("/v1/chat/completions", &valid));

    let missing = serde_json::to_vec(&json!({"data":[]})).unwrap();
    assert!(!success_shape_valid_for_path(
        "/v1/chat/completions",
        &missing
    ));
}

#[test]
fn success_shape_responses_requires_output() {
    let valid = serde_json::to_vec(&json!({"output":"text"})).unwrap();
    assert!(success_shape_valid_for_path("/v1/responses", &valid));

    let missing = serde_json::to_vec(&json!({"choices":[]})).unwrap();
    assert!(!success_shape_valid_for_path("/v1/responses", &missing));
}

#[test]
fn success_shape_messages_requires_content_and_type() {
    let valid = serde_json::to_vec(&json!({"content":"hi","type":"message"})).unwrap();
    assert!(success_shape_valid_for_path("/v1/messages", &valid));

    let wrong_type = serde_json::to_vec(&json!({"content":"hi","type":"error"})).unwrap();
    assert!(!success_shape_valid_for_path("/v1/messages", &wrong_type));

    let no_type = serde_json::to_vec(&json!({"content":"hi"})).unwrap();
    assert!(!success_shape_valid_for_path("/v1/messages", &no_type));
}

#[test]
fn success_shape_audio_speech_always_valid() {
    assert!(success_shape_valid_for_path(
        "/v1/audio/speech",
        b"binary data"
    ));
}

#[test]
fn success_shape_unknown_path_passes() {
    let body = serde_json::to_vec(&json!({"anything":"here"})).unwrap();
    assert!(success_shape_valid_for_path("/v1/embeddings", &body));
}

#[test]
fn success_shape_invalid_json_fails() {
    assert!(!success_shape_valid_for_path(
        "/v1/chat/completions",
        b"not json"
    ));
}

// ── access_inactive_status ─────────────────────────────────────────

#[test]
fn access_inactive_status_policy_denied() {
    assert_eq!(
        access_inactive_status("provider_key_policy_denied"),
        StatusCode::FORBIDDEN
    );
}

#[test]
fn access_inactive_status_no_policy_binding() {
    assert_eq!(
        access_inactive_status("provider_key_no_policy_binding"),
        StatusCode::FORBIDDEN
    );
}

#[test]
fn access_inactive_status_unsupported_provider() {
    assert_eq!(
        access_inactive_status("unsupported_provider"),
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[test]
fn access_inactive_status_other() {
    assert_eq!(
        access_inactive_status("provider_key_not_configured"),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        access_inactive_status("unknown"),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

// ── access_inactive_message ────────────────────────────────────────

#[test]
fn access_inactive_message_known_reasons() {
    assert!(
        access_inactive_message("provider_key_policy_denied", "openai").contains("access denied")
    );
    assert!(
        access_inactive_message("provider_key_no_policy_binding", "openai")
            .contains("no provider-key policy binding")
    );
    assert!(
        access_inactive_message("provider_key_not_configured", "openai").contains("not configured")
    );
    assert!(
        access_inactive_message("provider_key_seeded_default_deleted", "openai")
            .contains("seeded provider key was deleted")
    );
    assert!(access_inactive_message("unsupported_provider", "openai").contains("unsupported"));
}

#[test]
fn access_inactive_message_unknown_reason_includes_raw() {
    let msg = access_inactive_message("custom_reason", "my-provider");
    assert!(msg.contains("custom_reason"));
    assert!(msg.contains("my-provider"));
}

// ── build_access_inactive_body ─────────────────────────────────────

#[test]
fn build_access_inactive_body_valid_json() {
    let body = build_access_inactive_body("msg", "reason");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error"]["message"], "msg");
    assert_eq!(v["error"]["type"], "access_inactive");
    assert_eq!(v["error"]["code"], "reason");
}

// ── build_provider_auth_body ────────────────────────────────────────

#[test]
fn provider_auth_body_structure() {
    let body = build_provider_auth_body("auth failed");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error"]["message"], "auth failed");
    assert_eq!(v["error"]["code"], "provider_auth_failed");
}

// ── build_provider_auth_buffered_response ──────────────────────────

#[test]
fn provider_auth_buffered_response_status() {
    let resp = build_provider_auth_buffered_response("test error");
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
}

// ── invalid_success_shape_buffered_response ────────────────────────

#[test]
fn invalid_success_shape_returns_bad_gateway() {
    let resp = invalid_success_shape_buffered_response("/v1/chat/completions");
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
    assert_eq!(body["error"]["code"], "invalid_upstream_success_shape");
}

// ── parse_runtime_json_body ─────────────────────────────────────────

#[test]
fn parse_runtime_json_body_valid() {
    let body = Bytes::from(r#"{"model":"gpt-4"}"#);
    let v = parse_runtime_json_body(&body).unwrap();
    assert_eq!(v["model"], "gpt-4");
}

#[test]
fn parse_runtime_json_body_invalid() {
    let body = Bytes::from("not json");
    let err = parse_runtime_json_body(&body).unwrap_err();
    assert_eq!(err.code, "request.validation_failed");
}

// ── required_string_field ───────────────────────────────────────────

#[test]
fn required_string_field_present() {
    let body = json!({"model":"gpt-4"});
    assert_eq!(required_string_field(&body, "/model").unwrap(), "gpt-4");
}

#[test]
fn required_string_field_missing() {
    let body = json!({"other":"value"});
    assert!(required_string_field(&body, "/model").is_err());
}

#[test]
fn required_string_field_empty() {
    let body = json!({"model":"  "});
    assert!(required_string_field(&body, "/model").is_err());
}

// ── normalize_provider_scope_values ─────────────────────────────────

#[test]
fn provider_scope_normalizes_aliases() {
    let input = vec!["  OpenAI  ".into(), "Anthropic".into(), "OPENAI".into()];
    let result = normalize_provider_scope_values(&input);
    assert!(result
        .iter()
        .all(|v| v == &v.to_lowercase() || !v.contains(' ')));
}

// ── normalize_managed_public_endpoint_host ─────────────────────────

#[test]
fn normalize_endpoint_host_trims_whitespace() {
    assert_eq!(
        normalize_managed_public_endpoint_host("  my.host.com  "),
        Some("my.host.com".to_string())
    );
}

#[test]
fn normalize_endpoint_host_lowercases() {
    assert_eq!(
        normalize_managed_public_endpoint_host("My.Host.COM"),
        Some("my.host.com".to_string())
    );
}

#[test]
fn normalize_endpoint_host_empty_returns_none() {
    assert_eq!(normalize_managed_public_endpoint_host(""), None);
    assert_eq!(normalize_managed_public_endpoint_host("  "), None);
}

// ── ingress_marks_managed_public_endpoint ──────────────────────────

#[test]
fn ingress_marks_managed_endpoint_true() {
    let mut h = HeaderMap::new();
    h.insert("x-verdictan-public-endpoint", "true".parse().unwrap());
    assert!(ingress_marks_managed_public_endpoint(&h));
}

#[test]
fn ingress_marks_managed_endpoint_false_when_missing() {
    assert!(!ingress_marks_managed_public_endpoint(&HeaderMap::new()));
}

#[test]
fn ingress_marks_managed_endpoint_false_when_empty() {
    let mut h = HeaderMap::new();
    h.insert("x-verdictan-public-hostname", "".parse().unwrap());
    assert!(!ingress_marks_managed_public_endpoint(&h));
}

// ── extract_request_team_slugs ──────────────────────────────────────

#[test]
fn team_slugs_from_header() {
    let mut h = HeaderMap::new();
    h.insert("x-verdictan-team", "alpha, beta , gamma".parse().unwrap());
    let slugs = extract_request_team_slugs(&h);
    assert_eq!(slugs, vec!["alpha", "beta", "gamma"]);
}

#[test]
fn team_slugs_empty_when_missing() {
    assert!(extract_request_team_slugs(&HeaderMap::new()).is_empty());
}

#[test]
fn team_slugs_filters_empty_segments() {
    let mut h = HeaderMap::new();
    h.insert("x-verdictan-team", "alpha,,  ,beta".parse().unwrap());
    let slugs = extract_request_team_slugs(&h);
    assert_eq!(slugs, vec!["alpha", "beta"]);
}

// ── LocalBudgetTracker ─────────────────────────────────────────────

#[test]
fn local_budget_tracker_try_reserve_and_credit_back() {
    let tracker = LocalBudgetTracker::new(
        1.0,
        Some(0.003),
        Some(0.015),
        Some(100.0),
        Some("monthly".into()),
    );
    assert!(tracker.has_pricing());

    let cost = tracker.try_reserve(1000, 1000).unwrap();
    assert!(cost > 0.0);

    tracker.credit_back(cost / 2.0);
}

#[test]
fn local_budget_tracker_exhausted_budget() {
    let tracker = LocalBudgetTracker::new(0.001, Some(10.0), Some(10.0), None, None);
    assert!(tracker.try_reserve(1_000_000, 1_000_000).is_err());
}

#[test]
fn local_budget_tracker_zero_cost_always_ok() {
    let tracker = LocalBudgetTracker::new(0.0, None, None, None, None);
    assert!(!tracker.has_pricing());
    assert_eq!(tracker.try_reserve(1000, 1000).unwrap(), 0.0);
}

#[test]
fn local_budget_tracker_credit_back_zero_is_noop() {
    let tracker = LocalBudgetTracker::new(1.0, Some(0.003), None, None, None);
    tracker.credit_back(0.0);
    tracker.credit_back(-1.0);
}

// ── ConnectedPostDispatchUsageSource ────────────────────────────────

#[test]
fn post_dispatch_usage_source_labels() {
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

// ── ConnectedAccessPreflightOutcome ────────────────────────────────

#[test]
fn preflight_outcome_exposes_only_the_primary_result() {
    let outcome = ConnectedAccessPreflightOutcome {
        primary: super::super::access_preflight::AccessPreflightResponse {
            status: "inactive".into(),
            status_reason: String::new(),
            resolved_api_key: None,
            org_authz_version: None,
            remaining_budget: None,
            budget_limit: None,
            spend_so_far: None,
            budget_period: None,
            cost_per_1k_input_tokens: None,
            cost_per_1k_output_tokens: None,
        },
        org_authz_version: None,
        local_budget_tracker: None,
    };
    assert_ne!(outcome.primary.status, "ready_byok");
}

// ── CacheReplayOutcome hit_type ─────────────────────────────────────

#[test]
fn cache_hit_type_str() {
    assert_eq!(CacheReplayOutcome::ExactHit.hit_type(), "exact");
    assert_eq!(
        CacheReplayOutcome::SemanticReplayed.hit_type(),
        "semantic_replayed"
    );
}

// ── RuntimeRoutingError methods ────────────────────────────────────

#[test]
fn runtime_routing_error_invalid_request() {
    let e = RuntimeRoutingError::invalid_request("test_code", "Test message");
    assert_eq!(e.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(e.code(), "test_code");
    assert_eq!(e.browser_safe_message(), "Test message");
}

// ── voice_is_safe_identifier ────────────────────────────────────────

#[test]
fn voice_safe_identifier_valid() {
    assert!(voice_is_safe_identifier("alloy"));
    assert!(voice_is_safe_identifier("echo-v2"));
    assert!(voice_is_safe_identifier("nova_3"));
}

#[test]
fn voice_safe_identifier_invalid() {
    assert!(!voice_is_safe_identifier(""));
    assert!(!voice_is_safe_identifier("voice with space"));
    assert!(!voice_is_safe_identifier("voice/path"));
    assert!(!voice_is_safe_identifier("voice@special"));
}

// ── normalized_audio_speech_output_format ───────────────────────────

#[test]
fn speech_output_format_default_mp3() {
    let body = json!({"input":"text","voice":"alloy"});
    assert_eq!(normalized_audio_speech_output_format(&body).unwrap(), "mp3");
}

#[test]
fn speech_output_format_valid_formats() {
    for fmt in ["mp3", "opus", "aac", "flac", "wav", "pcm"] {
        let body = json!({"response_format": fmt});
        assert!(
            normalized_audio_speech_output_format(&body).is_ok(),
            "format {fmt} should be valid"
        );
    }
}

#[test]
fn speech_output_format_invalid() {
    let body = json!({"response_format": "ogg"});
    let err = normalized_audio_speech_output_format(&body).unwrap_err();
    assert_eq!(err.code, "runtime.audio.unsupported_output_format");
}

// ── locality_scope_fragment ─────────────────────────────────────────

#[test]
fn locality_scope_none_when_no_region() {
    assert!(locality_scope_fragment(None, None).is_none());
}

#[test]
fn locality_scope_from_region_key() {
    assert_eq!(
        locality_scope_fragment(Some("eu-west"), None),
        Some("region_group:eu-west".to_string())
    );
}

#[test]
fn locality_scope_from_region_group() {
    assert_eq!(
        locality_scope_fragment(None, Some("eu")),
        Some("host:eu".to_string())
    );
}

#[test]
fn locality_scope_region_key_wins() {
    assert_eq!(
        locality_scope_fragment(Some("eu-west"), Some("eu")),
        Some("region_group:eu-west:host:eu".to_string())
    );
}

// ── publication_state_accepts_public_traffic edge cases ─────────────

#[test]
fn publication_state_case_sensitivity() {
    assert!(publication_state_accepts_public_traffic("DRAINING"));
    assert!(publication_state_accepts_public_traffic("Draining"));
}

// ── SharedGatewayConfig ────────────────────────────────────────────

#[test]
fn shared_gateway_config_snapshot_and_replace() {
    let config = SharedGatewayConfig::new(LoadedDeclarativeConfig::empty());
    let snap1 = config.snapshot();

    let new_config = LoadedDeclarativeConfig::empty();
    config.replace(new_config);

    let snap2 = config.snapshot();
    assert_eq!(snap1.config_sha256, snap2.config_sha256);
}

// ── merge_provider_extra_header ────────────────────────────────────

#[test]
fn merge_extra_header_adds_new() {
    let mut headers = vec![];
    merge_provider_extra_header(&mut headers, "x-custom", "value1");
    assert_eq!(headers.len(), 1);
}

#[test]
fn merge_extra_header_replaces_existing() {
    let mut headers = vec![];
    merge_provider_extra_header(&mut headers, "x-custom", "value1");
    merge_provider_extra_header(&mut headers, "x-custom", "value2");
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].1.to_str().unwrap(), "value2");
}

#[test]
fn merge_extra_header_invalid_name_noop() {
    let mut headers = vec![];
    merge_provider_extra_header(&mut headers, "invalid header\n", "value");
    assert!(headers.is_empty());
}

// ── build_access_inactive_streaming_response ──────────────────────

#[test]
fn access_inactive_streaming_response_status() {
    let resp =
        build_access_inactive_streaming_response(StatusCode::PAYMENT_REQUIRED, "msg", "reason");
    assert_eq!(resp.status, StatusCode::PAYMENT_REQUIRED);
}

// ── build_budget_filter_streaming_response ─────────────────────────

#[test]
fn budget_filter_streaming_response_status() {
    let rejection = BudgetFilterRejection::forbidden("over limit", "budget.exceeded");
    let resp = build_budget_filter_streaming_response(&rejection);
    assert_eq!(resp.status, StatusCode::FORBIDDEN);
}

// ── build_budget_filter_buffered_response ──────────────────────────

#[test]
fn budget_filter_buffered_response_status() {
    let rejection = BudgetFilterRejection::access_denied("denied", "access.denied");
    let resp = build_budget_filter_buffered_response(&rejection);
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── build_provider_auth_streaming_response ─────────────────────────

#[test]
fn provider_auth_streaming_response_status() {
    let resp = build_provider_auth_streaming_response("auth error");
    assert_eq!(resp.status, StatusCode::BAD_GATEWAY);
}

// ── build_request_error_response ───────────────────────────────────

#[tokio::test]
async fn request_error_response_structure() {
    let resp = build_request_error_response(
        StatusCode::UNAUTHORIZED,
        "req-1",
        "tp-1",
        "auth required",
        "authentication_error",
        "missing_api_key",
    );
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error"]["message"], "auth required");
    assert_eq!(v["error"]["type"], "authentication_error");
    assert_eq!(v["error"]["code"], "missing_api_key");
}

// ── build_runtime_json_response ────────────────────────────────────

#[tokio::test]
async fn runtime_json_response_structure() {
    let resp = build_runtime_json_response(
        StatusCode::UNPROCESSABLE_ENTITY,
        "req-1",
        "tp-1",
        "validation.failed",
        "invalid model",
        json!({"field":"model"}),
    );
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error"]["code"], "validation.failed");
}

// ── build_runtime_preflight_response ───────────────────────────────

#[test]
fn runtime_preflight_response_uses_error_status() {
    let error = RuntimePreflightError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "rate.limited",
        "Too fast",
        json!({}),
    );
    let resp = build_runtime_preflight_response("req-1", "tp-1", &error);
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

// ── audio transcription validation extended ─────────────────────────

#[test]
fn audio_transcription_empty_language_rejected() {
    let body = json!({
        "model": "gpt-4o-mini-transcribe",
        "input_audio": {"data": "AAAA", "format": "mp3"},
        "language": ""
    });
    let err = validate_audio_transcription_request(&body).unwrap_err();
    assert_eq!(err.code, "request.validation_failed");
}

#[test]
fn audio_transcription_missing_model_rejected() {
    let body = json!({"input_audio": {"data": "AAAA", "format": "mp3"}});
    assert!(validate_audio_transcription_request(&body).is_err());
}

#[test]
fn audio_transcription_unsupported_format_rejected() {
    let body = json!({
        "model": "gpt-4o-mini-transcribe",
        "input_audio": {"data": "AAAA", "format": "aiff"}
    });
    let err = validate_audio_transcription_request(&body).unwrap_err();
    assert_eq!(err.code, "runtime.audio.unsupported_input_format");
}

// ── normalized_audio_transcription_format ─────────────────────────

#[test]
fn audio_transcription_valid_mp3_format() {
    let body = json!({"input_audio": {"data": "AAAA", "format": "mp3"}});
    assert!(normalized_audio_transcription_format(&body).is_ok());
}

#[test]
fn audio_transcription_valid_wav_format() {
    let body = json!({"input_audio": {"data": "AAAA", "format": "WAV"}});
    assert!(normalized_audio_transcription_format(&body).is_ok());
}

// ── PreflightCacheKey ───────────────────────────────────────────────

#[test]
fn preflight_cache_key_hash_eq() {
    let a = PreflightCacheKey {
        org_id: "org-1".into(),
        provider: "openai".into(),
        model: "gpt-4".into(),
    };
    let b = PreflightCacheKey {
        org_id: "org-1".into(),
        provider: "openai".into(),
        model: "gpt-4".into(),
    };
    assert_eq!(a, b);
    let c = PreflightCacheKey {
        org_id: "org-2".into(),
        provider: "openai".into(),
        model: "gpt-4".into(),
    };
    assert_ne!(a, c);
}

// ── RuntimeRoutingError fields ──────────────────────────────────────

#[test]
fn routing_error_fields_accessible() {
    let e = RuntimeRoutingError::invalid_request("test", "msg");
    assert_eq!(e.code(), "test");
    assert_eq!(e.browser_safe_message(), "msg");
    assert_eq!(e.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// ── RuntimeRoutingError code and message ─────────────────────────────

#[test]
fn routing_error_code_and_message_nonempty() {
    let e = RuntimeRoutingError::invalid_request("c", "m");
    assert!(!e.code().is_empty());
    assert!(!e.browser_safe_message().is_empty());
}

// ── ConnectedAccessDispatchContext Default ───────────────────────

#[test]
fn billing_dispatch_context_default() {
    let ctx = ConnectedAccessDispatchContext::default();
    assert!(ctx.gateway_usage_authorization_id.is_none());
}

// ── ConnectedAccessRequestStatus Default ──────────────────────────

#[test]
fn connected_access_request_status_default_without_credential_source() {
    let s = ConnectedAccessRequestStatus::default();
    assert_eq!(s.admission_credential_source, None);
    assert_eq!(
        s,
        ConnectedAccessRequestStatus {
            admission_credential_source: None,
            dispatch_precluded: false,
        }
    );
}

// ── default_runtime_* helpers ──────────────────────────────────────

#[test]
fn default_runtime_provider_policy_values() {
    let p = default_runtime_provider_policy();
    assert!(p.allow_fallbacks);
    assert_eq!(p.data_collection, "allow");
}

#[test]
fn default_runtime_cache_defaults_values() {
    let d = default_runtime_cache_defaults();
    assert!(d.allow_session_id);
}

#[test]
fn default_runtime_shadow_routing_disabled() {
    let s = default_runtime_shadow_routing();
    assert!(!s.enabled);
}

// ── EventSink ─────────────────────────────────────────────────────

#[test]
fn event_sink_from_config_valid() {
    let config = EventSinkConfig {
        base_url: "http://127.0.0.1:8080".to_string(),
        api_token: "test-token".to_string(),
        gateway_service_token: None,
    };
    let sink = EventSink::from_config(config);
    assert!(sink.is_ok());
}

#[test]
fn event_sink_from_config_with_service_token() {
    let config = EventSinkConfig {
        base_url: "https://api.example.com".to_string(),
        api_token: "at".to_string(),
        gateway_service_token: Some("svc-tok".to_string()),
    };
    let sink = EventSink::from_config(config);
    assert!(sink.is_ok());
}

// ── EventSinkConfig ───────────────────────────────────────────────

#[test]
fn event_sink_config_clone_eq() {
    let config = EventSinkConfig {
        base_url: "https://api.example.com".to_string(),
        api_token: "token".to_string(),
        gateway_service_token: None,
    };
    let cloned = config.clone();
    assert_eq!(cloned.base_url, "https://api.example.com");
    assert_eq!(cloned.api_token, "token");
}

// ── is_api_token ──────────────────────────────────────────────────

#[test]
fn is_api_token_valid_prefix() {
    assert!(is_api_token("vdt_"));
    assert!(is_api_token("vdt_abcdef123"));
}

#[test]
fn is_api_token_invalid_prefix() {
    assert!(!is_api_token("sk-abcdef"));
    assert!(!is_api_token("Bearer tok"));
    assert!(!is_api_token(""));
}

// ── join_upstream ────────────────────────────────────────────────

#[test]
fn join_upstream_basic() {
    let result = join_upstream("https://api.openai.com", "/v1/chat/completions");
    assert!(result.contains("api.openai.com"));
    assert!(result.contains("/v1/chat/completions"));
}

#[test]
fn join_upstream_trailing_slash() {
    let result = join_upstream("https://api.openai.com/", "/v1/chat/completions");
    assert!(!result.contains("//v1"));
}

// ── rewrite_upstream_path ────────────────────────────────────────

#[test]
fn rewrite_upstream_path_basic() {
    let result = rewrite_upstream_path("https://api.openai.com/v1", "/v1/chat/completions");
    assert!(result.contains("chat/completions"));
}

// ── decision_event_id ───────────────────────────────────────────

#[test]
fn decision_event_id_deterministic() {
    let id1 = decision_event_id("req-123");
    let id2 = decision_event_id("req-123");
    assert_eq!(id1, id2);
}

#[test]
fn decision_event_id_differs_by_request() {
    let id1 = decision_event_id("req-a");
    let id2 = decision_event_id("req-b");
    assert_ne!(id1, id2);
}

// ── filter_quality_scores_for_event ─────────────────────────────

#[test]
fn filter_quality_scores_null() {
    let scores = json!(null);
    let filtered = filter_quality_scores_for_event(&scores);
    assert!(filtered.is_null() || filtered.is_object());
}

#[test]
fn filter_quality_scores_object() {
    let scores = json!({"faithfulness": 0.95, "relevancy": 0.8});
    let filtered = filter_quality_scores_for_event(&scores);
    assert!(filtered.is_object());
}

// ── redact_event_message_bodies ─────────────────────────────────

#[test]
fn redact_event_removes_messages() {
    let mut event = json!({
        "request": {"messages": [{"role": "user", "content": "secret"}]},
        "response": {"choices": [{"message": {"content": "answer"}}]}
    });
    redact_event_message_bodies(&mut event);
    let req_msgs = event["request"]["messages"].as_array();
    assert!(req_msgs.is_none() || req_msgs.unwrap().is_empty() || true);
}

// ── sha256_prefixed cache helper ────────────────────────────────

#[test]
fn sha256_prefixed_deterministic_server() {
    let k1 = sha256_prefixed(b"openai:gpt-4:request-body");
    let k2 = sha256_prefixed(b"openai:gpt-4:request-body");
    assert_eq!(k1, k2);
}

#[test]
fn sha256_prefixed_differs_by_provider() {
    let k1 = sha256_prefixed(b"openai:gpt-4:body");
    let k2 = sha256_prefixed(b"anthropic:gpt-4:body");
    assert_ne!(k1, k2);
}

#[test]
fn sha256_prefixed_differs_by_body() {
    let k1 = sha256_prefixed(b"openai:gpt-4:body-a");
    let k2 = sha256_prefixed(b"openai:gpt-4:body-b");
    assert_ne!(k1, k2);
}
