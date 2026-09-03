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
use axum::http::{HeaderMap, HeaderValue};
use serde_json::json;

// ── Helper factories ────────────────────────────────────────────────

fn make_target(id: &str, provider: &str, model: &str) -> super::super::providers::ProviderTarget {
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
        timeout: Duration::from_secs(30),
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

fn make_target_with_models(
    id: &str,
    provider: &str,
    model: &str,
    models: Vec<super::super::providers::ProviderModelEntry>,
) -> super::super::providers::ProviderTarget {
    let mut t = make_target(id, provider, model);
    t.models = models;
    t
}

fn make_model_entry(model_id: &str, enabled: bool) -> super::super::providers::ProviderModelEntry {
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

fn make_model_entry_with_aliases(
    model_id: &str,
    aliases: Vec<&str>,
    enabled: bool,
) -> super::super::providers::ProviderModelEntry {
    let mut entry = make_model_entry(model_id, enabled);
    entry.aliases = aliases.into_iter().map(String::from).collect();
    entry
}

fn make_model_entry_with_features(
    model_id: &str,
    features: Vec<&str>,
    enabled: bool,
) -> super::super::providers::ProviderModelEntry {
    let mut entry = make_model_entry(model_id, enabled);
    entry.supported_features = features.into_iter().map(String::from).collect();
    entry
}

fn make_token_record(id: &str) -> TokenRecord {
    TokenRecord {
        id: id.into(),
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

fn make_token_validation_response() -> TokenValidationResponse {
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

// ═══════════════════════════════════════════════════════════════════
// error_json
// ═══════════════════════════════════════════════════════════════════

#[test]
fn error_json_produces_correct_shape() {
    let result = error_json("test message", "test_type", "test_code");
    assert_eq!(result["message"], "test message");
    assert_eq!(result["type"], "test_type");
    assert_eq!(result["code"], "test_code");
    assert!(result["param"].is_null());
}

// ═══════════════════════════════════════════════════════════════════
// format_upstream_unreachable_message
// ═══════════════════════════════════════════════════════════════════

#[test]
fn format_unreachable_message_includes_provider_and_url() {
    let msg = format_upstream_unreachable_message(
        "openai",
        "https://api.openai.com/v1",
        &"connection refused",
    );
    assert!(msg.contains("openai"));
    assert!(msg.contains("https://api.openai.com/v1"));
    assert!(msg.contains("connection refused"));
    assert!(msg.contains("status"));
}

// ═══════════════════════════════════════════════════════════════════
// ratelimit_headers
// ═══════════════════════════════════════════════════════════════════

#[test]
fn ratelimit_headers_basic() {
    let hdrs = ratelimit_headers(100, 50, 30, None, None);
    assert_eq!(hdrs.len(), 3);
    assert_eq!(hdrs[0], ("x-ratelimit-limit-requests", "100".into()));
    assert_eq!(hdrs[1], ("x-ratelimit-remaining-requests", "50".into()));
    assert_eq!(hdrs[2], ("Retry-After", "30".into()));
}

#[test]
fn ratelimit_headers_with_tokens() {
    let hdrs = ratelimit_headers(100, 50, 30, Some(5000), Some(4000));
    assert_eq!(hdrs.len(), 5);
    assert_eq!(hdrs[3], ("x-ratelimit-limit-tokens", "5000".into()));
    assert_eq!(hdrs[4], ("x-ratelimit-remaining-tokens", "4000".into()));
}

// ═══════════════════════════════════════════════════════════════════
// extract_openai_chat_output
// ═══════════════════════════════════════════════════════════════════

#[test]
fn extract_chat_output_single_choice() {
    let body = json!({
        "choices": [{"message": {"content": "hello world"}}]
    });
    assert_eq!(
        extract_openai_chat_output(&body),
        Some("hello world".into())
    );
}

#[test]
fn extract_chat_output_multiple_choices() {
    let body = json!({
        "choices": [
            {"message": {"content": "first"}},
            {"message": {"content": "second"}}
        ]
    });
    assert_eq!(
        extract_openai_chat_output(&body),
        Some("first\nsecond".into())
    );
}

#[test]
fn extract_chat_output_empty_choices() {
    let body = json!({"choices": []});
    assert_eq!(extract_openai_chat_output(&body), None);
}

#[test]
fn extract_chat_output_no_choices_key() {
    let body = json!({"id": "test"});
    assert_eq!(extract_openai_chat_output(&body), None);
}

#[test]
fn extract_chat_output_skips_empty_content() {
    let body = json!({
        "choices": [{"message": {"content": "  "}}]
    });
    assert_eq!(extract_openai_chat_output(&body), None);
}

// ═══════════════════════════════════════════════════════════════════
// extract_openai_responses_output
// ═══════════════════════════════════════════════════════════════════

#[test]
fn extract_responses_output_string_form() {
    let body = json!({"output": "direct text"});
    assert_eq!(
        extract_openai_responses_output(&body),
        Some("direct text".into())
    );
}

#[test]
fn extract_responses_output_array_form() {
    let body = json!({
        "output": [{
            "content": [
                {"type": "output_text", "text": "answer"},
                {"type": "tool_use", "text": "ignored"}
            ]
        }]
    });
    assert_eq!(
        extract_openai_responses_output(&body),
        Some("answer".into())
    );
}

#[test]
fn extract_responses_output_empty_array() {
    let body = json!({"output": []});
    assert_eq!(extract_openai_responses_output(&body), None);
}

#[test]
fn extract_responses_output_no_key() {
    let body = json!({"id": "test"});
    assert_eq!(extract_openai_responses_output(&body), None);
}

#[test]
fn extract_responses_output_skips_empty_string() {
    let body = json!({"output": "  "});
    assert_eq!(extract_openai_responses_output(&body), None);
}

// ═══════════════════════════════════════════════════════════════════
// extract_upstream_model_name / extract_response_model_name
// ═══════════════════════════════════════════════════════════════════

#[test]
fn extract_upstream_model_returns_model() {
    let body = Bytes::from(serde_json::to_vec(&json!({"model": "gpt-4"})).unwrap());
    assert_eq!(
        extract_upstream_model_name(&body),
        Some("gpt-4".to_string())
    );
}

#[test]
fn extract_upstream_model_none_when_missing() {
    let body = Bytes::from(serde_json::to_vec(&json!({"foo": "bar"})).unwrap());
    assert_eq!(extract_upstream_model_name(&body), None);
}

#[test]
fn extract_upstream_model_none_for_invalid_json() {
    let body = Bytes::from_static(b"not json");
    assert_eq!(extract_upstream_model_name(&body), None);
}

#[test]
fn extract_response_model_returns_model() {
    let body = Bytes::from(serde_json::to_vec(&json!({"model": "claude-3-opus"})).unwrap());
    assert_eq!(
        extract_response_model_name(&body),
        Some("claude-3-opus".to_string())
    );
}

// ═══════════════════════════════════════════════════════════════════
// extract_pipeline_metadata
// ═══════════════════════════════════════════════════════════════════

#[test]
fn extract_pipeline_metadata_present() {
    let body =
        Bytes::from(serde_json::to_vec(&json!({"verdictan_pipeline": {"step": 1}})).unwrap());
    let meta = extract_pipeline_metadata(&body).unwrap();
    assert_eq!(meta["step"], 1);
}

#[test]
fn extract_pipeline_metadata_absent() {
    let body = Bytes::from(serde_json::to_vec(&json!({"model": "gpt-4"})).unwrap());
    assert!(extract_pipeline_metadata(&body).is_none());
}

// ═══════════════════════════════════════════════════════════════════
// extract_request_team_slugs
// ═══════════════════════════════════════════════════════════════════

#[test]
fn team_slugs_from_comma_separated_header() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-team",
        HeaderValue::from_static("team-a, team-b, team-c"),
    );
    let slugs = extract_request_team_slugs(&headers);
    assert_eq!(slugs, vec!["team-a", "team-b", "team-c"]);
}

#[test]
fn team_slugs_skips_empty_entries() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-team",
        HeaderValue::from_static("team-a, , team-b"),
    );
    let slugs = extract_request_team_slugs(&headers);
    assert_eq!(slugs, vec!["team-a", "team-b"]);
}

#[test]
fn team_slugs_empty_when_header_absent() {
    let headers = HeaderMap::new();
    let slugs = extract_request_team_slugs(&headers);
    assert!(slugs.is_empty());
}

// ═══════════════════════════════════════════════════════════════════
// extract_trace_correlation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn trace_correlation_from_verdictan_block() {
    let body = json!({
        "verdictan": {
            "evaluation_id": "eval-1",
            "evaluation_run_id": "run-1",
            "test_case_id": "tc-1",
            "test_run_id": "tr-1"
        }
    });
    let tc = extract_trace_correlation(&body);
    assert_eq!(tc.evaluation_id.as_deref(), Some("eval-1"));
    assert_eq!(tc.evaluation_run_id.as_deref(), Some("run-1"));
    assert_eq!(tc.test_case_id.as_deref(), Some("tc-1"));
    assert_eq!(tc.test_run_id.as_deref(), Some("tr-1"));
}

#[test]
fn trace_correlation_from_verdictan_trace_block() {
    let body = json!({
        "verdictan": {
            "trace": {
                "evaluation_id": "eval-2"
            }
        }
    });
    let tc = extract_trace_correlation(&body);
    assert_eq!(tc.evaluation_id.as_deref(), Some("eval-2"));
}

#[test]
fn trace_correlation_from_verdictan_correlation_block() {
    let body = json!({
        "verdictan": {
            "correlation": {
                "evaluation_id": "eval-3",
                "test_run_id": "tr-3"
            }
        }
    });
    let tc = extract_trace_correlation(&body);
    assert_eq!(tc.evaluation_id.as_deref(), Some("eval-3"));
    assert_eq!(tc.test_run_id.as_deref(), Some("tr-3"));
}

#[test]
fn trace_correlation_empty_for_absent() {
    let body = json!({});
    let tc = extract_trace_correlation(&body);
    assert!(tc.is_empty());
}

// ═══════════════════════════════════════════════════════════════════
// extract_request_telemetry_hints
// ═══════════════════════════════════════════════════════════════════

#[test]
fn telemetry_hints_from_verdictan_block() {
    let body = json!({
        "verdictan": {
            "prompt_label": "my-prompt",
            "test_index": 42
        }
    });
    let hints = extract_request_telemetry_hints(&body);
    assert_eq!(hints.prompt_label.as_deref(), Some("my-prompt"));
    assert_eq!(hints.test_index, Some(42));
}

#[test]
fn telemetry_hints_from_prompt_label() {
    let body = json!({
        "verdictan": {
            "prompt_label": "from-prompt-label"
        }
    });
    let hints = extract_request_telemetry_hints(&body);
    assert_eq!(hints.prompt_label.as_deref(), Some("from-prompt-label"));
}

#[test]
fn telemetry_hints_from_nested_prompt_label() {
    let body = json!({
        "verdictan": {
            "prompt": {"label": "nested-label"},
            "test": {"index": 7}
        }
    });
    let hints = extract_request_telemetry_hints(&body);
    assert_eq!(hints.prompt_label.as_deref(), Some("nested-label"));
    assert_eq!(hints.test_index, Some(7));
}

#[test]
fn telemetry_hints_empty_for_no_data() {
    let body = json!({});
    let hints = extract_request_telemetry_hints(&body);
    assert!(hints.prompt_label.is_none());
    assert!(hints.test_index.is_none());
}

// ═══════════════════════════════════════════════════════════════════
// semantic_cache_text_from_body
// ═══════════════════════════════════════════════════════════════════

#[test]
fn semantic_text_from_messages() {
    let body = json!({
        "messages": [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi"}
        ]
    });
    let text = semantic_cache_text_from_body(&body).unwrap();
    assert!(text.contains("hello"));
    assert!(text.contains("hi"));
}

#[test]
fn semantic_text_from_input_string() {
    let body = json!({"input": "summarize this"});
    assert_eq!(
        semantic_cache_text_from_body(&body),
        Some("summarize this".into())
    );
}

#[test]
fn semantic_text_from_input_array() {
    let body = json!({
        "input": [{"content": "item one"}, {"content": "item two"}]
    });
    let text = semantic_cache_text_from_body(&body).unwrap();
    assert!(text.contains("item one"));
    assert!(text.contains("item two"));
}

#[test]
fn semantic_text_from_prompt() {
    let body = json!({"prompt": "complete this"});
    assert_eq!(
        semantic_cache_text_from_body(&body),
        Some("complete this".into())
    );
}

#[test]
fn semantic_text_none_for_empty() {
    let body = json!({});
    assert!(semantic_cache_text_from_body(&body).is_none());
}

#[test]
fn semantic_text_prefers_messages_over_input() {
    let body = json!({
        "messages": [{"role": "user", "content": "from messages"}],
        "input": "from input"
    });
    let text = semantic_cache_text_from_body(&body).unwrap();
    assert!(text.contains("from messages"));
}

// ═══════════════════════════════════════════════════════════════════
// local_semantic_similarity / tokenize_semantic_text
// ═══════════════════════════════════════════════════════════════════

#[test]
fn tokenize_splits_on_non_alphanumeric() {
    let tokens = tokenize_semantic_text("Hello, World! 123");
    assert!(tokens.contains("hello"));
    assert!(tokens.contains("world"));
    assert!(tokens.contains("123"));
    assert!(!tokens.contains(","));
}

#[test]
fn tokenize_empty_string() {
    let tokens = tokenize_semantic_text("");
    assert!(tokens.is_empty());
}

#[test]
fn semantic_similarity_identical_texts() {
    let score = local_semantic_similarity("hello world", "hello world");
    assert!((score - 1.0).abs() < 0.001);
}

#[test]
fn semantic_similarity_completely_different() {
    let score = local_semantic_similarity("apple banana", "xyz uvw");
    assert!(score < 0.001);
}

#[test]
fn semantic_similarity_partial_overlap() {
    let score = local_semantic_similarity("hello world test", "hello world other");
    assert!(score > 0.3);
    assert!(score < 1.0);
}

#[test]
fn semantic_similarity_empty_string_zero() {
    assert!(local_semantic_similarity("", "hello") < 0.001);
    assert!(local_semantic_similarity("hello", "") < 0.001);
}

// ═══════════════════════════════════════════════════════════════════
// extract_provider_cache_context
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cache_context_from_verdictan_variables() {
    let body = json!({
        "verdictan": {"context_variables": {"key": "value"}}
    });
    let ctx = extract_provider_cache_context(&body).unwrap();
    assert!(ctx.is_object());
}

#[test]
fn cache_context_from_top_level_variables() {
    let body = json!({"variables": {"a": 1}});
    let ctx = extract_provider_cache_context(&body).unwrap();
    assert!(ctx.is_object());
}

#[test]
fn cache_context_none_for_empty() {
    let body = json!({"messages": []});
    assert!(extract_provider_cache_context(&body).is_none());
}

// ═══════════════════════════════════════════════════════════════════
// canonicalize_json_value
// ═══════════════════════════════════════════════════════════════════

#[test]
fn canonicalize_sorts_object_keys() {
    let val = json!({"z": 1, "a": 2, "m": 3});
    let canon = canonicalize_json_value(&val);
    let keys: Vec<&String> = canon.as_object().unwrap().keys().collect();
    assert_eq!(keys, vec!["a", "m", "z"]);
}

#[test]
fn canonicalize_handles_nested_objects() {
    let val = json!({"b": {"z": 1, "a": 2}, "a": "hello"});
    let canon = canonicalize_json_value(&val);
    let outer_keys: Vec<&String> = canon.as_object().unwrap().keys().collect();
    assert_eq!(outer_keys, vec!["a", "b"]);
    let inner_keys: Vec<&String> = canon["b"].as_object().unwrap().keys().collect();
    assert_eq!(inner_keys, vec!["a", "z"]);
}

#[test]
fn canonicalize_preserves_arrays() {
    let val = json!([3, 1, 2]);
    let canon = canonicalize_json_value(&val);
    assert_eq!(canon, json!([3, 1, 2]));
}

#[test]
fn canonicalize_scalars_pass_through() {
    assert_eq!(canonicalize_json_value(&json!(42)), json!(42));
    assert_eq!(canonicalize_json_value(&json!("text")), json!("text"));
    assert_eq!(canonicalize_json_value(&json!(true)), json!(true));
    assert_eq!(canonicalize_json_value(&json!(null)), json!(null));
}

// ═══════════════════════════════════════════════════════════════════
// provider_name_from_upstream / provider_scope_key
// ═══════════════════════════════════════════════════════════════════

#[test]
fn provider_name_strips_scheme() {
    assert_eq!(
        provider_name_from_upstream("https://api.openai.com/v1"),
        "api.openai.com"
    );
}

#[test]
fn provider_name_http_scheme() {
    assert_eq!(
        provider_name_from_upstream("http://localhost:8080/v1"),
        "localhost:8080"
    );
}

#[test]
fn provider_scope_key_without_auth() {
    let key = provider_scope_key("https://api.openai.com", None);
    assert!(key.starts_with("scope:"));
    assert!(key.len() > 10);
}

#[test]
fn provider_scope_key_with_auth_changes_hash() {
    let key1 = provider_scope_key("https://api.openai.com", None);
    let key2 = provider_scope_key("https://api.openai.com", Some(b"Bearer sk-test"));
    assert_ne!(key1, key2);
}

// ═══════════════════════════════════════════════════════════════════
// build_response
// ═══════════════════════════════════════════════════════════════════

#[test]
fn build_response_sets_headers() {
    let resp = build_response(
        StatusCode::OK,
        HeaderValue::from_static("application/json"),
        "req-123".into(),
        "trace-456".into(),
        Bytes::from_static(b"{}"),
        false,
        None,
    );
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/json"
    );
    assert_eq!(resp.headers().get("x-request-id").unwrap(), "req-123");
    assert_eq!(resp.headers().get("traceparent").unwrap(), "trace-456");
    assert!(resp.headers().get("x-verdictan-degraded").is_none());
}

#[test]
fn build_response_degraded_header() {
    let resp = build_response(
        StatusCode::OK,
        HeaderValue::from_static("application/json"),
        "req-1".into(),
        "trace-1".into(),
        Bytes::from_static(b"{}"),
        true,
        None,
    );
    assert_eq!(resp.headers().get("x-verdictan-degraded").unwrap(), "true");
}

#[test]
fn build_response_with_extra_headers() {
    let extra = vec![(
        axum::http::HeaderName::from_static("x-custom"),
        HeaderValue::from_static("value"),
    )];
    let resp = build_response(
        StatusCode::OK,
        HeaderValue::from_static("application/json"),
        "req-1".into(),
        "trace-1".into(),
        Bytes::from_static(b"{}"),
        false,
        Some(extra),
    );
    assert_eq!(resp.headers().get("x-custom").unwrap(), "value");
}

// ═══════════════════════════════════════════════════════════════════
// build_request_error_response
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn build_request_error_response_structure() {
    let resp = build_request_error_response(
        StatusCode::BAD_REQUEST,
        "req-1",
        "trace-1",
        "bad request",
        "invalid_request",
        "bad_input",
    );
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["error"]["message"], "bad request");
    assert_eq!(parsed["error"]["type"], "invalid_request");
    assert_eq!(parsed["error"]["code"], "bad_input");
}

// ═══════════════════════════════════════════════════════════════════
// inject_ratelimit_info
// ═══════════════════════════════════════════════════════════════════

#[test]
fn inject_ratelimit_adds_headers_to_success() {
    let resp = Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap();
    let info = [("x-ratelimit-limit-requests", "100".into())];
    let resp = inject_ratelimit_info(resp, &info);
    assert_eq!(
        resp.headers()
            .get("x-ratelimit-limit-requests")
            .unwrap()
            .to_str()
            .unwrap(),
        "100"
    );
}

#[test]
fn inject_ratelimit_skips_non_success() {
    let resp = Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::empty())
        .unwrap();
    let info = [("x-ratelimit-limit-requests", "100".into())];
    let resp = inject_ratelimit_info(resp, &info);
    assert!(resp.headers().get("x-ratelimit-limit-requests").is_none());
}

#[test]
fn inject_ratelimit_skips_empty_info() {
    let resp = Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap();
    let resp = inject_ratelimit_info(resp, &[]);
    assert_eq!(resp.status(), StatusCode::OK);
}

// ═══════════════════════════════════════════════════════════════════
// build_budget_filter_body / build_budget_filter_buffered_response
// ═══════════════════════════════════════════════════════════════════

#[test]
fn budget_filter_body_contains_error() {
    let rejection = BudgetFilterRejection::forbidden("over budget", "budget_exceeded");
    let body = build_budget_filter_body(&rejection);
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(parsed["error"]["message"]
        .as_str()
        .unwrap()
        .contains("over budget"));
}

#[test]
fn budget_filter_buffered_response_status() {
    let rejection = BudgetFilterRejection::forbidden("test", "test_code");
    let resp = build_budget_filter_buffered_response(&rejection);
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/json"
    );
}

#[tokio::test]
async fn budget_filter_streaming_response_status() {
    let rejection = BudgetFilterRejection::forbidden("test", "test_code");
    let resp = build_budget_filter_streaming_response(&rejection);
    assert_eq!(resp.status, StatusCode::FORBIDDEN);
}

// ═══════════════════════════════════════════════════════════════════
// build_provider_auth_body / build_provider_auth_buffered_response
// ═══════════════════════════════════════════════════════════════════

#[test]
fn provider_auth_body_contains_message() {
    let body = build_provider_auth_body("auth failed");
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(parsed["error"]["message"]
        .as_str()
        .unwrap()
        .contains("auth failed"));
}

#[test]
fn provider_auth_buffered_response_status() {
    let resp = build_provider_auth_buffered_response("auth error");
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn provider_auth_streaming_response_status() {
    let resp = build_provider_auth_streaming_response("auth error");
    assert_eq!(resp.status, StatusCode::BAD_GATEWAY);
}

// ═══════════════════════════════════════════════════════════════════
// build_token_validation_error_response
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn token_validation_error_unauthorized() {
    let err = TokenValidationError::Unauthorized { body: "bad".into() };
    let resp = build_token_validation_error_response("req-1", "trace-1", &err);
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(parsed["error"]["message"]
        .as_str()
        .unwrap()
        .contains("misconfigured"));
}

#[tokio::test]
async fn token_validation_error_unexpected_status() {
    let err = TokenValidationError::UnexpectedStatus {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        body: "server error".into(),
    };
    let resp = build_token_validation_error_response("req-1", "trace-1", &err);
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(parsed["error"]["message"]
        .as_str()
        .unwrap()
        .contains("temporarily unavailable"));
}

// ═══════════════════════════════════════════════════════════════════
// TokenValidationError Display
// ═══════════════════════════════════════════════════════════════════

#[test]
fn token_validation_error_display_unauthorized() {
    let err = TokenValidationError::Unauthorized {
        body: "test body".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("unauthorized"));
    assert!(msg.contains("test body"));
}

#[test]
fn token_validation_error_display_forbidden() {
    let err = TokenValidationError::Forbidden {
        body: "forbidden body".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("forbidden"));
}

#[test]
fn token_validation_error_display_unexpected_status() {
    let err = TokenValidationError::UnexpectedStatus {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        body: "server error".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("500"));
    assert!(msg.contains("server error"));
}

#[test]
fn token_validation_error_is_std_error() {
    let err = TokenValidationError::Unauthorized {
        body: "test".into(),
    };
    let _: &dyn std::error::Error = &err;
}

// ═══════════════════════════════════════════════════════════════════
// GatewayRuntimeMetrics
// ═══════════════════════════════════════════════════════════════════

#[test]
fn runtime_metrics_record_and_read() {
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
// BudgetFilterRejection constructors
// ═══════════════════════════════════════════════════════════════════

#[test]
fn budget_rejection_forbidden() {
    let r = BudgetFilterRejection::forbidden("over budget", "cost_exceeded");
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.error_type, "cost_budget_exceeded");
    assert_eq!(r.code, "cost_exceeded");
    assert_eq!(r.message, "over budget");
}

#[test]
fn budget_rejection_access_denied() {
    let r = BudgetFilterRejection::access_denied("not allowed", "denied_code");
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.error_type, "access_denied");
}

#[test]
fn budget_rejection_service_unavailable() {
    let r = BudgetFilterRejection::service_unavailable("budget service down", "budget_unavailable");
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.error_type, "service_unavailable");
}

// ═══════════════════════════════════════════════════════════════════
// TraceCorrelation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn trace_correlation_is_empty_when_all_none() {
    let tc = TraceCorrelation::default();
    assert!(tc.is_empty());
}

#[test]
fn trace_correlation_not_empty_when_set() {
    let tc = TraceCorrelation {
        evaluation_id: Some("eval-1".into()),
        ..Default::default()
    };
    assert!(!tc.is_empty());
}

#[test]
fn trace_correlation_as_event_json_none_when_empty() {
    let tc = TraceCorrelation::default();
    assert!(tc.as_event_json().is_none());
}

#[test]
fn trace_correlation_as_event_json_has_fields() {
    let tc = TraceCorrelation {
        evaluation_id: Some("eval-1".into()),
        test_case_id: Some("tc-1".into()),
        ..Default::default()
    };
    let json = tc.as_event_json().unwrap();
    assert_eq!(json["evaluation_id"], "eval-1");
    assert_eq!(json["test_case_id"], "tc-1");
}

// ═══════════════════════════════════════════════════════════════════
// ConnectedPostDispatchUsageSource
// ═══════════════════════════════════════════════════════════════════

#[test]
fn usage_source_upstream_reported() {
    let src = ConnectedPostDispatchUsageSource::UpstreamReported;
    assert_eq!(src.as_str(), "provider_reported");
    assert!(!src.is_estimated());
}

#[test]
fn usage_source_streaming_estimate() {
    let src = ConnectedPostDispatchUsageSource::StreamingEstimate;
    assert_eq!(src.as_str(), "streaming_estimate");
    assert!(src.is_estimated());
}

#[test]
fn usage_source_prompt_only_fallback() {
    let src = ConnectedPostDispatchUsageSource::PromptOnlyFallback;
    assert_eq!(src.as_str(), "prompt_only_fallback");
    assert!(src.is_estimated());
}

// ═══════════════════════════════════════════════════════════════════
// CacheTier / CacheReplayOutcome
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cache_tier_as_str() {
    assert_eq!(CacheTier::PrivateEdge.as_str(), "private_edge_cache");
    assert_eq!(CacheTier::OrgShared.as_str(), "org_shared_cache");
}

#[test]
fn cache_replay_outcome_hit_types() {
    assert_eq!(CacheReplayOutcome::ExactHit.as_str(), "exact_hit");
    assert_eq!(CacheReplayOutcome::ExactHit.hit_type(), "exact");
    assert_eq!(
        CacheReplayOutcome::SemanticReplayed.as_str(),
        "semantic_replayed"
    );
    assert_eq!(
        CacheReplayOutcome::SemanticReplayed.hit_type(),
        "semantic_replayed"
    );
    assert_eq!(
        CacheReplayOutcome::SemanticCandidate.as_str(),
        "semantic_candidate"
    );
    assert_eq!(CacheReplayOutcome::StaleMiss.as_str(), "stale_miss");
    assert_eq!(CacheReplayOutcome::DeniedReplay.as_str(), "denied_replay");
}

// ═══════════════════════════════════════════════════════════════════
// RequestFinopsContext helper methods
// ═══════════════════════════════════════════════════════════════════

#[test]
fn finops_has_token_identity_true_with_key_id() {
    let finops = RequestFinopsContext {
        key_id: Some("key-1".into()),
        ..Default::default()
    };
    assert!(finops.has_token_identity());
}

#[test]
fn finops_has_token_identity_false_with_only_user_id() {
    let finops = RequestFinopsContext {
        user_id: Some("user-1".into()),
        ..Default::default()
    };
    assert!(!finops.has_token_identity());
}

#[test]
fn finops_has_token_identity_false_empty() {
    let finops = RequestFinopsContext::default();
    assert!(!finops.has_token_identity());
}

#[test]
fn finops_identity_context_json_none_when_no_identity() {
    let finops = RequestFinopsContext::default();
    assert!(finops.identity_context_json().is_none());
}

#[test]
fn finops_identity_context_json_with_keys() {
    let finops = RequestFinopsContext {
        key_id: Some("key-1".into()),
        user_id: Some("user-1".into()),
        team_id: Some("team-1".into()),
        org_id: Some("org-1".into()),
        ..Default::default()
    };
    let json = finops.identity_context_json().unwrap();
    assert_eq!(json["key_id"], "key-1");
    assert_eq!(json["user_id"], "user-1");
    assert_eq!(json["team_id"], "team-1");
    assert_eq!(json["org_id"], "org-1");
}

#[test]
fn finops_context_selection_json_none_when_no_hash() {
    let finops = RequestFinopsContext::default();
    assert!(finops.context_selection_json().is_none());
}

#[test]
fn finops_context_selection_json_with_data() {
    let finops = RequestFinopsContext {
        context_plan_hash: Some("hash-1".into()),
        context_policy_version: Some(5),
        context_selected_item_ids: vec!["item-1".into()],
        context_citation_required_count: Some(2),
        context_max_tokens: Some(1000),
        context_estimated_tokens: Some(500),
        context_injected_tokens: Some(300),
        working_context_tokens: Some(200),
        ..Default::default()
    };
    let json = finops.context_selection_json().unwrap();
    assert_eq!(json["plan_hash"], "hash-1");
    assert_eq!(json["context_policy_version"], 5);
    assert_eq!(json["selected_item_ids"], json!(["item-1"]));
    assert_eq!(json["citation_required_count"], 2);
    assert_eq!(json["max_context_tokens"], 1000);
}

// ═══════════════════════════════════════════════════════════════════
// token_current_spend / token_max_budget / token_current_requests / token_max_requests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn token_spend_from_depletion() {
    let key = make_token_record("key-1");
    let mut validation = make_token_validation_response();
    validation.depletion = Some(TokenDepletionState {
        current_spend: Some(42.0),
        ..Default::default()
    });
    assert!((token_current_spend(&key, &validation) - 42.0).abs() < 0.001);
}

#[test]
fn token_spend_falls_back_to_key() {
    let mut key = make_token_record("key-1");
    key.current_spend = 10.0;
    let validation = make_token_validation_response();
    assert!((token_current_spend(&key, &validation) - 10.0).abs() < 0.001);
}

#[test]
fn token_max_budget_from_depletion() {
    let key = make_token_record("key-1");
    let mut validation = make_token_validation_response();
    validation.depletion = Some(TokenDepletionState {
        max_budget: Some(100.0),
        ..Default::default()
    });
    assert_eq!(token_max_budget(&key, &validation), Some(100.0));
}

#[test]
fn token_max_budget_from_key() {
    let mut key = make_token_record("key-1");
    key.max_budget = Some(50.0);
    let validation = make_token_validation_response();
    assert_eq!(token_max_budget(&key, &validation), Some(50.0));
}

#[test]
fn token_current_requests_from_depletion() {
    let mut validation = make_token_validation_response();
    validation.depletion = Some(TokenDepletionState {
        current_requests: Some(15),
        ..Default::default()
    });
    assert_eq!(token_current_requests(&validation), 15);
}

#[test]
fn token_current_requests_default_zero() {
    let validation = make_token_validation_response();
    assert_eq!(token_current_requests(&validation), 0);
}

#[test]
fn token_max_requests_from_depletion() {
    let mut validation = make_token_validation_response();
    validation.depletion = Some(TokenDepletionState {
        max_requests: Some(100),
        ..Default::default()
    });
    assert_eq!(token_max_requests(&validation), Some(100));
}

#[test]
fn token_max_requests_none_when_absent() {
    let validation = make_token_validation_response();
    assert_eq!(token_max_requests(&validation), None);
}

// ═══════════════════════════════════════════════════════════════════
// parse_expiry_timestamp
// ═══════════════════════════════════════════════════════════════════

#[test]
fn parse_expiry_valid_rfc3339() {
    let result = parse_expiry_timestamp(Some("2025-12-31T23:59:59Z"));
    assert!(result.is_some());
    assert_eq!(result.unwrap().format("%Y").to_string(), "2025");
}

#[test]
fn parse_expiry_invalid_string() {
    assert!(parse_expiry_timestamp(Some("not a date")).is_none());
}

#[test]
fn parse_expiry_none() {
    assert!(parse_expiry_timestamp(None).is_none());
}

// ═══════════════════════════════════════════════════════════════════
// intersect_scope_values
// ═══════════════════════════════════════════════════════════════════

#[test]
fn intersect_both_empty_returns_empty() {
    let result = intersect_scope_values(&[], &[], normalize_text_scope_values);
    assert!(result.is_empty());
}

#[test]
fn intersect_binding_only_returns_binding() {
    let binding = vec!["a".into(), "b".into()];
    let result = intersect_scope_values(&binding, &[], normalize_text_scope_values);
    assert_eq!(result, vec!["a", "b"]);
}

#[test]
fn intersect_policy_only_returns_policy() {
    let policy = vec!["x".into(), "y".into()];
    let result = intersect_scope_values(&[], &policy, normalize_text_scope_values);
    assert_eq!(result, vec!["x", "y"]);
}

#[test]
fn intersect_both_present_returns_intersection() {
    let binding = vec!["a".into(), "b".into(), "c".into()];
    let policy = vec!["b".into(), "c".into(), "d".into()];
    let result = intersect_scope_values(&binding, &policy, normalize_text_scope_values);
    assert_eq!(result, vec!["b", "c"]);
}

// ═══════════════════════════════════════════════════════════════════
// merged_token_scopes
// ═══════════════════════════════════════════════════════════════════

#[test]
fn merged_token_scopes_no_policy_no_bindings() {
    let key = make_token_record("key-1");
    let result = merged_token_scopes(&key, None, &[]).unwrap();
    assert!(result.allowed_providers.is_empty());
    assert!(result.allowed_models.is_empty());
    assert!(result.allowed_gateways.is_empty());
}

#[test]
fn merged_token_scopes_errors_when_policy_ids_without_controls() {
    let key = make_token_record("key-1");
    let err = merged_token_scopes(&key, None, &["policy-1".into()]);
    assert!(err.is_err());
}

#[test]
fn merged_token_scopes_gateway_from_key_field() {
    let mut key = make_token_record("key-1");
    key.gateway_id = Some("gw-1".into());
    let result = merged_token_scopes(&key, None, &[]).unwrap();
    assert_eq!(result.allowed_gateways, vec!["gw-1"]);
}

#[test]
fn merged_token_scopes_provider_from_key() {
    let mut key = make_token_record("key-1");
    key.provider = Some("openai".into());
    let result = merged_token_scopes(&key, None, &[]).unwrap();
    assert!(!result.allowed_providers.is_empty());
}

// ═══════════════════════════════════════════════════════════════════
// merge_provider_extra_header
// ═══════════════════════════════════════════════════════════════════

#[test]
fn merge_extra_header_adds_new() {
    let mut headers = Vec::new();
    merge_provider_extra_header(&mut headers, "x-custom", "value1");
    assert_eq!(headers.len(), 1);
}

#[test]
fn merge_extra_header_replaces_existing() {
    let mut headers = Vec::new();
    merge_provider_extra_header(&mut headers, "x-custom", "value1");
    merge_provider_extra_header(&mut headers, "x-custom", "value2");
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].1.to_str().unwrap(), "value2");
}

#[test]
fn merge_extra_header_skips_invalid_name() {
    let mut headers = Vec::new();
    merge_provider_extra_header(&mut headers, "\x00invalid", "value");
    assert!(headers.is_empty());
}

// ═══════════════════════════════════════════════════════════════════
// requested_anthropic_beta_headers
// ═══════════════════════════════════════════════════════════════════

#[test]
fn anthropic_beta_from_header() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "anthropic-beta",
        HeaderValue::from_static("feature-a, feature-b"),
    );
    let betas = requested_anthropic_beta_headers("/v1/chat/completions", &headers, &json!({}));
    assert!(betas.contains(&"feature-a".to_string()));
    assert!(betas.contains(&"feature-b".to_string()));
}

#[test]
fn anthropic_beta_deduplicates() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "anthropic-beta",
        HeaderValue::from_static("feature-a, feature-a"),
    );
    let betas = requested_anthropic_beta_headers("/v1/chat/completions", &headers, &json!({}));
    assert_eq!(betas.iter().filter(|b| *b == "feature-a").count(), 1);
}

#[test]
fn anthropic_beta_empty_when_no_header() {
    let headers = HeaderMap::new();
    let betas = requested_anthropic_beta_headers("/v1/chat/completions", &headers, &json!({}));
    assert!(betas.is_empty());
}

// ═══════════════════════════════════════════════════════════════════
// PipelineUsageTotals
// ═══════════════════════════════════════════════════════════════════

#[test]
fn pipeline_usage_totals_record_step() {
    let mut totals = PipelineUsageTotals::default();
    let usage = SpendUsage {
        prompt_tokens: 100,
        completion_tokens: 50,
        total_tokens: 150,
        cached_input_tokens: 10,
        prompt_cost: Some(0.01),
        completion_cost: Some(0.02),
        total_cost: Some(0.03),
    };
    totals.record_step(usage, 0.01, 0.02, 0.005, 0.035);

    assert_eq!(totals.prompt_tokens, 100);
    assert_eq!(totals.completion_tokens, 50);
    assert_eq!(totals.total_tokens, 150);
    assert_eq!(totals.cached_input_tokens, 10);
    assert!(totals.has_usage);
}

#[test]
fn pipeline_usage_totals_accumulates() {
    let mut totals = PipelineUsageTotals::default();
    let usage1 = SpendUsage {
        prompt_tokens: 100,
        completion_tokens: 50,
        total_tokens: 150,
        cached_input_tokens: 0,
        prompt_cost: None,
        completion_cost: None,
        total_cost: None,
    };
    let usage2 = SpendUsage {
        prompt_tokens: 200,
        completion_tokens: 100,
        total_tokens: 300,
        cached_input_tokens: 20,
        prompt_cost: None,
        completion_cost: None,
        total_cost: None,
    };
    totals.record_step(usage1, 0.01, 0.02, 0.0, 0.03);
    totals.record_step(usage2, 0.02, 0.04, 0.005, 0.065);

    assert_eq!(totals.prompt_tokens, 300);
    assert_eq!(totals.completion_tokens, 150);
    assert_eq!(totals.cached_input_tokens, 20);
}

#[test]
fn pipeline_usage_totals_into_json_none_when_no_usage() {
    let totals = PipelineUsageTotals::default();
    assert!(totals.into_json().is_none());
}

#[test]
fn pipeline_usage_totals_into_json_has_fields() {
    let mut totals = PipelineUsageTotals::default();
    let usage = SpendUsage {
        prompt_tokens: 50,
        completion_tokens: 25,
        total_tokens: 75,
        cached_input_tokens: 5,
        prompt_cost: None,
        completion_cost: None,
        total_cost: None,
    };
    totals.record_step(usage, 0.005, 0.01, 0.001, 0.016);
    let json = totals.into_json().unwrap();
    assert_eq!(json["prompt_tokens"], 50);
    assert_eq!(json["completion_tokens"], 25);
    assert_eq!(json["total_tokens"], 75);
    assert_eq!(json["cached_input_tokens"], 5);
}

// ═══════════════════════════════════════════════════════════════════
// pipeline_supported_path / pipeline helpers
// ═══════════════════════════════════════════════════════════════════

#[test]
fn pipeline_supported_paths() {
    assert!(pipeline_supported_path("/v1/chat/completions"));
    assert!(pipeline_supported_path("/v1/responses"));
    assert!(!pipeline_supported_path("/v1/embeddings"));
    assert!(!pipeline_supported_path("/v1/completions"));
}

#[test]
fn pipeline_json_response_has_correct_headers() {
    let resp = build_pipeline_json_response(StatusCode::OK, json!({"data": "test"}));
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/json"
    );
}

#[test]
fn pipeline_error_response_has_error_body() {
    let resp = build_pipeline_error_response(
        StatusCode::BAD_REQUEST,
        "bad input",
        "invalid_request",
        "bad_input",
    );
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
    assert_eq!(body["error"]["message"], "bad input");
}

// ═══════════════════════════════════════════════════════════════════
// target_supports_model
// ═══════════════════════════════════════════════════════════════════

#[test]
fn target_supports_exact_model() {
    let target = make_target("t1", "openai", "gpt-4");
    assert!(target_supports_model(&target, "gpt-4"));
}

#[test]
fn target_rejects_different_model() {
    let target = make_target("t1", "openai", "gpt-4");
    assert!(!target_supports_model(&target, "gpt-3.5-turbo"));
}

#[test]
fn target_supports_wildcard_model() {
    let target = make_target("t1", "openai", "*");
    assert!(target_supports_model(&target, "gpt-4"));
    assert!(target_supports_model(&target, "any-model"));
}

#[test]
fn target_supports_model_from_entries() {
    let models = vec![
        make_model_entry("gpt-4", true),
        make_model_entry("gpt-3.5-turbo", true),
    ];
    let target = make_target_with_models("t1", "openai", "*", models);
    assert!(target_supports_model(&target, "gpt-4"));
    assert!(target_supports_model(&target, "gpt-3.5-turbo"));
}

#[test]
fn target_rejects_disabled_model_entry() {
    let models = vec![make_model_entry("gpt-4", false)];
    let target = make_target_with_models("t1", "openai", "other", models);
    assert!(!target_supports_model(&target, "gpt-4"));
}

#[test]
fn target_supports_model_via_alias() {
    let models = vec![make_model_entry_with_aliases(
        "gpt-4-turbo-preview",
        vec!["gpt-4-turbo"],
        true,
    )];
    let target = make_target_with_models("t1", "openai", "*", models);
    assert!(target_supports_model(&target, "gpt-4-turbo"));
}

#[test]
fn target_rejects_empty_model_name() {
    let target = make_target("t1", "openai", "gpt-4");
    assert!(!target_supports_model(&target, ""));
    assert!(!target_supports_model(&target, "  "));
}

#[test]
fn target_supports_provider_prefixed_model() {
    let target = make_target("t1", "openai", "gpt-4");
    assert!(target_supports_model(&target, "openai/gpt-4"));
}

#[test]
fn target_rejects_wrong_provider_prefix() {
    let target = make_target("t1", "openai", "gpt-4");
    assert!(!target_supports_model(&target, "anthropic/gpt-4"));
}

// ═══════════════════════════════════════════════════════════════════
// resolve_target_model_name
// ═══════════════════════════════════════════════════════════════════

#[test]
fn resolve_target_model_name_returns_model() {
    let target = make_target("t1", "openai", "gpt-4");
    assert_eq!(resolve_target_model_name(&target), Some("gpt-4"));
}

#[test]
fn resolve_target_model_name_skips_wildcard() {
    let target = make_target("t1", "openai", "*");
    assert_eq!(resolve_target_model_name(&target), None);
}

#[test]
fn resolve_target_model_name_from_entries() {
    let models = vec![
        make_model_entry("gpt-3.5-turbo", false),
        make_model_entry("gpt-4", true),
    ];
    let target = make_target_with_models("t1", "openai", "*", models);
    assert_eq!(resolve_target_model_name(&target), Some("gpt-4"));
}

// ═══════════════════════════════════════════════════════════════════
// find_enabled_target_model_entry
// ═══════════════════════════════════════════════════════════════════

#[test]
fn find_enabled_entry_by_id() {
    let models = vec![make_model_entry("gpt-4", true)];
    let target = make_target_with_models("t1", "openai", "*", models);
    let entry = find_enabled_target_model_entry(&target, "gpt-4");
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().model_id, "gpt-4");
}

#[test]
fn find_enabled_entry_by_alias() {
    let models = vec![make_model_entry_with_aliases(
        "gpt-4-turbo-preview",
        vec!["gpt-4-turbo"],
        true,
    )];
    let target = make_target_with_models("t1", "openai", "*", models);
    assert!(find_enabled_target_model_entry(&target, "gpt-4-turbo").is_some());
}

#[test]
fn find_enabled_entry_skips_disabled() {
    let models = vec![make_model_entry("gpt-4", false)];
    let target = make_target_with_models("t1", "openai", "*", models);
    assert!(find_enabled_target_model_entry(&target, "gpt-4").is_none());
}

#[test]
fn find_enabled_entry_empty_candidate() {
    let target = make_target("t1", "openai", "gpt-4");
    assert!(find_enabled_target_model_entry(&target, "").is_none());
}

// ═══════════════════════════════════════════════════════════════════
// supported_features_contain
// ═══════════════════════════════════════════════════════════════════

#[test]
fn supported_features_case_insensitive_match() {
    let features = vec!["Vision".into(), "ToolUse".into()];
    assert!(supported_features_contain(&features, "vision"));
    assert!(supported_features_contain(&features, "TOOLUSE"));
    assert!(!supported_features_contain(&features, "audio"));
}

#[test]
fn supported_features_empty() {
    assert!(!supported_features_contain(&[], "vision"));
}

// ═══════════════════════════════════════════════════════════════════
// resolve_catalog_model_name_for_request
// ═══════════════════════════════════════════════════════════════════

#[test]
fn catalog_model_name_exact_match() {
    let target = make_target("t1", "openai", "gpt-4");
    assert_eq!(
        resolve_catalog_model_name_for_request(&target, "gpt-4"),
        Some("gpt-4")
    );
}

#[test]
fn catalog_model_name_no_match() {
    let target = make_target("t1", "openai", "gpt-4");
    assert_eq!(
        resolve_catalog_model_name_for_request(&target, "gpt-3.5-turbo"),
        None
    );
}

#[test]
fn catalog_model_name_empty_request_falls_to_target() {
    let target = make_target("t1", "openai", "gpt-4");
    assert_eq!(
        resolve_catalog_model_name_for_request(&target, ""),
        Some("gpt-4")
    );
}

#[test]
fn catalog_model_name_from_model_entry() {
    let models = vec![make_model_entry_with_aliases(
        "gpt-4-turbo-preview",
        vec!["gpt-4-turbo"],
        true,
    )];
    let target = make_target_with_models("t1", "openai", "*", models);
    assert_eq!(
        resolve_catalog_model_name_for_request(&target, "gpt-4-turbo"),
        Some("gpt-4-turbo-preview")
    );
}

// ═══════════════════════════════════════════════════════════════════
// annotate_post_dispatch_usage_source
// ═══════════════════════════════════════════════════════════════════

#[test]
fn annotate_usage_source_sets_metadata() {
    let mut spend_log = SpendLogPayload {
        provider: "openai".into(),
        model: "gpt-4".into(),
        prompt_tokens: 0,
        completion_tokens: 0,
        total_tokens: 0,
        cached_input_tokens: 0,
        prompt_cost: 0.0,
        completion_cost: 0.0,
        cached_input_cost: 0.0,
        total_cost: 0.0,
        currency: "USD".into(),
        key_id: None,
        user_id: None,
        team_id: None,
        provider_target_id: None,
        model_id: None,
        requested_model: None,
        requested_provider: None,
        pricing_source: None,
        pricing_snapshot: None,
        metadata: json!({}),
        gateway_id: None,
        configuration_id: None,
        configuration_version_id: None,
        agent_id: None,
        gateway_execution_session_id: None,
        execution_surface: None,
        usage_category: "gateway_llm".into(),
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
    annotate_post_dispatch_usage_source(
        &mut spend_log,
        ConnectedPostDispatchUsageSource::StreamingEstimate,
    );
    assert_eq!(spend_log.metadata["usage_source"], "streaming_estimate");
    assert_eq!(spend_log.metadata["usage_estimated"], true);
}

// ═══════════════════════════════════════════════════════════════════
// RuntimeRoutingSettings defaults
// ═══════════════════════════════════════════════════════════════════

#[test]
fn default_runtime_routing_settings() {
    let settings = RuntimeRoutingSettings::default();
    assert!(settings.default_provider_policy.allow_fallbacks);
    assert!(settings.default_provider_policy.require_parameters);
    assert_eq!(settings.default_provider_policy.data_collection, "allow");
    assert!(!settings.default_provider_policy.zdr);
    assert!(settings.cache_defaults.allow_cache_control);
    assert!(settings.cache_defaults.sticky_routing);
    assert_eq!(settings.cache_defaults.session_header_name, "x-session-id");
    assert!(!settings.shadow_routing.enabled);
}

// ═══════════════════════════════════════════════════════════════════
// runtime_routing_from_declarative
// ═══════════════════════════════════════════════════════════════════

#[test]
fn routing_from_declarative_none_returns_defaults() {
    let result = runtime_routing_from_declarative(None);
    assert!(result.default_provider_policy.allow_fallbacks);
}

// ═══════════════════════════════════════════════════════════════════
// normalize_optional_string_value
// ═══════════════════════════════════════════════════════════════════

#[test]
fn normalize_optional_string_value_from_string() {
    let val = json!("hello");
    assert_eq!(
        normalize_optional_string_value(Some(&val)),
        Some("hello".into())
    );
}

#[test]
fn normalize_optional_string_value_trims_empty() {
    let val = json!("  ");
    assert_eq!(normalize_optional_string_value(Some(&val)), None);
}

#[test]
fn normalize_optional_string_value_none() {
    assert_eq!(normalize_optional_string_value(None), None);
}

// ═══════════════════════════════════════════════════════════════════
// join_upstream / rewrite_upstream_path / is_github_models_upstream
// ═══════════════════════════════════════════════════════════════════

#[test]
fn join_upstream_trims_slashes() {
    assert_eq!(
        join_upstream("https://api.openai.com/", "/v1/completions"),
        "https://api.openai.com/v1/completions"
    );
    assert_eq!(
        join_upstream("https://api.openai.com", "/v1/models"),
        "https://api.openai.com/v1/models"
    );
}

#[test]
fn rewrite_upstream_path_github_models() {
    let path = rewrite_upstream_path("https://models.github.ai/v1", "/v1/chat/completions");
    assert_eq!(path, "/inference/chat/completions");
}

#[test]
fn rewrite_upstream_path_non_github() {
    let path = rewrite_upstream_path("https://api.openai.com/v1", "/v1/chat/completions");
    assert_eq!(path, "/v1/chat/completions");
}

#[test]
fn is_github_models_detects_known_hosts() {
    assert!(is_github_models_upstream("https://models.github.ai/v1"));
    assert!(is_github_models_upstream(
        "https://models.inference.ai.azure.com"
    ));
    assert!(!is_github_models_upstream("https://api.openai.com"));
}

// ═══════════════════════════════════════════════════════════════════
// RuntimeRoutingError
// ═══════════════════════════════════════════════════════════════════

#[test]
fn runtime_routing_error_status() {
    let err = RuntimeRoutingError::invalid_request("test_code", "bad input");
    assert_eq!(err.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(err.code(), "test_code");
    assert_eq!(err.browser_safe_message(), "bad input");
}

// ═══════════════════════════════════════════════════════════════════
// EffectiveShadowRouting defaults
// ═══════════════════════════════════════════════════════════════════

#[test]
fn effective_shadow_routing_defaults() {
    let sr = EffectiveShadowRouting::default();
    assert!(!sr.enabled);
    assert_eq!(sr.capture_mode, "metadata_only");
}

// ═══════════════════════════════════════════════════════════════════
// RuntimePreflightError
// ═══════════════════════════════════════════════════════════════════

#[test]
fn runtime_preflight_error_validation_failed() {
    let err = RuntimePreflightError::validation_failed("invalid input", json!({"field": "model"}));
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert_eq!(err.code, "request.validation_failed");
    assert_eq!(err.details["field"], "model");
}

#[test]
fn runtime_preflight_error_custom() {
    let err = RuntimePreflightError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        "runtime.size_exceeded",
        "too large",
        json!({"max_bytes": 1024}),
    );
    assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(err.code, "runtime.size_exceeded");
    assert_eq!(err.message, "too large");
}

// ═══════════════════════════════════════════════════════════════════
// SharedGatewayConfig
// ═══════════════════════════════════════════════════════════════════

#[test]
fn shared_gateway_config_snapshot_and_replace() {
    let config = SharedGatewayConfig::new(LoadedDeclarativeConfig::empty());
    let snap1 = config.snapshot();
    assert!(snap1.chain_entries.is_empty());

    config.replace(LoadedDeclarativeConfig::empty());
    let snap2 = config.snapshot();
    assert!(snap2.chain_entries.is_empty());
}

// ═══════════════════════════════════════════════════════════════════
// normalize_optional_text
// ═══════════════════════════════════════════════════════════════════

#[test]
fn normalize_optional_text_trims_and_filters() {
    assert_eq!(
        normalize_optional_text(Some("  hello  ")),
        Some("hello".to_string())
    );
    assert_eq!(normalize_optional_text(Some("  ")), None);
    assert_eq!(normalize_optional_text(Some("")), None);
    assert_eq!(normalize_optional_text(None), None);
}

// ═══════════════════════════════════════════════════════════════════
// normalize_text_scope_values / normalize_provider_scope_values
// ═══════════════════════════════════════════════════════════════════

#[test]
fn normalize_text_scope_deduplicates_and_sorts() {
    let values: Vec<String> = vec!["  z  ".into(), "a".into(), "z".into(), "  ".into()];
    let result = normalize_text_scope_values(&values);
    assert_eq!(result, vec!["a", "z"]);
}

#[test]
fn normalize_provider_scope_deduplicates() {
    let values: Vec<String> = vec!["OpenAI".into(), "openai".into(), "anthropic".into()];
    let result = normalize_provider_scope_values(&values);
    assert!(result.len() <= 2);
    assert!(result.contains(&"openai".to_string()) || result.iter().any(|v| v.contains("openai")));
}

// ═══════════════════════════════════════════════════════════════════
// normalize_provider_alias_list
// ═══════════════════════════════════════════════════════════════════

#[test]
fn normalize_provider_alias_list_sorts_and_deduplicates() {
    let values: Vec<String> = vec!["Anthropic".into(), "anthropic".into()];
    let result = normalize_provider_alias_list(&values);
    assert_eq!(result.len(), 1);
}

// ═══════════════════════════════════════════════════════════════════
// default_usage_category_cli and other defaults
// ═══════════════════════════════════════════════════════════════════

#[test]
fn default_functions_return_expected_values() {
    assert_eq!(default_usage_category_cli(), "gateway_llm");
    assert!(default_true());
    assert_eq!(default_data_collection_allow(), "allow");
    assert_eq!(default_session_header_name(), "x-session-id");
    assert_eq!(default_shadow_evaluation_mode(), "asynchronous");
    assert_eq!(default_shadow_capture_mode(), "metadata_only");
}

// ═══════════════════════════════════════════════════════════════════
// PricingSource serialization
// ═══════════════════════════════════════════════════════════════════

#[test]
fn pricing_source_serializes_correctly() {
    let upstream = serde_json::to_value(PricingSource::Upstream).unwrap();
    assert_eq!(upstream, "upstream");
    let declared = serde_json::to_value(PricingSource::ConfigDeclared).unwrap();
    assert_eq!(declared, "config_declared");
}

// ═══════════════════════════════════════════════════════════════════
// CacheReplayMetadata
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cache_replay_metadata_json_roundtrip() {
    let meta = CacheReplayMetadata {
        outcome: CacheReplayOutcome::ExactHit,
        cache_key_digest: Some("abc123".to_string()),
        cache_tier: CacheTier::OrgShared,
        selected_fabric_artifact_ids: vec!["art-1".into()],
        selected_fabric_source_digests: vec!["dig-1".into()],
    };
    let json = meta.to_json();
    assert_eq!(json["outcome"], "exact_hit");
    assert_eq!(json["cache_key_digest"], "abc123");
    assert_eq!(json["cache_tier"], "org_shared_cache");
}

#[test]
fn cache_replay_metadata_stale_miss() {
    let meta = CacheReplayMetadata {
        outcome: CacheReplayOutcome::StaleMiss,
        cache_key_digest: None,
        cache_tier: CacheTier::PrivateEdge,
        selected_fabric_artifact_ids: vec![],
        selected_fabric_source_digests: vec![],
    };
    let json = meta.to_json();
    assert_eq!(json["outcome"], "stale_miss");
    assert!(json.get("cache_key_digest").is_none() || json["cache_key_digest"].is_null());
}

// ═══════════════════════════════════════════════════════════════════
// publication_active_revision_accepts_public_traffic
// ═══════════════════════════════════════════════════════════════════

#[test]
fn revision_accepts_published_active() {
    assert!(publication_active_revision_accepts_public_traffic(
        "published",
        "active"
    ));
}

#[test]
fn revision_accepts_draining_draining() {
    assert!(publication_active_revision_accepts_public_traffic(
        "draining", "draining"
    ));
}

#[test]
fn revision_rejects_published_draining() {
    assert!(!publication_active_revision_accepts_public_traffic(
        "published",
        "draining"
    ));
}

#[test]
fn revision_case_insensitive() {
    assert!(publication_active_revision_accepts_public_traffic(
        "  Published  ",
        "  Active  "
    ));
}

// ═══════════════════════════════════════════════════════════════════
// gateway_identity_matches_candidate
// ═══════════════════════════════════════════════════════════════════

#[test]
fn identity_matches_via_registration_id() {
    assert!(gateway_identity_matches_candidate(
        "gw-1",
        Some("gw-1"),
        None
    ));
}

#[test]
fn identity_matches_via_gateway_id() {
    assert!(gateway_identity_matches_candidate(
        "gw-1",
        None,
        Some("gw-1")
    ));
}

#[test]
fn identity_no_match_different_ids() {
    assert!(!gateway_identity_matches_candidate(
        "gw-1",
        Some("gw-2"),
        Some("gw-3")
    ));
}

#[test]
fn identity_empty_candidate_no_match() {
    assert!(!gateway_identity_matches_candidate(
        "  ",
        Some("gw-1"),
        None
    ));
}

#[test]
fn identity_case_insensitive() {
    assert!(gateway_identity_matches_candidate(
        "GW-1",
        Some("gw-1"),
        None
    ));
}

// ═══════════════════════════════════════════════════════════════════
// evaluate_connected_cell_pool_admitted_members
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cell_pool_null_is_missing() {
    let result = evaluate_connected_cell_pool_admitted_members(&json!(null), Some("gw-1"), None);
    assert_eq!(result, ConnectedCellPoolAdmissionMatch::Missing);
}

#[test]
fn cell_pool_string_matched() {
    let result = evaluate_connected_cell_pool_admitted_members(&json!("gw-1"), Some("gw-1"), None);
    assert_eq!(result, ConnectedCellPoolAdmissionMatch::Matched);
}

#[test]
fn cell_pool_string_not_matched() {
    let result = evaluate_connected_cell_pool_admitted_members(&json!("gw-2"), Some("gw-1"), None);
    assert_eq!(result, ConnectedCellPoolAdmissionMatch::NotMatched);
}

#[test]
fn cell_pool_array_contains_match() {
    let result =
        evaluate_connected_cell_pool_admitted_members(&json!(["gw-2", "gw-1"]), Some("gw-1"), None);
    assert_eq!(result, ConnectedCellPoolAdmissionMatch::Matched);
}

#[test]
fn cell_pool_empty_array_not_matched() {
    let result = evaluate_connected_cell_pool_admitted_members(&json!([]), Some("gw-1"), None);
    assert_eq!(result, ConnectedCellPoolAdmissionMatch::NotMatched);
}

#[test]
fn cell_pool_object_with_identity_field() {
    let result = evaluate_connected_cell_pool_admitted_members(
        &json!({"runtime_registration_id": "gw-1", "admitted": true}),
        Some("gw-1"),
        None,
    );
    assert_eq!(result, ConnectedCellPoolAdmissionMatch::Matched);
}

#[test]
fn cell_pool_object_with_nested_members() {
    let result = evaluate_connected_cell_pool_admitted_members(
        &json!({"members": ["gw-1", "gw-2"]}),
        Some("gw-1"),
        None,
    );
    assert_eq!(result, ConnectedCellPoolAdmissionMatch::Matched);
}

#[test]
fn cell_pool_object_not_admitted() {
    let result = evaluate_connected_cell_pool_admitted_members(
        &json!({"runtime_registration_id": "gw-1", "admitted": false}),
        Some("gw-1"),
        None,
    );
    assert_eq!(result, ConnectedCellPoolAdmissionMatch::NotMatched);
}

#[test]
fn cell_pool_boolean_unsupported() {
    let result = evaluate_connected_cell_pool_admitted_members(&json!(true), Some("gw-1"), None);
    assert_eq!(result, ConnectedCellPoolAdmissionMatch::Unsupported);
}

// ═══════════════════════════════════════════════════════════════════
// active_revision_pool_membership_issue_for_gateway
// ═══════════════════════════════════════════════════════════════════

#[test]
fn pool_membership_no_issue_non_pool_class() {
    let result =
        active_revision_pool_membership_issue_for_gateway("managed", Some("gw-1"), None, None);
    assert!(result.is_none());
}

#[test]
fn pool_membership_identity_missing() {
    let result =
        active_revision_pool_membership_issue_for_gateway("connected_cell_pool", None, None, None);
    assert_eq!(result, Some("runtime_pool_identity_missing"));
}

#[test]
fn pool_membership_matched() {
    let members = json!(["gw-1"]);
    let result = active_revision_pool_membership_issue_for_gateway(
        "connected_cell_pool",
        Some("gw-1"),
        None,
        Some(&members),
    );
    assert!(result.is_none());
}

#[test]
fn pool_membership_not_matched() {
    let members = json!(["gw-2"]);
    let result = active_revision_pool_membership_issue_for_gateway(
        "connected_cell_pool",
        Some("gw-1"),
        None,
        Some(&members),
    );
    assert_eq!(result, Some("current_gateway_not_admitted"));
}

// ═══════════════════════════════════════════════════════════════════
// admitted_member_status_allows_public_traffic
// ═══════════════════════════════════════════════════════════════════

#[test]
fn admitted_member_all_true_allows() {
    let member = json!({"admitted": true, "healthy": true})
        .as_object()
        .unwrap()
        .clone();
    assert!(admitted_member_status_allows_public_traffic(&member));
}

#[test]
fn admitted_member_false_flag_blocks() {
    let member = json!({"admitted": false}).as_object().unwrap().clone();
    assert!(!admitted_member_status_allows_public_traffic(&member));
}

#[test]
fn admitted_member_bad_status_blocks() {
    let member = json!({"status": "suspended"}).as_object().unwrap().clone();
    assert!(!admitted_member_status_allows_public_traffic(&member));
}

#[test]
fn admitted_member_active_status_allows() {
    let member = json!({"status": "active"}).as_object().unwrap().clone();
    assert!(admitted_member_status_allows_public_traffic(&member));
}

#[test]
fn admitted_member_empty_object_allows() {
    let member = serde_json::Map::new();
    assert!(admitted_member_status_allows_public_traffic(&member));
}

// ═══════════════════════════════════════════════════════════════════
// sha256_prefixed
// ═══════════════════════════════════════════════════════════════════

#[test]
fn sha256_prefixed_starts_with_sha256() {
    let result = sha256_prefixed(b"hello world");
    assert!(result.starts_with("sha256:"));
    assert!(result.len() > 10);
}

#[test]
fn sha256_prefixed_deterministic() {
    let r1 = sha256_prefixed(b"test input");
    let r2 = sha256_prefixed(b"test input");
    assert_eq!(r1, r2);
}

#[test]
fn sha256_prefixed_different_for_different_input() {
    let r1 = sha256_prefixed(b"input a");
    let r2 = sha256_prefixed(b"input b");
    assert_ne!(r1, r2);
}

// ═══════════════════════════════════════════════════════════════════
// non_empty_str
// ═══════════════════════════════════════════════════════════════════

#[test]
fn non_empty_str_filters_empty() {
    assert_eq!(non_empty_str(Some("hello")), Some("hello"));
    assert_eq!(non_empty_str(Some("  ")), None);
    assert_eq!(non_empty_str(Some("")), None);
    assert_eq!(non_empty_str(None), None);
}

// ═══════════════════════════════════════════════════════════════════
// estimate_streaming_spend_usage
// ═══════════════════════════════════════════════════════════════════

#[test]
fn estimate_streaming_none_for_zero_tokens() {
    let body = Bytes::from(serde_json::to_vec(&json!({})).unwrap());
    assert!(estimate_streaming_spend_usage(&body, None, 0).is_none());
}

#[test]
fn estimate_streaming_with_output_text() {
    let body = Bytes::from(
            serde_json::to_vec(&json!({
                "messages": [{"role": "user", "content": "Hello, how are you doing today? Tell me about the weather."}]
            }))
            .unwrap(),
        );
    let usage = estimate_streaming_spend_usage(&body, Some("Fine thanks!"), 12);
    assert!(usage.is_some());
    let usage = usage.unwrap();
    assert!(usage.prompt_tokens > 0);
    assert!(usage.completion_tokens > 0);
}

// ═══════════════════════════════════════════════════════════════════
// estimate_prompt_only_spend_usage
// ═══════════════════════════════════════════════════════════════════

#[test]
fn estimate_prompt_only_with_messages() {
    let body = json!({
        "messages": [{"role": "user", "content": "Hello this is a test message with enough words to estimate tokens"}]
    });
    let usage = estimate_prompt_only_spend_usage(&body);
    if let Some(usage) = usage {
        assert!(usage.prompt_tokens > 0);
        assert_eq!(usage.completion_tokens, 0);
    }
}

#[test]
fn estimate_prompt_only_empty() {
    let body = json!({});
    assert!(estimate_prompt_only_spend_usage(&body).is_none());
}

// ═══════════════════════════════════════════════════════════════════
// resolve_target_model_entry_for_request
// ═══════════════════════════════════════════════════════════════════

#[test]
fn resolve_model_entry_with_pin() {
    let models = vec![
        make_model_entry("gpt-4", true),
        make_model_entry("gpt-3.5-turbo", true),
    ];
    let target = make_target_with_models("t1", "openai", "*", models);
    let entry = resolve_target_model_entry_for_request(&target, "gpt-3.5-turbo", Some("gpt-4"));
    assert_eq!(entry.unwrap().model_id, "gpt-4");
}

#[test]
fn resolve_model_entry_without_pin() {
    let models = vec![make_model_entry("gpt-4", true)];
    let target = make_target_with_models("t1", "openai", "*", models);
    let entry = resolve_target_model_entry_for_request(&target, "gpt-4", None);
    assert_eq!(entry.unwrap().model_id, "gpt-4");
}

#[test]
fn resolve_model_entry_empty_request() {
    let target = make_target("t1", "openai", "gpt-4");
    let entry = resolve_target_model_entry_for_request(&target, "", None);
    assert!(entry.is_none());
}

// ═══════════════════════════════════════════════════════════════════
// ingress_marks_managed_public_endpoint
// ═══════════════════════════════════════════════════════════════════

#[test]
fn ingress_marks_true_values() {
    for value in ["1", "true", "yes", "managed"] {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-verdictan-public-endpoint",
            HeaderValue::from_str(value).unwrap(),
        );
        assert!(
            ingress_marks_managed_public_endpoint(&headers),
            "should match for '{value}'"
        );
    }
}

#[test]
fn ingress_marks_false_for_unknown() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-public-endpoint",
        HeaderValue::from_static("no"),
    );
    assert!(!ingress_marks_managed_public_endpoint(&headers));
}

#[test]
fn ingress_marks_false_when_absent() {
    let headers = HeaderMap::new();
    assert!(!ingress_marks_managed_public_endpoint(&headers));
}

// ═══════════════════════════════════════════════════════════════════
// managed_public_endpoint_requested_region_group
// ═══════════════════════════════════════════════════════════════════

#[test]
fn requested_region_group_from_header() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-requested-region-group",
        HeaderValue::from_static("us-east"),
    );
    assert_eq!(
        managed_public_endpoint_requested_region_group(&headers),
        Some("us-east".to_string())
    );
}

#[test]
fn requested_region_group_none_when_empty() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-requested-region-group",
        HeaderValue::from_static("  "),
    );
    assert!(managed_public_endpoint_requested_region_group(&headers).is_none());
}

// ═══════════════════════════════════════════════════════════════════
// resolve_request_capability_metadata (integration of several fns)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn request_capability_metadata_from_target() {
    let target = make_target("t1", "openai", "gpt-4");
    let result = resolve_request_capability_metadata(&target, "gpt-4", None, None);
    assert!(result.is_some());
    let (model_id, _, _) = result.unwrap();
    assert_eq!(model_id, "gpt-4");
}

#[test]
fn request_capability_metadata_with_model_entry_features() {
    let models = vec![make_model_entry_with_features(
        "gpt-4-vision",
        vec!["vision", "tool_use"],
        true,
    )];
    let target = make_target_with_models("t1", "openai", "*", models);
    let result = resolve_request_capability_metadata(&target, "gpt-4-vision", None, None);
    let (model_id, features, _) = result.unwrap();
    assert_eq!(model_id, "gpt-4-vision");
    assert!(features.contains(&"vision".to_string()));
    assert!(features.contains(&"tool_use".to_string()));
}

// ═══════════════════════════════════════════════════════════════════
// ControlPlaneBudgetQueryCacheKey / ControlPlaneProviderBudgetQueryCacheKey
// ═══════════════════════════════════════════════════════════════════

#[test]
fn budget_cache_key_equality() {
    let key1 = ControlPlaneBudgetQueryCacheKey {
        org_id: "org-1".into(),
        target_type: "gateway".into(),
        target_id: Some("gw1".into()),
        team_id: None,
        user_id: None,
        key_id: Some("k1".into()),
    };
    let key2 = ControlPlaneBudgetQueryCacheKey {
        org_id: "org-1".into(),
        target_type: "gateway".into(),
        target_id: Some("gw1".into()),
        team_id: None,
        user_id: None,
        key_id: Some("k1".into()),
    };
    assert_eq!(key1, key2);

    let key3 = ControlPlaneBudgetQueryCacheKey {
        org_id: "org-1".into(),
        target_type: "gateway".into(),
        target_id: Some("gw1".into()),
        team_id: None,
        user_id: None,
        key_id: Some("k2".into()),
    };
    assert_ne!(key1, key3);
}

#[test]
fn provider_budget_cache_key_equality() {
    let key1 = ControlPlaneProviderBudgetQueryCacheKey {
        org_id: "org-1".into(),
        provider: "openai".into(),
        model: None,
        team_id: None,
        user_id: None,
        key_id: Some("k1".into()),
    };
    let key2 = ControlPlaneProviderBudgetQueryCacheKey {
        org_id: "org-1".into(),
        provider: "openai".into(),
        model: None,
        team_id: None,
        user_id: None,
        key_id: Some("k1".into()),
    };
    assert_eq!(key1, key2);
}

// ═══════════════════════════════════════════════════════════════════
// UsagePricingContext
// ═══════════════════════════════════════════════════════════════════

#[test]
fn usage_pricing_context_fields() {
    let ctx = UsagePricingContext {
        provider: "openai".into(),
        model: "gpt-4".into(),
        estimated_cost_usd: Some(0.05),
    };
    assert_eq!(ctx.provider, "openai");
    assert_eq!(ctx.model, "gpt-4");
    assert_eq!(ctx.estimated_cost_usd, Some(0.05));
}

// ═══════════════════════════════════════════════════════════════════
// SpendUsage
// ═══════════════════════════════════════════════════════════════════

#[test]
fn spend_usage_default() {
    let u = SpendUsage {
        prompt_tokens: 0,
        completion_tokens: 0,
        total_tokens: 0,
        cached_input_tokens: 0,
        prompt_cost: None,
        completion_cost: None,
        total_cost: None,
    };
    assert_eq!(u.total_tokens, 0);
}

// ═══════════════════════════════════════════════════════════════════
// TokenRecord deserialization
// ═══════════════════════════════════════════════════════════════════

#[test]
fn token_record_deserializes() {
    let json = json!({
        "id": "key-1",
        "current_spend": 5.0,
        "model_filter": ["gpt-4", "gpt-3.5"],
        "metadata": {"gateway_id": "gw-1"}
    });
    let record: TokenRecord = serde_json::from_value(json).unwrap();
    assert_eq!(record.id, "key-1");
    assert_eq!(record.model_filter, vec!["gpt-4", "gpt-3.5"]);
    assert!((record.current_spend - 5.0).abs() < 0.001);
}

#[test]
fn token_record_model_filter_single_string() {
    let json = json!({
        "id": "key-2",
        "current_spend": 0.0,
        "model_filter": "gpt-4"
    });
    let record: TokenRecord = serde_json::from_value(json).unwrap();
    assert_eq!(record.model_filter, vec!["gpt-4"]);
}

#[test]
fn token_record_model_filter_empty() {
    let json = json!({
        "id": "key-3",
        "current_spend": 0.0
    });
    let record: TokenRecord = serde_json::from_value(json).unwrap();
    assert!(record.model_filter.is_empty());
}

// ═══════════════════════════════════════════════════════════════════
// GatewayControlsPayload deserialization
// ═══════════════════════════════════════════════════════════════════

#[test]
fn gateway_controls_deserializes() {
    let json = json!({
        "fail_closed": true,
        "allowed_providers": ["openai"],
        "allowed_models": ["gpt-4"],
        "allowed_gateways": ["gw-1"],
        "disabled_providers": ["bad_provider"]
    });
    let controls: GatewayControlsPayload = serde_json::from_value(json).unwrap();
    assert!(controls.fail_closed);
    assert_eq!(controls.allowed_providers, vec!["openai"]);
    assert_eq!(controls.disabled_providers, vec!["bad_provider"]);
}

// ═══════════════════════════════════════════════════════════════════
// TokenValidationResponse deserialization
// ═══════════════════════════════════════════════════════════════════

#[test]
fn token_validation_response_full_deserialize() {
    let json = json!({
        "valid": true,
        "reason": null,
        "org_id": "org-1",
        "key_id": "key-1",
        "team_id": "team-1",
        "user_id": "user-1",
        "agent_id": "agent-1",
        "agent_gateway_group_id": "group-1",
        "attached_policy_ids": ["policy-1"],
        "entitlements": ["premium"],
        "depletion": {
            "max_budget": 100.0,
            "current_spend": 25.0,
            "remaining_budget": 75.0,
            "max_requests": 1000,
            "current_requests": 200,
            "remaining_requests": 800
        },
        "gateway_controls": {
            "fail_closed": false,
            "allowed_providers": ["openai"],
            "allowed_models": [],
            "allowed_gateways": []
        }
    });
    let resp: TokenValidationResponse = serde_json::from_value(json).unwrap();
    assert!(resp.valid);
    assert_eq!(resp.org_id.as_deref(), Some("org-1"));
    assert_eq!(resp.agent_id.as_deref(), Some("agent-1"));
    assert_eq!(resp.entitlements, vec!["premium"]);
    let depl = resp.depletion.as_ref().unwrap();
    assert_eq!(depl.max_budget, Some(100.0));
    assert_eq!(depl.current_requests, Some(200));
    let controls = resp.gateway_controls.as_ref().unwrap();
    assert_eq!(controls.allowed_providers, vec!["openai"]);
}

// ═══════════════════════════════════════════════════════════════════
// SpendLogPayload serialization
// ═══════════════════════════════════════════════════════════════════

#[test]
fn spend_log_payload_serialization() {
    let payload = SpendLogPayload {
        provider: "openai".into(),
        model: "gpt-4".into(),
        prompt_tokens: 100,
        completion_tokens: 50,
        total_tokens: 150,
        cached_input_tokens: 10,
        prompt_cost: 0.003,
        completion_cost: 0.006,
        cached_input_cost: 0.001,
        total_cost: 0.01,
        currency: "USD".into(),
        key_id: Some("key-1".into()),
        user_id: None,
        team_id: None,
        provider_target_id: Some("target-1".into()),
        model_id: Some("gpt-4".into()),
        requested_model: Some("gpt-4".into()),
        requested_provider: None,
        pricing_source: Some(PricingSource::Upstream),
        pricing_snapshot: None,
        metadata: json!({}),
        gateway_id: Some(Arc::from("gw-1")),
        configuration_id: None,
        configuration_version_id: None,
        agent_id: None,
        gateway_execution_session_id: None,
        execution_surface: None,
        usage_category: "gateway_llm".into(),
        request_bytes: 512,
        response_bytes: 1024,
        processing_units: 2,
        conversation_id: None,
        catalog_input_price: Some("0.00003".into()),
        catalog_output_price: Some("0.00006".into()),
        catalog_model_id: Some("gpt-4".into()),
        catalog_provider_id: Some("openai".into()),
        catalog_pricing_source: Some("catalog".into()),
    };
    let json = serde_json::to_value(&payload).unwrap();
    assert_eq!(json["provider"], "openai");
    assert_eq!(json["prompt_tokens"], 100);
    assert_eq!(json["usage_category"], "gateway_llm");
    assert_eq!(json["catalog_input_price"], "0.00003");
}
