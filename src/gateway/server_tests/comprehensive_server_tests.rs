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

// ═══════════════════════════════════════════════════════════════════════
// is_api_token
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn is_api_token_valid_prefix() {
    assert!(is_api_token("vdt_abc123"));
    assert!(is_api_token("vdt_live_secret_12345"));
}

#[test]
fn is_api_token_accepts_gateway_key_prefix() {
    assert!(is_api_token("vdt_gk_abc123"));
    assert!(is_api_token("vdt_gk_"));
}

#[test]
fn is_api_token_rejects_other_prefixes() {
    assert!(!is_api_token("sk_abc123"));
    assert!(!is_api_token("Bearer vdt_abc"));
    assert!(!is_api_token(""));
    assert!(!is_api_token("k"));
    assert!(!is_api_token("verdictan"));
}

#[test]
fn is_api_token_minimal_valid() {
    assert!(is_api_token("vdt_"));
}

// ═══════════════════════════════════════════════════════════════════════
// join_upstream / rewrite_upstream_path
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn join_upstream_basic() {
    assert_eq!(
        join_upstream("http://api.openai.com", "/v1/chat/completions"),
        "http://api.openai.com/v1/chat/completions"
    );
}

#[test]
fn join_upstream_strips_trailing_slash() {
    assert_eq!(
        join_upstream("http://api.openai.com/", "/v1/models"),
        "http://api.openai.com/v1/models"
    );
}

#[test]
fn join_upstream_strips_leading_slash_from_path() {
    assert_eq!(
        join_upstream("http://example.com", "v1/chat"),
        "http://example.com/v1/chat"
    );
}

#[test]
fn join_upstream_both_slashes() {
    assert_eq!(join_upstream("http://host/", "/path"), "http://host/path");
}

#[test]
fn rewrite_upstream_path_passthrough_non_github() {
    assert_eq!(
        rewrite_upstream_path("https://api.openai.com", "/v1/chat/completions"),
        "/v1/chat/completions"
    );
}

#[test]
fn rewrite_upstream_path_github_models_chat() {
    assert_eq!(
        rewrite_upstream_path(
            "https://models.inference.ai.azure.com",
            "/v1/chat/completions"
        ),
        "/inference/chat/completions"
    );
}

#[test]
fn rewrite_upstream_path_github_models_embeddings() {
    assert_eq!(
        rewrite_upstream_path("https://models.inference.ai.azure.com", "/v1/embeddings"),
        "/inference/embeddings"
    );
}

#[test]
fn rewrite_upstream_path_github_models_other_paths() {
    assert_eq!(
        rewrite_upstream_path("https://models.inference.ai.azure.com", "/v1/audio/speech"),
        "/v1/audio/speech"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// extract_bearer_token
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn extract_bearer_standard() {
    let mut h = HeaderMap::new();
    h.insert(header::AUTHORIZATION, "Bearer my_token".parse().unwrap());
    assert_eq!(extract_bearer_token(&h), Some("my_token".to_string()));
}

#[test]
fn extract_bearer_lowercase() {
    let mut h = HeaderMap::new();
    h.insert(header::AUTHORIZATION, "bearer my_token".parse().unwrap());
    assert_eq!(extract_bearer_token(&h), Some("my_token".to_string()));
}

#[test]
fn extract_bearer_trims() {
    let mut h = HeaderMap::new();
    h.insert(
        header::AUTHORIZATION,
        "Bearer   spaced_token  ".parse().unwrap(),
    );
    assert_eq!(extract_bearer_token(&h), Some("spaced_token".to_string()));
}

#[test]
fn extract_bearer_empty_value() {
    let mut h = HeaderMap::new();
    h.insert(header::AUTHORIZATION, "Bearer   ".parse().unwrap());
    assert_eq!(extract_bearer_token(&h), None);
}

#[test]
fn extract_bearer_no_prefix() {
    let mut h = HeaderMap::new();
    h.insert(header::AUTHORIZATION, "Basic abc".parse().unwrap());
    assert_eq!(extract_bearer_token(&h), None);
}

#[test]
fn extract_bearer_no_header() {
    assert_eq!(extract_bearer_token(&HeaderMap::new()), None);
}

// ═══════════════════════════════════════════════════════════════════════
// error_json
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn error_json_structure() {
    let result = error_json("Something failed", "server_error", "internal");
    assert_eq!(result["message"], "Something failed");
    assert_eq!(result["type"], "server_error");
    assert_eq!(result["code"], "internal");
    assert!(result["param"].is_null());
}

// ═══════════════════════════════════════════════════════════════════════
// verdictan_extension_json
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn verdictan_extension_json_basic() {
    let result = verdictan_extension_json("ALLOW", "ok", "1.0.0", "req-123", 42, None, None);
    let decision = &result["decision"];
    assert_eq!(decision["verdict"], "ALLOW");
    assert_eq!(decision["reason_code"], "ok");
    assert_eq!(decision["config_version"], "1.0.0");
    assert_eq!(decision["request_id"], "req-123");
    assert_eq!(decision["latency_ms"], 42);
}

#[test]
fn verdictan_extension_json_with_escalation() {
    let esc = json!({"action": "review"});
    let result = verdictan_extension_json(
        "ESCALATE",
        "review_required",
        "2.0.0",
        "req-456",
        100,
        Some(esc.clone()),
        None,
    );
    assert_eq!(result["escalation"], esc);
}

#[test]
fn verdictan_extension_json_with_redactions() {
    let red = json!({"applied": true, "entities": ["email"]});
    let result = verdictan_extension_json(
        "REDACT",
        "pii_detected",
        "1.0.0",
        "req-789",
        55,
        None,
        Some(red.clone()),
    );
    assert_eq!(result["redactions"], red);
}

// ═══════════════════════════════════════════════════════════════════════
// decision_event_id
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn decision_event_id_format() {
    assert_eq!(decision_event_id("req_abc"), "vdt_decision_req_abc");
    assert_eq!(decision_event_id("plain"), "vdt_decision_plain");
}

// ═══════════════════════════════════════════════════════════════════════
// runtime_error_id
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn runtime_error_id_strips_req_prefix() {
    assert_eq!(runtime_error_id("req_abc123"), "err_abc123");
}

#[test]
fn runtime_error_id_no_prefix() {
    assert_eq!(runtime_error_id("custom_id"), "err_custom_id");
}

// ═══════════════════════════════════════════════════════════════════════
// runtime_error_envelope
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn runtime_error_envelope_structure() {
    let result = runtime_error_envelope(
        StatusCode::BAD_REQUEST,
        "req_test",
        "request.validation_failed",
        "Bad input",
        json!({"field": "model"}),
    );
    let error = &result["error"];
    assert_eq!(error["status"], 400);
    assert_eq!(error["code"], "request.validation_failed");
    assert_eq!(error["message"], "Bad input");
    assert_eq!(error["details"]["field"], "model");
    assert_eq!(error["error_id"], "err_test");
    assert_eq!(error["request_id"], "req_test");
}

// ═══════════════════════════════════════════════════════════════════════
// RuntimePreflightError
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn runtime_preflight_error_validation_failed() {
    let e = RuntimePreflightError::validation_failed("invalid model", json!({"model": "x"}));
    assert_eq!(e.status, StatusCode::BAD_REQUEST);
    assert_eq!(e.code, "request.validation_failed");
    assert_eq!(e.message, "invalid model");
}

#[test]
fn runtime_preflight_error_custom() {
    let e = RuntimePreflightError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "Too many",
        json!({}),
    );
    assert_eq!(e.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(e.code, "rate_limited");
}

// ═══════════════════════════════════════════════════════════════════════
// BudgetFilterRejection constructors
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn budget_filter_rejection_forbidden() {
    let r = BudgetFilterRejection::forbidden("budget exceeded", "budget.exceeded");
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.error_type, "cost_budget_exceeded");
    assert_eq!(r.code, "budget.exceeded");
    assert_eq!(r.message, "budget exceeded");
}

#[test]
fn budget_filter_rejection_access_denied() {
    let r = BudgetFilterRejection::access_denied("not allowed", "access.denied");
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.error_type, "access_denied");
    assert_eq!(r.code, "access.denied");
}

#[test]
fn budget_filter_rejection_service_unavailable() {
    let r = BudgetFilterRejection::service_unavailable("down", "svc.down");
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.error_type, "service_unavailable");
    assert_eq!(r.code, "svc.down");
}

// ═══════════════════════════════════════════════════════════════════════
// build_budget_filter_body
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn build_budget_filter_body_valid_json() {
    let r = BudgetFilterRejection::forbidden("over budget", "budget.over");
    let body = build_budget_filter_body(&r);
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["error"]["message"], "over budget");
    assert_eq!(parsed["error"]["type"], "cost_budget_exceeded");
    assert_eq!(parsed["error"]["code"], "budget.over");
}

// ═══════════════════════════════════════════════════════════════════════
// access_inactive_status / access_inactive_message
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn access_inactive_status_cases() {
    assert_eq!(
        access_inactive_status("provider_key_policy_denied"),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        access_inactive_status("provider_key_no_policy_binding"),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        access_inactive_status("unsupported_provider"),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        access_inactive_status("unknown_reason"),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(access_inactive_status(""), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn access_inactive_message_variants() {
    let msg = access_inactive_message("provider_key_policy_denied", "target-1");
    assert!(msg.contains("target-1"));
    assert!(msg.contains("access denied"));

    let msg = access_inactive_message("provider_key_no_policy_binding", "t2");
    assert!(msg.contains("no provider-key policy binding"));

    let msg = access_inactive_message("provider_key_not_configured", "t3");
    assert!(msg.contains("not configured"));

    let msg = access_inactive_message("provider_key_seeded_default_deleted", "t4");
    assert!(msg.contains("seeded provider key was deleted"));

    let msg = access_inactive_message("unsupported_provider", "t5");
    assert!(msg.contains("unsupported"));

    let msg = access_inactive_message("custom_reason", "t7");
    assert!(msg.contains("custom_reason"));
}

// ═══════════════════════════════════════════════════════════════════════
// success_shape_valid_for_path
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn success_shape_audio_speech_always_valid() {
    assert!(success_shape_valid_for_path(
        "/v1/audio/speech",
        b"anything"
    ));
    assert!(success_shape_valid_for_path("/v1/audio/speech", b""));
}

#[test]
fn success_shape_chat_completions_valid() {
    let body = serde_json::to_vec(&json!({"choices": []})).unwrap();
    assert!(success_shape_valid_for_path("/v1/chat/completions", &body));
}

#[test]
fn success_shape_chat_completions_invalid_no_choices() {
    let body = serde_json::to_vec(&json!({"data": []})).unwrap();
    assert!(!success_shape_valid_for_path("/v1/chat/completions", &body));
}

#[test]
fn success_shape_responses_valid() {
    let body = serde_json::to_vec(&json!({"output": []})).unwrap();
    assert!(success_shape_valid_for_path("/v1/responses", &body));
}

#[test]
fn success_shape_responses_invalid() {
    let body = serde_json::to_vec(&json!({"result": "ok"})).unwrap();
    assert!(!success_shape_valid_for_path("/v1/responses", &body));
}

#[test]
fn success_shape_messages_valid() {
    let body = serde_json::to_vec(&json!({"content": [], "type": "message"})).unwrap();
    assert!(success_shape_valid_for_path("/v1/messages", &body));
}

#[test]
fn success_shape_messages_wrong_type() {
    let body = serde_json::to_vec(&json!({"content": [], "type": "error"})).unwrap();
    assert!(!success_shape_valid_for_path("/v1/messages", &body));
}

#[test]
fn success_shape_messages_missing_content() {
    let body = serde_json::to_vec(&json!({"type": "message"})).unwrap();
    assert!(!success_shape_valid_for_path("/v1/messages", &body));
}

#[test]
fn success_shape_unknown_path_always_valid() {
    let body = serde_json::to_vec(&json!({"anything": true})).unwrap();
    assert!(success_shape_valid_for_path("/v1/embeddings", &body));
}

#[test]
fn success_shape_invalid_json() {
    assert!(!success_shape_valid_for_path(
        "/v1/chat/completions",
        b"not json"
    ));
}

// ═══════════════════════════════════════════════════════════════════════
// extract_openai_chat_output
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn extract_openai_chat_output_single_choice() {
    let v = json!({"choices": [{"message": {"content": "Hello!"}}]});
    assert_eq!(extract_openai_chat_output(&v), Some("Hello!".to_string()));
}

#[test]
fn extract_openai_chat_output_multiple_choices() {
    let v = json!({"choices": [
        {"message": {"content": "First"}},
        {"message": {"content": "Second"}}
    ]});
    assert_eq!(
        extract_openai_chat_output(&v),
        Some("First\nSecond".to_string())
    );
}

#[test]
fn extract_openai_chat_output_empty_choices() {
    let v = json!({"choices": []});
    assert_eq!(extract_openai_chat_output(&v), None);
}

#[test]
fn extract_openai_chat_output_empty_content() {
    let v = json!({"choices": [{"message": {"content": "   "}}]});
    assert_eq!(extract_openai_chat_output(&v), None);
}

#[test]
fn extract_openai_chat_output_missing_choices() {
    let v = json!({"data": []});
    assert_eq!(extract_openai_chat_output(&v), None);
}

// ═══════════════════════════════════════════════════════════════════════
// extract_openai_responses_output
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn extract_openai_responses_output_string() {
    let v = json!({"output": "Direct text output"});
    assert_eq!(
        extract_openai_responses_output(&v),
        Some("Direct text output".to_string())
    );
}

#[test]
fn extract_openai_responses_output_array() {
    let v = json!({"output": [
        {"content": [{"type": "output_text", "text": "Result"}]}
    ]});
    assert_eq!(
        extract_openai_responses_output(&v),
        Some("Result".to_string())
    );
}

#[test]
fn extract_openai_responses_output_multiple_items() {
    let v = json!({"output": [
        {"content": [
            {"type": "output_text", "text": "First"},
            {"type": "output_text", "text": "Second"}
        ]}
    ]});
    assert_eq!(
        extract_openai_responses_output(&v),
        Some("First\nSecond".to_string())
    );
}

#[test]
fn extract_openai_responses_output_skips_non_text() {
    let v = json!({"output": [
        {"content": [
            {"type": "tool_call", "text": "skipped"},
            {"type": "output_text", "text": "kept"}
        ]}
    ]});
    assert_eq!(
        extract_openai_responses_output(&v),
        Some("kept".to_string())
    );
}

#[test]
fn extract_openai_responses_output_empty() {
    let v = json!({"output": []});
    assert_eq!(extract_openai_responses_output(&v), None);
}

#[test]
fn extract_openai_responses_output_whitespace_only() {
    let v = json!({"output": "   "});
    assert_eq!(extract_openai_responses_output(&v), None);
}

// ═══════════════════════════════════════════════════════════════════════
// regex_escape_literal
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn regex_escape_literal_plain() {
    assert_eq!(regex_escape_literal("hello"), "hello");
}

#[test]
fn regex_escape_literal_special_chars() {
    assert_eq!(regex_escape_literal("a.b"), "a\\.b");
    assert_eq!(regex_escape_literal("x*y"), "x\\*y");
    assert_eq!(regex_escape_literal("(foo)"), "\\(foo\\)");
    assert_eq!(regex_escape_literal("[bar]"), "\\[bar\\]");
    assert_eq!(regex_escape_literal("{baz}"), "\\{baz\\}");
    assert_eq!(regex_escape_literal("a|b"), "a\\|b");
    assert_eq!(regex_escape_literal("a\\b"), "a\\\\b");
    assert_eq!(regex_escape_literal("^$"), "\\^\\$");
    assert_eq!(regex_escape_literal("a+b?"), "a\\+b\\?");
}

#[test]
fn regex_escape_literal_trims() {
    assert_eq!(regex_escape_literal("  hello  "), "hello");
}

// ═══════════════════════════════════════════════════════════════════════
// extract_messages_from_value
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn extract_messages_basic() {
    let v = json!({"messages": [
        {"role": "user", "content": "Hi"},
        {"role": "assistant", "content": "Hello"}
    ]});
    let msgs = extract_messages_from_value(Some(&v));
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0].role, "user");
    assert_eq!(msgs[0].content, "Hi");
    assert_eq!(msgs[1].role, "assistant");
    assert_eq!(msgs[1].content, "Hello");
}

#[test]
fn extract_messages_none_input() {
    assert!(extract_messages_from_value(None).is_empty());
}

#[test]
fn extract_messages_missing_messages_key() {
    let v = json!({"data": []});
    assert!(extract_messages_from_value(Some(&v)).is_empty());
}

#[test]
fn extract_messages_skips_invalid_entries() {
    let v = json!({"messages": [
        {"role": "user", "content": "Valid"},
        {"role": "system"},
        {"content": "no role"},
        42
    ]});
    let msgs = extract_messages_from_value(Some(&v));
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].content, "Valid");
}

// ═══════════════════════════════════════════════════════════════════════
// verdictan_verdict_for_success
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn verdict_for_success_mapping() {
    assert_eq!(verdictan_verdict_for_success(&Verdict::Allow), "ALLOW");
    assert_eq!(verdictan_verdict_for_success(&Verdict::Redact), "REDACT");
    assert_eq!(verdictan_verdict_for_success(&Verdict::Block), "BLOCK");
    assert_eq!(
        verdictan_verdict_for_success(&Verdict::Escalate),
        "ESCALATE"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// inject_verdictan_response_extension / strip_verdictan_request_extension
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn inject_verdictan_extension_into_json() {
    let body = Bytes::from(serde_json::to_vec(&json!({"id": "resp-1"})).unwrap());
    let verdictan = json!({"decision": {"verdict": "ALLOW"}});
    let result = inject_verdictan_response_extension(body, verdictan.clone());
    let parsed: serde_json::Value = serde_json::from_slice(&result).unwrap();
    assert_eq!(parsed["id"], "resp-1");
    assert_eq!(parsed["verdictan"], verdictan);
}

#[test]
fn inject_verdictan_extension_non_json_passthrough() {
    let body = Bytes::from("not json");
    let verdictan = json!({"x": 1});
    let result = inject_verdictan_response_extension(body.clone(), verdictan);
    assert_eq!(result, body);
}

#[test]
fn strip_verdictan_request_extension_removes() {
    let mut v = json!({"model": "gpt-4", "verdictan": {"session": "s1"}});
    assert!(strip_verdictan_request_extension(&mut v));
    assert!(v.get("verdictan").is_none());
    assert_eq!(v["model"], "gpt-4");
}

#[test]
fn strip_verdictan_request_extension_no_key() {
    let mut v = json!({"model": "gpt-4"});
    assert!(!strip_verdictan_request_extension(&mut v));
}

#[test]
fn strip_verdictan_request_extension_non_object() {
    let mut v = json!("string");
    assert!(!strip_verdictan_request_extension(&mut v));
}

// ═══════════════════════════════════════════════════════════════════════
// filter_quality_scores_for_event
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn filter_quality_scores_includes_output_stats() {
    let scores = json!({
        "output_chars": 500,
        "sentence_count": 5,
        "min_output_chars": 100,
        "min_sentences": 2,
        "metrics": {"aggregate": 0.85, "faithfulness": 0.9}
    });
    let filtered = filter_quality_scores_for_event(&scores);
    assert_eq!(filtered["output_chars"], 500);
    assert_eq!(filtered["sentence_count"], 5);
    assert_eq!(filtered["min_output_chars"], 100);
    assert_eq!(filtered["min_sentences"], 2);
    assert_eq!(filtered["aggregate"], 0.85);
    assert_eq!(filtered["faithfulness"], 0.9);
}

#[test]
fn filter_quality_scores_renames_nli_to_accuracy() {
    let scores = json!({
        "output_chars": 0,
        "sentence_count": 0,
        "min_output_chars": 0,
        "min_sentences": 0,
        "metrics": {"nli_entailment": 0.75}
    });
    let filtered = filter_quality_scores_for_event(&scores);
    assert_eq!(filtered["accuracy"], 0.75);
    assert!(filtered.get("nli_entailment").is_none());
}

#[test]
fn filter_quality_scores_excludes_null_metrics() {
    let scores = json!({
        "output_chars": 10,
        "sentence_count": 1,
        "min_output_chars": 0,
        "min_sentences": 0,
        "metrics": {"aggregate": null, "relevancy": 0.5}
    });
    let filtered = filter_quality_scores_for_event(&scores);
    assert!(filtered.get("aggregate").is_none());
    assert_eq!(filtered["relevancy"], 0.5);
}

#[test]
fn filter_quality_scores_includes_judge_metadata() {
    let scores = json!({
        "output_chars": 0,
        "sentence_count": 0,
        "min_output_chars": 0,
        "min_sentences": 0,
        "metrics": {},
        "judge": {"model": "gpt-4", "rationale": "Good output"}
    });
    let filtered = filter_quality_scores_for_event(&scores);
    assert_eq!(filtered["judge"]["model"], "gpt-4");
}

// ═══════════════════════════════════════════════════════════════════════
// ratelimit_headers
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn ratelimit_headers_basic() {
    let hdrs = ratelimit_headers(100, 95, 60, None, None);
    assert_eq!(hdrs.len(), 3);
    assert_eq!(hdrs[0], ("x-ratelimit-limit-requests", "100".to_string()));
    assert_eq!(
        hdrs[1],
        ("x-ratelimit-remaining-requests", "95".to_string())
    );
    assert_eq!(hdrs[2], ("Retry-After", "60".to_string()));
}

#[test]
fn ratelimit_headers_with_tokens() {
    let hdrs = ratelimit_headers(50, 40, 30, Some(1000000), Some(999000));
    assert_eq!(hdrs.len(), 5);
    assert_eq!(hdrs[3], ("x-ratelimit-limit-tokens", "1000000".to_string()));
    assert_eq!(
        hdrs[4],
        ("x-ratelimit-remaining-tokens", "999000".to_string())
    );
}

// ═══════════════════════════════════════════════════════════════════════
// format_upstream_unreachable_message
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn format_upstream_unreachable_message_contains_details() {
    let msg = format_upstream_unreachable_message(
        "openai",
        "https://api.openai.com",
        &"connection refused",
    );
    assert!(msg.contains("openai"));
    assert!(msg.contains("https://api.openai.com"));
    assert!(msg.contains("connection refused"));
    assert!(msg.contains("Check:"));
}

// ═══════════════════════════════════════════════════════════════════════
// LocalBudgetTracker
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn local_budget_tracker_basic_reserve() {
    let tracker = LocalBudgetTracker::new(1.0, Some(0.01), Some(0.03), Some(10.0), None);
    let result = tracker.try_reserve(100, 100);
    assert!(result.is_ok());
    let cost = result.unwrap();
    assert!(cost > 0.0);
}

#[test]
fn local_budget_tracker_exhausted() {
    let tracker = LocalBudgetTracker::new(0.001, Some(0.01), Some(0.03), Some(10.0), None);
    let result = tracker.try_reserve(10000, 10000);
    assert!(result.is_err());
}

#[test]
fn local_budget_tracker_zero_cost_always_succeeds() {
    let tracker = LocalBudgetTracker::new(0.0, None, None, None, None);
    assert_eq!(tracker.try_reserve(100, 100), Ok(0.0));
}

#[test]
fn local_budget_tracker_credit_back() {
    let tracker = LocalBudgetTracker::new(1.0, Some(0.01), Some(0.03), Some(10.0), None);
    let cost = tracker.try_reserve(1000, 1000).unwrap();
    tracker.credit_back(cost);
    let second = tracker.try_reserve(1000, 1000);
    assert!(second.is_ok());
}

#[test]
fn local_budget_tracker_credit_back_zero_noop() {
    let tracker = LocalBudgetTracker::new(1.0, Some(0.01), None, None, None);
    tracker.credit_back(0.0);
    tracker.credit_back(-5.0);
}

#[test]
fn local_budget_tracker_has_pricing() {
    let with_input = LocalBudgetTracker::new(1.0, Some(0.01), None, None, None);
    assert!(with_input.has_pricing());

    let with_output = LocalBudgetTracker::new(1.0, None, Some(0.03), None, None);
    assert!(with_output.has_pricing());

    let without = LocalBudgetTracker::new(1.0, None, None, None, None);
    assert!(!without.has_pricing());
}

// ═══════════════════════════════════════════════════════════════════════
// ConnectedPostDispatchUsageSource
// ═══════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════
// normalize_text_scope_values / normalize_provider_scope_values
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn normalize_text_scope_values_deduplicates_and_sorts() {
    let input = vec![
        "b".to_string(),
        "a".to_string(),
        "b".to_string(),
        " ".to_string(),
    ];
    let result = normalize_text_scope_values(&input);
    assert_eq!(result, vec!["a", "b"]);
}

#[test]
fn normalize_text_scope_values_trims() {
    let input = vec!["  hello  ".to_string()];
    let result = normalize_text_scope_values(&input);
    assert_eq!(result, vec!["hello"]);
}

#[test]
fn normalize_text_scope_values_empty() {
    let result = normalize_text_scope_values(&[]);
    assert!(result.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════
// intersect_scope_values
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn intersect_scope_values_both_empty() {
    let result = intersect_scope_values(&[], &[], normalize_text_scope_values);
    assert!(result.is_empty());
}

#[test]
fn intersect_scope_values_first_only() {
    let a = vec!["x".to_string(), "y".to_string()];
    let result = intersect_scope_values(&a, &[], normalize_text_scope_values);
    assert_eq!(result, vec!["x", "y"]);
}

#[test]
fn intersect_scope_values_second_only() {
    let b = vec!["p".to_string(), "q".to_string()];
    let result = intersect_scope_values(&[], &b, normalize_text_scope_values);
    assert_eq!(result, vec!["p", "q"]);
}

#[test]
fn intersect_scope_values_intersection() {
    let a = vec!["x".to_string(), "y".to_string(), "z".to_string()];
    let b = vec!["y".to_string(), "z".to_string(), "w".to_string()];
    let result = intersect_scope_values(&a, &b, normalize_text_scope_values);
    assert_eq!(result, vec!["y", "z"]);
}

#[test]
fn intersect_scope_values_disjoint() {
    let a = vec!["x".to_string()];
    let b = vec!["y".to_string()];
    let result = intersect_scope_values(&a, &b, normalize_text_scope_values);
    assert!(result.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════
// token_current_spend / token_max_budget / token_current_requests / token_max_requests
// ═══════════════════════════════════════════════════════════════════════

fn make_token_record(current_spend: f64, max_budget: Option<f64>) -> TokenRecord {
    TokenRecord {
        id: "tok-1".into(),
        gateway_id: None,
        provider: None,
        model_filter: vec![],
        team_id: None,
        user_id: None,
        max_budget,
        current_spend,
        key_class: None,
        resource_id: None,
        resource_vrn: None,
        expires_at: None,
        metadata: json!({}),
        rate_limit_rpm: None,
    }
}

fn make_validation_response(depletion: Option<TokenDepletionState>) -> TokenValidationResponse {
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
        depletion,
        ip_restrictions: None,
        entitlements: vec![],
        history: None,
        created_by: None,
        key: None,
        gateway_controls: None,
        org_authz_version: None,
    }
}

#[test]
fn token_current_spend_from_depletion() {
    let key = make_token_record(5.0, Some(100.0));
    let validation = make_validation_response(Some(TokenDepletionState {
        current_spend: Some(7.5),
        ..Default::default()
    }));
    assert_eq!(token_current_spend(&key, &validation), 7.5);
}

#[test]
fn token_current_spend_falls_back_to_key() {
    let key = make_token_record(5.0, Some(100.0));
    let validation = make_validation_response(None);
    assert_eq!(token_current_spend(&key, &validation), 5.0);
}

#[test]
fn token_max_budget_from_depletion() {
    let key = make_token_record(0.0, Some(100.0));
    let validation = make_validation_response(Some(TokenDepletionState {
        max_budget: Some(200.0),
        ..Default::default()
    }));
    assert_eq!(token_max_budget(&key, &validation), Some(200.0));
}

#[test]
fn token_max_budget_falls_back_to_key() {
    let key = make_token_record(0.0, Some(100.0));
    let validation = make_validation_response(None);
    assert_eq!(token_max_budget(&key, &validation), Some(100.0));
}

#[test]
fn token_max_budget_none() {
    let key = make_token_record(0.0, None);
    let validation = make_validation_response(None);
    assert_eq!(token_max_budget(&key, &validation), None);
}

#[test]
fn token_current_requests_from_depletion() {
    let validation = make_validation_response(Some(TokenDepletionState {
        current_requests: Some(42),
        ..Default::default()
    }));
    assert_eq!(token_current_requests(&validation), 42);
}

#[test]
fn token_current_requests_defaults_to_zero() {
    let validation = make_validation_response(None);
    assert_eq!(token_current_requests(&validation), 0);
}

#[test]
fn token_max_requests_from_depletion() {
    let validation = make_validation_response(Some(TokenDepletionState {
        max_requests: Some(1000),
        ..Default::default()
    }));
    assert_eq!(token_max_requests(&validation), Some(1000));
}

#[test]
fn token_max_requests_none() {
    let validation = make_validation_response(None);
    assert_eq!(token_max_requests(&validation), None);
}

// ═══════════════════════════════════════════════════════════════════════
// parse_expiry_timestamp
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn parse_expiry_timestamp_valid() {
    let result = parse_expiry_timestamp(Some("2025-06-15T12:00:00Z"));
    assert!(result.is_some());
}

#[test]
fn parse_expiry_timestamp_invalid() {
    assert_eq!(parse_expiry_timestamp(Some("not a date")), None);
}

#[test]
fn parse_expiry_timestamp_none() {
    assert_eq!(parse_expiry_timestamp(None), None);
}

#[test]
fn parse_expiry_timestamp_with_offset() {
    let result = parse_expiry_timestamp(Some("2025-06-15T12:00:00+05:00"));
    assert!(result.is_some());
}

// ═══════════════════════════════════════════════════════════════════════
// validated_key_gateway_binding / validated_key_agent_binding
// ═══════════════════════════════════════════════════════════════════════

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
fn validated_key_gateway_binding_prefers_personal() {
    let meta = json!({"personal_gateway_id": "gw-1", "gateway_id": "gw-2"});
    assert_eq!(validated_key_gateway_binding(&meta), Some("gw-1"));
}

#[test]
fn validated_key_gateway_binding_empty_value() {
    let meta = json!({"personal_gateway_id": "  ", "gateway_id": ""});
    assert_eq!(validated_key_gateway_binding(&meta), None);
}

#[test]
fn validated_key_gateway_binding_missing() {
    let meta = json!({});
    assert_eq!(validated_key_gateway_binding(&meta), None);
}

#[test]
fn validated_key_agent_binding_present() {
    let meta = json!({"agent_id": "agent-abc"});
    assert_eq!(validated_key_agent_binding(&meta), Some("agent-abc"));
}

#[test]
fn validated_key_agent_binding_empty() {
    let meta = json!({"agent_id": "   "});
    assert_eq!(validated_key_agent_binding(&meta), None);
}

#[test]
fn validated_key_agent_binding_missing() {
    let meta = json!({});
    assert_eq!(validated_key_agent_binding(&meta), None);
}

// ═══════════════════════════════════════════════════════════════════════
// RequestFinopsContext helper methods
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn finops_has_token_identity_with_key_id() {
    let ctx = RequestFinopsContext {
        key_id: Some("key-1".into()),
        ..Default::default()
    };
    assert!(ctx.has_token_identity());
}

#[test]
fn finops_has_token_identity_empty_key_id() {
    let ctx = RequestFinopsContext {
        key_id: Some("  ".into()),
        ..Default::default()
    };
    assert!(!ctx.has_token_identity());
}

#[test]
fn finops_has_token_identity_none() {
    let ctx = RequestFinopsContext::default();
    assert!(!ctx.has_token_identity());
}

#[test]
fn finops_identity_context_json_with_all_fields() {
    let ctx = RequestFinopsContext {
        key_id: Some("key-1".into()),
        org_id: Some("org-1".into()),
        user_id: Some("user-1".into()),
        team_id: Some("team-1".into()),
        ..Default::default()
    };
    let result = ctx.identity_context_json().unwrap();
    assert_eq!(result["key_id"], "key-1");
    assert_eq!(result["org_id"], "org-1");
    assert_eq!(result["user_id"], "user-1");
    assert_eq!(result["team_id"], "team-1");
}

#[test]
fn finops_identity_context_json_none_when_empty() {
    let ctx = RequestFinopsContext::default();
    assert!(ctx.identity_context_json().is_none());
}

#[test]
fn finops_identity_context_json_with_only_org() {
    let ctx = RequestFinopsContext {
        org_id: Some("org-1".into()),
        ..Default::default()
    };
    assert!(ctx.identity_context_json().is_some());
}

#[test]
fn finops_context_selection_json_none_when_no_plan_hash() {
    let ctx = RequestFinopsContext::default();
    assert!(ctx.context_selection_json().is_none());
}

#[test]
fn finops_context_selection_json_none_when_empty_plan_hash() {
    let ctx = RequestFinopsContext {
        context_plan_hash: Some("   ".into()),
        ..Default::default()
    };
    assert!(ctx.context_selection_json().is_none());
}

#[test]
fn finops_context_selection_json_with_data() {
    let ctx = RequestFinopsContext {
        context_plan_hash: Some("hash-abc".into()),
        context_policy_version: Some(3),
        context_selected_item_ids: vec!["item-1".into()],
        context_citation_required_count: Some(2),
        context_max_tokens: Some(4096),
        context_estimated_tokens: Some(1500),
        context_injected_tokens: Some(1000),
        working_context_tokens: Some(500),
        ..Default::default()
    };
    let result = ctx.context_selection_json().unwrap();
    assert_eq!(result["plan_hash"], "hash-abc");
    assert_eq!(result["context_policy_version"], 3);
    assert_eq!(result["citation_required_count"], 2);
}

// ═══════════════════════════════════════════════════════════════════════
// GatewayRuntimeMetrics
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn runtime_metrics_increments_and_serializes() {
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

// ═══════════════════════════════════════════════════════════════════════
// ConnectedAccessPreflightOutcome readiness
// ═══════════════════════════════════════════════════════════════════════

fn test_preflight_response(
    status: &str,
) -> super::super::access_preflight::AccessPreflightResponse {
    serde_json::from_value(json!({
        "status": status,
        "status_reason": ""
    }))
    .unwrap()
}

#[test]
fn preflight_outcome_reports_ready_byok_status() {
    let outcome = ConnectedAccessPreflightOutcome {
        primary: test_preflight_response("ready_byok"),
        org_authz_version: None,
        local_budget_tracker: None,
    };
    assert_eq!(outcome.primary.status, "ready_byok");
}

#[test]
fn preflight_outcome_keeps_non_ready_status_unchanged() {
    let outcome = ConnectedAccessPreflightOutcome {
        primary: test_preflight_response("inactive"),
        org_authz_version: None,
        local_budget_tracker: None,
    };
    assert_eq!(outcome.primary.status, "inactive");
}

// ═══════════════════════════════════════════════════════════════════════
// spend_cost_breakdown
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn spend_cost_breakdown_from_usage_costs() {
    let usage = SpendUsage {
        prompt_tokens: 100,
        completion_tokens: 50,
        total_tokens: 150,
        cached_input_tokens: 0,
        prompt_cost: Some(0.01),
        completion_cost: Some(0.02),
        total_cost: Some(0.03),
    };
    let (prompt, completion, cached, total) = spend_cost_breakdown(usage, None);
    assert_eq!(prompt, 0.01);
    assert_eq!(completion, 0.02);
    assert_eq!(cached, 0.0);
    assert_eq!(total, 0.03);
}

#[test]
fn spend_cost_breakdown_infers_completion_from_total() {
    let usage = SpendUsage {
        prompt_tokens: 100,
        completion_tokens: 50,
        total_tokens: 150,
        cached_input_tokens: 0,
        prompt_cost: Some(0.01),
        completion_cost: None,
        total_cost: Some(0.05),
    };
    let (prompt, completion, _, total) = spend_cost_breakdown(usage, None);
    assert_eq!(prompt, 0.01);
    assert_eq!(completion, 0.04);
    assert_eq!(total, 0.05);
}

#[test]
fn spend_cost_breakdown_no_costs_no_pricing_returns_zeros() {
    let usage = SpendUsage {
        prompt_tokens: 100,
        completion_tokens: 50,
        total_tokens: 150,
        cached_input_tokens: 0,
        prompt_cost: None,
        completion_cost: None,
        total_cost: None,
    };
    let (prompt, completion, cached, total) = spend_cost_breakdown(usage, None);
    assert_eq!(prompt, 0.0);
    assert_eq!(completion, 0.0);
    assert_eq!(cached, 0.0);
    assert_eq!(total, 0.0);
}

// ═══════════════════════════════════════════════════════════════════════
// verdictan_headers
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn verdictan_headers_basic() {
    let hdrs = verdictan_headers("ALLOW", "ok", "1.0.0", 15, false, &[], None, false, None);
    let find = |name: &str| {
        hdrs.iter()
            .find(|(n, _)| n.as_str() == name)
            .map(|(_, v)| v.to_str().unwrap().to_string())
    };
    assert_eq!(find("x-verdictan-verdict"), Some("ALLOW".to_string()));
    assert_eq!(find("x-verdictan-reason-code"), Some("ok".to_string()));
    assert_eq!(
        find("x-verdictan-config-version"),
        Some("1.0.0".to_string())
    );
    assert_eq!(find("x-verdictan-latency-ms"), Some("15".to_string()));
    assert_eq!(
        find("x-verdictan-prompt-redacted"),
        Some("false".to_string())
    );
    assert_eq!(
        find("x-verdictan-response-redacted"),
        Some("false".to_string())
    );
    assert!(find("x-verdictan-degraded").is_none());
}

#[test]
fn verdictan_headers_degraded() {
    let hdrs = verdictan_headers("ALLOW", "ok", "1.0.0", 0, false, &[], None, true, None);
    let find = |name: &str| hdrs.iter().find(|(n, _)| n.as_str() == name);
    assert!(find("x-verdictan-degraded").is_some());
}

#[test]
fn verdictan_headers_prompt_redacted() {
    let hdrs = verdictan_headers("REDACT", "pii", "1.0.0", 0, true, &[], None, false, None);
    let find = |name: &str| {
        hdrs.iter()
            .find(|(n, _)| n.as_str() == name)
            .map(|(_, v)| v.to_str().unwrap().to_string())
    };
    assert_eq!(
        find("x-verdictan-prompt-redacted"),
        Some("true".to_string())
    );
}

#[test]
fn verdictan_headers_with_redactions() {
    let redactions = vec![
        super::super::redaction::VerdictanRedaction {
            kind: "email".to_string(),
            replacement: "[EMAIL]".to_string(),
            start: 0,
            end: 16,
            span_hash: "hash1".to_string(),
        },
        super::super::redaction::VerdictanRedaction {
            kind: "email".to_string(),
            replacement: "[EMAIL]".to_string(),
            start: 20,
            end: 34,
            span_hash: "hash2".to_string(),
        },
    ];
    let hdrs = verdictan_headers(
        "REDACT",
        "pii",
        "1.0.0",
        0,
        false,
        &redactions,
        None,
        false,
        None,
    );
    let find = |name: &str| {
        hdrs.iter()
            .find(|(n, _)| n.as_str() == name)
            .map(|(_, v)| v.to_str().unwrap().to_string())
    };
    assert_eq!(
        find("x-verdictan-response-redacted"),
        Some("true".to_string())
    );
    assert_eq!(find("x-verdictan-redaction-count"), Some("2".to_string()));
    assert_eq!(
        find("x-verdictan-redacted-entities"),
        Some("email".to_string())
    );
}

// ═══════════════════════════════════════════════════════════════════════
// inject_identity_headers_from_finops
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn inject_identity_headers_adds_missing() {
    let ctx = RequestFinopsContext {
        org_id: Some("org-1".into()),
        user_id: Some("user-1".into()),
        team_id: Some("team-1".into()),
        key_id: Some("key-1".into()),
        ..Default::default()
    };
    let mut headers = HeaderMap::new();
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
    let ctx = RequestFinopsContext {
        org_id: Some("org-new".into()),
        ..Default::default()
    };
    let mut headers = HeaderMap::new();
    headers.insert("X-Org-ID", "org-existing".parse().unwrap());
    inject_identity_headers_from_finops(&mut headers, Some(&ctx));
    assert_eq!(
        headers.get("X-Org-ID").unwrap().to_str().unwrap(),
        "org-new"
    );
}

#[test]
fn inject_identity_headers_skips_empty() {
    let ctx = RequestFinopsContext {
        org_id: Some("".into()),
        ..Default::default()
    };
    let mut headers = HeaderMap::new();
    inject_identity_headers_from_finops(&mut headers, Some(&ctx));
    assert!(headers.get("X-Org-ID").is_none());
}

#[test]
fn inject_identity_headers_none_finops() {
    let mut headers = HeaderMap::new();
    inject_identity_headers_from_finops(&mut headers, None);
    assert!(headers.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════
// policy_input_headers
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn policy_input_headers_strips_key_id_always() {
    let mut h = HeaderMap::new();
    h.insert("X-Key-ID", "spoofed".parse().unwrap());
    let result = policy_input_headers(&h, None);
    assert!(result.get("X-Key-ID").is_none());
}

#[test]
fn policy_input_headers_strips_identity_with_finops() {
    let ctx = RequestFinopsContext {
        org_id: Some("real-org".into()),
        ..Default::default()
    };
    let mut h = HeaderMap::new();
    h.insert("X-Org-ID", "spoofed-org".parse().unwrap());
    h.insert("X-User-ID", "spoofed-user".parse().unwrap());
    let result = policy_input_headers(&h, Some(&ctx));
    assert_eq!(
        result.get("X-Org-ID").unwrap().to_str().unwrap(),
        "real-org"
    );
    assert!(result.get("X-User-ID").is_none());
}

#[test]
fn policy_input_headers_preserves_identity_with_telemetry_only_finops() {
    let ctx = RequestFinopsContext {
        context_plan_hash: Some("plan-1".into()),
        work_reuse_mode: Some("replay".into()),
        ..Default::default()
    };
    let mut h = HeaderMap::new();
    h.insert("X-Key-ID", "spoofed-key".parse().unwrap());
    h.insert("X-Org-ID", "caller-org".parse().unwrap());
    h.insert("X-User-ID", "caller-user".parse().unwrap());
    h.insert("X-User-Role", "caller-role".parse().unwrap());
    let result = policy_input_headers(&h, Some(&ctx));
    assert!(result.get("X-Key-ID").is_none());
    assert_eq!(
        result.get("X-Org-ID").unwrap().to_str().unwrap(),
        "caller-org"
    );
    assert_eq!(
        result.get("X-User-ID").unwrap().to_str().unwrap(),
        "caller-user"
    );
    assert_eq!(
        result.get("X-User-Role").unwrap().to_str().unwrap(),
        "caller-role"
    );
}

#[test]
fn policy_input_headers_replaces_spoofed_identity_with_authoritative_finops() {
    let ctx = RequestFinopsContext {
        key_id: Some("real-key".into()),
        org_id: Some("real-org".into()),
        team_id: Some("real-team".into()),
        user_id: Some("real-user".into()),
        ..Default::default()
    };
    let mut h = HeaderMap::new();
    h.insert("X-Key-ID", "spoofed-key".parse().unwrap());
    h.insert("X-Org-ID", "spoofed-org".parse().unwrap());
    h.insert("X-Team-ID", "spoofed-team".parse().unwrap());
    h.insert("X-User-ID", "spoofed-user".parse().unwrap());
    h.insert("X-User-Role", "spoofed-role".parse().unwrap());
    h.insert("X-Custom", "value".parse().unwrap());
    let result = policy_input_headers(&h, Some(&ctx));
    assert_eq!(
        result.get("X-Key-ID").unwrap().to_str().unwrap(),
        "real-key"
    );
    assert_eq!(
        result.get("X-Org-ID").unwrap().to_str().unwrap(),
        "real-org"
    );
    assert_eq!(
        result.get("X-Team-ID").unwrap().to_str().unwrap(),
        "real-team"
    );
    assert_eq!(
        result.get("X-User-ID").unwrap().to_str().unwrap(),
        "real-user"
    );
    assert!(result.get("X-User-Role").is_none());
    assert_eq!(result.get("X-Custom").unwrap().to_str().unwrap(), "value");
}

#[test]
fn policy_input_headers_preserves_non_identity() {
    let mut h = HeaderMap::new();
    h.insert("X-Custom", "value".parse().unwrap());
    let result = policy_input_headers(&h, None);
    assert_eq!(result.get("X-Custom").unwrap().to_str().unwrap(), "value");
}

// ═══════════════════════════════════════════════════════════════════════
// build_request_error_response
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn build_request_error_response_structure() {
    let resp = build_request_error_response(
        StatusCode::UNAUTHORIZED,
        "req-123",
        "tp-456",
        "Authentication required",
        "auth_error",
        "missing_api_key",
    );
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers()
            .get("x-request-id")
            .unwrap()
            .to_str()
            .unwrap(),
        "req-123"
    );
    assert_eq!(
        resp.headers().get("traceparent").unwrap().to_str().unwrap(),
        "tp-456"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// deserialize_token_model_filters (via JSON)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn deserialize_model_filters_single_string() {
    let json = r#"{"id":"t","current_spend":0,"model_filter":"gpt-4"}"#;
    let record: TokenRecord = serde_json::from_str(json).unwrap();
    assert_eq!(record.model_filter, vec!["gpt-4"]);
}

#[test]
fn deserialize_model_filters_array() {
    let json = r#"{"id":"t","current_spend":0,"model_filter":["gpt-4","claude-3"]}"#;
    let record: TokenRecord = serde_json::from_str(json).unwrap();
    assert_eq!(record.model_filter, vec!["gpt-4", "claude-3"]);
}

#[test]
fn deserialize_model_filters_null() {
    let json = r#"{"id":"t","current_spend":0,"model_filter":null}"#;
    let record: TokenRecord = serde_json::from_str(json).unwrap();
    assert!(record.model_filter.is_empty());
}

#[test]
fn deserialize_model_filters_empty_string() {
    let json = r#"{"id":"t","current_spend":0,"model_filter":"  "}"#;
    let record: TokenRecord = serde_json::from_str(json).unwrap();
    assert!(record.model_filter.is_empty());
}

#[test]
fn deserialize_model_filters_trims_array_entries() {
    let json = r#"{"id":"t","current_spend":0,"model_filter":["  gpt-4  ", ""]}"#;
    let record: TokenRecord = serde_json::from_str(json).unwrap();
    assert_eq!(record.model_filter, vec!["gpt-4"]);
}

// ═══════════════════════════════════════════════════════════════════════
// merged_token_scopes
// ═══════════════════════════════════════════════════════════════════════

fn make_token_for_scopes(
    gateway_id: Option<&str>,
    provider: Option<&str>,
    model_filter: Vec<&str>,
) -> TokenRecord {
    TokenRecord {
        id: "t-1".into(),
        gateway_id: gateway_id.map(Into::into),
        provider: provider.map(Into::into),
        model_filter: model_filter.into_iter().map(Into::into).collect(),
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

#[test]
fn merged_token_scopes_no_policy_no_binding() {
    let key = make_token_for_scopes(None, None, vec![]);
    let result = merged_token_scopes(&key, None, &[]).unwrap();
    assert_eq!(result, EffectiveTokenScopes::default());
}

#[test]
fn merged_token_scopes_key_binding_only() {
    let key = make_token_for_scopes(Some("gw-1"), Some("openai"), vec!["gpt-4"]);
    let result = merged_token_scopes(&key, None, &[]).unwrap();
    assert_eq!(result.allowed_gateways, vec!["gw-1"]);
    assert!(!result.allowed_providers.is_empty());
    assert_eq!(result.allowed_models, vec!["gpt-4"]);
}

#[test]
fn merged_token_scopes_errors_when_policies_without_controls() {
    let key = make_token_for_scopes(None, None, vec![]);
    let result = merged_token_scopes(&key, None, &["policy-1".into()]);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        TokenScopeMergeError::PolicyResolutionFailed
    );
}

#[test]
fn merged_token_scopes_intersects_binding_and_policy() {
    let key = make_token_for_scopes(None, None, vec!["gpt-4", "claude-3"]);
    let controls = GatewayControlsPayload {
        fail_closed: false,
        allowed_providers: vec![],
        allowed_models: vec!["gpt-4".into(), "gpt-5".into()],
        allowed_gateways: vec![],
        disabled_providers: vec![],
    };
    let result = merged_token_scopes(&key, Some(&controls), &["p1".into()]).unwrap();
    assert_eq!(result.allowed_models, vec!["gpt-4"]);
}

#[test]
fn merged_token_scopes_rejects_conflicting_gateway_governance() {
    let key = make_token_for_scopes(Some("gw-eu-primary"), Some("openai"), vec!["gpt-5.4-mini"]);
    let controls = GatewayControlsPayload {
        fail_closed: false,
        allowed_providers: vec!["openai".into()],
        allowed_models: vec!["gpt-5.4-mini".into()],
        allowed_gateways: vec!["gw-us-secondary".into()],
        disabled_providers: vec![],
    };

    let result = merged_token_scopes(&key, Some(&controls), &["p1".into()]);
    assert_eq!(result, Err(TokenScopeMergeError::GovernedScopeConflict));
}

// ═══════════════════════════════════════════════════════════════════════
// PricingSource serialization
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn pricing_source_serializes_snake_case() {
    assert_eq!(
        serde_json::to_value(PricingSource::Upstream).unwrap(),
        "upstream"
    );
    assert_eq!(
        serde_json::to_value(PricingSource::ConfigDeclared).unwrap(),
        "config_declared"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// SpendLogPayload serialization basics
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn spend_log_payload_default_usage_category() {
    let payload = SpendLogPayload {
        provider: "test".into(),
        model: "m".into(),
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
        usage_category: default_usage_category_cli(),
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
    let j = serde_json::to_value(&payload).unwrap();
    assert_eq!(j["usage_category"], "gateway_llm");
    assert!(j.get("conversation_id").is_none());
    assert!(j.get("catalog_input_price").is_none());
}

// ═══════════════════════════════════════════════════════════════════════
// TokenValidationError Display
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn token_validation_error_display_unauthorized() {
    let e = TokenValidationError::Unauthorized {
        body: "bad token".into(),
    };
    let msg = format!("{e}");
    assert!(msg.contains("unauthorized"));
    assert!(msg.contains("bad token"));
}

#[test]
fn token_validation_error_display_forbidden() {
    let e = TokenValidationError::Forbidden {
        body: "denied".into(),
    };
    let msg = format!("{e}");
    assert!(msg.contains("forbidden"));
    assert!(msg.contains("denied"));
}

#[test]
fn token_validation_error_display_unexpected_status() {
    let e = TokenValidationError::UnexpectedStatus {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        body: "oops".into(),
    };
    let msg = format!("{e}");
    assert!(msg.contains("500"));
    assert!(msg.contains("oops"));
}

// ═══════════════════════════════════════════════════════════════════════
// missing_provider_registry_message
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn missing_provider_registry_message_connected() {
    let msg = missing_provider_registry_message(true);
    assert!(msg.contains("no configuration is currently deployed"));
}

#[test]
fn missing_provider_registry_message_disconnected() {
    let msg = missing_provider_registry_message(false);
    assert!(msg.contains("no provider registry configured"));
}

// ═══════════════════════════════════════════════════════════════════════
// is_optional_control_plane_capability_failure
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn optional_cp_failure_not_found() {
    assert!(is_optional_control_plane_capability_failure(
        StatusCode::NOT_FOUND,
        ""
    ));
}

#[test]
fn optional_cp_failure_forbidden_insufficient() {
    assert!(is_optional_control_plane_capability_failure(
        StatusCode::FORBIDDEN,
        r#"{"code":"auth.insufficient_permissions"}"#,
    ));
}

#[test]
fn optional_cp_failure_forbidden_admin_surface() {
    assert!(is_optional_control_plane_capability_failure(
        StatusCode::FORBIDDEN,
        r#"{"code":"auth.admin_surface_required"}"#,
    ));
}

#[test]
fn optional_cp_failure_other_forbidden() {
    assert!(!is_optional_control_plane_capability_failure(
        StatusCode::FORBIDDEN,
        r#"{"code":"other"}"#,
    ));
}

#[test]
fn optional_cp_failure_server_error() {
    assert!(!is_optional_control_plane_capability_failure(
        StatusCode::INTERNAL_SERVER_ERROR,
        "",
    ));
}

// ═══════════════════════════════════════════════════════════════════════
// normalize_provider_alias_list
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn normalize_provider_alias_list_deduplicates() {
    let input = vec![
        "OpenAI".to_string(),
        "openai".to_string(),
        "Anthropic".to_string(),
    ];
    let result = normalize_provider_alias_list(&input);
    assert!(
        result.contains(&"openai".to_string())
            || result.iter().any(|v| v.eq_ignore_ascii_case("openai"))
    );
    assert!(result.len() <= input.len());
}

// ═══════════════════════════════════════════════════════════════════════
// verdictan_redactions_json
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn verdictan_redactions_json_empty() {
    let result = verdictan_redactions_json(&[]);
    assert_eq!(result["applied"], false);
    assert_eq!(result["entities"], json!([]));
    assert_eq!(result["count_by_type"], json!({}));
}

#[test]
fn verdictan_redactions_json_with_items() {
    let items = vec![
        super::super::redaction::VerdictanRedaction {
            kind: "email".to_string(),
            replacement: "[EMAIL]".to_string(),
            start: 0,
            end: 7,
            span_hash: "h1".to_string(),
        },
        super::super::redaction::VerdictanRedaction {
            kind: "phone".to_string(),
            replacement: "[PHONE]".to_string(),
            start: 10,
            end: 18,
            span_hash: "h2".to_string(),
        },
        super::super::redaction::VerdictanRedaction {
            kind: "email".to_string(),
            replacement: "[EMAIL]".to_string(),
            start: 20,
            end: 27,
            span_hash: "h3".to_string(),
        },
    ];
    let result = verdictan_redactions_json(&items);
    assert_eq!(result["applied"], true);
    let entities = result["entities"].as_array().unwrap();
    assert!(entities.contains(&json!("email")));
    assert!(entities.contains(&json!("phone")));
    assert_eq!(result["count_by_type"]["email"], 2);
    assert_eq!(result["count_by_type"]["phone"], 1);
}

// ═══════════════════════════════════════════════════════════════════════
// CacheReplayMetadata::to_json
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cache_replay_metadata_to_json() {
    let meta = CacheReplayMetadata {
        outcome: CacheReplayOutcome::ExactHit,
        cache_tier: CacheTier::OrgShared,
        cache_key_digest: Some("sha256:abc".into()),
        selected_fabric_artifact_ids: vec!["art-1".into()],
        selected_fabric_source_digests: vec!["digest-1".into()],
    };
    let j = meta.to_json();
    assert_eq!(j["outcome"], "exact_hit");
    assert_eq!(j["cache_tier"], "org_shared_cache");
    assert_eq!(j["cache_key_digest"], "sha256:abc");
    assert_eq!(j["selected_fabric_artifact_ids"], json!(["art-1"]));
}

// ═══════════════════════════════════════════════════════════════════════
// prepend_openai_output_in_place
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn prepend_openai_output_choices() {
    let mut v = json!({"choices": [{"message": {"content": "world"}}]});
    assert!(prepend_openai_output_in_place(&mut v, "Hello "));
    assert_eq!(v["choices"][0]["message"]["content"], "Hello world");
}

#[test]
fn prepend_openai_output_responses_format() {
    let mut v = json!({"output": [{"content": [{"type": "output_text", "text": "world"}]}]});
    assert!(prepend_openai_output_in_place(&mut v, "Hello "));
    assert_eq!(v["output"][0]["content"][0]["text"], "Hello world");
}

#[test]
fn prepend_openai_output_no_content() {
    let mut v = json!({"data": "x"});
    assert!(!prepend_openai_output_in_place(&mut v, "prefix"));
}

// ═══════════════════════════════════════════════════════════════════════
// inject_review_result_into_event / inject_review_result_into_payload
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn inject_review_result_into_event_adds_to_details() {
    let mut event = json!({"details": {}});
    let review = json!({"verdict": "ALLOW"});
    inject_review_result_into_event(&mut event, &review);
    assert_eq!(event["details"]["review_result"]["verdict"], "ALLOW");
}

#[test]
fn inject_review_result_into_event_creates_details() {
    let mut event = json!({});
    let review = json!({"verdict": "BLOCK"});
    inject_review_result_into_event(&mut event, &review);
    assert_eq!(event["details"]["review_result"]["verdict"], "BLOCK");
}

#[test]
fn inject_review_result_into_event_non_object() {
    let mut event = json!("not an object");
    inject_review_result_into_event(&mut event, &json!({}));
    assert_eq!(event, json!("not an object"));
}

// ═══════════════════════════════════════════════════════════════════════
// append_cache_status_header
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn append_cache_status_header_hit() {
    let mut headers = Vec::new();
    append_cache_status_header(&mut headers, true);
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].0.as_str(), "x-cache-status");
    assert_eq!(headers[0].1.to_str().unwrap(), "hit");
}

#[test]
fn append_cache_status_header_miss() {
    let mut headers = Vec::new();
    append_cache_status_header(&mut headers, false);
    assert_eq!(headers[0].1.to_str().unwrap(), "miss");
}

#[test]
fn append_cache_status_header_replaces_existing() {
    let mut headers = vec![(
        axum::http::HeaderName::from_static("x-cache-status"),
        HeaderValue::from_static("old"),
    )];
    append_cache_status_header(&mut headers, true);
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].1.to_str().unwrap(), "hit");
}

// ═══════════════════════════════════════════════════════════════════════
// redact_request_messages
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn redact_request_messages_no_messages_key() {
    let cfg = super::super::redaction::RedactionConfig::default();
    let mut v = json!({"model": "gpt-4"});
    assert!(!redact_request_messages(&mut v, &cfg));
}

#[test]
fn redact_request_messages_no_string_content() {
    let cfg = super::super::redaction::RedactionConfig::default();
    let mut v = json!({"messages": [{"role": "user", "content": 42}]});
    assert!(!redact_request_messages(&mut v, &cfg));
}

// ═══════════════════════════════════════════════════════════════════════
// build_response (via build_request_error_response)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn build_response_sets_standard_headers() {
    let resp = build_response(
        StatusCode::OK,
        HeaderValue::from_static("application/json"),
        "req-test".to_string(),
        "tp-test".to_string(),
        Bytes::from("{}"),
        false,
        None,
    );
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/json"
    );
    assert_eq!(resp.headers().get("x-request-id").unwrap(), "req-test");
    assert_eq!(resp.headers().get("traceparent").unwrap(), "tp-test");
    assert!(resp.headers().get("x-verdictan-degraded").is_none());
}

#[test]
fn build_response_degraded_flag() {
    let resp = build_response(
        StatusCode::OK,
        HeaderValue::from_static("text/plain"),
        "r".to_string(),
        "t".to_string(),
        Bytes::from(""),
        true,
        None,
    );
    assert_eq!(resp.headers().get("x-verdictan-degraded").unwrap(), "true");
}

#[test]
fn build_response_extra_headers() {
    let extra = vec![(
        axum::http::HeaderName::from_static("x-custom"),
        HeaderValue::from_static("val"),
    )];
    let resp = build_response(
        StatusCode::OK,
        HeaderValue::from_static("application/json"),
        "r".to_string(),
        "t".to_string(),
        Bytes::from("{}"),
        false,
        Some(extra),
    );
    assert_eq!(resp.headers().get("x-custom").unwrap(), "val");
}

// ═══════════════════════════════════════════════════════════════════════
// EffectiveTokenScopes Default
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn effective_token_scopes_default_is_empty() {
    let scopes = EffectiveTokenScopes::default();
    assert!(scopes.allowed_providers.is_empty());
    assert!(scopes.allowed_models.is_empty());
    assert!(scopes.allowed_gateways.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════
// ConnectedAccessRequestStatus
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn connected_access_request_status_default() {
    let status = ConnectedAccessRequestStatus::default();
    assert_eq!(status.admission_credential_source, None);
    assert!(!status.dispatch_precluded);
}

// ═══════════════════════════════════════════════════════════════════════
// publication_state_accepts_public_traffic
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn publication_state_accepts_published() {
    assert!(publication_state_accepts_public_traffic("published"));
}

#[test]
fn publication_state_accepts_draining() {
    assert!(publication_state_accepts_public_traffic("draining"));
}

#[test]
fn publication_state_rejects_other() {
    assert!(!publication_state_accepts_public_traffic("active"));
    assert!(!publication_state_accepts_public_traffic("disabled"));
    assert!(!publication_state_accepts_public_traffic("pending"));
    assert!(!publication_state_accepts_public_traffic(""));
}

// ═══════════════════════════════════════════════════════════════════════
// non_empty_str
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn non_empty_str_some_value() {
    assert_eq!(non_empty_str(Some("hello")), Some("hello"));
}

#[test]
fn non_empty_str_empty() {
    assert_eq!(non_empty_str(Some("")), None);
}

#[test]
fn non_empty_str_none() {
    assert_eq!(non_empty_str(None), None);
}

// ═══════════════════════════════════════════════════════════════════════
// extract_request_team_slugs
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn extract_request_team_slugs_from_header() {
    let mut h = HeaderMap::new();
    h.insert("x-verdictan-team", "team-a,team-b".parse().unwrap());
    let slugs = extract_request_team_slugs(&h);
    assert!(slugs.contains(&"team-a".to_string()));
    assert!(slugs.contains(&"team-b".to_string()));
}

#[test]
fn extract_request_team_slugs_trims_and_filters_empty() {
    let mut h = HeaderMap::new();
    h.insert("x-verdictan-team", " team-a , team-a , ".parse().unwrap());
    let slugs = extract_request_team_slugs(&h);
    assert_eq!(slugs.len(), 2);
    assert_eq!(slugs[0], "team-a");
    assert_eq!(slugs[1], "team-a");
}

#[test]
fn extract_request_team_slugs_empty_header() {
    let h = HeaderMap::new();
    assert!(extract_request_team_slugs(&h).is_empty());
}

// ═══════════════════════════════════════════════════════════════════════
// ingress_marks_managed_public_endpoint
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn ingress_marks_managed_public_endpoint_with_header() {
    let mut h = HeaderMap::new();
    h.insert("x-verdictan-public-endpoint", "true".parse().unwrap());
    assert!(ingress_marks_managed_public_endpoint(&h));
}

#[test]
fn ingress_marks_managed_public_endpoint_missing() {
    assert!(!ingress_marks_managed_public_endpoint(&HeaderMap::new()));
}

// ═══════════════════════════════════════════════════════════════════════
// normalize_managed_public_endpoint_host
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn normalize_managed_host_valid() {
    assert_eq!(
        normalize_managed_public_endpoint_host("MyGateway.verdictan.ai"),
        Some("mygateway.verdictan.ai".to_string())
    );
}

#[test]
fn normalize_managed_host_trims() {
    assert_eq!(
        normalize_managed_public_endpoint_host("  host.example.com  "),
        Some("host.example.com".to_string())
    );
}

#[test]
fn normalize_managed_host_empty() {
    assert_eq!(normalize_managed_public_endpoint_host(""), None);
    assert_eq!(normalize_managed_public_endpoint_host("   "), None);
}

// ═══════════════════════════════════════════════════════════════════════
// managed_public_endpoint_host / managed_public_endpoint_requested_region_group
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn managed_public_endpoint_host_from_headers() {
    let mut h = HeaderMap::new();
    h.insert(
        "x-verdictan-public-hostname",
        "my.host.com".parse().unwrap(),
    );
    assert_eq!(
        managed_public_endpoint_host(&h),
        Some("my.host.com".to_string())
    );
}

#[test]
fn managed_public_endpoint_host_missing() {
    assert_eq!(managed_public_endpoint_host(&HeaderMap::new()), None);
}

#[test]
fn managed_public_endpoint_requested_region_group_from_headers() {
    let mut h = HeaderMap::new();
    h.insert(
        "x-verdictan-requested-region-group",
        "eu-west".parse().unwrap(),
    );
    assert_eq!(
        managed_public_endpoint_requested_region_group(&h),
        Some("eu-west".to_string())
    );
}
