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

// ── extract_messages_for_responses ──────────────────────────────────

#[test]
fn responses_input_string_extracts_single_user_message() {
    let v = json!({"input": "Hello world"});
    let msgs = extract_messages_for_responses(Some(&v));
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].role, "user");
    assert_eq!(msgs[0].content, "Hello world");
}

#[test]
fn responses_input_string_whitespace_only_returns_empty() {
    let v = json!({"input": "   "});
    let msgs = extract_messages_for_responses(Some(&v));
    assert!(msgs.is_empty());
}

#[test]
fn responses_input_array_of_strings() {
    let v = json!({"input": ["first", "second"]});
    let msgs = extract_messages_for_responses(Some(&v));
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0].content, "first");
    assert_eq!(msgs[1].content, "second");
}

#[test]
fn responses_input_array_of_objects_with_roles() {
    let v = json!({"input": [
        {"role": "system", "content": "You are helpful"},
        {"role": "user", "content": "Hi"}
    ]});
    let msgs = extract_messages_for_responses(Some(&v));
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0].role, "system");
    assert_eq!(msgs[1].role, "user");
}

#[test]
fn responses_input_array_mixed_strings_and_objects() {
    let v = json!({"input": [
        "raw string",
        {"role": "assistant", "content": "response"}
    ]});
    let msgs = extract_messages_for_responses(Some(&v));
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0].role, "user");
    assert_eq!(msgs[1].role, "assistant");
}

#[test]
fn responses_input_none() {
    assert!(extract_messages_for_responses(None).is_empty());
}

#[test]
fn responses_prefers_messages_over_input() {
    let v = json!({
        "messages": [{"role": "user", "content": "from messages"}],
        "input": "from input"
    });
    let msgs = extract_messages_for_responses(Some(&v));
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].content, "from messages");
}

#[test]
fn responses_input_array_skips_whitespace_only_strings() {
    let v = json!({"input": ["  ", "valid"]});
    let msgs = extract_messages_for_responses(Some(&v));
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].content, "valid");
}

#[test]
fn responses_input_object_without_role_defaults_to_user() {
    let v = json!({"input": [{"content": "no role"}]});
    let msgs = extract_messages_for_responses(Some(&v));
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].role, "user");
}

// ── replace_openai_chat_output_in_place ─────────────────────────────

#[test]
fn replace_chat_output_single_choice() {
    let mut v = json!({"choices": [{"message": {"content": "original"}}]});
    assert!(replace_openai_chat_output_in_place(&mut v, "replaced"));
    assert_eq!(v["choices"][0]["message"]["content"], "replaced");
}

#[test]
fn replace_chat_output_multiple_choices() {
    let mut v = json!({"choices": [
        {"message": {"content": "a"}},
        {"message": {"content": "b"}}
    ]});
    assert!(replace_openai_chat_output_in_place(&mut v, "x"));
    assert_eq!(v["choices"][0]["message"]["content"], "x");
    assert_eq!(v["choices"][1]["message"]["content"], "x");
}

#[test]
fn replace_chat_output_no_choices() {
    let mut v = json!({"data": []});
    assert!(!replace_openai_chat_output_in_place(&mut v, "x"));
}

#[test]
fn replace_chat_output_null_content_unchanged() {
    let mut v = json!({"choices": [{"message": {"content": null}}]});
    assert!(!replace_openai_chat_output_in_place(&mut v, "x"));
}

// ── replace_openai_responses_output_in_place ────────────────────────

#[test]
fn replace_responses_output_text_items() {
    let mut v = json!({"output": [
        {"content": [
            {"type": "output_text", "text": "original"},
            {"type": "tool_call", "text": "untouched"}
        ]}
    ]});
    assert!(replace_openai_responses_output_in_place(&mut v, "replaced"));
    assert_eq!(v["output"][0]["content"][0]["text"], "replaced");
    assert_eq!(v["output"][0]["content"][1]["text"], "untouched");
}

#[test]
fn replace_responses_output_no_output_key() {
    let mut v = json!({"result": "ok"});
    assert!(!replace_openai_responses_output_in_place(&mut v, "x"));
}

#[test]
fn replace_responses_output_skips_non_text_types() {
    let mut v = json!({"output": [
        {"content": [{"type": "image", "text": "img"}]}
    ]});
    assert!(!replace_openai_responses_output_in_place(&mut v, "x"));
    assert_eq!(v["output"][0]["content"][0]["text"], "img");
}

// ── prepend_openai_output_in_place ──────────────────────────────────

#[test]
fn prepend_chat_output() {
    let mut v = json!({"choices": [{"message": {"content": "world"}}]});
    assert!(prepend_openai_output_in_place(&mut v, "hello "));
    assert_eq!(v["choices"][0]["message"]["content"], "hello world");
}

#[test]
fn prepend_responses_output() {
    let mut v = json!({"output": [
        {"content": [{"type": "output_text", "text": "bar"}]}
    ]});
    assert!(prepend_openai_output_in_place(&mut v, "foo"));
    assert_eq!(v["output"][0]["content"][0]["text"], "foobar");
}

#[test]
fn prepend_no_matching_structure() {
    let mut v = json!({"data": "irrelevant"});
    assert!(!prepend_openai_output_in_place(&mut v, "prefix"));
}

// ── extract_openai_output_text_from_json ────────────────────────────

#[test]
fn extract_output_text_from_chat_choices() {
    let v = json!({"choices": [
        {"message": {"content": "A"}},
        {"message": {"content": "B"}}
    ]});
    assert_eq!(extract_openai_output_text_from_json(&v), "A\nB");
}

#[test]
fn extract_output_text_from_responses_string() {
    let v = json!({"output": "direct text"});
    assert_eq!(extract_openai_output_text_from_json(&v), "direct text");
}

#[test]
fn extract_output_text_from_responses_array() {
    let v = json!({"output": [
        {"content": [{"type": "output_text", "text": "a"}]},
        {"content": [{"type": "output_text", "text": "b"}]}
    ]});
    assert_eq!(extract_openai_output_text_from_json(&v), "a\nb");
}

#[test]
fn extract_output_text_empty_when_no_known_structure() {
    let v = json!({"data": "irrelevant"});
    assert_eq!(extract_openai_output_text_from_json(&v), "");
}

#[test]
fn extract_output_text_skips_non_output_text_items() {
    let v = json!({"output": [
        {"content": [
            {"type": "tool_call", "text": "skipped"},
            {"type": "output_text", "text": "kept"}
        ]}
    ]});
    assert_eq!(extract_openai_output_text_from_json(&v), "kept");
}

// ── streaming_mode_label ────────────────────────────────────────────

#[test]
fn streaming_mode_label_redaction() {
    assert_eq!(streaming_mode_label(false, true), "buffered_redaction");
    assert_eq!(streaming_mode_label(true, true), "buffered_redaction");
}

#[test]
fn streaming_mode_label_policy() {
    assert_eq!(streaming_mode_label(true, false), "buffered_policy");
}

#[test]
fn streaming_mode_label_passthrough() {
    assert_eq!(streaming_mode_label(false, false), "passthrough");
}

// ── verdictan_headers ──────────────────────────────────────────────

#[test]
fn verdictan_headers_basic_allow() {
    let hdrs = verdictan_headers("ALLOW", "ok", "1.0.0", 42, false, &[], None, false, None);
    let find = |name: &str| {
        hdrs.iter()
            .find(|(n, _)| n.as_str() == name)
            .map(|(_, v)| v.to_str().unwrap().to_string())
    };
    assert_eq!(find("x-verdictan-verdict").as_deref(), Some("ALLOW"));
    assert_eq!(find("x-verdictan-reason-code").as_deref(), Some("ok"));
    assert_eq!(find("x-verdictan-config-version").as_deref(), Some("1.0.0"));
    assert_eq!(find("x-verdictan-latency-ms").as_deref(), Some("42"));
    assert_eq!(
        find("x-verdictan-prompt-redacted").as_deref(),
        Some("false")
    );
    assert_eq!(
        find("x-verdictan-response-redacted").as_deref(),
        Some("false")
    );
    assert!(find("x-verdictan-degraded").is_none());
}

#[test]
fn verdictan_headers_with_degraded_flag() {
    let hdrs = verdictan_headers("ALLOW", "ok", "1.0.0", 0, false, &[], None, true, None);
    let has_degraded = hdrs
        .iter()
        .any(|(n, v)| n.as_str() == "x-verdictan-degraded" && v.to_str().unwrap() == "true");
    assert!(has_degraded);
}

#[test]
fn verdictan_headers_with_prompt_redacted() {
    let hdrs = verdictan_headers("REDACT", "pii", "1.0.0", 10, true, &[], None, false, None);
    let val = hdrs
        .iter()
        .find(|(n, _)| n.as_str() == "x-verdictan-prompt-redacted")
        .map(|(_, v)| v.to_str().unwrap().to_string());
    assert_eq!(val.as_deref(), Some("true"));
}

#[test]
fn verdictan_headers_with_rbac_missing() {
    let rbac = json!({"missing_headers": ["x-custom-role", "x-custom-team"]});
    let hdrs = verdictan_headers(
        "BLOCK",
        "rbac",
        "1.0",
        5,
        false,
        &[],
        None,
        false,
        Some(&rbac),
    );
    let missing = hdrs
        .iter()
        .find(|(n, _)| n.as_str() == "x-verdictan-rbac-missing")
        .map(|(_, v)| v.to_str().unwrap().to_string());
    assert!(missing.is_some());
    let val = missing.unwrap();
    assert!(val.contains("x-custom-role"));
    assert!(val.contains("x-custom-team"));
}

// ── verdictan_redactions_json ───────────────────────────────────────

#[test]
fn redactions_json_empty() {
    let items: Vec<super::super::redaction::VerdictanRedaction> = vec![];
    let j = verdictan_redactions_json(&items);
    assert_eq!(j["applied"], false);
    assert!(j["entities"].as_array().unwrap().is_empty());
}

// ── merge_stage_decision ────────────────────────────────────────────

#[test]
fn merge_stage_block_overrides_allow() {
    let mut decision = enforcement::DecisionEnvelope {
        final_verdict: Verdict::Allow,
        reason_code: "ok".to_string(),
        results: vec![],
    };
    let stage = enforcement::DecisionEnvelope {
        final_verdict: Verdict::Block,
        reason_code: "blocked_by_stage".to_string(),
        results: vec![],
    };
    merge_stage_decision(&mut decision, stage);
    assert_eq!(decision.final_verdict, Verdict::Block);
    assert_eq!(decision.reason_code, "blocked_by_stage");
}

#[test]
fn merge_stage_escalate_overrides_allow() {
    let mut decision = enforcement::DecisionEnvelope {
        final_verdict: Verdict::Allow,
        reason_code: "ok".to_string(),
        results: vec![],
    };
    let stage = enforcement::DecisionEnvelope {
        final_verdict: Verdict::Escalate,
        reason_code: "escalated".to_string(),
        results: vec![],
    };
    merge_stage_decision(&mut decision, stage);
    assert_eq!(decision.final_verdict, Verdict::Escalate);
}

#[test]
fn merge_stage_block_wins_over_escalate() {
    let mut decision = enforcement::DecisionEnvelope {
        final_verdict: Verdict::Block,
        reason_code: "blocked".to_string(),
        results: vec![],
    };
    let stage = enforcement::DecisionEnvelope {
        final_verdict: Verdict::Escalate,
        reason_code: "escalated".to_string(),
        results: vec![],
    };
    merge_stage_decision(&mut decision, stage);
    assert_eq!(decision.final_verdict, Verdict::Block);
    assert_eq!(decision.reason_code, "blocked");
}

#[test]
fn merge_stage_redact_overrides_allow() {
    let mut decision = enforcement::DecisionEnvelope {
        final_verdict: Verdict::Allow,
        reason_code: "ok".to_string(),
        results: vec![],
    };
    let stage = enforcement::DecisionEnvelope {
        final_verdict: Verdict::Redact,
        reason_code: "pii_found".to_string(),
        results: vec![],
    };
    merge_stage_decision(&mut decision, stage);
    assert_eq!(decision.final_verdict, Verdict::Redact);
    assert_eq!(decision.reason_code, "pii_found");
}

#[test]
fn merge_stage_allow_does_not_override_redact() {
    let mut decision = enforcement::DecisionEnvelope {
        final_verdict: Verdict::Redact,
        reason_code: "redacted".to_string(),
        results: vec![],
    };
    let stage = enforcement::DecisionEnvelope {
        final_verdict: Verdict::Allow,
        reason_code: "ok".to_string(),
        results: vec![],
    };
    merge_stage_decision(&mut decision, stage);
    assert_eq!(decision.final_verdict, Verdict::Redact);
}

#[test]
fn merge_stage_accumulates_results() {
    let mut decision = enforcement::DecisionEnvelope {
        final_verdict: Verdict::Allow,
        reason_code: "ok".to_string(),
        results: vec![enforcement::PolicyResult {
            policy_kind: "content-filter".to_string(),
            phase: "input".to_string(),
            verdict: Verdict::Allow,
            reason_code: "ok".to_string(),
            details: None,
            redaction_targets: None,
        }],
    };
    let stage = enforcement::DecisionEnvelope {
        final_verdict: Verdict::Allow,
        reason_code: "ok".to_string(),
        results: vec![enforcement::PolicyResult {
            policy_kind: "rbac".to_string(),
            phase: "input".to_string(),
            verdict: Verdict::Allow,
            reason_code: "ok".to_string(),
            details: None,
            redaction_targets: None,
        }],
    };
    merge_stage_decision(&mut decision, stage);
    assert_eq!(decision.results.len(), 2);
}

// ── output_messages_for_stage ────────────────────────────────────────

#[test]
fn output_messages_from_chat_completions() {
    let v = json!({"choices": [{"message": {"content": "hello"}}]});
    let msgs = output_messages_for_stage(Some(&v), &Bytes::new());
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].role, "assistant");
    assert_eq!(msgs[0].content, "hello");
}

#[test]
fn output_messages_from_responses_api() {
    let v = json!({"output": [
        {"content": [{"type": "output_text", "text": "response text"}]}
    ]});
    let msgs = output_messages_for_stage(Some(&v), &Bytes::new());
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].content, "response text");
}

#[test]
fn output_messages_fallback_to_raw_bytes() {
    let raw = Bytes::from("raw text content");
    let msgs = output_messages_for_stage(None, &raw);
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].content, "raw text content");
}

#[test]
fn output_messages_empty_for_whitespace_text() {
    let v = json!({"choices": [{"message": {"content": "   "}}]});
    let msgs = output_messages_for_stage(Some(&v), &Bytes::new());
    assert!(msgs.is_empty());
}

// ── extract_history_token_usage ──────────────────────────────────────

#[test]
fn history_usage_basic() {
    let v = json!({"usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}});
    let u = extract_history_token_usage(&v, None);
    assert_eq!(u["prompt_tokens"], 10);
    assert_eq!(u["completion_tokens"], 5);
    assert_eq!(u["total_tokens"], 15);
}

#[test]
fn history_usage_anthropic_style() {
    let v = json!({"usage": {"input_tokens": 20, "output_tokens": 8}});
    let u = extract_history_token_usage(&v, None);
    assert_eq!(u["prompt_tokens"], 20);
    assert_eq!(u["completion_tokens"], 8);
    assert_eq!(u["total_tokens"], 28);
}

#[test]
fn history_usage_missing_usage_block() {
    let v = json!({"model": "gpt-4"});
    let u = extract_history_token_usage(&v, None);
    assert_eq!(u["prompt_tokens"], 0);
    assert_eq!(u["completion_tokens"], 0);
    assert_eq!(u["total_tokens"], 0);
}

#[test]
fn history_usage_with_finops_context() {
    let v = json!({"usage": {"prompt_tokens": 100, "completion_tokens": 50}});
    let finops = RequestFinopsContext {
        working_context_tokens: Some(30),
        context_plan_hash: Some("hash-abc".to_string()),
        ..Default::default()
    };
    let u = extract_history_token_usage(&v, Some(&finops));
    assert_eq!(u["user_prompt_tokens"], 70);
    assert_eq!(u["working_context_tokens"], 30);
    assert_eq!(u["context_plan_hash"], "hash-abc");
}

#[test]
fn history_usage_user_prompt_tokens_floor_at_zero() {
    let v = json!({"usage": {"prompt_tokens": 5, "completion_tokens": 10}});
    let finops = RequestFinopsContext {
        working_context_tokens: Some(50),
        ..Default::default()
    };
    let u = extract_history_token_usage(&v, Some(&finops));
    assert_eq!(u["user_prompt_tokens"], 0);
}

// ── attach_history_usage_block ──────────────────────────────────────

#[test]
fn attach_usage_adds_block() {
    let payload = json!({"id": "resp-1"});
    let usage = SpendUsage {
        prompt_tokens: 10,
        completion_tokens: 5,
        total_tokens: 15,
        cached_input_tokens: 2,
        prompt_cost: None,
        completion_cost: None,
        total_cost: None,
    };
    let result = attach_history_usage_block(payload, Some(usage));
    assert_eq!(result["usage"]["prompt_tokens"], 10);
    assert_eq!(result["usage"]["total_tokens"], 15);
}

#[test]
fn attach_usage_preserves_existing_usage() {
    let payload = json!({"usage": {"prompt_tokens": 99}});
    let usage = SpendUsage {
        prompt_tokens: 10,
        completion_tokens: 5,
        total_tokens: 15,
        cached_input_tokens: 0,
        prompt_cost: None,
        completion_cost: None,
        total_cost: None,
    };
    let result = attach_history_usage_block(payload, Some(usage));
    assert_eq!(result["usage"]["prompt_tokens"], 99);
}

#[test]
fn attach_usage_skips_zero_total() {
    let payload = json!({"id": "resp-1"});
    let usage = SpendUsage {
        prompt_tokens: 0,
        completion_tokens: 0,
        total_tokens: 0,
        cached_input_tokens: 0,
        prompt_cost: None,
        completion_cost: None,
        total_cost: None,
    };
    let result = attach_history_usage_block(payload, Some(usage));
    assert!(result.get("usage").is_none());
}

#[test]
fn attach_usage_skips_none() {
    let payload = json!({"id": "resp-1"});
    let result = attach_history_usage_block(payload.clone(), None);
    assert!(result.get("usage").is_none());
}

#[test]
fn attach_usage_non_object_passthrough() {
    let payload = json!("string payload");
    let usage = SpendUsage {
        prompt_tokens: 10,
        completion_tokens: 5,
        total_tokens: 15,
        cached_input_tokens: 0,
        prompt_cost: None,
        completion_cost: None,
        total_cost: None,
    };
    let result = attach_history_usage_block(payload, Some(usage));
    assert_eq!(result, json!("string payload"));
}

// ── extract_title_seed_from_request ──────────────────────────────────

#[test]
fn title_seed_last_user_message() {
    let v = json!({"messages": [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "first question"},
        {"role": "assistant", "content": "answer"},
        {"role": "user", "content": "follow up"}
    ]});
    let seed = extract_title_seed_from_request(&v);
    assert_eq!(seed.as_deref(), Some("follow up"));
}

#[test]
fn title_seed_truncates_long_messages() {
    let long_text = "a ".repeat(200);
    let v = json!({"messages": [{"role": "user", "content": long_text}]});
    let seed = extract_title_seed_from_request(&v).unwrap();
    assert!(seed.len() <= 124);
    assert!(seed.ends_with('…'));
}

#[test]
fn title_seed_none_without_user_messages() {
    let v = json!({"messages": [{"role": "assistant", "content": "reply"}]});
    assert!(extract_title_seed_from_request(&v).is_none());
}

#[test]
fn title_seed_none_for_empty_content() {
    let v = json!({"messages": [{"role": "user", "content": "   "}]});
    assert!(extract_title_seed_from_request(&v).is_none());
}

#[test]
fn title_seed_short_message_not_truncated() {
    let v = json!({"messages": [{"role": "user", "content": "short"}]});
    let seed = extract_title_seed_from_request(&v).unwrap();
    assert_eq!(seed, "short");
    assert!(!seed.contains('…'));
}

// ── build_metadata_only_history_response ────────────────────────────

#[test]
fn metadata_only_response_with_output() {
    let v = json!({
        "choices": [{"message": {"content": "hello"}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    });
    let result = build_metadata_only_history_response(&v, None);
    assert_eq!(result["has_output"], true);
    assert_eq!(result["usage"]["prompt_tokens"], 10);
}

#[test]
fn metadata_only_response_no_output() {
    let v = json!({"usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}});
    let result = build_metadata_only_history_response(&v, None);
    assert_eq!(result["has_output"], false);
}

// ── append_history_writeback_metadata ────────────────────────────────

#[test]
fn append_writeback_metadata_creates_verdictan_block() {
    let v = json!({"id": "resp-1"});
    let result = append_history_writeback_metadata(v, Some(42), false);
    assert_eq!(result["verdictan"]["history"]["latency_ms"], 42);
    assert_eq!(
        result["verdictan"]["history"]["background_requested"],
        false
    );
}

#[test]
fn append_writeback_metadata_background_true() {
    let v = json!({"id": "resp-1"});
    let result = append_history_writeback_metadata(v, None, true);
    assert!(result["verdictan"]["history"]["latency_ms"].is_null());
    assert_eq!(result["verdictan"]["history"]["background_requested"], true);
}

#[test]
fn append_writeback_metadata_preserves_existing_verdictan() {
    let v = json!({"verdictan": {"decision": {"verdict": "ALLOW"}}});
    let result = append_history_writeback_metadata(v, Some(10), false);
    assert_eq!(result["verdictan"]["decision"]["verdict"], "ALLOW");
    assert_eq!(result["verdictan"]["history"]["latency_ms"], 10);
}

#[test]
fn append_writeback_metadata_non_object_passthrough() {
    let v = json!("not an object");
    let result = append_history_writeback_metadata(v, Some(1), false);
    assert_eq!(result, json!("not an object"));
}

// ── derive_gateway_id ───────────────────────────────────────────────

#[test]
fn derive_gateway_id_from_name() {
    let id = derive_gateway_id(Some("My Gateway 1"));
    assert_eq!(id, "my-gateway-1-gw");
}

#[test]
fn derive_gateway_id_sanitizes_special_chars() {
    let id = derive_gateway_id(Some("test@gateway#42"));
    assert_eq!(id, "test-gateway-42-gw");
}

#[test]
fn derive_gateway_id_trims_whitespace() {
    let id = derive_gateway_id(Some("  edge  "));
    assert_eq!(id, "edge-gw");
}

#[test]
fn derive_gateway_id_from_hostname() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    let original = std::env::var_os("HOSTNAME");
    std::env::set_var("HOSTNAME", "my-host-01");
    let id = derive_gateway_id(None);
    assert_eq!(id, "my-host-01-gw");
    match original {
        Some(v) => std::env::set_var("HOSTNAME", v),
        None => std::env::remove_var("HOSTNAME"),
    }
}

// ── decision_runtime_json_streaming ──────────────────────────────────

#[test]
fn streaming_runtime_json_basic() {
    let val = decision_runtime_json_streaming(
        Some(500),
        Some("stop"),
        None,
        10,
        false,
        false,
        None,
        None,
        None,
    );
    assert_eq!(val["streaming"], true);
    assert_eq!(val["output_chars"], 500);
    assert_eq!(val["finish_reason"], "stop");
    assert_eq!(val["chunks_forwarded"], 10);
    assert_eq!(val["buffered"], false);
    assert_eq!(val["interrupted"], false);
}

#[test]
fn streaming_runtime_json_with_failure() {
    let val = decision_runtime_json_streaming(
        None,
        None,
        Some("fallback-provider"),
        0,
        true,
        true,
        Some("timeout"),
        Some("upstream timed out"),
        None,
    );
    assert_eq!(val["interrupted"], true);
    assert_eq!(val["failure_reason"], "timeout");
    assert_eq!(val["failure_message"], "upstream timed out");
    assert_eq!(val["fallback_provider_id"], "fallback-provider");
    assert_eq!(val["buffered"], true);
}

#[test]
fn streaming_runtime_json_with_gateway_context() {
    let ctx = StreamingGatewayContext {
        gateway_id: Some(Arc::from("gw-eu-1")),
        provider: Some("openai".to_string()),
        resolved_provider: Some("openai-primary".to_string()),
        config_name: Some("production".to_string()),
    };
    let val = decision_runtime_json_streaming(
        Some(100),
        Some("stop"),
        None,
        5,
        false,
        false,
        None,
        None,
        Some(&ctx),
    );
    assert_eq!(val["gateway_id"], "gw-eu-1");
    assert_eq!(val["provider"], "openai");
    assert_eq!(val["resolved_provider"], "openai-primary");
    assert_eq!(val["config_name"], "production");
}

// ── extract_config_version ──────────────────────────────────────────

#[test]
fn config_version_from_yaml() {
    let content = "name: test\nversion: 1.2.3\nproviders: []";
    assert_eq!(extract_config_version(content), Some("1.2.3".to_string()));
}

#[test]
fn config_version_quoted() {
    let content = "version: \"2.0.0\"";
    assert_eq!(extract_config_version(content), Some("2.0.0".to_string()));
}

#[test]
fn config_version_single_quoted() {
    let content = "version: '3.0.0'";
    assert_eq!(extract_config_version(content), Some("3.0.0".to_string()));
}

#[test]
fn config_version_with_leading_whitespace() {
    let content = "  version:   4.5.6  ";
    assert_eq!(extract_config_version(content), Some("4.5.6".to_string()));
}

#[test]
fn config_version_missing() {
    let content = "name: test\nproviders: []";
    assert_eq!(extract_config_version(content), None);
}

#[test]
fn config_version_empty_value() {
    let content = "version: ";
    assert_eq!(extract_config_version(content), None);
}

// ── extract_requested_max_tokens ────────────────────────────────────

#[test]
fn max_tokens_from_max_tokens() {
    let v = json!({"max_tokens": 100});
    assert_eq!(extract_requested_max_tokens(&v), Some(100));
}

#[test]
fn max_tokens_from_max_completion_tokens() {
    let v = json!({"max_completion_tokens": 200});
    assert_eq!(extract_requested_max_tokens(&v), Some(200));
}

#[test]
fn max_tokens_from_max_output_tokens() {
    let v = json!({"max_output_tokens": 300});
    assert_eq!(extract_requested_max_tokens(&v), Some(300));
}

#[test]
fn max_tokens_prefers_max_tokens_over_alternatives() {
    let v = json!({"max_tokens": 100, "max_completion_tokens": 200});
    assert_eq!(extract_requested_max_tokens(&v), Some(100));
}

#[test]
fn max_tokens_none_when_absent() {
    let v = json!({"model": "gpt-4"});
    assert_eq!(extract_requested_max_tokens(&v), None);
}

// ── tighter_remaining_budget ────────────────────────────────────────

#[test]
fn tighter_budget_both_some() {
    assert_eq!(tighter_remaining_budget(Some(10.0), Some(5.0)), Some(5.0));
    assert_eq!(tighter_remaining_budget(Some(3.0), Some(8.0)), Some(3.0));
}

#[test]
fn tighter_budget_one_some() {
    assert_eq!(tighter_remaining_budget(Some(10.0), None), Some(10.0));
    assert_eq!(tighter_remaining_budget(None, Some(5.0)), Some(5.0));
}

#[test]
fn tighter_budget_both_none() {
    assert_eq!(tighter_remaining_budget(None, None), None);
}

// ── remaining_budget_from_records ────────────────────────────────────

#[test]
fn remaining_budget_single_record() {
    let records = vec![GatewayBudgetRecord {
        max_budget: 100.0,
        current_spend: 30.0,
    }];
    assert_eq!(remaining_budget_from_records(&records), Some(70.0));
}

#[test]
fn remaining_budget_multiple_records_uses_min() {
    let records = vec![
        GatewayBudgetRecord {
            max_budget: 100.0,
            current_spend: 30.0,
        },
        GatewayBudgetRecord {
            max_budget: 50.0,
            current_spend: 40.0,
        },
    ];
    assert_eq!(remaining_budget_from_records(&records), Some(10.0));
}

#[test]
fn remaining_budget_overspent_floors_at_zero() {
    let records = vec![GatewayBudgetRecord {
        max_budget: 10.0,
        current_spend: 15.0,
    }];
    assert_eq!(remaining_budget_from_records(&records), Some(0.0));
}

#[test]
fn remaining_budget_empty_records() {
    let records: Vec<GatewayBudgetRecord> = vec![];
    assert_eq!(remaining_budget_from_records(&records), None);
}

// ── normalize_optional_string_value ──────────────────────────────────

#[test]
fn optional_string_value_from_string() {
    let v = json!("hello");
    assert_eq!(
        normalize_optional_string_value(Some(&v)),
        Some("hello".to_string())
    );
}

#[test]
fn optional_string_value_trims() {
    let v = json!("  world  ");
    assert_eq!(
        normalize_optional_string_value(Some(&v)),
        Some("world".to_string())
    );
}

#[test]
fn optional_string_value_empty_returns_none() {
    let v = json!("   ");
    assert_eq!(normalize_optional_string_value(Some(&v)), None);
}

#[test]
fn optional_string_value_non_string_returns_none() {
    let v = json!(42);
    assert_eq!(normalize_optional_string_value(Some(&v)), None);
}

#[test]
fn optional_string_value_none_returns_none() {
    assert_eq!(normalize_optional_string_value(None), None);
}

// ── normalize_provider_scope_values ──────────────────────────────────

#[test]
fn provider_scope_lowercases_and_deduplicates() {
    let input = vec!["OpenAI".into(), "openai".into(), "Anthropic".into()];
    let result = normalize_provider_scope_values(&input);
    assert_eq!(result, vec!["anthropic", "openai"]);
}

#[test]
fn provider_scope_filters_empty() {
    let input = vec!["".into(), "  ".into(), "openai".into()];
    let result = normalize_provider_scope_values(&input);
    assert_eq!(result, vec!["openai"]);
}

// ── build_access_inactive_body ─────────────────────────────────────

#[test]
fn access_inactive_body_is_valid_json() {
    let body = build_access_inactive_body("Provider unavailable", "provider_key_not_configured");
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["error"]["message"], "Provider unavailable");
    assert_eq!(parsed["error"]["type"], "access_inactive");
    assert_eq!(parsed["error"]["code"], "provider_key_not_configured");
}

// ── build_provider_auth_body ────────────────────────────────────────

#[test]
fn provider_auth_body_is_valid_json() {
    let body = build_provider_auth_body("auth failed");
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["error"]["message"], "auth failed");
    assert_eq!(parsed["error"]["type"], "server_error");
    assert_eq!(parsed["error"]["code"], "provider_auth_failed");
}

// ── invalid_success_shape_buffered_response ─────────────────────────

#[test]
fn invalid_success_shape_response_has_bad_gateway_status() {
    let resp = invalid_success_shape_buffered_response("/v1/chat/completions");
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("/v1/chat/completions"));
    assert_eq!(body["error"]["code"], "invalid_upstream_success_shape");
}

// ── RegisterError Display ───────────────────────────────────────────

#[test]
fn register_error_conflict_display() {
    let err = RegisterError::Conflict;
    assert!(err.to_string().contains("409"));
}

#[test]
fn register_error_other_display() {
    let err = RegisterError::Other("network issue".to_string());
    assert_eq!(err.to_string(), "network issue");
}

// ── append_cache_status_header ──────────────────────────────────────

#[test]
fn cache_status_header_hit() {
    let mut headers = vec![];
    append_cache_status_header(&mut headers, true);
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].0.as_str(), "x-cache-status");
    assert_eq!(headers[0].1.to_str().unwrap(), "hit");
}

#[test]
fn cache_status_header_miss() {
    let mut headers = vec![];
    append_cache_status_header(&mut headers, false);
    assert_eq!(headers[0].1.to_str().unwrap(), "miss");
}

#[test]
fn cache_status_header_replaces_existing() {
    let mut headers = vec![(
        axum::http::HeaderName::from_static("x-cache-status"),
        HeaderValue::from_static("stale"),
    )];
    append_cache_status_header(&mut headers, true);
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].1.to_str().unwrap(), "hit");
}

// ── verdictan_rbac_details ──────────────────────────────────────────

#[test]
fn rbac_details_found() {
    let decision = DecisionEnvelope {
        final_verdict: Verdict::Block,
        reason_code: "rbac_denied".to_string(),
        results: vec![enforcement::PolicyResult {
            policy_kind: "rbac".to_string(),
            phase: "input".to_string(),
            verdict: Verdict::Block,
            reason_code: "missing_role".to_string(),
            details: Some(json!({"missing_headers": ["x-role"]})),
            redaction_targets: None,
        }],
    };
    let details = verdictan_rbac_details(&decision);
    assert!(details.is_some());
    assert_eq!(details.unwrap()["missing_headers"][0], "x-role");
}

#[test]
fn rbac_details_none_when_no_rbac_result() {
    let decision = DecisionEnvelope {
        final_verdict: Verdict::Allow,
        reason_code: "ok".to_string(),
        results: vec![enforcement::PolicyResult {
            policy_kind: "content-filter".to_string(),
            phase: "input".to_string(),
            verdict: Verdict::Allow,
            reason_code: "ok".to_string(),
            details: None,
            redaction_targets: None,
        }],
    };
    assert!(verdictan_rbac_details(&decision).is_none());
}

// ── normalize_optional_owned ─────────────────────────────────────────

#[test]
fn normalize_optional_owned_trims() {
    assert_eq!(
        normalize_optional_owned(Some("  hello  ".to_string())),
        Some("hello".to_string())
    );
}

#[test]
fn normalize_optional_owned_empty_returns_none() {
    assert_eq!(normalize_optional_owned(Some("   ".to_string())), None);
    assert_eq!(normalize_optional_owned(None), None);
}

// ── managed_public_endpoint_host_shard_key ──────────────────────────

#[test]
fn shard_key_lowercase() {
    let key = managed_public_endpoint_host_shard_key("abc123.ai.eu.verdictan.com");
    assert!(!key.is_empty());
}

#[test]
fn shard_key_deterministic() {
    let a = managed_public_endpoint_host_shard_key("test.example.com");
    let b = managed_public_endpoint_host_shard_key("test.example.com");
    assert_eq!(a, b);
}

#[test]
fn shard_key_different_for_different_hosts() {
    let a = managed_public_endpoint_host_shard_key("alpha.example.com");
    let b = managed_public_endpoint_host_shard_key("beta.example.com");
    assert_ne!(a, b);
}

// ── non_empty_str ────────────────────────────────────────────────────

#[test]
fn non_empty_str_some_value() {
    assert_eq!(non_empty_str(Some("hello")), Some("hello"));
}

#[test]
fn non_empty_str_empty_returns_none() {
    assert_eq!(non_empty_str(Some("")), None);
}

#[test]
fn non_empty_str_none_returns_none() {
    assert_eq!(non_empty_str(None), None);
}

// ── voice_is_safe_identifier ────────────────────────────────────────

#[test]
fn voice_safe_identifiers() {
    assert!(voice_is_safe_identifier("alloy"));
    assert!(voice_is_safe_identifier("echo-v2"));
    assert!(voice_is_safe_identifier("nova_3"));
}

#[test]
fn voice_unsafe_identifiers() {
    assert!(!voice_is_safe_identifier(""));
    assert!(!voice_is_safe_identifier("bad voice"));
    assert!(!voice_is_safe_identifier("voice@evil"));
}

// ── env_flag_enabled ────────────────────────────────────────────────

#[test]
fn env_flag_enabled_true() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    std::env::set_var("__DEEP_COV_FLAG_TRUE", "1");
    assert!(env_flag_enabled("__DEEP_COV_FLAG_TRUE"));
    std::env::set_var("__DEEP_COV_FLAG_TRUE", "true");
    assert!(env_flag_enabled("__DEEP_COV_FLAG_TRUE"));
    std::env::set_var("__DEEP_COV_FLAG_TRUE", "yes");
    assert!(env_flag_enabled("__DEEP_COV_FLAG_TRUE"));
    std::env::remove_var("__DEEP_COV_FLAG_TRUE");
}

#[test]
fn env_flag_enabled_false() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    std::env::remove_var("__DEEP_COV_FLAG_FALSE");
    assert!(!env_flag_enabled("__DEEP_COV_FLAG_FALSE"));
    std::env::set_var("__DEEP_COV_FLAG_FALSE", "0");
    assert!(!env_flag_enabled("__DEEP_COV_FLAG_FALSE"));
    std::env::set_var("__DEEP_COV_FLAG_FALSE", "no");
    assert!(!env_flag_enabled("__DEEP_COV_FLAG_FALSE"));
    std::env::remove_var("__DEEP_COV_FLAG_FALSE");
}

// ── short_hostname_hash ─────────────────────────────────────────────

#[test]
fn short_hostname_hash_is_8_hex_chars() {
    let hash = short_hostname_hash();
    assert_eq!(hash.len(), 8);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

// ── waiting_connected_config ────────────────────────────────────────

#[test]
fn waiting_connected_config_preserves_hosted_gateway() {
    let hosted = Some(
        super::super::declarative_config::HostedGatewayRuntimeConfig {
            local_access: super::super::declarative_config::HostedGatewayLocalAccessConfig::default(
            ),
        },
    );
    let config = waiting_connected_config(&hosted);
    assert!(config.hosted_gateway.is_some());
}

#[test]
fn waiting_connected_config_none_hosted() {
    let config = waiting_connected_config(&None);
    assert!(config.hosted_gateway.is_none());
}

// ── build_metadata_only_history_request ─────────────────────────────

#[test]
fn metadata_only_request_basic() {
    let v = json!({
        "messages": [
            {"role": "user", "content": "Hello world"}
        ]
    });
    let result = build_metadata_only_history_request(&v, "req-123", None);
    assert_eq!(result["request_id"], "req-123");
    assert_eq!(result["message_count"], 1);
    assert_eq!(result["has_verdictan"], false);
    assert_eq!(result["title_seed"], "Hello world");
}

#[test]
fn metadata_only_request_with_verdictan() {
    let v = json!({
        "messages": [{"role": "user", "content": "Hi"}],
        "verdictan": {"trace": {"evaluation_id": "e1"}}
    });
    let result = build_metadata_only_history_request(&v, "req-456", None);
    assert_eq!(result["has_verdictan"], true);
}

#[test]
fn metadata_only_request_no_messages() {
    let v = json!({"model": "gpt-4"});
    let result = build_metadata_only_history_request(&v, "req-789", None);
    assert_eq!(result["message_count"], 0);
    assert!(result.get("title_seed").is_none());
}

// ── normalized_audio_transcription_format ───────────────────────────

#[test]
fn audio_transcription_format_known_wav() {
    let body = json!({"input_audio": {"format": "WAV"}});
    let result = normalized_audio_transcription_format(&body);
    assert!(result.is_ok());
}

#[test]
fn audio_transcription_format_known_mp3() {
    let body = json!({"input_audio": {"format": "mp3"}});
    let result = normalized_audio_transcription_format(&body);
    assert!(result.is_ok());
}

#[test]
fn audio_transcription_format_unknown() {
    let body = json!({"input_audio": {"format": "csv"}});
    let result = normalized_audio_transcription_format(&body);
    assert!(result.is_err());
}

#[test]
fn audio_transcription_format_missing() {
    let body = json!({"model": "whisper-1"});
    let result = normalized_audio_transcription_format(&body);
    assert!(result.is_err());
}

// ── normalized_audio_speech_output_format ────────────────────────────

#[test]
fn audio_speech_format_defaults_mp3() {
    let body = json!({"model": "tts-1"});
    let result = normalized_audio_speech_output_format(&body);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "mp3");
}

#[test]
fn audio_speech_format_known_opus() {
    let body = json!({"response_format": "opus"});
    let result = normalized_audio_speech_output_format(&body);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "opus");
}

#[test]
fn audio_speech_format_unknown() {
    let body = json!({"response_format": "ogg"});
    let result = normalized_audio_speech_output_format(&body);
    assert!(result.is_err());
}

// ── parse_runtime_json_body ──────────────────────────────────────────

#[test]
fn parse_runtime_json_body_valid() {
    let body = Bytes::from(serde_json::to_vec(&json!({"model": "gpt-4"})).unwrap());
    let result = parse_runtime_json_body(&body);
    assert!(result.is_ok());
    assert_eq!(result.unwrap()["model"], "gpt-4");
}

#[test]
fn parse_runtime_json_body_invalid() {
    let body = Bytes::from("not json {{{");
    let result = parse_runtime_json_body(&body);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert_eq!(err.code, "request.validation_failed");
}

// ── required_string_field ────────────────────────────────────────────

#[test]
fn required_string_field_present() {
    let v = json!({"model": "gpt-4"});
    let result = required_string_field(&v, "/model");
    assert_eq!(result.unwrap(), "gpt-4");
}

#[test]
fn required_string_field_missing() {
    let v = json!({});
    let result = required_string_field(&v, "/model");
    assert!(result.is_err());
}

#[test]
fn required_string_field_non_string() {
    let v = json!({"model": 42});
    let result = required_string_field(&v, "/model");
    assert!(result.is_err());
}

#[test]
fn required_string_field_empty() {
    let v = json!({"model": "  "});
    let result = required_string_field(&v, "/model");
    assert!(result.is_err());
}

// ── SharedGatewayConfig ─────────────────────────────────────────────

#[test]
fn shared_gateway_config_read_and_update() {
    let config = SharedGatewayConfig::new(LoadedDeclarativeConfig::empty());
    let snapshot = config.snapshot();
    assert!(snapshot.provider_registry.is_none());
}

// ── RuntimeRoutingError ─────────────────────────────────────────────

#[test]
fn runtime_routing_error_invalid_request_status() {
    let err = RuntimeRoutingError::invalid_request("routing.validation_failed", "bad field");
    assert_eq!(err.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[test]
fn runtime_routing_error_invalid_request_code() {
    let err = RuntimeRoutingError::invalid_request("routing.option_not_allowed", "forbidden");
    assert_eq!(err.code(), "routing.option_not_allowed");
}

// ── normalize_provider_alias_list ────────────────────────────────────

#[test]
fn provider_alias_list_normalizes() {
    let input = vec![
        "OpenAI".into(),
        "openai".into(),
        "".into(),
        " Anthropic ".into(),
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

// ── RegistrationCache serde ─────────────────────────────────────────

#[test]
fn registration_cache_roundtrip() {
    let cache = RegistrationCache {
        runtime_registration_id: "rid-1".to_string(),
        gateway_id: "gw-1".to_string(),
    };
    let json = serde_json::to_string(&cache).unwrap();
    let deserialized: RegistrationCache = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.runtime_registration_id, "rid-1");
    assert_eq!(deserialized.gateway_id, "gw-1");
}

// ── default_* functions ─────────────────────────────────────────────

#[test]
fn default_functions_return_expected_values() {
    assert!(default_true());
    assert_eq!(default_data_collection_allow(), "allow");
    assert_eq!(default_session_header_name(), "x-session-id");
    assert_eq!(default_shadow_evaluation_mode(), "asynchronous");
    assert_eq!(default_shadow_capture_mode(), "metadata_only");
}

// ── RuntimeProviderPolicySettings defaults ──────────────────────────

#[test]
fn runtime_provider_policy_defaults() {
    let d = default_runtime_provider_policy();
    assert!(d.allow_fallbacks);
    assert!(d.require_parameters);
    assert_eq!(d.data_collection, "allow");
    assert!(!d.zdr);
}

// ── RuntimeCacheDefaults defaults ───────────────────────────────────

#[test]
fn runtime_cache_defaults() {
    let d = default_runtime_cache_defaults();
    assert!(d.allow_cache_control);
    assert!(d.sticky_routing);
    assert!(d.allow_session_id);
    assert_eq!(d.session_header_name, "x-session-id");
}

// ── RuntimePluginGovernance defaults ─────────────────────────────────

#[test]
fn runtime_plugin_governance_defaults() {
    let d = default_runtime_plugin_governance();
    assert!(d.defaults.is_empty());
    assert!(d.forced_on.is_empty());
    assert!(d.prevent_overrides.is_empty());
}

// ── EffectiveShadowRouting defaults ──────────────────────────────────

#[test]
fn effective_shadow_routing_defaults() {
    let d = EffectiveShadowRouting::default();
    assert!(!d.enabled);
    assert_eq!(d.capture_mode, "metadata_only");
}

// ── TraceCorrelation::is_empty ──────────────────────────────────────

#[test]
fn trace_correlation_empty_when_all_none() {
    let tc = TraceCorrelation::default();
    assert!(tc.is_empty());
}

#[test]
fn trace_correlation_not_empty_with_field() {
    let mut tc = TraceCorrelation::default();
    tc.evaluation_id = Some("e1".to_string());
    assert!(!tc.is_empty());
}

// ── RuntimeRoutingSettings default ──────────────────────────────────

#[test]
fn runtime_routing_settings_defaults() {
    let d = RuntimeRoutingSettings::default();
    assert!(d.default_provider_policy.allow_fallbacks);
    assert!(d.cache_defaults.allow_session_id);
}
