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

// ── success_shape_valid_for_path ─────────────────────────────────────

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
    let body = serde_json::to_vec(&json!({"id": "x"})).unwrap();
    assert!(!success_shape_valid_for_path("/v1/chat/completions", &body));
}

#[test]
fn success_shape_chat_completions_invalid_json() {
    assert!(!success_shape_valid_for_path(
        "/v1/chat/completions",
        b"not json"
    ));
}

#[test]
fn success_shape_responses_valid() {
    let body = serde_json::to_vec(&json!({"output": []})).unwrap();
    assert!(success_shape_valid_for_path("/v1/responses", &body));
}

#[test]
fn success_shape_responses_invalid_no_output() {
    let body = serde_json::to_vec(&json!({"id": "x"})).unwrap();
    assert!(!success_shape_valid_for_path("/v1/responses", &body));
}

#[test]
fn success_shape_messages_valid() {
    let body = serde_json::to_vec(&json!({"content": [], "type": "message"})).unwrap();
    assert!(success_shape_valid_for_path("/v1/messages", &body));
}

#[test]
fn success_shape_messages_wrong_type() {
    let body = serde_json::to_vec(&json!({"content": [], "type": "tool_use"})).unwrap();
    assert!(!success_shape_valid_for_path("/v1/messages", &body));
}

#[test]
fn success_shape_messages_missing_content() {
    let body = serde_json::to_vec(&json!({"type": "message"})).unwrap();
    assert!(!success_shape_valid_for_path("/v1/messages", &body));
}

#[test]
fn success_shape_unknown_path_always_valid() {
    let body = serde_json::to_vec(&json!({"foo": "bar"})).unwrap();
    assert!(success_shape_valid_for_path("/v1/completions", &body));
}

// ── access_inactive_status ──────────────────────────────────────────

#[test]
fn access_inactive_status_provider_key_denied() {
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
fn access_inactive_status_unknown_falls_through() {
    assert_eq!(
        access_inactive_status("weird_reason"),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

// ── access_inactive_message ─────────────────────────────────────────

#[test]
fn access_inactive_message_policy_denied() {
    let msg = access_inactive_message("provider_key_policy_denied", "openai");
    assert!(msg.contains("openai"));
    assert!(msg.contains("access denied"));
}

#[test]
fn access_inactive_message_no_binding() {
    let msg = access_inactive_message("provider_key_no_policy_binding", "anthropic");
    assert!(msg.contains("anthropic"));
    assert!(msg.contains("no provider-key policy binding"));
}

#[test]
fn access_inactive_message_not_configured() {
    let msg = access_inactive_message("provider_key_not_configured", "azure");
    assert!(msg.contains("not configured"));
}

#[test]
fn access_inactive_message_seeded_deleted() {
    let msg = access_inactive_message("provider_key_seeded_default_deleted", "gcp");
    assert!(msg.contains("seeded provider key was deleted"));
}

#[test]
fn access_inactive_message_unsupported() {
    let msg = access_inactive_message("unsupported_provider", "custom");
    assert!(msg.contains("unsupported"));
}

#[test]
fn access_inactive_message_unknown_reason() {
    let msg = access_inactive_message("custom_reason", "foo");
    assert!(msg.contains("foo"));
    assert!(msg.contains("custom_reason"));
}

// ── missing_provider_registry_message ────────────────────────────────

#[test]
fn missing_provider_registry_connected() {
    let msg = missing_provider_registry_message(true);
    assert!(msg.contains("connect"));
}

#[test]
fn missing_provider_registry_local() {
    let msg = missing_provider_registry_message(false);
    assert!(msg.contains("provider registry"));
}

// ── extract_spend_usage ──────────────────────────────────────────────

#[test]
fn extract_spend_usage_standard_openai() {
    let body = Bytes::from(
        serde_json::to_vec(&json!({
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150
            }
        }))
        .unwrap(),
    );
    let usage = extract_spend_usage(&body).unwrap();
    assert_eq!(usage.prompt_tokens, 100);
    assert_eq!(usage.completion_tokens, 50);
    assert_eq!(usage.total_tokens, 150);
}

#[test]
fn extract_spend_usage_anthropic_keys() {
    let body = Bytes::from(
        serde_json::to_vec(&json!({
            "usage": {
                "input_tokens": 80,
                "output_tokens": 40
            }
        }))
        .unwrap(),
    );
    let usage = extract_spend_usage(&body).unwrap();
    assert_eq!(usage.prompt_tokens, 80);
    assert_eq!(usage.completion_tokens, 40);
    assert_eq!(usage.total_tokens, 120);
}

#[test]
fn extract_spend_usage_cached_tokens_openai() {
    let body = Bytes::from(
        serde_json::to_vec(&json!({
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150,
                "prompt_tokens_details": {
                    "cached_tokens": 30
                }
            }
        }))
        .unwrap(),
    );
    let usage = extract_spend_usage(&body).unwrap();
    assert_eq!(usage.cached_input_tokens, 30);
}

#[test]
fn extract_spend_usage_cached_tokens_anthropic() {
    let body = Bytes::from(
        serde_json::to_vec(&json!({
            "usage": {
                "input_tokens": 100,
                "output_tokens": 50,
                "cache_read_input_tokens": 25
            }
        }))
        .unwrap(),
    );
    let usage = extract_spend_usage(&body).unwrap();
    assert_eq!(usage.cached_input_tokens, 25);
}

#[test]
fn extract_spend_usage_cost_fields() {
    let body = Bytes::from(
        serde_json::to_vec(&json!({
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15,
                "prompt_cost": 0.001,
                "completion_cost": 0.002,
                "total_cost": 0.003
            }
        }))
        .unwrap(),
    );
    let usage = extract_spend_usage(&body).unwrap();
    assert_eq!(usage.prompt_cost, Some(0.001));
    assert_eq!(usage.completion_cost, Some(0.002));
    assert_eq!(usage.total_cost, Some(0.003));
}

#[test]
fn extract_spend_usage_alt_cost_keys() {
    let body = Bytes::from(
        serde_json::to_vec(&json!({
            "usage": {
                "input_tokens": 10,
                "output_tokens": 5,
                "input_cost": 0.01,
                "output_cost": 0.02,
                "cost": 0.03
            }
        }))
        .unwrap(),
    );
    let usage = extract_spend_usage(&body).unwrap();
    assert_eq!(usage.prompt_cost, Some(0.01));
    assert_eq!(usage.completion_cost, Some(0.02));
    assert_eq!(usage.total_cost, Some(0.03));
}

#[test]
fn extract_spend_usage_all_zero_returns_none() {
    let body = Bytes::from(
        serde_json::to_vec(&json!({
            "usage": {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0
            }
        }))
        .unwrap(),
    );
    assert!(extract_spend_usage(&body).is_none());
}

#[test]
fn extract_spend_usage_no_usage_key() {
    let body = Bytes::from(serde_json::to_vec(&json!({"id": "resp-1"})).unwrap());
    assert!(extract_spend_usage(&body).is_none());
}

#[test]
fn extract_spend_usage_invalid_json() {
    let body = Bytes::from("not json");
    assert!(extract_spend_usage(&body).is_none());
}

// ── extract_upstream_model_name / extract_response_model_name ────────

#[test]
fn extract_upstream_model_name_present() {
    let body = Bytes::from(serde_json::to_vec(&json!({"model": "gpt-4"})).unwrap());
    assert_eq!(
        extract_upstream_model_name(&body),
        Some("gpt-4".to_string())
    );
}

#[test]
fn extract_upstream_model_name_missing() {
    let body = Bytes::from(serde_json::to_vec(&json!({"id": "x"})).unwrap());
    assert!(extract_upstream_model_name(&body).is_none());
}

#[test]
fn extract_upstream_model_name_invalid_json() {
    let body = Bytes::from("{{");
    assert!(extract_upstream_model_name(&body).is_none());
}

#[test]
fn extract_response_model_name_present() {
    let body = Bytes::from(serde_json::to_vec(&json!({"model": "claude-3"})).unwrap());
    assert_eq!(
        extract_response_model_name(&body),
        Some("claude-3".to_string())
    );
}

// ── extract_pipeline_metadata ────────────────────────────────────────

#[test]
fn extract_pipeline_metadata_present() {
    let body = Bytes::from(
        serde_json::to_vec(&json!({
            "verdictan_pipeline": {"steps": 2}
        }))
        .unwrap(),
    );
    let meta = extract_pipeline_metadata(&body).unwrap();
    assert_eq!(meta["steps"], 2);
}

#[test]
fn extract_pipeline_metadata_absent() {
    let body = Bytes::from(serde_json::to_vec(&json!({"id": "x"})).unwrap());
    assert!(extract_pipeline_metadata(&body).is_none());
}

// ── annotate_cache_replay_metadata ───────────────────────────────────

#[test]
fn annotate_cache_replay_no_metadata_noop() {
    let mut event = json!({"metadata": {"foo": "bar"}});
    annotate_cache_replay_metadata(&mut event, None);
    assert!(event["metadata"].get("cache_replay").is_none());
}

#[test]
fn annotate_cache_replay_appends_to_existing_metadata() {
    let mut event = json!({"metadata": {"foo": "bar"}});
    let replay = CacheReplayMetadata {
        cache_tier: CacheTier::PrivateEdge,
        outcome: CacheReplayOutcome::ExactHit,
        cache_key_digest: Some("sha256:abc".to_string()),
        selected_fabric_artifact_ids: vec![],
        selected_fabric_source_digests: vec![],
    };
    annotate_cache_replay_metadata(&mut event, Some(&replay));
    assert!(event["metadata"]["cache_replay"].is_object());
}

#[test]
fn annotate_cache_replay_creates_metadata_if_absent() {
    let mut event = json!({"id": "ev-1"});
    let replay = CacheReplayMetadata {
        cache_tier: CacheTier::OrgShared,
        outcome: CacheReplayOutcome::StaleMiss,
        cache_key_digest: None,
        selected_fabric_artifact_ids: vec![],
        selected_fabric_source_digests: vec![],
    };
    annotate_cache_replay_metadata(&mut event, Some(&replay));
    assert!(event["metadata"]["cache_replay"].is_object());
}

// ── local_semantic_similarity ─────────────────────────────────────────

#[test]
fn semantic_similarity_identical() {
    let score = local_semantic_similarity("hello world", "hello world");
    assert!((score - 1.0).abs() < 1e-10);
}

#[test]
fn semantic_similarity_partial_overlap() {
    let score = local_semantic_similarity("hello world foo", "hello world bar");
    assert!(score > 0.0);
    assert!(score < 1.0);
}

#[test]
fn semantic_similarity_no_overlap() {
    let score = local_semantic_similarity("alpha beta", "gamma delta");
    assert_eq!(score, 0.0);
}

#[test]
fn semantic_similarity_empty_returns_zero() {
    assert_eq!(local_semantic_similarity("", "hello"), 0.0);
    assert_eq!(local_semantic_similarity("hello", ""), 0.0);
}

// ── tokenize_semantic_text ────────────────────────────────────────────

#[test]
fn tokenize_splits_on_punctuation() {
    let tokens = tokenize_semantic_text("hello, world! foo-bar");
    assert!(tokens.contains("hello"));
    assert!(tokens.contains("world"));
    assert!(tokens.contains("foo"));
    assert!(tokens.contains("bar"));
}

#[test]
fn tokenize_lowercases() {
    let tokens = tokenize_semantic_text("Hello WORLD");
    assert!(tokens.contains("hello"));
    assert!(tokens.contains("world"));
}

#[test]
fn tokenize_empty_string() {
    let tokens = tokenize_semantic_text("");
    assert!(tokens.is_empty());
}

// ── canonicalize_json_value ───────────────────────────────────────────

#[test]
fn canonicalize_sorts_object_keys() {
    let v = json!({"z": 1, "a": 2, "m": 3});
    let canonical = canonicalize_json_value(&v);
    let keys: Vec<_> = canonical.as_object().unwrap().keys().collect();
    assert_eq!(keys, vec!["a", "m", "z"]);
}

#[test]
fn canonicalize_nested_objects() {
    let v = json!({"outer": {"z": 1, "a": 2}});
    let canonical = canonicalize_json_value(&v);
    let inner = canonical["outer"].as_object().unwrap();
    let keys: Vec<_> = inner.keys().collect();
    assert_eq!(keys, vec!["a", "z"]);
}

#[test]
fn canonicalize_arrays_preserved_order() {
    let v = json!([3, 1, 2]);
    let canonical = canonicalize_json_value(&v);
    assert_eq!(canonical, json!([3, 1, 2]));
}

#[test]
fn canonicalize_primitives() {
    assert_eq!(canonicalize_json_value(&json!("hello")), json!("hello"));
    assert_eq!(canonicalize_json_value(&json!(42)), json!(42));
    assert_eq!(canonicalize_json_value(&json!(true)), json!(true));
    assert_eq!(canonicalize_json_value(&json!(null)), json!(null));
}

// ── extract_provider_cache_context ────────────────────────────────────

#[test]
fn provider_cache_context_with_variables() {
    let v = json!({"variables": {"env": "prod"}});
    let ctx = extract_provider_cache_context(&v).unwrap();
    assert!(ctx["variables"].is_object());
}

#[test]
fn provider_cache_context_with_verdictan_vars() {
    let v = json!({"verdictan": {"context_variables": {"a": 1}, "variables": {"b": 2}}});
    let ctx = extract_provider_cache_context(&v).unwrap();
    assert!(ctx.as_object().unwrap().len() >= 2);
}

#[test]
fn provider_cache_context_with_context_fabric_scope() {
    let v = json!({
        "verdictan": {
            "context_fabric": {
                "selected_artifact_ids": ["artifact-1"],
                "source_digests": ["sha256:tree"],
                "git_repo": "verdictan/verdictan",
                "git_branch": "feature/context"
            }
        }
    });
    let ctx = extract_provider_cache_context(&v).unwrap();
    assert_eq!(
        ctx["context_fabric"]["selected_artifact_ids"],
        json!(["artifact-1"])
    );
    assert_eq!(
        ctx["context_fabric"]["source_digests"],
        json!(["sha256:tree"])
    );
    assert_eq!(ctx["context_fabric"]["git_repo"], "verdictan/verdictan");
    assert_eq!(ctx["context_fabric"]["git_branch"], "feature/context");
}

#[test]
fn provider_cache_context_empty_when_no_vars() {
    let v = json!({"model": "gpt-4", "messages": []});
    assert!(extract_provider_cache_context(&v).is_none());
}

// ── provider_name_from_upstream ───────────────────────────────────────

#[test]
fn provider_name_from_https_url() {
    assert_eq!(
        provider_name_from_upstream("https://api.openai.com/v1"),
        "api.openai.com"
    );
}

#[test]
fn provider_name_from_http_url() {
    assert_eq!(
        provider_name_from_upstream("http://localhost:8080/v1"),
        "localhost:8080"
    );
}

#[test]
fn provider_name_no_scheme() {
    assert_eq!(
        provider_name_from_upstream("api.example.com/v1"),
        "api.example.com"
    );
}

// ── provider_scope_key ───────────────────────────────────────────────

#[test]
fn provider_scope_key_deterministic() {
    let k1 = provider_scope_key("https://api.openai.com", Some(b"key123"));
    let k2 = provider_scope_key("https://api.openai.com", Some(b"key123"));
    assert_eq!(k1, k2);
    assert!(k1.starts_with("scope:"));
    assert_eq!(k1.len(), "scope:".len() + 16);
}

#[test]
fn provider_scope_key_different_keys_differ() {
    let k1 = provider_scope_key("https://api.openai.com", Some(b"key1"));
    let k2 = provider_scope_key("https://api.openai.com", Some(b"key2"));
    assert_ne!(k1, k2);
}

#[test]
fn provider_scope_key_none_auth() {
    let k = provider_scope_key("https://api.openai.com", None);
    assert!(k.starts_with("scope:"));
}

// ── sha256_prefixed ──────────────────────────────────────────────────

#[test]
fn sha256_prefixed_deterministic() {
    let h1 = sha256_prefixed(b"hello");
    let h2 = sha256_prefixed(b"hello");
    assert_eq!(h1, h2);
    assert!(h1.starts_with("sha256:"));
}

#[test]
fn sha256_prefixed_different_input_different_hash() {
    let h1 = sha256_prefixed(b"hello");
    let h2 = sha256_prefixed(b"world");
    assert_ne!(h1, h2);
}

// ── join_upstream / rewrite_upstream_path ─────────────────────────────

#[test]
fn join_upstream_strips_trailing_slash() {
    assert_eq!(
        join_upstream("https://api.openai.com/", "/v1/chat"),
        "https://api.openai.com/v1/chat"
    );
}

#[test]
fn join_upstream_no_double_slash() {
    assert_eq!(
        join_upstream("https://api.openai.com", "v1/chat"),
        "https://api.openai.com/v1/chat"
    );
}

#[test]
fn rewrite_upstream_path_non_github() {
    assert_eq!(
        rewrite_upstream_path("https://api.openai.com", "/v1/chat/completions"),
        "/v1/chat/completions"
    );
}

#[test]
fn rewrite_upstream_path_github_models() {
    assert_eq!(
        rewrite_upstream_path(
            "https://models.inference.ai.azure.com",
            "/v1/chat/completions"
        ),
        "/inference/chat/completions"
    );
}

#[test]
fn rewrite_upstream_path_github_other_path() {
    assert_eq!(
        rewrite_upstream_path("https://models.inference.ai.azure.com", "/v1/embeddings"),
        "/inference/embeddings"
    );
}

// ── is_github_models_upstream ─────────────────────────────────────────

#[test]
fn is_github_models_true() {
    assert!(is_github_models_upstream(
        "https://models.inference.ai.azure.com/v1"
    ));
}

#[test]
fn is_github_models_false() {
    assert!(!is_github_models_upstream("https://api.openai.com/v1"));
}

// ── build_response ───────────────────────────────────────────────────

#[test]
fn build_response_sets_status_and_headers() {
    let resp = build_response(
        StatusCode::OK,
        HeaderValue::from_static("application/json"),
        "req-123".to_string(),
        "00-trace-1".to_string(),
        Bytes::from(b"{}".to_vec()),
        false,
        None,
    );
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("x-request-id").unwrap(), "req-123");
    assert_eq!(resp.headers().get("traceparent").unwrap(), "00-trace-1");
    assert!(resp.headers().get("x-verdictan-degraded").is_none());
}

#[test]
fn build_response_degraded_flag() {
    let resp = build_response(
        StatusCode::OK,
        HeaderValue::from_static("application/json"),
        "req-456".to_string(),
        "00-trace-2".to_string(),
        Bytes::new(),
        true,
        None,
    );
    assert_eq!(resp.headers().get("x-verdictan-degraded").unwrap(), "true");
}

#[test]
fn build_response_with_extra_headers() {
    let extra = vec![(
        axum::http::HeaderName::from_static("x-custom"),
        HeaderValue::from_static("hello"),
    )];
    let resp = build_response(
        StatusCode::OK,
        HeaderValue::from_static("text/plain"),
        "req-789".to_string(),
        "00-trace-3".to_string(),
        Bytes::new(),
        false,
        Some(extra),
    );
    assert_eq!(resp.headers().get("x-custom").unwrap(), "hello");
}

// ── build_streaming_error_sse_bytes ───────────────────────────────────

#[test]
fn streaming_error_sse_bytes_format() {
    let result = build_streaming_error_sse_bytes(
        "req-1",
        "1.0.0",
        "block",
        "policy.blocked",
        "Blocked by policy",
        42,
    );
    assert!(result.is_some());
    let bytes = result.unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.starts_with("data: "));
    assert!(text.contains("policy.blocked"));
    assert!(text.contains("Blocked by policy"));
    assert!(text.ends_with("\n\n"));
}

// ── build_unknown_provider_pin_body ───────────────────────────────────

#[test]
fn unknown_provider_pin_body_json_structure() {
    let body = build_unknown_provider_pin_body("custom-pin");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("custom-pin"));
    assert_eq!(v["error"]["type"], "invalid_provider_pin");
    assert_eq!(v["error"]["code"], "unknown_provider");
}

// ── build_no_compliant_provider_body ──────────────────────────────────

#[test]
fn no_compliant_provider_body_json_structure() {
    let body = build_no_compliant_provider_body();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("data-routing-policy"));
    assert_eq!(v["error"]["code"], "no_compliant_provider");
}

// ── pipeline_supported_path ──────────────────────────────────────────

#[test]
fn pipeline_supported_chat_completions() {
    assert!(pipeline_supported_path("/v1/chat/completions"));
}

#[test]
fn pipeline_supported_responses() {
    assert!(pipeline_supported_path("/v1/responses"));
}

#[test]
fn pipeline_unsupported_embeddings() {
    assert!(!pipeline_supported_path("/v1/embeddings"));
}

#[test]
fn pipeline_unsupported_audio() {
    assert!(!pipeline_supported_path("/v1/audio/speech"));
}

// ── PipelineUsageTotals ──────────────────────────────────────────────

#[test]
fn pipeline_usage_totals_default() {
    let totals = PipelineUsageTotals::default();
    assert_eq!(totals.prompt_tokens, 0);
    assert_eq!(totals.total_cost, 0.0);
    assert!(!totals.has_usage);
}

#[test]
fn pipeline_usage_totals_record_step() {
    let mut totals = PipelineUsageTotals::default();
    let usage = SpendUsage {
        prompt_tokens: 10,
        completion_tokens: 5,
        total_tokens: 15,
        cached_input_tokens: 2,
        prompt_cost: Some(0.001),
        completion_cost: Some(0.002),
        total_cost: Some(0.003),
    };
    totals.record_step(usage, 0.001, 0.002, 0.0005, 0.003);
    assert_eq!(totals.prompt_tokens, 10);
    assert_eq!(totals.completion_tokens, 5);
    assert_eq!(totals.total_tokens, 15);
    assert_eq!(totals.cached_input_tokens, 2);
    assert!(totals.has_usage);
}

#[test]
fn pipeline_usage_totals_into_json_none_without_usage() {
    let totals = PipelineUsageTotals::default();
    assert!(totals.into_json().is_none());
}

#[test]
fn pipeline_usage_totals_into_json_some_with_usage() {
    let mut totals = PipelineUsageTotals::default();
    let usage = SpendUsage {
        prompt_tokens: 100,
        completion_tokens: 50,
        total_tokens: 150,
        cached_input_tokens: 0,
        prompt_cost: None,
        completion_cost: None,
        total_cost: None,
    };
    totals.record_step(usage, 0.01, 0.02, 0.0, 0.03);
    let j = totals.into_json().unwrap();
    assert_eq!(j["prompt_tokens"], 100);
    assert_eq!(j["completion_tokens"], 50);
    assert_eq!(j["total_tokens"], 150);
}

// ── connected_provider_key_status_allows_local_fallback ───────────────

#[test]
fn connected_provider_key_allows_fallback_not_configured() {
    assert!(connected_provider_key_status_allows_local_fallback(
        "provider_key_not_configured"
    ));
}

#[test]
fn connected_provider_key_allows_fallback_seeded_deleted() {
    assert!(connected_provider_key_status_allows_local_fallback(
        "provider_key_seeded_default_deleted"
    ));
}

#[test]
fn connected_provider_key_disallows_fallback_denied() {
    assert!(!connected_provider_key_status_allows_local_fallback(
        "provider_key_policy_denied"
    ));
}

#[test]
fn connected_provider_key_disallows_fallback_active() {
    assert!(!connected_provider_key_status_allows_local_fallback(
        "active"
    ));
}

// ── error_json ───────────────────────────────────────────────────────

#[test]
fn error_json_structure() {
    let e = error_json("something failed", "server_error", "internal");
    assert_eq!(e["message"], "something failed");
    assert_eq!(e["type"], "server_error");
    assert_eq!(e["code"], "internal");
}

// ── runtime_error_id ─────────────────────────────────────────────────

#[test]
fn runtime_error_id_format() {
    let id = runtime_error_id("req-abc");
    assert!(id.starts_with("err_"));
}

// ── verdictan_verdict_for_success ────────────────────────────────────

#[test]
fn verdict_for_success_allow() {
    assert_eq!(verdictan_verdict_for_success(&Verdict::Allow), "ALLOW");
}

#[test]
fn verdict_for_success_redact() {
    assert_eq!(verdictan_verdict_for_success(&Verdict::Redact), "REDACT");
}

#[test]
fn verdict_for_success_other() {
    assert_eq!(
        verdictan_verdict_for_success(&Verdict::Escalate),
        "ESCALATE"
    );
}

// ── inject_verdictan_response_extension ─────────────────────────────

#[test]
fn inject_extension_into_json() {
    let body = Bytes::from(serde_json::to_vec(&json!({"id": "resp-1"})).unwrap());
    let ext = json!({"verdict": "allow"});
    let result = inject_verdictan_response_extension(body, ext);
    let v: serde_json::Value = serde_json::from_slice(&result).unwrap();
    assert_eq!(v["verdictan"]["verdict"], "allow");
    assert_eq!(v["id"], "resp-1");
}

#[test]
fn inject_extension_invalid_json_returns_original() {
    let body = Bytes::from("not json");
    let ext = json!({"verdict": "allow"});
    let result = inject_verdictan_response_extension(body.clone(), ext);
    assert_eq!(result, body);
}

// ── strip_verdictan_request_extension ────────────────────────────────

#[test]
fn strip_extension_removes_verdictan_key() {
    let mut v = json!({"model": "gpt-4", "verdictan": {"session_id": "s1"}});
    let removed = strip_verdictan_request_extension(&mut v);
    assert!(removed);
    assert!(v.get("verdictan").is_none());
    assert_eq!(v["model"], "gpt-4");
}

#[test]
fn strip_extension_noop_when_absent() {
    let mut v = json!({"model": "gpt-4"});
    let removed = strip_verdictan_request_extension(&mut v);
    assert!(!removed);
}

// ── extract_request_team_slugs ───────────────────────────────────────

#[test]
fn extract_team_slugs_from_header() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::HeaderName::from_static("x-verdictan-team"),
        HeaderValue::from_static("team-a,team-b, team-c "),
    );
    let slugs = extract_request_team_slugs(&headers);
    assert_eq!(slugs, vec!["team-a", "team-b", "team-c"]);
}

#[test]
fn extract_team_slugs_empty_header() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::HeaderName::from_static("x-verdictan-team"),
        HeaderValue::from_static(""),
    );
    let slugs = extract_request_team_slugs(&headers);
    assert!(slugs.is_empty());
}

#[test]
fn extract_team_slugs_missing_header() {
    let headers = HeaderMap::new();
    let slugs = extract_request_team_slugs(&headers);
    assert!(slugs.is_empty());
}

// ── validate_audio_transcription_request helpers ─────────────────────

#[test]
fn voice_is_safe_identifier_valid() {
    assert!(voice_is_safe_identifier("alloy"));
    assert!(voice_is_safe_identifier("nova-v2"));
    assert!(voice_is_safe_identifier("echo_3"));
}

#[test]
fn voice_is_safe_identifier_invalid() {
    assert!(!voice_is_safe_identifier(""));
    assert!(!voice_is_safe_identifier("voice with spaces"));
    assert!(!voice_is_safe_identifier("voice;injection"));
    assert!(!voice_is_safe_identifier("a".repeat(65).as_str()));
}

// ── BudgetFilterRejection ────────────────────────────────────────────

#[test]
fn build_budget_filter_body_json_structure() {
    let rejection = BudgetFilterRejection {
        status: StatusCode::TOO_MANY_REQUESTS,
        error_type: "budget_exceeded",
        code: "token_budget_exhausted",
        message: "Token budget exhausted".to_string(),
    };
    let body = build_budget_filter_body(&rejection);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v["error"]["message"].is_string());
    assert!(v["error"]["code"].is_string());
}

// ── RuntimePreflightError ────────────────────────────────────────────

#[test]
fn runtime_preflight_error_validation_failed() {
    let err = RuntimePreflightError::validation_failed("bad input", json!({"field": "model"}));
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert_eq!(err.code, "request.validation_failed");
}

#[test]
fn runtime_preflight_error_new() {
    let err = RuntimePreflightError::new(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "audio.bad_format",
        "Unsupported format",
        json!({"field": "format"}),
    );
    assert_eq!(err.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(err.code, "audio.bad_format");
}

// ── optional_env ─────────────────────────────────────────────────────

#[test]
fn optional_env_reads_var() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    std::env::set_var("__VERDICTAN_TEST_OPT_VAR", "hello");
    assert_eq!(
        optional_env("__VERDICTAN_TEST_OPT_VAR"),
        Some("hello".to_string())
    );
    std::env::remove_var("__VERDICTAN_TEST_OPT_VAR");
}

#[test]
fn optional_env_returns_none_for_missing() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    std::env::remove_var("__VERDICTAN_TEST_MISSING_VAR");
    assert!(optional_env("__VERDICTAN_TEST_MISSING_VAR").is_none());
}

#[test]
fn optional_env_returns_none_for_empty() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    std::env::set_var("__VERDICTAN_TEST_EMPTY_VAR", "");
    assert!(optional_env("__VERDICTAN_TEST_EMPTY_VAR").is_none());
    std::env::remove_var("__VERDICTAN_TEST_EMPTY_VAR");
}

#[test]
fn optional_env_returns_none_for_whitespace() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    std::env::set_var("__VERDICTAN_TEST_WS_VAR", "   ");
    assert!(optional_env("__VERDICTAN_TEST_WS_VAR").is_none());
    std::env::remove_var("__VERDICTAN_TEST_WS_VAR");
}

// ── streaming_requires_buffering / streaming_mode_label ───────────────

#[test]
fn streaming_mode_label_passthrough() {
    assert_eq!(streaming_mode_label(false, false), "passthrough");
}

#[test]
fn streaming_mode_label_policy_buffered() {
    assert_eq!(streaming_mode_label(true, false), "buffered_policy");
}

#[test]
fn streaming_mode_label_redaction_buffered() {
    assert_eq!(streaming_mode_label(false, true), "buffered_redaction");
}

#[test]
fn streaming_mode_label_both() {
    assert_eq!(streaming_mode_label(true, true), "buffered_redaction");
}

// ── extract_bearer_token ─────────────────────────────────────────────

#[test]
fn extract_bearer_token_standard() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer sk-test-123"),
    );
    assert_eq!(
        extract_bearer_token(&headers),
        Some("sk-test-123".to_string())
    );
}

#[test]
fn extract_bearer_token_case_insensitive() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("bearer sk-test"),
    );
    assert_eq!(extract_bearer_token(&headers), Some("sk-test".to_string()));
}

#[test]
fn extract_bearer_token_missing() {
    let headers = HeaderMap::new();
    assert!(extract_bearer_token(&headers).is_none());
}

#[test]
fn extract_bearer_token_non_bearer() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Basic abc123"),
    );
    assert!(extract_bearer_token(&headers).is_none());
}

// ── is_api_token ─────────────────────────────────────────────────────

#[test]
fn is_api_token_valid() {
    assert!(is_api_token("vdt_"));
}

#[test]
fn is_api_token_invalid() {
    assert!(!is_api_token("sk-proj-abc"));
    assert!(!is_api_token(""));
    assert!(!is_api_token("random-string"));
}

// ── decision_event_id ────────────────────────────────────────────────

#[test]
fn decision_event_id_format() {
    let id = decision_event_id("req-abc");
    assert!(id.starts_with("vdt_decision_"));
}

// ── regex_escape_literal ─────────────────────────────────────────────

#[test]
fn regex_escape_special_chars() {
    assert_eq!(regex_escape_literal("hello.world"), "hello\\.world");
    assert_eq!(regex_escape_literal("a*b+c"), "a\\*b\\+c");
    assert_eq!(regex_escape_literal("no specials"), "no specials");
}

#[test]
fn regex_escape_brackets_and_parens() {
    assert_eq!(regex_escape_literal("[test]"), "\\[test\\]");
    assert_eq!(regex_escape_literal("(test)"), "\\(test\\)");
}

// ── publication_state_accepts_public_traffic ─────────────────────────

#[test]
fn publication_state_active() {
    assert!(publication_state_accepts_public_traffic("published"));
}

#[test]
fn publication_state_serving() {
    assert!(publication_state_accepts_public_traffic("draining"));
}

#[test]
fn publication_state_disabled() {
    assert!(!publication_state_accepts_public_traffic("disabled"));
}

#[test]
fn publication_state_unknown() {
    assert!(!publication_state_accepts_public_traffic("paused"));
}

// ── serving_fleet_class_requires_public_pool_membership ──────────────

#[test]
fn fleet_class_public_requires_membership() {
    assert!(serving_fleet_class_requires_public_pool_membership(
        "connected_cell_pool"
    ));
}

#[test]
fn fleet_class_shared_requires_membership() {
    assert!(!serving_fleet_class_requires_public_pool_membership(
        "shared"
    ));
}

#[test]
fn fleet_class_dedicated_no_membership() {
    assert!(!serving_fleet_class_requires_public_pool_membership(
        "dedicated"
    ));
}

// ── github_models_api_version_header ──────────────────────────────────

#[test]
fn github_models_api_version_has_default() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    std::env::remove_var("VERDICTAN_GITHUB_MODELS_API_VERSION");
    let version = github_models_api_version_header();
    assert!(!version.is_empty());
    std::env::remove_var("VERDICTAN_GITHUB_MODELS_API_VERSION");
}

// ── extract_config_version (additional cases) ────────────────────────

#[test]
fn extract_config_version_no_match() {
    assert!(extract_config_version("gateway:\n  name: test").is_none());
}

#[test]
fn extract_config_version_empty_value() {
    assert!(extract_config_version("version: ").is_none());
}

// ── normalize_runtime_plugin_id ──────────────────────────────────────

#[test]
fn normalize_plugin_id_valid() {
    let result = normalize_runtime_plugin_id("my-plugin");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "my-plugin");
}

#[test]
fn normalize_plugin_id_lowercases() {
    let result = normalize_runtime_plugin_id("  MY_Plugin  ");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "my-plugin");
}

#[test]
fn normalize_plugin_id_empty_error() {
    let result = normalize_runtime_plugin_id("  ");
    assert!(result.is_err());
}

// ── normalize_runtime_data_collection ────────────────────────────────

#[test]
fn normalize_data_collection_allow() {
    assert_eq!(normalize_runtime_data_collection("ALLOW").unwrap(), "allow");
}

#[test]
fn normalize_data_collection_deny() {
    assert_eq!(normalize_runtime_data_collection("deny").unwrap(), "deny");
}

#[test]
fn normalize_data_collection_invalid() {
    assert!(normalize_runtime_data_collection("partial").is_err());
}

// ── parse_runtime_cache_ttl ──────────────────────────────────────────

#[test]
fn parse_cache_ttl_seconds() {
    let d = parse_runtime_cache_ttl("60").unwrap();
    assert_eq!(d, Duration::from_secs(60));
}

#[test]
fn parse_cache_ttl_with_suffix() {
    let d = parse_runtime_cache_ttl("5m").unwrap();
    assert_eq!(d, Duration::from_secs(300));
}

#[test]
fn parse_cache_ttl_hours() {
    let d = parse_runtime_cache_ttl("2h").unwrap();
    assert_eq!(d, Duration::from_secs(7200));
}

#[test]
fn parse_cache_ttl_zero_clamps_to_minimum() {
    let d = parse_runtime_cache_ttl("0").unwrap();
    assert_eq!(d, Duration::from_secs(1));
}

#[test]
fn parse_cache_ttl_negative_error() {
    assert!(parse_runtime_cache_ttl("-5").is_err());
}

#[test]
fn parse_cache_ttl_garbage_error() {
    assert!(parse_runtime_cache_ttl("abc").is_err());
}

// ── SpendUsage with costs ────────────────────────────────────────────

#[test]
fn spend_usage_with_all_fields() {
    let u = SpendUsage {
        prompt_tokens: 100,
        completion_tokens: 50,
        total_tokens: 150,
        cached_input_tokens: 10,
        prompt_cost: Some(0.01),
        completion_cost: Some(0.02),
        total_cost: Some(0.03),
    };
    assert_eq!(u.prompt_tokens, 100);
    assert_eq!(u.total_cost, Some(0.03));
}

// ── split_provider_prefixed_model_reference ──────────────────────────

#[test]
fn split_provider_prefixed_valid() {
    let result = split_provider_prefixed_model_reference("openai/gpt-4");
    assert_eq!(result, Some(("openai", "gpt-4")));
}

#[test]
fn split_provider_prefixed_no_slash() {
    let result = split_provider_prefixed_model_reference("gpt-4");
    assert!(result.is_none());
}

#[test]
fn split_provider_prefixed_empty_parts() {
    assert!(split_provider_prefixed_model_reference("/gpt-4").is_none());
    assert!(split_provider_prefixed_model_reference("openai/").is_none());
}

// ── infer_provider_from_model ────────────────────────────────────────

#[test]
fn infer_provider_openai_gpt() {
    let provider = infer_provider_from_model("gpt-4");
    assert_eq!(provider, Some("openai".to_string()));
}

#[test]
fn infer_provider_anthropic_claude() {
    let provider = infer_provider_from_model("claude-3-opus");
    assert_eq!(provider, Some("anthropic".to_string()));
}

#[test]
fn infer_provider_unknown() {
    let provider = infer_provider_from_model("custom-model-v1");
    assert!(provider.is_none());
}

// ── infer_provider_from_upstream ──────────────────────────────────────

#[test]
fn infer_provider_from_openai_url() {
    let provider = infer_provider_from_upstream("https://api.openai.com/v1");
    assert_eq!(provider, "openai");
}

#[test]
fn infer_provider_from_anthropic_url() {
    let provider = infer_provider_from_upstream("https://api.anthropic.com/v1");
    assert_eq!(provider, "anthropic");
}

#[test]
fn infer_provider_from_unknown_url() {
    let provider = infer_provider_from_upstream("https://custom.example.com/v1");
    assert!(!provider.is_empty());
}
