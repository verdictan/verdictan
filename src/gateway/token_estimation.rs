// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Lightweight prompt-token estimation for pre-call context-window checks.
//!
//! Uses a chars/4 heuristic (widely accepted rough approximation for English/Latin
//! text across BPE tokenizers). This intentionally trades precision for zero
//! external dependencies — a real tiktoken or HuggingFace tokenizer can be swapped
//! in later without changing the call-site API.

use super::content_extraction::{
    collect_request_text_segments_for_path, extract_request_messages, extract_responses_messages,
};

pub fn estimate_text_tokens(text: &str) -> usize {
    text.len().div_ceil(4)
}

fn estimate_message_tokens(
    messages: &[super::content_extraction::ExtractedRequestMessage],
    message_count: usize,
) -> usize {
    let total_chars: usize = messages.iter().map(|message| message.content.len()).sum();
    total_chars.div_ceil(4) + (message_count * 4)
}

fn estimate_field_tokens(field_name: &str, value: &serde_json::Value, path: &str) -> Option<usize> {
    if let serde_json::Value::Array(items) = value {
        if items.iter().all(serde_json::Value::is_number) {
            return Some(items.len() + 4);
        }
    }

    let body = serde_json::json!({ field_name: value.clone() });
    let segments = collect_request_text_segments_for_path(path, &body);
    if segments.is_empty() {
        return None;
    }

    Some(
        segments
            .iter()
            .map(|segment| estimate_text_tokens(&segment.text) + 4)
            .sum(),
    )
}

pub fn estimate_prompt_tokens_for_path(path: &str, body: &serde_json::Value) -> Option<usize> {
    match path {
        "/v1/chat/completions" => {
            let raw_messages = body.get("messages").and_then(|value| value.as_array())?;
            let messages = extract_request_messages(body);
            Some(estimate_message_tokens(&messages, raw_messages.len()))
        }
        "/v1/messages" => {
            let raw_message_count = body
                .get("messages")
                .and_then(|value| value.as_array())
                .map_or(0, Vec::len);
            let system_count = body
                .get("system")
                .and_then(|value| value.as_str())
                .filter(|value| !value.trim().is_empty())
                .map_or(0, |_| 1);
            if raw_message_count == 0 && system_count == 0 {
                return None;
            }
            let messages = extract_request_messages(body);
            Some(estimate_message_tokens(
                &messages,
                raw_message_count + system_count,
            ))
        }
        "/v1/responses" => {
            if body.get("messages").is_some() {
                return estimate_prompt_tokens_for_path("/v1/chat/completions", body);
            }

            let messages = extract_responses_messages(body);
            if !messages.is_empty() {
                return Some(estimate_message_tokens(&messages, messages.len()));
            }

            body.get("input")
                .and_then(|input| estimate_field_tokens("input", input, "/v1/responses"))
        }
        "/v1/embeddings" => body
            .get("input")
            .and_then(|input| estimate_field_tokens("input", input, "/v1/embeddings")),
        "/v1/moderations" => body
            .get("input")
            .and_then(|input| estimate_field_tokens("input", input, "/v1/moderations")),
        "/v1/audio/speech" => body
            .get("input")
            .and_then(|input| estimate_field_tokens("input", input, "/v1/audio/speech")),
        "/v1/audio/transcriptions" => body
            .get("prompt")
            .and_then(|prompt| estimate_field_tokens("prompt", prompt, "/v1/audio/transcriptions")),
        "/v1/completions" => body
            .get("prompt")
            .and_then(|prompt| estimate_field_tokens("prompt", prompt, "/v1/completions")),
        _ => None,
    }
}

/// Estimate the number of tokens in a chat-completions-style request body.
///
/// Supports message, prompt, and input payloads across the gateway's public
/// request families.
///
/// Returns `None` when neither field is present (caller should skip the check).
pub fn estimate_prompt_tokens(body: &serde_json::Value) -> Option<usize> {
    if body.get("messages").is_some() {
        if body.get("system").is_some() {
            return estimate_prompt_tokens_for_path("/v1/messages", body);
        }
        return estimate_prompt_tokens_for_path("/v1/chat/completions", body);
    }

    if body.get("prompt").is_some() {
        if body.get("input_audio").is_some() {
            return estimate_prompt_tokens_for_path("/v1/audio/transcriptions", body);
        }
        return estimate_prompt_tokens_for_path("/v1/completions", body);
    }

    if let Some(input) = body.get("input") {
        if body.get("instructions").is_some() {
            return estimate_prompt_tokens_for_path("/v1/responses", body);
        }
        if body.get("voice").is_some() || body.get("response_format").is_some() {
            return estimate_prompt_tokens_for_path("/v1/audio/speech", body);
        }
        return estimate_field_tokens("input", input, "/v1/embeddings")
            .or_else(|| estimate_field_tokens("input", input, "/v1/moderations"))
            .or_else(|| estimate_field_tokens("input", input, "/v1/responses"));
    }

    None
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn estimate_text_tokens_empty_string() {
        assert_eq!(estimate_text_tokens(""), 0);
    }

    #[test]
    fn estimate_text_tokens_short_text() {
        assert_eq!(estimate_text_tokens("hi"), 1);
        assert_eq!(estimate_text_tokens("test"), 1);
        assert_eq!(estimate_text_tokens("hello"), 2);
    }

    #[test]
    fn estimate_text_tokens_exact_multiple_of_four() {
        assert_eq!(estimate_text_tokens("12345678"), 2);
        assert_eq!(estimate_text_tokens("1234567890123456"), 4);
    }

    #[test]
    fn estimate_text_tokens_rounds_up() {
        assert_eq!(estimate_text_tokens("123456789"), 3);
        assert_eq!(estimate_text_tokens("1"), 1);
        assert_eq!(estimate_text_tokens("12"), 1);
        assert_eq!(estimate_text_tokens("123"), 1);
    }

    #[test]
    fn estimate_prompt_tokens_with_messages() {
        let body = json!({
            "messages": [
                {"role": "user", "content": "Hello world!"}
            ]
        });
        // "Hello world!" is 12 chars → 3 tokens + 4 overhead = 7
        assert_eq!(estimate_prompt_tokens(&body), Some(7));
    }

    #[test]
    fn estimate_prompt_tokens_multiple_messages() {
        let body = json!({
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Hi"}
            ]
        });
        // "You are helpful." = 16 chars, "Hi" = 2 chars → total 18 chars
        // 18.div_ceil(4) = 5 tokens + 2*4 overhead = 13
        assert_eq!(estimate_prompt_tokens(&body), Some(13));
    }

    #[test]
    fn estimate_prompt_tokens_empty_messages() {
        let body = json!({"messages": []});
        assert_eq!(estimate_prompt_tokens(&body), Some(0));
    }

    #[test]
    fn estimate_prompt_tokens_messages_without_content() {
        let body = json!({
            "messages": [{"role": "user"}]
        });
        // No content → 0 chars, div_ceil(4) = 0, plus 4 overhead = 4
        assert_eq!(estimate_prompt_tokens(&body), Some(4));
    }

    #[test]
    fn estimate_prompt_tokens_input_string() {
        let body = json!({"input": "Hello world!"});
        // 12 chars → estimate_text_tokens = 3, plus 4 overhead = 7
        assert_eq!(estimate_prompt_tokens(&body), Some(7));
    }

    #[test]
    fn estimate_prompt_tokens_input_array_of_strings() {
        let body = json!({"input": ["Hello", "World"]});
        // "Hello" = 5 chars → 2 tokens + 4 = 6
        // "World" = 5 chars → 2 tokens + 4 = 6
        // total = 12
        assert_eq!(estimate_prompt_tokens(&body), Some(12));
    }

    #[test]
    fn estimate_prompt_tokens_input_array_of_numbers() {
        let body = json!({"input": [1, 2, 3, 4, 5]});
        // 5 numbers + 4 overhead = 9
        assert_eq!(estimate_prompt_tokens(&body), Some(9));
    }

    #[test]
    fn estimate_prompt_tokens_input_array_of_objects_with_text() {
        let body = json!({"input": [{"text": "Hello world!"}]});
        // "Hello world!" = 12 chars → 3 tokens + 4 = 7
        assert_eq!(estimate_prompt_tokens(&body), Some(7));
    }

    #[test]
    fn estimate_field_tokens_string_adds_fixed_overhead() {
        assert_eq!(
            estimate_field_tokens("input", &json!("abcd"), "/v1/moderations"),
            Some(5)
        );
    }

    #[test]
    fn estimate_prompt_tokens_mixed_supported_items_skip_unsupported_entries() {
        let body = json!({
            "input": [
                "hello",
                {"content": [{"type": "input_text", "text": "rust"}]},
                true,
                null
            ]
        });
        assert_eq!(
            estimate_prompt_tokens_for_path("/v1/responses", &body),
            Some(11)
        );
    }

    #[test]
    fn estimate_prompt_tokens_array_without_supported_entries_returns_none() {
        let body = json!({"input": [{"kind": "image"}, false]});
        assert_eq!(estimate_prompt_tokens(&body), None);
    }

    #[test]
    fn estimate_prompt_tokens_input_array_mixed_unsupported() {
        let body = json!({"input": [true, null]});
        assert_eq!(estimate_prompt_tokens(&body), None);
    }

    #[test]
    fn estimate_prompt_tokens_no_messages_no_input() {
        let body = json!({"model": "gpt-4"});
        assert_eq!(estimate_prompt_tokens(&body), None);
    }

    #[test]
    fn estimate_prompt_tokens_input_number() {
        let body = json!({"input": 42});
        assert_eq!(estimate_prompt_tokens(&body), None);
    }

    #[test]
    fn estimate_prompt_tokens_messages_takes_priority_over_input() {
        let body = json!({
            "messages": [{"role": "user", "content": "Hi"}],
            "input": "This should be ignored"
        });
        // "Hi" = 2 chars → 1 token + 4 overhead = 5
        assert_eq!(estimate_prompt_tokens(&body), Some(5));
    }

    #[test]
    fn estimate_prompt_tokens_messages_include_block_array_text() {
        let body = json!({
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "Hello"}]},
                {"role": "assistant", "content": "ok"}
            ]
        });
        // "Hello" = 5 chars, "ok" = 2 chars → ceil(7/4) = 2 + 2*4 overhead = 10
        assert_eq!(estimate_prompt_tokens(&body), Some(10));
    }

    #[test]
    fn estimate_prompt_tokens_input_array_of_objects_ignores_missing_text_fields() {
        let body = json!({"input": [{"text": "Hello"}, {"kind": "image"}]});
        assert_eq!(estimate_prompt_tokens(&body), Some(6));
    }

    #[test]
    fn estimate_prompt_tokens_messages_api_includes_system_and_block_text() {
        let body = json!({
            "system": "Classify securely",
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "Patient SSN 123-45-6789"}
                ]
            }]
        });
        assert_eq!(
            estimate_prompt_tokens_for_path("/v1/messages", &body),
            Some(18)
        );
    }

    #[test]
    fn estimate_prompt_tokens_responses_instructions_and_block_input() {
        let body = json!({
            "instructions": "Be brief",
            "input": [{
                "role": "user",
                "content": [
                    {"type": "input_text", "text": "Account 4111111111111111"}
                ]
            }]
        });
        assert_eq!(
            estimate_prompt_tokens_for_path("/v1/responses", &body),
            Some(16)
        );
    }

    #[test]
    fn estimate_prompt_tokens_moderations_block_array_input() {
        let body = json!({
            "input": [{
                "role": "user",
                "content": [
                    {"type": "input_text", "text": "Patient SSN 123-45-6789"}
                ]
            }]
        });
        assert_eq!(
            estimate_prompt_tokens_for_path("/v1/moderations", &body),
            Some(10)
        );
    }

    #[test]
    fn estimate_prompt_tokens_completions_prompt_field() {
        let body = json!({"prompt": "legacy"});
        assert_eq!(estimate_prompt_tokens(&body), Some(6));
    }
}
