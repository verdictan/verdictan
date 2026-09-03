// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

/// Result of inspecting a provider response for zero-completion conditions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZeroCompletionResult {
    /// Response contains valid completion content.
    Ok,
    /// Zero tokens and blank/null/error finish_reason — should retry.
    ZeroCompletion { finish_reason: String },
    /// Response body is not parseable as a chat completion — pass through.
    NotApplicable,
}

/// Inspect a chat-completion response body for zero-completion conditions.
///
/// A zero completion occurs when:
/// - `usage.completion_tokens == 0`, AND
/// - `choices[0].finish_reason` is empty, null, or an error value like "error" / "content_filter".
///
/// This is distinct from a legitimate empty response (e.g. `finish_reason: "stop"` with
/// completion_tokens == 0, which some providers use for function-call-only responses).
pub fn check_response(body: &Value) -> ZeroCompletionResult {
    // Check usage.completion_tokens.
    let completion_tokens = body
        .pointer("/usage/completion_tokens")
        .and_then(|v| v.as_u64());

    let completion_tokens = match completion_tokens {
        Some(t) => t,
        None => return ZeroCompletionResult::NotApplicable,
    };

    if completion_tokens > 0 {
        return ZeroCompletionResult::Ok;
    }

    // Zero tokens — check finish_reason.
    let finish_reason = body
        .pointer("/choices/0/finish_reason")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let is_error_finish = matches!(
        finish_reason,
        "" | "error" | "content_filter" | "content_filter_error"
    );

    // Check if finish_reason is null explicitly.
    let is_null_finish = body
        .pointer("/choices/0/finish_reason")
        .is_none_or(|v| v.is_null());

    if is_error_finish || is_null_finish {
        ZeroCompletionResult::ZeroCompletion {
            finish_reason: if is_null_finish && finish_reason.is_empty() {
                "null".to_string()
            } else {
                finish_reason.to_string()
            },
        }
    } else {
        // finish_reason is "stop", "length", "tool_calls", etc. — legitimate.
        ZeroCompletionResult::Ok
    }
}

/// Check a streaming response for zero-completion by inspecting the final accumulated state.
/// `accumulated_content` is the full streamed content, `finish_reason` is from the final chunk.
#[allow(dead_code)]
fn check_stream_result(
    accumulated_content: &str,
    finish_reason: Option<&str>,
) -> ZeroCompletionResult {
    if !accumulated_content.is_empty() {
        return ZeroCompletionResult::Ok;
    }

    let reason = finish_reason.unwrap_or("");
    let is_error_finish = matches!(
        reason,
        "" | "error" | "content_filter" | "content_filter_error"
    );

    if is_error_finish || finish_reason.is_none() {
        ZeroCompletionResult::ZeroCompletion {
            finish_reason: if finish_reason.is_none() {
                "null".to_string()
            } else {
                reason.to_string()
            },
        }
    } else {
        ZeroCompletionResult::Ok
    }
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
    fn check_response_ok_with_positive_completion_tokens() {
        let body = json!({
            "usage": {"completion_tokens": 10},
            "choices": [{"finish_reason": "stop"}]
        });
        assert_eq!(check_response(&body), ZeroCompletionResult::Ok);
    }

    #[test]
    fn check_response_not_applicable_without_usage() {
        let body = json!({"choices": [{"finish_reason": "stop"}]});
        assert_eq!(check_response(&body), ZeroCompletionResult::NotApplicable);
    }

    #[test]
    fn check_response_not_applicable_without_completion_tokens() {
        let body = json!({"usage": {"prompt_tokens": 10}});
        assert_eq!(check_response(&body), ZeroCompletionResult::NotApplicable);
    }

    #[test]
    fn check_response_zero_tokens_with_stop_is_ok() {
        let body = json!({
            "usage": {"completion_tokens": 0},
            "choices": [{"finish_reason": "stop"}]
        });
        assert_eq!(check_response(&body), ZeroCompletionResult::Ok);
    }

    #[test]
    fn check_response_zero_tokens_with_length_is_ok() {
        let body = json!({
            "usage": {"completion_tokens": 0},
            "choices": [{"finish_reason": "length"}]
        });
        assert_eq!(check_response(&body), ZeroCompletionResult::Ok);
    }

    #[test]
    fn check_response_zero_tokens_with_tool_calls_is_ok() {
        let body = json!({
            "usage": {"completion_tokens": 0},
            "choices": [{"finish_reason": "tool_calls"}]
        });
        assert_eq!(check_response(&body), ZeroCompletionResult::Ok);
    }

    #[test]
    fn check_response_zero_tokens_empty_finish_reason() {
        let body = json!({
            "usage": {"completion_tokens": 0},
            "choices": [{"finish_reason": ""}]
        });
        assert_eq!(
            check_response(&body),
            ZeroCompletionResult::ZeroCompletion {
                finish_reason: "".to_string()
            }
        );
    }

    #[test]
    fn check_response_zero_tokens_error_finish() {
        let body = json!({
            "usage": {"completion_tokens": 0},
            "choices": [{"finish_reason": "error"}]
        });
        assert_eq!(
            check_response(&body),
            ZeroCompletionResult::ZeroCompletion {
                finish_reason: "error".to_string()
            }
        );
    }

    #[test]
    fn check_response_zero_tokens_content_filter() {
        let body = json!({
            "usage": {"completion_tokens": 0},
            "choices": [{"finish_reason": "content_filter"}]
        });
        assert_eq!(
            check_response(&body),
            ZeroCompletionResult::ZeroCompletion {
                finish_reason: "content_filter".to_string()
            }
        );
    }

    #[test]
    fn check_response_zero_tokens_content_filter_error() {
        let body = json!({
            "usage": {"completion_tokens": 0},
            "choices": [{"finish_reason": "content_filter_error"}]
        });
        assert_eq!(
            check_response(&body),
            ZeroCompletionResult::ZeroCompletion {
                finish_reason: "content_filter_error".to_string()
            }
        );
    }

    #[test]
    fn check_response_zero_tokens_null_finish_reason() {
        let body = json!({
            "usage": {"completion_tokens": 0},
            "choices": [{"finish_reason": null}]
        });
        assert_eq!(
            check_response(&body),
            ZeroCompletionResult::ZeroCompletion {
                finish_reason: "null".to_string()
            }
        );
    }

    #[test]
    fn check_response_zero_tokens_no_choices() {
        let body = json!({
            "usage": {"completion_tokens": 0}
        });
        assert_eq!(
            check_response(&body),
            ZeroCompletionResult::ZeroCompletion {
                finish_reason: "null".to_string()
            }
        );
    }

    #[test]
    fn check_stream_result_non_empty_content_is_ok() {
        assert_eq!(
            check_stream_result("hello", Some("stop")),
            ZeroCompletionResult::Ok
        );
        assert_eq!(check_stream_result("hello", None), ZeroCompletionResult::Ok);
    }

    #[test]
    fn check_stream_result_empty_with_stop_is_ok() {
        assert_eq!(
            check_stream_result("", Some("stop")),
            ZeroCompletionResult::Ok
        );
    }

    #[test]
    fn check_stream_result_empty_with_none_is_zero() {
        assert_eq!(
            check_stream_result("", None),
            ZeroCompletionResult::ZeroCompletion {
                finish_reason: "null".to_string()
            }
        );
    }

    #[test]
    fn check_stream_result_empty_with_error() {
        assert_eq!(
            check_stream_result("", Some("error")),
            ZeroCompletionResult::ZeroCompletion {
                finish_reason: "error".to_string()
            }
        );
    }

    #[test]
    fn check_stream_result_empty_with_content_filter() {
        assert_eq!(
            check_stream_result("", Some("content_filter")),
            ZeroCompletionResult::ZeroCompletion {
                finish_reason: "content_filter".to_string()
            }
        );
    }

    #[test]
    fn check_stream_result_empty_with_empty_reason() {
        assert_eq!(
            check_stream_result("", Some("")),
            ZeroCompletionResult::ZeroCompletion {
                finish_reason: "".to_string()
            }
        );
    }

    #[test]
    fn check_stream_result_empty_with_length_is_ok() {
        assert_eq!(
            check_stream_result("", Some("length")),
            ZeroCompletionResult::Ok
        );
    }

    #[test]
    fn check_stream_result_empty_with_tool_calls_is_ok() {
        assert_eq!(
            check_stream_result("", Some("tool_calls")),
            ZeroCompletionResult::Ok
        );
    }
}
