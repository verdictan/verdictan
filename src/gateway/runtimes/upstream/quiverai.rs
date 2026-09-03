// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::{json, Value};

use crate::error::CliError;

use super::VerdictanUpstreamRuntime;

pub static QUIVERAI_RUNTIME: QuiverAiRuntime = QuiverAiRuntime;

pub struct QuiverAiRuntime;

impl super::super::VerdictanRuntime for QuiverAiRuntime {
    fn runtime_id(&self) -> &'static str {
        "quiverai"
    }

    fn validate_config(&self, config: &Value) -> Result<(), CliError> {
        let mut base_url = None;
        for key in ["model", "base_url"] {
            match config.get(key).and_then(Value::as_str).map(str::trim) {
                Some(value) if !value.is_empty() => {
                    if key == "base_url" {
                        base_url = Some(value);
                    }
                }
                _ => {
                    return Err(CliError::user(format!(
                        "{key} is required for quiverai runtime"
                    )))
                }
            }
        }
        // SAFETY: base_url is guaranteed Some after validate succeeds
        #[allow(clippy::expect_used)]
        let base_url = base_url.expect("base_url captured during validation");
        self.validate_endpoint_url(base_url)?;
        Ok(())
    }

    fn build_request(&self, config: &Value, input: &Value) -> Result<Value, CliError> {
        let model = config
            .get("model")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| CliError::user("model is required for quiverai runtime"))?;

        Ok(json!({
            "model": model,
            "prompt": prompt_text(input),
            "stream": false,
        }))
    }

    fn execute(&self, _config: &Value, request: &Value) -> Result<Value, CliError> {
        Ok(request.clone())
    }

    fn translate_response(&self, response: &Value) -> Result<Value, CliError> {
        let id = response
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("quiverai-chatcmpl");
        let created = response
            .get("created")
            .cloned()
            .unwrap_or_else(|| json!(chrono::Utc::now().timestamp()));
        let content = response
            .get("data")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry.get("svg").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join("\n\n")
            })
            .unwrap_or_default();
        let usage = response.get("usage").cloned().unwrap_or_else(|| json!({}));

        Ok(json!({
            "id": id,
            "object": "chat.completion",
            "created": created,
            "model": response.get("model").cloned().unwrap_or_else(|| json!("arrow-preview")),
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": content,
                },
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": usage.get("input_tokens").cloned().unwrap_or_else(|| json!(0)),
                "completion_tokens": usage.get("output_tokens").cloned().unwrap_or_else(|| json!(0)),
                "total_tokens": usage.get("total_tokens").cloned().unwrap_or_else(|| json!(0)),
            }
        }))
    }

    fn default_path_template(&self) -> Option<&'static str> {
        crate::gateway::provider_catalog::provider_path_template_for_public_path(
            self.provider_kind(),
            "/v1/chat/completions",
        )
        .or(Some("/svgs/generations"))
    }
}

impl VerdictanUpstreamRuntime for QuiverAiRuntime {
    fn provider_kind(&self) -> &'static str {
        "quiverai"
    }

    fn validate_endpoint_url(&self, base_url: &str) -> Result<(), CliError> {
        if base_url.starts_with("http://") || base_url.starts_with("https://") {
            return Ok(());
        }
        Err(CliError::user(
            "quiverai runtime requires an http:// or https:// base_url",
        ))
    }

    fn normalize_upstream_response(&self, response: &Value) -> Result<Value, CliError> {
        Ok(response.clone())
    }
}

fn prompt_text(input: &Value) -> String {
    input
        .get("messages")
        .and_then(Value::as_array)
        .and_then(|messages| messages.last())
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            input
                .get("prompt")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .or_else(|| {
            input
                .get("input")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .unwrap_or_default()
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
    use crate::gateway::runtimes::VerdictanRuntime;
    use serde_json::json;

    #[test]
    fn runtime_id() {
        assert_eq!(QUIVERAI_RUNTIME.runtime_id(), "quiverai");
    }

    #[test]
    fn provider_kind() {
        assert_eq!(QUIVERAI_RUNTIME.provider_kind(), "quiverai");
    }

    #[test]
    fn validate_config_valid_https() {
        let config = json!({"model": "arrow-preview", "base_url": "https://api.quiverai.com"});
        assert!(QUIVERAI_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_valid_http() {
        let config = json!({"model": "arrow-preview", "base_url": "http://localhost:8080"});
        assert!(QUIVERAI_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_missing_fields() {
        assert!(QUIVERAI_RUNTIME
            .validate_config(&json!({"model": "m"}))
            .is_err());
        assert!(QUIVERAI_RUNTIME
            .validate_config(&json!({"base_url": "https://x.com"}))
            .is_err());
    }

    #[test]
    fn validate_endpoint_url_accepts_http_and_https() {
        assert!(QUIVERAI_RUNTIME
            .validate_endpoint_url("https://api.quiverai.com")
            .is_ok());
        assert!(QUIVERAI_RUNTIME
            .validate_endpoint_url("http://localhost:8080")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_url_rejects_other_schemes() {
        assert!(QUIVERAI_RUNTIME
            .validate_endpoint_url("ftp://example.com")
            .is_err());
    }

    #[test]
    fn default_path_template_value() {
        assert_eq!(
            VerdictanRuntime::default_path_template(&QUIVERAI_RUNTIME),
            Some("/svgs/generations")
        );
    }

    #[test]
    fn build_request_includes_model_and_prompt() {
        let config = json!({"model": "arrow-preview"});
        let input = json!({"messages": [{"role": "user", "content": "draw a cat"}]});
        let result = QUIVERAI_RUNTIME.build_request(&config, &input).unwrap();
        assert_eq!(result["model"], "arrow-preview");
        assert_eq!(result["prompt"], "draw a cat");
        assert_eq!(result["stream"], false);
    }

    #[test]
    fn build_request_missing_model_errors() {
        let config = json!({});
        let input = json!({"messages": [{"role": "user", "content": "hi"}]});
        assert!(QUIVERAI_RUNTIME.build_request(&config, &input).is_err());
    }

    #[test]
    fn prompt_text_from_messages() {
        let input = json!({"messages": [
            {"role": "system", "content": "you are helpful"},
            {"role": "user", "content": "draw something"}
        ]});
        assert_eq!(prompt_text(&input), "draw something");
    }

    #[test]
    fn prompt_text_from_prompt_field() {
        let input = json!({"prompt": "draw a house"});
        assert_eq!(prompt_text(&input), "draw a house");
    }

    #[test]
    fn prompt_text_from_input_field() {
        let input = json!({"input": "draw a tree"});
        assert_eq!(prompt_text(&input), "draw a tree");
    }

    #[test]
    fn prompt_text_empty_fallback() {
        let input = json!({"other": "value"});
        assert_eq!(prompt_text(&input), "");
    }

    #[test]
    fn translate_response_produces_chat_completion_format() {
        let response = json!({
            "id": "resp-1",
            "created": 1700000000,
            "model": "arrow-preview",
            "data": [
                {"svg": "<svg>circle</svg>"},
                {"svg": "<svg>square</svg>"}
            ],
            "usage": {
                "input_tokens": 10,
                "output_tokens": 50,
                "total_tokens": 60
            }
        });
        let result = QUIVERAI_RUNTIME.translate_response(&response).unwrap();
        assert_eq!(result["id"], "resp-1");
        assert_eq!(result["object"], "chat.completion");
        assert_eq!(result["model"], "arrow-preview");
        let content = result["choices"][0]["message"]["content"].as_str().unwrap();
        assert!(content.contains("<svg>circle</svg>"));
        assert!(content.contains("<svg>square</svg>"));
        assert_eq!(result["usage"]["prompt_tokens"], 10);
        assert_eq!(result["usage"]["completion_tokens"], 50);
        assert_eq!(result["usage"]["total_tokens"], 60);
    }

    #[test]
    fn translate_response_handles_missing_data() {
        let response = json!({"model": "arrow-preview"});
        let result = QUIVERAI_RUNTIME.translate_response(&response).unwrap();
        assert_eq!(result["choices"][0]["message"]["content"], "");
        assert_eq!(result["choices"][0]["finish_reason"], "stop");
    }

    #[test]
    fn translate_response_default_id() {
        let response = json!({});
        let result = QUIVERAI_RUNTIME.translate_response(&response).unwrap();
        assert_eq!(result["id"], "quiverai-chatcmpl");
    }
}
