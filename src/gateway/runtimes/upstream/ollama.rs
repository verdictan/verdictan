// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::{json, Value};

use crate::error::CliError;
use crate::gateway::runtimes::VerdictanRuntime;

use super::VerdictanUpstreamRuntime;

pub static OLLAMA_RUNTIME: OllamaRuntime = OllamaRuntime;

pub struct OllamaRuntime;

impl super::super::VerdictanRuntime for OllamaRuntime {
    fn runtime_id(&self) -> &'static str {
        "ollama"
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
                        "{key} is required for ollama runtime"
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
            .ok_or_else(|| CliError::user("model is required for ollama runtime"))?;
        let path_template = config
            .get("path_template")
            .and_then(Value::as_str)
            .unwrap_or("/api/chat");
        let stream = input
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if path_template.contains("/api/embeddings") {
            return Ok(json!({
                "model": model,
                "prompt": embedding_prompt(input),
            }));
        }

        if path_template.contains("/api/generate") {
            return Ok(json!({
                "model": model,
                "prompt": prompt_text(input),
                "stream": stream,
            }));
        }

        Ok(json!({
            "model": model,
            "messages": ollama_messages(input),
            "stream": stream,
            "tools": input.get("tools").cloned().unwrap_or(Value::Null),
        }))
    }

    fn execute(&self, _config: &Value, request: &Value) -> Result<Value, CliError> {
        Ok(request.clone())
    }

    fn translate_response(&self, response: &Value) -> Result<Value, CliError> {
        if let Some(embedding) = response.get("embedding") {
            let model = response
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or("ollama");
            return Ok(json!({
                "object": "list",
                "data": [{
                    "object": "embedding",
                    "embedding": embedding,
                    "index": 0,
                }],
                "model": model,
            }));
        }

        if let Some(message) = response.get("message") {
            let content = normalized_message_content(message);
            let finish_reason = response
                .get("done_reason")
                .and_then(Value::as_str)
                .unwrap_or("stop");
            let model = response
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or("ollama");
            return Ok(json!({
                "id": "ollama-chat",
                "object": "chat.completion",
                "created": 0,
                "model": model,
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": message.get("role").and_then(Value::as_str).unwrap_or("assistant"),
                        "content": content,
                    },
                    "finish_reason": finish_reason,
                }],
                "usage": usage_block(response),
            }));
        }

        if let Some(content) = response.get("response").and_then(Value::as_str) {
            let finish_reason = response
                .get("done_reason")
                .and_then(Value::as_str)
                .unwrap_or("stop");
            let model = response
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or("ollama");
            return Ok(json!({
                "id": "ollama-completion",
                "object": "text_completion",
                "created": 0,
                "model": model,
                "choices": [{
                    "index": 0,
                    "text": content,
                    "finish_reason": finish_reason,
                }],
                "usage": usage_block(response),
            }));
        }

        Ok(response.clone())
    }

    fn auth_optional(&self) -> bool {
        true
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn supports_tools(&self) -> bool {
        true
    }
    fn default_path_template(&self) -> Option<&'static str> {
        Some("/api/chat")
    }
}

impl VerdictanUpstreamRuntime for OllamaRuntime {
    fn provider_kind(&self) -> &'static str {
        "ollama"
    }

    fn validate_endpoint_url(&self, base_url: &str) -> Result<(), CliError> {
        if base_url.starts_with("http://") || base_url.starts_with("https://") {
            return Ok(());
        }
        Err(CliError::user(
            "ollama runtime requires an http:// or https:// base_url",
        ))
    }

    fn normalize_upstream_response(&self, response: &Value) -> Result<Value, CliError> {
        self.translate_response(response)
    }
}

fn ollama_messages(input: &Value) -> Vec<Value> {
    input
        .get("messages")
        .and_then(Value::as_array)
        .map(|messages| {
            messages
                .iter()
                .map(|message| {
                    json!({
                        "role": message.get("role").and_then(Value::as_str).unwrap_or("user"),
                        "content": normalized_message_content(message),
                    })
                })
                .collect()
        })
        .unwrap_or_else(|| {
            vec![json!({
                "role": "user",
                "content": prompt_text(input),
            })]
        })
}

fn normalized_message_content(message: &Value) -> String {
    let Some(content) = message.get("content") else {
        return String::new();
    };

    if let Some(text) = content.as_str() {
        return text.to_string();
    }

    content
        .as_array()
        .map(|parts| {
            parts
                .iter()
                .filter_map(|part| part.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

fn prompt_text(input: &Value) -> String {
    input
        .get("prompt")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            input
                .get("input")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .or_else(|| {
            input
                .get("messages")
                .and_then(Value::as_array)
                .and_then(|messages| {
                    messages
                        .iter()
                        .rev()
                        .find(|message| message.get("role").and_then(Value::as_str) == Some("user"))
                })
                .map(normalized_message_content)
        })
        .unwrap_or_default()
}

fn embedding_prompt(input: &Value) -> String {
    if let Some(value) = input.get("input") {
        if let Some(text) = value.as_str() {
            return text.to_string();
        }
        if let Some(items) = value.as_array() {
            return items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("\n");
        }
    }

    prompt_text(input)
}

fn usage_block(response: &Value) -> Value {
    let prompt_tokens = response
        .get("prompt_eval_count")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let completion_tokens = response
        .get("eval_count")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    json!({
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens,
    })
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
    fn runtime_id_returns_ollama() {
        assert_eq!(OLLAMA_RUNTIME.runtime_id(), "ollama");
    }

    #[test]
    fn provider_kind_returns_ollama() {
        assert_eq!(OLLAMA_RUNTIME.provider_kind(), "ollama");
    }

    #[test]
    fn validate_config_accepts_valid_http() {
        let config = json!({"model": "llama3", "base_url": "http://localhost:11434"});
        assert!(OLLAMA_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_accepts_valid_https() {
        let config = json!({"model": "llama3", "base_url": "https://ollama.example.com"});
        assert!(OLLAMA_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_rejects_missing_model() {
        let config = json!({"base_url": "http://localhost:11434"});
        let err = OLLAMA_RUNTIME.validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("model"));
    }

    #[test]
    fn validate_config_rejects_missing_base_url() {
        let config = json!({"model": "llama3"});
        let err = OLLAMA_RUNTIME.validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("base_url"));
    }

    #[test]
    fn validate_config_rejects_bare_hostname() {
        let config = json!({"model": "llama3", "base_url": "localhost:11434"});
        assert!(OLLAMA_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_endpoint_url_accepts_http_and_https() {
        assert!(OLLAMA_RUNTIME
            .validate_endpoint_url("http://localhost:11434")
            .is_ok());
        assert!(OLLAMA_RUNTIME
            .validate_endpoint_url("https://ollama.host")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_url_rejects_other_schemes() {
        assert!(OLLAMA_RUNTIME.validate_endpoint_url("ftp://host").is_err());
    }

    #[test]
    fn auth_optional_is_true() {
        assert!(OLLAMA_RUNTIME.auth_optional());
    }

    #[test]
    fn supports_streaming_and_tools() {
        assert!(OLLAMA_RUNTIME.supports_streaming());
        assert!(OLLAMA_RUNTIME.supports_tools());
    }

    #[test]
    fn default_path_template_is_api_chat() {
        assert_eq!(
            VerdictanRuntime::default_path_template(&OLLAMA_RUNTIME),
            Some("/api/chat")
        );
    }

    #[test]
    fn build_request_chat_format() {
        let config = json!({"model": "llama3"});
        let input = json!({
            "messages": [{"role": "user", "content": "hello"}],
            "stream": false
        });
        let result = OLLAMA_RUNTIME.build_request(&config, &input).unwrap();
        assert_eq!(result["model"], "llama3");
        assert_eq!(result["stream"], false);
        assert!(result["messages"].is_array());
    }

    #[test]
    fn build_request_embeddings_path() {
        let config = json!({"model": "nomic-embed", "path_template": "/api/embeddings"});
        let input = json!({"input": "test text"});
        let result = OLLAMA_RUNTIME.build_request(&config, &input).unwrap();
        assert_eq!(result["model"], "nomic-embed");
        assert!(result.get("prompt").is_some());
    }

    #[test]
    fn build_request_generate_path() {
        let config = json!({"model": "llama3", "path_template": "/api/generate"});
        let input = json!({"prompt": "Once upon a time", "stream": true});
        let result = OLLAMA_RUNTIME.build_request(&config, &input).unwrap();
        assert_eq!(result["model"], "llama3");
        assert_eq!(result["stream"], true);
        assert!(result.get("prompt").is_some());
    }

    #[test]
    fn build_request_rejects_missing_model() {
        let config = json!({});
        let input = json!({"messages": []});
        assert!(OLLAMA_RUNTIME.build_request(&config, &input).is_err());
    }

    #[test]
    fn translate_response_embedding_format() {
        let response = json!({
            "embedding": [0.1, 0.2, 0.3],
            "model": "nomic-embed"
        });
        let result = OLLAMA_RUNTIME.translate_response(&response).unwrap();
        assert_eq!(result["object"], "list");
        assert_eq!(result["data"][0]["object"], "embedding");
        assert_eq!(result["model"], "nomic-embed");
    }

    #[test]
    fn translate_response_chat_message_format() {
        let response = json!({
            "message": {"role": "assistant", "content": "Hello!"},
            "done_reason": "stop",
            "model": "llama3",
            "prompt_eval_count": 10,
            "eval_count": 5
        });
        let result = OLLAMA_RUNTIME.translate_response(&response).unwrap();
        assert_eq!(result["object"], "chat.completion");
        assert_eq!(result["choices"][0]["message"]["content"], "Hello!");
        assert_eq!(result["choices"][0]["finish_reason"], "stop");
        assert_eq!(result["usage"]["prompt_tokens"], 10);
        assert_eq!(result["usage"]["completion_tokens"], 5);
        assert_eq!(result["usage"]["total_tokens"], 15);
    }

    #[test]
    fn translate_response_generate_text_format() {
        let response = json!({
            "response": "Once upon a time...",
            "done_reason": "length",
            "model": "llama3"
        });
        let result = OLLAMA_RUNTIME.translate_response(&response).unwrap();
        assert_eq!(result["object"], "text_completion");
        assert_eq!(result["choices"][0]["text"], "Once upon a time...");
        assert_eq!(result["choices"][0]["finish_reason"], "length");
    }

    #[test]
    fn translate_response_passthrough_for_unknown_format() {
        let response = json!({"custom": "data"});
        let result = OLLAMA_RUNTIME.translate_response(&response).unwrap();
        assert_eq!(result, response);
    }

    #[test]
    fn ollama_messages_from_input() {
        let input = json!({
            "messages": [
                {"role": "system", "content": "Be helpful"},
                {"role": "user", "content": "Hi"}
            ]
        });
        let msgs = ollama_messages(&input);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0]["role"], "system");
        assert_eq!(msgs[1]["role"], "user");
    }

    #[test]
    fn ollama_messages_fallback_to_prompt() {
        let input = json!({"prompt": "Hello"});
        let msgs = ollama_messages(&input);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0]["role"], "user");
        assert_eq!(msgs[0]["content"], "Hello");
    }

    #[test]
    fn normalized_message_content_string() {
        let msg = json!({"content": "hello world"});
        assert_eq!(normalized_message_content(&msg), "hello world");
    }

    #[test]
    fn normalized_message_content_array_of_parts() {
        let msg = json!({"content": [{"text": "part1"}, {"text": "part2"}]});
        assert_eq!(normalized_message_content(&msg), "part1\npart2");
    }

    #[test]
    fn normalized_message_content_missing() {
        let msg = json!({"role": "user"});
        assert_eq!(normalized_message_content(&msg), "");
    }

    #[test]
    fn prompt_text_from_prompt_field() {
        let input = json!({"prompt": "test prompt"});
        assert_eq!(prompt_text(&input), "test prompt");
    }

    #[test]
    fn prompt_text_from_input_field() {
        let input = json!({"input": "test input"});
        assert_eq!(prompt_text(&input), "test input");
    }

    #[test]
    fn prompt_text_from_last_user_message() {
        let input = json!({
            "messages": [
                {"role": "system", "content": "sys"},
                {"role": "user", "content": "last user msg"}
            ]
        });
        assert_eq!(prompt_text(&input), "last user msg");
    }

    #[test]
    fn prompt_text_empty_fallback() {
        let input = json!({});
        assert_eq!(prompt_text(&input), "");
    }

    #[test]
    fn embedding_prompt_from_string_input() {
        let input = json!({"input": "embed this"});
        assert_eq!(embedding_prompt(&input), "embed this");
    }

    #[test]
    fn embedding_prompt_from_array_input() {
        let input = json!({"input": ["a", "b", "c"]});
        assert_eq!(embedding_prompt(&input), "a\nb\nc");
    }

    #[test]
    fn embedding_prompt_falls_back_to_prompt_text() {
        let input = json!({"prompt": "fallback"});
        assert_eq!(embedding_prompt(&input), "fallback");
    }

    #[test]
    fn usage_block_extracts_token_counts() {
        let resp = json!({"prompt_eval_count": 100, "eval_count": 50});
        let usage = usage_block(&resp);
        assert_eq!(usage["prompt_tokens"], 100);
        assert_eq!(usage["completion_tokens"], 50);
        assert_eq!(usage["total_tokens"], 150);
    }

    #[test]
    fn usage_block_defaults_to_zero() {
        let resp = json!({});
        let usage = usage_block(&resp);
        assert_eq!(usage["prompt_tokens"], 0);
        assert_eq!(usage["completion_tokens"], 0);
        assert_eq!(usage["total_tokens"], 0);
    }
}
