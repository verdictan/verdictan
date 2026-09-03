// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;
use crate::gateway::format_translation::{infer_request_format, translate_request, ProviderFormat};

use super::VerdictanUpstreamRuntime;

pub static ANTHROPIC_RUNTIME: AnthropicRuntime = AnthropicRuntime;

pub struct AnthropicRuntime;

impl AnthropicRuntime {
    /// Extract assistant text from a Messages-shaped response for output policy.
    fn assistant_text_for_policy(response: &Value) -> String {
        response
            .get("content")
            .and_then(Value::as_array)
            .map(|blocks| {
                blocks
                    .iter()
                    .filter_map(|block| {
                        (block.get("type").and_then(Value::as_str) == Some("text"))
                            .then(|| {
                                block
                                    .get("text")
                                    .and_then(Value::as_str)
                                    .map(str::to_string)
                            })
                            .flatten()
                    })
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default()
    }
}

impl super::super::VerdictanRuntime for AnthropicRuntime {
    fn runtime_id(&self) -> &'static str {
        "anthropic"
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
                        "{key} is required for anthropic runtime"
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
        if let Some(version) = config.get("anthropic_version").and_then(Value::as_str) {
            if version.trim().is_empty() {
                return Err(CliError::user(
                    "anthropic_version cannot be empty when provided",
                ));
            }
        }

        let source_format = infer_request_format(input);
        let mut request =
            translate_request(input.clone(), source_format, ProviderFormat::Anthropic)?;
        if let Some(object) = request.as_object_mut() {
            object.remove("anthropic_version");
            // Keep stream/tools/system available for Messages governance parity.
            if let Some(stream) = input.get("stream") {
                object.insert("stream".to_string(), stream.clone());
            }
            if let Some(tools) = input.get("tools") {
                object.entry("tools".to_string()).or_insert(tools.clone());
            }
            if let Some(tool_choice) = input.get("tool_choice") {
                object
                    .entry("tool_choice".to_string())
                    .or_insert(tool_choice.clone());
            }
            if let Some(system) = input.get("system") {
                object.entry("system".to_string()).or_insert(system.clone());
            }
        }
        Ok(request)
    }

    fn execute(&self, _config: &Value, request: &Value) -> Result<Value, CliError> {
        Ok(request.clone())
    }

    fn translate_response(&self, response: &Value) -> Result<Value, CliError> {
        if response.get("error").is_some()
            || response.get("type").and_then(Value::as_str) == Some("error")
        {
            return Ok(response.clone());
        }
        if response.get("content").and_then(Value::as_array).is_none() {
            return Err(CliError::user("anthropic response missing content array"));
        }
        Ok(response.clone())
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn supports_tools(&self) -> bool {
        true
    }

    fn default_path_template(&self) -> Option<&'static str> {
        Some("/v1/messages")
    }
}

impl VerdictanUpstreamRuntime for AnthropicRuntime {
    fn provider_kind(&self) -> &'static str {
        "anthropic"
    }

    fn validate_endpoint_url(&self, base_url: &str) -> Result<(), CliError> {
        if base_url.starts_with("https://") {
            return Ok(());
        }
        if let Ok(url) = reqwest::Url::parse(base_url) {
            if url.scheme() == "http" {
                if let Some(host) = url.host_str() {
                    if matches!(host, "127.0.0.1" | "localhost" | "::1") {
                        return Ok(());
                    }
                }
            }
        }
        Err(CliError::user(
            "anthropic runtime requires an https:// base_url unless it targets a loopback test endpoint",
        ))
    }

    fn normalize_upstream_response(&self, response: &Value) -> Result<Value, CliError> {
        Ok(response.clone())
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
    use crate::gateway::runtimes::VerdictanRuntime;
    use serde_json::json;

    #[test]
    fn runtime_id_returns_anthropic() {
        assert_eq!(ANTHROPIC_RUNTIME.runtime_id(), "anthropic");
    }

    #[test]
    fn provider_kind_returns_anthropic() {
        assert_eq!(ANTHROPIC_RUNTIME.provider_kind(), "anthropic");
    }

    #[test]
    fn validate_config_accepts_valid_config() {
        let config = json!({
            "model": "claude-3-opus",
            "base_url": "https://api.anthropic.com",
            "anthropic_version": "2023-06-01"
        });
        assert!(ANTHROPIC_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_rejects_missing_model() {
        let config = json!({
            "base_url": "https://api.anthropic.com",
            "anthropic_version": "2023-06-01"
        });
        let err = ANTHROPIC_RUNTIME.validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("model"));
    }

    #[test]
    fn validate_config_rejects_missing_base_url() {
        let config = json!({
            "model": "claude-3-opus",
            "anthropic_version": "2023-06-01"
        });
        let err = ANTHROPIC_RUNTIME.validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("base_url"));
    }

    #[test]
    fn validate_config_accepts_config_without_anthropic_version() {
        let config = json!({
            "model": "claude-3-opus",
            "base_url": "https://api.anthropic.com"
        });
        assert!(ANTHROPIC_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_rejects_empty_model() {
        let config = json!({
            "model": "",
            "base_url": "https://api.anthropic.com",
            "anthropic_version": "2023-06-01"
        });
        assert!(ANTHROPIC_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_endpoint_url_accepts_https() {
        assert!(ANTHROPIC_RUNTIME
            .validate_endpoint_url("https://api.anthropic.com")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_url_accepts_http_localhost() {
        assert!(ANTHROPIC_RUNTIME
            .validate_endpoint_url("http://localhost:8080")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_url_accepts_http_127_0_0_1() {
        assert!(ANTHROPIC_RUNTIME
            .validate_endpoint_url("http://127.0.0.1:9000")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_url_accepts_http_ipv6_loopback() {
        let result = ANTHROPIC_RUNTIME.validate_endpoint_url("http://[::1]:8080");
        let host = reqwest::Url::parse("http://[::1]:8080")
            .ok()
            .and_then(|u| u.host_str().map(String::from));
        if host.as_deref() == Some("::1") {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn validate_endpoint_url_rejects_http_non_loopback() {
        assert!(ANTHROPIC_RUNTIME
            .validate_endpoint_url("http://api.anthropic.com")
            .is_err());
    }

    #[test]
    fn validate_endpoint_url_rejects_bare_host() {
        assert!(ANTHROPIC_RUNTIME
            .validate_endpoint_url("api.anthropic.com")
            .is_err());
    }

    #[test]
    fn default_path_template_is_messages() {
        assert_eq!(
            VerdictanRuntime::default_path_template(&ANTHROPIC_RUNTIME),
            Some("/v1/messages")
        );
    }

    #[test]
    fn build_request_strips_anthropic_version_from_translated_body() {
        let config = json!({"anthropic_version": "2023-06-01"});
        let input = json!({"messages": [{"role": "user", "content": "hi"}]});
        let result = ANTHROPIC_RUNTIME.build_request(&config, &input).unwrap();
        assert!(result.get("anthropic_version").is_none());
        assert!(result.get("messages").is_some());
    }

    #[test]
    fn build_request_omits_anthropic_version_when_config_omits_it() {
        let config = json!({});
        let input = json!({"messages": []});
        let result = ANTHROPIC_RUNTIME.build_request(&config, &input).unwrap();
        assert!(result.get("anthropic_version").is_none());
    }

    #[test]
    fn build_request_strips_anthropic_version_from_input() {
        let config = json!({"anthropic_version": "2023-06-01"});
        let input = json!({"anthropic_version": "2024-01-01", "messages": []});
        let result = ANTHROPIC_RUNTIME.build_request(&config, &input).unwrap();
        assert!(result.get("anthropic_version").is_none());
    }

    #[test]
    fn build_request_rejects_empty_anthropic_version_in_config() {
        let config = json!({"anthropic_version": "  "});
        let input = json!({"messages": []});
        let err = ANTHROPIC_RUNTIME
            .build_request(&config, &input)
            .unwrap_err();
        assert!(err.to_string().contains("anthropic_version"));
    }

    #[test]
    fn execute_passes_request_through() {
        let config = json!({});
        let request = json!({"messages": []});
        let result = ANTHROPIC_RUNTIME.execute(&config, &request).unwrap();
        assert_eq!(result, request);
    }

    #[test]
    fn translate_response_passes_through() {
        let response = json!({"id": "msg_01", "content": []});
        let result = ANTHROPIC_RUNTIME.translate_response(&response).unwrap();
        assert_eq!(result, response);
    }

    #[test]
    fn normalize_upstream_response_passes_through() {
        let response = json!({"data": "test"});
        let result = ANTHROPIC_RUNTIME
            .normalize_upstream_response(&response)
            .unwrap();
        assert_eq!(result, response);
    }

    #[test]
    fn supports_streaming_is_true() {
        assert!(ANTHROPIC_RUNTIME.supports_streaming());
    }

    #[test]
    fn supports_tools_is_true() {
        assert!(ANTHROPIC_RUNTIME.supports_tools());
    }

    #[test]
    fn build_request_preserves_stream_and_tools_for_governance() {
        let config = json!({
            "model": "claude-3-opus",
            "base_url": "https://api.anthropic.com"
        });
        let input = json!({
            "stream": true,
            "system": "Be brief",
            "tools": [{
                "name": "lookup",
                "description": "Lookup",
                "input_schema": {"type": "object", "properties": {}}
            }],
            "tool_choice": {"type": "auto"},
            "messages": [{"role": "user", "content": "hi"}]
        });
        let result = ANTHROPIC_RUNTIME.build_request(&config, &input).unwrap();
        assert_eq!(result.get("stream"), Some(&json!(true)));
        assert!(result
            .get("tools")
            .and_then(|v| v.as_array())
            .is_some_and(|tools| !tools.is_empty()));
        assert!(result.get("tool_choice").is_some());
        assert_eq!(result.get("system"), Some(&json!("Be brief")));
    }

    #[test]
    fn assistant_text_for_policy_joins_text_blocks() {
        let response = json!({
            "content": [
                {"type": "text", "text": "hello "},
                {"type": "tool_use", "name": "lookup", "id": "1", "input": {}},
                {"type": "text", "text": "world"}
            ]
        });
        assert_eq!(
            AnthropicRuntime::assistant_text_for_policy(&response),
            "hello world"
        );
    }
}
