// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

use super::VerdictanUpstreamRuntime;

pub static ALIBABA_RUNTIME: AlibabaRuntime = AlibabaRuntime;

pub struct AlibabaRuntime;

impl super::super::VerdictanRuntime for AlibabaRuntime {
    fn runtime_id(&self) -> &'static str {
        "alibaba"
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
                        "{key} is required for alibaba runtime"
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

    fn build_request(&self, _config: &Value, input: &Value) -> Result<Value, CliError> {
        Ok(input.clone())
    }
    fn execute(&self, _config: &Value, request: &Value) -> Result<Value, CliError> {
        Ok(request.clone())
    }
    fn translate_response(&self, response: &Value) -> Result<Value, CliError> {
        Ok(response.clone())
    }
    fn supports_streaming(&self) -> bool {
        true
    }
    fn supports_tools(&self) -> bool {
        true
    }

    fn default_path_template(&self) -> Option<&'static str> {
        Some("/v1/chat/completions")
    }
}

impl VerdictanUpstreamRuntime for AlibabaRuntime {
    fn provider_kind(&self) -> &'static str {
        "alibaba"
    }
    fn validate_endpoint_url(&self, base_url: &str) -> Result<(), CliError> {
        if base_url.starts_with("https://") {
            Ok(())
        } else {
            Err(CliError::user(
                "alibaba runtime requires an https:// base_url",
            ))
        }
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
    fn runtime_id_returns_alibaba() {
        assert_eq!(ALIBABA_RUNTIME.runtime_id(), "alibaba");
    }

    #[test]
    fn provider_kind_returns_alibaba() {
        assert_eq!(ALIBABA_RUNTIME.provider_kind(), "alibaba");
    }

    #[test]
    fn validate_config_accepts_valid_config() {
        let config = json!({
            "model": "qwen-turbo",
            "base_url": "https://dashscope.aliyuncs.com"
        });
        assert!(ALIBABA_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_rejects_missing_model() {
        let config = json!({
            "base_url": "https://dashscope.aliyuncs.com"
        });
        let err = ALIBABA_RUNTIME.validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("model"));
    }

    #[test]
    fn validate_config_rejects_missing_base_url() {
        let config = json!({
            "model": "qwen-turbo"
        });
        let err = ALIBABA_RUNTIME.validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("base_url"));
    }

    #[test]
    fn validate_config_rejects_empty_model() {
        let config = json!({
            "model": "  ",
            "base_url": "https://dashscope.aliyuncs.com"
        });
        let err = ALIBABA_RUNTIME.validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("model"));
    }

    #[test]
    fn validate_config_rejects_empty_base_url() {
        let config = json!({
            "model": "qwen-turbo",
            "base_url": ""
        });
        let err = ALIBABA_RUNTIME.validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("base_url"));
    }

    #[test]
    fn validate_config_rejects_http_base_url() {
        let config = json!({
            "model": "qwen-turbo",
            "base_url": "http://dashscope.aliyuncs.com"
        });
        assert!(ALIBABA_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_endpoint_url_accepts_https() {
        assert!(ALIBABA_RUNTIME
            .validate_endpoint_url("https://example.com")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_url_rejects_http() {
        assert!(ALIBABA_RUNTIME
            .validate_endpoint_url("http://example.com")
            .is_err());
    }

    #[test]
    fn validate_endpoint_url_rejects_bare_host() {
        assert!(ALIBABA_RUNTIME
            .validate_endpoint_url("example.com")
            .is_err());
    }

    #[test]
    fn default_path_template_is_chat_completions() {
        assert_eq!(
            VerdictanRuntime::default_path_template(&ALIBABA_RUNTIME),
            Some("/v1/chat/completions")
        );
    }

    #[test]
    fn build_request_passes_input_through() {
        let config = json!({"model": "qwen-turbo"});
        let input = json!({"messages": [{"role": "user", "content": "hi"}]});
        let result = ALIBABA_RUNTIME.build_request(&config, &input).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn execute_passes_request_through() {
        let config = json!({});
        let request = json!({"messages": []});
        let result = ALIBABA_RUNTIME.execute(&config, &request).unwrap();
        assert_eq!(result, request);
    }

    #[test]
    fn translate_response_passes_through() {
        let response = json!({"id": "resp-1", "choices": []});
        let result = ALIBABA_RUNTIME.translate_response(&response).unwrap();
        assert_eq!(result, response);
    }

    #[test]
    fn normalize_upstream_response_passes_through() {
        let response = json!({"data": "test"});
        let result = ALIBABA_RUNTIME
            .normalize_upstream_response(&response)
            .unwrap();
        assert_eq!(result, response);
    }

    #[test]
    fn supports_streaming_is_true() {
        assert!(ALIBABA_RUNTIME.supports_streaming());
    }

    #[test]
    fn supports_tools_is_true() {
        assert!(ALIBABA_RUNTIME.supports_tools());
    }
}
