// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

use super::VerdictanUpstreamRuntime;

pub static LLAMA_CPP_RUNTIME: LlamaCppRuntime = LlamaCppRuntime;

pub struct LlamaCppRuntime;

impl super::super::VerdictanRuntime for LlamaCppRuntime {
    fn runtime_id(&self) -> &'static str {
        "llama.cpp"
    }

    fn validate_config(&self, config: &Value) -> Result<(), CliError> {
        let base_url = config
            .get("base_url")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| CliError::user("base_url is required for llama.cpp runtime"))?;
        self.validate_endpoint_url(base_url)
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
        Some("/v1/chat/completions")
    }
}

impl VerdictanUpstreamRuntime for LlamaCppRuntime {
    fn provider_kind(&self) -> &'static str {
        "llama.cpp"
    }

    fn validate_endpoint_url(&self, base_url: &str) -> Result<(), CliError> {
        if base_url.starts_with("http://") || base_url.starts_with("https://") {
            return Ok(());
        }
        Err(CliError::user(
            "llama.cpp runtime requires an http:// or https:// base_url",
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
    fn runtime_id_returns_llama_cpp() {
        assert_eq!(LLAMA_CPP_RUNTIME.runtime_id(), "llama.cpp");
    }

    #[test]
    fn provider_kind_returns_llama_cpp() {
        assert_eq!(LLAMA_CPP_RUNTIME.provider_kind(), "llama.cpp");
    }

    #[test]
    fn validate_config_accepts_http_base_url() {
        let config = json!({"base_url": "http://localhost:8080"});
        assert!(LLAMA_CPP_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_accepts_https_base_url() {
        let config = json!({"base_url": "https://llama-cpp.example.com"});
        assert!(LLAMA_CPP_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_rejects_missing_base_url() {
        let config = json!({});
        let err = LLAMA_CPP_RUNTIME.validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("base_url"));
    }

    #[test]
    fn validate_config_rejects_empty_base_url() {
        let config = json!({"base_url": ""});
        assert!(LLAMA_CPP_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_whitespace_base_url() {
        let config = json!({"base_url": "   "});
        assert!(LLAMA_CPP_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_bare_host() {
        let config = json!({"base_url": "localhost:8080"});
        assert!(LLAMA_CPP_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_endpoint_url_accepts_http() {
        assert!(LLAMA_CPP_RUNTIME
            .validate_endpoint_url("http://localhost:8080")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_url_accepts_https() {
        assert!(LLAMA_CPP_RUNTIME
            .validate_endpoint_url("https://llama-cpp.example.com")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_url_rejects_bare_host() {
        assert!(LLAMA_CPP_RUNTIME
            .validate_endpoint_url("localhost:8080")
            .is_err());
    }

    #[test]
    fn validate_endpoint_url_rejects_ftp() {
        assert!(LLAMA_CPP_RUNTIME
            .validate_endpoint_url("ftp://localhost:8080")
            .is_err());
    }

    #[test]
    fn default_path_template_is_chat_completions() {
        assert_eq!(
            VerdictanRuntime::default_path_template(&LLAMA_CPP_RUNTIME),
            Some("/v1/chat/completions")
        );
    }

    #[test]
    fn auth_optional_is_true() {
        assert!(LLAMA_CPP_RUNTIME.auth_optional());
    }

    #[test]
    fn build_request_passes_through() {
        let config = json!({});
        let input = json!({"messages": []});
        let result = LLAMA_CPP_RUNTIME.build_request(&config, &input).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn execute_passes_through() {
        let config = json!({});
        let request = json!({"prompt": "test"});
        let result = LLAMA_CPP_RUNTIME.execute(&config, &request).unwrap();
        assert_eq!(result, request);
    }

    #[test]
    fn translate_response_passes_through() {
        let response = json!({"choices": []});
        let result = LLAMA_CPP_RUNTIME.translate_response(&response).unwrap();
        assert_eq!(result, response);
    }

    #[test]
    fn normalize_upstream_response_passes_through() {
        let response = json!({"content": "hello"});
        let result = LLAMA_CPP_RUNTIME
            .normalize_upstream_response(&response)
            .unwrap();
        assert_eq!(result, response);
    }

    #[test]
    fn supports_streaming_is_true() {
        assert!(LLAMA_CPP_RUNTIME.supports_streaming());
    }

    #[test]
    fn supports_tools_is_true() {
        assert!(LLAMA_CPP_RUNTIME.supports_tools());
    }
}
