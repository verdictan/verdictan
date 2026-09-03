// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

use super::VerdictanUpstreamRuntime;

pub static OPENAI_RUNTIME: OpenAiRuntime = OpenAiRuntime;

pub struct OpenAiRuntime;

impl super::super::VerdictanRuntime for OpenAiRuntime {
    fn runtime_id(&self) -> &'static str {
        "openai"
    }

    fn validate_config(&self, config: &Value) -> Result<(), CliError> {
        validate_required_string(config, "model")?;
        validate_required_string(config, "base_url")?;
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
        crate::gateway::provider_catalog::provider_path_template_for_public_path(
            self.provider_kind(),
            "/v1/chat/completions",
        )
        .or(Some("/v1/chat/completions"))
    }
}

impl VerdictanUpstreamRuntime for OpenAiRuntime {
    fn provider_kind(&self) -> &'static str {
        "openai"
    }

    fn validate_endpoint_url(&self, base_url: &str) -> Result<(), CliError> {
        validate_base_url(base_url)
    }

    fn normalize_upstream_response(&self, response: &Value) -> Result<Value, CliError> {
        Ok(response.clone())
    }
}

fn validate_required_string(config: &Value, key: &str) -> Result<(), CliError> {
    match config.get(key).and_then(Value::as_str).map(str::trim) {
        Some(value) if !value.is_empty() => Ok(()),
        _ => Err(CliError::user(format!(
            "{key} is required for openai runtime"
        ))),
    }
}

fn validate_base_url(base_url: &str) -> Result<(), CliError> {
    if base_url.starts_with("https://") || base_url.starts_with("http://") {
        return Ok(());
    }
    Err(CliError::user(
        "base_url must start with http:// or https:// for openai runtime",
    ))
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
    fn runtime_id_returns_openai() {
        assert_eq!(OPENAI_RUNTIME.runtime_id(), "openai");
    }

    #[test]
    fn provider_kind_returns_openai() {
        assert_eq!(OPENAI_RUNTIME.provider_kind(), "openai");
    }

    #[test]
    fn validate_config_accepts_valid() {
        let config = json!({"model": "gpt-4", "base_url": "https://api.openai.com"});
        assert!(OPENAI_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_rejects_missing_model() {
        let config = json!({"base_url": "https://api.openai.com"});
        assert!(OPENAI_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_missing_base_url() {
        let config = json!({"model": "gpt-4"});
        assert!(OPENAI_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_empty_model() {
        let config = json!({"model": "", "base_url": "https://api.openai.com"});
        assert!(OPENAI_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_whitespace_only_model() {
        let config = json!({"model": "  ", "base_url": "https://api.openai.com"});
        assert!(OPENAI_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_required_string_accepts_valid() {
        let config = json!({"key": "value"});
        assert!(validate_required_string(&config, "key").is_ok());
    }

    #[test]
    fn validate_required_string_rejects_missing() {
        let config = json!({});
        assert!(validate_required_string(&config, "key").is_err());
    }

    #[test]
    fn validate_base_url_accepts_https() {
        assert!(validate_base_url("https://api.openai.com").is_ok());
    }

    #[test]
    fn validate_base_url_accepts_http() {
        assert!(validate_base_url("http://localhost:8080").is_ok());
    }

    #[test]
    fn validate_base_url_rejects_bare_hostname() {
        assert!(validate_base_url("api.openai.com").is_err());
    }

    #[test]
    fn validate_endpoint_url_delegates_to_validate_base_url() {
        assert!(OPENAI_RUNTIME
            .validate_endpoint_url("https://api.openai.com")
            .is_ok());
        assert!(OPENAI_RUNTIME.validate_endpoint_url("ftp://nope").is_err());
    }

    #[test]
    fn build_request_passes_through() {
        let input = json!({"messages": [{"role": "user", "content": "hi"}]});
        let result = OPENAI_RUNTIME.build_request(&json!({}), &input).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn execute_passes_through() {
        let req = json!({"test": 1});
        assert_eq!(OPENAI_RUNTIME.execute(&json!({}), &req).unwrap(), req);
    }

    #[test]
    fn translate_response_passes_through() {
        let resp = json!({"choices": []});
        assert_eq!(OPENAI_RUNTIME.translate_response(&resp).unwrap(), resp);
    }

    #[test]
    fn normalize_upstream_response_passes_through() {
        let resp = json!({"id": "chatcmpl-123"});
        assert_eq!(
            OPENAI_RUNTIME.normalize_upstream_response(&resp).unwrap(),
            resp
        );
    }

    #[test]
    fn supports_streaming_and_tools() {
        assert!(OPENAI_RUNTIME.supports_streaming());
        assert!(OPENAI_RUNTIME.supports_tools());
    }

    #[test]
    fn default_path_template_contains_chat_completions() {
        let path = VerdictanRuntime::default_path_template(&OPENAI_RUNTIME);
        assert!(path.is_some());
        assert!(path.unwrap().contains("chat/completions"));
    }
}
