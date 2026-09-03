// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use super::VerdictanUpstreamRuntime;
use crate::error::CliError;
use serde_json::Value;
pub static LITELLM_RUNTIME: LiteLlmRuntime = LiteLlmRuntime;
pub struct LiteLlmRuntime;
impl super::super::VerdictanRuntime for LiteLlmRuntime {
    fn runtime_id(&self) -> &'static str {
        "litellm"
    }
    fn validate_config(&self, config: &Value) -> Result<(), CliError> {
        let base_url = config
            .get("base_url")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| CliError::user("base_url is required for litellm runtime"))?;
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
    fn requires_model(&self) -> bool {
        true
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
impl VerdictanUpstreamRuntime for LiteLlmRuntime {
    fn provider_kind(&self) -> &'static str {
        "litellm"
    }
    fn validate_endpoint_url(&self, base_url: &str) -> Result<(), CliError> {
        if base_url.starts_with("http://") || base_url.starts_with("https://") {
            Ok(())
        } else {
            Err(CliError::user(
                "litellm runtime requires an http:// or https:// base_url",
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
    fn runtime_id_returns_litellm() {
        assert_eq!(LITELLM_RUNTIME.runtime_id(), "litellm");
    }

    #[test]
    fn provider_kind_returns_litellm() {
        assert_eq!(LITELLM_RUNTIME.provider_kind(), "litellm");
    }

    #[test]
    fn validate_config_accepts_https_base_url() {
        let config = json!({"base_url": "https://litellm.example.com"});
        assert!(LITELLM_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_accepts_http_base_url() {
        let config = json!({"base_url": "http://localhost:4000"});
        assert!(LITELLM_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_rejects_missing_base_url() {
        let config = json!({});
        let err = LITELLM_RUNTIME.validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("base_url"));
    }

    #[test]
    fn validate_config_rejects_empty_base_url() {
        let config = json!({"base_url": ""});
        let err = LITELLM_RUNTIME.validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("base_url"));
    }

    #[test]
    fn validate_config_rejects_whitespace_base_url() {
        let config = json!({"base_url": "   "});
        assert!(LITELLM_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_bare_host() {
        let config = json!({"base_url": "litellm.example.com"});
        assert!(LITELLM_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_endpoint_url_accepts_http() {
        assert!(LITELLM_RUNTIME
            .validate_endpoint_url("http://localhost:4000")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_url_accepts_https() {
        assert!(LITELLM_RUNTIME
            .validate_endpoint_url("https://litellm.example.com")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_url_rejects_bare_host() {
        assert!(LITELLM_RUNTIME
            .validate_endpoint_url("litellm.example.com")
            .is_err());
    }

    #[test]
    fn validate_endpoint_url_rejects_ftp() {
        assert!(LITELLM_RUNTIME
            .validate_endpoint_url("ftp://litellm.example.com")
            .is_err());
    }

    #[test]
    fn default_path_template_is_chat_completions() {
        assert_eq!(
            VerdictanRuntime::default_path_template(&LITELLM_RUNTIME),
            Some("/v1/chat/completions")
        );
    }

    #[test]
    fn requires_model_is_true() {
        assert!(LITELLM_RUNTIME.requires_model());
    }

    #[test]
    fn auth_optional_is_true() {
        assert!(LITELLM_RUNTIME.auth_optional());
    }

    #[test]
    fn build_request_passes_through() {
        let config = json!({});
        let input = json!({"messages": []});
        let result = LITELLM_RUNTIME.build_request(&config, &input).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn execute_passes_through() {
        let config = json!({});
        let request = json!({"messages": []});
        let result = LITELLM_RUNTIME.execute(&config, &request).unwrap();
        assert_eq!(result, request);
    }

    #[test]
    fn translate_response_passes_through() {
        let response = json!({"choices": []});
        let result = LITELLM_RUNTIME.translate_response(&response).unwrap();
        assert_eq!(result, response);
    }

    #[test]
    fn normalize_upstream_response_passes_through() {
        let response = json!({"data": "value"});
        let result = LITELLM_RUNTIME
            .normalize_upstream_response(&response)
            .unwrap();
        assert_eq!(result, response);
    }

    #[test]
    fn supports_streaming_is_true() {
        assert!(LITELLM_RUNTIME.supports_streaming());
    }

    #[test]
    fn supports_tools_is_true() {
        assert!(LITELLM_RUNTIME.supports_tools());
    }
}
