// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

use super::VerdictanUpstreamRuntime;

pub static XAI_RUNTIME: XaiRuntime = XaiRuntime;

pub struct XaiRuntime;

impl super::super::VerdictanRuntime for XaiRuntime {
    fn runtime_id(&self) -> &'static str {
        "xai"
    }

    fn validate_config(&self, config: &Value) -> Result<(), CliError> {
        if config
            .get("model")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .is_none()
        {
            return Err(CliError::user("model is required for xai runtime"));
        }
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

impl VerdictanUpstreamRuntime for XaiRuntime {
    fn provider_kind(&self) -> &'static str {
        "xai"
    }

    fn validate_endpoint_url(&self, base_url: &str) -> Result<(), CliError> {
        if base_url.starts_with("https://") {
            return Ok(());
        }
        Err(CliError::user("xai runtime requires an https:// base_url"))
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
    fn runtime_id_returns_xai() {
        assert_eq!(XAI_RUNTIME.runtime_id(), "xai");
    }

    #[test]
    fn provider_kind_returns_xai() {
        assert_eq!(XAI_RUNTIME.provider_kind(), "xai");
    }

    #[test]
    fn validate_config_accepts_valid_model() {
        let config = json!({"model": "grok-2"});
        assert!(XAI_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_rejects_missing_model() {
        let config = json!({});
        assert!(XAI_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_empty_model() {
        let config = json!({"model": ""});
        assert!(XAI_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_whitespace_model() {
        let config = json!({"model": "  "});
        assert!(XAI_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_does_not_require_base_url() {
        let config = json!({"model": "grok-2"});
        assert!(XAI_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_endpoint_url_only_accepts_https() {
        assert!(XAI_RUNTIME
            .validate_endpoint_url("https://api.x.ai")
            .is_ok());
        assert!(XAI_RUNTIME
            .validate_endpoint_url("http://api.x.ai")
            .is_err());
    }

    #[test]
    fn default_path_template_is_chat_completions() {
        assert_eq!(
            VerdictanRuntime::default_path_template(&XAI_RUNTIME),
            Some("/v1/chat/completions")
        );
    }

    #[test]
    fn verdictan_runtime_default_path_template_is_chat_completions() {
        assert_eq!(
            VerdictanRuntime::default_path_template(&XAI_RUNTIME),
            Some("/v1/chat/completions")
        );
    }

    #[test]
    fn supports_streaming_and_tools() {
        assert!(XAI_RUNTIME.supports_streaming());
        assert!(XAI_RUNTIME.supports_tools());
    }

    #[test]
    fn build_request_passes_through() {
        let input = json!({"messages": []});
        assert_eq!(
            XAI_RUNTIME.build_request(&json!({}), &input).unwrap(),
            input
        );
    }

    #[test]
    fn execute_passes_through() {
        let req = json!({"prompt": "test"});
        assert_eq!(XAI_RUNTIME.execute(&json!({}), &req).unwrap(), req);
    }

    #[test]
    fn translate_response_passes_through() {
        let resp = json!({"choices": []});
        assert_eq!(XAI_RUNTIME.translate_response(&resp).unwrap(), resp);
    }

    #[test]
    fn normalize_upstream_response_passes_through() {
        let resp = json!({"data": "value"});
        assert_eq!(
            XAI_RUNTIME.normalize_upstream_response(&resp).unwrap(),
            resp
        );
    }

    #[test]
    fn validate_endpoint_url_rejects_bare_host() {
        assert!(XAI_RUNTIME.validate_endpoint_url("api.x.ai").is_err());
    }
}
