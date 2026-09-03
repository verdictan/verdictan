// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

use super::VerdictanUpstreamRuntime;

pub static OPENLLM_RUNTIME: OpenLlmRuntime = OpenLlmRuntime;

pub struct OpenLlmRuntime;

impl super::super::VerdictanRuntime for OpenLlmRuntime {
    fn runtime_id(&self) -> &'static str {
        "openllm"
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
                        "{key} is required for openllm runtime"
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

impl VerdictanUpstreamRuntime for OpenLlmRuntime {
    fn provider_kind(&self) -> &'static str {
        "openllm"
    }

    fn validate_endpoint_url(&self, base_url: &str) -> Result<(), CliError> {
        if base_url.starts_with("http://") || base_url.starts_with("https://") {
            return Ok(());
        }
        Err(CliError::user(
            "openllm runtime requires an http:// or https:// base_url",
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
    fn runtime_id_returns_openllm() {
        assert_eq!(OPENLLM_RUNTIME.runtime_id(), "openllm");
    }

    #[test]
    fn provider_kind_returns_openllm() {
        assert_eq!(OPENLLM_RUNTIME.provider_kind(), "openllm");
    }

    #[test]
    fn validate_config_accepts_valid() {
        let config = json!({"model": "falcon", "base_url": "http://localhost:3000"});
        assert!(OPENLLM_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_rejects_missing_model() {
        let config = json!({"base_url": "http://localhost:3000"});
        assert!(OPENLLM_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_missing_base_url() {
        let config = json!({"model": "falcon"});
        assert!(OPENLLM_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_invalid_scheme() {
        let config = json!({"model": "falcon", "base_url": "ws://host"});
        assert!(OPENLLM_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_endpoint_url_accepts_http_and_https() {
        assert!(OPENLLM_RUNTIME.validate_endpoint_url("http://host").is_ok());
        assert!(OPENLLM_RUNTIME
            .validate_endpoint_url("https://host")
            .is_ok());
    }

    #[test]
    fn auth_optional_is_true() {
        assert!(OPENLLM_RUNTIME.auth_optional());
    }

    #[test]
    fn supports_streaming_and_tools() {
        assert!(OPENLLM_RUNTIME.supports_streaming());
        assert!(OPENLLM_RUNTIME.supports_tools());
    }

    #[test]
    fn default_path_template_is_chat_completions() {
        assert_eq!(
            VerdictanRuntime::default_path_template(&OPENLLM_RUNTIME),
            Some("/v1/chat/completions")
        );
    }

    #[test]
    fn build_request_passes_through() {
        let input = json!({"model": "test"});
        assert_eq!(
            OPENLLM_RUNTIME.build_request(&json!({}), &input).unwrap(),
            input
        );
    }

    #[test]
    fn validate_config_rejects_empty_model() {
        let config = json!({"model": "", "base_url": "http://localhost:3000"});
        assert!(OPENLLM_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_whitespace_model() {
        let config = json!({"model": "  ", "base_url": "http://localhost:3000"});
        assert!(OPENLLM_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_endpoint_url_rejects_bare_host() {
        assert!(OPENLLM_RUNTIME
            .validate_endpoint_url("localhost:3000")
            .is_err());
    }

    #[test]
    fn execute_passes_through() {
        let req = json!({"prompt": "test"});
        assert_eq!(OPENLLM_RUNTIME.execute(&json!({}), &req).unwrap(), req);
    }

    #[test]
    fn translate_response_passes_through() {
        let resp = json!({"choices": []});
        assert_eq!(OPENLLM_RUNTIME.translate_response(&resp).unwrap(), resp);
    }

    #[test]
    fn normalize_upstream_response_passes_through() {
        let resp = json!({"data": "value"});
        assert_eq!(
            OPENLLM_RUNTIME.normalize_upstream_response(&resp).unwrap(),
            resp
        );
    }
}
