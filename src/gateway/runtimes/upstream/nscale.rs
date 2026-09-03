// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

use super::VerdictanUpstreamRuntime;

pub static NSCALE_RUNTIME: NscaleRuntime = NscaleRuntime;

pub struct NscaleRuntime;

impl super::super::VerdictanRuntime for NscaleRuntime {
    fn runtime_id(&self) -> &'static str {
        "nscale"
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
                        "{key} is required for nscale runtime"
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

impl VerdictanUpstreamRuntime for NscaleRuntime {
    fn provider_kind(&self) -> &'static str {
        "nscale"
    }

    fn validate_endpoint_url(&self, base_url: &str) -> Result<(), CliError> {
        if base_url.starts_with("https://") {
            return Ok(());
        }
        Err(CliError::user(
            "nscale runtime requires an https:// base_url",
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
    fn runtime_id_returns_nscale() {
        assert_eq!(NSCALE_RUNTIME.runtime_id(), "nscale");
    }

    #[test]
    fn provider_kind_returns_nscale() {
        assert_eq!(NSCALE_RUNTIME.provider_kind(), "nscale");
    }

    #[test]
    fn validate_config_accepts_valid_config() {
        let config = json!({
            "model": "llama-3",
            "base_url": "https://inference.nscale.com"
        });
        assert!(NSCALE_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_rejects_missing_model() {
        let config = json!({ "base_url": "https://inference.nscale.com" });
        let err = NSCALE_RUNTIME.validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("model"));
    }

    #[test]
    fn validate_config_rejects_missing_base_url() {
        let config = json!({ "model": "llama-3" });
        let err = NSCALE_RUNTIME.validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("base_url"));
    }

    #[test]
    fn validate_config_rejects_empty_model() {
        let config = json!({ "model": "  ", "base_url": "https://x.com" });
        let err = NSCALE_RUNTIME.validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("model"));
    }

    #[test]
    fn validate_config_rejects_http_base_url() {
        let config = json!({ "model": "llama-3", "base_url": "http://local:8080" });
        let err = NSCALE_RUNTIME.validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("https://"));
    }

    #[test]
    fn validate_endpoint_url_accepts_https() {
        assert!(NSCALE_RUNTIME
            .validate_endpoint_url("https://inference.nscale.com")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_url_rejects_http() {
        assert!(NSCALE_RUNTIME
            .validate_endpoint_url("http://localhost:8080")
            .is_err());
    }

    #[test]
    fn validate_endpoint_url_rejects_bare_string() {
        assert!(NSCALE_RUNTIME
            .validate_endpoint_url("inference.nscale.com")
            .is_err());
    }

    #[test]
    fn default_path_template_is_chat_completions() {
        assert_eq!(
            VerdictanRuntime::default_path_template(&NSCALE_RUNTIME),
            Some("/v1/chat/completions")
        );
    }

    #[test]
    fn build_request_passes_input_through() {
        let config = json!({});
        let input = json!({"messages": [{"role": "user", "content": "hi"}]});
        let result = NSCALE_RUNTIME.build_request(&config, &input).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn execute_passes_request_through() {
        let request = json!({"test": true});
        let result = NSCALE_RUNTIME.execute(&json!({}), &request).unwrap();
        assert_eq!(result, request);
    }

    #[test]
    fn translate_response_passes_through() {
        let response = json!({"choices": []});
        let result = NSCALE_RUNTIME.translate_response(&response).unwrap();
        assert_eq!(result, response);
    }

    #[test]
    fn normalize_upstream_response_passes_through() {
        let response = json!({"id": "test"});
        let result = NSCALE_RUNTIME
            .normalize_upstream_response(&response)
            .unwrap();
        assert_eq!(result, response);
    }

    #[test]
    fn supports_streaming() {
        assert!(NSCALE_RUNTIME.supports_streaming());
    }

    #[test]
    fn supports_tools() {
        assert!(NSCALE_RUNTIME.supports_tools());
    }
}
