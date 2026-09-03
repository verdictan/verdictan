// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

use super::VerdictanUpstreamRuntime;

pub static HYPERBOLIC_RUNTIME: HyperbolicRuntime = HyperbolicRuntime;

pub struct HyperbolicRuntime;

impl super::super::VerdictanRuntime for HyperbolicRuntime {
    fn runtime_id(&self) -> &'static str {
        "hyperbolic"
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
                        "{key} is required for hyperbolic runtime"
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

impl VerdictanUpstreamRuntime for HyperbolicRuntime {
    fn provider_kind(&self) -> &'static str {
        "hyperbolic"
    }

    fn validate_endpoint_url(&self, base_url: &str) -> Result<(), CliError> {
        if base_url.starts_with("https://") {
            return Ok(());
        }
        Err(CliError::user(
            "hyperbolic runtime requires an https:// base_url",
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
    fn runtime_id() {
        assert_eq!(HYPERBOLIC_RUNTIME.runtime_id(), "hyperbolic");
    }

    #[test]
    fn provider_kind() {
        assert_eq!(HYPERBOLIC_RUNTIME.provider_kind(), "hyperbolic");
    }

    #[test]
    fn validate_config_valid() {
        let config =
            json!({"model": "meta-llama/llama-3", "base_url": "https://api.hyperbolic.xyz"});
        assert!(HYPERBOLIC_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_missing_fields() {
        assert!(HYPERBOLIC_RUNTIME
            .validate_config(&json!({"model": "m"}))
            .is_err());
    }

    #[test]
    fn validate_endpoint_url_https() {
        assert!(HYPERBOLIC_RUNTIME
            .validate_endpoint_url("https://api.hyperbolic.xyz")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_url_http_rejected() {
        assert!(HYPERBOLIC_RUNTIME
            .validate_endpoint_url("http://api.hyperbolic.xyz")
            .is_err());
    }

    #[test]
    fn default_path_template_value() {
        assert_eq!(
            <HyperbolicRuntime as crate::gateway::runtimes::VerdictanRuntime>::default_path_template(&HYPERBOLIC_RUNTIME),
            Some("/v1/chat/completions")
        );
    }

    #[test]
    fn supports_streaming_and_tools() {
        assert!(HYPERBOLIC_RUNTIME.supports_streaming());
        assert!(HYPERBOLIC_RUNTIME.supports_tools());
    }

    #[test]
    fn validate_config_rejects_missing_base_url() {
        let config = json!({"model": "meta-llama/llama-3"});
        assert!(HYPERBOLIC_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_empty_model() {
        let config = json!({"model": "", "base_url": "https://api.hyperbolic.xyz"});
        assert!(HYPERBOLIC_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_whitespace_model() {
        let config = json!({"model": "  ", "base_url": "https://api.hyperbolic.xyz"});
        assert!(HYPERBOLIC_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_endpoint_url_rejects_bare_host() {
        assert!(HYPERBOLIC_RUNTIME
            .validate_endpoint_url("api.hyperbolic.xyz")
            .is_err());
    }

    #[test]
    fn build_request_passes_through() {
        let input = json!({"messages": []});
        assert_eq!(
            HYPERBOLIC_RUNTIME
                .build_request(&json!({}), &input)
                .unwrap(),
            input
        );
    }

    #[test]
    fn execute_passes_through() {
        let req = json!({"prompt": "test"});
        assert_eq!(HYPERBOLIC_RUNTIME.execute(&json!({}), &req).unwrap(), req);
    }

    #[test]
    fn translate_response_passes_through() {
        let resp = json!({"choices": []});
        assert_eq!(HYPERBOLIC_RUNTIME.translate_response(&resp).unwrap(), resp);
    }

    #[test]
    fn normalize_upstream_response_passes_through() {
        let resp = json!({"data": "value"});
        assert_eq!(
            HYPERBOLIC_RUNTIME
                .normalize_upstream_response(&resp)
                .unwrap(),
            resp
        );
    }

    #[test]
    fn upstream_default_path_template_value() {
        assert_eq!(
            VerdictanRuntime::default_path_template(&HYPERBOLIC_RUNTIME),
            Some("/v1/chat/completions")
        );
    }
}
