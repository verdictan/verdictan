// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

use super::VerdictanUpstreamRuntime;

pub static OPENROUTER_RUNTIME: OpenRouterRuntime = OpenRouterRuntime;

pub struct OpenRouterRuntime;

impl super::super::VerdictanRuntime for OpenRouterRuntime {
    fn runtime_id(&self) -> &'static str {
        "openrouter"
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
                        "{key} is required for openrouter runtime"
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
        crate::gateway::provider_catalog::provider_path_template_for_public_path(
            self.provider_kind(),
            "/v1/chat/completions",
        )
        .or(Some("/v1/chat/completions"))
    }
}

impl VerdictanUpstreamRuntime for OpenRouterRuntime {
    fn provider_kind(&self) -> &'static str {
        "openrouter"
    }

    fn validate_endpoint_url(&self, base_url: &str) -> Result<(), CliError> {
        if base_url.starts_with("https://") {
            return Ok(());
        }
        Err(CliError::user(
            "openrouter runtime requires an https:// base_url",
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
    fn runtime_id_returns_openrouter() {
        assert_eq!(OPENROUTER_RUNTIME.runtime_id(), "openrouter");
    }

    #[test]
    fn provider_kind_returns_openrouter() {
        assert_eq!(OPENROUTER_RUNTIME.provider_kind(), "openrouter");
    }

    #[test]
    fn validate_config_accepts_valid() {
        let config = json!({"model": "openai/gpt-4", "base_url": "https://openrouter.ai"});
        assert!(OPENROUTER_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_rejects_http_base_url() {
        let config = json!({"model": "m", "base_url": "http://openrouter.ai"});
        assert!(OPENROUTER_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_missing_model() {
        let config = json!({"base_url": "https://openrouter.ai"});
        assert!(OPENROUTER_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_missing_base_url() {
        let config = json!({"model": "m"});
        assert!(OPENROUTER_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_endpoint_url_only_accepts_https() {
        assert!(OPENROUTER_RUNTIME
            .validate_endpoint_url("https://openrouter.ai")
            .is_ok());
        assert!(OPENROUTER_RUNTIME
            .validate_endpoint_url("http://openrouter.ai")
            .is_err());
    }

    #[test]
    fn default_path_template_contains_chat_completions() {
        let path = VerdictanRuntime::default_path_template(&OPENROUTER_RUNTIME);
        assert!(path.is_some());
        assert!(path.unwrap().contains("chat/completions"));
    }

    #[test]
    fn supports_streaming_and_tools() {
        assert!(OPENROUTER_RUNTIME.supports_streaming());
        assert!(OPENROUTER_RUNTIME.supports_tools());
    }

    #[test]
    fn build_request_passes_through() {
        let input = json!({"messages": []});
        assert_eq!(
            OPENROUTER_RUNTIME
                .build_request(&json!({}), &input)
                .unwrap(),
            input
        );
    }

    #[test]
    fn validate_config_rejects_empty_model() {
        let config = json!({"model": "", "base_url": "https://openrouter.ai"});
        assert!(OPENROUTER_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_whitespace_model() {
        let config = json!({"model": "  ", "base_url": "https://openrouter.ai"});
        assert!(OPENROUTER_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_endpoint_url_rejects_bare_host() {
        assert!(OPENROUTER_RUNTIME
            .validate_endpoint_url("openrouter.ai")
            .is_err());
    }

    #[test]
    fn execute_passes_through() {
        let req = json!({"prompt": "test"});
        assert_eq!(OPENROUTER_RUNTIME.execute(&json!({}), &req).unwrap(), req);
    }

    #[test]
    fn translate_response_passes_through() {
        let resp = json!({"choices": []});
        assert_eq!(OPENROUTER_RUNTIME.translate_response(&resp).unwrap(), resp);
    }

    #[test]
    fn normalize_upstream_response_passes_through() {
        let resp = json!({"data": "value"});
        assert_eq!(
            OPENROUTER_RUNTIME
                .normalize_upstream_response(&resp)
                .unwrap(),
            resp
        );
    }
}
