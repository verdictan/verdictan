// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

use super::VerdictanUpstreamRuntime;

pub static AZURE_RUNTIME: AzureRuntime = AzureRuntime;

pub struct AzureRuntime;

impl super::super::VerdictanRuntime for AzureRuntime {
    fn runtime_id(&self) -> &'static str {
        "azure"
    }

    fn validate_config(&self, config: &Value) -> Result<(), CliError> {
        for key in ["model", "base_url"] {
            match config.get(key).and_then(Value::as_str).map(str::trim) {
                Some(value) if !value.is_empty() => {}
                _ => {
                    return Err(CliError::user(format!(
                        "{key} is required for azure runtime"
                    )))
                }
            }
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
}

impl VerdictanUpstreamRuntime for AzureRuntime {
    fn provider_kind(&self) -> &'static str {
        "azure"
    }

    fn validate_endpoint_url(&self, base_url: &str) -> Result<(), CliError> {
        if base_url.starts_with("https://") {
            return Ok(());
        }
        Err(CliError::user(
            "azure runtime requires an https:// base_url",
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
    fn runtime_id_returns_azure() {
        assert_eq!(AZURE_RUNTIME.runtime_id(), "azure");
    }

    #[test]
    fn provider_kind_returns_azure() {
        assert_eq!(AZURE_RUNTIME.provider_kind(), "azure");
    }

    #[test]
    fn validate_config_accepts_valid_config() {
        let config = json!({
            "model": "gpt-4",
            "base_url": "https://my-resource.openai.azure.com"
        });
        assert!(AZURE_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_rejects_missing_model() {
        let config = json!({"base_url": "https://example.com"});
        let err = AZURE_RUNTIME.validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("model"));
    }

    #[test]
    fn validate_config_rejects_missing_base_url() {
        let config = json!({"model": "gpt-4"});
        let err = AZURE_RUNTIME.validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("base_url"));
    }

    #[test]
    fn validate_config_rejects_empty_model() {
        let config = json!({"model": "", "base_url": "https://example.com"});
        assert!(AZURE_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_whitespace_base_url() {
        let config = json!({"model": "gpt-4", "base_url": "   "});
        assert!(AZURE_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_endpoint_url_accepts_https() {
        assert!(AZURE_RUNTIME
            .validate_endpoint_url("https://my-resource.openai.azure.com")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_url_rejects_http() {
        assert!(AZURE_RUNTIME
            .validate_endpoint_url("http://my-resource.openai.azure.com")
            .is_err());
    }

    #[test]
    fn validate_endpoint_url_rejects_bare_host() {
        assert!(AZURE_RUNTIME
            .validate_endpoint_url("my-resource.openai.azure.com")
            .is_err());
    }

    #[test]
    fn default_path_template_is_none() {
        assert_eq!(
            VerdictanRuntime::default_path_template(&AZURE_RUNTIME),
            None
        );
    }

    #[test]
    fn build_request_passes_through() {
        let config = json!({});
        let input = json!({"messages": [{"role": "user", "content": "hi"}]});
        let result = AZURE_RUNTIME.build_request(&config, &input).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn execute_passes_through() {
        let config = json!({});
        let request = json!({"prompt": "test"});
        let result = AZURE_RUNTIME.execute(&config, &request).unwrap();
        assert_eq!(result, request);
    }

    #[test]
    fn translate_response_passes_through() {
        let response = json!({"choices": [{"text": "hello"}]});
        let result = AZURE_RUNTIME.translate_response(&response).unwrap();
        assert_eq!(result, response);
    }

    #[test]
    fn normalize_upstream_response_passes_through() {
        let response = json!({"result": true});
        let result = AZURE_RUNTIME
            .normalize_upstream_response(&response)
            .unwrap();
        assert_eq!(result, response);
    }

    #[test]
    fn supports_streaming_is_true() {
        assert!(AZURE_RUNTIME.supports_streaming());
    }

    #[test]
    fn supports_tools_is_true() {
        assert!(AZURE_RUNTIME.supports_tools());
    }
}
