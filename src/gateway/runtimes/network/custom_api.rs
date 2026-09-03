// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

use super::VerdictanNetworkAdapterRuntime;

pub static CUSTOM_API_RUNTIME: CustomApiRuntime = CustomApiRuntime;

pub struct CustomApiRuntime;

impl super::super::VerdictanRuntime for CustomApiRuntime {
    fn runtime_id(&self) -> &'static str {
        "custom-api"
    }

    fn validate_config(&self, config: &Value) -> Result<(), CliError> {
        let endpoint = config
            .get("base_url")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| CliError::user("base_url is required for custom-api runtime"))?;
        self.validate_endpoint(endpoint)
    }

    fn build_request(&self, _config: &Value, input: &Value) -> Result<Value, CliError> {
        self.serialize_request(input)
    }

    fn execute(&self, config: &Value, request: &Value) -> Result<Value, CliError> {
        self.execute_network_call(config, request)
    }

    fn translate_response(&self, response: &Value) -> Result<Value, CliError> {
        self.parse_network_response(response)
    }

    fn requires_model(&self) -> bool {
        false
    }

    fn auth_optional(&self) -> bool {
        true
    }
}

impl VerdictanNetworkAdapterRuntime for CustomApiRuntime {
    fn adapter_id(&self) -> &'static str {
        "custom-api"
    }

    fn validate_endpoint(&self, endpoint: &str) -> Result<(), CliError> {
        if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            return Ok(());
        }

        Err(CliError::user(
            "custom-api runtime requires a base_url starting with http:// or https://",
        ))
    }

    fn serialize_request(&self, request: &Value) -> Result<Value, CliError> {
        Ok(request.clone())
    }

    fn execute_network_call(&self, _config: &Value, request: &Value) -> Result<Value, CliError> {
        Ok(request.clone())
    }

    fn parse_network_response(&self, response: &Value) -> Result<Value, CliError> {
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
    fn runtime_id_returns_custom_api() {
        assert_eq!(CUSTOM_API_RUNTIME.runtime_id(), "custom-api");
    }

    #[test]
    fn adapter_id_returns_custom_api() {
        assert_eq!(CUSTOM_API_RUNTIME.adapter_id(), "custom-api");
    }

    #[test]
    fn validate_config_accepts_http() {
        let config = json!({"base_url": "http://localhost:8080/api"});
        assert!(CUSTOM_API_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_accepts_https() {
        let config = json!({"base_url": "https://api.example.com"});
        assert!(CUSTOM_API_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_rejects_missing_base_url() {
        let config = json!({});
        assert!(CUSTOM_API_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_empty_base_url() {
        let config = json!({"base_url": ""});
        assert!(CUSTOM_API_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_invalid_scheme() {
        let config = json!({"base_url": "ftp://host"});
        assert!(CUSTOM_API_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_endpoint_accepts_http_and_https() {
        assert!(CUSTOM_API_RUNTIME
            .validate_endpoint("http://localhost")
            .is_ok());
        assert!(CUSTOM_API_RUNTIME.validate_endpoint("https://host").is_ok());
    }

    #[test]
    fn validate_endpoint_rejects_other_schemes() {
        assert!(CUSTOM_API_RUNTIME.validate_endpoint("ws://host").is_err());
    }

    #[test]
    fn requires_model_is_false() {
        assert!(!CUSTOM_API_RUNTIME.requires_model());
    }

    #[test]
    fn auth_optional_is_true() {
        assert!(CUSTOM_API_RUNTIME.auth_optional());
    }

    #[test]
    fn build_request_delegates_to_serialize() {
        let input = json!({"data": "test"});
        let result = CUSTOM_API_RUNTIME
            .build_request(&json!({}), &input)
            .unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn execute_delegates_to_execute_network_call() {
        let config = json!({"base_url": "http://host"});
        let req = json!({"body": true});
        let result = CUSTOM_API_RUNTIME.execute(&config, &req).unwrap();
        assert_eq!(result, req);
    }

    #[test]
    fn translate_response_delegates_to_parse() {
        let resp = json!({"result": "ok"});
        let result = CUSTOM_API_RUNTIME.translate_response(&resp).unwrap();
        assert_eq!(result, resp);
    }

    #[test]
    fn does_not_support_streaming() {
        assert!(!CUSTOM_API_RUNTIME.supports_streaming());
    }

    #[test]
    fn does_not_support_tools() {
        assert!(!CUSTOM_API_RUNTIME.supports_tools());
    }

    #[test]
    fn validate_config_rejects_whitespace_base_url() {
        let config = json!({"base_url": "   "});
        assert!(CUSTOM_API_RUNTIME.validate_config(&config).is_err());
    }
}
