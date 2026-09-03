// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

use super::VerdictanNetworkAdapterRuntime;

pub static WEBSOCKET_RUNTIME: WebSocketRuntime = WebSocketRuntime;

pub struct WebSocketRuntime;

impl super::super::VerdictanRuntime for WebSocketRuntime {
    fn runtime_id(&self) -> &'static str {
        "websocket"
    }

    fn validate_config(&self, config: &Value) -> Result<(), CliError> {
        let has_adapter = config
            .get("adapter_command")
            .and_then(Value::as_str)
            .map(str::trim)
            .is_some_and(|value| !value.is_empty());
        let has_base_url = config
            .get("base_url")
            .and_then(Value::as_str)
            .map(str::trim)
            .is_some_and(|value| !value.is_empty());

        if has_adapter || has_base_url {
            return Ok(());
        }

        Err(CliError::user(
            "websocket runtime requires adapter_command until a native websocket bridge exists",
        ))
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
        false
    }

    fn auth_optional(&self) -> bool {
        true
    }
}

impl VerdictanNetworkAdapterRuntime for WebSocketRuntime {
    fn adapter_id(&self) -> &'static str {
        "websocket"
    }

    fn validate_endpoint(&self, endpoint: &str) -> Result<(), CliError> {
        if endpoint.starts_with("ws://") || endpoint.starts_with("wss://") {
            return Ok(());
        }
        Err(CliError::user(
            "websocket runtime requires a base_url starting with ws:// or wss://",
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
    fn runtime_id_returns_websocket() {
        assert_eq!(WEBSOCKET_RUNTIME.runtime_id(), "websocket");
    }

    #[test]
    fn adapter_id_returns_websocket() {
        assert_eq!(WEBSOCKET_RUNTIME.adapter_id(), "websocket");
    }

    #[test]
    fn validate_config_accepts_adapter_command() {
        let config = json!({"adapter_command": "node ws-bridge.js"});
        assert!(WEBSOCKET_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_accepts_base_url() {
        let config = json!({"base_url": "ws://localhost:8080"});
        assert!(WEBSOCKET_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_accepts_both_adapter_and_base_url() {
        let config = json!({"adapter_command": "node ws.js", "base_url": "ws://host"});
        assert!(WEBSOCKET_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_rejects_neither_adapter_nor_base_url() {
        let config = json!({});
        assert!(WEBSOCKET_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_empty_adapter_command_and_no_base_url() {
        let config = json!({"adapter_command": "  "});
        assert!(WEBSOCKET_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_endpoint_accepts_ws() {
        assert!(WEBSOCKET_RUNTIME
            .validate_endpoint("ws://localhost:8080")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_accepts_wss() {
        assert!(WEBSOCKET_RUNTIME
            .validate_endpoint("wss://secure.host")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_rejects_http() {
        assert!(WEBSOCKET_RUNTIME.validate_endpoint("http://host").is_err());
    }

    #[test]
    fn validate_endpoint_rejects_https() {
        assert!(WEBSOCKET_RUNTIME.validate_endpoint("https://host").is_err());
    }

    #[test]
    fn requires_model_is_false() {
        assert!(!WEBSOCKET_RUNTIME.requires_model());
    }

    #[test]
    fn auth_optional_is_true() {
        assert!(WEBSOCKET_RUNTIME.auth_optional());
    }

    #[test]
    fn build_request_passes_through() {
        let input = json!({"message": "hello"});
        assert_eq!(
            WEBSOCKET_RUNTIME.build_request(&json!({}), &input).unwrap(),
            input
        );
    }

    #[test]
    fn execute_passes_through() {
        let req = json!({"type": "message"});
        assert_eq!(WEBSOCKET_RUNTIME.execute(&json!({}), &req).unwrap(), req);
    }

    #[test]
    fn translate_response_passes_through() {
        let resp = json!({"type": "response"});
        assert_eq!(WEBSOCKET_RUNTIME.translate_response(&resp).unwrap(), resp);
    }

    #[test]
    fn does_not_support_streaming() {
        assert!(!WEBSOCKET_RUNTIME.supports_streaming());
    }

    #[test]
    fn does_not_support_tools() {
        assert!(!WEBSOCKET_RUNTIME.supports_tools());
    }

    #[test]
    fn validate_config_rejects_empty_base_url_and_empty_adapter() {
        let config = json!({"base_url": "", "adapter_command": ""});
        assert!(WEBSOCKET_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_accepts_any_base_url_scheme() {
        let config = json!({"base_url": "http://localhost:8080"});
        assert!(WEBSOCKET_RUNTIME.validate_config(&config).is_ok());
    }
}
