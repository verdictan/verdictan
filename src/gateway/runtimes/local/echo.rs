// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

use super::VerdictanLocalRuntime;

pub static ECHO_RUNTIME: EchoRuntime = EchoRuntime;

pub struct EchoRuntime;

impl super::super::VerdictanRuntime for EchoRuntime {
    fn runtime_id(&self) -> &'static str {
        "echo"
    }

    fn validate_config(&self, _config: &Value) -> Result<(), CliError> {
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

    fn requires_model(&self) -> bool {
        false
    }

    fn auth_optional(&self) -> bool {
        true
    }
}

impl VerdictanLocalRuntime for EchoRuntime {
    fn resolve_binary(&self, _config: &Value) -> Result<String, CliError> {
        Ok("echo".to_string())
    }

    fn validate_local_inputs(&self, _config: &Value, _request: &Value) -> Result<(), CliError> {
        Ok(())
    }

    fn execute_local(&self, _config: &Value, request: &Value) -> Result<Value, CliError> {
        Ok(request.clone())
    }

    fn parse_local_output(&self, output: &str) -> Result<Value, CliError> {
        Ok(Value::String(output.to_string()))
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
        assert_eq!(ECHO_RUNTIME.runtime_id(), "echo");
    }

    #[test]
    fn validate_config_always_ok() {
        assert!(ECHO_RUNTIME.validate_config(&json!({})).is_ok());
    }

    #[test]
    fn build_request_passthrough() {
        let input = json!({"msg": "hello"});
        assert_eq!(
            ECHO_RUNTIME.build_request(&json!({}), &input).unwrap(),
            input
        );
    }

    #[test]
    fn execute_passthrough() {
        let req = json!({"data": [1, 2, 3]});
        assert_eq!(ECHO_RUNTIME.execute(&json!({}), &req).unwrap(), req);
    }

    #[test]
    fn translate_response_passthrough() {
        let resp = json!({"output": "world"});
        assert_eq!(ECHO_RUNTIME.translate_response(&resp).unwrap(), resp);
    }

    #[test]
    fn requires_model_false() {
        assert!(!ECHO_RUNTIME.requires_model());
    }

    #[test]
    fn auth_optional_true() {
        assert!(ECHO_RUNTIME.auth_optional());
    }

    #[test]
    fn resolve_binary_returns_echo() {
        assert_eq!(ECHO_RUNTIME.resolve_binary(&json!({})).unwrap(), "echo");
    }

    #[test]
    fn validate_local_inputs_ok() {
        assert!(ECHO_RUNTIME
            .validate_local_inputs(&json!({}), &json!({}))
            .is_ok());
    }

    #[test]
    fn execute_local_passthrough() {
        let req = json!({"prompt": "test"});
        assert_eq!(ECHO_RUNTIME.execute_local(&json!({}), &req).unwrap(), req);
    }

    #[test]
    fn parse_local_output_wraps_string() {
        let result = ECHO_RUNTIME.parse_local_output("hello world").unwrap();
        assert_eq!(result, Value::String("hello world".to_string()));
    }

    #[test]
    fn parse_local_output_empty_string() {
        let result = ECHO_RUNTIME.parse_local_output("").unwrap();
        assert_eq!(result, Value::String(String::new()));
    }

    #[test]
    fn does_not_support_streaming() {
        assert!(!ECHO_RUNTIME.supports_streaming());
    }

    #[test]
    fn does_not_support_tools() {
        assert!(!ECHO_RUNTIME.supports_tools());
    }
}
