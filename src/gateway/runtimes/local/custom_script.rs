// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

use super::VerdictanLocalRuntime;

pub static CUSTOM_SCRIPT_RUNTIME: CustomScriptRuntime = CustomScriptRuntime;

pub struct CustomScriptRuntime;

impl super::super::VerdictanRuntime for CustomScriptRuntime {
    fn runtime_id(&self) -> &'static str {
        "custom-script"
    }

    fn validate_config(&self, _config: &Value) -> Result<(), CliError> {
        Err(CliError::user(
            "custom-script providers require exec:<command> or file://...; provider: custom-script alone is not executable in verdictan gateway run",
        ))
    }

    fn build_request(&self, _config: &Value, _input: &Value) -> Result<Value, CliError> {
        Err(CliError::user(
            "custom-script runtime cannot build a request without an explicit exec: or file:// script target",
        ))
    }

    fn execute(&self, _config: &Value, _request: &Value) -> Result<Value, CliError> {
        Err(CliError::user(
            "custom-script runtime is not executable in verdictan gateway run without an explicit script target",
        ))
    }

    fn translate_response(&self, _response: &Value) -> Result<Value, CliError> {
        Err(CliError::user(
            "custom-script runtime has no implicit output contract in gateway mode",
        ))
    }

    fn requires_model(&self) -> bool {
        false
    }

    fn auth_optional(&self) -> bool {
        true
    }
}

impl VerdictanLocalRuntime for CustomScriptRuntime {
    fn resolve_binary(&self, _config: &Value) -> Result<String, CliError> {
        Err(CliError::user(
            "custom-script runtime does not resolve to a binary without exec:...",
        ))
    }

    fn validate_local_inputs(&self, _config: &Value, _request: &Value) -> Result<(), CliError> {
        super::super::VerdictanRuntime::validate_config(self, &Value::Null)
    }

    fn execute_local(&self, _config: &Value, _request: &Value) -> Result<Value, CliError> {
        Err(CliError::user(
            "custom-script runtime is not executable in non-interactive gateway mode without an explicit script target",
        ))
    }

    fn parse_local_output(&self, _output: &str) -> Result<Value, CliError> {
        Err(CliError::user(
            "custom-script runtime has no implicit local output contract in gateway mode",
        ))
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
        assert_eq!(CUSTOM_SCRIPT_RUNTIME.runtime_id(), "custom-script");
    }

    #[test]
    fn validate_config_always_errors() {
        assert!(CUSTOM_SCRIPT_RUNTIME.validate_config(&json!({})).is_err());
    }

    #[test]
    fn build_request_errors() {
        assert!(CUSTOM_SCRIPT_RUNTIME
            .build_request(&json!({}), &json!({}))
            .is_err());
    }

    #[test]
    fn execute_errors() {
        assert!(CUSTOM_SCRIPT_RUNTIME
            .execute(&json!({}), &json!({}))
            .is_err());
    }

    #[test]
    fn translate_response_errors() {
        assert!(CUSTOM_SCRIPT_RUNTIME
            .translate_response(&json!({}))
            .is_err());
    }

    #[test]
    fn requires_model_false() {
        assert!(!CUSTOM_SCRIPT_RUNTIME.requires_model());
    }

    #[test]
    fn auth_optional_true() {
        assert!(CUSTOM_SCRIPT_RUNTIME.auth_optional());
    }

    #[test]
    fn resolve_binary_errors() {
        assert!(CUSTOM_SCRIPT_RUNTIME.resolve_binary(&json!({})).is_err());
    }

    #[test]
    fn validate_local_inputs_errors() {
        assert!(CUSTOM_SCRIPT_RUNTIME
            .validate_local_inputs(&json!({}), &json!({}))
            .is_err());
    }

    #[test]
    fn execute_local_errors() {
        assert!(CUSTOM_SCRIPT_RUNTIME
            .execute_local(&json!({}), &json!({}))
            .is_err());
    }

    #[test]
    fn parse_local_output_errors() {
        assert!(CUSTOM_SCRIPT_RUNTIME
            .parse_local_output("anything")
            .is_err());
    }

    #[test]
    fn does_not_support_streaming() {
        assert!(!CUSTOM_SCRIPT_RUNTIME.supports_streaming());
    }

    #[test]
    fn does_not_support_tools() {
        assert!(!CUSTOM_SCRIPT_RUNTIME.supports_tools());
    }
}
