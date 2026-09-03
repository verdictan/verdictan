// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

use super::super::VerdictanRuntime;

pub static MANUAL_INPUT_RUNTIME: ManualInputRuntime = ManualInputRuntime;

pub struct ManualInputRuntime;

impl super::super::VerdictanRuntime for ManualInputRuntime {
    fn runtime_id(&self) -> &'static str {
        "manual-input"
    }

    fn validate_config(&self, _config: &Value) -> Result<(), CliError> {
        Err(CliError::user(
            "manual-input requires an interactive human input runtime and is not supported by verdictan gateway run",
        ))
    }

    fn build_request(&self, _config: &Value, _input: &Value) -> Result<Value, CliError> {
        Err(CliError::user(
            "manual-input cannot build a non-interactive request payload",
        ))
    }

    fn execute(&self, _config: &Value, _request: &Value) -> Result<Value, CliError> {
        Err(CliError::user(
            "manual-input cannot execute without a human in the loop",
        ))
    }

    fn translate_response(&self, _response: &Value) -> Result<Value, CliError> {
        Err(CliError::user(
            "manual-input does not produce a machine-translatable response in gateway mode",
        ))
    }

    fn requires_model(&self) -> bool {
        false
    }

    fn auth_optional(&self) -> bool {
        true
    }
}

impl super::VerdictanLocalRuntime for ManualInputRuntime {
    fn resolve_binary(&self, _config: &Value) -> Result<String, CliError> {
        Err(CliError::user(
            "manual-input does not resolve to a local binary",
        ))
    }

    fn validate_local_inputs(&self, _config: &Value, _request: &Value) -> Result<(), CliError> {
        VerdictanRuntime::validate_config(self, &Value::Null)
    }

    fn execute_local(&self, _config: &Value, _request: &Value) -> Result<Value, CliError> {
        Err(CliError::user(
            "manual-input is not executable in non-interactive proxy mode",
        ))
    }

    fn parse_local_output(&self, _output: &str) -> Result<Value, CliError> {
        Err(CliError::user(
            "manual-input has no local output contract in proxy mode",
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
    use crate::gateway::runtimes::local::VerdictanLocalRuntime;
    use serde_json::json;

    #[test]
    fn runtime_id() {
        assert_eq!(MANUAL_INPUT_RUNTIME.runtime_id(), "manual-input");
    }

    #[test]
    fn validate_config_always_errors() {
        assert!(MANUAL_INPUT_RUNTIME.validate_config(&json!({})).is_err());
    }

    #[test]
    fn build_request_errors() {
        assert!(MANUAL_INPUT_RUNTIME
            .build_request(&json!({}), &json!({}))
            .is_err());
    }

    #[test]
    fn execute_errors() {
        assert!(<ManualInputRuntime as VerdictanRuntime>::execute(
            &MANUAL_INPUT_RUNTIME,
            &json!({}),
            &json!({})
        )
        .is_err());
    }

    #[test]
    fn translate_response_errors() {
        assert!(MANUAL_INPUT_RUNTIME.translate_response(&json!({})).is_err());
    }

    #[test]
    fn requires_model_false() {
        assert!(!MANUAL_INPUT_RUNTIME.requires_model());
    }

    #[test]
    fn auth_optional_true() {
        assert!(MANUAL_INPUT_RUNTIME.auth_optional());
    }

    #[test]
    fn resolve_binary_errors() {
        assert!(MANUAL_INPUT_RUNTIME.resolve_binary(&json!({})).is_err());
    }

    #[test]
    fn validate_local_inputs_errors() {
        assert!(MANUAL_INPUT_RUNTIME
            .validate_local_inputs(&json!({}), &json!({}))
            .is_err());
    }

    #[test]
    fn execute_local_errors() {
        assert!(MANUAL_INPUT_RUNTIME
            .execute_local(&json!({}), &json!({}))
            .is_err());
    }

    #[test]
    fn parse_local_output_errors() {
        assert!(MANUAL_INPUT_RUNTIME.parse_local_output("anything").is_err());
    }

    #[test]
    fn does_not_support_streaming() {
        assert!(!MANUAL_INPUT_RUNTIME.supports_streaming());
    }

    #[test]
    fn does_not_support_tools() {
        assert!(!MANUAL_INPUT_RUNTIME.supports_tools());
    }
}
