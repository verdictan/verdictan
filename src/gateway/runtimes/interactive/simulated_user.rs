// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

use super::VerdictanInteractiveRuntime;

pub static SIMULATED_USER_RUNTIME: SimulatedUserRuntime = SimulatedUserRuntime;

pub struct SimulatedUserRuntime;

impl super::super::VerdictanRuntime for SimulatedUserRuntime {
    fn runtime_id(&self) -> &'static str {
        "simulated-user"
    }

    fn validate_config(&self, _config: &Value) -> Result<(), CliError> {
        Err(CliError::user(
            "simulated-user requires an evaluator runtime and is not supported by verdictan gateway run",
        ))
    }

    fn build_request(&self, _config: &Value, _input: &Value) -> Result<Value, CliError> {
        Err(CliError::user(
            "simulated-user cannot build a non-interactive request payload in gateway mode",
        ))
    }

    fn execute(&self, _config: &Value, _request: &Value) -> Result<Value, CliError> {
        Err(CliError::user(
            "simulated-user cannot execute without an evaluator runtime",
        ))
    }

    fn translate_response(&self, _response: &Value) -> Result<Value, CliError> {
        Err(CliError::user(
            "simulated-user does not produce a machine-translatable response in gateway mode",
        ))
    }

    fn requires_model(&self) -> bool {
        false
    }

    fn auth_optional(&self) -> bool {
        true
    }
}

impl VerdictanInteractiveRuntime for SimulatedUserRuntime {
    fn initialize_session(&self, _config: &Value) -> Result<Value, CliError> {
        Err(CliError::user(
            "simulated-user cannot initialize an interactive session in verdictan gateway run",
        ))
    }

    fn execute_step(
        &self,
        _config: &Value,
        _session: &Value,
        _request: &Value,
    ) -> Result<Value, CliError> {
        Err(CliError::user(
            "simulated-user cannot execute steps in verdictan gateway run",
        ))
    }

    fn capture_state(&self, _session: &Value) -> Result<Value, CliError> {
        Err(CliError::user(
            "simulated-user does not expose session capture in gateway mode",
        ))
    }

    fn finalize_session(&self, _session: &Value) -> Result<Value, CliError> {
        Err(CliError::user(
            "simulated-user does not finalize sessions in gateway mode",
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
    fn runtime_id_returns_simulated_user() {
        assert_eq!(SIMULATED_USER_RUNTIME.runtime_id(), "simulated-user");
    }

    #[test]
    fn validate_config_always_errors() {
        assert!(SIMULATED_USER_RUNTIME.validate_config(&json!({})).is_err());
    }

    #[test]
    fn build_request_always_errors() {
        assert!(SIMULATED_USER_RUNTIME
            .build_request(&json!({}), &json!({}))
            .is_err());
    }

    #[test]
    fn execute_always_errors() {
        assert!(SIMULATED_USER_RUNTIME
            .execute(&json!({}), &json!({}))
            .is_err());
    }

    #[test]
    fn translate_response_always_errors() {
        assert!(SIMULATED_USER_RUNTIME
            .translate_response(&json!({}))
            .is_err());
    }

    #[test]
    fn requires_model_is_false() {
        assert!(!SIMULATED_USER_RUNTIME.requires_model());
    }

    #[test]
    fn auth_optional_is_true() {
        assert!(SIMULATED_USER_RUNTIME.auth_optional());
    }

    #[test]
    fn initialize_session_errors() {
        assert!(SIMULATED_USER_RUNTIME
            .initialize_session(&json!({}))
            .is_err());
    }

    #[test]
    fn execute_step_errors() {
        assert!(SIMULATED_USER_RUNTIME
            .execute_step(&json!({}), &json!({}), &json!({}))
            .is_err());
    }

    #[test]
    fn capture_state_errors() {
        assert!(SIMULATED_USER_RUNTIME.capture_state(&json!({})).is_err());
    }

    #[test]
    fn finalize_session_errors() {
        assert!(SIMULATED_USER_RUNTIME.finalize_session(&json!({})).is_err());
    }

    #[test]
    fn does_not_support_streaming() {
        assert!(!SIMULATED_USER_RUNTIME.supports_streaming());
    }

    #[test]
    fn does_not_support_tools() {
        assert!(!SIMULATED_USER_RUNTIME.supports_tools());
    }
}
