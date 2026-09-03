// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

use super::VerdictanLocalRuntime;

pub static RUBY_RUNTIME: RubyRuntime = RubyRuntime;

pub struct RubyRuntime;

impl super::super::VerdictanRuntime for RubyRuntime {
    fn runtime_id(&self) -> &'static str {
        "ruby"
    }

    fn validate_config(&self, _config: &Value) -> Result<(), CliError> {
        Err(CliError::user(
            "ruby script providers require file://path/to/script.rb or exec:ruby ...; provider: ruby alone is not executable in verdictan gateway run",
        ))
    }

    fn build_request(&self, _config: &Value, _input: &Value) -> Result<Value, CliError> {
        Err(CliError::user(
            "ruby runtime cannot build a request without an explicit file:// or exec: target",
        ))
    }

    fn execute(&self, _config: &Value, _request: &Value) -> Result<Value, CliError> {
        Err(CliError::user(
            "ruby runtime is not executable in verdictan gateway run without an explicit script target",
        ))
    }

    fn translate_response(&self, _response: &Value) -> Result<Value, CliError> {
        Err(CliError::user(
            "ruby runtime has no implicit output contract in gateway mode",
        ))
    }

    fn requires_model(&self) -> bool {
        false
    }

    fn auth_optional(&self) -> bool {
        true
    }
}

impl VerdictanLocalRuntime for RubyRuntime {
    fn resolve_binary(&self, _config: &Value) -> Result<String, CliError> {
        Err(CliError::user(
            "ruby runtime does not resolve to a binary without an explicit script target",
        ))
    }

    fn validate_local_inputs(&self, _config: &Value, _request: &Value) -> Result<(), CliError> {
        super::super::VerdictanRuntime::validate_config(self, &Value::Null)
    }

    fn execute_local(&self, _config: &Value, _request: &Value) -> Result<Value, CliError> {
        Err(CliError::user(
            "ruby runtime is not executable in non-interactive gateway mode without an explicit script target",
        ))
    }

    fn parse_local_output(&self, _output: &str) -> Result<Value, CliError> {
        Err(CliError::user(
            "ruby runtime has no implicit local output contract in gateway mode",
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
    fn runtime_id_returns_ruby() {
        assert_eq!(RUBY_RUNTIME.runtime_id(), "ruby");
    }

    #[test]
    fn validate_config_always_errors() {
        assert!(RUBY_RUNTIME.validate_config(&json!({})).is_err());
    }

    #[test]
    fn build_request_always_errors() {
        assert!(RUBY_RUNTIME.build_request(&json!({}), &json!({})).is_err());
    }

    #[test]
    fn execute_always_errors() {
        assert!(RUBY_RUNTIME.execute(&json!({}), &json!({})).is_err());
    }

    #[test]
    fn translate_response_always_errors() {
        assert!(RUBY_RUNTIME.translate_response(&json!({})).is_err());
    }

    #[test]
    fn requires_model_is_false() {
        assert!(!RUBY_RUNTIME.requires_model());
    }

    #[test]
    fn auth_optional_is_true() {
        assert!(RUBY_RUNTIME.auth_optional());
    }

    #[test]
    fn resolve_binary_errors() {
        assert!(RUBY_RUNTIME.resolve_binary(&json!({})).is_err());
    }

    #[test]
    fn validate_local_inputs_errors() {
        assert!(RUBY_RUNTIME
            .validate_local_inputs(&json!({}), &json!({}))
            .is_err());
    }

    #[test]
    fn execute_local_errors() {
        assert!(RUBY_RUNTIME.execute_local(&json!({}), &json!({})).is_err());
    }

    #[test]
    fn parse_local_output_errors() {
        assert!(RUBY_RUNTIME.parse_local_output("output").is_err());
    }

    #[test]
    fn does_not_support_streaming() {
        assert!(!RUBY_RUNTIME.supports_streaming());
    }

    #[test]
    fn does_not_support_tools() {
        assert!(!RUBY_RUNTIME.supports_tools());
    }
}
