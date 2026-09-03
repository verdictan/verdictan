// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

use super::VerdictanAgentRuntime;

pub static CHATKIT_RUNTIME: ChatKitRuntime = ChatKitRuntime;

pub struct ChatKitRuntime;

impl super::super::VerdictanRuntime for ChatKitRuntime {
    fn runtime_id(&self) -> &'static str {
        "chatkit"
    }

    fn validate_config(&self, config: &Value) -> Result<(), CliError> {
        match config
            .get("adapter_command")
            .and_then(Value::as_str)
            .map(str::trim)
        {
            Some(value) if !value.is_empty() => Ok(()),
            _ => Err(CliError::user(
                "chatkit runtime requires adapter_command until a native runner exists",
            )),
        }
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

impl VerdictanAgentRuntime for ChatKitRuntime {
    fn initialize_agent(&self, config: &Value) -> Result<Value, CliError> {
        super::super::VerdictanRuntime::validate_config(self, config)?;
        Ok(Value::Object(Default::default()))
    }

    fn execute_agent_call(
        &self,
        _config: &Value,
        _state: &Value,
        request: &Value,
    ) -> Result<Value, CliError> {
        Ok(request.clone())
    }

    fn stream_agent_events(&self, _state: &Value) -> Result<Vec<Value>, CliError> {
        Ok(Vec::new())
    }

    fn finalize_agent_state(&self, state: &Value) -> Result<Value, CliError> {
        Ok(state.clone())
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
        assert_eq!(CHATKIT_RUNTIME.runtime_id(), "chatkit");
    }

    #[test]
    fn validate_config_valid() {
        let config = json!({"adapter_command": "/usr/local/bin/chatkit-adapter"});
        assert!(CHATKIT_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_missing_adapter_command() {
        assert!(CHATKIT_RUNTIME.validate_config(&json!({})).is_err());
        assert!(CHATKIT_RUNTIME
            .validate_config(&json!({"adapter_command": ""}))
            .is_err());
        assert!(CHATKIT_RUNTIME
            .validate_config(&json!({"adapter_command": "  "}))
            .is_err());
    }

    #[test]
    fn requires_model_false() {
        assert!(!CHATKIT_RUNTIME.requires_model());
    }

    #[test]
    fn auth_optional_true() {
        assert!(CHATKIT_RUNTIME.auth_optional());
    }

    #[test]
    fn initialize_agent_validates_config() {
        assert!(CHATKIT_RUNTIME.initialize_agent(&json!({})).is_err());
        let valid = json!({"adapter_command": "chatkit-run"});
        assert_eq!(CHATKIT_RUNTIME.initialize_agent(&valid).unwrap(), json!({}));
    }

    #[test]
    fn execute_agent_call_passthrough() {
        let req = json!({"msg": "hi"});
        let result = CHATKIT_RUNTIME
            .execute_agent_call(&json!({}), &json!({}), &req)
            .unwrap();
        assert_eq!(result, req);
    }

    #[test]
    fn stream_agent_events_empty() {
        assert!(CHATKIT_RUNTIME
            .stream_agent_events(&json!({}))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn finalize_agent_state_passthrough() {
        let state = json!({"done": true});
        assert_eq!(CHATKIT_RUNTIME.finalize_agent_state(&state).unwrap(), state);
    }

    #[test]
    fn build_request_passthrough() {
        let input = json!({"messages": []});
        assert_eq!(
            CHATKIT_RUNTIME.build_request(&json!({}), &input).unwrap(),
            input
        );
    }

    #[test]
    fn execute_passthrough() {
        let req = json!({"data": 1});
        assert_eq!(CHATKIT_RUNTIME.execute(&json!({}), &req).unwrap(), req);
    }

    #[test]
    fn translate_response_passthrough() {
        let resp = json!({"output": "hello"});
        assert_eq!(CHATKIT_RUNTIME.translate_response(&resp).unwrap(), resp);
    }

    #[test]
    fn does_not_support_streaming() {
        assert!(!CHATKIT_RUNTIME.supports_streaming());
    }

    #[test]
    fn does_not_support_tools() {
        assert!(!CHATKIT_RUNTIME.supports_tools());
    }

    #[test]
    fn validate_config_null_adapter_command() {
        assert!(CHATKIT_RUNTIME
            .validate_config(&json!({"adapter_command": null}))
            .is_err());
    }
}
