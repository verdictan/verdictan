// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

use super::VerdictanAgentRuntime;

pub static CLAUDE_AGENT_SDK_RUNTIME: ClaudeAgentSdkRuntime = ClaudeAgentSdkRuntime;

pub struct ClaudeAgentSdkRuntime;

impl super::super::VerdictanRuntime for ClaudeAgentSdkRuntime {
    fn runtime_id(&self) -> &'static str {
        "claude-agent-sdk"
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

impl VerdictanAgentRuntime for ClaudeAgentSdkRuntime {
    fn initialize_agent(&self, _config: &Value) -> Result<Value, CliError> {
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
    fn runtime_id_returns_claude_agent_sdk() {
        assert_eq!(CLAUDE_AGENT_SDK_RUNTIME.runtime_id(), "claude-agent-sdk");
    }

    #[test]
    fn validate_config_always_succeeds() {
        assert!(CLAUDE_AGENT_SDK_RUNTIME.validate_config(&json!({})).is_ok());
        assert!(CLAUDE_AGENT_SDK_RUNTIME
            .validate_config(&json!({"model": "claude"}))
            .is_ok());
    }

    #[test]
    fn build_request_passes_through() {
        let input = json!({"prompt": "hello"});
        assert_eq!(
            CLAUDE_AGENT_SDK_RUNTIME
                .build_request(&json!({}), &input)
                .unwrap(),
            input
        );
    }

    #[test]
    fn execute_passes_through() {
        let req = json!({"action": "run"});
        assert_eq!(
            CLAUDE_AGENT_SDK_RUNTIME.execute(&json!({}), &req).unwrap(),
            req
        );
    }

    #[test]
    fn translate_response_passes_through() {
        let resp = json!({"output": "done"});
        assert_eq!(
            CLAUDE_AGENT_SDK_RUNTIME.translate_response(&resp).unwrap(),
            resp
        );
    }

    #[test]
    fn requires_model_is_false() {
        assert!(!CLAUDE_AGENT_SDK_RUNTIME.requires_model());
    }

    #[test]
    fn auth_optional_is_true() {
        assert!(CLAUDE_AGENT_SDK_RUNTIME.auth_optional());
    }

    #[test]
    fn initialize_agent_returns_empty_object() {
        let result = CLAUDE_AGENT_SDK_RUNTIME
            .initialize_agent(&json!({}))
            .unwrap();
        assert!(result.is_object());
        assert!(result.as_object().unwrap().is_empty());
    }

    #[test]
    fn execute_agent_call_passes_request_through() {
        let req = json!({"messages": [{"role": "user", "content": "hi"}]});
        let result = CLAUDE_AGENT_SDK_RUNTIME
            .execute_agent_call(&json!({}), &json!({}), &req)
            .unwrap();
        assert_eq!(result, req);
    }

    #[test]
    fn stream_agent_events_returns_empty_vec() {
        let events = CLAUDE_AGENT_SDK_RUNTIME
            .stream_agent_events(&json!({}))
            .unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn finalize_agent_state_passes_state_through() {
        let state = json!({"conversation_id": "abc"});
        assert_eq!(
            CLAUDE_AGENT_SDK_RUNTIME
                .finalize_agent_state(&state)
                .unwrap(),
            state
        );
    }

    #[test]
    fn does_not_support_streaming() {
        assert!(!CLAUDE_AGENT_SDK_RUNTIME.supports_streaming());
    }

    #[test]
    fn does_not_support_tools() {
        assert!(!CLAUDE_AGENT_SDK_RUNTIME.supports_tools());
    }
}
