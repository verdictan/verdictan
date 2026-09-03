// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

use super::VerdictanAgentRuntime;

pub static OPENAI_AGENTS_RUNTIME: OpenAiAgentsRuntime = OpenAiAgentsRuntime;

pub struct OpenAiAgentsRuntime;

impl super::super::VerdictanRuntime for OpenAiAgentsRuntime {
    fn runtime_id(&self) -> &'static str {
        "openai-agents"
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

impl VerdictanAgentRuntime for OpenAiAgentsRuntime {
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
    fn runtime_id() {
        assert_eq!(OPENAI_AGENTS_RUNTIME.runtime_id(), "openai-agents");
    }

    #[test]
    fn validate_config_always_ok() {
        assert!(OPENAI_AGENTS_RUNTIME.validate_config(&json!({})).is_ok());
    }

    #[test]
    fn requires_model_false() {
        assert!(!OPENAI_AGENTS_RUNTIME.requires_model());
    }

    #[test]
    fn auth_optional_true() {
        assert!(OPENAI_AGENTS_RUNTIME.auth_optional());
    }

    #[test]
    fn initialize_agent_returns_empty_object() {
        assert_eq!(
            OPENAI_AGENTS_RUNTIME.initialize_agent(&json!({})).unwrap(),
            json!({})
        );
    }

    #[test]
    fn execute_agent_call_passthrough() {
        let req = json!({"messages": []});
        assert_eq!(
            OPENAI_AGENTS_RUNTIME
                .execute_agent_call(&json!({}), &json!({}), &req)
                .unwrap(),
            req
        );
    }

    #[test]
    fn stream_agent_events_empty() {
        assert!(OPENAI_AGENTS_RUNTIME
            .stream_agent_events(&json!({}))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn finalize_agent_state_passthrough() {
        let state = json!({"thread_id": "t-1"});
        assert_eq!(
            OPENAI_AGENTS_RUNTIME.finalize_agent_state(&state).unwrap(),
            state
        );
    }

    #[test]
    fn build_request_passthrough() {
        let input = json!({"messages": []});
        assert_eq!(
            OPENAI_AGENTS_RUNTIME
                .build_request(&json!({}), &input)
                .unwrap(),
            input
        );
    }

    #[test]
    fn execute_passthrough() {
        let req = json!({"data": 1});
        assert_eq!(
            OPENAI_AGENTS_RUNTIME.execute(&json!({}), &req).unwrap(),
            req
        );
    }

    #[test]
    fn translate_response_passthrough() {
        let resp = json!({"output": "hello"});
        assert_eq!(
            OPENAI_AGENTS_RUNTIME.translate_response(&resp).unwrap(),
            resp
        );
    }

    #[test]
    fn does_not_support_streaming() {
        assert!(!OPENAI_AGENTS_RUNTIME.supports_streaming());
    }

    #[test]
    fn does_not_support_tools() {
        assert!(!OPENAI_AGENTS_RUNTIME.supports_tools());
    }
}
