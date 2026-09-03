// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

use super::super::VerdictanRuntime;

pub static BROWSER_RUNTIME: BrowserRuntime = BrowserRuntime;

pub struct BrowserRuntime;

impl super::super::VerdictanRuntime for BrowserRuntime {
    fn runtime_id(&self) -> &'static str {
        "browser"
    }

    fn validate_config(&self, config: &Value) -> Result<(), CliError> {
        match config
            .get("adapter_command")
            .and_then(Value::as_str)
            .map(str::trim)
        {
            Some(value) if !value.is_empty() => Ok(()),
            _ => Err(CliError::user(
                "browser runtime requires adapter_command until a native runner exists",
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
}

impl super::VerdictanInteractiveRuntime for BrowserRuntime {
    fn initialize_session(&self, config: &Value) -> Result<Value, CliError> {
        VerdictanRuntime::validate_config(self, config)?;
        Ok(Value::Object(Default::default()))
    }

    fn execute_step(
        &self,
        _config: &Value,
        _session: &Value,
        request: &Value,
    ) -> Result<Value, CliError> {
        Ok(request.clone())
    }

    fn capture_state(&self, session: &Value) -> Result<Value, CliError> {
        Ok(session.clone())
    }

    fn finalize_session(&self, session: &Value) -> Result<Value, CliError> {
        Ok(session.clone())
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
    use crate::gateway::runtimes::interactive::VerdictanInteractiveRuntime;
    use crate::gateway::runtimes::VerdictanRuntime;
    use serde_json::json;

    #[test]
    fn runtime_id_returns_browser() {
        assert_eq!(BROWSER_RUNTIME.runtime_id(), "browser");
    }

    #[test]
    fn validate_config_accepts_adapter_command() {
        let config = json!({"adapter_command": "playwright run"});
        assert!(BROWSER_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_rejects_missing_adapter_command() {
        let config = json!({});
        assert!(BROWSER_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_empty_adapter_command() {
        let config = json!({"adapter_command": "  "});
        assert!(BROWSER_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn build_request_passes_through() {
        let input = json!({"url": "https://example.com"});
        assert_eq!(
            BROWSER_RUNTIME.build_request(&json!({}), &input).unwrap(),
            input
        );
    }

    #[test]
    fn execute_passes_through() {
        let req = json!({"action": "click"});
        assert_eq!(BROWSER_RUNTIME.execute(&json!({}), &req).unwrap(), req);
    }

    #[test]
    fn translate_response_passes_through() {
        let resp = json!({"screenshot": "base64data"});
        assert_eq!(BROWSER_RUNTIME.translate_response(&resp).unwrap(), resp);
    }

    #[test]
    fn initialize_session_validates_config_first() {
        let config = json!({});
        assert!(BROWSER_RUNTIME.initialize_session(&config).is_err());
    }

    #[test]
    fn initialize_session_returns_empty_object_on_valid_config() {
        let config = json!({"adapter_command": "playwright"});
        let session = BROWSER_RUNTIME.initialize_session(&config).unwrap();
        assert!(session.is_object());
        assert!(session.as_object().unwrap().is_empty());
    }

    #[test]
    fn execute_step_passes_request_through() {
        let req = json!({"step": "navigate"});
        let result = BROWSER_RUNTIME
            .execute_step(&json!({}), &json!({}), &req)
            .unwrap();
        assert_eq!(result, req);
    }

    #[test]
    fn capture_state_passes_session_through() {
        let session = json!({"state": "ready"});
        assert_eq!(BROWSER_RUNTIME.capture_state(&session).unwrap(), session);
    }

    #[test]
    fn finalize_session_passes_session_through() {
        let session = json!({"done": true});
        assert_eq!(BROWSER_RUNTIME.finalize_session(&session).unwrap(), session);
    }

    #[test]
    fn does_not_support_streaming() {
        assert!(!BROWSER_RUNTIME.supports_streaming());
    }

    #[test]
    fn does_not_support_tools() {
        assert!(!BROWSER_RUNTIME.supports_tools());
    }

    #[test]
    fn requires_model_default() {
        assert!(BROWSER_RUNTIME.requires_model());
    }

    #[test]
    fn auth_optional_default() {
        assert!(!BROWSER_RUNTIME.auth_optional());
    }

    #[test]
    fn validate_config_null_adapter_command() {
        assert!(BROWSER_RUNTIME
            .validate_config(&json!({"adapter_command": null}))
            .is_err());
    }
}
