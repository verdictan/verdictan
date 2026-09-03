// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;
use crate::gateway::format_translation::{
    infer_request_format, translate_request, translate_response, ProviderFormat,
};

use super::VerdictanUpstreamRuntime;

pub static COHERE_RUNTIME: CohereRuntime = CohereRuntime;

pub struct CohereRuntime;

impl super::super::VerdictanRuntime for CohereRuntime {
    fn runtime_id(&self) -> &'static str {
        "cohere"
    }

    fn validate_config(&self, config: &Value) -> Result<(), CliError> {
        let mut base_url = None;
        for key in ["model", "base_url"] {
            match config.get(key).and_then(Value::as_str).map(str::trim) {
                Some(value) if !value.is_empty() => {
                    if key == "base_url" {
                        base_url = Some(value);
                    }
                }
                _ => {
                    return Err(CliError::user(format!(
                        "{key} is required for cohere runtime"
                    )))
                }
            }
        }
        // SAFETY: base_url is guaranteed Some after validate succeeds
        #[allow(clippy::expect_used)]
        let base_url = base_url.expect("base_url captured during validation");
        self.validate_endpoint_url(base_url)?;
        Ok(())
    }

    fn build_request(&self, _config: &Value, input: &Value) -> Result<Value, CliError> {
        let source_format = infer_request_format(input);
        let request = if source_format == ProviderFormat::Cohere && input.get("messages").is_some()
        {
            input.clone()
        } else {
            translate_request(input.clone(), source_format, ProviderFormat::Cohere)?
        };
        if request.get("message").is_some()
            || request.get("chat_history").is_some()
            || request.get("preamble").is_some()
        {
            return Err(CliError::user(
                "cohere runtime requires v2 chat messages and forbids legacy message/chat_history/preamble fields",
            ));
        }
        if request.get("messages").and_then(Value::as_array).is_none() {
            return Err(CliError::user("cohere runtime requires a messages array"));
        }
        Ok(request)
    }

    fn execute(&self, _config: &Value, request: &Value) -> Result<Value, CliError> {
        Ok(request.clone())
    }

    fn translate_response(&self, response: &Value) -> Result<Value, CliError> {
        translate_response(
            response.clone(),
            ProviderFormat::Cohere,
            ProviderFormat::OpenAI,
        )
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn supports_tools(&self) -> bool {
        true
    }

    fn default_path_template(&self) -> Option<&'static str> {
        Some("/v2/chat")
    }
}

impl VerdictanUpstreamRuntime for CohereRuntime {
    fn provider_kind(&self) -> &'static str {
        "cohere"
    }

    fn validate_endpoint_url(&self, base_url: &str) -> Result<(), CliError> {
        if base_url.starts_with("https://") {
            return Ok(());
        }
        Err(CliError::user(
            "cohere runtime requires an https:// base_url",
        ))
    }

    fn normalize_upstream_response(&self, response: &Value) -> Result<Value, CliError> {
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
    fn runtime_id() {
        assert_eq!(COHERE_RUNTIME.runtime_id(), "cohere");
    }

    #[test]
    fn provider_kind() {
        assert_eq!(COHERE_RUNTIME.provider_kind(), "cohere");
    }

    #[test]
    fn validate_config_valid() {
        let config = json!({"model": "command-r", "base_url": "https://api.cohere.ai"});
        assert!(COHERE_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_missing_model() {
        let config = json!({"base_url": "https://api.cohere.ai"});
        assert!(COHERE_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_http_rejected() {
        let config = json!({"model": "m", "base_url": "http://api.cohere.ai"});
        assert!(COHERE_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_endpoint_url_https() {
        assert!(COHERE_RUNTIME
            .validate_endpoint_url("https://api.cohere.ai")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_url_http_rejected() {
        assert!(COHERE_RUNTIME
            .validate_endpoint_url("http://api.cohere.ai")
            .is_err());
    }

    #[test]
    fn default_path_template_value() {
        assert_eq!(
            VerdictanRuntime::default_path_template(&COHERE_RUNTIME),
            Some("/v2/chat")
        );
    }

    #[test]
    fn supports_streaming_and_tools() {
        assert!(COHERE_RUNTIME.supports_streaming());
        assert!(COHERE_RUNTIME.supports_tools());
    }

    #[test]
    fn normalize_upstream_response_passthrough() {
        let resp = json!({"text": "hello"});
        assert_eq!(
            COHERE_RUNTIME.normalize_upstream_response(&resp).unwrap(),
            resp
        );
    }

    #[test]
    fn validate_config_rejects_missing_base_url() {
        let config = json!({"model": "command-r"});
        assert!(COHERE_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_empty_model() {
        let config = json!({"model": "", "base_url": "https://api.cohere.ai"});
        assert!(COHERE_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_whitespace_model() {
        let config = json!({"model": "  ", "base_url": "https://api.cohere.ai"});
        assert!(COHERE_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_endpoint_url_rejects_bare_host() {
        assert!(COHERE_RUNTIME
            .validate_endpoint_url("api.cohere.ai")
            .is_err());
    }

    #[test]
    fn build_request_accepts_v2_chat_messages() {
        let input = json!({"messages": [{"role": "user", "content": "hello"}]});
        let result = COHERE_RUNTIME.build_request(&json!({}), &input).unwrap();
        assert!(result.get("messages").and_then(Value::as_array).is_some());
        assert!(result.get("message").is_none());
    }

    #[test]
    fn build_request_translates_legacy_prompt_to_messages() {
        let input = json!({"message": "hello"});
        let result = COHERE_RUNTIME.build_request(&json!({}), &input).unwrap();
        assert!(result.get("messages").and_then(Value::as_array).is_some());
        assert!(result.get("message").is_none());
    }

    #[test]
    fn execute_passes_through() {
        let req = json!({"prompt": "test"});
        assert_eq!(COHERE_RUNTIME.execute(&json!({}), &req).unwrap(), req);
    }

    #[test]
    fn translate_response_translates_to_openai_shape() {
        let resp = json!({
            "message": {
                "role": "assistant",
                "content": "hi"
            },
            "finish_reason": "COMPLETE"
        });
        let result = COHERE_RUNTIME.translate_response(&resp).unwrap();
        assert!(result.get("choices").is_some());
    }
}
