// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Vercel AI Gateway upstream runtime.
//!
//! Vercel AI Gateway exposes an OpenAI-compatible HTTP API at
//! `https://ai-gateway.vercel.sh/v1`. Requests and responses follow the
//! standard OpenAI chat-completions wire format, so this runtime is thin: it
//! validates the required configuration fields, injects the `model` field into
//! the request body when the caller omits it, and forwards both streaming (SSE)
//! and non-streaming responses unchanged.
//!
//! # Configuration
//!
//! ```yaml
//! providers:
//!   targets:
//!     - id: vercel
//!       provider: vercel
//!       model: openai/gpt-5.4-mini # passed as-is to the Vercel endpoint
//!       base_url: https://ai-gateway.vercel.sh/v1
//!       secret_key_ref:
//!         env: VERCEL_AI_GATEWAY_API_KEY
//! ```
//!
//! The `VERCEL_AI_GATEWAY_API_KEY` environment variable must contain a valid
//! Vercel AI Gateway bearer token. The gateway adds
//! `Authorization: Bearer <token>` to every upstream request automatically.
//!
//! # Error handling
//!
//! Vercel AI Gateway returns standard OpenAI-shaped error bodies
//! (`{"error": {"message": "...", "type": "...", "code": "..."}}`).
//! This runtime passes them through without transformation; the gateway's
//! existing error-envelope logic surfaces them to callers unchanged.
//!
//! # Streaming
//!
//! Both streaming (SSE) and non-streaming responses are supported. The
//! gateway's generic SSE forwarding path handles chunked responses without
//! runtime-specific intervention.

use serde_json::{json, Value};

use crate::error::CliError;

use super::VerdictanUpstreamRuntime;

pub static VERCEL_RUNTIME: VercelRuntime = VercelRuntime;

pub struct VercelRuntime;

impl super::super::VerdictanRuntime for VercelRuntime {
    fn runtime_id(&self) -> &'static str {
        "vercel"
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
                        "{key} is required for vercel runtime"
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

    /// Build the upstream request body.
    ///
    /// Vercel AI Gateway uses the standard OpenAI chat-completions request
    /// format. If the caller has not already set the `model` field in the
    /// request body, this method injects it from the provider configuration so
    /// the upstream receives a complete, well-formed request.
    fn build_request(&self, config: &Value, input: &Value) -> Result<Value, CliError> {
        let mut request = input.clone();
        if request.get("model").is_none() || request["model"].as_str() == Some("") {
            if let Some(model) = config.get("model").and_then(Value::as_str) {
                if !model.trim().is_empty() {
                    if let Some(obj) = request.as_object_mut() {
                        obj.insert("model".to_string(), json!(model));
                    }
                }
            }
        }
        Ok(request)
    }

    fn execute(&self, _config: &Value, request: &Value) -> Result<Value, CliError> {
        Ok(request.clone())
    }

    /// Normalize the upstream response.
    ///
    /// Vercel AI Gateway returns standard OpenAI-compatible response bodies for
    /// both success and error cases. No transformation is required; this method
    /// is a verified pass-through for the OpenAI wire format.
    fn translate_response(&self, response: &Value) -> Result<Value, CliError> {
        Ok(response.clone())
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn supports_tools(&self) -> bool {
        true
    }

    fn default_path_template(&self) -> Option<&'static str> {
        Some("/chat/completions")
    }
}

impl VerdictanUpstreamRuntime for VercelRuntime {
    fn provider_kind(&self) -> &'static str {
        "vercel"
    }

    /// Validate the Vercel AI Gateway endpoint URL.
    ///
    /// Vercel AI Gateway is a hosted service; only `https://` base URLs are
    /// accepted in production configurations.
    fn validate_endpoint_url(&self, base_url: &str) -> Result<(), CliError> {
        if base_url.starts_with("https://") {
            return Ok(());
        }
        Err(CliError::user(
            "vercel runtime requires an https:// base_url",
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
    fn runtime_id_returns_vercel() {
        assert_eq!(VERCEL_RUNTIME.runtime_id(), "vercel");
    }

    #[test]
    fn provider_kind_returns_vercel() {
        assert_eq!(VERCEL_RUNTIME.provider_kind(), "vercel");
    }

    #[test]
    fn validate_config_accepts_valid() {
        let config =
            json!({"model": "openai/gpt-4", "base_url": "https://ai-gateway.vercel.sh/v1"});
        assert!(VERCEL_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_rejects_http() {
        let config = json!({"model": "m", "base_url": "http://ai-gateway.vercel.sh/v1"});
        assert!(VERCEL_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_missing_model() {
        let config = json!({"base_url": "https://ai-gateway.vercel.sh/v1"});
        assert!(VERCEL_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_missing_base_url() {
        let config = json!({"model": "m"});
        assert!(VERCEL_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_endpoint_url_only_accepts_https() {
        assert!(VERCEL_RUNTIME
            .validate_endpoint_url("https://ai-gateway.vercel.sh")
            .is_ok());
        assert!(VERCEL_RUNTIME.validate_endpoint_url("http://host").is_err());
    }

    #[test]
    fn build_request_injects_model_when_missing() {
        let config = json!({"model": "openai/gpt-4"});
        let input = json!({"messages": [{"role": "user", "content": "hi"}]});
        let result = VERCEL_RUNTIME.build_request(&config, &input).unwrap();
        assert_eq!(result["model"], "openai/gpt-4");
    }

    #[test]
    fn build_request_preserves_existing_model() {
        let config = json!({"model": "openai/gpt-4"});
        let input = json!({"model": "custom/model", "messages": []});
        let result = VERCEL_RUNTIME.build_request(&config, &input).unwrap();
        assert_eq!(result["model"], "custom/model");
    }

    #[test]
    fn build_request_replaces_empty_string_model() {
        let config = json!({"model": "openai/gpt-4"});
        let input = json!({"model": "", "messages": []});
        let result = VERCEL_RUNTIME.build_request(&config, &input).unwrap();
        assert_eq!(result["model"], "openai/gpt-4");
    }

    #[test]
    fn build_request_no_model_in_config_leaves_input_unchanged() {
        let config = json!({});
        let input = json!({"messages": []});
        let result = VERCEL_RUNTIME.build_request(&config, &input).unwrap();
        assert!(result.get("model").is_none());
    }

    #[test]
    fn default_path_template_is_chat_completions() {
        assert_eq!(
            VerdictanRuntime::default_path_template(&VERCEL_RUNTIME),
            Some("/chat/completions")
        );
    }

    #[test]
    fn supports_streaming_and_tools() {
        assert!(VERCEL_RUNTIME.supports_streaming());
        assert!(VERCEL_RUNTIME.supports_tools());
    }

    #[test]
    fn validate_config_rejects_empty_model() {
        let config = json!({"model": "", "base_url": "https://ai-gateway.vercel.sh/v1"});
        assert!(VERCEL_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_whitespace_model() {
        let config = json!({"model": "  ", "base_url": "https://ai-gateway.vercel.sh/v1"});
        assert!(VERCEL_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_endpoint_url_rejects_bare_host() {
        assert!(VERCEL_RUNTIME
            .validate_endpoint_url("ai-gateway.vercel.sh")
            .is_err());
    }

    #[test]
    fn execute_passes_through() {
        let req = json!({"prompt": "test"});
        assert_eq!(VERCEL_RUNTIME.execute(&json!({}), &req).unwrap(), req);
    }

    #[test]
    fn translate_response_passes_through() {
        let resp = json!({"choices": []});
        assert_eq!(VERCEL_RUNTIME.translate_response(&resp).unwrap(), resp);
    }

    #[test]
    fn normalize_upstream_response_passes_through() {
        let resp = json!({"data": "value"});
        assert_eq!(
            VERCEL_RUNTIME.normalize_upstream_response(&resp).unwrap(),
            resp
        );
    }

    #[test]
    fn build_request_whitespace_model_in_config_is_not_injected() {
        let config = json!({"model": "   "});
        let input = json!({"messages": []});
        let result = VERCEL_RUNTIME.build_request(&config, &input).unwrap();
        assert!(result.get("model").is_none());
    }
}
