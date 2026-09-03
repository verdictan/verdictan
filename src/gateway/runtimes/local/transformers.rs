// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

pub static TRANSFORMERS_RUNTIME: TransformersRuntime = TransformersRuntime;

pub struct TransformersRuntime;

impl super::super::VerdictanRuntime for TransformersRuntime {
    fn runtime_id(&self) -> &'static str {
        "transformers"
    }

    fn validate_config(&self, config: &Value) -> Result<(), CliError> {
        let provider = config
            .get("provider")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or_default();
        let provider_spec = config
            .get("provider_spec")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or(provider);
        let explicit_model = config
            .get("model")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or_default();
        let (task, model) = if provider_spec.starts_with("transformers:")
            || provider_spec.starts_with("transformers.js:")
        {
            let parts = provider_spec.split(':').collect::<Vec<_>>();
            (
                parts.get(1).copied().unwrap_or_default().to_string(),
                parts
                    .get(2..)
                    .map(|segments| segments.join(":"))
                    .unwrap_or_default(),
            )
        } else if let Some((task, model)) = explicit_model.split_once(':') {
            (task.to_string(), model.to_string())
        } else {
            (String::new(), explicit_model.to_string())
        };

        match task.as_str() {
            "feature-extraction" | "embeddings" | "text-generation" => {}
            _ => {
                return Err(CliError::user(
                    "transformers runtime requires provider syntax transformers:<feature-extraction|embeddings|text-generation>:<model>",
                ));
            }
        }

        if model.trim().is_empty() {
            return Err(CliError::user(
                "transformers runtime requires a model name after the task, for example transformers:text-generation:onnx-community/Qwen3-0.6B-ONNX",
            ));
        }

        if let Some(adapter_command) = config
            .get("adapter_command")
            .and_then(Value::as_str)
            .map(str::trim)
        {
            if adapter_command.is_empty() {
                return Err(CliError::user(
                    "transformers runtime received an empty adapter_command; omit it to use the built-in Node runner or provide a non-empty command",
                ));
            }
        }

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
    fn runtime_id_returns_transformers() {
        assert_eq!(TRANSFORMERS_RUNTIME.runtime_id(), "transformers");
    }

    #[test]
    fn validate_config_accepts_feature_extraction_via_provider_spec() {
        let config = json!({"provider_spec": "transformers:feature-extraction:all-MiniLM-L6-v2"});
        assert!(TRANSFORMERS_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_accepts_embeddings_via_provider_spec() {
        let config = json!({"provider_spec": "transformers:embeddings:nomic-embed"});
        assert!(TRANSFORMERS_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_accepts_text_generation_via_provider_spec() {
        let config = json!({"provider_spec": "transformers:text-generation:gpt2"});
        assert!(TRANSFORMERS_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_accepts_transformers_js_prefix() {
        let config = json!({"provider_spec": "transformers.js:text-generation:gpt2"});
        assert!(TRANSFORMERS_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_accepts_model_with_colon_task() {
        let config = json!({"model": "text-generation:gpt2"});
        assert!(TRANSFORMERS_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_uses_provider_field_as_fallback() {
        let config = json!({"provider": "transformers:text-generation:gpt2"});
        assert!(TRANSFORMERS_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_rejects_invalid_task() {
        let config = json!({"provider_spec": "transformers:summarization:model"});
        assert!(TRANSFORMERS_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_empty_model_after_task() {
        let config = json!({"provider_spec": "transformers:text-generation:"});
        assert!(TRANSFORMERS_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_no_task() {
        let config = json!({});
        assert!(TRANSFORMERS_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_empty_adapter_command() {
        let config = json!({
            "provider_spec": "transformers:text-generation:gpt2",
            "adapter_command": "  "
        });
        assert!(TRANSFORMERS_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_accepts_nonempty_adapter_command() {
        let config = json!({
            "provider_spec": "transformers:text-generation:gpt2",
            "adapter_command": "node runner.js"
        });
        assert!(TRANSFORMERS_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn requires_model_is_false() {
        assert!(!TRANSFORMERS_RUNTIME.requires_model());
    }

    #[test]
    fn auth_optional_is_true() {
        assert!(TRANSFORMERS_RUNTIME.auth_optional());
    }

    #[test]
    fn build_request_passes_through() {
        let input = json!({"input": "test"});
        assert_eq!(
            TRANSFORMERS_RUNTIME
                .build_request(&json!({}), &input)
                .unwrap(),
            input
        );
    }

    #[test]
    fn execute_passes_through() {
        let req = json!({"data": true});
        assert_eq!(TRANSFORMERS_RUNTIME.execute(&json!({}), &req).unwrap(), req);
    }

    #[test]
    fn translate_response_passes_through() {
        let resp = json!({"result": [1, 2]});
        assert_eq!(
            TRANSFORMERS_RUNTIME.translate_response(&resp).unwrap(),
            resp
        );
    }

    #[test]
    fn does_not_support_streaming() {
        assert!(!TRANSFORMERS_RUNTIME.supports_streaming());
    }

    #[test]
    fn does_not_support_tools() {
        assert!(!TRANSFORMERS_RUNTIME.supports_tools());
    }
}
