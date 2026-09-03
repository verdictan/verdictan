// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;
use crate::gateway::format_translation::{infer_request_format, translate_request, ProviderFormat};

use super::VerdictanUpstreamRuntime;

pub static AWS_BEDROCK_RUNTIME: AwsBedrockRuntime = AwsBedrockRuntime;

pub struct AwsBedrockRuntime;

impl super::super::VerdictanRuntime for AwsBedrockRuntime {
    fn runtime_id(&self) -> &'static str {
        "aws-bedrock"
    }

    fn validate_config(&self, config: &Value) -> Result<(), CliError> {
        match config.get("model").and_then(Value::as_str).map(str::trim) {
            Some(value) if !value.is_empty() => {}
            _ => return Err(CliError::user("model is required for aws-bedrock runtime")),
        }
        let model = config
            .get("model")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or_default();
        if !model.contains("anthropic.") {
            return Err(CliError::user(
                "aws-bedrock runtime requires an Anthropic model id",
            ));
        }
        if config
            .get("bedrock_model_family")
            .and_then(Value::as_str)
            .map(str::trim)
            != Some("anthropic_messages")
        {
            return Err(CliError::user(
                "aws-bedrock runtime requires bedrock_model_family=anthropic_messages",
            ));
        }
        let region = config
            .get("aws_region")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| CliError::user("aws_region is required for aws-bedrock runtime"))?;
        if let Some(base_url) = config.get("base_url").and_then(Value::as_str) {
            if !base_url.trim().is_empty() {
                self.validate_endpoint_url(base_url)?;
                if let Ok(url) = reqwest::Url::parse(base_url) {
                    if let Some(host) = url.host_str() {
                        let is_loopback = matches!(host, "127.0.0.1" | "localhost" | "::1");
                        if !is_loopback
                            && host.contains("amazonaws.com")
                            && !host.contains(&format!("bedrock-runtime.{region}.amazonaws.com"))
                        {
                            return Err(CliError::user(
                                "aws-bedrock runtime base_url host must match aws_region",
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn build_request(&self, config: &Value, input: &Value) -> Result<Value, CliError> {
        let source_format = infer_request_format(input);
        let mut request =
            translate_request(input.clone(), source_format, ProviderFormat::Anthropic)?;
        let object = request
            .as_object_mut()
            .ok_or_else(|| CliError::user("aws-bedrock request must be a JSON object"))?;
        object.insert(
            "anthropic_version".to_string(),
            Value::String("bedrock-2023-05-31".to_string()),
        );
        if let Some(model) = config.get("model").cloned() {
            object.insert("model".to_string(), model);
        }
        Ok(request)
    }

    fn execute(&self, _config: &Value, request: &Value) -> Result<Value, CliError> {
        Ok(request.clone())
    }

    fn translate_response(&self, response: &Value) -> Result<Value, CliError> {
        if response.get("error").is_some()
            || response.get("type").and_then(Value::as_str) == Some("error")
        {
            return Ok(response.clone());
        }
        if response.get("content").and_then(Value::as_array).is_none() {
            return Err(CliError::user(
                "aws-bedrock response missing Anthropic content array",
            ));
        }
        Ok(response.clone())
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn supports_tools(&self) -> bool {
        true
    }

    fn default_path_template(&self) -> Option<&'static str> {
        Some("/model/{model}/invoke")
    }
}

impl VerdictanUpstreamRuntime for AwsBedrockRuntime {
    fn provider_kind(&self) -> &'static str {
        "aws-bedrock"
    }

    fn validate_endpoint_url(&self, base_url: &str) -> Result<(), CliError> {
        if base_url.starts_with("https://") {
            return Ok(());
        }
        if let Ok(url) = reqwest::Url::parse(base_url) {
            if url.scheme() == "http" {
                if let Some(host) = url.host_str() {
                    if matches!(host, "127.0.0.1" | "localhost" | "::1") {
                        return Ok(());
                    }
                }
            }
        }
        Err(CliError::user(
            "aws-bedrock runtime requires an https:// base_url unless it targets a loopback test endpoint",
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
    fn runtime_id_returns_aws_bedrock() {
        assert_eq!(AWS_BEDROCK_RUNTIME.runtime_id(), "aws-bedrock");
    }

    #[test]
    fn provider_kind_returns_aws_bedrock() {
        assert_eq!(AWS_BEDROCK_RUNTIME.provider_kind(), "aws-bedrock");
    }

    #[test]
    fn validate_config_accepts_anthropic_messages() {
        let config = json!({
            "model": "anthropic.claude-v2",
            "bedrock_model_family": "anthropic_messages",
            "aws_region": "us-east-1"
        });
        assert!(AWS_BEDROCK_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_rejects_non_anthropic_model() {
        let config = json!({
            "model": "amazon.titan-text-v1",
            "bedrock_model_family": "anthropic_messages",
            "aws_region": "us-east-1"
        });
        assert!(AWS_BEDROCK_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_missing_bedrock_model_family() {
        let config = json!({
            "model": "anthropic.claude-v2",
            "aws_region": "us-east-1"
        });
        assert!(AWS_BEDROCK_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_missing_aws_region() {
        let config = json!({
            "model": "anthropic.claude-v2",
            "bedrock_model_family": "anthropic_messages"
        });
        assert!(AWS_BEDROCK_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_missing_model() {
        let config = json!({});
        let err = AWS_BEDROCK_RUNTIME.validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("model"));
    }

    #[test]
    fn validate_config_rejects_empty_model() {
        let config = json!({"model": ""});
        assert!(AWS_BEDROCK_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_whitespace_model() {
        let config = json!({"model": "   "});
        assert!(AWS_BEDROCK_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_endpoint_url_accepts_https() {
        assert!(AWS_BEDROCK_RUNTIME
            .validate_endpoint_url("https://bedrock-runtime.us-east-1.amazonaws.com")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_url_rejects_http() {
        assert!(AWS_BEDROCK_RUNTIME
            .validate_endpoint_url("http://bedrock-runtime.us-east-1.amazonaws.com")
            .is_err());
    }

    #[test]
    fn validate_endpoint_url_rejects_bare_host() {
        assert!(AWS_BEDROCK_RUNTIME
            .validate_endpoint_url("bedrock-runtime.us-east-1.amazonaws.com")
            .is_err());
    }

    #[test]
    fn default_path_template_contains_model_placeholder() {
        let template = VerdictanRuntime::default_path_template(&AWS_BEDROCK_RUNTIME).unwrap();
        assert_eq!(template, "/model/{model}/invoke");
        assert!(template.contains("{model}"));
    }

    #[test]
    fn build_request_translates_to_anthropic_messages_shape() {
        let config = json!({
            "model": "anthropic.claude-v2",
            "bedrock_model_family": "anthropic_messages",
            "aws_region": "us-east-1"
        });
        let input = json!({"prompt": "hello"});
        let result = AWS_BEDROCK_RUNTIME.build_request(&config, &input).unwrap();
        assert_eq!(
            result.get("anthropic_version").and_then(Value::as_str),
            Some("bedrock-2023-05-31")
        );
        assert_eq!(result.get("model"), config.get("model"));
        assert!(result.get("messages").is_some());
    }

    #[test]
    fn execute_passes_through() {
        let config = json!({});
        let request = json!({"prompt": "test"});
        let result = AWS_BEDROCK_RUNTIME.execute(&config, &request).unwrap();
        assert_eq!(result, request);
    }

    #[test]
    fn translate_response_accepts_anthropic_content_shape() {
        let response = json!({"content": [{"type": "text", "text": "world"}]});
        let result = AWS_BEDROCK_RUNTIME.translate_response(&response).unwrap();
        assert_eq!(result, response);
    }

    #[test]
    fn translate_response_passes_through_error_payload() {
        let response = json!({"error": "upstream failure"});
        let result = AWS_BEDROCK_RUNTIME.translate_response(&response).unwrap();
        assert_eq!(result, response);
    }

    #[test]
    fn translate_response_rejects_missing_content_array() {
        let response = json!({"completion": "world"});
        assert!(AWS_BEDROCK_RUNTIME.translate_response(&response).is_err());
    }

    #[test]
    fn normalize_upstream_response_passes_through() {
        let response = json!({"output": "data"});
        let result = AWS_BEDROCK_RUNTIME
            .normalize_upstream_response(&response)
            .unwrap();
        assert_eq!(result, response);
    }

    #[test]
    fn supports_streaming_is_true() {
        assert!(AWS_BEDROCK_RUNTIME.supports_streaming());
    }

    #[test]
    fn supports_tools_is_true() {
        assert!(AWS_BEDROCK_RUNTIME.supports_tools());
    }
}
