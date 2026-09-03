// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;
use crate::gateway::format_translation::{
    infer_request_format, translate_request, translate_response, ProviderFormat,
};

use super::VerdictanUpstreamRuntime;

pub static WATSONX_RUNTIME: WatsonxRuntime = WatsonxRuntime;

pub struct WatsonxRuntime;

impl super::super::VerdictanRuntime for WatsonxRuntime {
    fn runtime_id(&self) -> &'static str {
        "watsonx"
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
                        "{key} is required for watsonx runtime"
                    )))
                }
            }
        }
        // SAFETY: base_url is guaranteed Some after validate succeeds
        #[allow(clippy::expect_used)]
        let base_url = base_url.expect("base_url captured during validation");
        self.validate_endpoint_url(base_url)?;
        if config
            .get("watsonx_api_version")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            return Err(CliError::user(
                "watsonx_api_version is required for watsonx runtime",
            ));
        }
        let project_id = config
            .get("watsonx_project_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let space_id = config
            .get("watsonx_space_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if project_id.is_some() == space_id.is_some() {
            return Err(CliError::user(
                "watsonx runtime requires exactly one of watsonx_project_id or watsonx_space_id",
            ));
        }
        Ok(())
    }

    fn build_request(&self, config: &Value, input: &Value) -> Result<Value, CliError> {
        let source_format = infer_request_format(input);
        let mut request =
            if source_format == ProviderFormat::WatsonX && input.get("messages").is_some() {
                input.clone()
            } else {
                translate_request(input.clone(), source_format, ProviderFormat::WatsonX)?
            };
        if request.get("project_id").is_some() || request.get("space_id").is_some() {
            return Err(CliError::user(
                "watsonx client requests cannot override project_id or space_id",
            ));
        }
        let object = request
            .as_object_mut()
            .ok_or_else(|| CliError::user("watsonx request must be a JSON object"))?;
        if let Some(messages) = object.get("messages").and_then(Value::as_array) {
            if messages.is_empty() {
                return Err(CliError::user(
                    "watsonx request requires at least one message",
                ));
            }
        } else {
            return Err(CliError::user("watsonx request requires a messages array"));
        }
        if let Some(project_id) = config.get("watsonx_project_id").cloned() {
            object.insert("project_id".to_string(), project_id);
        }
        if let Some(space_id) = config.get("watsonx_space_id").cloned() {
            object.insert("space_id".to_string(), space_id);
        }
        if let Some(model_id) = config.get("model").cloned() {
            object.insert("model_id".to_string(), model_id);
        }
        Ok(request)
    }

    fn execute(&self, _config: &Value, request: &Value) -> Result<Value, CliError> {
        Ok(request.clone())
    }

    fn translate_response(&self, response: &Value) -> Result<Value, CliError> {
        translate_response(
            response.clone(),
            ProviderFormat::WatsonX,
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
        Some("/ml/v1/text/chat")
    }
}

impl VerdictanUpstreamRuntime for WatsonxRuntime {
    fn provider_kind(&self) -> &'static str {
        "watsonx"
    }

    fn validate_endpoint_url(&self, base_url: &str) -> Result<(), CliError> {
        if base_url.starts_with("https://") {
            if let Ok(url) = reqwest::Url::parse(base_url) {
                if let Some(host) = url.host_str() {
                    if host.ends_with(".ml.cloud.ibm.com")
                        || matches!(host, "127.0.0.1" | "localhost" | "::1")
                    {
                        return Ok(());
                    }
                }
            }
        }
        if let Ok(url) = reqwest::Url::parse(base_url) {
            if url.scheme() == "https" {
                return Err(CliError::user(
                    "watsonx runtime requires a regional https://*.ml.cloud.ibm.com base_url",
                ));
            }
        }
        Err(CliError::user(
            "watsonx runtime requires a regional https://*.ml.cloud.ibm.com base_url",
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
    fn runtime_id_returns_watsonx() {
        assert_eq!(WATSONX_RUNTIME.runtime_id(), "watsonx");
    }

    #[test]
    fn provider_kind_returns_watsonx() {
        assert_eq!(WATSONX_RUNTIME.provider_kind(), "watsonx");
    }

    #[test]
    fn validate_config_accepts_valid() {
        let config = json!({
            "model": "ibm/granite",
            "base_url": "https://us-south.ml.cloud.ibm.com",
            "watsonx_api_version": "2024-05-29",
            "watsonx_project_id": "proj-123"
        });
        assert!(WATSONX_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_rejects_http() {
        let config = json!({"model": "m", "base_url": "http://host"});
        assert!(WATSONX_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_missing_model() {
        let config = json!({"base_url": "https://host"});
        assert!(WATSONX_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_missing_base_url() {
        let config = json!({"model": "m"});
        assert!(WATSONX_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_endpoint_url_accepts_regional_ml_cloud_host() {
        assert!(WATSONX_RUNTIME
            .validate_endpoint_url("https://us-south.ml.cloud.ibm.com")
            .is_ok());
        assert!(WATSONX_RUNTIME
            .validate_endpoint_url("https://host")
            .is_err());
        assert!(WATSONX_RUNTIME
            .validate_endpoint_url("http://host")
            .is_err());
    }

    #[test]
    fn default_path_template_is_chat() {
        assert_eq!(
            VerdictanRuntime::default_path_template(&WATSONX_RUNTIME),
            Some("/ml/v1/text/chat")
        );
    }

    #[test]
    fn supports_streaming_and_tools() {
        assert!(WATSONX_RUNTIME.supports_streaming());
        assert!(WATSONX_RUNTIME.supports_tools());
    }

    #[test]
    fn validate_config_rejects_empty_model() {
        let config = json!({"model": "", "base_url": "https://us-south.ml.cloud.ibm.com"});
        assert!(WATSONX_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_whitespace_model() {
        let config = json!({"model": "  ", "base_url": "https://us-south.ml.cloud.ibm.com"});
        assert!(WATSONX_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_endpoint_url_rejects_bare_host() {
        assert!(WATSONX_RUNTIME
            .validate_endpoint_url("us-south.ml.cloud.ibm.com")
            .is_err());
    }

    #[test]
    fn build_request_injects_watsonx_scope_and_model() {
        let config = json!({
            "model": "ibm/granite",
            "watsonx_project_id": "proj-123"
        });
        let input = json!({"messages": [{"role": "user", "content": "test text"}]});
        let result = WATSONX_RUNTIME.build_request(&config, &input).unwrap();
        assert_eq!(result.get("project_id"), config.get("watsonx_project_id"));
        assert_eq!(result.get("model_id"), config.get("model"));
        assert!(result.get("messages").and_then(Value::as_array).is_some());
    }

    #[test]
    fn execute_passes_through() {
        let req = json!({"prompt": "test"});
        assert_eq!(WATSONX_RUNTIME.execute(&json!({}), &req).unwrap(), req);
    }

    #[test]
    fn translate_response_translates_to_openai_shape() {
        let resp = json!({
            "choices": [{
                "message": {"role": "assistant", "content": "hi"},
                "finish_reason": "stop"
            }]
        });
        let result = WATSONX_RUNTIME.translate_response(&resp).unwrap();
        assert!(result.get("choices").is_some());
    }

    #[test]
    fn normalize_upstream_response_passes_through() {
        let resp = json!({"data": "value"});
        assert_eq!(
            WATSONX_RUNTIME.normalize_upstream_response(&resp).unwrap(),
            resp
        );
    }
}
