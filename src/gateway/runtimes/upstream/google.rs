// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

use super::VerdictanUpstreamRuntime;

pub static GOOGLE_RUNTIME: GoogleRuntime = GoogleRuntime;

pub struct GoogleRuntime;

impl super::super::VerdictanRuntime for GoogleRuntime {
    fn runtime_id(&self) -> &'static str {
        "google"
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
                        "{key} is required for google runtime"
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
        Ok(input.clone())
    }

    fn execute(&self, _config: &Value, request: &Value) -> Result<Value, CliError> {
        Ok(request.clone())
    }

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
        Some("/v1beta/models/{model}:generateContent")
    }
}

impl VerdictanUpstreamRuntime for GoogleRuntime {
    fn provider_kind(&self) -> &'static str {
        "google"
    }

    fn validate_endpoint_url(&self, base_url: &str) -> Result<(), CliError> {
        if base_url.starts_with("https://") || is_loopback_http_url(base_url) {
            return Ok(());
        }
        Err(CliError::user(
            "google runtime requires an https:// base_url",
        ))
    }

    fn normalize_upstream_response(&self, response: &Value) -> Result<Value, CliError> {
        Ok(response.clone())
    }
}

fn is_loopback_http_url(base_url: &str) -> bool {
    let Some(remainder) = base_url.strip_prefix("http://") else {
        return false;
    };

    let authority = remainder.split('/').next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or(authority);

    if let Some(ipv6_host) = host
        .strip_prefix('[')
        .and_then(|value| value.split(']').next())
    {
        return ipv6_host == "::1";
    }

    let host = host.split(':').next().unwrap_or_default();
    matches!(host, "localhost" | "127.0.0.1")
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
        assert_eq!(GOOGLE_RUNTIME.runtime_id(), "google");
    }

    #[test]
    fn provider_kind() {
        assert_eq!(GOOGLE_RUNTIME.provider_kind(), "google");
    }

    #[test]
    fn validate_config_valid_https() {
        let config =
            json!({"model": "gemini-pro", "base_url": "https://generativelanguage.googleapis.com"});
        assert!(GOOGLE_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_valid_loopback() {
        let config = json!({"model": "gemini-pro", "base_url": "http://localhost:8080"});
        assert!(GOOGLE_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_missing_model() {
        let config = json!({"base_url": "https://api.google.com"});
        assert!(GOOGLE_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_endpoint_url_https() {
        assert!(GOOGLE_RUNTIME
            .validate_endpoint_url("https://api.google.com")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_url_loopback_localhost() {
        assert!(GOOGLE_RUNTIME
            .validate_endpoint_url("http://localhost:8080")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_url_loopback_127() {
        assert!(GOOGLE_RUNTIME
            .validate_endpoint_url("http://127.0.0.1:9999")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_url_http_non_loopback_rejected() {
        assert!(GOOGLE_RUNTIME
            .validate_endpoint_url("http://api.google.com")
            .is_err());
    }

    #[test]
    fn is_loopback_http_url_localhost() {
        assert!(is_loopback_http_url("http://localhost:8080/path"));
        assert!(is_loopback_http_url("http://localhost/path"));
    }

    #[test]
    fn is_loopback_http_url_127() {
        assert!(is_loopback_http_url("http://127.0.0.1:3000"));
        assert!(is_loopback_http_url("http://127.0.0.1"));
    }

    #[test]
    fn is_loopback_http_url_ipv6() {
        assert!(is_loopback_http_url("http://[::1]:8080/path"));
        assert!(is_loopback_http_url("http://[::1]/path"));
    }

    #[test]
    fn is_loopback_http_url_not_loopback() {
        assert!(!is_loopback_http_url("http://10.0.0.1:8080"));
        assert!(!is_loopback_http_url("https://localhost:8080"));
        assert!(!is_loopback_http_url("http://example.com"));
    }

    #[test]
    fn is_loopback_http_url_with_auth() {
        assert!(is_loopback_http_url("http://user@localhost:8080/path"));
    }

    #[test]
    fn default_path_template_value() {
        assert_eq!(
            VerdictanRuntime::default_path_template(&GOOGLE_RUNTIME),
            Some("/v1beta/models/{model}:generateContent")
        );
    }

    #[test]
    fn supports_streaming_and_tools() {
        assert!(GOOGLE_RUNTIME.supports_streaming());
        assert!(GOOGLE_RUNTIME.supports_tools());
    }

    #[test]
    fn build_request_passes_through() {
        let input = json!({"messages": []});
        assert_eq!(
            GOOGLE_RUNTIME.build_request(&json!({}), &input).unwrap(),
            input
        );
    }

    #[test]
    fn execute_passes_through() {
        let req = json!({"prompt": "test"});
        assert_eq!(GOOGLE_RUNTIME.execute(&json!({}), &req).unwrap(), req);
    }

    #[test]
    fn translate_response_passes_through() {
        let resp = json!({"candidates": []});
        assert_eq!(GOOGLE_RUNTIME.translate_response(&resp).unwrap(), resp);
    }

    #[test]
    fn normalize_upstream_response_passes_through() {
        let resp = json!({"data": "value"});
        assert_eq!(
            GOOGLE_RUNTIME.normalize_upstream_response(&resp).unwrap(),
            resp
        );
    }

    #[test]
    fn validate_config_rejects_empty_model() {
        let config = json!({"model": ""});
        assert!(GOOGLE_RUNTIME.validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_rejects_whitespace_model() {
        let config = json!({"model": "  "});
        assert!(GOOGLE_RUNTIME.validate_config(&config).is_err());
    }
}
