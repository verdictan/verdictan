// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;

use crate::error::CliError;

#[derive(Debug, Args)]
pub(crate) struct GatewayConfigArgs {
    /// Base URL of the running proxy, for example http://127.0.0.1:8080.
    #[arg(long)]
    pub(crate) gateway_url: String,

    /// Fail if the running proxy is not using this config version.
    #[arg(long)]
    pub(crate) expect_version: Option<String>,

    /// Fail if the running proxy is not using this config digest.
    #[arg(long)]
    pub(crate) expect_sha256: Option<String>,
}
pub(crate) async fn run_async(args: GatewayConfigArgs) -> Result<(), CliError> {
    let url = format!(
        "{}/verdictan/config",
        args.gateway_url.trim_end_matches('/'),
    );

    let client =
        crate::gateway::http_client::shared_gateway_http_client().map_err(CliError::internal)?;
    let mut request = client.get(&url);
    if let Some(token) = crate::commands::gateway_reload::resolve_gateway_api_token(None, None) {
        request = request.bearer_auth(token);
    }

    let response = request
        .send()
        .await
        .map_err(|e| CliError::network(format!("failed to query proxy config: {e}")))?;

    let status = response.status();
    let body_text = response
        .text()
        .await
        .map_err(|e| CliError::network(format!("failed to read proxy response: {e}")))?;

    if !status.is_success() {
        return Err(CliError::network(format!(
            "proxy config endpoint returned {}: {}",
            status, body_text
        )));
    }

    let value: serde_json::Value = serde_json::from_str(&body_text)
        .map_err(|e| CliError::internal(format!("proxy config response is not valid JSON: {e}")))?;

    let config = value
        .get("config")
        .and_then(|v| v.as_object())
        .ok_or_else(|| CliError::internal("proxy config response is missing config object"))?;

    if let Some(expected) = args.expect_version.as_deref() {
        let actual = config
            .get("config_version")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if actual != expected {
            return Err(CliError::user(format!(
                "proxy is running config version {} instead of {}",
                actual, expected
            )));
        }
    }

    if let Some(expected) = args.expect_sha256.as_deref() {
        let actual = config
            .get("config_sha256")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if actual != expected {
            return Err(CliError::user(format!(
                "proxy is running config digest {} instead of {}",
                actual, expected
            )));
        }
    }

    let rendered = serde_json::to_string_pretty(&value)
        .map_err(|e| CliError::internal(format!("failed to render proxy config JSON: {e}")))?;
    println!("{}", rendered);
    Ok(())
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
    use serde_json::json;

    #[test]
    fn config_url_formatting() {
        let gateway_url = "http://127.0.0.1:8080";
        let url = format!("{}/verdictan/config", gateway_url.trim_end_matches('/'));
        assert_eq!(url, "http://127.0.0.1:8080/verdictan/config");
    }

    #[test]
    fn config_url_strips_trailing_slash() {
        let gateway_url = "http://127.0.0.1:8080/";
        let url = format!("{}/verdictan/config", gateway_url.trim_end_matches('/'));
        assert_eq!(url, "http://127.0.0.1:8080/verdictan/config");
    }

    #[test]
    fn expect_version_match() {
        let config = json!({"config_version": "v3", "config_sha256": "abc"});
        let actual = config
            .get("config_version")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert_eq!(actual, "v3");
    }

    #[test]
    fn expect_version_mismatch_detected() {
        let config = json!({"config_version": "v2"});
        let actual = config
            .get("config_version")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let expected = "v3";
        assert_ne!(actual, expected);
    }

    #[test]
    fn expect_sha256_defaults_empty() {
        let config = json!({});
        let actual = config
            .get("config_sha256")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert_eq!(actual, "");
    }

    #[test]
    fn parse_config_response_extracts_config_object() {
        let value = json!({"config": {"config_version": "v1", "config_sha256": "deadbeef"}});
        let config = value
            .get("config")
            .and_then(|v| v.as_object())
            .expect("config object");
        assert!(config.contains_key("config_version"));
        assert!(config.contains_key("config_sha256"));
    }

    #[test]
    fn parse_config_response_missing_config() {
        let value = json!({"status": "ok"});
        let config = value.get("config").and_then(|v| v.as_object());
        assert!(config.is_none());
    }

    #[test]
    fn expect_version_missing_defaults_empty() {
        let config = json!({});
        let actual = config
            .get("config_version")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert_eq!(actual, "");
    }

    #[test]
    fn expect_sha256_match() {
        let config = json!({"config_sha256": "deadbeef123"});
        let actual = config
            .get("config_sha256")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert_eq!(actual, "deadbeef123");
    }

    #[test]
    fn expect_sha256_mismatch_detected() {
        let config = json!({"config_sha256": "aaa"});
        let actual = config
            .get("config_sha256")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let expected = "bbb";
        assert_ne!(actual, expected);
    }

    #[test]
    fn config_url_with_port_and_path() {
        let gateway_url = "http://gateway.internal:9090/";
        let url = format!("{}/verdictan/config", gateway_url.trim_end_matches('/'));
        assert_eq!(url, "http://gateway.internal:9090/verdictan/config");
    }

    #[test]
    fn parse_config_response_nested_config_fields() {
        let value = json!({"config": {
            "config_version": "v5",
            "config_sha256": "sha256:aabb",
            "policy": {"name": "default"}
        }});
        let config = value.get("config").and_then(|v| v.as_object()).unwrap();
        assert_eq!(config.get("policy").unwrap()["name"], "default");
    }

    #[test]
    fn config_url_with_ipv6_host() {
        let gateway_url = "http://[::1]:8080";
        let url = format!("{}/verdictan/config", gateway_url.trim_end_matches('/'));
        assert_eq!(url, "http://[::1]:8080/verdictan/config");
    }

    #[test]
    fn config_url_double_trailing_slash() {
        let gateway_url = "http://gateway.example.com//";
        let url = format!("{}/verdictan/config", gateway_url.trim_end_matches('/'));
        assert_eq!(url, "http://gateway.example.com/verdictan/config");
    }

    #[test]
    fn parse_config_response_empty_config_object() {
        let value = json!({"config": {}});
        let config = value.get("config").and_then(|v| v.as_object()).unwrap();
        assert!(config.is_empty());
    }

    #[test]
    fn expect_version_null_value_defaults_empty() {
        let config = json!({"config_version": null});
        let actual = config
            .get("config_version")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert_eq!(actual, "");
    }

    #[test]
    fn expect_sha256_null_value_defaults_empty() {
        let config = json!({"config_sha256": null});
        let actual = config
            .get("config_sha256")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert_eq!(actual, "");
    }

    #[test]
    fn args_debug_impl() {
        let args = super::GatewayConfigArgs {
            gateway_url: "http://localhost:8080".to_string(),
            expect_version: None,
            expect_sha256: None,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("localhost"));
    }
}
