// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP resource for gateway effective declarative config snapshots.

use std::path::PathBuf;

use serde_json::Value;

use crate::api::AsyncApiClient;
use crate::error::CliError;
use crate::gateway::declarative_config::LoadedDeclarativeConfig;

const RESOURCE_URI: &str = "gateway://effective-config";
const LEGACY_RESOURCE_URI: &str = "gateway-effective-config://resolved";

pub(crate) fn descriptor() -> Value {
    serde_json::json!({
        "uri": RESOURCE_URI,
        "name": "Gateway Effective Config",
        "description": "Resolved declarative gateway config. Supports more than one ?path=... query parameter. Parameter sequence sets the overlay sequence.",
        "mimeType": "application/json"
    })
}

pub(crate) fn matches_uri(uri: &str) -> bool {
    [RESOURCE_URI, LEGACY_RESOURCE_URI]
        .into_iter()
        .any(|candidate| {
            uri == candidate
                || uri
                    .strip_prefix(candidate)
                    .is_some_and(|suffix| suffix.starts_with('?'))
        })
}

pub(crate) async fn read_resource(_client: &AsyncApiClient, uri: &str) -> Result<Value, CliError> {
    if !matches_uri(uri) {
        return Err(CliError::user(format!(
            "Unknown gateway effective config resource URI: {uri}"
        )));
    }

    let selected_paths = config_paths_from_uri(uri);
    tracing::debug!(
        uri = %uri,
        path_count = selected_paths.len(),
        "reading gateway effective config MCP resource"
    );

    let loaded = LoadedDeclarativeConfig::from_paths(selected_paths.iter())?;
    let payload = serde_json::json!({
        "selected_paths": display_paths(&selected_paths),
        "effective_config": serde_json::to_value(&loaded)
            .map_err(|error| CliError::internal(format!("failed to serialize effective config: {error}")))?,
    });

    wrap_json_contents(uri, payload)
}

fn config_paths_from_uri(uri: &str) -> Vec<PathBuf> {
    let mut paths = query_values(uri, &["path", "config"])
        .into_iter()
        .filter_map(|value| {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then(|| PathBuf::from(trimmed))
        })
        .collect::<Vec<_>>();

    if paths.is_empty() {
        paths.push(PathBuf::from("policy-config.yaml"));
    }

    paths
}

fn display_paths(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect()
}

fn query_values(uri: &str, keys: &[&str]) -> Vec<String> {
    let Some((_, query)) = uri.split_once('?') else {
        return Vec::new();
    };

    query
        .split('&')
        .filter_map(|pair| {
            let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
            keys.iter()
                .any(|candidate| raw_key.eq_ignore_ascii_case(candidate))
                .then(|| decode_query_value(raw_value))
        })
        .collect()
}

fn decode_query_value(raw_value: &str) -> String {
    match urlencoding::decode(raw_value) {
        Ok(value) => value.into_owned(),
        Err(_) => raw_value.to_string(),
    }
}

fn wrap_json_contents(uri: &str, payload: Value) -> Result<Value, CliError> {
    let text = serde_json::to_string(&payload).map_err(|error| {
        CliError::internal(format!("failed to encode resource payload: {error}"))
    })?;

    Ok(serde_json::json!({
        "contents": [{
            "uri": uri,
            "mimeType": "application/json",
            "text": text
        }]
    }))
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
    use tempfile::NamedTempFile;

    fn write_temp_config(contents: &str) -> NamedTempFile {
        let file = NamedTempFile::new().expect("temp config");
        std::fs::write(file.path(), contents).expect("write temp config");
        file
    }

    #[test]
    fn descriptor_uses_stable_uri() {
        assert_eq!(descriptor()["uri"], RESOURCE_URI);
        assert_eq!(descriptor()["mimeType"], "application/json");
    }

    #[test]
    fn matches_uri_accepts_query_variants() {
        assert!(matches_uri(RESOURCE_URI));
        assert!(matches_uri(LEGACY_RESOURCE_URI));
        assert!(matches_uri(
            "gateway://effective-config?path=/tmp/policy.yaml"
        ));
        assert!(matches_uri(
            "gateway-effective-config://resolved?path=/tmp/policy.yaml"
        ));
        assert!(!matches_uri("gateway://other"));
    }

    #[tokio::test]
    async fn read_resource_serializes_effective_config_and_selected_paths() {
        let file = write_temp_config(
            r#"
pack:
  name: finance-pack
  version: "3.2.1"
region: eu-west
tool_servers:
  - id: repo-browser
    name: Repo Browser
    transport:
      kind: stdio
      command: npx
      args: ["repo-browser"]
"#,
        );
        let uri = format!(
            "{RESOURCE_URI}?path={}",
            urlencoding::encode(&file.path().display().to_string())
        );
        let client = AsyncApiClient::new("http://127.0.0.1:9", "test-token").expect("client");

        let result = read_resource(&client, &uri).await.expect("resource read");
        let payload: Value =
            serde_json::from_str(result["contents"][0]["text"].as_str().unwrap()).unwrap();

        assert_eq!(
            payload["selected_paths"][0],
            file.path().display().to_string()
        );
        assert_eq!(payload["effective_config"]["pack_name"], "finance-pack");
        assert_eq!(payload["effective_config"]["config_version"], "3.2.1");
        assert_eq!(payload["effective_config"]["region"], "eu-west");
    }

    #[test]
    fn config_paths_from_uri_defaults_to_policy_config_yaml() {
        assert_eq!(
            config_paths_from_uri(RESOURCE_URI),
            vec![PathBuf::from("policy-config.yaml")]
        );
    }
}
