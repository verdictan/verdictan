// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP resource for declared gateway tool servers.

use std::path::PathBuf;

use serde_json::Value;

use crate::api::AsyncApiClient;
use crate::error::CliError;
use crate::gateway::declarative_config::{LoadedDeclarativeConfig, ToolServerDeclaration};

const RESOURCE_URI: &str = "gateway://tool-servers";
const LEGACY_RESOURCE_URI: &str = "gateway-tool-servers://declared";

pub(crate) fn descriptor() -> Value {
    serde_json::json!({
        "uri": RESOURCE_URI,
        "name": "Gateway Tool Servers",
        "description": "Durable tool server declarations from the gateway policy config. Supports more than one ?path=... query parameter. Parameter sequence sets the overlay sequence.",
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
            "Unknown gateway tool servers resource URI: {uri}"
        )));
    }

    let selected_paths = config_paths_from_uri(uri);
    tracing::debug!(
        uri = %uri,
        path_count = selected_paths.len(),
        "reading gateway tool servers MCP resource"
    );

    let loaded = LoadedDeclarativeConfig::from_paths(selected_paths.iter())?;
    let tool_servers = loaded
        .tool_servers
        .iter()
        .map(serialize_tool_server)
        .collect::<Vec<_>>();

    let payload = serde_json::json!({
        "selected_paths": display_paths(&selected_paths),
        "config_version": loaded.config_version,
        "config_sha256": loaded.config_sha256,
        "tool_servers": tool_servers,
    });

    wrap_json_contents(uri, payload)
}

fn serialize_tool_server(server: &ToolServerDeclaration) -> Value {
    serde_json::json!({
        "id": server.id,
        "name": server.name,
        "description": server.description,
        "transport": {
            "kind": server.transport.kind,
            "command": server.transport.command,
            "args": server.transport.args,
            "url": server.transport.url,
            "auth_type": server.transport.auth_type,
            "secret_key_env": server.transport.secret_key_env,
            "header_name": server.transport.header_name,
        },
        "mutability_class": server.mutability_class,
        "trust_state": server.trust_state,
        "containment": {
            "network_policy": server.containment.network_policy,
            "timeout_ms": server.containment.timeout_ms,
            "max_concurrent_calls": server.containment.max_concurrent_calls,
        },
        "labels": server.labels,
    })
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

    fn tool_servers_fixture_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/declarative_config/tool_servers_with_connectors.yaml")
    }

    #[test]
    fn descriptor_exposes_stable_uri() {
        assert_eq!(descriptor()["uri"], RESOURCE_URI);
    }

    #[tokio::test]
    async fn read_resource_serializes_declared_tool_servers() {
        let path = tool_servers_fixture_path();
        let uri = format!(
            "{RESOURCE_URI}?path={}",
            urlencoding::encode(&path.display().to_string())
        );
        let client = AsyncApiClient::new("http://127.0.0.1:9", "test-token").expect("client");

        let result = read_resource(&client, &uri).await.expect("resource read");
        let payload: Value =
            serde_json::from_str(result["contents"][0]["text"].as_str().unwrap()).unwrap();

        assert_eq!(payload["config_version"], "1.0.0");
        assert_eq!(payload["tool_servers"].as_array().unwrap().len(), 2);
        assert_eq!(payload["tool_servers"][0]["id"], "chrome-devtools-mcp");
        assert_eq!(
            payload["tool_servers"][0]["containment"]["timeout_ms"],
            60000
        );
        assert_eq!(
            payload["tool_servers"][1]["transport"]["args"][1],
            "--read-only"
        );
    }

    #[tokio::test]
    async fn read_resource_returns_empty_array_when_tool_servers_absent() {
        let file = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(
            file.path(),
            r#"
pack:
  name: no-tools
  version: "1.0.0"
"#,
        )
        .expect("write config");
        let uri = format!(
            "{RESOURCE_URI}?path={}",
            urlencoding::encode(&file.path().display().to_string())
        );
        let client = AsyncApiClient::new("http://127.0.0.1:9", "test-token").expect("client");

        let result = read_resource(&client, &uri).await.expect("resource read");
        let payload: Value =
            serde_json::from_str(result["contents"][0]["text"].as_str().unwrap()).unwrap();

        assert_eq!(payload["tool_servers"], serde_json::json!([]));
    }
}
