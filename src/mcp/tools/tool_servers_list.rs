// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP tool: tool_servers_list

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::ToolContext;
use crate::error::CliError;
use crate::gateway::declarative_config::{LoadedDeclarativeConfig, ToolServerDeclaration};

#[derive(Debug)]
pub(crate) struct ToolServerConfigSource {
    pub(crate) kind: &'static str,
    pub(crate) path: Option<PathBuf>,
    pub(crate) config: LoadedDeclarativeConfig,
}

pub(crate) async fn execute(_ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let source = load_tool_server_config(arguments, false)?;
    let trust_state = arguments.get("trust_state").and_then(Value::as_str);
    let mutability_class = arguments.get("mutability_class").and_then(Value::as_str);

    let tool_servers: Vec<Value> = source
        .config
        .tool_servers
        .iter()
        .filter(|server| trust_state.is_none_or(|value| server.trust_state == value))
        .filter(|server| mutability_class.is_none_or(|value| server.mutability_class == value))
        .map(tool_server_json)
        .collect();

    let approved_count = tool_servers
        .iter()
        .filter(|server| server.get("trust_state").and_then(Value::as_str) == Some("approved"))
        .count();
    let pending_count = tool_servers.len().saturating_sub(approved_count);

    Ok(json!({
        "ok": true,
        "source": {
            "kind": source.kind,
            "config_path": source.path.as_ref().map(|path| path.display().to_string()),
        },
        "summary": {
            "tool_server_count": tool_servers.len(),
            "approved_count": approved_count,
            "pending_count": pending_count,
        },
        "tool_servers": tool_servers,
    }))
}

pub(crate) fn load_tool_server_config(
    arguments: &Value,
    validation_mode: bool,
) -> Result<ToolServerConfigSource, CliError> {
    let yaml = arguments
        .get("yaml")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let config_path = arguments
        .get("config_path")
        .or_else(|| arguments.get("file"))
        .or_else(|| arguments.get("path"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if yaml.is_some() && config_path.is_some() {
        return Err(CliError::user(
            "tool server tools accept either 'yaml' or 'config_path', but not both",
        ));
    }

    if let Some(yaml) = yaml {
        let config = if validation_mode {
            LoadedDeclarativeConfig::from_bytes_for_validation(yaml.as_bytes())?
        } else {
            LoadedDeclarativeConfig::from_bytes(yaml.as_bytes())?
        };

        return Ok(ToolServerConfigSource {
            kind: "inline_yaml",
            path: None,
            config,
        });
    }

    if let Some(config_path) = config_path {
        let path = PathBuf::from(config_path);
        let config = if validation_mode {
            LoadedDeclarativeConfig::from_path_for_validation(&path)?
        } else {
            LoadedDeclarativeConfig::from_path(&path)?
        };

        return Ok(ToolServerConfigSource {
            kind: "file_path",
            path: Some(path),
            config,
        });
    }

    if let Some(path) = default_policy_config_path() {
        let config = if validation_mode {
            LoadedDeclarativeConfig::from_path_for_validation(&path)?
        } else {
            LoadedDeclarativeConfig::from_path(&path)?
        };

        return Ok(ToolServerConfigSource {
            kind: "default_path",
            path: Some(path),
            config,
        });
    }

    Err(CliError::user(
        "tool server tools require 'config_path' or 'yaml', or a readable local policy-config.yaml",
    ))
}

pub(crate) fn tool_server_json(server: &ToolServerDeclaration) -> Value {
    json!({
        "id": &server.id,
        "name": &server.name,
        "description": &server.description,
        "mutability_class": &server.mutability_class,
        "trust_state": &server.trust_state,
        "transport": {
            "kind": &server.transport.kind,
            "command": &server.transport.command,
            "args": &server.transport.args,
            "url": &server.transport.url,
            "auth_type": &server.transport.auth_type,
            "secret_key_env": &server.transport.secret_key_env,
            "header_name": &server.transport.header_name,
        },
        "containment": {
            "network_policy": &server.containment.network_policy,
            "timeout_ms": server.containment.timeout_ms,
            "max_concurrent_calls": server.containment.max_concurrent_calls,
        },
        "labels": &server.labels,
    })
}

fn default_policy_config_path() -> Option<PathBuf> {
    for candidate in ["policy-config.yaml", "/etc/verdictan/policy-config.yaml"] {
        let resolved = crate::commands::gateway_run::resolve_policy_config_paths(
            &[],
            false,
            Path::new(candidate),
        );
        if let Some(path) = resolved.into_iter().next() {
            return Some(path);
        }
    }

    None
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
    use serde_json::json;

    const VALID_TOOL_SERVERS_YAML: &str = r#"
pack:
  name: governed-tools
  version: "1.0.0"
providers:
  targets:
    - id: openai
      provider: openai
      model: gpt-5.4-mini
      base_url: https://api.openai.com/v1
      secret_key_ref:
        store: OPENAI_API_KEY
tool_servers:
  - id: filesystem-mcp
    name: Filesystem MCP
    transport:
      kind: stdio
      command: npx
      args: ["@anthropic/filesystem-mcp", "--read-only"]
    mutability_class: read_only
    trust_state: approved
    containment:
      network_policy: isolated
      timeout_ms: 10000
      max_concurrent_calls: 10
    labels:
      team: platform
  - id: pending-browser
    name: Pending Browser
    transport:
      kind: sse
      url: https://example.test/mcp
    mutability_class: mutating
    trust_state: pending
"#;

    #[test]
    fn load_tool_server_config_rejects_conflicting_sources() {
        let error = load_tool_server_config(
            &json!({
                "yaml": VALID_TOOL_SERVERS_YAML,
                "config_path": "policy-config.yaml"
            }),
            false,
        )
        .expect_err("conflicting sources should fail");

        assert!(error.to_string().contains("either 'yaml' or 'config_path'"));
    }

    #[test]
    fn tool_server_json_exposes_expected_fields() {
        let source = load_tool_server_config(&json!({"yaml": VALID_TOOL_SERVERS_YAML}), false)
            .expect("inline config");
        let server = tool_server_json(&source.config.tool_servers[0]);

        assert_eq!(server["id"], "filesystem-mcp");
        assert_eq!(server["trust_state"], "approved");
        assert_eq!(server["containment"]["network_policy"], "isolated");
        assert_eq!(server["labels"]["team"], "platform");
    }

    #[tokio::test]
    async fn execute_filters_by_trust_state_and_mutability() {
        let client =
            crate::api::AsyncApiClient::new("http://127.0.0.1:9", "token").expect("client");
        let ctx = ToolContext {
            client: &client,
            session_id: "session-1",
        };

        let result = execute(
            &ctx,
            &json!({
                "yaml": VALID_TOOL_SERVERS_YAML,
                "trust_state": "approved",
                "mutability_class": "read_only"
            }),
        )
        .await
        .expect("tool servers list");

        let tool_servers = result["tool_servers"]
            .as_array()
            .expect("tool_servers array");
        assert_eq!(tool_servers.len(), 1);
        assert_eq!(tool_servers[0]["id"], "filesystem-mcp");
        assert_eq!(result["summary"]["approved_count"], 1);
    }
}
