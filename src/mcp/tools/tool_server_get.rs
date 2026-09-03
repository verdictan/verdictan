// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP tool: tool_server_get

use serde_json::{json, Value};

use super::tool_servers_list::{load_tool_server_config, tool_server_json};
use super::ToolContext;
use crate::error::CliError;

pub(crate) async fn execute(_ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let requested = arguments
        .get("id")
        .or_else(|| arguments.get("name"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::user("tool_server_get requires 'id' or 'name'"))?;

    let source = load_tool_server_config(arguments, false)?;
    let tool_server = source
        .config
        .tool_servers
        .iter()
        .find(|server| server.id == requested || server.name == requested);

    Ok(match tool_server {
        Some(tool_server) => json!({
            "ok": true,
            "source": {
                "kind": source.kind,
                "config_path": source.path.as_ref().map(|path| path.display().to_string()),
            },
            "tool_server": tool_server_json(tool_server),
        }),
        None => json!({
            "ok": false,
            "source": {
                "kind": source.kind,
                "config_path": source.path.as_ref().map(|path| path.display().to_string()),
            },
            "error": {
                "code": "tool_server.not_found",
                "message": format!("no tool server matched '{}'", requested),
                "remediation": "Use tool_servers_list to inspect the declared IDs and names before requesting a single server.",
            }
        }),
    })
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
"#;

    #[tokio::test]
    async fn execute_returns_matching_tool_server_by_id() {
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
                "id": "filesystem-mcp"
            }),
        )
        .await
        .expect("tool server get");

        assert_eq!(result["ok"], true);
        assert_eq!(result["tool_server"]["name"], "Filesystem MCP");
    }

    #[tokio::test]
    async fn execute_returns_structured_not_found_payload() {
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
                "name": "missing"
            }),
        )
        .await
        .expect("tool server get");

        assert_eq!(result["ok"], false);
        assert_eq!(result["error"]["code"], "tool_server.not_found");
    }
}
