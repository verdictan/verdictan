// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP tool: tool_server_validate

use serde_json::{json, Value};

use super::tool_servers_list::{load_tool_server_config, tool_server_json};
use super::ToolContext;
use crate::error::CliError;
use crate::gateway::declarative_config::validate_config;

pub(crate) async fn execute(_ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let source = match load_tool_server_config(arguments, true) {
        Ok(source) => source,
        Err(error) => {
            return Ok(validation_failure(
                "config_load",
                None,
                vec![error.to_string()],
            ))
        }
    };

    let diagnostics: Vec<String> = validate_config(&source.config)
        .into_iter()
        .filter(|diagnostic| is_tool_server_diagnostic(diagnostic))
        .collect();
    let tool_servers = source
        .config
        .tool_servers
        .iter()
        .map(tool_server_json)
        .collect::<Vec<_>>();

    if diagnostics.is_empty() {
        return Ok(json!({
            "ok": true,
            "source": {
                "kind": source.kind,
                "config_path": source.path.as_ref().map(|path| path.display().to_string()),
            },
            "summary": {
                "tool_server_count": tool_servers.len(),
                "diagnostic_count": 0,
            },
            "tool_servers": tool_servers,
            "diagnostics": [],
        }));
    }

    Ok(validation_failure(
        source.kind,
        source.path.as_ref(),
        diagnostics,
    ))
}

fn validation_failure(
    source_kind: &str,
    config_path: Option<&std::path::PathBuf>,
    diagnostics: Vec<String>,
) -> Value {
    let details = diagnostics
        .iter()
        .map(|diagnostic| {
            let (rule_id, remediation) = classify_tool_server_diagnostic(diagnostic);
            json!({
                "rule_id": rule_id,
                "severity": "error",
                "message": diagnostic,
                "remediation": remediation,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "ok": false,
        "source": {
            "kind": source_kind,
            "config_path": config_path.map(|path| path.display().to_string()),
        },
        "summary": {
            "diagnostic_count": details.len(),
        },
        "diagnostics": details,
    })
}

fn is_tool_server_diagnostic(message: &str) -> bool {
    message.contains("tool_server")
        || message.contains("tool servers")
        || message.contains("tool_servers")
        || message.contains("mcp.tool_servers")
}

fn classify_tool_server_diagnostic(message: &str) -> (&'static str, &'static str) {
    if message.contains("top-level 'tool_servers' block")
        || message.contains("matching tool_servers[] entry")
    {
        return (
            "tool_servers.boundary_conflation",
            "Move durable tool server declarations into the top-level 'tool_servers' array and keep provider bridge targets under providers.targets[].mcp.",
        );
    }
    if message.contains("duplicated") {
        return (
            "tool_servers.duplicate_id",
            "Give each declared tool server a unique 'id' so approvals, telemetry, and policy references stay deterministic.",
        );
    }
    if message.contains("transport.kind") {
        return (
            "tool_servers.transport_kind",
            "Use one of the supported transport kinds: stdio, sse, or streamable_http.",
        );
    }
    if message.contains("transport.command is required")
        || message.contains("transport.url is required")
    {
        return (
            "tool_servers.transport_missing_endpoint",
            "Set transport.command for stdio servers or transport.url for remote servers so the gateway has one concrete execution target.",
        );
    }
    if message.contains("mutability_class") {
        return (
            "tool_servers.mutability_class",
            "Set mutability_class to read_only, mutating, or unknown so governance can classify tool-side effects correctly.",
        );
    }
    if message.contains("trust_state") {
        return (
            "tool_servers.trust_state",
            "Set trust_state to pending or approved so session policy can fail closed for unapproved tool servers.",
        );
    }
    if message.contains("containment.network_policy") {
        return (
            "tool_servers.containment_network_policy",
            "Use containment.network_policy values unrestricted, egress_restricted, or isolated.",
        );
    }
    if message.contains("containment.timeout_ms") {
        return (
            "tool_servers.containment_timeout",
            "Choose a containment.timeout_ms between 100 and 300000 milliseconds.",
        );
    }
    if message.contains("containment.max_concurrent_calls") {
        return (
            "tool_servers.containment_concurrency",
            "Choose a containment.max_concurrent_calls value between 1 and 100.",
        );
    }

    (
        "tool_servers.validation",
        "Fix the reported tool-server configuration error and rerun validation before publishing the MCP server.",
    )
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

    const INVALID_TOOL_SERVERS_YAML: &str = r#"
pack:
  name: conflation-attempt
  version: "0.0.1"
providers:
  targets:
    - id: chrome-devtools-mcp
      provider: openai
      model: gpt-5.4-mini
      base_url: https://api.openai.com/v1
      secret_key_ref:
        store: OPENAI_API_KEY
      mcp:
        endpoint: http://localhost:3000
        transport: sse
tool_servers:
  - id: chrome-devtools-mcp
    name: Chrome DevTools
    transport:
      kind: sse
      url: http://localhost:3000
    mutability_class: mutating
    trust_state: approved
"#;

    #[test]
    fn classify_tool_server_diagnostic_detects_boundary_issues() {
        let (rule_id, remediation) = classify_tool_server_diagnostic(
            "tool server declarations belong in the top-level 'tool_servers' block",
        );

        assert_eq!(rule_id, "tool_servers.boundary_conflation");
        assert!(remediation.contains("top-level 'tool_servers'"));
    }

    #[tokio::test]
    async fn execute_reports_valid_tool_servers_cleanly() {
        let client =
            crate::api::AsyncApiClient::new("http://127.0.0.1:9", "token").expect("client");
        let ctx = ToolContext {
            client: &client,
            session_id: "session-1",
        };

        let result = execute(&ctx, &json!({"yaml": VALID_TOOL_SERVERS_YAML}))
            .await
            .expect("validation result");

        assert_eq!(result["ok"], true);
        assert_eq!(result["summary"]["tool_server_count"], 1);
    }

    #[tokio::test]
    async fn execute_surfaces_structured_validation_failures() {
        let client =
            crate::api::AsyncApiClient::new("http://127.0.0.1:9", "token").expect("client");
        let ctx = ToolContext {
            client: &client,
            session_id: "session-1",
        };

        let result = execute(&ctx, &json!({"yaml": INVALID_TOOL_SERVERS_YAML}))
            .await
            .expect("validation result");

        assert_eq!(result["ok"], false);
        assert!(result["diagnostics"][0]["rule_id"]
            .as_str()
            .expect("rule id")
            .starts_with("tool_servers."));
    }
}
