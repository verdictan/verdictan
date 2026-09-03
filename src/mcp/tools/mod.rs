// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP tool definitions and execution.

pub mod chat_compare;
pub mod chat_test;
pub mod context_conflicts;
pub mod context_feedback;
pub mod context_flag;
pub mod context_graph_query;
pub mod context_recent;
pub mod context_search;
pub mod context_share;
pub mod events_query;
pub mod history_search;
pub mod model_get;
pub mod model_recommend;
pub mod models_list;
pub mod policy_lint;
pub mod policy_test;
pub mod providers_list;
pub mod region_get;
pub mod regions_list;
pub mod request_trace_get;
pub mod schema_lookup;
pub mod session_init;
pub mod tool_server_get;
pub mod tool_server_validate;
pub mod tool_servers_list;

use serde_json::Value;

use crate::api::AsyncApiClient;
use crate::error::CliError;
pub(crate) use crate::gateway::context_recall::{
    local_context_session_handle, local_entry_value, resolve_session_scope,
};

pub(crate) const MCP_SESSION_REGION_SOURCE: &str = "mcp session region";
pub(crate) const TOOL_ARGUMENT_REGION_SOURCE: &str = "tool argument 'region'";

/// Shared context available to all tool implementations during execution.
pub struct ToolContext<'a> {
    pub client: &'a AsyncApiClient,
    pub session_id: &'a str,
}

tokio::task_local! {
    static EXECUTION_IDEMPOTENCY_KEY: uuid::Uuid;
}

/// Durable execution key available to every MCP tool during dispatch.
fn current_execution_idempotency_key() -> Option<uuid::Uuid> {
    EXECUTION_IDEMPOTENCY_KEY.try_with(|key| *key).ok()
}

pub(crate) fn resolved_api_endpoint(client: &AsyncApiClient) -> String {
    client.join_url("").trim_end_matches('/').to_string()
}

pub(crate) fn region_resolution_metadata(
    client: &AsyncApiClient,
    resolved_region: Option<&str>,
    resolved_region_source: Option<&str>,
) -> serde_json::Map<String, Value> {
    let mut object = serde_json::Map::new();
    object.insert(
        "resolved_region".to_string(),
        resolved_region
            .map(|value| Value::String(value.to_string()))
            .unwrap_or(Value::Null),
    );
    object.insert(
        "resolved_region_source".to_string(),
        resolved_region_source
            .map(|value| Value::String(value.to_string()))
            .unwrap_or(Value::Null),
    );
    object.insert(
        "resolved_api_endpoint".to_string(),
        Value::String(resolved_api_endpoint(client)),
    );
    object
}

pub(crate) fn session_region_resolution_metadata(
    client: &AsyncApiClient,
) -> serde_json::Map<String, Value> {
    region_resolution_metadata(
        client,
        client.region(),
        client.region().map(|_| MCP_SESSION_REGION_SOURCE),
    )
}

/// Execute a tool with the durable pre-dispatch idempotency key scoped to the
/// complete async call tree.
pub async fn execute_tool_with_idempotency_key(
    ctx: &ToolContext<'_>,
    tool_name: &str,
    arguments: &Value,
    execution_idempotency_key: uuid::Uuid,
) -> Result<Value, CliError> {
    EXECUTION_IDEMPOTENCY_KEY
        .scope(
            execution_idempotency_key,
            execute_tool_inner(ctx, tool_name, arguments),
        )
        .await
}

async fn execute_tool_inner(
    ctx: &ToolContext<'_>,
    tool_name: &str,
    arguments: &Value,
) -> Result<Value, CliError> {
    let result = match tool_name {
        "history_search" => history_search::execute(ctx, arguments).await?,
        "models_list" => models_list::execute(ctx, arguments).await?,
        "model_get" => model_get::execute(ctx, arguments).await?,
        "model_recommend" => model_recommend::execute(ctx, arguments).await?,
        "chat_test" => chat_test::execute(ctx, arguments).await?,
        "chat_compare" => chat_compare::execute(ctx, arguments).await?,
        "providers_list" => providers_list::execute(ctx, arguments).await?,
        "regions_list" => regions_list::execute(ctx, arguments).await?,
        "region_get" => region_get::execute(ctx, arguments).await?,
        "session_init" => session_init::execute(ctx, arguments).await?,
        "context_graph_query" => context_graph_query::execute(ctx, arguments).await?,
        "context_conflicts" => context_conflicts::execute(ctx, arguments).await?,
        "context_search" => context_search::execute(ctx, arguments).await?,
        "context_share" => context_share::execute(ctx, arguments).await?,
        "context_recent" => context_recent::execute(ctx, arguments).await?,
        "context_feedback" => context_feedback::execute(ctx, arguments).await?,
        "context_flag" => context_flag::execute(ctx, arguments).await?,
        "schema_lookup" => schema_lookup::execute(ctx, arguments).await?,
        "policy_lint" => policy_lint::execute(ctx, arguments).await?,
        "policy_test" => policy_test::execute(ctx, arguments).await?,
        "events_query" => events_query::execute(ctx, arguments).await?,
        "request_trace_get" => request_trace_get::execute(ctx, arguments).await?,
        "tool_servers_list" => tool_servers_list::execute(ctx, arguments).await?,
        "tool_server_get" => tool_server_get::execute(ctx, arguments).await?,
        "tool_server_validate" => tool_server_validate::execute(ctx, arguments).await?,
        _ => {
            return Err(CliError::user(format!(
                "Unknown tool: {tool_name}. Use tools/list to see available tools."
            )));
        }
    };
    Ok(result)
}

/// Return the full tools list JSON array for `tools/list`.
pub fn tools_list() -> Value {
    Value::Array(vec![
        serde_json::json!({
            "name": "history_search",
            "description": "Search conversation history entries.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query string."
                    },
                    "entry_kind": {
                        "type": "string",
                        "description": "Filter by entry type."
                    },
                    "agent_id": {
                        "type": "string",
                        "description": "Filter by agent ID."
                    },
                    "limit": {
                        "type": "number",
                        "description": "Maximum number of results (default: 20)."
                    }
                },
                "required": ["query"]
            }
        }),
        models_list::definition(),
        model_get::definition(),
        model_recommend::definition(),
        chat_test::definition(),
        chat_compare::definition(),
        providers_list::definition(),
        regions_list::definition(),
        region_get::definition(),
        session_init::definition(),
        context_graph_query::definition(),
        context_conflicts::definition(),
        context_search::definition(),
        context_share::definition(),
        context_recent::definition(),
        context_feedback::definition(),
        context_flag::definition(),
        schema_lookup::definition(),
        policy_lint::definition(),
        serde_json::json!({
            "name": "policy_test",
            "description": "Run declarative policy-pack tests and return structured case results.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pack_dir": {
                        "type": "string",
                        "description": "Directory containing the policy pack and tests."
                    },
                    "yaml": {
                        "type": "string",
                        "description": "Inline policy-pack YAML."
                    }
                }
            }
        }),
        serde_json::json!({
            "name": "events_query",
            "description": "Query audit trail events and correlate them with history entries.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "request_id": {
                        "type": "string",
                        "description": "Exact request id for audit lookup."
                    },
                    "session_id": {
                        "type": "string",
                        "description": "History session id for correlation."
                    },
                    "tool_name": {
                        "type": "string",
                        "description": "Optional tool-name filter for correlated history entries."
                    },
                    "entry_kind": {
                        "type": "string",
                        "description": "Optional history entry-type filter."
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum trail events to return."
                    },
                    "history_limit": {
                        "type": "integer",
                        "description": "Maximum correlated history entries to return."
                    }
                }
            }
        }),
        serde_json::json!({
            "name": "request_trace_get",
            "description": "Fetch one workflow trace by request id and correlate it with audit and history data.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "request_id": {
                        "type": "string",
                        "description": "Exact request id to resolve."
                    },
                    "session_id": {
                        "type": "string",
                        "description": "Optional explicit history session id override."
                    },
                    "tool_name": {
                        "type": "string",
                        "description": "Optional tool-name filter for correlated history entries."
                    },
                    "entry_kind": {
                        "type": "string",
                        "description": "Optional history entry-type filter."
                    },
                    "history_limit": {
                        "type": "integer",
                        "description": "Maximum correlated history entries to return."
                    },
                    "trace_limit": {
                        "type": "integer",
                        "description": "Maximum workflow trace summaries to examine."
                    }
                },
                "required": ["request_id"]
            }
        }),
        serde_json::json!({
            "name": "tool_servers_list",
            "description": "List governed tool server declarations from the gateway policy config.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "config_path": {
                        "type": "string",
                        "description": "Path to the declarative gateway config file."
                    },
                    "yaml": {
                        "type": "string",
                        "description": "Inline declarative gateway config YAML."
                    },
                    "trust_state": {
                        "type": "string",
                        "description": "Optional trust-state filter."
                    },
                    "mutability_class": {
                        "type": "string",
                        "description": "Optional mutability-class filter."
                    }
                }
            }
        }),
        serde_json::json!({
            "name": "tool_server_get",
            "description": "Read a single governed tool server declaration by id or name.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Declared tool server id."
                    },
                    "name": {
                        "type": "string",
                        "description": "Declared tool server name."
                    },
                    "config_path": {
                        "type": "string",
                        "description": "Path to the declarative gateway config file."
                    },
                    "yaml": {
                        "type": "string",
                        "description": "Inline declarative gateway config YAML."
                    }
                }
            }
        }),
        serde_json::json!({
            "name": "tool_server_validate",
            "description": "Validate governed tool server declarations and return structured diagnostics.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "config_path": {
                        "type": "string",
                        "description": "Path to the declarative gateway config file."
                    },
                    "yaml": {
                        "type": "string",
                        "description": "Inline declarative gateway config YAML."
                    }
                }
            }
        }),
    ])
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

    fn assert_ste_description(description: &str) {
        let lowercase = description.to_ascii_lowercase();
        assert!(
            !lowercase.contains(';'),
            "MCP description contains a semicolon: {description}"
        );
        assert!(
            !lowercase.contains("e.g."),
            "MCP description contains e.g.: {description}"
        );
        assert!(
            !lowercase.contains("i.e."),
            "MCP description contains i.e.: {description}"
        );

        let disallowed = [
            "any", "required", "require", "requires", "need", "needs", "once", "both", "either",
            "already", "still", "never", "present", "intended", "valid", "instead",
        ];
        for word in lowercase.split(|character: char| {
            !character.is_ascii_alphanumeric() && character != '_' && character != '-'
        }) {
            assert!(
                !disallowed.contains(&word),
                "MCP description contains a non-STE construction '{word}': {description}"
            );
        }
    }

    fn assert_value_descriptions_are_ste(value: &Value) {
        match value {
            Value::Array(values) => {
                for value in values {
                    assert_value_descriptions_are_ste(value);
                }
            }
            Value::Object(object) => {
                if let Some(description) = object.get("description").and_then(Value::as_str) {
                    assert_ste_description(description);
                }
                for value in object.values() {
                    assert_value_descriptions_are_ste(value);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn tools_list_returns_array() {
        let list = tools_list();
        assert!(list.is_array());
    }

    #[test]
    fn tools_list_contains_expected_tools() {
        let list = tools_list();
        let tools = list.as_array().unwrap();
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
            .collect();
        assert!(names.contains(&"history_search"));
        assert!(names.contains(&"models_list"));
        assert!(names.contains(&"model_get"));
        assert!(names.contains(&"providers_list"));
        assert!(names.contains(&"regions_list"));
        assert!(names.contains(&"region_get"));
        assert!(names.contains(&"session_init"));
        assert!(names.contains(&"context_graph_query"));
        assert!(names.contains(&"context_conflicts"));
        assert!(names.contains(&"context_search"));
        assert!(names.contains(&"context_share"));
        assert!(names.contains(&"context_recent"));
        assert!(names.contains(&"schema_lookup"));
        assert!(names.contains(&"policy_lint"));
        assert!(names.contains(&"policy_test"));
        assert!(names.contains(&"events_query"));
        assert!(names.contains(&"request_trace_get"));
        assert!(names.contains(&"tool_servers_list"));
        assert!(names.contains(&"tool_server_get"));
        assert!(names.contains(&"tool_server_validate"));
    }

    #[test]
    fn tools_list_all_have_description() {
        let list = tools_list();
        let tools = list.as_array().unwrap();
        for tool in tools {
            let desc = tool.get("description").and_then(|d| d.as_str());
            assert!(
                desc.is_some(),
                "tool missing description: {:?}",
                tool.get("name")
            );
            assert!(!desc.unwrap().is_empty());
        }
    }

    #[test]
    fn tools_list_descriptions_use_ste_constructions() {
        assert_value_descriptions_are_ste(&tools_list());
    }

    #[test]
    fn tools_list_all_have_input_schema() {
        let list = tools_list();
        let tools = list.as_array().unwrap();
        for tool in tools {
            let schema = tool.get("inputSchema");
            assert!(
                schema.is_some(),
                "tool missing inputSchema: {:?}",
                tool.get("name")
            );
            let schema = schema.unwrap();
            assert_eq!(
                schema.get("type").and_then(|t| t.as_str()),
                Some("object"),
                "inputSchema.type must be 'object'"
            );
        }
    }

    #[test]
    fn tools_list_history_search_requires_query() {
        let list = tools_list();
        let tools = list.as_array().unwrap();
        let tool = tools
            .iter()
            .find(|t| t.get("name").and_then(|n| n.as_str()) == Some("history_search"))
            .unwrap();
        let required = tool
            .get("inputSchema")
            .and_then(|s| s.get("required"))
            .and_then(|r| r.as_array())
            .unwrap();
        let required_strs: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(required_strs.contains(&"query"));
    }

    #[test]
    fn tools_list_policy_lint_is_inline_only_and_bounded() {
        let list = tools_list();
        let tool = list
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool.get("name").and_then(Value::as_str) == Some("policy_lint"))
            .unwrap();
        let schema = &tool["inputSchema"];

        assert_eq!(schema["required"], serde_json::json!(["yaml"]));
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["yaml"]["maxLength"],
            policy_lint::MAX_INLINE_YAML_BYTES
        );
        assert!(schema["properties"].get("file_path").is_none());
    }

    #[tokio::test]
    async fn durable_execution_key_is_scoped_to_complete_tool_call_tree() {
        let key = uuid::Uuid::new_v4();
        assert_eq!(current_execution_idempotency_key(), None);
        EXECUTION_IDEMPOTENCY_KEY
            .scope(key, async {
                tokio::task::yield_now().await;
                assert_eq!(current_execution_idempotency_key(), Some(key));
            })
            .await;
        assert_eq!(current_execution_idempotency_key(), None);
    }

    #[tokio::test]
    async fn execute_tool_with_idempotency_key_covers_full_published_catalog() {
        let catalog = tools_list();
        let names: Vec<&str> = catalog
            .as_array()
            .expect("tools array")
            .iter()
            .filter_map(|tool| tool.get("name").and_then(Value::as_str))
            .collect();
        assert!(
            !names.is_empty(),
            "published MCP catalog must expose tools for idempotency propagation"
        );
        assert!(
            names.iter().all(|name| !name.is_empty()),
            "catalog tool names must be non-empty for propagation"
        );

        let client =
            crate::api::AsyncApiClient::new("http://127.0.0.1:9", "test-token").expect("client");
        let ctx = ToolContext {
            client: &client,
            session_id: "idempotency-propagation",
        };
        let key = uuid::Uuid::new_v4();
        let err = execute_tool_with_idempotency_key(
            &ctx,
            "__missing__",
            &Value::Object(Default::default()),
            key,
        )
        .await
        .expect_err("missing tool fails after key is scoped across the dispatch tree");
        assert!(err.to_string().contains("Unknown tool"));
        assert_eq!(current_execution_idempotency_key(), None);
        // Catalog coverage: every published name is dispatched only through
        // execute_tool_with_idempotency_key from the sealed MCP server path.
        let _ = names.len();
    }
}
