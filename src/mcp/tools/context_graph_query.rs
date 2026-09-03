// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP tool: context_graph_query

use serde_json::{Map, Value};

use super::ToolContext;
use crate::error::CliError;
use crate::gateway::ground_truth;

const DEFAULT_GRAPH_DEPTH: i64 = 2;

pub(crate) fn definition() -> Value {
    serde_json::json!({
        "name": "context_graph_query",
        "description": "Traverse the shared context knowledge graph for one entity.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "entity": {
                    "type": "string",
                    "description": "Entity name to query."
                },
                "relationship": {
                    "type": "string",
                    "description": "Optional relationship-type filter."
                },
                "depth": {
                    "type": "integer",
                    "description": "Traversal depth. Defaults to 2."
                },
                "team_id": {
                    "type": "string",
                    "description": "Optional explicit team scope override."
                },
                "repo": {
                    "type": "string",
                    "description": "Optional explicit repository override."
                },
                "branch": {
                    "type": "string",
                    "description": "Optional explicit branch override."
                }
            },
            "required": ["entity"]
        }
    })
}

pub(crate) async fn execute(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let entity = required_string_argument(arguments, "entity")?;
    let relationship = optional_string_argument(arguments, "relationship")?;
    let depth = optional_i64_argument(arguments, "depth")?.unwrap_or(DEFAULT_GRAPH_DEPTH);
    let team_id = optional_string_argument(arguments, "team_id")?;
    let repo = optional_string_argument(arguments, "repo")?;
    let branch = optional_string_argument(arguments, "branch")?;

    let mut body = Map::new();
    body.insert("entity_name".to_string(), Value::String(entity.clone()));
    body.insert(
        "session_id".to_string(),
        Value::String(ctx.session_id.to_string()),
    );
    if let Some(value) = relationship.clone() {
        body.insert("relationship_type".to_string(), Value::String(value));
    }
    body.insert("depth".to_string(), Value::Number(depth.into()));
    if let Some(value) = team_id.clone() {
        body.insert("team_id".to_string(), Value::String(value));
    }
    if let Some(value) = repo.clone() {
        body.insert("repo".to_string(), Value::String(value));
    }
    if let Some(value) = branch.clone() {
        body.insert("branch".to_string(), Value::String(value));
    }

    let response = ctx
        .client
        .post_json_value("/v1/context/graph/query", &Value::Object(body))
        .await?;

    Ok(serde_json::json!({
        "tool_name": "context_graph_query",
        "status": "ok",
        "entity": entity,
        "scope": scope_metadata(
            Some(ctx.session_id),
            team_id.as_deref(),
            repo.as_deref(),
            branch.as_deref(),
        ),
        "nodes": response
            .get("nodes")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|value| normalize_node(&value))
            .collect::<Vec<_>>(),
        "edges": response
            .get("edges")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|value| normalize_edge(&value))
            .collect::<Vec<_>>(),
        "conflicts": response
            .get("conflicts")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|value| normalize_conflict(&value))
            .collect::<Vec<_>>(),
    }))
}

fn normalize_node(value: &Value) -> Value {
    serde_json::json!({
        "id": string_field(value, "id"),
        "team_id": optional_output_string(value, "team_id"),
        "repo": string_field(value, "repo"),
        "branch": string_field(value, "branch"),
        "entity_type": string_field(value, "entity_type"),
        "entity_name": string_field(value, "entity_name"),
        "properties": value.get("properties").cloned().unwrap_or(Value::Object(Map::new())),
        "source_ref": value.get("source_ref").cloned().unwrap_or(Value::Null),
        "source_kind": optional_output_string(value, "source_kind"),
        "source_type": optional_output_string(value, "source_type"),
        "verification_hash": optional_output_string(value, "verification_hash"),
        "verified_by": optional_output_string(value, "verified_by"),
        "content_addressable_ref": optional_output_string(value, "content_addressable_ref"),
        "confidence_score": value.get("confidence_score").cloned().unwrap_or(Value::Null),
        "verification_status": optional_output_string(value, "verification_status"),
        "verified_at": optional_output_string(value, "verified_at"),
        "created_at": string_field(value, "created_at"),
        "updated_at": string_field(value, "updated_at"),
        "provenance": ground_truth::normalize_document_provenance(value),
    })
}

fn normalize_edge(value: &Value) -> Value {
    serde_json::json!({
        "id": string_field(value, "id"),
        "team_id": optional_output_string(value, "team_id"),
        "repo": string_field(value, "repo"),
        "branch": string_field(value, "branch"),
        "source_node_id": string_field(value, "source_node_id"),
        "target_node_id": string_field(value, "target_node_id"),
        "relationship_type": string_field(value, "relationship_type"),
        "properties": value.get("properties").cloned().unwrap_or(Value::Object(Map::new())),
        "source_ref": value.get("source_ref").cloned().unwrap_or(Value::Null),
        "source_kind": optional_output_string(value, "source_kind"),
        "source_type": optional_output_string(value, "source_type"),
        "verification_hash": optional_output_string(value, "verification_hash"),
        "verified_by": optional_output_string(value, "verified_by"),
        "content_addressable_ref": optional_output_string(value, "content_addressable_ref"),
        "confidence_score": value.get("confidence_score").cloned().unwrap_or(Value::Null),
        "verification_status": optional_output_string(value, "verification_status"),
        "verified_at": optional_output_string(value, "verified_at"),
        "created_at": string_field(value, "created_at"),
        "updated_at": string_field(value, "updated_at"),
        "provenance": ground_truth::normalize_document_provenance(value),
    })
}

fn normalize_conflict(value: &Value) -> Value {
    serde_json::json!({
        "conflict_id": string_field(value, "conflict_id"),
        "subject_kind": string_field(value, "subject_kind"),
        "subject_key": string_field(value, "subject_key"),
        "team_id": optional_output_string(value, "team_id"),
        "repo": optional_output_string(value, "repo"),
        "branch": optional_output_string(value, "branch"),
        "source_a_id": string_field(value, "source_a_id"),
        "source_b_id": string_field(value, "source_b_id"),
        "conflict_type": string_field(value, "conflict_type"),
        "resolution_strategy": string_field(value, "resolution_strategy"),
        "suggested_winner": optional_output_string(value, "suggested_winner"),
        "status": string_field(value, "status"),
        "details": value.get("details").cloned().unwrap_or(Value::Object(Map::new())),
        "chosen_resolution": optional_output_string(value, "chosen_resolution"),
        "resolved_by": optional_output_string(value, "resolved_by"),
        "resolved_at": optional_output_string(value, "resolved_at"),
        "created_at": string_field(value, "created_at"),
        "updated_at": string_field(value, "updated_at"),
    })
}

fn scope_metadata(
    session_id: Option<&str>,
    team_id: Option<&str>,
    repo: Option<&str>,
    branch: Option<&str>,
) -> Value {
    let (kind, resolved_scope_known, resolution, note) = if branch.is_some() {
        ("branch", true, "explicit_inputs", None)
    } else if repo.is_some() {
        ("repo", true, "explicit_inputs", None)
    } else if team_id.is_some() {
        ("team", true, "explicit_inputs", None)
    } else if session_id.is_some_and(|value| !value.trim().is_empty()) {
        (
            "session",
            false,
            "session_registration_or_api_resolution",
            Some("The graph query will use the registered session scope when available."),
        )
    } else {
        ("org", true, "default_org_scope", None)
    };

    serde_json::json!({
        "kind": kind,
        "session_id": session_id,
        "team_id": team_id,
        "repo": repo,
        "branch": branch,
        "resolved_scope_known": resolved_scope_known,
        "resolution": resolution,
        "note": note,
    })
}

fn required_string_argument(arguments: &Value, key: &str) -> Result<String, CliError> {
    optional_string_argument(arguments, key)?
        .ok_or_else(|| CliError::user(format!("context_graph_query requires '{key}' parameter")))
}

fn optional_string_argument(arguments: &Value, key: &str) -> Result<Option<String>, CliError> {
    let Some(value) = arguments.get(key) else {
        return Ok(None);
    };
    let text = value
        .as_str()
        .ok_or_else(|| CliError::user(format!("context_graph_query '{key}' must be a string")))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed.to_string()))
}

fn optional_i64_argument(arguments: &Value, key: &str) -> Result<Option<i64>, CliError> {
    let Some(value) = arguments.get(key) else {
        return Ok(None);
    };
    value
        .as_i64()
        .map(Some)
        .ok_or_else(|| CliError::user(format!("context_graph_query '{key}' must be an integer")))
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn optional_output_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}
