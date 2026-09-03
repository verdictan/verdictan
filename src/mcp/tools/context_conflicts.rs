// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP tool: context_conflicts

use serde_json::Value;

use super::ToolContext;
use crate::error::CliError;

const DEFAULT_CONFLICT_STATUS: &str = "open";
const ALLOWED_RESOLUTIONS: &[&str] = &["keep_a", "keep_b", "keep_both", "merge"];

pub(crate) fn definition() -> Value {
    serde_json::json!({
        "name": "context_conflicts",
        "description": "List or resolve unresolved context-fabric conflicts for the current scope.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Use 'list' (default) or 'resolve'.",
                    "enum": ["list", "resolve"]
                },
                "conflict_id": {
                    "type": "string",
                    "description": "Conflict identifier to resolve."
                },
                "resolution": {
                    "type": "string",
                    "description": "Resolution to apply: 'keep_a', 'keep_b', 'keep_both', or 'merge'.",
                    "enum": ["keep_a", "keep_b", "keep_both", "merge"]
                },
                "notes": {
                    "type": "string",
                    "description": "Optional operator note for the resolution."
                },
                "team_id": {
                    "type": "string",
                    "description": "Optional explicit team scope override for list actions."
                },
                "repo": {
                    "type": "string",
                    "description": "Optional explicit repository override for list actions."
                },
                "branch": {
                    "type": "string",
                    "description": "Optional explicit branch override for list actions."
                },
                "status": {
                    "type": "string",
                    "description": "Optional status filter for list actions. Defaults to open."
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of conflicts to return."
                }
            }
        }
    })
}

pub(crate) async fn execute(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    match optional_string_argument(arguments, "action")?
        .unwrap_or_else(|| "list".to_string())
        .as_str()
    {
        "resolve" => resolve_conflict(ctx, arguments).await,
        "list" => list_conflicts(ctx, arguments).await,
        other => Err(CliError::user(format!(
            "context_conflicts action must be 'list' or 'resolve', got '{other}'"
        ))),
    }
}

async fn list_conflicts(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let team_id = optional_string_argument(arguments, "team_id")?;
    let repo = optional_string_argument(arguments, "repo")?;
    let branch = optional_string_argument(arguments, "branch")?;
    let status = optional_string_argument(arguments, "status")?
        .unwrap_or_else(|| DEFAULT_CONFLICT_STATUS.to_string());
    let limit = optional_i64_argument(arguments, "limit")?;

    let mut params = vec![format!(
        "session_id={}",
        urlencoding::encode(ctx.session_id)
    )];
    if let Some(value) = team_id.clone() {
        params.push(format!("team_id={}", urlencoding::encode(&value)));
    }
    if let Some(value) = repo.clone() {
        params.push(format!("repo={}", urlencoding::encode(&value)));
    }
    if let Some(value) = branch.clone() {
        params.push(format!("branch={}", urlencoding::encode(&value)));
    }
    params.push(format!("status={}", urlencoding::encode(&status)));
    if let Some(value) = limit {
        params.push(format!("limit={value}"));
    }
    let path = format!("/v1/context/conflicts?{}", params.join("&"));
    let response = ctx.client.get_json_value(&path).await?;

    Ok(serde_json::json!({
        "tool_name": "context_conflicts",
        "action": "list",
        "status": "ok",
        "scope": scope_metadata(
            Some(ctx.session_id),
            team_id.as_deref(),
            repo.as_deref(),
            branch.as_deref(),
        ),
        "items": response
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|value| normalize_conflict(&value))
            .collect::<Vec<_>>(),
    }))
}

async fn resolve_conflict(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let conflict_id = required_string_argument(arguments, "conflict_id")?;
    let resolution = normalize_resolution(&required_string_argument(arguments, "resolution")?)?;
    let notes = optional_string_argument(arguments, "notes")?;

    let response = ctx
        .client
        .post_json_value(
            "/v1/context/conflicts/resolve",
            &serde_json::json!({
                "conflict_id": conflict_id,
                "resolution": resolution,
                "notes": notes,
            }),
        )
        .await?;

    Ok(serde_json::json!({
        "tool_name": "context_conflicts",
        "action": "resolve",
        "status": "ok",
        "conflict": normalize_conflict(response.get("conflict").unwrap_or(&Value::Null)),
    }))
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
        "details": value.get("details").cloned().unwrap_or(Value::Null),
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
            Some("The conflict list will use the registered session scope when available."),
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
        .ok_or_else(|| CliError::user(format!("context_conflicts requires '{key}' parameter")))
}

fn optional_string_argument(arguments: &Value, key: &str) -> Result<Option<String>, CliError> {
    let Some(value) = arguments.get(key) else {
        return Ok(None);
    };
    let text = value
        .as_str()
        .ok_or_else(|| CliError::user(format!("context_conflicts '{key}' must be a string")))?;
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
        .ok_or_else(|| CliError::user(format!("context_conflicts '{key}' must be an integer")))
}

fn normalize_resolution(value: &str) -> Result<String, CliError> {
    let trimmed = value.trim();
    if ALLOWED_RESOLUTIONS.contains(&trimmed) {
        return Ok(trimmed.to_string());
    }
    Err(CliError::user(format!(
        "context_conflicts 'resolution' must be one of: {}",
        ALLOWED_RESOLUTIONS.join(", ")
    )))
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
