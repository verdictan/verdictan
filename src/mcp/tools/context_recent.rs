// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP tool: context_recent

use serde_json::Value;

use super::ToolContext;
use crate::error::CliError;
use crate::gateway::crdt::LocalReadScope;

pub(crate) fn definition() -> Value {
    serde_json::json!({
        "name": "context_recent",
        "description": "List recently shared context entries for the current or explicit scope.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of items to return."
                },
                "cursor": {
                    "type": "string",
                    "description": "Optional pagination cursor from a prior call."
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
            }
        }
    })
}

pub(crate) async fn execute(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let limit = optional_u64_argument(arguments, "limit")?;
    let cursor = optional_string_argument(arguments, "cursor")?;
    let team_id = optional_string_argument(arguments, "team_id")?;
    let repo = optional_string_argument(arguments, "repo")?;
    let branch = optional_string_argument(arguments, "branch")?;

    if cursor.is_none() {
        if let Some(local_response) = try_local_context_recent(
            ctx,
            limit,
            team_id.as_deref(),
            repo.as_deref(),
            branch.as_deref(),
        )
        .await
        {
            return Ok(local_response);
        }
    }

    let path = build_recent_path(
        Some(ctx.session_id),
        team_id.as_deref(),
        repo.as_deref(),
        branch.as_deref(),
        limit,
        cursor.as_deref(),
    );

    tracing::debug!(
        session_id = %ctx.session_id,
        path = %path,
        "loading recent context-fabric entries via MCP"
    );

    let response = ctx.client.get_json_value(&path).await?;
    let items = response
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|document| normalize_document(&document))
        .collect::<Vec<_>>();

    Ok(serde_json::json!({
        "tool_name": "context_recent",
        "status": "ok",
        "scope": scope_metadata(
            Some(ctx.session_id),
            team_id.as_deref(),
            repo.as_deref(),
            branch.as_deref(),
        ),
        "items": items,
        "next_cursor": optional_output_string(&response, "next_cursor"),
        "total_count": items.len(),
    }))
}

async fn try_local_context_recent(
    ctx: &ToolContext<'_>,
    limit: Option<u64>,
    team_id: Option<&str>,
    repo: Option<&str>,
    branch: Option<&str>,
) -> Option<Value> {
    let handle = super::local_context_session_handle(ctx.session_id);
    let driver = handle.crdt_sync_driver()?;
    let resolved_scope = super::resolve_session_scope(ctx.session_id, team_id, repo, branch);
    if resolved_scope.repo.is_none()
        && resolved_scope.branch.is_none()
        && resolved_scope.team_id.is_none()
    {
        return None;
    }

    let scope = LocalReadScope::scoped(
        resolved_scope.repo.as_deref(),
        resolved_scope.branch.as_deref(),
    );
    let limit = limit.unwrap_or(20).min(usize::MAX as u64) as usize;
    let replica = driver.state();
    let mut items = replica.read().await.local_recent(&scope, usize::MAX);
    if let Some(expected_team_id) = resolved_scope.team_id.as_deref() {
        items.retain(|view| {
            view.field_str("owner_team_id")
                .map(|value| value == expected_team_id)
                .unwrap_or(false)
        });
    }
    items.truncate(limit);
    let normalized = items
        .iter()
        .map(|view| normalize_document(&super::local_entry_value(view)))
        .collect::<Vec<_>>();

    Some(serde_json::json!({
        "tool_name": "context_recent",
        "status": "ok",
        "backend": "local_crdt",
        "scope": scope_metadata(
            Some(ctx.session_id),
            resolved_scope.team_id.as_deref(),
            resolved_scope.repo.as_deref(),
            resolved_scope.branch.as_deref(),
        ),
        "items": normalized,
        "next_cursor": Value::Null,
        "total_count": normalized.len(),
        "note": "Served from the local gateway CRDT replica for the current MCP session.",
    }))
}

fn build_recent_path(
    session_id: Option<&str>,
    team_id: Option<&str>,
    repo: Option<&str>,
    branch: Option<&str>,
    limit: Option<u64>,
    cursor: Option<&str>,
) -> String {
    let mut params = Vec::new();
    if let Some(value) = session_id.filter(|value| !value.trim().is_empty()) {
        params.push(format!("session_id={}", urlencoding::encode(value)));
    }
    if let Some(value) = team_id {
        params.push(format!("team_id={}", urlencoding::encode(value)));
    }
    if let Some(value) = repo {
        params.push(format!("repo={}", urlencoding::encode(value)));
    }
    if let Some(value) = branch {
        params.push(format!("branch={}", urlencoding::encode(value)));
    }
    if let Some(value) = limit {
        params.push(format!("limit={value}"));
    }
    if let Some(value) = cursor {
        params.push(format!("cursor={}", urlencoding::encode(value)));
    }

    if params.is_empty() {
        return "/v1/context/recent".to_string();
    }

    let query = params.join("&");
    format!("/v1/context/recent?{query}")
}

fn normalize_document(document: &Value) -> Value {
    serde_json::json!({
        "id": string_field(document, "id"),
        "history_session_id": string_field(document, "history_session_id"),
        "source_kind": string_field(document, "source_kind"),
        "content": string_field(document, "content"),
        "token_estimate": document.get("token_estimate").and_then(Value::as_i64).unwrap_or(0),
        "source_user_id": optional_output_string(document, "source_user_id"),
        "source_user_display_name": optional_output_string(document, "source_user_display_name"),
        "owner_team_id": optional_output_string(document, "owner_team_id"),
        "git_repo": optional_output_string(document, "git_repo"),
        "git_branch": optional_output_string(document, "git_branch"),
        "git_commit": optional_output_string(document, "git_commit"),
        "tags": normalize_string_array(document.get("tags")),
        "resource_name": optional_output_string(document, "resource_name"),
        "rank_score": document.get("rank_score").and_then(Value::as_f64),
        "citation_required": document
            .get("citation_required")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "created_at": string_field(document, "created_at"),
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
            "session_registration_or_org_fallback",
            Some(
                "The current API read endpoints do not echo whether session scope resolved or fell back to org scope.",
            ),
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

fn optional_string_argument(arguments: &Value, key: &str) -> Result<Option<String>, CliError> {
    let Some(value) = arguments.get(key) else {
        return Ok(None);
    };
    let text = value
        .as_str()
        .ok_or_else(|| CliError::user(format!("context_recent '{key}' must be a string")))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed.to_string()))
}

fn optional_u64_argument(arguments: &Value, key: &str) -> Result<Option<u64>, CliError> {
    let Some(value) = arguments.get(key) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| CliError::user(format!("context_recent '{key}' must be a positive integer")))
}

fn normalize_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
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
