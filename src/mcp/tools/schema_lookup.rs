// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP tool: schema_lookup

use serde_json::Value;

use super::ToolContext;
use crate::error::CliError;
use crate::gateway::{crdt::LocalReadScope, ground_truth};

pub(crate) fn definition() -> Value {
    serde_json::json!({
        "name": "schema_lookup",
        "description": "Look up the latest schema-tagged context entry for a table or entity.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "table": {
                    "type": "string",
                    "description": "Table or entity name to look up."
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
            "required": ["table"]
        }
    })
}

pub(crate) async fn execute(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let table = required_string_argument(arguments, "table")?;
    let team_id = optional_string_argument(arguments, "team_id")?;
    let repo = optional_string_argument(arguments, "repo")?;
    let branch = optional_string_argument(arguments, "branch")?;

    if let Some(local_response) = try_local_schema_lookup(
        ctx,
        &table,
        team_id.as_deref(),
        repo.as_deref(),
        branch.as_deref(),
    )
    .await
    {
        return Ok(local_response);
    }

    let path = build_schema_path(
        &table,
        Some(ctx.session_id),
        team_id.as_deref(),
        repo.as_deref(),
        branch.as_deref(),
    );

    tracing::debug!(
        session_id = %ctx.session_id,
        table = %table,
        path = %path,
        "loading schema context via MCP"
    );

    let response = ctx.client.get_json_value(&path).await?;
    let document = response.get("document").cloned().unwrap_or(Value::Null);
    let normalized_document = if document.is_null() {
        Value::Null
    } else {
        normalize_document(&document)
    };

    Ok(serde_json::json!({
        "tool_name": "schema_lookup",
        "status": "ok",
        "table": table,
        "scope": scope_metadata(
            Some(ctx.session_id),
            team_id.as_deref(),
            repo.as_deref(),
            branch.as_deref(),
        ),
        "found": !normalized_document.is_null(),
        "document": normalized_document,
    }))
}

async fn try_local_schema_lookup(
    ctx: &ToolContext<'_>,
    table: &str,
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
    let replica = driver.state();
    let mut matches = replica.read().await.local_schema_lookup(table, &scope);
    if let Some(expected_team_id) = resolved_scope.team_id.as_deref() {
        matches.retain(|view| {
            view.field_str("owner_team_id")
                .map(|value| value == expected_team_id)
                .unwrap_or(false)
        });
    }
    matches.sort_by(|left, right| {
        right
            .last_updated
            .cmp(&left.last_updated)
            .then_with(|| left.entry_id.cmp(&right.entry_id))
    });

    let document = matches
        .first()
        .map(|view| normalize_document(&super::local_entry_value(view)));
    Some(serde_json::json!({
        "tool_name": "schema_lookup",
        "status": "ok",
        "backend": "local_crdt",
        "table": table,
        "scope": scope_metadata(
            Some(ctx.session_id),
            resolved_scope.team_id.as_deref(),
            resolved_scope.repo.as_deref(),
            resolved_scope.branch.as_deref(),
        ),
        "found": document.is_some(),
        "document": document.unwrap_or(Value::Null),
        "note": "Served from the local gateway CRDT replica for the current MCP session.",
    }))
}

fn build_schema_path(
    table: &str,
    session_id: Option<&str>,
    team_id: Option<&str>,
    repo: Option<&str>,
    branch: Option<&str>,
) -> String {
    let mut params = Vec::new();
    if let Some(value) = session_id.filter(|value| !value.trim().is_empty()) {
        params.push(("session_id", value));
    }
    if let Some(value) = team_id {
        params.push(("team_id", value));
    }
    if let Some(value) = repo {
        params.push(("repo", value));
    }
    if let Some(value) = branch {
        params.push(("branch", value));
    }

    let base = format!("/v1/context/schema/{}", urlencoding::encode(table));
    if params.is_empty() {
        return base;
    }

    let query = params
        .into_iter()
        .map(|(key, value)| format!("{key}={}", urlencoding::encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{base}?{query}")
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
        "confidence_tier": optional_output_string(document, "confidence_tier"),
        "verification_status": optional_output_string(document, "verification_status"),
        "confidence_score": document.get("confidence_score").and_then(Value::as_f64),
        "authority_rank": document.get("authority_rank").and_then(Value::as_i64),
        "source_type": optional_output_string(document, "source_type"),
        "source_ref": document.get("source_ref").cloned().unwrap_or(Value::Null),
        "verification_hash": optional_output_string(document, "verification_hash"),
        "verified_at": optional_output_string(document, "verified_at"),
        "verified_by": optional_output_string(document, "verified_by"),
        "content_addressable_ref": optional_output_string(document, "content_addressable_ref"),
        "citation_required": document
            .get("citation_required")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "created_at": string_field(document, "created_at"),
        "provenance": ground_truth::normalize_document_provenance(document),
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

fn required_string_argument(arguments: &Value, key: &str) -> Result<String, CliError> {
    optional_string_argument(arguments, key)?
        .ok_or_else(|| CliError::user(format!("schema_lookup requires '{key}' parameter")))
}

fn optional_string_argument(arguments: &Value, key: &str) -> Result<Option<String>, CliError> {
    let Some(value) = arguments.get(key) else {
        return Ok(None);
    };
    let text = value
        .as_str()
        .ok_or_else(|| CliError::user(format!("schema_lookup '{key}' must be a string")))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed.to_string()))
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
