// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP resource for branch-scoped context.

use serde_json::Value;

use crate::api::AsyncApiClient;
use crate::error::CliError;

const RESOURCE_PREFIX: &str = "context://branch/";

pub(crate) fn descriptor() -> Value {
    serde_json::json!({
        "uri": "context://branch/{name}",
        "name": "Branch Context",
        "description": "Branch-scoped context entries from /v1/context/recent. Optional query params: session_id, team_id, repo, limit, cursor.",
        "mimeType": "application/json"
    })
}

pub(crate) fn matches_uri(uri: &str) -> bool {
    uri.strip_prefix(RESOURCE_PREFIX)
        .map(|suffix| {
            !suffix
                .split('?')
                .next()
                .unwrap_or_default()
                .trim()
                .is_empty()
        })
        .unwrap_or(false)
}

pub(crate) async fn read_resource_for_session(
    client: &AsyncApiClient,
    uri: &str,
    active_session_id: Option<&str>,
) -> Result<Value, CliError> {
    if !matches_uri(uri) {
        return Err(CliError::user(format!(
            "Unknown branch context resource URI: {uri}"
        )));
    }

    let branch = branch_from_uri(uri)?;
    let session_id = query_value(uri, "session_id").or_else(|| {
        active_session_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    });
    let team_id = query_value(uri, "team_id");
    let repo = query_value(uri, "repo");
    let limit = query_value(uri, "limit");
    let cursor = query_value(uri, "cursor");

    let path = build_recent_path(
        session_id.as_deref(),
        team_id.as_deref(),
        repo.as_deref(),
        Some(branch.as_str()),
        limit.as_deref(),
        cursor.as_deref(),
    )?;

    tracing::debug!(uri = %uri, branch = %branch, path = %path, "reading branch context MCP resource");

    let response = client.get_json_value(&path).await?;
    let items = response
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|document| normalize_document(&document))
        .collect::<Vec<_>>();

    wrap_json_contents(
        uri,
        serde_json::json!({
            "resource": "context://branch/{name}",
            "scope": {
                "kind": "branch",
                "session_id": session_id,
                "team_id": team_id,
                "repo": repo,
                "branch": branch,
                "resolved_scope_known": true,
                "resolution": "branch_uri",
            },
            "items": items,
            "next_cursor": optional_output_string(&response, "next_cursor"),
            "total_count": items.len(),
        }),
    )
}

fn branch_from_uri(uri: &str) -> Result<String, CliError> {
    let suffix = uri
        .strip_prefix(RESOURCE_PREFIX)
        .ok_or_else(|| CliError::user(format!("Unknown branch context resource URI: {uri}")))?;
    let encoded = suffix.split('?').next().unwrap_or_default().trim();
    if encoded.is_empty() {
        return Err(CliError::user(
            "context://branch/{name} requires a non-empty branch name",
        ));
    }
    Ok(match urlencoding::decode(encoded) {
        Ok(value) => value.into_owned(),
        Err(_) => encoded.to_string(),
    })
}

fn build_recent_path(
    session_id: Option<&str>,
    team_id: Option<&str>,
    repo: Option<&str>,
    branch: Option<&str>,
    limit: Option<&str>,
    cursor: Option<&str>,
) -> Result<String, CliError> {
    let mut params = Vec::new();
    if let Some(value) = session_id.filter(|value| !value.trim().is_empty()) {
        params.push(format!("session_id={}", urlencoding::encode(value)));
    }
    if let Some(value) = team_id.filter(|value| !value.trim().is_empty()) {
        params.push(format!("team_id={}", urlencoding::encode(value)));
    }
    if let Some(value) = repo.filter(|value| !value.trim().is_empty()) {
        params.push(format!("repo={}", urlencoding::encode(value)));
    }
    if let Some(value) = branch.filter(|value| !value.trim().is_empty()) {
        params.push(format!("branch={}", urlencoding::encode(value)));
    }
    if let Some(value) = limit.filter(|value| !value.trim().is_empty()) {
        value.parse::<u64>().map_err(|_| {
            CliError::user(
                "context://branch/{name} 'limit' query parameter must be a positive integer",
            )
        })?;
        params.push(format!("limit={value}"));
    }
    if let Some(value) = cursor.filter(|value| !value.trim().is_empty()) {
        params.push(format!("cursor={}", urlencoding::encode(value)));
    }

    if params.is_empty() {
        return Ok("/v1/context/recent".to_string());
    }

    Ok(format!("/v1/context/recent?{}", params.join("&")))
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

fn query_value(uri: &str, key: &str) -> Option<String> {
    let (_, query) = uri.split_once('?')?;
    query.split('&').find_map(|pair| {
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        raw_key
            .eq_ignore_ascii_case(key)
            .then(|| decode_query_value(raw_value))
    })
}

fn decode_query_value(raw_value: &str) -> String {
    match urlencoding::decode(raw_value) {
        Ok(value) => value.into_owned(),
        Err(_) => raw_value.to_string(),
    }
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
