// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP resource for schema-tagged context.

use serde_json::Value;

use crate::api::AsyncApiClient;
use crate::error::CliError;

const RESOURCE_PREFIX: &str = "context://schema/";

pub(crate) fn descriptor() -> Value {
    serde_json::json!({
        "uri": "context://schema/{table}",
        "name": "Schema Context",
        "description": "Latest schema-tagged context document for a table or entity. Optional query params: session_id, team_id, repo, branch.",
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
            "Unknown schema context resource URI: {uri}"
        )));
    }

    let table = table_from_uri(uri)?;
    let (session_id, session_id_source) = effective_session_id(uri, active_session_id);
    let team_id = query_value(uri, "team_id");
    let repo = query_value(uri, "repo");
    let branch = query_value(uri, "branch");

    let path = build_schema_path(
        &table,
        session_id.as_deref(),
        team_id.as_deref(),
        repo.as_deref(),
        branch.as_deref(),
    );

    tracing::debug!(uri = %uri, table = %table, path = %path, "reading schema context MCP resource");

    let response = client.get_json_value(&path).await?;
    let document = response.get("document").cloned().unwrap_or(Value::Null);
    let normalized_document = if document.is_null() {
        Value::Null
    } else {
        normalize_document(&document)
    };

    wrap_json_contents(
        uri,
        serde_json::json!({
            "resource": "context://schema/{table}",
            "table": table,
            "scope": scope_metadata(
                session_id.as_deref(),
                team_id.as_deref(),
                repo.as_deref(),
                branch.as_deref(),
                session_id_source,
            ),
            "found": !normalized_document.is_null(),
            "document": normalized_document,
        }),
    )
}

fn table_from_uri(uri: &str) -> Result<String, CliError> {
    let suffix = uri
        .strip_prefix(RESOURCE_PREFIX)
        .ok_or_else(|| CliError::user(format!("Unknown schema context resource URI: {uri}")))?;
    let encoded = suffix.split('?').next().unwrap_or_default().trim();
    if encoded.is_empty() {
        return Err(CliError::user(
            "context://schema/{table} requires a non-empty table name",
        ));
    }
    Ok(match urlencoding::decode(encoded) {
        Ok(value) => value.into_owned(),
        Err(_) => encoded.to_string(),
    })
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

    let base = format!("/v1/context/schema/{}", urlencoding::encode(table));
    if params.is_empty() {
        return base;
    }
    format!("{base}?{}", params.join("&"))
}

fn scope_metadata(
    session_id: Option<&str>,
    team_id: Option<&str>,
    repo: Option<&str>,
    branch: Option<&str>,
    session_id_source: SessionIdSource,
) -> Value {
    let (kind, resolved_scope_known, resolution, note) = if branch.is_some() {
        ("branch", true, "explicit_query_params", None)
    } else if repo.is_some() {
        ("repo", true, "explicit_query_params", None)
    } else if team_id.is_some() {
        ("team", true, "explicit_query_params", None)
    } else if session_id.is_some_and(|value| !value.trim().is_empty()) {
        match session_id_source {
            SessionIdSource::Uri => ("session", false, "session_query_param_or_org_fallback", None),
            SessionIdSource::Inherited => (
                "session",
                false,
                "active_mcp_session_or_org_fallback",
                Some(
                    "The active MCP session ID was inherited automatically, but the backing context endpoint can still fall back to org scope when no registered session scope exists.",
                ),
            ),
            SessionIdSource::None => ("org", true, "default_org_scope", None),
        }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionIdSource {
    None,
    Uri,
    Inherited,
}

fn effective_session_id(
    uri: &str,
    active_session_id: Option<&str>,
) -> (Option<String>, SessionIdSource) {
    if let Some(session_id) = query_value(uri, "session_id")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return (Some(session_id), SessionIdSource::Uri);
    }

    if let Some(session_id) = active_session_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
    {
        return (Some(session_id), SessionIdSource::Inherited);
    }

    (None, SessionIdSource::None)
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
