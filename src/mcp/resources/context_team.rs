// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP resource for the categorized team-context knowledge base.

use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::api::AsyncApiClient;
use crate::error::CliError;

const RESOURCE_URI: &str = "context://team";
const CATEGORY_SCHEMA: &str = "Schema Knowledge";
const CATEGORY_QUERY: &str = "Query Patterns";
const CATEGORY_ARCHITECTURE: &str = "Architecture";
const CATEGORY_DEBUG: &str = "Debug Notes";
const CATEGORY_CONVENTIONS: &str = "Conventions";
const CATEGORY_TROUBLESHOOTING: &str = "Troubleshooting";
const CATEGORY_ORDER: [&str; 6] = [
    CATEGORY_SCHEMA,
    CATEGORY_QUERY,
    CATEGORY_ARCHITECTURE,
    CATEGORY_DEBUG,
    CATEGORY_CONVENTIONS,
    CATEGORY_TROUBLESHOOTING,
];

pub(crate) fn descriptor() -> Value {
    serde_json::json!({
        "uri": RESOURCE_URI,
        "name": "Team Context",
        "description": "Categorized team knowledge base backed by /v1/context/recent. Optional query params: session_id, team_id, repo, branch, category, limit, cursor.",
        "mimeType": "application/json"
    })
}

pub(crate) fn matches_uri(uri: &str) -> bool {
    uri == RESOURCE_URI
        || uri
            .strip_prefix(RESOURCE_URI)
            .is_some_and(|suffix| suffix.starts_with('?'))
}

pub(crate) async fn read_resource_for_session(
    client: &AsyncApiClient,
    uri: &str,
    active_session_id: Option<&str>,
) -> Result<Value, CliError> {
    if !matches_uri(uri) {
        return Err(CliError::user(format!(
            "Unknown team context resource URI: {uri}"
        )));
    }

    let (session_id, session_id_source) = effective_session_id(uri, active_session_id);
    let team_id = query_value(uri, "team_id");
    let repo = query_value(uri, "repo");
    let branch = query_value(uri, "branch");
    let category = query_value(uri, "category");
    let limit = query_value(uri, "limit");
    let cursor = query_value(uri, "cursor");

    let path = build_recent_path(
        session_id.as_deref(),
        team_id.as_deref(),
        repo.as_deref(),
        branch.as_deref(),
        limit.as_deref(),
        cursor.as_deref(),
    )?;

    tracing::debug!(uri = %uri, path = %path, "reading team context MCP resource");

    let response = client.get_json_value(&path).await?;
    let items = response
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|document| normalize_document(&document))
        .filter(|document| category_matches(document, category.as_deref()))
        .collect::<Vec<_>>();
    let categories = group_documents(&items);

    wrap_json_contents(
        uri,
        serde_json::json!({
            "resource": RESOURCE_URI,
            "view": "team_knowledge_base",
            "scope": scope_metadata(
                session_id.as_deref(),
                team_id.as_deref(),
                repo.as_deref(),
                branch.as_deref(),
                session_id_source,
            ),
            "filters": {
                "category": category,
                "limit": limit,
                "cursor": cursor,
            },
            "categories": categories,
            "items": items,
            "next_cursor": optional_output_string(&response, "next_cursor"),
            "total_count": items.len(),
        }),
    )
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
            CliError::user("context://team 'limit' query parameter must be a positive integer")
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
    let created_at = string_field(document, "created_at");
    let category = classify_document(document);
    serde_json::json!({
        "id": string_field(document, "id"),
        "title": derive_title(document),
        "category": category,
        "history_session_id": string_field(document, "history_session_id"),
        "source_kind": string_field(document, "source_kind"),
        "content": string_field(document, "content"),
        "token_estimate": document.get("token_estimate").and_then(Value::as_i64).unwrap_or(0),
        "source_user_id": optional_output_string(document, "source_user_id"),
        "source_user_display_name": optional_output_string(document, "source_user_display_name"),
        "author": optional_output_string(document, "source_user_display_name")
            .or_else(|| optional_output_string(document, "source_user_id")),
        "owner_team_id": optional_output_string(document, "owner_team_id"),
        "git_repo": optional_output_string(document, "git_repo"),
        "git_branch": optional_output_string(document, "git_branch"),
        "git_commit": optional_output_string(document, "git_commit"),
        "tags": normalize_string_array(document.get("tags")),
        "resource_name": optional_output_string(document, "resource_name"),
        "rank_score": document.get("rank_score").and_then(Value::as_f64),
        "confidence_tier": optional_output_string(document, "confidence_tier"),
        "verification_status": optional_output_string(document, "verification_status"),
        "citation_required": document
            .get("citation_required")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "created_at": created_at,
        "age_seconds": age_seconds(document),
    })
}

fn group_documents(items: &[Value]) -> Vec<Value> {
    let mut grouped = BTreeMap::<&str, Vec<Value>>::new();
    for category in CATEGORY_ORDER {
        grouped.insert(category, Vec::new());
    }

    for document in items {
        let category = document
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or(CATEGORY_ARCHITECTURE);
        grouped.entry(category).or_default().push(document.clone());
    }

    CATEGORY_ORDER
        .iter()
        .map(|category| {
            let entries = grouped.remove(category).unwrap_or_default();
            serde_json::json!({
                "name": category,
                "count": entries.len(),
                "items": entries,
            })
        })
        .collect()
}

fn category_matches(document: &Value, requested: Option<&str>) -> bool {
    let Some(requested) = requested.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };
    document
        .get("category")
        .and_then(Value::as_str)
        .is_some_and(|value| value.eq_ignore_ascii_case(requested))
}

fn classify_document(document: &Value) -> &'static str {
    let tags = normalize_string_array(document.get("tags"))
        .into_iter()
        .map(|tag| tag.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let content = string_field(document, "content").to_ascii_lowercase();
    let resource_name = optional_output_string(document, "resource_name")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();

    if !resource_name.is_empty()
        || tags
            .iter()
            .any(|tag| tag == "schema" || tag.starts_with("table:"))
    {
        return CATEGORY_SCHEMA;
    }

    if tags
        .iter()
        .any(|tag| matches!(tag.as_str(), "query" | "sql" | "ddl"))
        || [
            "select ", "insert ", "update ", "delete ", " join ", " where ",
        ]
        .iter()
        .any(|needle| content.contains(needle))
    {
        return CATEGORY_QUERY;
    }

    if tags.iter().any(|tag| {
        matches!(
            tag.as_str(),
            "debug" | "incident" | "failure" | "error" | "panic" | "stacktrace"
        )
    }) || ["error", "panic", "stack trace", "exception", "failing"]
        .iter()
        .any(|needle| content.contains(needle))
    {
        return CATEGORY_DEBUG;
    }

    if tags
        .iter()
        .any(|tag| matches!(tag.as_str(), "convention" | "style" | "guideline" | "lint"))
        || ["convention", "guideline", "prefer ", "always ", "never "]
            .iter()
            .any(|needle| content.contains(needle))
    {
        return CATEGORY_CONVENTIONS;
    }

    if tags.iter().any(|tag| {
        matches!(
            tag.as_str(),
            "troubleshooting" | "workaround" | "fix" | "recovery" | "runbook"
        )
    }) || [
        "workaround",
        "fix",
        "resolved by",
        "troubleshoot",
        "recovery",
    ]
    .iter()
    .any(|needle| content.contains(needle))
    {
        return CATEGORY_TROUBLESHOOTING;
    }

    if tags.iter().any(|tag| {
        matches!(
            tag.as_str(),
            "architecture" | "service" | "endpoint" | "design" | "api"
        )
    }) || ["service", "endpoint", "architecture", "design", "component"]
        .iter()
        .any(|needle| content.contains(needle))
    {
        return CATEGORY_ARCHITECTURE;
    }

    CATEGORY_ARCHITECTURE
}

fn derive_title(document: &Value) -> String {
    if let Some(resource_name) = optional_output_string(document, "resource_name") {
        return resource_name;
    }

    let content = string_field(document, "content");
    content
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| {
            let mut title = line.to_string();
            if title.len() > 80 {
                title.truncate(77);
                title.push_str("...");
            }
            title
        })
        .unwrap_or_else(|| "Untitled context entry".to_string())
}

fn age_seconds(document: &Value) -> Option<i64> {
    let created_at = document.get("created_at").and_then(Value::as_str)?.trim();
    let parsed = DateTime::parse_from_rfc3339(created_at).ok()?;
    Some(
        Utc::now()
            .signed_duration_since(parsed.with_timezone(&Utc))
            .num_seconds(),
    )
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
