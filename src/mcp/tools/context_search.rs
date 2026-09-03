// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP tool: context_search

use serde_json::{Map, Value};

use super::ToolContext;
use crate::error::CliError;
use crate::gateway::{
    cache::l1::{shared_l1_cache, ContextPlan, ContextPlanItem},
    context_recall, ground_truth,
};

const CONTEXT_SEARCH_TOP_LEVEL_PASSTHROUGH_KEYS: [&str; 5] = [
    "include_disputed",
    "confidence_tier",
    "confidence",
    "suggested_answer",
    "recalled_entries",
];
const CONTEXT_SEARCH_DOCUMENT_PASSTHROUGH_KEYS: [&str; 12] = [
    "authority_rank",
    "staleness_indicator",
    "disputed_warning",
    "supersedes_document_id",
    "superseded_by_document_id",
    "correction_chain",
    "source_type",
    "source_ref",
    "verification_hash",
    "verified_at",
    "verified_by",
    "content_addressable_ref",
];
const DIRECT_ANSWER_FIELD_PREFIX: &str = "direct_answer_";
const CORRECTION_FIELD_PREFIX: &str = "correction_";

pub(crate) fn definition() -> Value {
    serde_json::json!({
        "name": "context_search",
        "description": "Search shared team or org context with optional repo and branch filters.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search text for the team context pool."
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results to return."
                },
                "include_disputed": {
                    "type": "boolean",
                    "description": "Include disputed or flagged context when the upstream API supports it."
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
            "required": ["query"]
        }
    })
}

pub(crate) async fn execute(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let query = required_string_argument(arguments, "query")?;
    let limit = optional_u64_argument(arguments, "limit")?;
    let include_disputed = optional_bool_argument(arguments, "include_disputed")?;
    let team_id = optional_string_argument(arguments, "team_id")?;
    let repo = optional_string_argument(arguments, "repo")?;
    let branch = optional_string_argument(arguments, "branch")?;

    let resolved = context_recall::resolve_session_scope(
        ctx.session_id,
        team_id.as_deref(),
        repo.as_deref(),
        branch.as_deref(),
    );
    let cache_authorization =
        context_recall::authorize_context_cache_scope(ctx.client, resolved.team_id.as_deref())
            .await?;
    let local_recall_config = context_recall::ContextRecallConfig {
        session_id: ctx.session_id,
        max_results: limit
            .map(|value| value.min(usize::MAX as u64) as usize)
            .unwrap_or(20),
        include_disputed: include_disputed.unwrap_or(false),
        team_id: cache_authorization.team_id.as_deref(),
        repo: repo.as_deref(),
        branch: branch.as_deref(),
        cache_authorization: Some(&cache_authorization),
        ..context_recall::ContextRecallConfig::new(ctx.session_id)
    };
    if let Some(local_recall) = context_recall::recall_context(&query, &local_recall_config).await {
        return Ok(render_local_context_search_result(
            ctx.session_id,
            &query,
            local_recall,
        ));
    }

    let mut body = Map::new();
    body.insert("query".to_string(), Value::String(query.clone()));
    body.insert(
        "session_id".to_string(),
        Value::String(ctx.session_id.to_string()),
    );
    if let Some(value) = limit {
        body.insert("limit".to_string(), Value::Number(value.into()));
    }
    if let Some(value) = include_disputed {
        body.insert("include_disputed".to_string(), Value::Bool(value));
    }
    if let Some(value) = team_id.clone() {
        body.insert("team_id".to_string(), Value::String(value));
    }
    if let Some(value) = repo.clone() {
        body.insert("repo".to_string(), Value::String(value));
    }
    if let Some(value) = branch.clone() {
        body.insert("branch".to_string(), Value::String(value));
    }

    tracing::debug!(
        session_id = %ctx.session_id,
        query = %query,
        include_disputed,
        "searching context-fabric documents via MCP"
    );

    let response = ctx
        .client
        .post_json_value("/v1/context/search", &Value::Object(body))
        .await?;

    let results = response
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|document| normalize_document(&document))
        .collect::<Vec<_>>();

    if let (Some(repo_val), Some(branch_val)) =
        (resolved.repo.as_deref(), resolved.branch.as_deref())
    {
        let items: Vec<ContextPlanItem> = results
            .iter()
            .filter_map(|doc| {
                let id = doc.get("id").and_then(Value::as_str)?;
                if id.is_empty() {
                    return None;
                }
                Some(ContextPlanItem {
                    organization_id: cache_authorization.organization_id.clone(),
                    team_id: cache_authorization.team_id.clone(),
                    authorization_version: cache_authorization.authorization_version.clone(),
                    item_id: id.to_string(),
                    content: doc
                        .get("content")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    token_estimate: doc
                        .get("token_estimate")
                        .and_then(Value::as_u64)
                        .unwrap_or(0) as u32,
                    citation_required: doc
                        .get("citation_required")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    source_kind: doc
                        .get("source_kind")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                })
            })
            .collect();
        if !items.is_empty() {
            let _ = shared_l1_cache().insert(ContextPlan::new(
                cache_authorization,
                repo_val,
                branch_val,
                &query,
                items,
            ));
        }
    }

    let total_count = results.len();
    let mut output = Map::new();
    output.insert(
        "tool_name".to_string(),
        Value::String("context_search".to_string()),
    );
    output.insert("status".to_string(), Value::String("ok".to_string()));
    output.insert("query".to_string(), Value::String(query));
    output.insert(
        "scope".to_string(),
        scope_metadata(
            Some(ctx.session_id),
            team_id.as_deref(),
            repo.as_deref(),
            branch.as_deref(),
        ),
    );
    output.insert("results".to_string(), Value::Array(results));
    output.insert(
        "total_count".to_string(),
        Value::Number((total_count as u64).into()),
    );
    if let Some(direct_answer) = normalize_direct_answer(&response) {
        output.insert("direct_answer".to_string(), direct_answer);
    }
    copy_passthrough_fields(
        &response,
        &mut output,
        &CONTEXT_SEARCH_TOP_LEVEL_PASSTHROUGH_KEYS,
    );
    copy_passthrough_prefixed_fields(&response, &mut output, DIRECT_ANSWER_FIELD_PREFIX);
    copy_passthrough_prefixed_fields(&response, &mut output, CORRECTION_FIELD_PREFIX);

    Ok(Value::Object(output))
}

fn render_local_context_search_result(
    session_id: &str,
    query: &str,
    recall: context_recall::ContextRecallResult,
) -> Value {
    let results = recall
        .entries
        .iter()
        .map(|entry| normalize_document(&entry.document))
        .collect::<Vec<_>>();
    serde_json::json!({
        "tool_name": "context_search",
        "status": "ok",
        "backend": recall.backend.as_str(),
        "query": query,
        "scope": scope_metadata(
            Some(session_id),
            recall.scope.team_id.as_deref(),
            recall.scope.repo.as_deref(),
            recall.scope.branch.as_deref(),
        ),
        "results": results,
        "total_count": results.len(),
        "include_disputed": recall.include_disputed,
        "note": recall.backend.note(),
    })
}

fn normalize_document(document: &Value) -> Value {
    let mut normalized = Map::new();
    normalized.insert(
        "id".to_string(),
        Value::String(string_field(document, "id")),
    );
    normalized.insert(
        "title".to_string(),
        optional_output_string(document, "title")
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    normalized.insert(
        "summary".to_string(),
        optional_output_string(document, "summary")
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    normalized.insert(
        "history_session_id".to_string(),
        Value::String(string_field(document, "history_session_id")),
    );
    normalized.insert(
        "source_kind".to_string(),
        Value::String(string_field(document, "source_kind")),
    );
    normalized.insert(
        "content".to_string(),
        Value::String(string_field(document, "content")),
    );
    normalized.insert(
        "token_estimate".to_string(),
        numeric_field_or_default(document, "token_estimate", 0),
    );
    normalized.insert(
        "source_user_id".to_string(),
        optional_output_string(document, "source_user_id")
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    normalized.insert(
        "source_user_display_name".to_string(),
        optional_output_string(document, "source_user_display_name")
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    normalized.insert(
        "author".to_string(),
        optional_output_string(document, "source_user_display_name")
            .or_else(|| optional_output_string(document, "source_user_id"))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    normalized.insert(
        "owner_team_id".to_string(),
        optional_output_string(document, "owner_team_id")
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    normalized.insert(
        "git_repo".to_string(),
        optional_output_string(document, "git_repo")
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    normalized.insert(
        "git_branch".to_string(),
        optional_output_string(document, "git_branch")
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    normalized.insert(
        "git_commit".to_string(),
        optional_output_string(document, "git_commit")
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    normalized.insert(
        "tags".to_string(),
        Value::Array(
            normalize_string_array(document.get("tags"))
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
    normalized.insert(
        "resource_name".to_string(),
        optional_output_string(document, "resource_name")
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    normalized.insert(
        "rank_score".to_string(),
        numeric_field_or_null(document, "rank_score"),
    );
    normalized.insert(
        "confidence_tier".to_string(),
        optional_output_string(document, "confidence_tier")
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    normalized.insert(
        "verification_status".to_string(),
        optional_output_string(document, "verification_status")
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    normalized.insert(
        "confidence_score".to_string(),
        numeric_field_or_null(document, "confidence_score"),
    );
    normalized.insert(
        "recall_count".to_string(),
        numeric_field_or_null(document, "recall_count"),
    );
    normalized.insert(
        "last_recalled_at".to_string(),
        optional_output_string(document, "last_recalled_at")
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    normalized.insert(
        "activity_type".to_string(),
        optional_output_string(document, "activity_type")
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    normalized.insert(
        "citation_required".to_string(),
        Value::Bool(
            document
                .get("citation_required")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        ),
    );
    normalized.insert(
        "created_at".to_string(),
        Value::String(string_field(document, "created_at")),
    );
    copy_passthrough_fields(
        document,
        &mut normalized,
        &CONTEXT_SEARCH_DOCUMENT_PASSTHROUGH_KEYS,
    );
    copy_passthrough_prefixed_fields(document, &mut normalized, DIRECT_ANSWER_FIELD_PREFIX);
    copy_passthrough_prefixed_fields(document, &mut normalized, CORRECTION_FIELD_PREFIX);
    normalized.insert(
        "provenance".to_string(),
        ground_truth::normalize_document_provenance(document),
    );

    Value::Object(normalized)
}

fn normalize_direct_answer(response: &Value) -> Option<Value> {
    let direct_answer = response.get("direct_answer");
    let suggested_answer = response.get("suggested_answer");
    let direct_answer_confidence = response.get("direct_answer_confidence");
    let direct_answer_source_ids = response.get("direct_answer_source_document_ids");

    if direct_answer.is_none()
        && suggested_answer.is_none()
        && direct_answer_confidence.is_none()
        && direct_answer_source_ids.is_none()
        && response.get("confidence").is_none()
    {
        return None;
    }

    let content = direct_answer
        .and_then(|value| value.get("content"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            suggested_answer
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .or_else(|| {
            suggested_answer
                .and_then(|value| value.get("content"))
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .or_else(|| {
            direct_answer
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .unwrap_or_default();

    let citations = direct_answer
        .and_then(|value| value.get("citations"))
        .filter(|value| value.is_array())
        .cloned()
        .or_else(|| direct_answer_source_ids.cloned())
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let source_document_ids = direct_answer
        .and_then(|value| value.get("source_document_ids"))
        .filter(|value| value.is_array())
        .cloned()
        .or_else(|| direct_answer_source_ids.cloned())
        .unwrap_or_else(|| Value::Array(Vec::new()));

    Some(serde_json::json!({
        "content": content,
        "citations": citations,
        "confidence": direct_answer
            .and_then(|value| value.get("confidence"))
            .cloned()
            .or_else(|| direct_answer_confidence.cloned())
            .or_else(|| response.get("confidence").cloned())
            .unwrap_or(Value::Null),
        "source_document_ids": source_document_ids,
        "author": direct_answer
            .and_then(|value| optional_output_string(value, "author"))
            .or_else(|| suggested_answer.and_then(|value| optional_output_string(value, "author"))),
        "created_at": direct_answer
            .and_then(|value| optional_output_string(value, "created_at"))
            .or_else(|| suggested_answer.and_then(|value| optional_output_string(value, "created_at"))),
        "branch": direct_answer
            .and_then(|value| optional_output_string(value, "branch"))
            .or_else(|| suggested_answer.and_then(|value| optional_output_string(value, "branch"))),
        "direct_answer": direct_answer
            .and_then(|value| value.get("direct_answer"))
            .and_then(Value::as_bool)
            .unwrap_or(true),
    }))
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
        .ok_or_else(|| CliError::user(format!("context_search requires '{key}' parameter")))
}

fn optional_string_argument(arguments: &Value, key: &str) -> Result<Option<String>, CliError> {
    let Some(value) = arguments.get(key) else {
        return Ok(None);
    };
    let text = value
        .as_str()
        .ok_or_else(|| CliError::user(format!("context_search '{key}' must be a string")))?;
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
        .ok_or_else(|| CliError::user(format!("context_search '{key}' must be a positive integer")))
}

fn optional_bool_argument(arguments: &Value, key: &str) -> Result<Option<bool>, CliError> {
    let Some(value) = arguments.get(key) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| CliError::user(format!("context_search '{key}' must be a boolean")))
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

fn numeric_field_or_default(value: &Value, key: &str, default: i64) -> Value {
    value
        .get(key)
        .filter(|candidate| candidate.is_number())
        .cloned()
        .unwrap_or_else(|| Value::Number(default.into()))
}

fn numeric_field_or_null(value: &Value, key: &str) -> Value {
    value
        .get(key)
        .filter(|candidate| candidate.is_number())
        .cloned()
        .unwrap_or(Value::Null)
}

fn copy_passthrough_fields(source: &Value, target: &mut Map<String, Value>, keys: &[&str]) {
    for key in keys {
        if let Some(value) = source.get(key) {
            target.insert((*key).to_string(), value.clone());
        }
    }
}

fn copy_passthrough_prefixed_fields(source: &Value, target: &mut Map<String, Value>, prefix: &str) {
    let Some(source) = source.as_object() else {
        return;
    };

    for (key, value) in source {
        if key.starts_with(prefix) {
            target.insert(key.clone(), value.clone());
        }
    }
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
