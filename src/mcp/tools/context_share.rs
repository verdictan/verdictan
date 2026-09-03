// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP tool: context_share

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::ToolContext;
use crate::error::CliError;
use crate::gateway::{
    cache::l1::{shared_l1_cache, ContextPoolMutation, ContextPoolMutationKind},
    context_recall,
    crdt::CrdtMutation,
    ground_truth,
};

const MAX_L2_TOPICS_PER_SHARE: usize = 128;

pub(crate) fn definition() -> Value {
    serde_json::json!({
        "name": "context_share",
        "description": "Store an explicit team context note for subsequent reuse.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "The note or insight to store."
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
                },
                "commit": {
                    "type": "string",
                    "description": "Optional commit SHA for provenance."
                },
                "file_path": {
                    "type": "string",
                    "description": "Optional repo-relative or logical file path to anchor a code-backed share."
                },
                "tags": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Optional topic or entity tags."
                },
                "source_type": {
                    "type": "string",
                    "description": "Optional explicit provenance source type. One of: database, code, config, api_contract, human_verified."
                },
                "source_ref": {
                    "description": "Optional explicit JSON provenance reference payload."
                },
                "verification_hash": {
                    "type": "string",
                    "description": "Optional caller-computed SHA-256 verification hash for the referenced source."
                },
                "verified_by": {
                    "type": "string",
                    "description": "Optional verifier marker. One of: system, human."
                },
                "content_addressable_ref": {
                    "type": "string",
                    "description": "Optional content-addressable source reference, typically in commit:path form."
                },
                "resolution": {
                    "type": "string",
                    "description": "Optional follow-up decision for a duplicate-detected share. Use 'replace', 'keep_both', or 'discard'."
                },
                "duplicate_document_id": {
                    "type": "string",
                    "description": "Document id from a prior duplicate_detected response, when the upstream API makes it mandatory."
                },
                "existing_document_id": {
                    "type": "string",
                    "description": "Alias for duplicate_document_id."
                },
                "resolution_token": {
                    "type": "string",
                    "description": "Duplicate-resolution token from a prior duplicate_detected response, when the API returns it."
                }
            },
            "required": ["content"]
        }
    })
}

pub(crate) async fn execute(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let content = required_string_argument(arguments, "content")?;
    let team_id = optional_string_argument(arguments, "team_id")?;
    let repo = optional_string_argument(arguments, "repo")?;
    let branch = optional_string_argument(arguments, "branch")?;
    let commit = optional_string_argument(arguments, "commit")?;
    let file_path = optional_string_argument(arguments, "file_path")?;
    let tags = string_array_argument(arguments, "tags")?;
    let source_type = optional_string_argument(arguments, "source_type")?;
    let source_ref = optional_value_argument(arguments, "source_ref");
    let verification_hash = optional_string_argument(arguments, "verification_hash")?;
    let verified_by = optional_string_argument(arguments, "verified_by")?;
    let content_addressable_ref = optional_string_argument(arguments, "content_addressable_ref")?;
    let resolution = optional_resolution_argument(arguments)?;
    let duplicate_document_id = duplicate_document_id_argument(arguments)?;
    let resolution_token = optional_string_argument(arguments, "resolution_token")?;
    let resolved_scope = context_recall::resolve_session_scope(
        ctx.session_id,
        team_id.as_deref(),
        repo.as_deref(),
        branch.as_deref(),
    );
    let cache_authorization = context_recall::authorize_context_cache_mutation_scope(
        ctx.client,
        resolved_scope.team_id.as_deref(),
    )
    .await?;
    let prepared_provenance = ground_truth::prepare_share_provenance(
        repo.as_deref(),
        branch.as_deref(),
        commit.as_deref(),
        file_path.as_deref(),
        source_type.as_deref(),
        source_ref.as_ref(),
        verification_hash.as_deref(),
        verified_by.as_deref(),
        content_addressable_ref.as_deref(),
    )
    .map_err(CliError::user)?;

    let mut body = Map::new();
    body.insert("content".to_string(), Value::String(content.clone()));
    body.insert(
        "session_id".to_string(),
        Value::String(ctx.session_id.to_string()),
    );
    if let Some(value) = team_id.clone() {
        body.insert("team_id".to_string(), Value::String(value));
    }
    if let Some(value) = repo.clone() {
        body.insert("repo".to_string(), Value::String(value));
    }
    if let Some(value) = branch.clone() {
        body.insert("branch".to_string(), Value::String(value));
    }
    if let Some(value) = commit.clone() {
        body.insert("commit".to_string(), Value::String(value));
    }
    if !tags.is_empty() {
        body.insert(
            "tags".to_string(),
            Value::Array(tags.iter().cloned().map(Value::String).collect()),
        );
    }
    prepared_provenance.insert_into_body(&mut body);
    if let Some(value) = resolution.clone() {
        body.insert("resolution".to_string(), Value::String(value));
    }
    if let Some(value) = duplicate_document_id.clone() {
        body.insert("duplicate_document_id".to_string(), Value::String(value));
    }
    if let Some(value) = resolution_token.clone() {
        body.insert("resolution_token".to_string(), Value::String(value));
    }

    tracing::debug!(
        session_id = %ctx.session_id,
        has_repo_override = repo.is_some(),
        has_branch_override = branch.is_some(),
        resolution = resolution.as_deref().unwrap_or("none"),
        "sharing context-fabric document via MCP"
    );

    let response = ctx
        .client
        .post_json_value("/v1/context/share", &Value::Object(body))
        .await?;

    if is_duplicate_detected_response(&response) {
        let existing_document = duplicate_existing_document(&response);
        let owner_team_id =
            existing_document.and_then(|value| optional_output_string(value, "owner_team_id"));
        let git_repo =
            existing_document.and_then(|value| optional_output_string(value, "git_repo"));
        let git_branch =
            existing_document.and_then(|value| optional_output_string(value, "git_branch"));

        return Ok(serde_json::json!({
            "tool_name": "context_share",
            "status": duplicate_status(&response),
            "scope": scope_metadata(
                Some(ctx.session_id),
                owner_team_id.as_deref().or(team_id.as_deref()),
                git_repo.as_deref().or(repo.as_deref()),
                git_branch.as_deref().or(branch.as_deref()),
                existing_document.is_some(),
            ),
            "duplicate_detected": normalize_duplicate_detected(&response),
            "resolution": normalize_resolution_details(&response),
        }));
    }

    let document = response
        .get("document")
        .cloned()
        .unwrap_or(Value::Object(Map::new()));
    let owner_team_id = optional_output_string(&document, "owner_team_id");
    let git_repo = optional_output_string(&document, "git_repo");
    let git_branch = optional_output_string(&document, "git_branch");

    if let (Some(r), Some(b)) = (
        git_repo.as_deref().or(repo.as_deref()),
        git_branch.as_deref().or(branch.as_deref()),
    ) {
        let mutation =
            ContextPoolMutation::new(cache_authorization, r, b, ContextPoolMutationKind::Share);
        shared_l1_cache().publish_invalidation(mutation.clone());
        crate::gateway::cache::l2::shared_l2_cache().apply_mutation(&mutation);
        record_l2_topics_for_context_share(r, b, &tags, &content, &document);
    }

    let mut output = Map::new();
    output.insert(
        "tool_name".to_string(),
        Value::String("context_share".to_string()),
    );
    output.insert("status".to_string(), Value::String("ok".to_string()));
    output.insert(
        "scope".to_string(),
        scope_metadata(
            Some(ctx.session_id),
            owner_team_id.as_deref(),
            git_repo.as_deref(),
            git_branch.as_deref(),
            true,
        ),
    );
    output.insert("document".to_string(), normalize_document(&document));
    output.insert(
        "local_replica".to_string(),
        mirror_document_into_local_runtime(
            ctx,
            &document,
            team_id.as_deref(),
            repo.as_deref(),
            branch.as_deref(),
        )
        .await,
    );
    if let Some(resolution_details) = normalize_resolution_details(&response) {
        output.insert("resolution".to_string(), resolution_details);
    }

    Ok(Value::Object(output))
}

fn normalize_document(document: &Value) -> Value {
    serde_json::json!({
        "id": string_field(document, "id"),
        "title": optional_output_string(document, "title"),
        "summary": optional_output_string(document, "summary"),
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
        "recall_count": document.get("recall_count").and_then(Value::as_i64),
        "last_recalled_at": optional_output_string(document, "last_recalled_at"),
        "activity_type": optional_output_string(document, "activity_type"),
        "citation_required": document
            .get("citation_required")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "created_at": string_field(document, "created_at"),
        "provenance": ground_truth::normalize_document_provenance(document),
    })
}

async fn mirror_document_into_local_runtime(
    ctx: &ToolContext<'_>,
    document: &Value,
    explicit_team_id: Option<&str>,
    explicit_repo: Option<&str>,
    explicit_branch: Option<&str>,
) -> Value {
    let handle = super::local_context_session_handle(ctx.session_id);
    let Some(driver) = handle.crdt_sync_driver() else {
        return serde_json::json!({
            "status": "skipped",
            "reason": "local_runtime_unavailable",
        });
    };
    let Some(document_object) = document.as_object() else {
        return serde_json::json!({
            "status": "skipped",
            "reason": "document_not_object",
        });
    };
    let entry_id = string_field(document, "id");
    if entry_id.is_empty() {
        return serde_json::json!({
            "status": "skipped",
            "reason": "document_id_missing",
        });
    }

    let resolved_scope = super::resolve_session_scope(
        ctx.session_id,
        explicit_team_id,
        explicit_repo,
        explicit_branch,
    );
    let repo = optional_output_string(document, "git_repo").or(resolved_scope.repo.clone());
    let branch = optional_output_string(document, "git_branch").or(resolved_scope.branch.clone());
    if branch.is_some() && repo.is_none() {
        return serde_json::json!({
            "status": "skipped",
            "reason": "scope_unavailable",
        });
    }

    let mut fields = BTreeMap::new();
    for (key, value) in document_object {
        if !value.is_null() {
            fields.insert(key.clone(), value.clone());
        }
    }
    if let Some(value) = resolved_scope
        .team_id
        .clone()
        .or_else(|| optional_output_string(document, "owner_team_id"))
    {
        fields.insert("owner_team_id".to_string(), Value::String(value));
    }
    if let Some(value) = repo.clone() {
        fields.insert("repo".to_string(), Value::String(value.clone()));
        fields
            .entry("git_repo".to_string())
            .or_insert(Value::String(value));
    }
    if let Some(value) = branch.clone() {
        fields.insert("branch".to_string(), Value::String(value.clone()));
        fields
            .entry("git_branch".to_string())
            .or_insert(Value::String(value));
    }
    if let Some(value) =
        optional_output_string(document, "git_commit").or(resolved_scope.commit.clone())
    {
        fields.insert("git_commit".to_string(), Value::String(value));
    }
    let schema_keys = derive_schema_keys(document);
    if let Some(schema_key) = schema_keys.first() {
        fields.insert("schema_key".to_string(), Value::String(schema_key.clone()));
    }
    if !schema_keys.is_empty() {
        fields.insert(
            "schema_keys".to_string(),
            Value::Array(schema_keys.into_iter().map(Value::String).collect()),
        );
    }
    fields.insert(
        "local_context_source".to_string(),
        Value::String("context_share".to_string()),
    );

    match driver
        .apply_local_mutation(CrdtMutation::UpsertEntry {
            entry_id,
            fields,
            now_ms: None,
        })
        .await
    {
        Ok(_) => serde_json::json!({
            "status": "mirrored",
            "backend": "local_crdt",
        }),
        Err(error) => serde_json::json!({
            "status": "error",
            "reason": "local_replica_update_failed",
            "message": error.to_string(),
        }),
    }
}

fn derive_schema_keys(document: &Value) -> Vec<String> {
    let mut keys = BTreeSet::new();
    if let Some(resource_name) = optional_output_string(document, "resource_name") {
        keys.insert(resource_name);
    }
    for tag in normalize_string_array(document.get("tags")) {
        if let Some(schema_key) = tag.strip_prefix("table:") {
            let trimmed = schema_key.trim();
            if !trimmed.is_empty() {
                keys.insert(trimmed.to_string());
            }
        }
    }
    keys.into_iter().collect()
}

fn record_l2_topics_for_context_share(
    repo: &str,
    branch: &str,
    tags: &[String],
    content: &str,
    document: &Value,
) {
    let l2 = crate::gateway::cache::l2::shared_l2_cache();
    for topic in context_share_l2_topics(tags, content, document) {
        l2.record_topic(repo, branch, &topic);
    }
}

fn context_share_l2_topics(tags: &[String], content: &str, document: &Value) -> Vec<String> {
    let mut topics = BTreeSet::new();
    for tag in tags {
        insert_l2_topic(&mut topics, tag);
        if let Some((_, suffix)) = tag.split_once(':') {
            insert_l2_topic(&mut topics, suffix);
        }
    }

    insert_text_l2_topics(&mut topics, content);
    for field in ["content", "title", "summary", "resource_name"] {
        if let Some(value) = optional_output_string(document, field) {
            insert_text_l2_topics(&mut topics, &value);
        }
    }

    topics.into_iter().collect()
}

fn insert_text_l2_topics(topics: &mut BTreeSet<String>, text: &str) {
    let words = text
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .filter_map(|word| {
            let normalized = word.trim().to_ascii_lowercase();
            if normalized.len() >= 2 {
                Some(normalized)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    for phrase_len in 1..=4 {
        for window in words.windows(phrase_len) {
            insert_l2_topic(topics, &window.join(" "));
        }
    }
}

fn insert_l2_topic(topics: &mut BTreeSet<String>, topic: &str) {
    if topics.len() >= MAX_L2_TOPICS_PER_SHARE {
        return;
    }
    let normalized = topic
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_ascii_lowercase();
    if !normalized.is_empty() {
        topics.insert(normalized);
    }
}

fn normalize_duplicate_detected(response: &Value) -> Value {
    let source = duplicate_source(response).unwrap_or(response);
    let existing_document = duplicate_existing_document(response);
    serde_json::json!({
        "existing_document_id": optional_output_string(source, "existing_document_id")
            .or_else(|| existing_document.and_then(|value| optional_output_string(value, "id"))),
        "existing_document": existing_document.map(normalize_document).unwrap_or(Value::Null),
        "similarity_score": source.get("similarity_score").cloned().unwrap_or(Value::Null),
        "reason": optional_output_string(source, "reason"),
        "matched_fields": source.get("matched_fields").cloned().unwrap_or(Value::Null),
    })
}

fn normalize_resolution_details(response: &Value) -> Option<Value> {
    let source = duplicate_source(response).unwrap_or(response);
    let options = source
        .get("resolution_options")
        .or_else(|| response.get("resolution_options"))
        .filter(|value| value.is_array())
        .cloned();
    let selected = optional_output_string(source, "resolution")
        .or_else(|| optional_output_string(source, "selected_resolution"))
        .or_else(|| optional_output_string(response, "resolution"))
        .or_else(|| optional_output_string(response, "selected_resolution"));
    let token = optional_output_string(source, "resolution_token")
        .or_else(|| optional_output_string(response, "resolution_token"));
    let timeout_ms = source
        .get("resolution_timeout_ms")
        .or_else(|| source.get("dedup_timeout_ms"))
        .or_else(|| source.get("timeout_ms"))
        .or_else(|| response.get("resolution_timeout_ms"))
        .or_else(|| response.get("dedup_timeout_ms"))
        .or_else(|| response.get("timeout_ms"))
        .filter(|value| value.is_number())
        .cloned();

    if options.is_none() && selected.is_none() && token.is_none() && timeout_ms.is_none() {
        return None;
    }

    Some(serde_json::json!({
        "required": options.is_some() && selected.is_none(),
        "selected": selected,
        "options": options.unwrap_or_else(|| Value::Array(Vec::new())),
        "token": token,
        "timeout_ms": timeout_ms.unwrap_or(Value::Null),
    }))
}

fn scope_metadata(
    session_id: Option<&str>,
    team_id: Option<&str>,
    repo: Option<&str>,
    branch: Option<&str>,
    resolved_scope_known: bool,
) -> Value {
    let (kind, resolution, note) = if branch.is_some() {
        ("branch", "resolved_write_scope", None)
    } else if repo.is_some() {
        ("repo", "resolved_write_scope", None)
    } else if team_id.is_some() {
        ("team", "resolved_write_scope", None)
    } else if resolved_scope_known {
        ("org", "default_org_scope", None)
    } else if session_id.is_some_and(|value| !value.trim().is_empty()) {
        (
            "session",
            if resolved_scope_known {
                "session_registration"
            } else {
                "session_registration_or_validation_block"
            },
            (!resolved_scope_known).then_some(
                "Write scope could not be resolved because the upstream API rejected the request before it echoed a registered repo and branch.",
            ),
        )
    } else {
        ("org", "default_org_scope", None)
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

fn duplicate_source(response: &Value) -> Option<&Value> {
    response
        .get("duplicate_detected")
        .filter(|value| value.is_object())
        .or_else(|| {
            response
                .get("status")
                .and_then(Value::as_str)
                .filter(|status| {
                    matches!(
                        *status,
                        "duplicate_detected" | "needs_resolution" | "resolution_required"
                    )
                })
                .map(|_| response)
        })
        .or_else(|| {
            (response.get("existing_document").is_some()
                && response.get("resolution_options").is_some())
            .then_some(response)
        })
}

fn duplicate_existing_document(response: &Value) -> Option<&Value> {
    let source = duplicate_source(response).unwrap_or(response);
    source
        .get("existing_document")
        .or_else(|| response.get("existing_document"))
        .filter(|value| value.is_object())
}

fn is_duplicate_detected_response(response: &Value) -> bool {
    duplicate_source(response).is_some()
}

fn duplicate_status(response: &Value) -> String {
    response
        .get("status")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("duplicate_detected")
        .to_string()
}

fn required_string_argument(arguments: &Value, key: &str) -> Result<String, CliError> {
    optional_string_argument(arguments, key)?
        .ok_or_else(|| CliError::user(format!("context_share requires '{key}' parameter")))
}

fn optional_string_argument(arguments: &Value, key: &str) -> Result<Option<String>, CliError> {
    let Some(value) = arguments.get(key) else {
        return Ok(None);
    };
    let text = value
        .as_str()
        .ok_or_else(|| CliError::user(format!("context_share '{key}' must be a string")))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed.to_string()))
}

fn optional_resolution_argument(arguments: &Value) -> Result<Option<String>, CliError> {
    let Some(value) = optional_string_argument(arguments, "resolution")? else {
        return Ok(None);
    };

    match value.as_str() {
        "replace" | "keep_both" | "discard" => Ok(Some(value)),
        _ => Err(CliError::user(
            "context_share 'resolution' must be one of: replace, keep_both, discard".to_string(),
        )),
    }
}

fn duplicate_document_id_argument(arguments: &Value) -> Result<Option<String>, CliError> {
    let duplicate_document_id = optional_string_argument(arguments, "duplicate_document_id")?;
    let existing_document_id = optional_string_argument(arguments, "existing_document_id")?;

    match (duplicate_document_id, existing_document_id) {
        (Some(left), Some(right)) if left != right => Err(CliError::user(
            "context_share 'duplicate_document_id' and 'existing_document_id' must match when both are provided"
                .to_string(),
        )),
        (Some(value), _) | (_, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

fn optional_value_argument(arguments: &Value, key: &str) -> Option<Value> {
    arguments.get(key).cloned().filter(|value| !value.is_null())
}

fn string_array_argument(arguments: &Value, key: &str) -> Result<Vec<String>, CliError> {
    let Some(value) = arguments.get(key) else {
        return Ok(Vec::new());
    };
    let values = value.as_array().ok_or_else(|| {
        CliError::user(format!("context_share '{key}' must be an array of strings"))
    })?;
    let mut deduped = BTreeSet::new();
    for entry in values {
        let text = entry.as_str().ok_or_else(|| {
            CliError::user(format!("context_share '{key}' entries must be strings"))
        })?;
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            deduped.insert(trimmed.to_string());
        }
    }
    Ok(deduped.into_iter().collect())
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
