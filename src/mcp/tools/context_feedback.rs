// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP tool: context_feedback

use serde_json::{Map, Value};

use super::ToolContext;
use crate::error::CliError;

pub(crate) fn definition() -> Value {
    serde_json::json!({
        "name": "context_feedback",
        "description": "Record ranking feedback or submit a correction for one shared context document.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "document_id": {
                    "type": "string",
                    "description": "Context document id returned from context_search, context_recent, or schema_lookup."
                },
                "action": {
                    "type": "string",
                    "description": "Preferred feedback selector. One of: thumbs_up, thumbs_down, correct."
                },
                "signal": {
                    "type": "string",
                    "description": "Legacy alias for action. One of: thumbs_up, thumbs_down, correct."
                },
                "correct": {
                    "type": "boolean",
                    "description": "Deprecated alias for action=correct."
                },
                "corrected_content": {
                    "type": "string",
                    "description": "Mandatory when action or signal is correct. Replacement content for the corrected context note."
                },
                "notes": {
                    "type": "string",
                    "description": "Optional reviewer note about the feedback or correction."
                }
            },
            "required": ["document_id"],
            "anyOf": [
                { "required": ["action"] },
                { "required": ["signal"] },
                { "required": ["correct"] }
            ]
        }
    })
}

pub(crate) async fn execute(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let document_id = required_string_argument(arguments, "document_id")?;
    let action = feedback_action_argument(arguments)?;
    let notes = optional_string_argument(arguments, "notes")?;
    let corrected_content = corrected_content_argument(arguments, &action)?;

    let mut body = Map::new();
    body.insert(
        "document_id".to_string(),
        Value::String(document_id.clone()),
    );
    body.insert("signal".to_string(), Value::String(action.clone()));
    if let Some(value) = corrected_content {
        body.insert("corrected_content".to_string(), Value::String(value));
    }
    if let Some(value) = notes {
        body.insert("notes".to_string(), Value::String(value));
    }

    tracing::debug!(
        document_id = %document_id,
        action = %action,
        "recording context-fabric feedback via MCP"
    );

    let response = match ctx
        .client
        .post_json_value("/v1/context/feedback", &Value::Object(body))
        .await
    {
        Ok(response) => response,
        Err(error) if error.http_status() == Some(422) && action == "correct" => {
            return Err(CliError::user(
                "context_feedback action 'correct' requires an API deployment with correction-chain support"
                    .to_string(),
            )
            .with_http_status(422));
        }
        Err(error) => return Err(error),
    };

    let response_document_id =
        optional_output_string(&response, "document_id").unwrap_or_else(|| document_id.clone());

    Ok(serde_json::json!({
        "tool_name": "context_feedback",
        "status": "ok",
        "document_id": response_document_id,
        "action": action.clone(),
        "signal": action,
        "recorded_feedback": normalize_feedback_record(response.get("recorded_feedback")),
        "summary": normalize_summary(response.get("summary")),
        "document_updates": normalize_document_updates(response.get("document_updates")),
        "correction": normalize_correction(&response),
    }))
}

fn normalize_feedback_record(value: Option<&Value>) -> Value {
    let value = value.unwrap_or(&Value::Null);
    serde_json::json!({
        "feedback_id": string_field(value, "feedback_id"),
        "document_id": string_field(value, "document_id"),
        "user_id": string_field(value, "user_id"),
        "feedback_type": string_field(value, "feedback_type"),
        "notes": optional_output_string(value, "notes"),
        "created_at": string_field(value, "created_at"),
    })
}

fn normalize_summary(value: Option<&Value>) -> Value {
    let value = value.unwrap_or(&Value::Null);
    serde_json::json!({
        "helpful": integer_field(value, "helpful"),
        "not_helpful": integer_field(value, "not_helpful"),
        "flagged": integer_field(value, "flagged"),
        "verified": integer_field(value, "verified"),
        "disputed": integer_field(value, "disputed"),
    })
}

fn normalize_document_updates(value: Option<&Value>) -> Value {
    let value = value.unwrap_or(&Value::Null);
    serde_json::json!({
        "verification_status": normalize_field_update(value.get("verification_status")),
        "confidence_score": normalize_field_update(value.get("confidence_score")),
    })
}

fn normalize_field_update(value: Option<&Value>) -> Value {
    let value = value.unwrap_or(&Value::Null);
    serde_json::json!({
        "updated": value.get("updated").and_then(Value::as_bool).unwrap_or(false),
        "reason": optional_output_string(value, "reason"),
    })
}

fn normalize_correction(response: &Value) -> Value {
    let correction = response
        .get("correction")
        .filter(|value| value.is_object())
        .unwrap_or(response);
    let corrected_document = correction
        .get("corrected_document")
        .or_else(|| correction.get("document"))
        .or_else(|| response.get("corrected_document"))
        .filter(|value| value.is_object());
    let correction_chain = correction
        .get("correction_chain")
        .or_else(|| response.get("correction_chain"));

    if corrected_document.is_none()
        && correction_chain.is_none()
        && optional_output_string(correction, "status").is_none()
        && optional_output_string(correction, "new_document_id").is_none()
        && optional_output_string(correction, "corrected_document_id").is_none()
        && optional_output_string(correction, "supersedes_document_id").is_none()
        && optional_output_string(correction, "superseded_document_id").is_none()
        && optional_output_string(correction, "superseded_by_document_id").is_none()
    {
        return Value::Null;
    }

    let mut normalized = Map::new();
    insert_optional_string_field(&mut normalized, correction, "status");
    insert_optional_string_field(&mut normalized, correction, "new_document_id");
    insert_optional_string_field(&mut normalized, correction, "corrected_document_id");
    insert_optional_string_field(&mut normalized, correction, "supersedes_document_id");
    insert_optional_string_field(&mut normalized, correction, "superseded_document_id");
    insert_optional_string_field(&mut normalized, correction, "superseded_by_document_id");
    if let Some(document) = corrected_document {
        normalized.insert(
            "corrected_document".to_string(),
            normalize_document(document),
        );
    }
    if let Some(chain) = correction_chain {
        normalized.insert("correction_chain".to_string(), chain.clone());
    }

    Value::Object(normalized)
}

fn normalize_document(document: &Value) -> Value {
    serde_json::json!({
        "id": string_field(document, "id"),
        "title": optional_output_string(document, "title"),
        "summary": optional_output_string(document, "summary"),
        "history_session_id": string_field(document, "history_session_id"),
        "source_kind": string_field(document, "source_kind"),
        "content": string_field(document, "content"),
        "token_estimate": integer_field(document, "token_estimate"),
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
        "recall_count": document.get("recall_count").and_then(Value::as_i64),
        "last_recalled_at": optional_output_string(document, "last_recalled_at"),
        "activity_type": optional_output_string(document, "activity_type"),
        "supersedes_document_id": optional_output_string(document, "supersedes_document_id"),
        "superseded_by_document_id": optional_output_string(document, "superseded_by_document_id"),
        "citation_required": document
            .get("citation_required")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "created_at": string_field(document, "created_at"),
    })
}

fn feedback_action_argument(arguments: &Value) -> Result<String, CliError> {
    let action = optional_string_argument(arguments, "action")?;
    let signal = optional_string_argument(arguments, "signal")?;
    let correct = arguments
        .get("correct")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    if let (Some(action), Some(signal)) = (&action, &signal) {
        if action != signal {
            return Err(CliError::user(
                "context_feedback 'action' and 'signal' must match when both are provided"
                    .to_string(),
            ));
        }
    }

    let resolved = action
        .or(signal)
        .or_else(|| correct.then_some("correct".to_string()))
        .ok_or_else(|| {
            CliError::user(
                "context_feedback requires either 'action', legacy 'signal', or deprecated 'correct=true'"
                    .to_string(),
            )
        })?;

    match resolved.as_str() {
        "thumbs_up" => Ok("thumbs_up".to_string()),
        "thumbs_down" => Ok("thumbs_down".to_string()),
        "correct" => Ok("correct".to_string()),
        _ => Err(CliError::user(
            "context_feedback action/signal must be one of: thumbs_up, thumbs_down, correct"
                .to_string(),
        )),
    }
}

fn corrected_content_argument(arguments: &Value, action: &str) -> Result<Option<String>, CliError> {
    let corrected_content = optional_string_argument(arguments, "corrected_content")?;
    if action == "correct" && corrected_content.is_none() {
        return Err(CliError::user(
            "context_feedback action 'correct' requires 'corrected_content'".to_string(),
        ));
    }
    Ok(corrected_content)
}

fn insert_optional_string_field(target: &mut Map<String, Value>, value: &Value, key: &str) {
    if let Some(text) = optional_output_string(value, key) {
        target.insert(key.to_string(), Value::String(text));
    }
}

fn required_string_argument(arguments: &Value, key: &str) -> Result<String, CliError> {
    optional_string_argument(arguments, key)?
        .ok_or_else(|| CliError::user(format!("context_feedback requires '{key}' parameter")))
}

fn optional_string_argument(arguments: &Value, key: &str) -> Result<Option<String>, CliError> {
    let Some(value) = arguments.get(key) else {
        return Ok(None);
    };
    let text = value
        .as_str()
        .ok_or_else(|| CliError::user(format!("context_feedback '{key}' must be a string")))?;
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

fn integer_field(value: &Value, key: &str) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(0)
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
