// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP tool: context_flag

use serde_json::{Map, Value};

use super::ToolContext;
use crate::error::CliError;

pub(crate) fn definition() -> Value {
    serde_json::json!({
        "name": "context_flag",
        "description": "Record a flag, dispute, or verification vote for one shared context document.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "document_id": {
                    "type": "string",
                    "description": "Context document id returned from context_search, context_recent, or schema_lookup."
                },
                "action": {
                    "type": "string",
                    "description": "One of: flag, dispute, verify."
                },
                "notes": {
                    "type": "string",
                    "description": "Optional reviewer note about the flag or verification."
                }
            },
            "required": ["document_id", "action"]
        }
    })
}

pub(crate) async fn execute(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let document_id = required_string_argument(arguments, "document_id")?;
    let action = action_argument(arguments)?;
    let notes = optional_string_argument(arguments, "notes")?;

    let mut body = Map::new();
    body.insert(
        "document_id".to_string(),
        Value::String(document_id.clone()),
    );
    body.insert("action".to_string(), Value::String(action.clone()));
    if let Some(value) = notes.clone() {
        body.insert("notes".to_string(), Value::String(value));
    }

    tracing::debug!(
        document_id = %document_id,
        action = %action,
        "recording context-fabric flag via MCP"
    );

    let response = ctx
        .client
        .post_json_value("/v1/context/flag", &Value::Object(body))
        .await?;

    Ok(serde_json::json!({
        "tool_name": "context_flag",
        "status": "ok",
        "document_id": string_field(&response, "document_id"),
        "action": action,
        "recorded_feedback": normalize_feedback_record(response.get("recorded_feedback")),
        "summary": normalize_summary(response.get("summary")),
        "document_updates": normalize_document_updates(response.get("document_updates")),
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

fn action_argument(arguments: &Value) -> Result<String, CliError> {
    match required_string_argument(arguments, "action")?.as_str() {
        "flag" | "flagged" => Ok("flag".to_string()),
        "dispute" | "disputed" => Ok("dispute".to_string()),
        "verify" | "verified" => Ok("verify".to_string()),
        _ => Err(CliError::user(
            "context_flag 'action' must be one of: flag, dispute, verify".to_string(),
        )),
    }
}

fn required_string_argument(arguments: &Value, key: &str) -> Result<String, CliError> {
    optional_string_argument(arguments, key)?
        .ok_or_else(|| CliError::user(format!("context_flag requires '{key}' parameter")))
}

fn optional_string_argument(arguments: &Value, key: &str) -> Result<Option<String>, CliError> {
    let Some(value) = arguments.get(key) else {
        return Ok(None);
    };
    let text = value
        .as_str()
        .ok_or_else(|| CliError::user(format!("context_flag '{key}' must be a string")))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed.to_string()))
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
