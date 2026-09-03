// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use bytes::Bytes;
use serde_json::Value;

pub(crate) fn stream_requested(value: &Value) -> bool {
    value
        .get("stream")
        .and_then(|candidate| candidate.as_bool())
        .unwrap_or(false)
}

pub(crate) fn disable_stream_flag(value: &mut Value) {
    if let Some(object) = value.as_object_mut() {
        object.insert("stream".to_string(), Value::Bool(false));
    }
}

pub fn chat_completion_json_to_sse(response_bytes: &[u8], include_usage: bool) -> Option<Bytes> {
    let response: Value = serde_json::from_slice(response_bytes).ok()?;
    let id = response
        .get("id")
        .and_then(|value| value.as_str())
        .unwrap_or("chatcmpl-verdictan");
    let created = response
        .get("created")
        .cloned()
        .unwrap_or_else(|| serde_json::json!(chrono::Utc::now().timestamp()));
    let model = response
        .get("model")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");

    let choices = response.get("choices")?.as_array()?;
    let usage = response.get("usage").cloned();
    let mut frames = String::new();

    for choice in choices {
        let index = choice
            .get("index")
            .and_then(|value| value.as_i64())
            .unwrap_or(0);
        let content = choice
            .get("message")
            .and_then(|message| message.get("content"))
            .and_then(|value| value.as_str())
            .unwrap_or("");

        let tool_calls = choice
            .get("message")
            .and_then(|message| message.get("tool_calls"))
            .and_then(|v| v.as_array());

        let has_tool_calls = tool_calls.is_some_and(|tc| !tc.is_empty());

        // Emit content delta when content is non-empty.
        if !content.is_empty() {
            let chunk = serde_json::json!({
                "id": id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [{
                    "index": index,
                    "delta": {
                        "role": "assistant",
                        "content": content,
                    },
                    "finish_reason": Value::Null,
                }]
            });
            frames.push_str("data: ");
            frames.push_str(&chunk.to_string());
            frames.push_str("\n\n");
        }

        // Emit tool-call delta frames when tool_calls are present.
        if let Some(tc_array) = tool_calls {
            for (tc_idx, tc) in tc_array.iter().enumerate() {
                let tc_chunk = serde_json::json!({
                    "id": id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{
                        "index": index,
                        "delta": {
                            "tool_calls": [{
                                "index": tc_idx,
                                "id": tc.get("id").cloned().unwrap_or(Value::Null),
                                "type": "function",
                                "function": {
                                    "name": tc.pointer("/function/name").cloned().unwrap_or(Value::Null),
                                    "arguments": tc.pointer("/function/arguments").cloned().unwrap_or(Value::String(String::new())),
                                }
                            }]
                        },
                        "finish_reason": Value::Null,
                    }]
                });
                frames.push_str("data: ");
                frames.push_str(&tc_chunk.to_string());
                frames.push_str("\n\n");
            }
        }

        // Emit the finish frame.
        let finish_reason = if has_tool_calls {
            Value::String("tool_calls".to_string())
        } else {
            choice
                .get("finish_reason")
                .cloned()
                .unwrap_or_else(|| Value::String("stop".to_string()))
        };
        let stop = serde_json::json!({
            "id": id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{
                "index": index,
                "delta": {},
                "finish_reason": finish_reason,
            }]
        });
        frames.push_str("data: ");
        frames.push_str(&stop.to_string());
        frames.push_str("\n\n");
    }

    // Emit usage-only chunk when requested and usage data is available.
    if include_usage {
        if let Some(ref u) = usage {
            let has_all = u.get("prompt_tokens").is_some()
                && u.get("completion_tokens").is_some()
                && u.get("total_tokens").is_some();
            if has_all {
                let usage_chunk = serde_json::json!({
                    "id": id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [],
                    "usage": {
                        "prompt_tokens": u["prompt_tokens"],
                        "completion_tokens": u["completion_tokens"],
                        "total_tokens": u["total_tokens"],
                    }
                });
                frames.push_str("data: ");
                frames.push_str(&usage_chunk.to_string());
                frames.push_str("\n\n");
            }
        }
    }

    frames.push_str("data: [DONE]\n\n");
    Some(Bytes::from(frames))
}

pub fn responses_json_to_sse(response_bytes: &[u8]) -> Option<Bytes> {
    let response: Value = serde_json::from_slice(response_bytes).ok()?;
    let id = response
        .get("id")
        .and_then(|value| value.as_str())
        .unwrap_or("resp_verdictan");
    let mut frames = String::new();

    if let Some(text) = response.get("output").and_then(|value| value.as_str()) {
        if !text.is_empty() {
            let chunk = serde_json::json!({
                "type": "response.output_text.delta",
                "response_id": id,
                "delta": text,
            });
            frames.push_str("data: ");
            frames.push_str(&chunk.to_string());
            frames.push_str("\n\n");
        }

        let completed = serde_json::json!({
            "type": "response.completed",
            "response_id": id,
        });
        frames.push_str("data: ");
        frames.push_str(&completed.to_string());
        frames.push_str("\n\n");
        frames.push_str("data: [DONE]\n\n");
        return Some(Bytes::from(frames));
    }

    let output = response.get("output")?.as_array()?;
    for item in output {
        if item.get("type").and_then(|value| value.as_str()) != Some("message") {
            continue;
        }
        let Some(content) = item.get("content").and_then(|value| value.as_array()) else {
            continue;
        };
        for part in content {
            if part.get("type").and_then(|value| value.as_str()) != Some("output_text") {
                continue;
            }
            let text = part
                .get("text")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            if text.is_empty() {
                continue;
            }
            let chunk = serde_json::json!({
                "type": "response.output_text.delta",
                "response_id": id,
                "delta": text,
            });
            frames.push_str("data: ");
            frames.push_str(&chunk.to_string());
            frames.push_str("\n\n");
        }
    }

    let completed = serde_json::json!({
        "type": "response.completed",
        "response_id": id,
    });
    frames.push_str("data: ");
    frames.push_str(&completed.to_string());
    frames.push_str("\n\n");
    frames.push_str("data: [DONE]\n\n");
    Some(Bytes::from(frames))
}

pub fn drain_sse_data_frames(buffer: &mut Vec<u8>) -> Vec<String> {
    let mut frames = Vec::new();

    while let Some(index) = find_frame_boundary(buffer) {
        let frame = buffer.drain(..index + 2).collect::<Vec<_>>();
        let payload = parse_sse_data_frame(&frame);
        if let Some(payload) = payload {
            frames.push(payload);
        }
    }

    frames
}

pub(crate) fn drain_json_line_frames(buffer: &mut Vec<u8>) -> Vec<String> {
    let mut frames = Vec::new();

    while let Some(index) = buffer.iter().position(|byte| *byte == b'\n') {
        let line = buffer.drain(..=index).collect::<Vec<_>>();
        let payload = String::from_utf8_lossy(&line).trim().to_string();
        if !payload.is_empty() {
            frames.push(payload);
        }
    }

    frames
}

pub(crate) fn ollama_chat_json_to_sse(
    payload: &str,
    response_id: &str,
    created: i64,
) -> Option<Bytes> {
    let value = serde_json::from_str::<Value>(payload).ok()?;
    let model = value
        .get("model")
        .and_then(|candidate| candidate.as_str())
        .unwrap_or("ollama");
    let mut frames = String::new();

    if let Some(content) = value
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(|candidate| candidate.as_str())
        .filter(|candidate| !candidate.is_empty())
    {
        let chunk = serde_json::json!({
            "id": response_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{
                "index": 0,
                "delta": {
                    "role": "assistant",
                    "content": content,
                },
                "finish_reason": Value::Null,
            }]
        });
        frames.push_str("data: ");
        frames.push_str(&chunk.to_string());
        frames.push_str("\n\n");
    }

    if value.get("done").and_then(|candidate| candidate.as_bool()) == Some(true) {
        let stop = serde_json::json!({
            "id": response_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": value
                    .get("done_reason")
                    .cloned()
                    .unwrap_or_else(|| Value::String("stop".to_string())),
            }]
        });
        frames.push_str("data: ");
        frames.push_str(&stop.to_string());
        frames.push_str("\n\n");
        frames.push_str("data: [DONE]\n\n");
    }

    if frames.is_empty() {
        return None;
    }

    Some(Bytes::from(frames))
}

pub(crate) fn accumulate_chat_completion_delta(
    payload: &str,
    content: &mut String,
    finish_reason: &mut Option<String>,
) {
    if payload == "[DONE]" {
        return;
    }

    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return;
    };
    let Some(choices) = value
        .get("choices")
        .and_then(|candidate| candidate.as_array())
    else {
        return;
    };

    for choice in choices {
        if let Some(text) = choice
            .get("delta")
            .and_then(|delta| delta.get("content"))
            .and_then(|candidate| candidate.as_str())
        {
            content.push_str(text);
        }

        if let Some(value) = choice
            .get("finish_reason")
            .and_then(|candidate| candidate.as_str())
        {
            *finish_reason = Some(value.to_string());
        }
    }
}

pub(crate) fn accumulate_chat_completion_delta_stats(
    payload: &str,
    output_chars: &mut usize,
    finish_reason: &mut Option<String>,
) {
    if payload == "[DONE]" {
        return;
    }

    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return;
    };
    let Some(choices) = value
        .get("choices")
        .and_then(|candidate| candidate.as_array())
    else {
        return;
    };

    for choice in choices {
        if let Some(text) = choice
            .get("delta")
            .and_then(|delta| delta.get("content"))
            .and_then(|candidate| candidate.as_str())
        {
            *output_chars += text.chars().count();
        }

        if let Some(value) = choice
            .get("finish_reason")
            .and_then(|candidate| candidate.as_str())
        {
            *finish_reason = Some(value.to_string());
        }
    }
}

pub(crate) fn accumulate_responses_delta(
    payload: &str,
    content: &mut String,
    finish_reason: &mut Option<String>,
) {
    if payload == "[DONE]" {
        return;
    }

    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return;
    };

    match value.get("type").and_then(|candidate| candidate.as_str()) {
        Some("response.output_text.delta") => {
            if let Some(text) = value.get("delta").and_then(|candidate| candidate.as_str()) {
                content.push_str(text);
            }
        }
        Some("response.output_text.done") => {
            if let Some(text) = value.get("text").and_then(|candidate| candidate.as_str()) {
                content.push_str(text);
            }
        }
        Some("response.completed") => {
            *finish_reason = Some("stop".to_string());
        }
        _ => {}
    }
}

pub(crate) fn accumulate_responses_delta_stats(
    payload: &str,
    output_chars: &mut usize,
    finish_reason: &mut Option<String>,
) {
    if payload == "[DONE]" {
        return;
    }

    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return;
    };

    match value.get("type").and_then(|candidate| candidate.as_str()) {
        Some("response.output_text.delta") => {
            if let Some(text) = value.get("delta").and_then(|candidate| candidate.as_str()) {
                *output_chars += text.chars().count();
            }
        }
        Some("response.output_text.done") => {
            if let Some(text) = value.get("text").and_then(|candidate| candidate.as_str()) {
                *output_chars += text.chars().count();
            }
        }
        Some("response.completed") => {
            *finish_reason = Some("stop".to_string());
        }
        _ => {}
    }
}

pub(crate) fn accumulate_messages_delta(
    payload: &str,
    content: &mut String,
    finish_reason: &mut Option<String>,
) {
    if payload == "[DONE]" {
        return;
    }

    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return;
    };

    match value.get("type").and_then(|candidate| candidate.as_str()) {
        Some("content_block_delta") => {
            if value
                .pointer("/delta/type")
                .and_then(|candidate| candidate.as_str())
                == Some("text_delta")
            {
                if let Some(text) = value
                    .pointer("/delta/text")
                    .and_then(|candidate| candidate.as_str())
                {
                    content.push_str(text);
                }
            }
        }
        Some("message_delta") => {
            if let Some(reason) = value
                .pointer("/delta/stop_reason")
                .and_then(|candidate| candidate.as_str())
            {
                *finish_reason = Some(match reason {
                    "end_turn" | "stop_sequence" => "stop".to_string(),
                    "tool_use" => "tool_calls".to_string(),
                    other => other.to_string(),
                });
            }
        }
        Some("message_stop") if finish_reason.is_none() => {
            *finish_reason = Some("stop".to_string());
        }
        _ => {}
    }
}

/// Request-family surface used when extracting SSE semantic units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamingFamily {
    ChatCompletions,
    Responses,
    Messages,
}

/// Minimum complete semantic unit extracted from one finished SSE data payload.
///
/// Output policies evaluate these units (or an aggregation of them) before any
/// client emission. Incomplete SSE frames remain in the byte buffer and are not
/// returned by [`drain_sse_data_frames`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseSemanticUnit {
    pub family: StreamingFamily,
    pub payload: String,
    pub text_delta: String,
    pub is_terminal: bool,
    pub finish_reason: Option<String>,
}

impl SseSemanticUnit {
    pub fn has_text(&self) -> bool {
        !self.text_delta.is_empty()
    }
}

/// Extract the minimum complete semantic unit carried by one SSE data payload.
///
/// Returns `None` for non-JSON / control-only payloads that carry no governance
/// signal (callers may still forward control frames under passthrough mode).
pub fn extract_sse_semantic_unit(
    family: StreamingFamily,
    payload: &str,
) -> Option<SseSemanticUnit> {
    if payload == "[DONE]" {
        return Some(SseSemanticUnit {
            family,
            payload: payload.to_string(),
            text_delta: String::new(),
            is_terminal: true,
            finish_reason: Some("stop".to_string()),
        });
    }

    let value = serde_json::from_str::<Value>(payload).ok()?;
    match family {
        StreamingFamily::ChatCompletions => {
            let mut text_delta = String::new();
            let mut finish_reason = None;
            let choices = value
                .get("choices")
                .and_then(|candidate| candidate.as_array())?;
            for choice in choices {
                if let Some(text) = choice
                    .get("delta")
                    .and_then(|delta| delta.get("content"))
                    .and_then(|candidate| candidate.as_str())
                {
                    text_delta.push_str(text);
                }
                if let Some(reason) = choice
                    .get("finish_reason")
                    .and_then(|candidate| candidate.as_str())
                {
                    finish_reason = Some(reason.to_string());
                }
            }
            Some(SseSemanticUnit {
                family,
                payload: payload.to_string(),
                text_delta,
                is_terminal: finish_reason.is_some(),
                finish_reason,
            })
        }
        StreamingFamily::Responses => {
            let event_type = value.get("type").and_then(|candidate| candidate.as_str())?;
            match event_type {
                "response.output_text.delta" => {
                    let text = value
                        .get("delta")
                        .and_then(|candidate| candidate.as_str())
                        .unwrap_or("")
                        .to_string();
                    Some(SseSemanticUnit {
                        family,
                        payload: payload.to_string(),
                        text_delta: text,
                        is_terminal: false,
                        finish_reason: None,
                    })
                }
                "response.output_text.done" => {
                    let text = value
                        .get("text")
                        .and_then(|candidate| candidate.as_str())
                        .unwrap_or("")
                        .to_string();
                    Some(SseSemanticUnit {
                        family,
                        payload: payload.to_string(),
                        text_delta: text,
                        is_terminal: false,
                        finish_reason: None,
                    })
                }
                "response.completed" => Some(SseSemanticUnit {
                    family,
                    payload: payload.to_string(),
                    text_delta: String::new(),
                    is_terminal: true,
                    finish_reason: Some("stop".to_string()),
                }),
                _ => Some(SseSemanticUnit {
                    family,
                    payload: payload.to_string(),
                    text_delta: String::new(),
                    is_terminal: false,
                    finish_reason: None,
                }),
            }
        }
        StreamingFamily::Messages => {
            let event_type = value.get("type").and_then(|candidate| candidate.as_str())?;
            match event_type {
                "content_block_delta" => {
                    let text = if value
                        .pointer("/delta/type")
                        .and_then(|candidate| candidate.as_str())
                        == Some("text_delta")
                    {
                        value
                            .pointer("/delta/text")
                            .and_then(|candidate| candidate.as_str())
                            .unwrap_or("")
                            .to_string()
                    } else {
                        String::new()
                    };
                    Some(SseSemanticUnit {
                        family,
                        payload: payload.to_string(),
                        text_delta: text,
                        is_terminal: false,
                        finish_reason: None,
                    })
                }
                "message_delta" => {
                    let finish_reason = value
                        .pointer("/delta/stop_reason")
                        .and_then(|candidate| candidate.as_str())
                        .map(|reason| match reason {
                            "end_turn" | "stop_sequence" => "stop".to_string(),
                            "tool_use" => "tool_calls".to_string(),
                            other => other.to_string(),
                        });
                    Some(SseSemanticUnit {
                        family,
                        payload: payload.to_string(),
                        text_delta: String::new(),
                        is_terminal: finish_reason.is_some(),
                        finish_reason,
                    })
                }
                "message_stop" => Some(SseSemanticUnit {
                    family,
                    payload: payload.to_string(),
                    text_delta: String::new(),
                    is_terminal: true,
                    finish_reason: Some("stop".to_string()),
                }),
                _ => Some(SseSemanticUnit {
                    family,
                    payload: payload.to_string(),
                    text_delta: String::new(),
                    is_terminal: false,
                    finish_reason: None,
                }),
            }
        }
    }
}

/// Wrap a JSON payload as one complete SSE data frame (semantic emission unit).
pub fn encode_sse_data_frame(payload: &str) -> Bytes {
    Bytes::from(format!("data: {payload}\n\n"))
}

/// Rebuild a Messages-family SSE stream from fully evaluated assistant text.
pub fn messages_text_to_sse(message_id: &str, content: &str, stop_reason: &str) -> Bytes {
    let mut frames = String::new();
    let start = serde_json::json!({
        "type": "content_block_start",
        "index": 0,
        "content_block": { "type": "text", "text": "" },
    });
    frames.push_str("data: ");
    frames.push_str(&start.to_string());
    frames.push_str("\n\n");

    if !content.is_empty() {
        let delta = serde_json::json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": { "type": "text_delta", "text": content },
            "message_id": message_id,
        });
        frames.push_str("data: ");
        frames.push_str(&delta.to_string());
        frames.push_str("\n\n");
    }

    let stop = serde_json::json!({
        "type": "content_block_stop",
        "index": 0,
    });
    frames.push_str("data: ");
    frames.push_str(&stop.to_string());
    frames.push_str("\n\n");

    let message_delta = serde_json::json!({
        "type": "message_delta",
        "delta": { "stop_reason": stop_reason, "stop_sequence": Value::Null },
    });
    frames.push_str("data: ");
    frames.push_str(&message_delta.to_string());
    frames.push_str("\n\n");

    frames.push_str("data: {\"type\":\"message_stop\"}\n\n");
    Bytes::from(frames)
}

/// Rewrite text inside a chat-completions SSE payload, preserving envelope fields.
pub fn rewrite_chat_completion_delta_text(payload: &str, replacement: &str) -> Option<String> {
    let mut value = serde_json::from_str::<Value>(payload).ok()?;
    let choices = value.get_mut("choices")?.as_array_mut()?;
    for choice in choices {
        if let Some(delta) = choice
            .get_mut("delta")
            .and_then(|candidate| candidate.as_object_mut())
        {
            if delta.contains_key("content") {
                delta.insert(
                    "content".to_string(),
                    Value::String(replacement.to_string()),
                );
            }
        }
    }
    Some(value.to_string())
}

/// Rewrite text inside a responses SSE delta payload.
pub fn rewrite_responses_delta_text(payload: &str, replacement: &str) -> Option<String> {
    let mut value = serde_json::from_str::<Value>(payload).ok()?;
    match value.get("type").and_then(|candidate| candidate.as_str()) {
        Some("response.output_text.delta") => {
            value
                .as_object_mut()?
                .insert("delta".to_string(), Value::String(replacement.to_string()));
            Some(value.to_string())
        }
        Some("response.output_text.done") => {
            value
                .as_object_mut()?
                .insert("text".to_string(), Value::String(replacement.to_string()));
            Some(value.to_string())
        }
        _ => None,
    }
}

/// Rewrite text inside a Messages SSE content_block_delta payload.
pub fn rewrite_messages_delta_text(payload: &str, replacement: &str) -> Option<String> {
    let mut value = serde_json::from_str::<Value>(payload).ok()?;
    if value.get("type").and_then(|candidate| candidate.as_str()) != Some("content_block_delta") {
        return None;
    }
    let delta = value.get_mut("delta")?.as_object_mut()?;
    if delta.get("type").and_then(|candidate| candidate.as_str()) != Some("text_delta") {
        return None;
    }
    delta.insert("text".to_string(), Value::String(replacement.to_string()));
    Some(value.to_string())
}

fn find_frame_boundary(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|window| window == b"\n\n")
}

fn parse_sse_data_frame(frame: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(frame).ok()?;
    let mut payload_lines = Vec::new();

    for line in text.lines() {
        if let Some(value) = line.strip_prefix("data:") {
            payload_lines.push(value.trim().to_string());
        }
    }

    if payload_lines.is_empty() {
        None
    } else {
        Some(payload_lines.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        dead_code,
        clippy::approx_constant,
        clippy::assertions_on_constants,
        clippy::assign_op_pattern,
        clippy::await_holding_lock,
        clippy::bool_assert_comparison,
        clippy::clone_on_copy,
        clippy::cloned_ref_to_slice_refs,
        clippy::const_is_empty,
        clippy::derivable_impls,
        clippy::err_expect,
        clippy::expect_fun_call,
        clippy::expect_used,
        clippy::field_reassign_with_default,
        clippy::large_enum_variant,
        clippy::len_zero,
        clippy::manual_contains,
        clippy::manual_range_contains,
        clippy::needless_borrow,
        clippy::needless_borrows_for_generic_args,
        clippy::panic,
        clippy::print_stderr,
        clippy::type_complexity,
        clippy::unnecessary_literal_unwrap,
        clippy::unnecessary_map_or,
        clippy::unwrap_used,
        clippy::useless_conversion,
        clippy::useless_vec,
        unused_imports,
        unused_macros,
        unused_mut,
        unused_variables,
        clippy::nonminimal_bool,
        clippy::overly_complex_bool_expr,
        clippy::needless_update,
        clippy::unnecessary_get_then_check
    )]
    use super::*;
    fn accumulate_messages_delta_stats(
        payload: &str,
        output_chars: &mut usize,
        finish_reason: &mut Option<String>,
    ) {
        if payload == "[DONE]" {
            return;
        }

        let Ok(value) = serde_json::from_str::<Value>(payload) else {
            return;
        };

        match value.get("type").and_then(|candidate| candidate.as_str()) {
            Some("content_block_delta") => {
                if value
                    .pointer("/delta/type")
                    .and_then(|candidate| candidate.as_str())
                    == Some("text_delta")
                {
                    if let Some(text) = value
                        .pointer("/delta/text")
                        .and_then(|candidate| candidate.as_str())
                    {
                        *output_chars += text.chars().count();
                    }
                }
            }
            Some("message_delta") => {
                if let Some(reason) = value
                    .pointer("/delta/stop_reason")
                    .and_then(|candidate| candidate.as_str())
                {
                    *finish_reason = Some(match reason {
                        "end_turn" | "stop_sequence" => "stop".to_string(),
                        "tool_use" => "tool_calls".to_string(),
                        other => other.to_string(),
                    });
                }
            }
            Some("message_stop") => {
                if finish_reason.is_none() {
                    *finish_reason = Some("stop".to_string());
                }
            }
            _ => {}
        }
    }

    use serde_json::json;

    fn parse_frames(bytes: Bytes) -> Vec<String> {
        let mut buffer = bytes.to_vec();
        drain_sse_data_frames(&mut buffer)
    }

    #[test]
    fn stream_requested_and_disable_stream_flag_handle_object_inputs() {
        let mut enabled = json!({ "stream": true, "model": "gpt-4o" });
        assert!(stream_requested(&enabled));

        disable_stream_flag(&mut enabled);
        assert!(!stream_requested(&enabled));
        assert_eq!(enabled["stream"], Value::Bool(false));

        let mut non_object = Value::Null;
        disable_stream_flag(&mut non_object);
        assert_eq!(non_object, Value::Null);
    }

    #[test]
    fn chat_completion_json_to_sse_emits_content_finish_usage_and_done() {
        let frames = parse_frames(
            chat_completion_json_to_sse(
                serde_json::to_vec(&json!({
                    "id": "chat-1",
                    "created": 123,
                    "model": "gpt-4o-mini",
                    "choices": [{
                        "index": 0,
                        "message": { "content": "hello" },
                        "finish_reason": "stop"
                    }],
                    "usage": {
                        "prompt_tokens": 2,
                        "completion_tokens": 1,
                        "total_tokens": 3
                    }
                }))
                .expect("response bytes")
                .as_slice(),
                true,
            )
            .expect("sse bytes"),
        );

        assert_eq!(frames.len(), 4);
        assert_eq!(
            serde_json::from_str::<Value>(&frames[0]).expect("content frame")["choices"][0]
                ["delta"]["content"],
            Value::String("hello".to_string())
        );
        assert_eq!(
            serde_json::from_str::<Value>(&frames[1]).expect("finish frame")["choices"][0]
                ["finish_reason"],
            Value::String("stop".to_string())
        );
        assert_eq!(
            serde_json::from_str::<Value>(&frames[2]).expect("usage frame")["usage"]
                ["total_tokens"],
            Value::from(3)
        );
        assert_eq!(frames[3], "[DONE]");
    }

    #[test]
    fn chat_completion_json_to_sse_emits_tool_call_finish_reason() {
        let frames = parse_frames(
            chat_completion_json_to_sse(
                serde_json::to_vec(&json!({
                    "id": "chat-2",
                    "created": 456,
                    "model": "gpt-4o",
                    "choices": [{
                        "index": 1,
                        "message": {
                            "tool_calls": [{
                                "id": "call-1",
                                "function": {
                                    "name": "search_docs",
                                    "arguments": "{\"query\":\"verdictan\"}"
                                }
                            }]
                        },
                        "finish_reason": "stop"
                    }]
                }))
                .expect("response bytes")
                .as_slice(),
                false,
            )
            .expect("sse bytes"),
        );

        assert_eq!(frames.len(), 3);
        assert_eq!(
            serde_json::from_str::<Value>(&frames[0]).expect("tool frame")["choices"][0]["delta"]
                ["tool_calls"][0]["function"]["name"],
            Value::String("search_docs".to_string())
        );
        assert_eq!(
            serde_json::from_str::<Value>(&frames[1]).expect("finish frame")["choices"][0]
                ["finish_reason"],
            Value::String("tool_calls".to_string())
        );
        assert_eq!(frames[2], "[DONE]");
    }

    #[test]
    fn responses_json_to_sse_supports_string_and_message_outputs() {
        let string_frames = parse_frames(
            responses_json_to_sse(
                serde_json::to_vec(&json!({
                    "id": "resp-1",
                    "output": "hello"
                }))
                .expect("response bytes")
                .as_slice(),
            )
            .expect("string response"),
        );
        assert_eq!(string_frames.len(), 3);
        assert_eq!(
            serde_json::from_str::<Value>(&string_frames[0]).expect("delta frame")["delta"],
            Value::String("hello".to_string())
        );
        assert_eq!(string_frames[2], "[DONE]");

        let message_frames = parse_frames(
            responses_json_to_sse(
                serde_json::to_vec(&json!({
                    "id": "resp-2",
                    "output": [
                        { "type": "reasoning", "content": [] },
                        {
                            "type": "message",
                            "content": [
                                { "type": "output_text", "text": "alpha" },
                                { "type": "tool_call", "name": "ignored" },
                                { "type": "output_text", "text": "beta" }
                            ]
                        }
                    ]
                }))
                .expect("response bytes")
                .as_slice(),
            )
            .expect("message response"),
        );
        assert_eq!(message_frames.len(), 4);
        assert_eq!(
            serde_json::from_str::<Value>(&message_frames[0]).expect("first frame")["delta"],
            Value::String("alpha".to_string())
        );
        assert_eq!(
            serde_json::from_str::<Value>(&message_frames[1]).expect("second frame")["delta"],
            Value::String("beta".to_string())
        );
        assert_eq!(
            serde_json::from_str::<Value>(&message_frames[2]).expect("completed frame")["type"],
            Value::String("response.completed".to_string())
        );
        assert_eq!(message_frames[3], "[DONE]");
    }

    #[test]
    fn drain_helpers_extract_complete_frames_and_leave_partial_data() {
        let mut buffer = b"data: first\ndata: second\n\npartial".to_vec();
        let frames = drain_sse_data_frames(&mut buffer);
        assert_eq!(frames, vec!["first\nsecond"]);
        assert_eq!(buffer, b"partial");

        let mut jsonl = b"{\"a\":1}\n\n{\"b\":2}\ntrailing".to_vec();
        let lines = drain_json_line_frames(&mut jsonl);
        assert_eq!(lines, vec!["{\"a\":1}", "{\"b\":2}"]);
        assert_eq!(jsonl, b"trailing");
    }

    #[test]
    fn ollama_chat_json_to_sse_handles_delta_and_done_frames() {
        let delta_frames = parse_frames(
            ollama_chat_json_to_sse(
                r#"{"model":"llama3","message":{"content":"hello"},"done":false}"#,
                "resp-ollama",
                789,
            )
            .expect("delta frames"),
        );
        assert_eq!(delta_frames.len(), 1);
        assert_eq!(
            serde_json::from_str::<Value>(&delta_frames[0]).expect("delta frame")["choices"][0]
                ["delta"]["content"],
            Value::String("hello".to_string())
        );

        let done_frames = parse_frames(
            ollama_chat_json_to_sse(
                r#"{"model":"llama3","done":true,"done_reason":"length"}"#,
                "resp-ollama",
                789,
            )
            .expect("done frames"),
        );
        assert_eq!(done_frames.len(), 2);
        assert_eq!(
            serde_json::from_str::<Value>(&done_frames[0]).expect("finish frame")["choices"][0]
                ["finish_reason"],
            Value::String("length".to_string())
        );
        assert_eq!(done_frames[1], "[DONE]");
        assert!(ollama_chat_json_to_sse(r#"{"model":"llama3"}"#, "resp-ollama", 789).is_none());
    }

    #[test]
    fn delta_accumulators_collect_content_and_finish_reasons() {
        let mut content = String::new();
        let mut finish_reason = None;
        accumulate_chat_completion_delta(
            r#"{"choices":[{"delta":{"content":"hel"}},{"delta":{"content":"lo"},"finish_reason":"stop"}]}"#,
            &mut content,
            &mut finish_reason,
        );
        accumulate_chat_completion_delta("[DONE]", &mut content, &mut finish_reason);
        assert_eq!(content, "hello");
        assert_eq!(finish_reason.as_deref(), Some("stop"));

        let mut stats_chars = 0;
        let mut stats_finish = None;
        accumulate_chat_completion_delta_stats(
            r#"{"choices":[{"delta":{"content":"hi"}},{"finish_reason":"tool_calls"}]}"#,
            &mut stats_chars,
            &mut stats_finish,
        );
        assert_eq!(stats_chars, 2);
        assert_eq!(stats_finish.as_deref(), Some("tool_calls"));
    }

    #[test]
    fn response_and_message_accumulators_ignore_invalid_frames_and_map_reasons() {
        let mut response_content = String::new();
        let mut response_finish = None;
        accumulate_responses_delta(
            r#"{"type":"response.output_text.delta","delta":"alpha"}"#,
            &mut response_content,
            &mut response_finish,
        );
        accumulate_responses_delta(
            r#"{"type":"response.output_text.done","text":"beta"}"#,
            &mut response_content,
            &mut response_finish,
        );
        accumulate_responses_delta(
            r#"{"type":"response.completed"}"#,
            &mut response_content,
            &mut response_finish,
        );
        accumulate_responses_delta("not-json", &mut response_content, &mut response_finish);
        assert_eq!(response_content, "alphabeta");
        assert_eq!(response_finish.as_deref(), Some("stop"));

        let mut response_chars = 0;
        let mut response_stats_finish = None;
        accumulate_responses_delta_stats(
            r#"{"type":"response.output_text.delta","delta":"abc"}"#,
            &mut response_chars,
            &mut response_stats_finish,
        );
        accumulate_responses_delta_stats(
            r#"{"type":"response.output_text.done","text":"de"}"#,
            &mut response_chars,
            &mut response_stats_finish,
        );
        accumulate_responses_delta_stats(
            r#"{"type":"response.completed"}"#,
            &mut response_chars,
            &mut response_stats_finish,
        );
        assert_eq!(response_chars, 5);
        assert_eq!(response_stats_finish.as_deref(), Some("stop"));

        let mut message_chars = 0;
        let mut message_finish = None;
        accumulate_messages_delta_stats(
            r#"{"type":"content_block_delta","delta":{"type":"text_delta","text":"abc"}}"#,
            &mut message_chars,
            &mut message_finish,
        );
        accumulate_messages_delta_stats(
            r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"}}"#,
            &mut message_chars,
            &mut message_finish,
        );
        accumulate_messages_delta_stats(
            r#"{"type":"message_stop"}"#,
            &mut message_chars,
            &mut message_finish,
        );
        accumulate_messages_delta_stats("not-json", &mut message_chars, &mut message_finish);
        assert_eq!(message_chars, 3);
        assert_eq!(message_finish.as_deref(), Some("tool_calls"));

        let mut message_content = String::new();
        let mut message_content_finish = None;
        accumulate_messages_delta(
            r#"{"type":"content_block_delta","delta":{"type":"text_delta","text":"hi"}}"#,
            &mut message_content,
            &mut message_content_finish,
        );
        accumulate_messages_delta(
            r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"}}"#,
            &mut message_content,
            &mut message_content_finish,
        );
        assert_eq!(message_content, "hi");
        assert_eq!(message_content_finish.as_deref(), Some("stop"));
    }

    #[test]
    fn extract_sse_semantic_unit_buffers_only_complete_frames() {
        let mut buffer = b"data: {\"choices\":[{\"delta\":{\"content\":\"hel\"},\"finish_reason\":null}]}\n\n partial".to_vec();
        let frames = drain_sse_data_frames(&mut buffer);
        assert_eq!(frames.len(), 1);
        assert_eq!(buffer, b" partial");

        let unit = extract_sse_semantic_unit(StreamingFamily::ChatCompletions, &frames[0])
            .expect("chat unit");
        assert_eq!(unit.text_delta, "hel");
        assert!(!unit.is_terminal);

        let messages = extract_sse_semantic_unit(
            StreamingFamily::Messages,
            r#"{"type":"content_block_delta","delta":{"type":"text_delta","text":"abc"}}"#,
        )
        .expect("messages unit");
        assert_eq!(messages.text_delta, "abc");

        let terminal =
            extract_sse_semantic_unit(StreamingFamily::Responses, "[DONE]").expect("done unit");
        assert!(terminal.is_terminal);
    }

    #[test]
    fn rewrite_helpers_and_messages_text_to_sse_preserve_complete_units() {
        let rewritten = rewrite_chat_completion_delta_text(
            r#"{"choices":[{"delta":{"content":"secret"},"finish_reason":null}]}"#,
            "[REDACTED]",
        )
        .expect("rewrite chat");
        assert!(rewritten.contains("[REDACTED]"));
        assert!(!rewritten.contains("secret"));

        let responses = rewrite_responses_delta_text(
            r#"{"type":"response.output_text.delta","delta":"secret"}"#,
            "[REDACTED]",
        )
        .expect("rewrite responses");
        assert!(responses.contains("[REDACTED]"));

        let messages = rewrite_messages_delta_text(
            r#"{"type":"content_block_delta","delta":{"type":"text_delta","text":"secret"}}"#,
            "[REDACTED]",
        )
        .expect("rewrite messages");
        assert!(messages.contains("[REDACTED]"));

        let frames = parse_frames(messages_text_to_sse("msg_1", "hello", "end_turn"));
        assert!(frames.iter().any(|frame| frame.contains("hello")));
        assert!(frames.iter().any(|frame| frame.contains("message_stop")));
        assert_eq!(
            encode_sse_data_frame("{\"ok\":true}"),
            Bytes::from_static(b"data: {\"ok\":true}\n\n")
        );
    }
}
