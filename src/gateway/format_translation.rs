// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Phase 15 — Provider request/response format translation.
//!
//! Translates Chat Completions API (OpenAI wire format) to and from a small set
//! of provider-native request/response shapes.

use bytes::Bytes;
use serde_json::json;
use serde_json::Value;
use std::collections::BTreeMap;

use crate::error::CliError;

// ---------------------------------------------------------------------------
// ProviderFormat
// ---------------------------------------------------------------------------

/// The wire format a provider endpoint uses natively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFormat {
    OpenAI,
    Anthropic,
    Cohere,
    HuggingFace,
    Replicate,
    WatsonX,
    GoogleGemini,
    AWSBedrock,
}

impl ProviderFormat {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "openai" => Some(Self::OpenAI),
            "anthropic" => Some(Self::Anthropic),
            "cohere" => Some(Self::Cohere),
            "huggingface" => Some(Self::HuggingFace),
            "replicate" => Some(Self::Replicate),
            "watsonx" => Some(Self::WatsonX),
            "google-gemini" => Some(Self::GoogleGemini),
            "aws-bedrock" | "bedrock" => Some(Self::AWSBedrock),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenAI => "openai",
            Self::Anthropic => "anthropic",
            Self::Cohere => "cohere",
            Self::HuggingFace => "huggingface",
            Self::Replicate => "replicate",
            Self::WatsonX => "watsonx",
            Self::GoogleGemini => "google-gemini",
            Self::AWSBedrock => "aws-bedrock",
        }
    }
}

// ---------------------------------------------------------------------------
// Inference
// ---------------------------------------------------------------------------

/// Infer the wire format of an incoming request body by inspecting its shape.
///
/// Returns `Anthropic` only when a definitive Anthropic-API-specific field is
/// present (`anthropic_version`). Otherwise falls back to `OpenAI`.
pub fn infer_request_format(body: &Value) -> ProviderFormat {
    if body.get("anthropic_version").is_some() {
        return ProviderFormat::Anthropic;
    }
    if body.get("model_id").is_some() && body.get("input").is_some() {
        return ProviderFormat::WatsonX;
    }
    if body.get("contents").is_some() || body.get("systemInstruction").is_some() {
        return ProviderFormat::GoogleGemini;
    }
    if body.get("message").is_some() && body.get("chat_history").is_some() {
        return ProviderFormat::Cohere;
    }
    if body.get("inputs").is_some() {
        return ProviderFormat::HuggingFace;
    }
    if body.get("input").is_some() {
        if body.get("model").is_some()
            || body.get("instructions").is_some()
            || body.get("max_output_tokens").is_some()
            || body.get("response_format").is_some()
            || body.get("modalities").is_some()
            || body.get("text").is_some()
            || body.get("previous_response_id").is_some()
        {
            return ProviderFormat::OpenAI;
        }
        return ProviderFormat::Replicate;
    }
    ProviderFormat::OpenAI
}

/// Resolve the route-native request/response wire format expected by a public
/// gateway family path.
pub fn route_native_format(path: &str, body: &Value) -> ProviderFormat {
    match path {
        "/v1/messages" => ProviderFormat::Anthropic,
        "/v1/chat/completions"
        | "/v1/responses"
        | "/v1/embeddings"
        | "/v1/audio/transcriptions"
        | "/v1/audio/speech" => ProviderFormat::OpenAI,
        _ => infer_request_format(body),
    }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Translate a request body from `from` to `to` format.
/// Returns the original body unchanged when `from == to`.
pub fn translate_request(
    body: Value,
    from: ProviderFormat,
    to: ProviderFormat,
) -> Result<Value, CliError> {
    if from == to {
        return Ok(body);
    }
    match (from, to) {
        (ProviderFormat::OpenAI, ProviderFormat::Anthropic) => openai_to_anthropic_request(body),
        (ProviderFormat::OpenAI, ProviderFormat::Cohere) => openai_to_cohere_request(body),
        (ProviderFormat::OpenAI, ProviderFormat::HuggingFace) => {
            openai_to_huggingface_request(body)
        }
        (ProviderFormat::OpenAI, ProviderFormat::Replicate) => openai_to_replicate_request(body),
        (ProviderFormat::OpenAI, ProviderFormat::WatsonX) => openai_to_watsonx_request(body),
        (ProviderFormat::OpenAI, ProviderFormat::GoogleGemini) => {
            openai_to_google_gemini_request(body)
        }
        (ProviderFormat::Anthropic, ProviderFormat::OpenAI) => anthropic_to_openai_request(body),
        (ProviderFormat::Cohere, ProviderFormat::OpenAI) => cohere_to_openai_request(body),
        (ProviderFormat::HuggingFace, ProviderFormat::OpenAI) => {
            huggingface_to_openai_request(body)
        }
        (ProviderFormat::Replicate, ProviderFormat::OpenAI) => replicate_to_openai_request(body),
        (ProviderFormat::WatsonX, ProviderFormat::OpenAI) => watsonx_to_openai_request(body),
        (ProviderFormat::GoogleGemini, ProviderFormat::OpenAI) => {
            google_gemini_to_openai_request(body)
        }
        _ => Err(CliError::user(format!(
            "unsupported request translation from '{}' to '{}'",
            from.as_str(),
            to.as_str()
        ))),
    }
}

/// Translate a response body from `from` (provider native) back to `to` (client expected).
/// Returns the original body unchanged when `from == to`.
pub fn translate_response(
    body: Value,
    from: ProviderFormat,
    to: ProviderFormat,
) -> Result<Value, CliError> {
    if from == to {
        return Ok(body);
    }
    match (from, to) {
        (ProviderFormat::Anthropic, ProviderFormat::OpenAI) => anthropic_to_openai_response(body),
        (ProviderFormat::OpenAI, ProviderFormat::Anthropic) => openai_to_anthropic_response(body),
        (ProviderFormat::Cohere, ProviderFormat::OpenAI) => cohere_to_openai_response(body),
        (ProviderFormat::OpenAI, ProviderFormat::Cohere) => openai_to_cohere_response(body),
        (ProviderFormat::HuggingFace, ProviderFormat::OpenAI) => {
            huggingface_to_openai_response(body)
        }
        (ProviderFormat::OpenAI, ProviderFormat::HuggingFace) => {
            openai_to_huggingface_response(body)
        }
        (ProviderFormat::Replicate, ProviderFormat::OpenAI) => replicate_to_openai_response(body),
        (ProviderFormat::OpenAI, ProviderFormat::Replicate) => openai_to_replicate_response(body),
        (ProviderFormat::WatsonX, ProviderFormat::OpenAI) => watsonx_to_openai_response(body),
        (ProviderFormat::OpenAI, ProviderFormat::WatsonX) => openai_to_watsonx_response(body),
        (ProviderFormat::GoogleGemini, ProviderFormat::OpenAI) => {
            google_gemini_to_openai_response(body)
        }
        (ProviderFormat::OpenAI, ProviderFormat::GoogleGemini) => {
            openai_to_google_gemini_response(body)
        }
        _ => Err(CliError::user(format!(
            "unsupported response translation from '{}' to '{}'",
            from.as_str(),
            to.as_str()
        ))),
    }
}

/// Translate a provider-native response into the route-native JSON shape expected
/// by the public gateway family path.
pub fn translate_response_for_path(
    body: Value,
    from: ProviderFormat,
    path: &str,
) -> Result<Value, CliError> {
    match path {
        "/v1/chat/completions" => translate_response(body, from, ProviderFormat::OpenAI),
        "/v1/messages" => translate_response(body, from, ProviderFormat::Anthropic),
        "/v1/responses" => match from {
            ProviderFormat::Anthropic => anthropic_to_openai_responses_response(body),
            ProviderFormat::OpenAI => openai_chat_completion_to_responses_response(body),
            _ => {
                let openai = translate_response(body, from, ProviderFormat::OpenAI)?;
                openai_chat_completion_to_responses_response(openai)
            }
        },
        _ => Err(CliError::user(format!(
            "unsupported response path translation for '{path}'"
        ))),
    }
}

fn openai_messages(body: &Value) -> Vec<Value> {
    body.get("messages")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default()
}

fn message_text(message: &Value) -> String {
    if let Some(content) = message.get("content") {
        if let Some(text) = content.as_str() {
            return text.to_string();
        }
        if let Some(parts) = content.as_array() {
            return parts
                .iter()
                .filter_map(|part| {
                    part.get("text")
                        .and_then(|value| value.as_str())
                        .map(ToString::to_string)
                })
                .collect::<Vec<_>>()
                .join("\n");
        }
    }
    String::new()
}

fn latest_user_message(messages: &[Value]) -> String {
    messages
        .iter()
        .rev()
        .find(|message| message.get("role").and_then(|value| value.as_str()) == Some("user"))
        .map(message_text)
        .unwrap_or_default()
}

fn system_prompt(messages: &[Value]) -> Option<String> {
    let system = messages
        .iter()
        .filter(|message| message.get("role").and_then(|value| value.as_str()) == Some("system"))
        .map(message_text)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n");
    if system.is_empty() {
        None
    } else {
        Some(system)
    }
}

fn flattened_prompt(messages: &[Value]) -> String {
    messages
        .iter()
        .filter_map(|message| {
            let role = message.get("role").and_then(|value| value.as_str())?;
            let content = message_text(message);
            if content.is_empty() {
                None
            } else {
                Some(format!("{role}: {content}"))
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn openai_response_content(body: &Value) -> String {
    body.get("choices")
        .and_then(|value| value.as_array())
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .map(message_text)
        .unwrap_or_default()
}

fn openai_finish_reason(body: &Value) -> &str {
    body.get("choices")
        .and_then(|value| value.as_array())
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("finish_reason"))
        .and_then(|value| value.as_str())
        .unwrap_or("stop")
}

fn build_openai_response(model: Option<&str>, content: String, finish_reason: &str) -> Value {
    json!({
        "id": "verdictan-translated",
        "object": "chat.completion",
        "created": 0,
        "model": model.unwrap_or("translated-model"),
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": content,
            },
            "finish_reason": finish_reason,
        }],
    })
}

fn openai_chat_completion_to_responses_response(body: Value) -> Result<Value, CliError> {
    let model = body
        .get("model")
        .and_then(|value| value.as_str())
        .unwrap_or("translated-model")
        .to_string();
    let id = body
        .get("id")
        .and_then(|value| value.as_str())
        .unwrap_or("resp_unknown")
        .to_string();
    let choice = body
        .get("choices")
        .and_then(|value| value.as_array())
        .and_then(|choices| choices.first())
        .ok_or_else(|| CliError::user("OpenAI response is missing choices[0]"))?;
    let message = choice
        .get("message")
        .ok_or_else(|| CliError::user("OpenAI response is missing choices[0].message"))?;

    let mut output = Vec::new();
    let content = message_text(message);
    if !content.is_empty() {
        output.push(json!({
            "type": "message",
            "role": "assistant",
            "content": [{
                "type": "output_text",
                "text": content,
            }]
        }));
    }

    if let Some(tool_calls) = message.get("tool_calls").and_then(|value| value.as_array()) {
        for tool_call in tool_calls {
            let function = tool_call
                .get("function")
                .ok_or_else(|| CliError::user("OpenAI tool call is missing function"))?;
            let name = function
                .get("name")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let arguments = match function.get("arguments") {
                Some(Value::String(value)) => value.clone(),
                Some(value) => serde_json::to_string(value).map_err(|error| {
                    CliError::user(format!(
                        "failed to serialize OpenAI tool arguments: {error}"
                    ))
                })?,
                None => "{}".to_string(),
            };
            let call_id = tool_call
                .get("id")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            output.push(json!({
                "type": "function_call",
                "id": call_id,
                "call_id": call_id,
                "name": name,
                "arguments": arguments,
            }));
        }
    }

    if output.is_empty() {
        return Err(CliError::user(
            "OpenAI response did not include assistant content or tool calls",
        ));
    }

    Ok(json!({
        "id": id,
        "object": "response",
        "status": "completed",
        "model": model,
        "output": output,
        "usage": body.get("usage").cloned().unwrap_or_else(|| json!({})),
    }))
}

fn openai_to_cohere_request(body: Value) -> Result<Value, CliError> {
    let messages = body
        .get("messages")
        .and_then(|value| value.as_array())
        .cloned()
        .or_else(|| {
            body.get("input")
                .and_then(|value| value.as_array())
                .cloned()
        })
        .or_else(|| {
            body.get("input")
                .and_then(|value| value.as_str())
                .map(|text| vec![json!({ "role": "user", "content": text })])
        })
        .unwrap_or_default();

    let mut cohere_messages = Vec::new();
    for message in messages {
        let role = message
            .get("role")
            .and_then(|value| value.as_str())
            .unwrap_or("user");
        match role {
            "system" | "user" | "assistant" => {
                let mut mapped = serde_json::Map::new();
                mapped.insert("role".to_string(), json!(role));
                mapped.insert(
                    "content".to_string(),
                    message
                        .get("content")
                        .cloned()
                        .unwrap_or_else(|| json!(message_text(&message))),
                );
                if role == "assistant" {
                    if let Some(tool_calls) =
                        message.get("tool_calls").and_then(|value| value.as_array())
                    {
                        mapped.insert("tool_calls".to_string(), json!(tool_calls));
                    }
                }
                cohere_messages.push(Value::Object(mapped));
            }
            "tool" => {
                let content = match message.get("content") {
                    Some(Value::Array(items)) => Value::Array(items.clone()),
                    Some(Value::String(text)) => Value::Array(vec![json!({
                        "type": "document",
                        "document": { "data": text }
                    })]),
                    Some(other) => Value::Array(vec![json!({
                        "type": "document",
                        "document": { "data": other }
                    })]),
                    None => Value::Array(Vec::new()),
                };
                cohere_messages.push(json!({
                    "role": "tool",
                    "tool_call_id": message
                        .get("tool_call_id")
                        .and_then(|value| value.as_str())
                        .unwrap_or(""),
                    "content": content,
                }));
            }
            _ => {}
        }
    }

    let mut request = serde_json::Map::new();
    request.insert(
        "model".to_string(),
        body.get("model").cloned().unwrap_or_else(|| json!("")),
    );
    request.insert("messages".to_string(), Value::Array(cohere_messages));
    request.insert(
        "stream".to_string(),
        body.get("stream").cloned().unwrap_or(json!(false)),
    );
    for (source, target) in [
        ("max_tokens", "max_tokens"),
        ("max_completion_tokens", "max_tokens"),
        ("temperature", "temperature"),
        ("top_p", "top_p"),
        ("presence_penalty", "presence_penalty"),
        ("frequency_penalty", "frequency_penalty"),
        ("seed", "seed"),
        ("response_format", "response_format"),
    ] {
        if let Some(value) = body.get(source).cloned() {
            request.insert(target.to_string(), value);
        }
    }
    if let Some(stop) = body.get("stop").cloned() {
        request.insert("stop_sequences".to_string(), stop);
    }
    if let Some(tools) = body.get("tools").cloned() {
        request.insert("tools".to_string(), tools);
    }
    if let Some(tool_choice) = body.get("tool_choice") {
        match tool_choice.as_str() {
            Some(value) => {
                request.insert("tool_choice".to_string(), json!(value));
                if value == "required" {
                    request.insert("strict_tools".to_string(), json!(true));
                }
            }
            None => {
                request.insert("tool_choice".to_string(), tool_choice.clone());
                request.insert("strict_tools".to_string(), json!(true));
            }
        }
    }

    Ok(Value::Object(request))
}

fn cohere_to_openai_request(body: Value) -> Result<Value, CliError> {
    let mut messages = Vec::new();
    if let Some(native_messages) = body.get("messages").and_then(|value| value.as_array()) {
        for item in native_messages {
            let role = item
                .get("role")
                .and_then(|value| value.as_str())
                .unwrap_or("user");
            let mut mapped = serde_json::Map::new();
            mapped.insert("role".to_string(), json!(role));
            mapped.insert(
                "content".to_string(),
                item.get("content")
                    .cloned()
                    .unwrap_or_else(|| json!(message_text(item))),
            );
            if let Some(tool_calls) = item.get("tool_calls").cloned() {
                mapped.insert("tool_calls".to_string(), tool_calls);
            }
            if let Some(tool_call_id) = item.get("tool_call_id").cloned() {
                mapped.insert("tool_call_id".to_string(), tool_call_id);
            }
            messages.push(Value::Object(mapped));
        }
    }
    Ok(json!({
        "model": body.get("model").cloned().unwrap_or_else(|| json!("")),
        "messages": messages,
        "max_tokens": body.get("max_tokens").cloned(),
        "temperature": body.get("temperature").cloned(),
        "top_p": body.get("top_p").cloned(),
        "stream": body.get("stream").cloned().unwrap_or(json!(false)),
    }))
}

fn cohere_to_openai_response(body: Value) -> Result<Value, CliError> {
    let message = body
        .get("message")
        .ok_or_else(|| CliError::user("cohere response is missing message"))?;
    let content = match message.get("content") {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.get("text").and_then(|value| value.as_str()))
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    };
    let tool_calls = message
        .get("tool_calls")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    if content.is_empty() && tool_calls.is_empty() {
        return Err(CliError::user(
            "cohere response did not include assistant content or tool calls",
        ));
    }

    let finish_reason = body
        .get("finish_reason")
        .and_then(|value| value.as_str())
        .unwrap_or(if tool_calls.is_empty() {
            "stop"
        } else {
            "tool_calls"
        });
    let model = body
        .get("model")
        .and_then(|value| value.as_str())
        .unwrap_or("cohere");
    let mut response = build_openai_response(Some(model), content, finish_reason);
    if let Some(choice_message) = response.pointer_mut("/choices/0/message") {
        if let Some(object) = choice_message.as_object_mut() {
            if !tool_calls.is_empty() {
                let mapped = tool_calls
                    .iter()
                    .map(|tool_call| {
                        json!({
                            "id": tool_call.get("id").and_then(|value| value.as_str()).unwrap_or(""),
                            "type": tool_call.get("type").and_then(|value| value.as_str()).unwrap_or("function"),
                            "function": {
                                "name": tool_call.pointer("/function/name").and_then(|value| value.as_str()).unwrap_or(""),
                                "arguments": match tool_call.pointer("/function/arguments") {
                                    Some(Value::String(value)) => Value::String(value.clone()),
                                    Some(value) => Value::String(serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string())),
                                    None => Value::String("{}".to_string()),
                                },
                            }
                        })
                    })
                    .collect::<Vec<_>>();
                object.insert("tool_calls".to_string(), Value::Array(mapped));
            }
        }
    }

    let usage = body
        .get("usage")
        .cloned()
        .or_else(|| {
            body.pointer("/meta/billed_units").map(|usage| {
                json!({
                    "prompt_tokens": usage.get("input_tokens").and_then(|value| value.as_u64()).unwrap_or(0),
                    "completion_tokens": usage.get("output_tokens").and_then(|value| value.as_u64()).unwrap_or(0),
                    "total_tokens": usage
                        .get("input_tokens")
                        .and_then(|value| value.as_u64())
                        .unwrap_or(0)
                        + usage.get("output_tokens").and_then(|value| value.as_u64()).unwrap_or(0),
                })
            })
        })
        .or_else(|| {
            body.pointer("/usage/tokens").map(|usage| {
                json!({
                    "prompt_tokens": usage.get("input_tokens").and_then(|value| value.as_u64()).unwrap_or(0),
                    "completion_tokens": usage.get("output_tokens").and_then(|value| value.as_u64()).unwrap_or(0),
                    "total_tokens": usage.get("total_tokens").and_then(|value| value.as_u64()).unwrap_or(
                        usage.get("input_tokens").and_then(|value| value.as_u64()).unwrap_or(0)
                            + usage.get("output_tokens").and_then(|value| value.as_u64()).unwrap_or(0)
                    ),
                })
            })
        });
    if let Some(usage) = usage {
        response["usage"] = usage;
    }
    Ok(response)
}

fn openai_to_cohere_response(body: Value) -> Result<Value, CliError> {
    Ok(json!({
        "text": openai_response_content(&body),
        "finish_reason": openai_finish_reason(&body),
    }))
}

fn openai_to_huggingface_request(body: Value) -> Result<Value, CliError> {
    let messages = openai_messages(&body);
    Ok(json!({
        "inputs": flattened_prompt(&messages),
        "parameters": {
            "max_new_tokens": body.get("max_tokens").or_else(|| body.get("max_completion_tokens")).cloned(),
            "temperature": body.get("temperature").cloned(),
            "top_p": body.get("top_p").cloned(),
        },
        "options": {"wait_for_model": true}
    }))
}

fn huggingface_to_openai_request(body: Value) -> Result<Value, CliError> {
    let input = body
        .get("inputs")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    Ok(json!({
        "messages": [{"role": "user", "content": input}],
        "max_tokens": body.pointer("/parameters/max_new_tokens").cloned(),
        "temperature": body.pointer("/parameters/temperature").cloned(),
        "top_p": body.pointer("/parameters/top_p").cloned(),
    }))
}

fn huggingface_to_openai_response(body: Value) -> Result<Value, CliError> {
    let content = body
        .as_array()
        .and_then(|items| items.first())
        .and_then(|item| item.get("generated_text"))
        .and_then(|value| value.as_str())
        .map(ToString::to_string)
        .or_else(|| {
            body.get("generated_text")
                .and_then(|value| value.as_str())
                .map(ToString::to_string)
        })
        .unwrap_or_default();
    Ok(build_openai_response(None, content, "stop"))
}

fn openai_to_huggingface_response(body: Value) -> Result<Value, CliError> {
    Ok(json!([{
        "generated_text": openai_response_content(&body)
    }]))
}

fn openai_to_replicate_request(body: Value) -> Result<Value, CliError> {
    let messages = openai_messages(&body);
    Ok(json!({
        "input": {
            "prompt": latest_user_message(&messages),
            "system_prompt": system_prompt(&messages),
            "max_new_tokens": body.get("max_tokens").or_else(|| body.get("max_completion_tokens")).cloned(),
            "temperature": body.get("temperature").cloned(),
            "top_p": body.get("top_p").cloned(),
        }
    }))
}

fn replicate_to_openai_request(body: Value) -> Result<Value, CliError> {
    let Some(input) = body.get("input") else {
        return Ok(json!({"messages": []}));
    };

    if let Some(prompt) = input.get("prompt").and_then(|value| value.as_str()) {
        let system = input.get("system_prompt").and_then(|value| value.as_str());
        let mut messages = Vec::new();
        if let Some(system) = system {
            messages.push(json!({"role": "system", "content": system}));
        }
        messages.push(json!({"role": "user", "content": prompt}));
        return Ok(json!({"messages": messages}));
    }

    if let Some(text) = input.as_str() {
        return Ok(json!({
            "messages": [{
                "role": "user",
                "content": text,
            }]
        }));
    }

    if let Some(items) = input.as_array() {
        let messages = items
            .iter()
            .filter_map(|item| {
                if let Some(text) = item.as_str() {
                    if text.trim().is_empty() {
                        return None;
                    }
                    return Some(json!({
                        "role": "user",
                        "content": text,
                    }));
                }

                let role = item
                    .get("role")
                    .and_then(|value| value.as_str())
                    .unwrap_or("user");
                let content = message_text(item);
                if content.trim().is_empty() {
                    None
                } else {
                    Some(json!({
                        "role": role,
                        "content": content,
                    }))
                }
            })
            .collect::<Vec<_>>();
        return Ok(json!({ "messages": messages }));
    }

    Ok(json!({"messages": []}))
}

fn replicate_to_openai_response(body: Value) -> Result<Value, CliError> {
    let content = body
        .get("output")
        .and_then(|value| {
            value.as_str().map(ToString::to_string).or_else(|| {
                value.as_array().map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str())
                        .collect::<Vec<_>>()
                        .join("")
                })
            })
        })
        .unwrap_or_default();
    Ok(build_openai_response(None, content, "stop"))
}

fn openai_to_replicate_response(body: Value) -> Result<Value, CliError> {
    let mut response = json!({
        "status": "succeeded",
        "output": openai_response_content(&body),
    });

    if let Some(usage) = body.get("usage").cloned() {
        response["usage"] = usage;
    }

    Ok(response)
}

fn openai_to_watsonx_request(body: Value) -> Result<Value, CliError> {
    let messages = body
        .get("messages")
        .and_then(|value| value.as_array())
        .cloned()
        .or_else(|| {
            body.get("input")
                .and_then(|value| value.as_array())
                .cloned()
        })
        .or_else(|| {
            body.get("input")
                .and_then(|value| value.as_str())
                .map(|text| vec![json!({ "role": "user", "content": text })])
        })
        .unwrap_or_default();
    let mut watsonx_messages = Vec::new();
    for message in messages {
        let role = message
            .get("role")
            .and_then(|value| value.as_str())
            .unwrap_or("user");
        let mut mapped = serde_json::Map::new();
        mapped.insert("role".to_string(), json!(role));
        mapped.insert(
            "content".to_string(),
            message
                .get("content")
                .cloned()
                .unwrap_or_else(|| json!(message_text(&message))),
        );
        if let Some(tool_calls) = message.get("tool_calls").cloned() {
            mapped.insert("tool_calls".to_string(), tool_calls);
        }
        if let Some(tool_call_id) = message.get("tool_call_id").cloned() {
            mapped.insert("tool_call_id".to_string(), tool_call_id);
        }
        watsonx_messages.push(Value::Object(mapped));
    }

    let mut request = serde_json::Map::new();
    request.insert(
        "model_id".to_string(),
        body.get("model").cloned().unwrap_or_else(|| json!("")),
    );
    request.insert("messages".to_string(), Value::Array(watsonx_messages));
    for (source, target) in [
        ("stream", "stream"),
        ("max_tokens", "max_tokens"),
        ("max_completion_tokens", "max_completion_tokens"),
        ("temperature", "temperature"),
        ("top_p", "top_p"),
        ("presence_penalty", "presence_penalty"),
        ("frequency_penalty", "frequency_penalty"),
        ("seed", "seed"),
        ("response_format", "response_format"),
    ] {
        if let Some(value) = body.get(source).cloned() {
            request.insert(target.to_string(), value);
        }
    }
    if let Some(stop) = body.get("stop").cloned() {
        request.insert("stop".to_string(), stop);
    }
    if let Some(tools) = body.get("tools").cloned() {
        request.insert("tools".to_string(), tools);
    }
    if let Some(tool_choice) = body.get("tool_choice") {
        match tool_choice.as_str() {
            Some(value) => {
                request.insert("tool_choice_option".to_string(), json!(value));
            }
            None => {
                request.insert("tool_choice".to_string(), tool_choice.clone());
            }
        }
    }

    Ok(Value::Object(request))
}

fn watsonx_to_openai_request(body: Value) -> Result<Value, CliError> {
    Ok(json!({
        "model": body
            .get("model")
            .cloned()
            .or_else(|| body.get("model_id").cloned())
            .unwrap_or_else(|| json!("")),
        "messages": body.get("messages").cloned().unwrap_or_else(|| json!([])),
        "max_tokens": body.get("max_tokens").cloned(),
        "max_completion_tokens": body.get("max_completion_tokens").cloned(),
        "temperature": body.get("temperature").cloned(),
        "top_p": body.get("top_p").cloned(),
        "stream": body.get("stream").cloned().unwrap_or(json!(false)),
        "tools": body.get("tools").cloned(),
        "response_format": body.get("response_format").cloned(),
    }))
}

fn watsonx_to_openai_response(body: Value) -> Result<Value, CliError> {
    let choices = body
        .get("choices")
        .and_then(|value| value.as_array())
        .cloned()
        .ok_or_else(|| CliError::user("watsonx response is missing choices"))?;
    let first_choice = choices
        .first()
        .ok_or_else(|| CliError::user("watsonx response is missing choices[0]"))?;
    let message = first_choice
        .get("message")
        .ok_or_else(|| CliError::user("watsonx response is missing choices[0].message"))?;
    let has_tool_calls = message
        .get("tool_calls")
        .and_then(|value| value.as_array())
        .is_some_and(|items| !items.is_empty());
    if message_text(message).is_empty() && !has_tool_calls {
        return Err(CliError::user(
            "watsonx response did not include assistant content or tool calls",
        ));
    }

    let mut response = body;
    if response.get("object").is_none() {
        response["object"] = json!("chat.completion");
    }
    if response.get("model").is_none() {
        if let Some(model_id) = response.get("model_id").cloned() {
            response["model"] = model_id;
        }
    }
    Ok(response)
}

fn openai_to_watsonx_response(body: Value) -> Result<Value, CliError> {
    Ok(json!({
        "results": [{
            "generated_text": openai_response_content(&body),
            "stop_reason": openai_finish_reason(&body),
        }]
    }))
}

fn openai_to_google_gemini_request(body: Value) -> Result<Value, CliError> {
    let messages = openai_messages(&body);
    let contents = messages
        .iter()
        .filter_map(|message| {
            let role = message.get("role")?.as_str()?;
            if role == "system" {
                return None;
            }
            let mapped_role = if role == "assistant" { "model" } else { "user" };
            Some(json!({
                "role": mapped_role,
                "parts": [{"text": message_text(message)}],
            }))
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "contents": contents,
        "systemInstruction": system_prompt(&messages).map(|text| json!({"parts": [{"text": text}]})),
        "generationConfig": {
            "maxOutputTokens": body.get("max_tokens").or_else(|| body.get("max_completion_tokens")).cloned(),
            "temperature": body.get("temperature").cloned(),
            "topP": body.get("top_p").cloned(),
            "stopSequences": body.get("stop").cloned(),
        }
    }))
}

fn google_gemini_to_openai_request(body: Value) -> Result<Value, CliError> {
    let mut messages = Vec::new();
    if let Some(text) = body
        .get("systemInstruction")
        .and_then(|value| value.get("parts"))
        .and_then(|value| value.as_array())
        .map(|parts| {
            parts
                .iter()
                .filter_map(|part| part.get("text").and_then(|value| value.as_str()))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .filter(|text| !text.is_empty())
    {
        messages.push(json!({"role": "system", "content": text}));
    }
    if let Some(contents) = body.get("contents").and_then(|value| value.as_array()) {
        for item in contents {
            let role = if item.get("role").and_then(|value| value.as_str()) == Some("model") {
                "assistant"
            } else {
                "user"
            };
            let text = item
                .get("parts")
                .and_then(|value| value.as_array())
                .map(|parts| {
                    parts
                        .iter()
                        .filter_map(|part| part.get("text").and_then(|value| value.as_str()))
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .unwrap_or_default();
            messages.push(json!({"role": role, "content": text}));
        }
    }
    Ok(json!({
        "messages": messages,
        "max_tokens": body.pointer("/generationConfig/maxOutputTokens").cloned(),
        "temperature": body.pointer("/generationConfig/temperature").cloned(),
        "top_p": body.pointer("/generationConfig/topP").cloned(),
        "stop": body.pointer("/generationConfig/stopSequences").cloned(),
    }))
}

fn google_gemini_to_openai_response(body: Value) -> Result<Value, CliError> {
    let content = body
        .get("candidates")
        .and_then(|value| value.as_array())
        .and_then(|items| items.first())
        .and_then(|candidate| candidate.get("content"))
        .and_then(|content| content.get("parts"))
        .and_then(|parts| parts.as_array())
        .map(|parts| {
            parts
                .iter()
                .filter_map(|part| part.get("text").and_then(|value| value.as_str()))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    let finish_reason = body
        .get("candidates")
        .and_then(|value| value.as_array())
        .and_then(|items| items.first())
        .and_then(|candidate| candidate.get("finishReason"))
        .and_then(|value| value.as_str())
        .map(|reason| match reason {
            "STOP" => "stop",
            "MAX_TOKENS" => "length",
            "SAFETY" => "content_filter",
            _ => "stop",
        })
        .unwrap_or("stop");
    let mut response = build_openai_response(None, content, finish_reason);
    if let Some(usage) = body.get("usageMetadata") {
        response["usage"] = json!({
            "prompt_tokens": usage.get("promptTokenCount").cloned().unwrap_or_else(|| json!(0)),
            "completion_tokens": usage.get("candidatesTokenCount").cloned().unwrap_or_else(|| json!(0)),
            "total_tokens": usage.get("totalTokenCount").cloned().unwrap_or_else(|| json!(0)),
        });
    }
    Ok(response)
}

fn openai_to_google_gemini_response(body: Value) -> Result<Value, CliError> {
    Ok(json!({
        "candidates": [{
            "finishReason": match openai_finish_reason(&body) {
                "length" => "MAX_TOKENS",
                "content_filter" => "SAFETY",
                _ => "STOP",
            },
            "content": {
                "role": "model",
                "parts": [{"text": openai_response_content(&body)}],
            }
        }]
    }))
}

// ---------------------------------------------------------------------------
// OpenAI → Anthropic: request
// ---------------------------------------------------------------------------

fn openai_to_anthropic_request(body: Value) -> Result<Value, CliError> {
    use serde_json::{json, Map};

    if body.get("response_format").is_some() {
        return Err(CliError::user(
            "Anthropic routing does not support response_format structured outputs",
        ));
    }

    let mut anthropic = Map::new();

    // model
    if let Some(model) = body.get("model").and_then(|v| v.as_str()) {
        anthropic.insert("model".into(), json!(model));
    }

    // max_tokens — required in Anthropic API
    let max_tokens = body
        .get("max_tokens")
        .or_else(|| body.get("max_completion_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(4096);
    anthropic.insert("max_tokens".into(), json!(max_tokens));

    // temperature / top_p
    if let Some(temp) = body.get("temperature").and_then(|v| v.as_f64()) {
        anthropic.insert("temperature".into(), json!(temp));
    }
    if let Some(top_p) = body.get("top_p").and_then(|v| v.as_f64()) {
        anthropic.insert("top_p".into(), json!(top_p));
    }

    // stream
    if let Some(stream) = body.get("stream").and_then(|v| v.as_bool()) {
        anthropic.insert("stream".into(), json!(stream));
    }

    // messages — extract system role messages into the top-level `system` string
    let messages = body
        .get("messages")
        .and_then(|v| v.as_array())
        .cloned()
        .or_else(|| body.get("input").and_then(|v| v.as_array()).cloned())
        .or_else(|| {
            body.get("input")
                .and_then(|v| v.as_str())
                .map(|text| vec![json!({ "role": "user", "content": text })])
        })
        .unwrap_or_default();

    let mut system_parts: Vec<String> = Vec::new();
    let mut ant_messages: Vec<Value> = Vec::new();

    for msg in &messages {
        let role = msg.get("role").and_then(|v| v.as_str()).unwrap_or("user");
        match role {
            "system" => {
                if let Some(content) = msg.get("content").and_then(|v| v.as_str()) {
                    system_parts.push(content.to_string());
                }
            }
            "user" | "assistant" => {
                let content = extract_message_content(msg);
                ant_messages.push(json!({ "role": role, "content": content }));
            }
            "tool" => {
                let tool_call_id = msg
                    .get("tool_call_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let content = msg.get("content").and_then(|v| v.as_str()).unwrap_or("");
                ant_messages.push(json!({
                    "role": "user",
                    "content": [{ "type": "tool_result", "tool_use_id": tool_call_id, "content": content }]
                }));
            }
            _ => {}
        }
    }

    if !system_parts.is_empty() {
        anthropic.insert("system".into(), json!(system_parts.join("\n\n")));
    }
    anthropic.insert("messages".into(), json!(ant_messages));

    // tools (OpenAI function tools → Anthropic tools)
    if let Some(tools) = body.get("tools").and_then(|v| v.as_array()) {
        let ant_tools: Vec<Value> = tools
            .iter()
            .filter_map(|tool| {
                let func = tool.get("function")?;
                let name = func.get("name")?.as_str()?;
                let desc = func
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let params = func
                    .get("parameters")
                    .cloned()
                    .unwrap_or_else(|| json!({ "type": "object", "properties": {} }));
                Some(json!({
                    "name": name,
                    "description": desc,
                    "input_schema": params,
                }))
            })
            .collect();
        if !ant_tools.is_empty() {
            anthropic.insert("tools".into(), json!(ant_tools));
        }
    }

    // tool_choice
    if let Some(tc) = body.get("tool_choice") {
        let ant_tc = match tc.as_str() {
            Some("auto") => json!({ "type": "auto" }),
            Some("required") => json!({ "type": "any" }),
            Some("none") => json!({ "type": "none" }),
            _ => {
                if let Some(func_name) = tc
                    .get("function")
                    .and_then(|f| f.get("name"))
                    .and_then(|n| n.as_str())
                {
                    json!({ "type": "tool", "name": func_name })
                } else {
                    json!({ "type": "auto" })
                }
            }
        };
        anthropic.insert("tool_choice".into(), ant_tc);
    }

    // Preserve unrecognised top-level fields in metadata
    let known = [
        "model",
        "messages",
        "max_tokens",
        "max_completion_tokens",
        "temperature",
        "top_p",
        "stream",
        "tools",
        "tool_choice",
        "n",
        "stop",
    ];
    let mut metadata_extra = serde_json::Map::new();
    if let Some(obj) = body.as_object() {
        for (k, v) in obj {
            if !known.contains(&k.as_str()) && k != "verdictan" {
                metadata_extra.insert(k.clone(), v.clone());
            }
        }
    }
    if !metadata_extra.is_empty() {
        anthropic.insert("metadata".into(), Value::Object(metadata_extra));
    }

    Ok(Value::Object(anthropic))
}

fn extract_message_content(msg: &Value) -> Value {
    if let Some(arr) = msg.get("content").and_then(|v| v.as_array()) {
        let blocks: Vec<Value> = arr
            .iter()
            .filter_map(|item| {
                let typ = item.get("type")?.as_str()?;
                match typ {
                    "text" => Some(serde_json::json!({
                        "type": "text",
                        "text": item.get("text").and_then(|v| v.as_str()).unwrap_or("")
                    })),
                    "document" => {
                        let source = item.get("source")?;
                        let media_type = source
                            .get("media_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("application/pdf");
                        if media_type != "application/pdf" {
                            return None;
                        }
                        Some(serde_json::json!({
                            "type": "document",
                            "source": source
                        }))
                    }
                    "image_url" => {
                        let url = item.get("image_url")?.get("url")?.as_str()?;
                        if url.starts_with("data:") {
                            let mut parts = url.splitn(2, ',');
                            let header = parts.next().unwrap_or("");
                            let data = parts.next().unwrap_or("");
                            let media_type = header
                                .strip_prefix("data:")
                                .and_then(|s| s.strip_suffix(";base64"))
                                .unwrap_or("image/jpeg");
                            Some(serde_json::json!({
                                "type": "image",
                                "source": { "type": "base64", "media_type": media_type, "data": data }
                            }))
                        } else {
                            Some(serde_json::json!({
                                "type": "image",
                                "source": { "type": "url", "url": url }
                            }))
                        }
                    }
                    "tool_use" | "tool_result" | "thinking" => Some(item.clone()),
                    _ => None,
                }
            })
            .collect();
        if blocks.len() == 1 {
            // Single text block → unwrap to plain string for Anthropic compatibility
            if let Some(text) = blocks[0].get("text").and_then(|v| v.as_str()) {
                return serde_json::json!(text);
            }
        }
        return serde_json::Value::Array(blocks);
    }
    msg.get("content")
        .cloned()
        .unwrap_or(serde_json::Value::String(String::new()))
}

// ---------------------------------------------------------------------------
// Anthropic → OpenAI: request
// ---------------------------------------------------------------------------

fn anthropic_to_openai_request(body: Value) -> Result<Value, CliError> {
    use serde_json::{json, Map};

    let mut openai = Map::new();

    if let Some(model) = body.get("model").and_then(|v| v.as_str()) {
        openai.insert("model".into(), json!(model));
    }
    if let Some(max_tokens) = body.get("max_tokens").and_then(|v| v.as_u64()) {
        openai.insert("max_tokens".into(), json!(max_tokens));
    }
    if let Some(temp) = body.get("temperature").and_then(|v| v.as_f64()) {
        openai.insert("temperature".into(), json!(temp));
    }
    if let Some(top_p) = body.get("top_p").and_then(|v| v.as_f64()) {
        openai.insert("top_p".into(), json!(top_p));
    }
    if let Some(stream) = body.get("stream").and_then(|v| v.as_bool()) {
        openai.insert("stream".into(), json!(stream));
    }

    // Promote Anthropic top-level `system` string to a system role message
    let mut messages: Vec<Value> = Vec::new();
    if let Some(system) = body.get("system").and_then(|v| v.as_str()) {
        if !system.trim().is_empty() {
            messages.push(json!({ "role": "system", "content": system }));
        }
    }
    if let Some(anthro_msgs) = body.get("messages").and_then(|v| v.as_array()) {
        for msg in anthro_msgs {
            let role = msg.get("role").and_then(|v| v.as_str()).unwrap_or("user");
            let content = anthropic_content_to_openai(msg.get("content"));
            messages.push(json!({ "role": role, "content": content }));
        }
    }
    openai.insert("messages".into(), json!(messages));

    // tools (Anthropic → OpenAI function tools)
    if let Some(tools) = body.get("tools").and_then(|v| v.as_array()) {
        let oai_tools: Vec<Value> = tools
            .iter()
            .filter_map(|tool| {
                let name = tool.get("name")?.as_str()?;
                let desc = tool
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let schema = tool
                    .get("input_schema")
                    .cloned()
                    .unwrap_or_else(|| json!({ "type": "object", "properties": {} }));
                Some(json!({
                    "type": "function",
                    "function": { "name": name, "description": desc, "parameters": schema }
                }))
            })
            .collect();
        if !oai_tools.is_empty() {
            openai.insert("tools".into(), json!(oai_tools));
        }
    }

    // tool_choice
    if let Some(tc) = body.get("tool_choice") {
        let oai_tc = match tc.get("type").and_then(|v| v.as_str()) {
            Some("auto") => json!("auto"),
            Some("any") => json!("required"),
            Some("none") => json!("none"),
            Some("tool") => {
                if let Some(name) = tc.get("name").and_then(|v| v.as_str()) {
                    json!({ "type": "function", "function": { "name": name } })
                } else {
                    json!("auto")
                }
            }
            _ => json!("auto"),
        };
        openai.insert("tool_choice".into(), oai_tc);
    }

    Ok(Value::Object(openai))
}

fn anthropic_content_to_openai(content: Option<&Value>) -> Value {
    match content {
        None => Value::String(String::new()),
        Some(Value::String(s)) => Value::String(s.clone()),
        Some(Value::Array(blocks)) => {
            let mut text_parts: Vec<&str> = Vec::new();
            let mut has_non_text = false;
            for block in blocks {
                match block.get("type").and_then(|v| v.as_str()) {
                    Some("text") => {
                        if let Some(t) = block.get("text").and_then(|v| v.as_str()) {
                            text_parts.push(t);
                        }
                    }
                    _ => has_non_text = true,
                }
            }
            if !has_non_text && !text_parts.is_empty() {
                Value::String(text_parts.join(""))
            } else {
                Value::Array(blocks.clone())
            }
        }
        Some(other) => other.clone(),
    }
}

// ---------------------------------------------------------------------------
// Anthropic → OpenAI: response
// ---------------------------------------------------------------------------

/// Translate an Anthropic Messages API response to OpenAI Chat Completions format.
fn anthropic_to_openai_response(body: Value) -> Result<Value, CliError> {
    use serde_json::json;

    let model = body
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let id = body
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("msg_unknown")
        .to_string();

    let content_text = extract_anthropic_text_content(&body);
    let tool_calls = extract_anthropic_tool_uses(&body);

    let finish_reason = body
        .get("stop_reason")
        .and_then(|v| v.as_str())
        .map(map_anthropic_stop_reason)
        .unwrap_or("stop");

    let usage = body
        .get("usage")
        .cloned()
        .map(|u| map_anthropic_usage(&u))
        .unwrap_or_else(|| json!({}));

    let mut message = json!({
        "role": "assistant",
        "content": content_text,
    });
    if !tool_calls.is_empty() {
        if let Some(obj) = message.as_object_mut() {
            obj.insert("tool_calls".into(), json!(tool_calls));
        }
    }

    Ok(json!({
        "id": format!("chatcmpl_{}", id),
        "object": "chat.completion",
        "created": chrono::Utc::now().timestamp(),
        "model": model,
        "choices": [{
            "index": 0,
            "message": message,
            "finish_reason": finish_reason,
        }],
        "usage": usage,
    }))
}

fn extract_anthropic_text_content(body: &Value) -> String {
    body.get("content")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|block| {
                    if block.get("type").and_then(|v| v.as_str()) == Some("text") {
                        block
                            .get("text")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default()
}

fn extract_anthropic_tool_uses(body: &Value) -> Vec<Value> {
    body.get("content")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|block| {
                    if block.get("type").and_then(|v| v.as_str()) == Some("tool_use") {
                        let id = block.get("id").and_then(|v| v.as_str()).unwrap_or("");
                        let name = block.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        let input = block
                            .get("input")
                            .cloned()
                            .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
                        let args = serde_json::to_string(&input).unwrap_or_else(|_| "{}".into());
                        Some(serde_json::json!({
                            "id": id,
                            "type": "function",
                            "function": { "name": name, "arguments": args }
                        }))
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn map_anthropic_stop_reason(reason: &str) -> &'static str {
    match reason {
        "end_turn" => "stop",
        "max_tokens" => "length",
        "tool_use" => "tool_calls",
        "stop_sequence" => "stop",
        _ => "stop",
    }
}

fn map_anthropic_usage(usage: &Value) -> Value {
    let input = usage
        .get("input_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let output = usage
        .get("output_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    serde_json::json!({
        "prompt_tokens": input,
        "completion_tokens": output,
        "total_tokens": input + output,
    })
}

// ---------------------------------------------------------------------------
// OpenAI → Anthropic: response
// ---------------------------------------------------------------------------

fn openai_to_anthropic_response(body: Value) -> Result<Value, CliError> {
    use serde_json::json;

    let model = body
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let id = body
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("chatcmpl_unknown")
        .to_string();

    let (content_text, finish_reason) = body
        .get("choices")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .map(|choice| {
            let text = choice
                .pointer("/message/content")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let fr = choice
                .get("finish_reason")
                .and_then(|v| v.as_str())
                .unwrap_or("stop");
            let ant_fr = match fr {
                "stop" => "end_turn",
                "length" => "max_tokens",
                "tool_calls" => "tool_use",
                _ => "end_turn",
            };
            (text, ant_fr)
        })
        .unwrap_or_default();

    let usage = body
        .get("usage")
        .cloned()
        .map(|u| {
            json!({
                "input_tokens": u.get("prompt_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
                "output_tokens": u.get("completion_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
            })
        })
        .unwrap_or_else(|| json!({ "input_tokens": 0, "output_tokens": 0 }));

    Ok(json!({
        "id": id,
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{ "type": "text", "text": content_text }],
        "stop_reason": finish_reason,
        "usage": usage,
    }))
}

fn anthropic_to_openai_responses_response(body: Value) -> Result<Value, CliError> {
    let model = body
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let id = body
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("resp_unknown")
        .to_string();
    let content = body
        .get("content")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let usage = body
        .get("usage")
        .map(map_anthropic_usage)
        .unwrap_or_else(|| json!({}));

    let output = content
        .iter()
        .filter_map(|block| match block.get("type").and_then(|v| v.as_str()) {
            Some("text") => Some(json!({
                "type": "message",
                "role": "assistant",
                "content": [{
                    "type": "output_text",
                    "text": block.get("text").and_then(|v| v.as_str()).unwrap_or(""),
                }]
            })),
            Some("tool_use") => Some(json!({
                "type": "function_call",
                "id": block.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                "call_id": block.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                "name": block.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                "arguments": serde_json::to_string(
                    &block.get("input").cloned().unwrap_or_else(|| json!({}))
                )
                .unwrap_or_else(|_| "{}".to_string()),
            })),
            _ => None,
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "id": id,
        "object": "response",
        "status": "completed",
        "model": model,
        "output": output,
        "usage": usage,
    }))
}

// ---------------------------------------------------------------------------
// Streaming SSE translation (Anthropic → OpenAI delta chunks)
// ---------------------------------------------------------------------------

/// Translate a single Anthropic SSE data payload to an equivalent OpenAI
/// `chat.completion.chunk` JSON. Returns `None` if the event should be
/// suppressed (e.g. `message_stop`, `ping`, internal control events).
#[allow(dead_code)]
fn translate_anthropic_sse_event(
    event_data: &str,
    request_id: &str,
    model: &str,
) -> Option<Vec<u8>> {
    let v: Value = serde_json::from_str(event_data).ok()?;
    let event_type = v.get("type").and_then(|t| t.as_str())?;

    let created = chrono::Utc::now().timestamp();

    match event_type {
        "message_start" => {
            let chunk = serde_json::json!({
                "id": format!("chatcmpl_{}", request_id),
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": null}]
            });
            serde_json::to_vec(&chunk).ok()
        }
        "content_block_delta" => {
            let text = v
                .pointer("/delta/text")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let chunk = serde_json::json!({
                "id": format!("chatcmpl_{}", request_id),
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": null}]
            });
            serde_json::to_vec(&chunk).ok()
        }
        "message_delta" => {
            let stop_reason = v
                .pointer("/delta/stop_reason")
                .and_then(|v| v.as_str())
                .map(map_anthropic_stop_reason);
            if let Some(fr) = stop_reason {
                let chunk = serde_json::json!({
                    "id": format!("chatcmpl_{}", request_id),
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{"index": 0, "delta": {}, "finish_reason": fr}]
                });
                return serde_json::to_vec(&chunk).ok();
            }
            None
        }
        // message_stop, content_block_start, content_block_stop, ping → suppress
        _ => None,
    }
}

#[derive(Debug, Default, Clone)]
struct StreamToolState {
    id: Option<String>,
    name: Option<String>,
    start_emitted: bool,
    stop_emitted: bool,
}

/// Stateful route-native SSE translator for text-family streaming lanes.
pub struct RouteNativeSseTranslator {
    path: String,
    source_format: ProviderFormat,
    request_id: String,
    message_started: bool,
    message_id: Option<String>,
    response_id: Option<String>,
    model: Option<String>,
    finished: bool,
    tool_states: BTreeMap<usize, StreamToolState>,
}

impl RouteNativeSseTranslator {
    pub fn new(path: &str, source_format: ProviderFormat, request_id: &str) -> Self {
        Self {
            path: path.to_string(),
            source_format,
            request_id: request_id.to_string(),
            message_started: false,
            message_id: None,
            response_id: None,
            model: None,
            finished: false,
            tool_states: BTreeMap::new(),
        }
    }

    pub fn translate_payload(&mut self, payload: &str) -> Vec<Bytes> {
        match (self.path.as_str(), self.source_format) {
            ("/v1/chat/completions", ProviderFormat::Anthropic) => {
                self.translate_anthropic_to_chat(payload)
            }
            ("/v1/chat/completions", ProviderFormat::Cohere) => {
                self.translate_cohere_to_chat(payload)
            }
            ("/v1/responses", ProviderFormat::Anthropic) => {
                self.translate_anthropic_to_responses(payload)
            }
            ("/v1/responses", ProviderFormat::Cohere) => {
                self.translate_cohere_to_responses(payload)
            }
            ("/v1/responses", ProviderFormat::OpenAI) => {
                self.translate_openai_chat_to_responses(payload)
            }
            ("/v1/messages", ProviderFormat::OpenAI) => self.translate_openai_to_messages(payload),
            _ => wrap_sse_payload(payload).into_iter().collect(),
        }
    }

    fn translate_anthropic_to_chat(&mut self, payload: &str) -> Vec<Bytes> {
        if payload == "[DONE]" {
            return Vec::new();
        }

        let Ok(value) = serde_json::from_str::<Value>(payload) else {
            return wrap_sse_payload(payload).into_iter().collect();
        };
        let Some(event_type) = value.get("type").and_then(|candidate| candidate.as_str()) else {
            return wrap_sse_payload(payload).into_iter().collect();
        };
        let created = chrono::Utc::now().timestamp();
        let model = value
            .pointer("/message/model")
            .and_then(|candidate| candidate.as_str())
            .or(self.model.as_deref())
            .unwrap_or("unknown")
            .to_string();
        if !model.is_empty() {
            self.model = Some(model.clone());
        }

        match event_type {
            "message_start" => {
                self.message_started = true;
                self.message_id = value
                    .pointer("/message/id")
                    .and_then(|candidate| candidate.as_str())
                    .map(ToString::to_string);
                vec![wrap_sse_json(json!({
                    "id": format!("chatcmpl_{}", self.request_id),
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{
                        "index": 0,
                        "delta": { "role": "assistant" },
                        "finish_reason": Value::Null,
                    }]
                }))]
            }
            "content_block_start" => {
                let index = value
                    .get("index")
                    .and_then(|candidate| candidate.as_u64())
                    .unwrap_or(0) as usize;
                let block = value
                    .get("content_block")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                if block.get("type").and_then(|candidate| candidate.as_str()) != Some("tool_use") {
                    return Vec::new();
                }
                let id = block
                    .get("id")
                    .and_then(|candidate| candidate.as_str())
                    .map(ToString::to_string);
                let name = block
                    .get("name")
                    .and_then(|candidate| candidate.as_str())
                    .map(ToString::to_string);
                self.tool_states.insert(
                    index,
                    StreamToolState {
                        id: id.clone(),
                        name: name.clone(),
                        ..Default::default()
                    },
                );
                vec![wrap_sse_json(json!({
                    "id": format!("chatcmpl_{}", self.request_id),
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{
                        "index": 0,
                        "delta": {
                            "tool_calls": [{
                                "index": index,
                                "id": id,
                                "type": "function",
                                "function": {
                                    "name": name,
                                    "arguments": ""
                                }
                            }]
                        },
                        "finish_reason": Value::Null,
                    }]
                }))]
            }
            "content_block_delta" => {
                let index = value
                    .get("index")
                    .and_then(|candidate| candidate.as_u64())
                    .unwrap_or(0) as usize;
                match value
                    .pointer("/delta/type")
                    .and_then(|candidate| candidate.as_str())
                {
                    Some("text_delta") => {
                        let text = value
                            .pointer("/delta/text")
                            .and_then(|candidate| candidate.as_str())
                            .unwrap_or("");
                        if text.is_empty() {
                            return Vec::new();
                        }
                        vec![wrap_sse_json(json!({
                            "id": format!("chatcmpl_{}", self.request_id),
                            "object": "chat.completion.chunk",
                            "created": created,
                            "model": model,
                            "choices": [{
                                "index": 0,
                                "delta": { "content": text },
                                "finish_reason": Value::Null,
                            }]
                        }))]
                    }
                    Some("input_json_delta") => {
                        let partial_json = value
                            .pointer("/delta/partial_json")
                            .and_then(|candidate| candidate.as_str())
                            .unwrap_or("");
                        if partial_json.is_empty() {
                            return Vec::new();
                        }
                        let state = self.tool_states.get(&index).cloned().unwrap_or_default();
                        vec![wrap_sse_json(json!({
                            "id": format!("chatcmpl_{}", self.request_id),
                            "object": "chat.completion.chunk",
                            "created": created,
                            "model": model,
                            "choices": [{
                                "index": 0,
                                "delta": {
                                    "tool_calls": [{
                                        "index": index,
                                        "id": state.id,
                                        "type": "function",
                                        "function": {
                                            "name": state.name,
                                            "arguments": partial_json
                                        }
                                    }]
                                },
                                "finish_reason": Value::Null,
                            }]
                        }))]
                    }
                    Some("thinking_delta") => {
                        let thinking = value
                            .pointer("/delta/thinking")
                            .and_then(|candidate| candidate.as_str())
                            .unwrap_or("");
                        if thinking.is_empty() {
                            return Vec::new();
                        }
                        vec![wrap_sse_json(json!({
                            "id": format!("chatcmpl_{}", self.request_id),
                            "object": "chat.completion.chunk",
                            "created": created,
                            "model": model,
                            "choices": [{
                                "index": 0,
                                "delta": { "reasoning": thinking },
                                "finish_reason": Value::Null,
                            }]
                        }))]
                    }
                    _ => Vec::new(),
                }
            }
            "message_delta" => {
                let finish_reason = value
                    .pointer("/delta/stop_reason")
                    .and_then(|candidate| candidate.as_str())
                    .map(map_anthropic_stop_reason)
                    .unwrap_or("stop");
                self.finished = true;
                vec![wrap_sse_json(json!({
                    "id": format!("chatcmpl_{}", self.request_id),
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{
                        "index": 0,
                        "delta": {},
                        "finish_reason": finish_reason,
                    }]
                }))]
            }
            "message_stop" => {
                if self.finished {
                    vec![Bytes::from_static(b"data: [DONE]\n\n")]
                } else {
                    Vec::new()
                }
            }
            _ => Vec::new(),
        }
    }

    fn translate_anthropic_to_responses(&mut self, payload: &str) -> Vec<Bytes> {
        if payload == "[DONE]" {
            return Vec::new();
        }

        let Ok(value) = serde_json::from_str::<Value>(payload) else {
            return wrap_sse_payload(payload).into_iter().collect();
        };
        let Some(event_type) = value.get("type").and_then(|candidate| candidate.as_str()) else {
            return wrap_sse_payload(payload).into_iter().collect();
        };

        match event_type {
            "message_start" => {
                self.response_id = value
                    .pointer("/message/id")
                    .and_then(|candidate| candidate.as_str())
                    .map(ToString::to_string);
                self.model = value
                    .pointer("/message/model")
                    .and_then(|candidate| candidate.as_str())
                    .map(ToString::to_string);
                Vec::new()
            }
            "content_block_start" => {
                let index = value
                    .get("index")
                    .and_then(|candidate| candidate.as_u64())
                    .unwrap_or(0) as usize;
                let block = value
                    .get("content_block")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                if block.get("type").and_then(|candidate| candidate.as_str()) != Some("tool_use") {
                    return Vec::new();
                }
                let id = block
                    .get("id")
                    .and_then(|candidate| candidate.as_str())
                    .unwrap_or_default()
                    .to_string();
                let name = block
                    .get("name")
                    .and_then(|candidate| candidate.as_str())
                    .unwrap_or_default()
                    .to_string();
                self.tool_states.insert(
                    index,
                    StreamToolState {
                        id: Some(id.clone()),
                        name: Some(name.clone()),
                        ..Default::default()
                    },
                );
                vec![wrap_sse_json(json!({
                    "type": "response.output_item.added",
                    "response_id": self.response_id.clone().unwrap_or_else(|| self.request_id.clone()),
                    "output_index": index,
                    "item": {
                        "type": "function_call",
                        "id": id,
                        "call_id": id,
                        "name": name,
                        "arguments": ""
                    }
                }))]
            }
            "content_block_delta" => match value
                .pointer("/delta/type")
                .and_then(|candidate| candidate.as_str())
            {
                Some("text_delta") => {
                    let text = value
                        .pointer("/delta/text")
                        .and_then(|candidate| candidate.as_str())
                        .unwrap_or("");
                    if text.is_empty() {
                        return Vec::new();
                    }
                    vec![wrap_sse_json(json!({
                        "type": "response.output_text.delta",
                        "response_id": self.response_id.clone().unwrap_or_else(|| self.request_id.clone()),
                        "delta": text,
                    }))]
                }
                Some("thinking_delta") => {
                    let text = value
                        .pointer("/delta/thinking")
                        .and_then(|candidate| candidate.as_str())
                        .unwrap_or("");
                    if text.is_empty() {
                        return Vec::new();
                    }
                    vec![wrap_sse_json(json!({
                        "type": "response.reasoning.delta",
                        "response_id": self.response_id.clone().unwrap_or_else(|| self.request_id.clone()),
                        "delta": text,
                    }))]
                }
                Some("input_json_delta") => {
                    let index = value
                        .get("index")
                        .and_then(|candidate| candidate.as_u64())
                        .unwrap_or(0) as usize;
                    let partial_json = value
                        .pointer("/delta/partial_json")
                        .and_then(|candidate| candidate.as_str())
                        .unwrap_or("");
                    let call_id = self
                        .tool_states
                        .get(&index)
                        .and_then(|state| state.id.clone())
                        .unwrap_or_default();
                    if partial_json.is_empty() || call_id.is_empty() {
                        return Vec::new();
                    }
                    vec![wrap_sse_json(json!({
                        "type": "response.function_call_arguments.delta",
                        "response_id": self.response_id.clone().unwrap_or_else(|| self.request_id.clone()),
                        "output_index": index,
                        "call_id": call_id,
                        "delta": partial_json,
                    }))]
                }
                _ => Vec::new(),
            },
            "content_block_stop" => {
                let index = value
                    .get("index")
                    .and_then(|candidate| candidate.as_u64())
                    .unwrap_or(0) as usize;
                let call_id = self
                    .tool_states
                    .get(&index)
                    .and_then(|state| state.id.clone())
                    .unwrap_or_default();
                if call_id.is_empty() {
                    return Vec::new();
                }
                vec![wrap_sse_json(json!({
                    "type": "response.function_call_arguments.done",
                    "response_id": self.response_id.clone().unwrap_or_else(|| self.request_id.clone()),
                    "output_index": index,
                    "call_id": call_id,
                }))]
            }
            "message_stop" => vec![
                wrap_sse_json(json!({
                    "type": "response.completed",
                    "response_id": self.response_id.clone().unwrap_or_else(|| self.request_id.clone()),
                })),
                Bytes::from_static(b"data: [DONE]\n\n"),
            ],
            _ => Vec::new(),
        }
    }

    fn translate_cohere_to_chat(&mut self, payload: &str) -> Vec<Bytes> {
        if payload == "[DONE]" {
            return Vec::new();
        }

        let Ok(value) = serde_json::from_str::<Value>(payload) else {
            return wrap_sse_payload(payload).into_iter().collect();
        };
        let Some(event_type) = value.get("type").and_then(|candidate| candidate.as_str()) else {
            return wrap_sse_payload(payload).into_iter().collect();
        };
        let created = chrono::Utc::now().timestamp();
        let model = value
            .pointer("/delta/message/model")
            .and_then(|candidate| candidate.as_str())
            .or(value.get("model").and_then(|candidate| candidate.as_str()))
            .or(self.model.as_deref())
            .unwrap_or("cohere")
            .to_string();
        if !model.is_empty() {
            self.model = Some(model.clone());
        }

        match event_type {
            "message-start" | "message_start" => {
                self.response_id = value
                    .pointer("/delta/message/id")
                    .and_then(|candidate| candidate.as_str())
                    .map(ToString::to_string)
                    .or_else(|| {
                        value
                            .get("id")
                            .and_then(|candidate| candidate.as_str())
                            .map(ToString::to_string)
                    });
                vec![wrap_sse_json(json!({
                    "id": format!("chatcmpl_{}", self.request_id),
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{
                        "index": 0,
                        "delta": { "role": "assistant" },
                        "finish_reason": Value::Null,
                    }]
                }))]
            }
            "content-delta" | "content_delta" => {
                let text = value
                    .pointer("/delta/message/content/text")
                    .and_then(|candidate| candidate.as_str())
                    .or_else(|| {
                        value
                            .pointer("/delta/message/content/0/text")
                            .and_then(|candidate| candidate.as_str())
                    })
                    .unwrap_or("");
                if text.is_empty() {
                    return Vec::new();
                }
                vec![wrap_sse_json(json!({
                    "id": format!("chatcmpl_{}", self.request_id),
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{
                        "index": 0,
                        "delta": { "content": text },
                        "finish_reason": Value::Null,
                    }]
                }))]
            }
            "tool-call-start" | "tool_call_start" => {
                let index = value
                    .get("index")
                    .and_then(|candidate| candidate.as_u64())
                    .unwrap_or(0) as usize;
                let id = value
                    .pointer("/delta/message/tool_calls/0/id")
                    .and_then(|candidate| candidate.as_str())
                    .or_else(|| {
                        value
                            .pointer("/delta/tool_call/id")
                            .and_then(|candidate| candidate.as_str())
                    })
                    .map(ToString::to_string);
                let name = value
                    .pointer("/delta/message/tool_calls/0/function/name")
                    .and_then(|candidate| candidate.as_str())
                    .or_else(|| {
                        value
                            .pointer("/delta/tool_call/function/name")
                            .and_then(|candidate| candidate.as_str())
                    })
                    .map(ToString::to_string);
                self.tool_states.insert(
                    index,
                    StreamToolState {
                        id: id.clone(),
                        name: name.clone(),
                        ..Default::default()
                    },
                );
                vec![wrap_sse_json(json!({
                    "id": format!("chatcmpl_{}", self.request_id),
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{
                        "index": 0,
                        "delta": {
                            "tool_calls": [{
                                "index": index,
                                "id": id,
                                "type": "function",
                                "function": {
                                    "name": name,
                                    "arguments": ""
                                }
                            }]
                        },
                        "finish_reason": Value::Null,
                    }]
                }))]
            }
            "tool-call-delta" | "tool_call_delta" => {
                let index = value
                    .get("index")
                    .and_then(|candidate| candidate.as_u64())
                    .unwrap_or(0) as usize;
                let partial_json = value
                    .pointer("/delta/message/tool_calls/0/function/arguments")
                    .and_then(|candidate| candidate.as_str())
                    .or_else(|| {
                        value
                            .pointer("/delta/message/tool_calls/0/function/arguments_delta")
                            .and_then(|candidate| candidate.as_str())
                    })
                    .unwrap_or("");
                if partial_json.is_empty() {
                    return Vec::new();
                }
                let state = self.tool_states.get(&index).cloned().unwrap_or_default();
                vec![wrap_sse_json(json!({
                    "id": format!("chatcmpl_{}", self.request_id),
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{
                        "index": 0,
                        "delta": {
                            "tool_calls": [{
                                "index": index,
                                "id": state.id,
                                "type": "function",
                                "function": {
                                    "name": state.name,
                                    "arguments": partial_json
                                }
                            }]
                        },
                        "finish_reason": Value::Null,
                    }]
                }))]
            }
            "message-end" | "message_end" => {
                let finish_reason = value
                    .pointer("/delta/finish_reason")
                    .and_then(|candidate| candidate.as_str())
                    .or_else(|| {
                        value
                            .get("finish_reason")
                            .and_then(|candidate| candidate.as_str())
                    })
                    .unwrap_or(if self.tool_states.is_empty() {
                        "stop"
                    } else {
                        "tool_calls"
                    });
                vec![
                    wrap_sse_json(json!({
                        "id": format!("chatcmpl_{}", self.request_id),
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": model,
                        "choices": [{
                            "index": 0,
                            "delta": {},
                            "finish_reason": finish_reason,
                        }]
                    })),
                    Bytes::from_static(b"data: [DONE]\n\n"),
                ]
            }
            _ => Vec::new(),
        }
    }

    fn translate_cohere_to_responses(&mut self, payload: &str) -> Vec<Bytes> {
        if payload == "[DONE]" {
            return Vec::new();
        }

        let Ok(value) = serde_json::from_str::<Value>(payload) else {
            return wrap_sse_payload(payload).into_iter().collect();
        };
        let Some(event_type) = value.get("type").and_then(|candidate| candidate.as_str()) else {
            return wrap_sse_payload(payload).into_iter().collect();
        };
        let response_id = self
            .response_id
            .clone()
            .or_else(|| {
                value
                    .pointer("/delta/message/id")
                    .and_then(|candidate| candidate.as_str())
                    .map(ToString::to_string)
            })
            .unwrap_or_else(|| self.request_id.clone());
        self.response_id = Some(response_id.clone());

        match event_type {
            "message-start" | "message_start" => Vec::new(),
            "content-delta" | "content_delta" => {
                let text = value
                    .pointer("/delta/message/content/text")
                    .and_then(|candidate| candidate.as_str())
                    .or_else(|| {
                        value
                            .pointer("/delta/message/content/0/text")
                            .and_then(|candidate| candidate.as_str())
                    })
                    .unwrap_or("");
                if text.is_empty() {
                    return Vec::new();
                }
                vec![wrap_sse_json(json!({
                    "type": "response.output_text.delta",
                    "response_id": response_id,
                    "delta": text,
                }))]
            }
            "tool-call-start" | "tool_call_start" => {
                let index = value
                    .get("index")
                    .and_then(|candidate| candidate.as_u64())
                    .unwrap_or(0) as usize;
                let id = value
                    .pointer("/delta/message/tool_calls/0/id")
                    .and_then(|candidate| candidate.as_str())
                    .unwrap_or_default()
                    .to_string();
                let name = value
                    .pointer("/delta/message/tool_calls/0/function/name")
                    .and_then(|candidate| candidate.as_str())
                    .unwrap_or_default()
                    .to_string();
                self.tool_states.insert(
                    index,
                    StreamToolState {
                        id: Some(id.clone()),
                        name: Some(name.clone()),
                        ..Default::default()
                    },
                );
                vec![wrap_sse_json(json!({
                    "type": "response.output_item.added",
                    "response_id": response_id,
                    "output_index": index,
                    "item": {
                        "type": "function_call",
                        "id": id,
                        "call_id": id,
                        "name": name,
                        "arguments": ""
                    }
                }))]
            }
            "tool-call-delta" | "tool_call_delta" => {
                let index = value
                    .get("index")
                    .and_then(|candidate| candidate.as_u64())
                    .unwrap_or(0) as usize;
                let partial_json = value
                    .pointer("/delta/message/tool_calls/0/function/arguments")
                    .and_then(|candidate| candidate.as_str())
                    .or_else(|| {
                        value
                            .pointer("/delta/message/tool_calls/0/function/arguments_delta")
                            .and_then(|candidate| candidate.as_str())
                    })
                    .unwrap_or("");
                let call_id = self
                    .tool_states
                    .get(&index)
                    .and_then(|state| state.id.clone())
                    .unwrap_or_default();
                if partial_json.is_empty() || call_id.is_empty() {
                    return Vec::new();
                }
                vec![wrap_sse_json(json!({
                    "type": "response.function_call_arguments.delta",
                    "response_id": response_id,
                    "output_index": index,
                    "call_id": call_id,
                    "delta": partial_json,
                }))]
            }
            "tool-call-end" | "tool_call_end" => {
                let index = value
                    .get("index")
                    .and_then(|candidate| candidate.as_u64())
                    .unwrap_or(0) as usize;
                let call_id = self
                    .tool_states
                    .get(&index)
                    .and_then(|state| state.id.clone())
                    .unwrap_or_default();
                if call_id.is_empty() {
                    return Vec::new();
                }
                vec![wrap_sse_json(json!({
                    "type": "response.function_call_arguments.done",
                    "response_id": response_id,
                    "output_index": index,
                    "call_id": call_id,
                }))]
            }
            "message-end" | "message_end" => vec![
                wrap_sse_json(json!({
                    "type": "response.completed",
                    "response_id": response_id,
                })),
                Bytes::from_static(b"data: [DONE]\n\n"),
            ],
            _ => Vec::new(),
        }
    }

    fn translate_openai_to_messages(&mut self, payload: &str) -> Vec<Bytes> {
        if payload == "[DONE]" {
            return Vec::new();
        }

        let Ok(value) = serde_json::from_str::<Value>(payload) else {
            return wrap_sse_payload(payload).into_iter().collect();
        };

        if value.get("error").is_some() {
            return vec![wrap_sse_json(value)];
        }

        if let Some(event_type) = value.get("type").and_then(|candidate| candidate.as_str()) {
            return self.translate_openai_responses_to_messages(&value, event_type);
        }

        self.translate_openai_chat_to_messages(&value)
    }

    fn translate_openai_chat_to_messages(&mut self, value: &Value) -> Vec<Bytes> {
        let mut frames = Vec::new();
        let id = value
            .get("id")
            .and_then(|candidate| candidate.as_str())
            .unwrap_or("msg_verdictan")
            .to_string();
        self.message_id.get_or_insert(id);
        self.model = value
            .get("model")
            .and_then(|candidate| candidate.as_str())
            .map(ToString::to_string)
            .or_else(|| self.model.clone());

        if let Some(choices) = value
            .get("choices")
            .and_then(|candidate| candidate.as_array())
        {
            for choice in choices {
                let index = choice
                    .get("index")
                    .and_then(|candidate| candidate.as_u64())
                    .unwrap_or(0) as usize;
                if !self.message_started
                    && choice
                        .pointer("/delta/role")
                        .and_then(|candidate| candidate.as_str())
                        .is_some()
                {
                    frames.push(self.ensure_message_start());
                }
                if let Some(text) = choice
                    .pointer("/delta/content")
                    .and_then(|candidate| candidate.as_str())
                    .filter(|candidate| !candidate.is_empty())
                {
                    if !self.message_started {
                        frames.push(self.ensure_message_start());
                    }
                    frames.push(wrap_sse_json(json!({
                        "type": "content_block_delta",
                        "index": 0,
                        "delta": {
                            "type": "text_delta",
                            "text": text,
                        }
                    })));
                }
                if let Some(tool_calls) = choice
                    .pointer("/delta/tool_calls")
                    .and_then(|candidate| candidate.as_array())
                {
                    if !self.message_started {
                        frames.push(self.ensure_message_start());
                    }
                    for tool_call in tool_calls {
                        let tool_index = tool_call
                            .get("index")
                            .and_then(|candidate| candidate.as_u64())
                            .unwrap_or(index as u64)
                            as usize;
                        let (emit_start, start_id, start_name) = {
                            let state = self.tool_states.entry(tool_index).or_default();
                            if state.id.is_none() {
                                state.id = tool_call
                                    .get("id")
                                    .and_then(|candidate| candidate.as_str())
                                    .map(ToString::to_string);
                            }
                            if state.name.is_none() {
                                state.name = tool_call
                                    .pointer("/function/name")
                                    .and_then(|candidate| candidate.as_str())
                                    .map(ToString::to_string);
                            }
                            let emit_start = !state.start_emitted
                                && (state.id.is_some() || state.name.is_some());
                            if emit_start {
                                state.start_emitted = true;
                                state.stop_emitted = false;
                            }
                            (
                                emit_start,
                                state.id.clone().unwrap_or_else(|| {
                                    format!("toolu_{}_{}", self.request_id, tool_index)
                                }),
                                state.name.clone().unwrap_or_default(),
                            )
                        };
                        if emit_start {
                            frames.push(wrap_sse_json(json!({
                                "type": "content_block_start",
                                "index": tool_index,
                                "content_block": {
                                    "type": "tool_use",
                                    "id": start_id,
                                    "name": start_name,
                                    "input": {}
                                }
                            })));
                        }
                        if let Some(arguments) = tool_call
                            .pointer("/function/arguments")
                            .and_then(|candidate| candidate.as_str())
                            .filter(|candidate| !candidate.is_empty())
                        {
                            frames.push(wrap_sse_json(json!({
                                "type": "content_block_delta",
                                "index": tool_index,
                                "delta": {
                                    "type": "input_json_delta",
                                    "partial_json": arguments,
                                }
                            })));
                        }
                    }
                }
                if let Some(reason) = choice
                    .get("finish_reason")
                    .and_then(|candidate| candidate.as_str())
                {
                    frames.extend(self.finish_openai_messages(reason));
                }
            }
        }

        frames
    }

    fn translate_openai_chat_to_responses(&mut self, payload: &str) -> Vec<Bytes> {
        if payload == "[DONE]" {
            if self.finished {
                return vec![Bytes::from_static(b"data: [DONE]\n\n")];
            }
            return Vec::new();
        }

        let Ok(value) = serde_json::from_str::<Value>(payload) else {
            return wrap_sse_payload(payload).into_iter().collect();
        };
        if value.get("error").is_some() {
            return vec![wrap_sse_json(value)];
        }
        let response_id = value
            .get("id")
            .and_then(|candidate| candidate.as_str())
            .map(ToString::to_string)
            .or_else(|| self.response_id.clone())
            .unwrap_or_else(|| self.request_id.clone());
        self.response_id = Some(response_id.clone());

        let mut frames = Vec::new();
        if let Some(choices) = value
            .get("choices")
            .and_then(|candidate| candidate.as_array())
        {
            for choice in choices {
                if let Some(text) = choice
                    .pointer("/delta/content")
                    .and_then(|candidate| candidate.as_str())
                    .filter(|candidate| !candidate.is_empty())
                {
                    frames.push(wrap_sse_json(json!({
                        "type": "response.output_text.delta",
                        "response_id": response_id,
                        "delta": text,
                    })));
                }
                if let Some(tool_calls) = choice
                    .pointer("/delta/tool_calls")
                    .and_then(|candidate| candidate.as_array())
                {
                    for tool_call in tool_calls {
                        let index = tool_call
                            .get("index")
                            .and_then(|candidate| candidate.as_u64())
                            .unwrap_or(0) as usize;
                        let emit_start = {
                            let state = self.tool_states.entry(index).or_default();
                            if state.id.is_none() {
                                state.id = tool_call
                                    .get("id")
                                    .and_then(|candidate| candidate.as_str())
                                    .map(ToString::to_string);
                            }
                            if state.name.is_none() {
                                state.name = tool_call
                                    .pointer("/function/name")
                                    .and_then(|candidate| candidate.as_str())
                                    .map(ToString::to_string);
                            }
                            let emit_start = !state.start_emitted
                                && (state.id.is_some() || state.name.is_some());
                            if emit_start {
                                state.start_emitted = true;
                                state.stop_emitted = false;
                            }
                            emit_start
                        };
                        if emit_start {
                            let state = self.tool_states.get(&index).cloned().unwrap_or_default();
                            let call_id = state
                                .id
                                .unwrap_or_else(|| format!("call_{}_{}", self.request_id, index));
                            let name = state.name.unwrap_or_default();
                            frames.push(wrap_sse_json(json!({
                                "type": "response.output_item.added",
                                "response_id": response_id,
                                "output_index": index,
                                "item": {
                                    "type": "function_call",
                                    "id": call_id,
                                    "call_id": call_id,
                                    "name": name,
                                    "arguments": ""
                                }
                            })));
                        }
                        if let Some(arguments) = tool_call
                            .pointer("/function/arguments")
                            .and_then(|candidate| candidate.as_str())
                            .filter(|candidate| !candidate.is_empty())
                        {
                            let call_id = self
                                .tool_states
                                .get(&index)
                                .and_then(|state| state.id.clone())
                                .unwrap_or_default();
                            frames.push(wrap_sse_json(json!({
                                "type": "response.function_call_arguments.delta",
                                "response_id": response_id,
                                "output_index": index,
                                "call_id": call_id,
                                "delta": arguments,
                            })));
                        }
                    }
                }
                if choice
                    .get("finish_reason")
                    .and_then(|candidate| candidate.as_str())
                    .is_some()
                {
                    self.finished = true;
                    for (index, state) in self.tool_states.clone() {
                        if state.start_emitted && !state.stop_emitted {
                            if let Some(call_id) = state.id {
                                frames.push(wrap_sse_json(json!({
                                    "type": "response.function_call_arguments.done",
                                    "response_id": response_id,
                                    "output_index": index,
                                    "call_id": call_id,
                                })));
                            }
                        }
                    }
                    frames.push(wrap_sse_json(json!({
                        "type": "response.completed",
                        "response_id": response_id,
                    })));
                    frames.push(Bytes::from_static(b"data: [DONE]\n\n"));
                }
            }
        }

        frames
    }

    fn translate_openai_responses_to_messages(
        &mut self,
        value: &Value,
        event_type: &str,
    ) -> Vec<Bytes> {
        match event_type {
            "response.output_text.delta" => {
                let text = value
                    .get("delta")
                    .and_then(|candidate| candidate.as_str())
                    .unwrap_or("");
                if text.is_empty() {
                    return Vec::new();
                }
                let mut frames = Vec::new();
                if !self.message_started {
                    self.message_id = value
                        .get("response_id")
                        .and_then(|candidate| candidate.as_str())
                        .map(ToString::to_string)
                        .or_else(|| self.message_id.clone());
                    frames.push(self.ensure_message_start());
                }
                frames.push(wrap_sse_json(json!({
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {
                        "type": "text_delta",
                        "text": text,
                    }
                })));
                frames
            }
            "response.output_item.added" => {
                let item = value.get("item").cloned().unwrap_or_else(|| json!({}));
                if item.get("type").and_then(|candidate| candidate.as_str())
                    != Some("function_call")
                {
                    return Vec::new();
                }
                let index = value
                    .get("output_index")
                    .and_then(|candidate| candidate.as_u64())
                    .unwrap_or(0) as usize;
                let call_id = item
                    .get("call_id")
                    .or_else(|| item.get("id"))
                    .and_then(|candidate| candidate.as_str())
                    .unwrap_or_default()
                    .to_string();
                let name = item
                    .get("name")
                    .and_then(|candidate| candidate.as_str())
                    .unwrap_or_default()
                    .to_string();
                let emit_start = {
                    let state = self.tool_states.entry(index).or_default();
                    if state.id.is_none() {
                        state.id = Some(call_id.clone());
                    }
                    if state.name.is_none() {
                        state.name = Some(name.clone());
                    }
                    let emit_start = !state.start_emitted;
                    if emit_start {
                        state.start_emitted = true;
                        state.stop_emitted = false;
                    }
                    emit_start
                };
                let mut frames = Vec::new();
                if !self.message_started {
                    self.message_id = value
                        .get("response_id")
                        .and_then(|candidate| candidate.as_str())
                        .map(ToString::to_string)
                        .or_else(|| self.message_id.clone());
                    frames.push(self.ensure_message_start());
                }
                if emit_start {
                    frames.push(wrap_sse_json(json!({
                        "type": "content_block_start",
                        "index": index,
                        "content_block": {
                            "type": "tool_use",
                            "id": call_id,
                            "name": name,
                            "input": {}
                        }
                    })));
                }
                frames
            }
            "response.function_call_arguments.delta" => {
                let index = value
                    .get("output_index")
                    .and_then(|candidate| candidate.as_u64())
                    .unwrap_or(0) as usize;
                let delta = value
                    .get("delta")
                    .and_then(|candidate| candidate.as_str())
                    .unwrap_or("");
                if delta.is_empty() {
                    return Vec::new();
                }
                vec![wrap_sse_json(json!({
                    "type": "content_block_delta",
                    "index": index,
                    "delta": {
                        "type": "input_json_delta",
                        "partial_json": delta,
                    }
                }))]
            }
            "response.function_call_arguments.done" => {
                let index = value
                    .get("output_index")
                    .and_then(|candidate| candidate.as_u64())
                    .unwrap_or(0) as usize;
                let should_emit_stop = self
                    .tool_states
                    .get_mut(&index)
                    .map(|state| {
                        if state.stop_emitted {
                            false
                        } else {
                            state.stop_emitted = true;
                            true
                        }
                    })
                    .unwrap_or(false);
                if !should_emit_stop {
                    return Vec::new();
                }
                vec![wrap_sse_json(json!({
                    "type": "content_block_stop",
                    "index": index,
                }))]
            }
            "response.reasoning.delta" => {
                let text = value
                    .get("delta")
                    .and_then(|candidate| candidate.as_str())
                    .unwrap_or("");
                if text.is_empty() {
                    return Vec::new();
                }
                let mut frames = Vec::new();
                if !self.message_started {
                    self.message_id = value
                        .get("response_id")
                        .and_then(|candidate| candidate.as_str())
                        .map(ToString::to_string)
                        .or_else(|| self.message_id.clone());
                    frames.push(self.ensure_message_start());
                }
                frames.push(wrap_sse_json(json!({
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {
                        "type": "thinking_delta",
                        "thinking": text,
                    }
                })));
                frames
            }
            "response.completed" => self.finish_openai_messages("stop"),
            _ => Vec::new(),
        }
    }

    fn ensure_message_start(&mut self) -> Bytes {
        self.message_started = true;
        wrap_sse_json(json!({
            "type": "message_start",
            "message": {
                "id": self.message_id.clone().unwrap_or_else(|| format!("msg_{}", self.request_id)),
                "type": "message",
                "role": "assistant",
                "content": [],
            }
        }))
    }

    fn finish_openai_messages(&mut self, finish_reason: &str) -> Vec<Bytes> {
        if self.finished {
            return Vec::new();
        }
        self.finished = true;
        let mut frames = Vec::new();
        if !self.message_started {
            frames.push(self.ensure_message_start());
        }
        let open_indices = self
            .tool_states
            .iter_mut()
            .filter_map(|(index, state)| {
                if state.start_emitted && !state.stop_emitted {
                    state.stop_emitted = true;
                    Some(*index)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for index in open_indices {
            frames.push(wrap_sse_json(json!({
                "type": "content_block_stop",
                "index": index,
            })));
        }
        frames.push(wrap_sse_json(json!({
            "type": "message_delta",
            "delta": {
                "stop_reason": map_openai_finish_reason(finish_reason),
            }
        })));
        frames.push(wrap_sse_json(json!({ "type": "message_stop" })));
        frames
    }
}

fn map_openai_finish_reason(reason: &str) -> &'static str {
    match reason {
        "tool_calls" => "tool_use",
        "length" => "max_tokens",
        _ => "end_turn",
    }
}

fn wrap_sse_json(value: Value) -> Bytes {
    Bytes::from(format!("data: {}\n\n", value))
}

fn wrap_sse_payload(payload: &str) -> Option<Bytes> {
    if payload.is_empty() {
        None
    } else {
        Some(Bytes::from(format!("data: {payload}\n\n")))
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

    #[test]
    fn route_native_format_prefers_messages_path() {
        let body = json!({
            "model": "claude-sonnet-test",
            "messages": [{"role": "user", "content": "hello"}]
        });

        assert_eq!(
            route_native_format("/v1/messages", &body),
            ProviderFormat::Anthropic
        );
    }

    #[test]
    fn anthropic_stream_translates_to_responses_events() {
        let mut translator =
            RouteNativeSseTranslator::new("/v1/responses", ProviderFormat::Anthropic, "req_123");

        let start = translator.translate_payload(
            r#"{"type":"message_start","message":{"id":"msg_123","type":"message","role":"assistant"}}"#,
        );
        assert!(start.is_empty());

        let delta = translator.translate_payload(
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}"#,
        );
        assert_eq!(delta.len(), 1);
        let text = String::from_utf8(delta[0].to_vec()).unwrap_or_default();
        assert!(text.contains("\"type\":\"response.output_text.delta\""));
        assert!(text.contains("\"delta\":\"hello\""));

        let completed = translator.translate_payload(r#"{"type":"message_stop"}"#);
        assert_eq!(completed.len(), 2);
        let completed_text = String::from_utf8(completed[0].to_vec()).unwrap_or_default();
        assert!(completed_text.contains("\"type\":\"response.completed\""));
    }

    #[test]
    fn openai_chat_stream_translates_to_messages_events() {
        let mut translator =
            RouteNativeSseTranslator::new("/v1/messages", ProviderFormat::OpenAI, "req_123");

        let frames = translator.translate_payload(
            r#"{"id":"chatcmpl_123","object":"chat.completion.chunk","model":"gpt-5.4-mini","choices":[{"index":0,"delta":{"role":"assistant","content":"hello"},"finish_reason":null}]}"#,
        );

        assert_eq!(frames.len(), 2);
        let start = String::from_utf8(frames[0].to_vec()).unwrap_or_default();
        assert!(start.contains("\"type\":\"message_start\""));
        let delta = String::from_utf8(frames[1].to_vec()).unwrap_or_default();
        assert!(delta.contains("\"type\":\"content_block_delta\""));
        assert!(delta.contains("\"text\":\"hello\""));

        let finished = translator.translate_payload(
            r#"{"id":"chatcmpl_123","object":"chat.completion.chunk","model":"gpt-5.4-mini","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        );
        assert_eq!(finished.len(), 2);
        let message_delta = String::from_utf8(finished[0].to_vec()).unwrap_or_default();
        assert!(message_delta.contains("\"type\":\"message_delta\""));
        let message_stop = String::from_utf8(finished[1].to_vec()).unwrap_or_default();
        assert!(message_stop.contains("\"type\":\"message_stop\""));
    }
}

// ---------------------------------------------------------------------------
// Extended tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod extended_tests {
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
    use serde_json::json;
    use serde_json::Value;

    fn decode_sse_json(frame: &Bytes) -> Value {
        let text = std::str::from_utf8(frame).unwrap_or_default();
        let payload = text.strip_prefix("data: ").unwrap_or(text).trim();
        serde_json::from_str(payload).unwrap()
    }

    fn decode_sse_text(frame: &Bytes) -> String {
        std::str::from_utf8(frame).unwrap_or_default().to_string()
    }

    #[test]
    fn provider_format_from_str_all_variants() {
        assert_eq!(
            ProviderFormat::from_str("openai"),
            Some(ProviderFormat::OpenAI)
        );
        assert_eq!(
            ProviderFormat::from_str("anthropic"),
            Some(ProviderFormat::Anthropic)
        );
        assert_eq!(
            ProviderFormat::from_str("cohere"),
            Some(ProviderFormat::Cohere)
        );
        assert_eq!(
            ProviderFormat::from_str("huggingface"),
            Some(ProviderFormat::HuggingFace)
        );
        assert_eq!(
            ProviderFormat::from_str("replicate"),
            Some(ProviderFormat::Replicate)
        );
        assert_eq!(
            ProviderFormat::from_str("watsonx"),
            Some(ProviderFormat::WatsonX)
        );
        assert_eq!(
            ProviderFormat::from_str("google-gemini"),
            Some(ProviderFormat::GoogleGemini)
        );
        assert_eq!(
            ProviderFormat::from_str("aws-bedrock"),
            Some(ProviderFormat::AWSBedrock)
        );
        assert_eq!(
            ProviderFormat::from_str("bedrock"),
            Some(ProviderFormat::AWSBedrock)
        );
        assert_eq!(ProviderFormat::from_str("unknown"), None);
    }

    #[test]
    fn provider_format_as_str_roundtrip() {
        for variant in [
            ProviderFormat::OpenAI,
            ProviderFormat::Anthropic,
            ProviderFormat::Cohere,
            ProviderFormat::HuggingFace,
            ProviderFormat::Replicate,
            ProviderFormat::WatsonX,
            ProviderFormat::GoogleGemini,
            ProviderFormat::AWSBedrock,
        ] {
            let s = variant.as_str();
            assert!(ProviderFormat::from_str(s).is_some());
        }
    }

    #[test]
    fn infer_request_format_anthropic() {
        let body = json!({ "anthropic_version": "2024-01-01", "messages": [] });
        assert_eq!(infer_request_format(&body), ProviderFormat::Anthropic);
    }

    #[test]
    fn infer_request_format_watsonx() {
        let body = json!({ "model_id": "ibm/granite", "input": "hello" });
        assert_eq!(infer_request_format(&body), ProviderFormat::WatsonX);
    }

    #[test]
    fn infer_request_format_gemini() {
        let body = json!({ "contents": [{ "parts": [{ "text": "hi" }] }] });
        assert_eq!(infer_request_format(&body), ProviderFormat::GoogleGemini);
    }

    #[test]
    fn infer_request_format_gemini_system_instruction() {
        let body = json!({ "systemInstruction": { "parts": [] } });
        assert_eq!(infer_request_format(&body), ProviderFormat::GoogleGemini);
    }

    #[test]
    fn infer_request_format_cohere() {
        let body = json!({ "message": "hi", "chat_history": [] });
        assert_eq!(infer_request_format(&body), ProviderFormat::Cohere);
    }

    #[test]
    fn infer_request_format_huggingface() {
        let body = json!({ "inputs": "prompt text" });
        assert_eq!(infer_request_format(&body), ProviderFormat::HuggingFace);
    }

    #[test]
    fn infer_request_format_replicate() {
        let body = json!({ "input": { "prompt": "hi" } });
        assert_eq!(infer_request_format(&body), ProviderFormat::Replicate);
    }

    #[test]
    fn infer_request_format_openai_with_input() {
        let body = json!({ "input": "text", "model": "gpt-5.4" });
        assert_eq!(infer_request_format(&body), ProviderFormat::OpenAI);
    }

    #[test]
    fn infer_request_format_openai_responses_shape() {
        let body = json!({ "input": "text", "previous_response_id": "resp_123" });
        assert_eq!(infer_request_format(&body), ProviderFormat::OpenAI);
    }

    #[test]
    fn infer_request_format_default_openai() {
        let body = json!({ "messages": [{ "role": "user", "content": "hi" }] });
        assert_eq!(infer_request_format(&body), ProviderFormat::OpenAI);
    }

    #[test]
    fn translate_request_same_format_passthrough() {
        let body = json!({ "model": "test", "messages": [] });
        let result =
            translate_request(body.clone(), ProviderFormat::OpenAI, ProviderFormat::OpenAI)
                .unwrap();
        assert_eq!(result, body);
    }

    #[test]
    fn translate_response_same_format_passthrough() {
        let body = json!({ "choices": [] });
        let result =
            translate_response(body.clone(), ProviderFormat::OpenAI, ProviderFormat::OpenAI)
                .unwrap();
        assert_eq!(result, body);
    }

    #[test]
    fn translate_request_openai_to_cohere() {
        let body = json!({
            "model": "command-r",
            "messages": [
                { "role": "system", "content": "You are helpful." },
                { "role": "user", "content": "Hello!" }
            ],
            "temperature": 0.7
        });
        let result =
            translate_request(body, ProviderFormat::OpenAI, ProviderFormat::Cohere).unwrap();
        let messages = result["messages"].as_array().unwrap();
        assert_eq!(result["model"], "command-r");
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], "You are helpful.");
        assert_eq!(messages[1]["role"], "user");
        assert_eq!(messages[1]["content"], "Hello!");
        assert_eq!(result["temperature"], 0.7);
        assert_eq!(result["stream"], false);
    }

    #[test]
    fn translate_request_cohere_to_openai() {
        let body = json!({
            "model": "command-r",
            "messages": [
                { "role": "system", "content": "system prompt" },
                { "role": "user", "content": "prev question" },
                { "role": "assistant", "content": "prev answer" },
                { "role": "user", "content": "What is Rust?" }
            ]
        });
        let result =
            translate_request(body, ProviderFormat::Cohere, ProviderFormat::OpenAI).unwrap();
        let messages = result["messages"].as_array().unwrap();
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], "system prompt");
        assert_eq!(messages[1]["role"], "user");
        assert_eq!(messages[2]["role"], "assistant");
        assert_eq!(messages[3]["role"], "user");
        assert_eq!(messages[3]["content"], "What is Rust?");
    }

    #[test]
    fn translate_response_cohere_to_openai() {
        let body = json!({
            "message": {
                "role": "assistant",
                "content": "Here is the answer."
            }
        });
        let result =
            translate_response(body, ProviderFormat::Cohere, ProviderFormat::OpenAI).unwrap();
        let content = result["choices"][0]["message"]["content"].as_str().unwrap();
        assert_eq!(content, "Here is the answer.");
    }

    #[test]
    fn translate_request_openai_to_huggingface() {
        let body = json!({
            "model": "mistral",
            "messages": [
                { "role": "user", "content": "Hello" }
            ]
        });
        let result =
            translate_request(body, ProviderFormat::OpenAI, ProviderFormat::HuggingFace).unwrap();
        assert!(result.get("inputs").is_some());
    }

    #[test]
    fn translate_request_openai_to_replicate() {
        let body = json!({
            "model": "llama",
            "messages": [{ "role": "user", "content": "Hi" }],
            "temperature": 0.5
        });
        let result =
            translate_request(body, ProviderFormat::OpenAI, ProviderFormat::Replicate).unwrap();
        assert!(result.get("input").is_some());
    }

    #[test]
    fn openai_to_cohere_request_maps_history_and_defaults() {
        let body = json!({
            "model": "command-r",
            "messages": [
                { "role": "system", "content": "System prompt" },
                { "role": "user", "content": "first" },
                { "role": "assistant", "content": "reply" },
                { "role": "tool", "content": "ignored" },
                { "role": "user", "content": [{ "type": "text", "text": "latest" }] }
            ],
            "max_completion_tokens": 22,
            "top_p": 0.9
        });

        let result = openai_to_cohere_request(body).unwrap();
        let messages = result["messages"].as_array().unwrap();

        assert_eq!(result["model"], "command-r");
        assert_eq!(result["max_tokens"], 22);
        assert_eq!(result["top_p"], 0.9);
        assert_eq!(result["stream"], false);
        assert_eq!(messages.len(), 5);
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], "System prompt");
        assert_eq!(messages[1]["role"], "user");
        assert_eq!(messages[1]["content"], "first");
        assert_eq!(messages[2]["role"], "assistant");
        assert_eq!(messages[2]["content"], "reply");
        assert_eq!(messages[3]["role"], "tool");
        assert_eq!(messages[4]["role"], "user");
        assert_eq!(messages[4]["content"][0]["text"], "latest");
    }

    #[test]
    fn openai_to_cohere_response_preserves_finish_reason() {
        let body = json!({
            "choices": [{
                "message": { "role": "assistant", "content": [{ "type": "text", "text": "answer" }] },
                "finish_reason": "length"
            }]
        });

        let result = openai_to_cohere_response(body).unwrap();
        assert_eq!(result["text"], "answer");
        assert_eq!(result["finish_reason"], "length");
    }

    #[test]
    fn openai_to_replicate_request_prefers_latest_user_and_max_completion_tokens() {
        let body = json!({
            "messages": [
                { "role": "system", "content": "Rule one" },
                { "role": "system", "content": [{ "type": "text", "text": "Rule two" }] },
                { "role": "user", "content": "First prompt" },
                { "role": "assistant", "content": "Interim answer" },
                { "role": "user", "content": [{ "type": "text", "text": "Latest prompt" }] }
            ],
            "max_completion_tokens": 33,
            "temperature": 0.4,
            "top_p": 0.8
        });

        let result = openai_to_replicate_request(body).unwrap();
        assert_eq!(result["input"]["prompt"], "Latest prompt");
        assert_eq!(result["input"]["system_prompt"], "Rule one\n\nRule two");
        assert_eq!(result["input"]["max_new_tokens"], 33);
        assert_eq!(result["input"]["temperature"], 0.4);
        assert_eq!(result["input"]["top_p"], 0.8);
    }

    #[test]
    fn openai_to_huggingface_and_watsonx_requests_use_flattened_prompt() {
        let body = json!({
            "model": "ibm/granite",
            "messages": [
                { "role": "system", "content": "Follow policy" },
                { "role": "user", "content": "Hello" }
            ],
            "max_completion_tokens": 12,
            "temperature": 0.2,
            "top_p": 0.7
        });

        let huggingface = openai_to_huggingface_request(body.clone()).unwrap();
        assert_eq!(huggingface["inputs"], "system: Follow policy\nuser: Hello");
        assert_eq!(huggingface["parameters"]["max_new_tokens"], 12);
        assert_eq!(huggingface["parameters"]["temperature"], 0.2);
        assert_eq!(huggingface["parameters"]["top_p"], 0.7);

        let watsonx = openai_to_watsonx_request(body).unwrap();
        let messages = watsonx["messages"].as_array().unwrap();
        assert_eq!(watsonx["model_id"], "ibm/granite");
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], "Follow policy");
        assert_eq!(messages[1]["role"], "user");
        assert_eq!(messages[1]["content"], "Hello");
        assert_eq!(watsonx["max_completion_tokens"], 12);
        assert_eq!(watsonx["temperature"], 0.2);
        assert_eq!(watsonx["top_p"], 0.7);
    }

    #[test]
    fn route_native_format_chat_completions() {
        let body = json!({});
        assert_eq!(
            route_native_format("/v1/chat/completions", &body),
            ProviderFormat::OpenAI
        );
    }

    #[test]
    fn route_native_format_embeddings() {
        let body = json!({});
        assert_eq!(
            route_native_format("/v1/embeddings", &body),
            ProviderFormat::OpenAI
        );
    }

    #[test]
    fn route_native_format_unknown_path_infers() {
        let body = json!({ "anthropic_version": "2024-01-01" });
        assert_eq!(
            route_native_format("/custom/path", &body),
            ProviderFormat::Anthropic
        );
    }

    #[test]
    fn message_text_string_content() {
        let msg = json!({ "role": "user", "content": "hello" });
        assert_eq!(message_text(&msg), "hello");
    }

    #[test]
    fn message_text_array_content() {
        let msg = json!({
            "role": "user",
            "content": [
                { "type": "text", "text": "part1" },
                { "type": "text", "text": "part2" }
            ]
        });
        assert_eq!(message_text(&msg), "part1\npart2");
    }

    #[test]
    fn message_text_missing_content() {
        let msg = json!({ "role": "user" });
        assert_eq!(message_text(&msg), "");
    }

    #[test]
    fn latest_user_message_finds_last_user() {
        let messages = vec![
            json!({ "role": "user", "content": "first" }),
            json!({ "role": "assistant", "content": "reply" }),
            json!({ "role": "user", "content": "second" }),
        ];
        assert_eq!(latest_user_message(&messages), "second");
    }

    #[test]
    fn latest_user_message_empty() {
        let messages = vec![json!({ "role": "assistant", "content": "hi" })];
        assert_eq!(latest_user_message(&messages), "");
    }

    #[test]
    fn system_prompt_extracted() {
        let messages = vec![
            json!({ "role": "system", "content": "You are helpful." }),
            json!({ "role": "user", "content": "hi" }),
        ];
        assert_eq!(
            system_prompt(&messages),
            Some("You are helpful.".to_string())
        );
    }

    #[test]
    fn system_prompt_none_when_missing() {
        let messages = vec![json!({ "role": "user", "content": "hi" })];
        assert_eq!(system_prompt(&messages), None);
    }

    #[test]
    fn system_prompt_joins_multiple_non_empty_messages() {
        let messages = vec![
            json!({ "role": "system", "content": "Rule one" }),
            json!({ "role": "system", "content": "" }),
            json!({ "role": "system", "content": [{ "type": "text", "text": "Rule two" }] }),
        ];
        assert_eq!(
            system_prompt(&messages),
            Some("Rule one\n\nRule two".to_string())
        );
    }

    #[test]
    fn flattened_prompt_formats_roles() {
        let messages = vec![
            json!({ "role": "system", "content": "sys" }),
            json!({ "role": "user", "content": "hi" }),
        ];
        let result = flattened_prompt(&messages);
        assert!(result.contains("system: sys"));
        assert!(result.contains("user: hi"));
    }

    #[test]
    fn openai_response_content_extraction() {
        let body = json!({
            "choices": [{ "message": { "role": "assistant", "content": "answer" } }]
        });
        assert_eq!(openai_response_content(&body), "answer");
    }

    #[test]
    fn openai_finish_reason_default() {
        let body = json!({ "choices": [{}] });
        assert_eq!(openai_finish_reason(&body), "stop");
    }

    #[test]
    fn map_openai_finish_reason_mappings() {
        assert_eq!(map_openai_finish_reason("tool_calls"), "tool_use");
        assert_eq!(map_openai_finish_reason("length"), "max_tokens");
        assert_eq!(map_openai_finish_reason("stop"), "end_turn");
        assert_eq!(map_openai_finish_reason("anything"), "end_turn");
    }

    #[test]
    fn translate_response_for_path_chat_completions() {
        let anthropic_resp = json!({
            "content": [{ "type": "text", "text": "hello" }],
            "stop_reason": "end_turn"
        });
        let result = translate_response_for_path(
            anthropic_resp,
            ProviderFormat::Anthropic,
            "/v1/chat/completions",
        )
        .unwrap();
        assert!(result.get("choices").is_some());
    }

    #[test]
    fn translate_response_for_path_messages() {
        let openai_resp = json!({
            "choices": [{
                "message": { "role": "assistant", "content": "hello" },
                "finish_reason": "stop"
            }]
        });
        let result =
            translate_response_for_path(openai_resp, ProviderFormat::OpenAI, "/v1/messages")
                .unwrap();
        assert!(result.get("content").is_some());
    }

    #[test]
    fn translate_response_for_path_unknown_path_passthrough() {
        let body = json!({ "raw": true });
        let error =
            translate_response_for_path(body, ProviderFormat::Anthropic, "/custom").unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported response path translation"));
    }

    // ── extract_message_content ──────────────────────────────────────────

    #[test]
    fn extract_message_content_string() {
        let msg = json!({"content": "hello"});
        assert_eq!(extract_message_content(&msg), json!("hello"));
    }

    #[test]
    fn extract_message_content_single_text_block() {
        let msg = json!({
            "content": [{"type": "text", "text": "hello"}]
        });
        assert_eq!(extract_message_content(&msg), json!("hello"));
    }

    #[test]
    fn extract_message_content_mixed_blocks() {
        let msg = json!({
            "content": [
                {"type": "text", "text": "hello"},
                {"type": "tool_use", "id": "t1", "name": "search"}
            ]
        });
        let result = extract_message_content(&msg);
        assert!(result.is_array());
        assert_eq!(result.as_array().unwrap().len(), 2);
    }

    #[test]
    fn extract_message_content_image_url_data() {
        let msg = json!({
            "content": [
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,abc123"}}
            ]
        });
        let result = extract_message_content(&msg);
        let blocks = result.as_array().unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0]["type"], "image");
        assert_eq!(blocks[0]["source"]["type"], "base64");
    }

    #[test]
    fn extract_message_content_image_url_http() {
        let msg = json!({
            "content": [
                {"type": "image_url", "image_url": {"url": "https://example.com/img.png"}}
            ]
        });
        let result = extract_message_content(&msg);
        let blocks = result.as_array().unwrap();
        assert_eq!(blocks[0]["source"]["type"], "url");
    }

    #[test]
    fn extract_message_content_preserves_supported_non_text_blocks() {
        let msg = json!({
            "content": [
                {
                    "type": "document",
                    "source": {
                        "type": "base64",
                        "media_type": "application/pdf",
                        "data": "abc123"
                    }
                },
                {"type": "image_url", "image_url": {"url": "data:,imgdata"}},
                {"type": "tool_result", "tool_use_id": "toolu_1", "content": "ok"},
                {"type": "thinking", "thinking": "draft"},
                {"type": "ignored"}
            ]
        });

        let result = extract_message_content(&msg);
        let blocks = result.as_array().unwrap();

        assert_eq!(blocks.len(), 4);
        assert_eq!(blocks[0]["type"], "document");
        assert_eq!(blocks[1]["type"], "image");
        assert_eq!(blocks[1]["source"]["media_type"], "image/jpeg");
        assert_eq!(blocks[2]["type"], "tool_result");
        assert_eq!(blocks[3]["type"], "thinking");
    }

    #[test]
    fn extract_message_content_drops_non_pdf_documents() {
        let msg = json!({
            "content": [
                {
                    "type": "document",
                    "source": {
                        "type": "base64",
                        "media_type": "text/plain",
                        "data": "abc123"
                    }
                }
            ]
        });
        assert_eq!(extract_message_content(&msg), json!([]));
    }

    #[test]
    fn extract_message_content_missing() {
        let msg = json!({"role": "user"});
        assert_eq!(extract_message_content(&msg), json!(""));
    }

    // ── anthropic_content_to_openai ──────────────────────────────────────

    #[test]
    fn anthropic_content_to_openai_string() {
        let content = json!("hello");
        assert_eq!(anthropic_content_to_openai(Some(&content)), json!("hello"));
    }

    #[test]
    fn anthropic_content_to_openai_text_blocks() {
        let content = json!([
            {"type": "text", "text": "part1"},
            {"type": "text", "text": "part2"}
        ]);
        assert_eq!(
            anthropic_content_to_openai(Some(&content)),
            json!("part1part2")
        );
    }

    #[test]
    fn anthropic_content_to_openai_mixed_blocks() {
        let content = json!([
            {"type": "text", "text": "hello"},
            {"type": "tool_use", "id": "t1"}
        ]);
        let result = anthropic_content_to_openai(Some(&content));
        assert!(result.is_array());
    }

    #[test]
    fn anthropic_content_to_openai_none() {
        assert_eq!(anthropic_content_to_openai(None), json!(""));
    }

    #[test]
    fn anthropic_content_to_openai_preserves_non_string_non_array_values() {
        let content = json!({ "raw": true });
        assert_eq!(anthropic_content_to_openai(Some(&content)), content);
    }

    // ── extract_anthropic_text_content ────────────────────────────────────

    #[test]
    fn extract_anthropic_text_content_basic() {
        let body = json!({
            "content": [
                {"type": "text", "text": "first"},
                {"type": "text", "text": " second"},
                {"type": "tool_use", "name": "search"}
            ]
        });
        assert_eq!(extract_anthropic_text_content(&body), "first second");
    }

    #[test]
    fn extract_anthropic_text_content_empty() {
        let body = json!({"content": []});
        assert_eq!(extract_anthropic_text_content(&body), "");
    }

    // ── extract_anthropic_tool_uses ──────────────────────────────────────

    #[test]
    fn extract_anthropic_tool_uses_present() {
        let body = json!({
            "content": [
                {"type": "tool_use", "id": "t1", "name": "search", "input": {"q": "rust"}}
            ]
        });
        let tools = extract_anthropic_tool_uses(&body);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["function"]["name"], "search");
    }

    #[test]
    fn extract_anthropic_tool_uses_none() {
        let body = json!({
            "content": [{"type": "text", "text": "hello"}]
        });
        assert!(extract_anthropic_tool_uses(&body).is_empty());
    }

    // ── map_anthropic_stop_reason ────────────────────────────────────────

    #[test]
    fn map_anthropic_stop_reason_mappings() {
        assert_eq!(map_anthropic_stop_reason("end_turn"), "stop");
        assert_eq!(map_anthropic_stop_reason("max_tokens"), "length");
        assert_eq!(map_anthropic_stop_reason("tool_use"), "tool_calls");
        assert_eq!(map_anthropic_stop_reason("stop_sequence"), "stop");
        assert_eq!(map_anthropic_stop_reason("unknown"), "stop");
    }

    // ── map_anthropic_usage ──────────────────────────────────────────────

    #[test]
    fn map_anthropic_usage_sums() {
        let usage = json!({"input_tokens": 10, "output_tokens": 20});
        let result = map_anthropic_usage(&usage);
        assert_eq!(result["prompt_tokens"], 10);
        assert_eq!(result["completion_tokens"], 20);
        assert_eq!(result["total_tokens"], 30);
    }

    #[test]
    fn map_anthropic_usage_defaults_to_zero() {
        let usage = json!({});
        let result = map_anthropic_usage(&usage);
        assert_eq!(result["total_tokens"], 0);
    }

    // ── build_openai_response ────────────────────────────────────────────

    #[test]
    fn build_openai_response_structure() {
        let resp = build_openai_response(Some("gpt-4"), "Hello!".to_string(), "stop");
        assert_eq!(resp["choices"][0]["message"]["content"], "Hello!");
        assert_eq!(resp["choices"][0]["finish_reason"], "stop");
        assert_eq!(resp["model"], "gpt-4");
    }

    #[test]
    fn build_openai_response_no_model() {
        let resp = build_openai_response(None, "text".to_string(), "stop");
        assert_eq!(resp["model"], "translated-model");
    }

    // ── openai_messages ──────────────────────────────────────────────────

    #[test]
    fn openai_messages_extracts_array() {
        let body = json!({"messages": [{"role": "user", "content": "hi"}]});
        let msgs = openai_messages(&body);
        assert_eq!(msgs.len(), 1);
    }

    #[test]
    fn openai_messages_empty_when_missing() {
        assert!(openai_messages(&json!({})).is_empty());
    }

    // ── openai_response_content ──────────────────────────────────────────

    #[test]
    fn openai_response_content_empty_when_missing() {
        assert_eq!(openai_response_content(&json!({})), "");
    }

    // ── openai_finish_reason ─────────────────────────────────────────────

    #[test]
    fn openai_finish_reason_extracted() {
        let body = json!({"choices": [{"finish_reason": "length"}]});
        assert_eq!(openai_finish_reason(&body), "length");
    }

    // ── translate_request roundtrips ─────────────────────────────────────

    #[test]
    fn translate_request_anthropic_to_openai() {
        let body = json!({
            "model": "claude-3",
            "system": "You are helpful.",
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 100,
            "temperature": 0.5
        });
        let result =
            translate_request(body, ProviderFormat::Anthropic, ProviderFormat::OpenAI).unwrap();
        let messages = result["messages"].as_array().unwrap();
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], "You are helpful.");
        assert_eq!(messages[1]["role"], "user");
        assert_eq!(result["temperature"], 0.5);
    }

    #[test]
    fn translate_response_anthropic_to_openai() {
        let body = json!({
            "id": "msg_123",
            "model": "claude-3",
            "content": [{"type": "text", "text": "world"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 5, "output_tokens": 10}
        });
        let result =
            translate_response(body, ProviderFormat::Anthropic, ProviderFormat::OpenAI).unwrap();
        assert!(result.get("choices").is_some());
        let choice = &result["choices"][0];
        assert_eq!(choice["finish_reason"], "stop");
    }

    #[test]
    fn translate_request_openai_to_watsonx() {
        let body = json!({
            "model": "ibm/granite",
            "messages": [{"role": "user", "content": "hello"}]
        });
        let result =
            translate_request(body, ProviderFormat::OpenAI, ProviderFormat::WatsonX).unwrap();
        assert!(result.get("input").is_some() || result.get("model_id").is_some());
    }

    #[test]
    fn translate_request_openai_to_gemini() {
        let body = json!({
            "model": "gemini-pro",
            "messages": [{"role": "user", "content": "hello"}]
        });
        let result =
            translate_request(body, ProviderFormat::OpenAI, ProviderFormat::GoogleGemini).unwrap();
        assert!(result.get("contents").is_some());
    }

    #[test]
    fn translate_response_gemini_to_openai() {
        let body = json!({
            "candidates": [{
                "content": {"parts": [{"text": "hello"}]},
                "finishReason": "STOP"
            }]
        });
        let result =
            translate_response(body, ProviderFormat::GoogleGemini, ProviderFormat::OpenAI).unwrap();
        assert!(result.get("choices").is_some());
    }

    // ── wrap_sse helpers ─────────────────────────────────────────────────

    #[test]
    fn wrap_sse_json_produces_sse_format() {
        let bytes = wrap_sse_json(json!({"type": "test"}));
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(text.starts_with("data: "));
        assert!(text.ends_with("\n\n"));
    }

    #[test]
    fn wrap_sse_payload_some() {
        let result = wrap_sse_payload("test data");
        assert!(result.is_some());
        let text = String::from_utf8(result.unwrap().to_vec()).unwrap();
        assert!(text.contains("test data"));
    }

    #[test]
    fn wrap_sse_payload_empty_is_none() {
        assert!(wrap_sse_payload("").is_none());
    }

    #[test]
    fn wrap_sse_payload_done_is_some() {
        assert!(wrap_sse_payload("[DONE]").is_some());
    }

    // ── openai_to_anthropic_request ──────────────────────────────────────

    #[test]
    fn translate_request_openai_to_anthropic() {
        let body = json!({
            "model": "claude-3",
            "messages": [
                {"role": "system", "content": "Be helpful."},
                {"role": "user", "content": "hi"}
            ],
            "max_tokens": 50,
            "temperature": 0.8
        });
        let result =
            translate_request(body, ProviderFormat::OpenAI, ProviderFormat::Anthropic).unwrap();
        assert_eq!(result["system"], "Be helpful.");
        assert_eq!(result["temperature"], 0.8);
        let msgs = result["messages"].as_array().unwrap();
        assert!(msgs.iter().all(|m| m["role"] != "system"));
    }

    #[test]
    fn translate_response_for_path_responses_maps_tool_calls_and_usage() {
        let anthropic_resp = json!({
            "id": "msg_123",
            "model": "claude-sonnet-test",
            "content": [
                { "type": "text", "text": "hello" },
                { "type": "tool_use", "id": "toolu_1", "name": "search", "input": { "q": "rust" } }
            ],
            "usage": {
                "input_tokens": 12,
                "output_tokens": 7
            }
        });

        let result =
            translate_response_for_path(anthropic_resp, ProviderFormat::Anthropic, "/v1/responses")
                .unwrap();

        assert_eq!(result["object"], "response");
        assert_eq!(result["id"], "msg_123");
        assert_eq!(result["output"][0]["type"], "message");
        assert_eq!(result["output"][0]["content"][0]["text"], "hello");
        assert_eq!(result["output"][1]["type"], "function_call");
        assert_eq!(result["output"][1]["call_id"], "toolu_1");
        assert_eq!(result["output"][1]["name"], "search");
        assert_eq!(result["usage"]["prompt_tokens"], 12);
        assert_eq!(result["usage"]["completion_tokens"], 7);
        assert_eq!(result["usage"]["total_tokens"], 19);
    }

    #[test]
    fn google_gemini_request_roundtrip_preserves_roles_and_generation_config() {
        let openai = json!({
            "messages": [
                { "role": "system", "content": "Follow policy." },
                { "role": "user", "content": "Hello" },
                { "role": "assistant", "content": "Hi there" }
            ],
            "max_completion_tokens": 128,
            "temperature": 0.2,
            "top_p": 0.9,
            "stop": ["END"]
        });

        let gemini = openai_to_google_gemini_request(openai).unwrap();
        assert_eq!(
            gemini["systemInstruction"]["parts"][0]["text"],
            "Follow policy."
        );
        assert_eq!(gemini["contents"][0]["role"], "user");
        assert_eq!(gemini["contents"][1]["role"], "model");
        assert_eq!(gemini["generationConfig"]["maxOutputTokens"], 128);
        assert_eq!(gemini["generationConfig"]["stopSequences"][0], "END");

        let roundtrip = google_gemini_to_openai_request(gemini).unwrap();
        let messages = roundtrip["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[1]["role"], "user");
        assert_eq!(messages[2]["role"], "assistant");
        assert_eq!(roundtrip["max_tokens"], 128);
        assert_eq!(roundtrip["temperature"], 0.2);
        assert_eq!(roundtrip["top_p"], 0.9);
        assert_eq!(roundtrip["stop"][0], "END");
    }

    #[test]
    fn google_gemini_response_maps_usage_and_finish_reason() {
        let gemini = json!({
            "candidates": [{
                "finishReason": "SAFETY",
                "content": {
                    "parts": [{ "text": "moderated output" }]
                }
            }],
            "usageMetadata": {
                "promptTokenCount": 4,
                "candidatesTokenCount": 6,
                "totalTokenCount": 10
            }
        });

        let openai = google_gemini_to_openai_response(gemini).unwrap();
        assert_eq!(
            openai["choices"][0]["message"]["content"],
            "moderated output"
        );
        assert_eq!(openai["choices"][0]["finish_reason"], "content_filter");
        assert_eq!(openai["usage"]["prompt_tokens"], 4);
        assert_eq!(openai["usage"]["completion_tokens"], 6);
        assert_eq!(openai["usage"]["total_tokens"], 10);
    }

    #[test]
    fn anthropic_chat_sse_translation_emits_tool_and_reasoning_frames() {
        let mut translator = RouteNativeSseTranslator::new(
            "/v1/chat/completions",
            ProviderFormat::Anthropic,
            "req_123",
        );

        let start = translator.translate_payload(
            r#"{"type":"message_start","message":{"id":"msg_123","model":"claude-sonnet-test"}}"#,
        );
        assert_eq!(start.len(), 1);
        assert_eq!(
            decode_sse_json(&start[0])["choices"][0]["delta"]["role"],
            "assistant"
        );

        let tool_start = translator.translate_payload(
            r#"{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"search","input":{}}}"#,
        );
        assert_eq!(tool_start.len(), 1);
        assert_eq!(
            decode_sse_json(&tool_start[0])["choices"][0]["delta"]["tool_calls"][0]["function"]
                ["name"],
            "search"
        );

        let tool_delta = translator.translate_payload(
            r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"q\":\"rust\"}"}}"#,
        );
        assert_eq!(tool_delta.len(), 1);
        assert_eq!(
            decode_sse_json(&tool_delta[0])["choices"][0]["delta"]["tool_calls"][0]["function"]
                ["arguments"],
            "{\"q\":\"rust\"}"
        );

        let reasoning = translator.translate_payload(
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"step by step"}}"#,
        );
        assert_eq!(reasoning.len(), 1);
        assert_eq!(
            decode_sse_json(&reasoning[0])["choices"][0]["delta"]["reasoning"],
            "step by step"
        );

        let finish = translator
            .translate_payload(r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"}}"#);
        assert_eq!(finish.len(), 1);
        assert_eq!(
            decode_sse_json(&finish[0])["choices"][0]["finish_reason"],
            "tool_calls"
        );

        let done = translator.translate_payload(r#"{"type":"message_stop"}"#);
        assert_eq!(done.len(), 1);
        assert_eq!(
            std::str::from_utf8(done[0].as_ref()).unwrap(),
            "data: [DONE]\n\n"
        );
    }

    #[test]
    fn openai_responses_events_translate_to_messages_tool_and_reasoning_frames() {
        let mut translator =
            RouteNativeSseTranslator::new("/v1/messages", ProviderFormat::OpenAI, "req_456");

        let tool_start = translator.translate_payload(
            r#"{"type":"response.output_item.added","response_id":"resp_1","output_index":2,"item":{"type":"function_call","call_id":"call_1","name":"search"}}"#,
        );
        assert_eq!(tool_start.len(), 2);
        assert_eq!(decode_sse_json(&tool_start[0])["type"], "message_start");
        assert_eq!(
            decode_sse_json(&tool_start[1])["type"],
            "content_block_start"
        );
        assert_eq!(
            decode_sse_json(&tool_start[1])["content_block"]["name"],
            "search"
        );

        let tool_delta = translator.translate_payload(
            r#"{"type":"response.function_call_arguments.delta","response_id":"resp_1","output_index":2,"delta":"{\"q\":\"rust\"}"}"#,
        );
        assert_eq!(tool_delta.len(), 1);
        assert_eq!(
            decode_sse_json(&tool_delta[0])["delta"]["partial_json"],
            "{\"q\":\"rust\"}"
        );

        let reasoning = translator.translate_payload(
            r#"{"type":"response.reasoning.delta","response_id":"resp_1","delta":"drafting answer"}"#,
        );
        assert_eq!(reasoning.len(), 1);
        assert_eq!(
            decode_sse_json(&reasoning[0])["delta"]["type"],
            "thinking_delta"
        );

        let completed =
            translator.translate_payload(r#"{"type":"response.completed","response_id":"resp_1"}"#);
        assert_eq!(completed.len(), 3);
        assert_eq!(decode_sse_json(&completed[0])["type"], "content_block_stop");
        assert_eq!(decode_sse_json(&completed[1])["type"], "message_delta");
        assert_eq!(decode_sse_json(&completed[2])["type"], "message_stop");
    }

    #[test]
    fn unsupported_translation_pairs_return_errors() {
        let request = json!({ "message": "hi", "chat_history": [] });
        let response = json!({ "text": "hello" });

        assert!(
            translate_request(request, ProviderFormat::Cohere, ProviderFormat::WatsonX).is_err()
        );
        assert!(
            translate_response(response, ProviderFormat::Cohere, ProviderFormat::WatsonX).is_err()
        );
    }

    #[test]
    fn translate_response_for_path_responses_passthrough_when_source_is_not_anthropic() {
        let body = json!({
            "id": "chatcmpl_1",
            "object": "chat.completion",
            "choices": [{
                "message": { "role": "assistant", "content": "hello" },
                "finish_reason": "stop"
            }]
        });
        let result =
            translate_response_for_path(body, ProviderFormat::OpenAI, "/v1/responses").unwrap();

        assert_eq!(result["object"], "response");
        assert_eq!(result["output"][0]["content"][0]["text"], "hello");
    }

    #[test]
    fn cohere_and_huggingface_response_mappings_cover_fallback_shapes() {
        let cohere = json!({
            "message": {
                "content": [{ "text": "nested answer" }]
            }
        });
        let cohere_openai = cohere_to_openai_response(cohere).unwrap();
        assert_eq!(
            cohere_openai["choices"][0]["message"]["content"],
            "nested answer"
        );

        let openai = json!({
            "choices": [{
                "message": { "role": "assistant", "content": "hf text" },
                "finish_reason": "length"
            }]
        });
        let huggingface = openai_to_huggingface_response(openai).unwrap();
        assert_eq!(huggingface[0]["generated_text"], "hf text");

        let huggingface_object = json!({ "generated_text": "object branch" });
        let huggingface_openai = huggingface_to_openai_response(huggingface_object).unwrap();
        assert_eq!(
            huggingface_openai["choices"][0]["message"]["content"],
            "object branch"
        );
    }

    #[test]
    fn huggingface_request_translation_preserves_generation_parameters() {
        let body = json!({
            "inputs": "prompt text",
            "parameters": {
                "max_new_tokens": 77,
                "temperature": 0.4,
                "top_p": 0.8
            }
        });

        let openai = huggingface_to_openai_request(body).unwrap();
        assert_eq!(openai["messages"][0]["content"], "prompt text");
        assert_eq!(openai["max_tokens"], 77);
        assert_eq!(openai["temperature"], 0.4);
        assert_eq!(openai["top_p"], 0.8);
    }

    #[test]
    fn replicate_request_translation_handles_object_string_and_array_inputs() {
        let object_input = json!({
            "input": {
                "prompt": "Say hi",
                "system_prompt": "Be concise"
            }
        });
        let object_result = replicate_to_openai_request(object_input).unwrap();
        let object_messages = object_result["messages"].as_array().unwrap();
        assert_eq!(object_messages.len(), 2);
        assert_eq!(object_messages[0]["role"], "system");
        assert_eq!(object_messages[1]["content"], "Say hi");

        let string_input = json!({ "input": "just text" });
        let string_result = replicate_to_openai_request(string_input).unwrap();
        assert_eq!(string_result["messages"][0]["content"], "just text");

        let array_input = json!({
            "input": [
                "",
                "user text",
                { "role": "assistant", "content": [{ "type": "text", "text": "assistant text" }] },
                { "role": "user", "content": "   " }
            ]
        });
        let array_result = replicate_to_openai_request(array_input).unwrap();
        let messages = array_result["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "user");
        assert_eq!(messages[0]["content"], "user text");
        assert_eq!(messages[1]["role"], "assistant");
        assert_eq!(messages[1]["content"], "assistant text");
    }

    #[test]
    fn replicate_request_translation_without_input_returns_empty_messages() {
        let result = replicate_to_openai_request(json!({ "status": "queued" })).unwrap();
        assert_eq!(result, json!({ "messages": [] }));
    }

    #[test]
    fn replicate_and_watsonx_response_mappings_preserve_usage_and_stop_reason() {
        let replicate = json!({ "output": ["hello", " world"] });
        let replicate_openai = replicate_to_openai_response(replicate).unwrap();
        assert_eq!(
            replicate_openai["choices"][0]["message"]["content"],
            "hello world"
        );

        let openai = json!({
            "choices": [{
                "message": { "role": "assistant", "content": "converted" },
                "finish_reason": "length"
            }],
            "usage": { "prompt_tokens": 3 }
        });
        let replicate_response = openai_to_replicate_response(openai.clone()).unwrap();
        assert_eq!(replicate_response["status"], "succeeded");
        assert_eq!(replicate_response["output"], "converted");
        assert_eq!(replicate_response["usage"]["prompt_tokens"], 3);

        let watsonx = openai_to_watsonx_response(openai).unwrap();
        assert_eq!(watsonx["results"][0]["generated_text"], "converted");
        assert_eq!(watsonx["results"][0]["stop_reason"], "length");
    }

    #[test]
    fn watsonx_request_and_response_translation_preserve_parameters() {
        let request = json!({
            "model_id": "ibm/granite",
            "messages": [{ "role": "user", "content": "Explain Rust" }],
            "max_tokens": 64,
            "temperature": 0.1,
            "top_p": 0.7
        });

        let openai = watsonx_to_openai_request(request).unwrap();
        assert_eq!(openai["model"], "ibm/granite");
        assert_eq!(openai["messages"][0]["content"], "Explain Rust");
        assert_eq!(openai["max_tokens"], 64);
        assert_eq!(openai["temperature"], 0.1);
        assert_eq!(openai["top_p"], 0.7);

        let response = json!({
            "choices": [{
                "message": { "role": "assistant", "content": "granite answer" },
                "finish_reason": "stop"
            }]
        });
        let openai_response = watsonx_to_openai_response(response).unwrap();
        assert_eq!(
            openai_response["choices"][0]["message"]["content"],
            "granite answer"
        );
    }

    #[test]
    fn google_gemini_request_and_response_cover_system_join_and_length_mapping() {
        let request = json!({
            "systemInstruction": {
                "parts": [
                    { "text": "Line 1" },
                    { "text": "Line 2" }
                ]
            },
            "contents": [
                { "role": "user", "parts": [{ "text": "Question" }, { "text": "More detail" }] },
                { "role": "model", "parts": [{ "text": "Answer" }] }
            ],
            "generationConfig": {
                "maxOutputTokens": 12,
                "temperature": 0.6,
                "topP": 0.9,
                "stopSequences": ["STOP"]
            }
        });

        let openai = google_gemini_to_openai_request(request).unwrap();
        let messages = openai["messages"].as_array().unwrap();
        assert_eq!(messages[0]["content"], "Line 1\nLine 2");
        assert_eq!(messages[1]["content"], "Question\nMore detail");
        assert_eq!(messages[2]["role"], "assistant");
        assert_eq!(openai["max_tokens"], 12);
        assert_eq!(openai["temperature"], 0.6);
        assert_eq!(openai["top_p"], 0.9);
        assert_eq!(openai["stop"][0], "STOP");

        let response = json!({
            "choices": [{
                "message": { "role": "assistant", "content": "halted" },
                "finish_reason": "length"
            }]
        });
        let gemini = openai_to_google_gemini_response(response).unwrap();
        assert_eq!(gemini["candidates"][0]["finishReason"], "MAX_TOKENS");
        assert_eq!(
            gemini["candidates"][0]["content"]["parts"][0]["text"],
            "halted"
        );
    }

    #[test]
    fn openai_to_google_gemini_response_maps_content_filter_finish_reason() {
        let response = json!({
            "choices": [{
                "message": { "role": "assistant", "content": "blocked" },
                "finish_reason": "content_filter"
            }]
        });

        let gemini = openai_to_google_gemini_response(response).unwrap();
        assert_eq!(gemini["candidates"][0]["finishReason"], "SAFETY");
        assert_eq!(
            gemini["candidates"][0]["content"]["parts"][0]["text"],
            "blocked"
        );
    }

    #[test]
    fn openai_to_anthropic_request_maps_tools_metadata_and_tool_results() {
        let body = json!({
            "model": "claude-sonnet-test",
            "messages": [
                { "role": "system", "content": "System rule" },
                {
                    "role": "user",
                    "content": [
                        { "type": "text", "text": "hello" },
                        {
                            "type": "document",
                            "source": {
                                "type": "base64",
                                "media_type": "application/pdf",
                                "data": "abc123"
                            }
                        }
                    ]
                },
                { "role": "tool", "tool_call_id": "toolu_1", "content": "tool output" }
            ],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "search",
                    "description": "Search docs",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "q": { "type": "string" }
                        }
                    }
                }
            }],
            "tool_choice": {
                "function": { "name": "search" }
            },
            "custom_flag": true,
            "verdictan": { "internal": true }
        });

        let result = openai_to_anthropic_request(body).unwrap();
        let messages = result["messages"].as_array().unwrap();
        let first_content = messages[0]["content"].as_array().unwrap();
        let tool_result = messages[1]["content"].as_array().unwrap();

        assert_eq!(result["system"], "System rule");
        assert_eq!(result["max_tokens"], 4096);
        assert_eq!(messages.len(), 2);
        assert_eq!(first_content[0]["type"], "text");
        assert_eq!(first_content[1]["type"], "document");
        assert_eq!(tool_result[0]["type"], "tool_result");
        assert_eq!(tool_result[0]["tool_use_id"], "toolu_1");
        assert_eq!(result["tools"][0]["name"], "search");
        assert_eq!(result["tool_choice"]["type"], "tool");
        assert_eq!(result["tool_choice"]["name"], "search");
        assert_eq!(result["metadata"]["custom_flag"], true);
        assert!(result["metadata"].get("verdictan").is_none());
    }

    #[test]
    fn openai_to_anthropic_request_uses_input_string_and_required_tool_choice() {
        let body = json!({
            "input": "Hello from responses",
            "max_completion_tokens": 21,
            "tool_choice": "required"
        });

        let result = openai_to_anthropic_request(body).unwrap();
        assert_eq!(result["max_tokens"], 21);
        assert_eq!(result["tool_choice"]["type"], "any");
        assert_eq!(result["messages"][0]["role"], "user");
        assert_eq!(result["messages"][0]["content"], "Hello from responses");
    }

    #[test]
    fn openai_to_anthropic_request_maps_string_tool_choice_variants_without_metadata() {
        let auto = openai_to_anthropic_request(json!({
            "messages": [],
            "tool_choice": "auto"
        }))
        .unwrap();
        assert_eq!(auto["tool_choice"]["type"], "auto");
        assert!(auto.get("metadata").is_none());

        let none = openai_to_anthropic_request(json!({
            "messages": [],
            "tool_choice": "none"
        }))
        .unwrap();
        assert_eq!(none["tool_choice"]["type"], "none");
    }

    #[test]
    fn anthropic_to_openai_request_and_response_map_tools_and_usage() {
        let request = json!({
            "model": "claude-sonnet-test",
            "system": "Stay helpful",
            "messages": [{
                "role": "assistant",
                "content": [
                    { "type": "text", "text": "hello" },
                    { "type": "tool_use", "id": "toolu_1", "name": "search", "input": { "q": "rust" } }
                ]
            }],
            "tools": [{
                "name": "search",
                "description": "Search docs",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "q": { "type": "string" }
                    }
                }
            }],
            "tool_choice": {
                "type": "tool",
                "name": "search"
            },
            "max_tokens": 42,
            "temperature": 0.2,
            "top_p": 0.7,
            "stream": true
        });

        let openai = anthropic_to_openai_request(request).unwrap();
        assert_eq!(openai["messages"][0]["role"], "system");
        assert_eq!(openai["messages"][1]["role"], "assistant");
        assert!(openai["messages"][1]["content"].is_array());
        assert_eq!(openai["tools"][0]["function"]["name"], "search");
        assert_eq!(openai["tool_choice"]["function"]["name"], "search");
        assert_eq!(openai["max_tokens"], 42);
        assert_eq!(openai["temperature"], 0.2);
        assert_eq!(openai["top_p"], 0.7);
        assert_eq!(openai["stream"], true);

        let response = json!({
            "id": "msg_abc",
            "model": "claude-sonnet-test",
            "content": [
                { "type": "text", "text": "done" },
                { "type": "tool_use", "id": "toolu_1", "name": "search", "input": { "q": "rust" } }
            ],
            "stop_reason": "tool_use",
            "usage": { "input_tokens": 2, "output_tokens": 5 }
        });

        let translated = anthropic_to_openai_response(response).unwrap();
        assert_eq!(translated["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(
            translated["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"],
            "{\"q\":\"rust\"}"
        );
        assert_eq!(translated["usage"]["total_tokens"], 7);
    }

    #[test]
    fn anthropic_to_openai_request_maps_non_tool_variants_to_string_tool_choices() {
        let required = anthropic_to_openai_request(json!({
            "messages": [],
            "tool_choice": { "type": "any" }
        }))
        .unwrap();
        assert_eq!(required["tool_choice"], "required");

        let none = anthropic_to_openai_request(json!({
            "messages": [],
            "tool_choice": { "type": "none" }
        }))
        .unwrap();
        assert_eq!(none["tool_choice"], "none");

        let auto = anthropic_to_openai_request(json!({
            "messages": [],
            "tool_choice": { "type": "unknown" }
        }))
        .unwrap();
        assert_eq!(auto["tool_choice"], "auto");
    }

    #[test]
    fn anthropic_to_openai_request_tool_choice_without_name_falls_back_to_auto() {
        let translated = anthropic_to_openai_request(json!({
            "messages": [],
            "tool_choice": { "type": "tool" }
        }))
        .unwrap();
        assert_eq!(translated["tool_choice"], "auto");
    }

    #[test]
    fn openai_to_anthropic_response_maps_length_finish_reason_and_usage_defaults() {
        let response = json!({
            "id": "chatcmpl_123",
            "model": "gpt-5.4",
            "choices": [{
                "message": { "role": "assistant", "content": "partial" },
                "finish_reason": "length"
            }]
        });

        let anthropic = openai_to_anthropic_response(response).unwrap();
        assert_eq!(anthropic["stop_reason"], "max_tokens");
        assert_eq!(anthropic["usage"]["input_tokens"], 0);
        assert_eq!(anthropic["usage"]["output_tokens"], 0);
        assert_eq!(anthropic["content"][0]["text"], "partial");
    }

    #[test]
    fn translate_anthropic_sse_event_maps_start_delta_and_finish_reason() {
        let start = translate_anthropic_sse_event(
            r#"{"type":"message_start"}"#,
            "req_1",
            "claude-sonnet-test",
        )
        .unwrap();
        let start_json: Value = serde_json::from_slice(&start).unwrap();
        assert_eq!(start_json["choices"][0]["delta"]["role"], "assistant");

        let delta = translate_anthropic_sse_event(
            r#"{"type":"content_block_delta","delta":{"text":"hello"}}"#,
            "req_1",
            "claude-sonnet-test",
        )
        .unwrap();
        let delta_json: Value = serde_json::from_slice(&delta).unwrap();
        assert_eq!(delta_json["choices"][0]["delta"]["content"], "hello");

        let finish = translate_anthropic_sse_event(
            r#"{"type":"message_delta","delta":{"stop_reason":"max_tokens"}}"#,
            "req_1",
            "claude-sonnet-test",
        )
        .unwrap();
        let finish_json: Value = serde_json::from_slice(&finish).unwrap();
        assert_eq!(finish_json["choices"][0]["finish_reason"], "length");
    }

    #[test]
    fn translate_anthropic_sse_event_suppresses_control_events() {
        assert!(translate_anthropic_sse_event(r#"{"type":"ping"}"#, "req_1", "claude").is_none());
        assert!(translate_anthropic_sse_event("not json", "req_1", "claude").is_none());
    }

    #[test]
    fn translate_anthropic_sse_event_ignores_message_delta_without_stop_reason() {
        assert!(translate_anthropic_sse_event(
            r#"{"type":"message_delta","delta":{"usage":{"input_tokens":1}}}"#,
            "req_1",
            "claude"
        )
        .is_none());
    }

    #[test]
    fn route_native_sse_translator_handles_passthrough_error_and_tool_call_done_events() {
        let mut passthrough =
            RouteNativeSseTranslator::new("/custom", ProviderFormat::Anthropic, "req_passthrough");
        let wrapped = passthrough.translate_payload(r#"{"raw":"value"}"#);
        assert_eq!(wrapped.len(), 1);
        assert!(std::str::from_utf8(wrapped[0].as_ref())
            .unwrap()
            .contains(r#"{"raw":"value"}"#));

        let mut openai_messages =
            RouteNativeSseTranslator::new("/v1/messages", ProviderFormat::OpenAI, "req_error");
        let error = openai_messages.translate_payload(r#"{"error":{"message":"boom"}}"#);
        assert_eq!(error.len(), 1);
        assert_eq!(decode_sse_json(&error[0])["error"]["message"], "boom");

        let tool_start = openai_messages.translate_payload(
            r#"{"type":"response.output_item.added","response_id":"resp_1","output_index":2,"item":{"type":"function_call","call_id":"call_1","name":"search"}}"#,
        );
        assert_eq!(tool_start.len(), 2);
        assert_eq!(
            decode_sse_json(&tool_start[1])["type"],
            "content_block_start"
        );

        let tool_done = openai_messages.translate_payload(
            r#"{"type":"response.function_call_arguments.done","response_id":"resp_1","output_index":2}"#,
        );
        assert_eq!(tool_done.len(), 1);
        assert_eq!(decode_sse_json(&tool_done[0])["type"], "content_block_stop");
    }

    #[test]
    fn openai_chat_tool_call_stream_translates_to_messages_tool_frames() {
        let mut translator =
            RouteNativeSseTranslator::new("/v1/messages", ProviderFormat::OpenAI, "req_tool");

        let frames = translator.translate_payload(
            r#"{"id":"chatcmpl_123","object":"chat.completion.chunk","model":"gpt-5.4-mini","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":1,"id":"call_1","function":{"name":"search","arguments":"{\"q\":\"rust\"}"}}]},"finish_reason":null}]}"#,
        );

        assert_eq!(frames.len(), 3);
        assert_eq!(decode_sse_json(&frames[0])["type"], "message_start");
        assert_eq!(decode_sse_json(&frames[1])["type"], "content_block_start");
        assert_eq!(
            decode_sse_json(&frames[1])["content_block"]["name"],
            "search"
        );
        assert_eq!(decode_sse_json(&frames[2])["type"], "content_block_delta");
        assert_eq!(
            decode_sse_json(&frames[2])["delta"]["partial_json"],
            "{\"q\":\"rust\"}"
        );
    }

    #[test]
    fn infer_request_format_openai_input_hints_cover_remaining_responses_fields() {
        for body in [
            json!({ "input": "hello", "instructions": "stay concise" }),
            json!({ "input": "hello", "max_output_tokens": 32 }),
            json!({ "input": "hello", "response_format": { "type": "json_object" } }),
            json!({ "input": "hello", "modalities": ["text"] }),
            json!({ "input": "hello", "text": { "format": "markdown" } }),
        ] {
            assert_eq!(infer_request_format(&body), ProviderFormat::OpenAI);
        }
    }

    #[test]
    fn route_native_format_forces_openai_on_remaining_public_family_paths() {
        let anthropic_looking_body = json!({ "anthropic_version": "2024-01-01" });

        for path in [
            "/v1/responses",
            "/v1/audio/transcriptions",
            "/v1/audio/speech",
        ] {
            assert_eq!(
                route_native_format(path, &anthropic_looking_body),
                ProviderFormat::OpenAI
            );
        }
    }

    #[test]
    fn translate_request_dispatch_covers_remaining_native_to_openai_branches() {
        let huggingface = translate_request(
            json!({
                "inputs": "prompt text",
                "parameters": {
                    "max_new_tokens": 77,
                    "temperature": 0.4,
                    "top_p": 0.8
                }
            }),
            ProviderFormat::HuggingFace,
            ProviderFormat::OpenAI,
        )
        .unwrap();
        assert_eq!(huggingface["messages"][0]["content"], "prompt text");
        assert_eq!(huggingface["max_tokens"], 77);

        let replicate = translate_request(
            json!({
                "input": {
                    "prompt": "Say hi",
                    "system_prompt": "Be concise"
                }
            }),
            ProviderFormat::Replicate,
            ProviderFormat::OpenAI,
        )
        .unwrap();
        let replicate_messages = replicate["messages"].as_array().unwrap();
        assert_eq!(replicate_messages.len(), 2);
        assert_eq!(replicate_messages[0]["role"], "system");
        assert_eq!(replicate_messages[1]["content"], "Say hi");

        let watsonx = translate_request(
            json!({
                "model_id": "ibm/granite",
                "messages": [{ "role": "user", "content": "Explain Rust" }],
                "max_tokens": 64,
                "temperature": 0.1,
                "top_p": 0.7
            }),
            ProviderFormat::WatsonX,
            ProviderFormat::OpenAI,
        )
        .unwrap();
        assert_eq!(watsonx["model"], "ibm/granite");
        assert_eq!(watsonx["messages"][0]["content"], "Explain Rust");
        assert_eq!(watsonx["max_tokens"], 64);

        let gemini = translate_request(
            json!({
                "systemInstruction": {
                    "parts": [{ "text": "Line 1" }, { "text": "Line 2" }]
                },
                "contents": [
                    { "role": "user", "parts": [{ "text": "Question" }, { "text": "More detail" }] },
                    { "role": "model", "parts": [{ "text": "Answer" }] }
                ],
                "generationConfig": {
                    "maxOutputTokens": 12,
                    "temperature": 0.6,
                    "topP": 0.9,
                    "stopSequences": ["STOP"]
                }
            }),
            ProviderFormat::GoogleGemini,
            ProviderFormat::OpenAI,
        )
        .unwrap();
        let gemini_messages = gemini["messages"].as_array().unwrap();
        assert_eq!(gemini_messages[0]["role"], "system");
        assert_eq!(gemini_messages[1]["content"], "Question\nMore detail");
        assert_eq!(gemini["top_p"], 0.9);
    }

    #[test]
    fn translate_response_dispatch_covers_remaining_openai_to_native_branches() {
        let openai = json!({
            "id": "chatcmpl_123",
            "model": "gpt-5.4",
            "choices": [{
                "message": { "role": "assistant", "content": "converted" },
                "finish_reason": "length"
            }],
            "usage": {
                "prompt_tokens": 3,
                "completion_tokens": 4,
                "total_tokens": 7
            }
        });

        let anthropic = translate_response(
            openai.clone(),
            ProviderFormat::OpenAI,
            ProviderFormat::Anthropic,
        )
        .unwrap();
        assert_eq!(anthropic["stop_reason"], "max_tokens");
        assert_eq!(anthropic["usage"]["output_tokens"], 4);

        let cohere = translate_response(
            openai.clone(),
            ProviderFormat::OpenAI,
            ProviderFormat::Cohere,
        )
        .unwrap();
        assert_eq!(cohere["text"], "converted");
        assert_eq!(cohere["finish_reason"], "length");

        let huggingface = translate_response(
            openai.clone(),
            ProviderFormat::OpenAI,
            ProviderFormat::HuggingFace,
        )
        .unwrap();
        assert_eq!(huggingface[0]["generated_text"], "converted");

        let replicate = translate_response(
            openai.clone(),
            ProviderFormat::OpenAI,
            ProviderFormat::Replicate,
        )
        .unwrap();
        assert_eq!(replicate["status"], "succeeded");
        assert_eq!(replicate["output"], "converted");

        let watsonx = translate_response(
            openai.clone(),
            ProviderFormat::OpenAI,
            ProviderFormat::WatsonX,
        )
        .unwrap();
        assert_eq!(watsonx["results"][0]["generated_text"], "converted");
        assert_eq!(watsonx["results"][0]["stop_reason"], "length");

        let gemini =
            translate_response(openai, ProviderFormat::OpenAI, ProviderFormat::GoogleGemini)
                .unwrap();
        assert_eq!(gemini["candidates"][0]["finishReason"], "MAX_TOKENS");
        assert_eq!(
            gemini["candidates"][0]["content"]["parts"][0]["text"],
            "converted"
        );
    }

    #[test]
    fn translate_response_dispatch_covers_remaining_native_to_openai_branches() {
        let huggingface = translate_response(
            json!({ "generated_text": "object branch" }),
            ProviderFormat::HuggingFace,
            ProviderFormat::OpenAI,
        )
        .unwrap();
        assert_eq!(
            huggingface["choices"][0]["message"]["content"],
            "object branch"
        );

        let replicate = translate_response(
            json!({ "output": ["hello", " world"] }),
            ProviderFormat::Replicate,
            ProviderFormat::OpenAI,
        )
        .unwrap();
        assert_eq!(replicate["choices"][0]["message"]["content"], "hello world");

        let watsonx = translate_response(
            json!({
                "choices": [{
                    "message": { "role": "assistant", "content": "granite answer" },
                    "finish_reason": "stop"
                }]
            }),
            ProviderFormat::WatsonX,
            ProviderFormat::OpenAI,
        )
        .unwrap();
        assert_eq!(
            watsonx["choices"][0]["message"]["content"],
            "granite answer"
        );
    }

    #[test]
    fn route_native_sse_translator_handles_anthropic_chat_edge_cases() {
        let mut translator = RouteNativeSseTranslator::new(
            "/v1/chat/completions",
            ProviderFormat::Anthropic,
            "req_chat_edge",
        );

        assert!(translator.translate_payload("[DONE]").is_empty());

        let invalid = translator.translate_payload("not-json");
        assert_eq!(invalid.len(), 1);
        assert_eq!(decode_sse_text(&invalid[0]), "data: not-json\n\n");

        let missing_type = translator.translate_payload(r#"{"delta":{"text":"hello"}}"#);
        assert_eq!(missing_type.len(), 1);
        assert_eq!(
            decode_sse_text(&missing_type[0]),
            "data: {\"delta\":{\"text\":\"hello\"}}\n\n"
        );

        assert!(translator
            .translate_payload(
                r#"{"type":"content_block_start","index":0,"content_block":{"type":"text"}}"#,
            )
            .is_empty());
        assert!(translator
            .translate_payload(
                r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":""}}"#,
            )
            .is_empty());
        assert!(translator
            .translate_payload(
                r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":""}}"#,
            )
            .is_empty());
        assert!(translator
            .translate_payload(
                r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":""}}"#,
            )
            .is_empty());
        assert!(translator
            .translate_payload(
                r#"{"type":"content_block_delta","index":0,"delta":{"type":"unknown"}}"#,
            )
            .is_empty());
        assert!(translator
            .translate_payload(r#"{"type":"message_stop"}"#)
            .is_empty());

        let finish =
            translator.translate_payload(r#"{"type":"message_delta","delta":{"usage":{}}}"#);
        assert_eq!(finish.len(), 1);
        assert_eq!(
            decode_sse_json(&finish[0])["choices"][0]["finish_reason"],
            "stop"
        );
    }

    #[test]
    fn route_native_sse_translator_handles_anthropic_responses_edge_cases() {
        let mut translator =
            RouteNativeSseTranslator::new("/v1/responses", ProviderFormat::Anthropic, "req_resp");

        assert!(translator.translate_payload("[DONE]").is_empty());

        let invalid = translator.translate_payload("not-json");
        assert_eq!(invalid.len(), 1);
        assert_eq!(decode_sse_text(&invalid[0]), "data: not-json\n\n");

        let missing_type = translator.translate_payload(r#"{"delta":{"text":"hello"}}"#);
        assert_eq!(missing_type.len(), 1);
        assert_eq!(
            decode_sse_text(&missing_type[0]),
            "data: {\"delta\":{\"text\":\"hello\"}}\n\n"
        );

        assert!(translator
            .translate_payload(
                r#"{"type":"content_block_start","index":0,"content_block":{"type":"text"}}"#,
            )
            .is_empty());
        assert!(translator
            .translate_payload(
                r#"{"type":"content_block_delta","delta":{"type":"text_delta","text":""}}"#,
            )
            .is_empty());
        assert!(translator
            .translate_payload(
                r#"{"type":"content_block_delta","delta":{"type":"thinking_delta","thinking":""}}"#,
            )
            .is_empty());
        assert!(translator
            .translate_payload(
                r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"q\":\"rust\"}"}}"#,
            )
            .is_empty());
        assert!(translator
            .translate_payload(r#"{"type":"content_block_stop","index":1}"#)
            .is_empty());
        assert!(translator
            .translate_payload(r#"{"type":"ping"}"#)
            .is_empty());
    }

    #[test]
    fn route_native_sse_translator_handles_openai_message_edge_cases() {
        let mut translator =
            RouteNativeSseTranslator::new("/v1/messages", ProviderFormat::OpenAI, "req_openai");

        assert!(translator.translate_payload("[DONE]").is_empty());

        let invalid = translator.translate_payload("not-json");
        assert_eq!(invalid.len(), 1);
        assert_eq!(decode_sse_text(&invalid[0]), "data: not-json\n\n");

        let text_frames = translator
            .translate_payload(r#"{"type":"response.output_text.delta","delta":"hello"}"#);
        assert_eq!(text_frames.len(), 2);
        assert_eq!(
            decode_sse_json(&text_frames[0])["message"]["id"],
            "msg_req_openai"
        );
        assert_eq!(decode_sse_json(&text_frames[1])["delta"]["text"], "hello");

        assert!(translator
            .translate_payload(r#"{"type":"response.output_text.delta","delta":""}"#)
            .is_empty());
        assert!(translator
            .translate_payload(
                r#"{"type":"response.output_item.added","output_index":0,"item":{"type":"message"}}"#,
            )
            .is_empty());
        assert!(translator
            .translate_payload(
                r#"{"type":"response.function_call_arguments.delta","output_index":0,"delta":""}"#,
            )
            .is_empty());
        assert!(translator
            .translate_payload(r#"{"type":"response.reasoning.delta","delta":""}"#)
            .is_empty());
        assert!(translator
            .translate_payload(r#"{"type":"response.unknown"}"#)
            .is_empty());
    }

    #[test]
    fn route_native_sse_translator_emits_anthropic_response_tool_frames() {
        let mut translator = RouteNativeSseTranslator::new(
            "/v1/responses",
            ProviderFormat::Anthropic,
            "req_resp_tool",
        );

        assert!(translator
            .translate_payload(
                r#"{"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-test"}}"#,
            )
            .is_empty());

        let start = translator.translate_payload(
            r#"{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"search","input":{}}}"#,
        );
        assert_eq!(start.len(), 1);
        assert_eq!(
            decode_sse_json(&start[0])["type"],
            "response.output_item.added"
        );
        assert_eq!(decode_sse_json(&start[0])["item"]["call_id"], "toolu_1");

        let delta = translator.translate_payload(
            r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"q\":\"rust\"}"}}"#,
        );
        assert_eq!(delta.len(), 1);
        assert_eq!(
            decode_sse_json(&delta[0])["type"],
            "response.function_call_arguments.delta"
        );
        assert_eq!(decode_sse_json(&delta[0])["call_id"], "toolu_1");
        assert_eq!(decode_sse_json(&delta[0])["delta"], "{\"q\":\"rust\"}");

        let done = translator.translate_payload(r#"{"type":"content_block_stop","index":1}"#);
        assert_eq!(done.len(), 1);
        assert_eq!(
            decode_sse_json(&done[0])["type"],
            "response.function_call_arguments.done"
        );
        assert_eq!(decode_sse_json(&done[0])["call_id"], "toolu_1");
    }

    #[test]
    fn route_native_sse_translator_suppresses_duplicate_openai_completion_finish() {
        let mut translator =
            RouteNativeSseTranslator::new("/v1/messages", ProviderFormat::OpenAI, "req_done");

        let first =
            translator.translate_payload(r#"{"type":"response.completed","response_id":"resp_1"}"#);
        assert_eq!(first.len(), 3);
        assert_eq!(decode_sse_json(&first[0])["type"], "message_start");
        assert_eq!(decode_sse_json(&first[1])["type"], "message_delta");
        assert_eq!(decode_sse_json(&first[2])["type"], "message_stop");

        assert!(translator
            .translate_payload(r#"{"type":"response.completed","response_id":"resp_1"}"#)
            .is_empty());
    }
}

#[cfg(test)]
mod coverage_expansion_format_tests {
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
    use serde_json::json;

    // ── ProviderFormat ───────────────────────────────────────────────────

    #[test]
    fn provider_format_from_str_all_variants() {
        assert_eq!(
            ProviderFormat::from_str("openai"),
            Some(ProviderFormat::OpenAI)
        );
        assert_eq!(
            ProviderFormat::from_str("anthropic"),
            Some(ProviderFormat::Anthropic)
        );
        assert_eq!(
            ProviderFormat::from_str("cohere"),
            Some(ProviderFormat::Cohere)
        );
        assert_eq!(
            ProviderFormat::from_str("huggingface"),
            Some(ProviderFormat::HuggingFace)
        );
        assert_eq!(
            ProviderFormat::from_str("replicate"),
            Some(ProviderFormat::Replicate)
        );
        assert_eq!(
            ProviderFormat::from_str("watsonx"),
            Some(ProviderFormat::WatsonX)
        );
        assert_eq!(
            ProviderFormat::from_str("google-gemini"),
            Some(ProviderFormat::GoogleGemini)
        );
        assert_eq!(
            ProviderFormat::from_str("aws-bedrock"),
            Some(ProviderFormat::AWSBedrock)
        );
        assert_eq!(
            ProviderFormat::from_str("bedrock"),
            Some(ProviderFormat::AWSBedrock)
        );
        assert_eq!(ProviderFormat::from_str("unknown"), None);
    }

    #[test]
    fn provider_format_as_str_round_trip() {
        let formats = [
            ProviderFormat::OpenAI,
            ProviderFormat::Anthropic,
            ProviderFormat::Cohere,
            ProviderFormat::HuggingFace,
            ProviderFormat::Replicate,
            ProviderFormat::WatsonX,
            ProviderFormat::GoogleGemini,
            ProviderFormat::AWSBedrock,
        ];
        for fmt in formats {
            let s = fmt.as_str();
            assert!(ProviderFormat::from_str(s).is_some());
        }
    }

    // ── infer_request_format ────────────────────────────────────────────

    #[test]
    fn infer_request_format_openai_default() {
        let body = json!({"model": "gpt-5.4", "messages": []});
        assert_eq!(infer_request_format(&body), ProviderFormat::OpenAI);
    }

    #[test]
    fn infer_request_format_anthropic() {
        let body = json!({"anthropic_version": "2023-06-01", "messages": []});
        assert_eq!(infer_request_format(&body), ProviderFormat::Anthropic);
    }

    #[test]
    fn infer_request_format_watsonx() {
        let body = json!({"model_id": "ibm/granite", "input": "hello"});
        assert_eq!(infer_request_format(&body), ProviderFormat::WatsonX);
    }

    #[test]
    fn infer_request_format_google_gemini_contents() {
        let body = json!({"contents": [{"parts": [{"text": "hi"}]}]});
        assert_eq!(infer_request_format(&body), ProviderFormat::GoogleGemini);
    }

    #[test]
    fn infer_request_format_google_gemini_system_instruction() {
        let body = json!({"systemInstruction": {"parts": [{"text": "system"}]}});
        assert_eq!(infer_request_format(&body), ProviderFormat::GoogleGemini);
    }

    #[test]
    fn infer_request_format_cohere() {
        let body = json!({"message": "hello", "chat_history": []});
        assert_eq!(infer_request_format(&body), ProviderFormat::Cohere);
    }

    #[test]
    fn infer_request_format_huggingface() {
        let body = json!({"inputs": "hello world"});
        assert_eq!(infer_request_format(&body), ProviderFormat::HuggingFace);
    }

    #[test]
    fn infer_request_format_replicate() {
        let body = json!({"input": {"prompt": "hello"}});
        assert_eq!(infer_request_format(&body), ProviderFormat::Replicate);
    }

    #[test]
    fn infer_request_format_openai_responses_api() {
        let body = json!({"input": "hello", "model": "gpt-5.4"});
        assert_eq!(infer_request_format(&body), ProviderFormat::OpenAI);
    }

    #[test]
    fn infer_request_format_openai_with_instructions() {
        let body = json!({"input": "hello", "instructions": "be helpful"});
        assert_eq!(infer_request_format(&body), ProviderFormat::OpenAI);
    }

    #[test]
    fn infer_request_format_openai_with_max_output_tokens() {
        let body = json!({"input": "hello", "max_output_tokens": 1000});
        assert_eq!(infer_request_format(&body), ProviderFormat::OpenAI);
    }

    #[test]
    fn infer_request_format_empty_body() {
        let body = json!({});
        assert_eq!(infer_request_format(&body), ProviderFormat::OpenAI);
    }
}
