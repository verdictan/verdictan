// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use indexmap::IndexMap;
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalToolCall {
    pub name: String,
    pub arguments: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolCallParseError {
    MissingName,
    InvalidName(String),
    IncompleteArguments,
}

impl std::fmt::Display for ToolCallParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingName => formatter.write_str("structured tool call is missing a name"),
            Self::InvalidName(name) => {
                write!(formatter, "structured tool call has invalid name: {name}")
            }
            Self::IncompleteArguments => {
                formatter.write_str("structured tool call has incomplete JSON arguments")
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
struct PartialToolCall {
    name: String,
    arguments: String,
    requires_json_arguments: bool,
}

#[derive(Clone, Debug, Default)]
pub struct StreamingToolCallAccumulator {
    // Insertion order matches stream appearance order across chat/responses/Anthropic
    // fragments; BTreeMap key sort would reorder mixed-provider assemblies.
    calls: IndexMap<String, PartialToolCall>,
}

impl StreamingToolCallAccumulator {
    pub fn ingest_sse_payload(&mut self, payload: &str) -> Result<(), ToolCallParseError> {
        if payload == "[DONE]" {
            return Ok(());
        }
        let Ok(value) = serde_json::from_str::<Value>(payload) else {
            return Ok(());
        };

        self.ingest_chat_delta(&value);
        self.ingest_responses_event(&value);
        self.ingest_anthropic_event(&value);
        Ok(())
    }

    pub fn finish(self) -> Result<Vec<CanonicalToolCall>, ToolCallParseError> {
        self.calls
            .into_values()
            .map(finalize_partial_call)
            .collect()
    }

    fn ingest_chat_delta(&mut self, value: &Value) {
        let Some(choices) = value.get("choices").and_then(Value::as_array) else {
            return;
        };
        for (choice_position, choice) in choices.iter().enumerate() {
            let choice_index = choice
                .get("index")
                .and_then(Value::as_u64)
                .map(|index| index.to_string())
                .unwrap_or_else(|| choice_position.to_string());
            let Some(delta) = choice.get("delta") else {
                continue;
            };
            if let Some(tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
                for (tool_position, tool_call) in tool_calls.iter().enumerate() {
                    let tool_index = tool_call
                        .get("index")
                        .and_then(Value::as_u64)
                        .map(|index| index.to_string())
                        .unwrap_or_else(|| tool_position.to_string());
                    let key = format!("chat:{choice_index}:{tool_index}");
                    let partial = self.calls.entry(key).or_default();
                    append_string(
                        &mut partial.name,
                        tool_call.pointer("/function/name").and_then(Value::as_str),
                    );
                    append_string(
                        &mut partial.arguments,
                        tool_call
                            .pointer("/function/arguments")
                            .and_then(Value::as_str),
                    );
                    partial.requires_json_arguments = true;
                }
            }
            if let Some(function_call) = delta.get("function_call") {
                let key = format!("chat:{choice_index}:legacy");
                let partial = self.calls.entry(key).or_default();
                append_string(
                    &mut partial.name,
                    function_call.get("name").and_then(Value::as_str),
                );
                append_string(
                    &mut partial.arguments,
                    function_call.get("arguments").and_then(Value::as_str),
                );
                partial.requires_json_arguments = true;
            }
        }
    }

    fn ingest_responses_event(&mut self, value: &Value) {
        let event_type = value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match event_type {
            "response.output_item.added" | "response.output_item.done" => {
                let Some(item) = value.get("item") else {
                    return;
                };
                if !is_responses_tool_call(item) {
                    return;
                }
                let key = responses_call_key(value, item);
                let partial = self.calls.entry(key).or_default();
                set_string(&mut partial.name, item.get("name").and_then(Value::as_str));
                if event_type.ends_with(".done") {
                    set_arguments(partial, item);
                } else {
                    append_arguments(partial, item);
                }
                partial.requires_json_arguments =
                    item.get("type").and_then(Value::as_str) != Some("custom_tool_call");
            }
            "response.function_call_arguments.delta" => {
                let key = responses_call_key(value, value);
                let partial = self.calls.entry(key).or_default();
                append_string(
                    &mut partial.arguments,
                    value.get("delta").and_then(Value::as_str),
                );
                partial.requires_json_arguments = true;
            }
            "response.function_call_arguments.done" => {
                let key = responses_call_key(value, value);
                let partial = self.calls.entry(key).or_default();
                set_string(
                    &mut partial.arguments,
                    value.get("arguments").and_then(Value::as_str),
                );
                partial.requires_json_arguments = true;
            }
            "response.completed" => {
                if let Some(response) = value.get("response") {
                    for call in canonical_tool_calls(response).unwrap_or_default() {
                        let key = format!("responses:completed:{}", self.calls.len());
                        self.calls.insert(
                            key,
                            PartialToolCall {
                                name: call.name,
                                arguments: call.arguments,
                                requires_json_arguments: true,
                            },
                        );
                    }
                }
            }
            _ => {}
        }
    }

    fn ingest_anthropic_event(&mut self, value: &Value) {
        let event_type = value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let index = value
            .get("index")
            .and_then(Value::as_u64)
            .map(|index| index.to_string())
            .unwrap_or_else(|| "0".to_string());
        let key = format!("anthropic:{index}");
        match event_type {
            "content_block_start"
                if value.pointer("/content_block/type").and_then(Value::as_str)
                    == Some("tool_use") =>
            {
                let partial = self.calls.entry(key).or_default();
                set_string(
                    &mut partial.name,
                    value.pointer("/content_block/name").and_then(Value::as_str),
                );
                if let Some(input) = value.pointer("/content_block/input") {
                    if !input.as_object().is_some_and(serde_json::Map::is_empty) {
                        partial.arguments = canonical_arguments(input);
                    }
                }
                partial.requires_json_arguments = true;
            }
            "content_block_delta"
                if value.pointer("/delta/type").and_then(Value::as_str)
                    == Some("input_json_delta") =>
            {
                let partial = self.calls.entry(key).or_default();
                append_string(
                    &mut partial.arguments,
                    value.pointer("/delta/partial_json").and_then(Value::as_str),
                );
                partial.requires_json_arguments = true;
            }
            _ => {}
        }
    }
}

pub fn canonical_tool_calls(value: &Value) -> Result<Vec<CanonicalToolCall>, ToolCallParseError> {
    let mut calls = Vec::new();

    if let Some(choices) = value.get("choices").and_then(Value::as_array) {
        for choice in choices {
            if let Some(message) = choice.get("message") {
                collect_message_tool_calls(message, &mut calls)?;
            }
        }
    }
    if let Some(messages) = value.get("messages").and_then(Value::as_array) {
        for message in messages {
            if message.get("role").and_then(Value::as_str) == Some("assistant") {
                collect_message_tool_calls(message, &mut calls)?;
            }
        }
    }
    if let Some(output) = value.get("output").and_then(Value::as_array) {
        collect_responses_items(output, &mut calls)?;
    }
    if let Some(input) = value.get("input").and_then(Value::as_array) {
        collect_responses_items(input, &mut calls)?;
    }
    if let Some(content) = value.get("content").and_then(Value::as_array) {
        collect_anthropic_content(content, &mut calls)?;
    }

    Ok(calls)
}

fn collect_message_tool_calls(
    message: &Value,
    calls: &mut Vec<CanonicalToolCall>,
) -> Result<(), ToolCallParseError> {
    if let Some(tool_calls) = message.get("tool_calls").and_then(Value::as_array) {
        for tool_call in tool_calls {
            let function = tool_call.get("function").unwrap_or(tool_call);
            calls.push(finalize_partial_call(PartialToolCall {
                name: function
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                arguments: function
                    .get("arguments")
                    .map(canonical_arguments)
                    .unwrap_or_default(),
                requires_json_arguments: true,
            })?);
        }
    }
    if let Some(function_call) = message.get("function_call") {
        calls.push(finalize_partial_call(PartialToolCall {
            name: function_call
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            arguments: function_call
                .get("arguments")
                .map(canonical_arguments)
                .unwrap_or_default(),
            requires_json_arguments: true,
        })?);
    }
    if let Some(content) = message.get("content").and_then(Value::as_array) {
        collect_anthropic_content(content, calls)?;
    }
    Ok(())
}

fn collect_responses_items(
    items: &[Value],
    calls: &mut Vec<CanonicalToolCall>,
) -> Result<(), ToolCallParseError> {
    for item in items {
        if is_responses_tool_call(item) {
            let item_type = item.get("type").and_then(Value::as_str);
            calls.push(finalize_partial_call(PartialToolCall {
                name: item
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                arguments: item
                    .get("arguments")
                    .or_else(|| item.get("input"))
                    .map(canonical_arguments)
                    .unwrap_or_default(),
                requires_json_arguments: item_type != Some("custom_tool_call"),
            })?);
        }
        if let Some(content) = item.get("content").and_then(Value::as_array) {
            collect_anthropic_content(content, calls)?;
        }
    }
    Ok(())
}

fn collect_anthropic_content(
    content: &[Value],
    calls: &mut Vec<CanonicalToolCall>,
) -> Result<(), ToolCallParseError> {
    for block in content {
        if block.get("type").and_then(Value::as_str) != Some("tool_use") {
            continue;
        }
        calls.push(finalize_partial_call(PartialToolCall {
            name: block
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            arguments: block
                .get("input")
                .map(canonical_arguments)
                .unwrap_or_default(),
            requires_json_arguments: true,
        })?);
    }
    Ok(())
}

fn is_responses_tool_call(item: &Value) -> bool {
    matches!(
        item.get("type").and_then(Value::as_str),
        Some("function_call" | "custom_tool_call" | "tool_call")
    )
}

fn finalize_partial_call(
    partial: PartialToolCall,
) -> Result<CanonicalToolCall, ToolCallParseError> {
    let name = partial.name.trim().to_ascii_lowercase();
    if name.is_empty() {
        return Err(ToolCallParseError::MissingName);
    }
    if !name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.'))
    {
        return Err(ToolCallParseError::InvalidName(name));
    }
    let arguments = partial.arguments.trim().to_string();
    if partial.requires_json_arguments
        && !arguments.is_empty()
        && serde_json::from_str::<Value>(&arguments).is_err()
    {
        return Err(ToolCallParseError::IncompleteArguments);
    }
    Ok(CanonicalToolCall { name, arguments })
}

fn canonical_arguments(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        value => serde_json::to_string(value).unwrap_or_default(),
    }
}

fn append_arguments(partial: &mut PartialToolCall, item: &Value) {
    if let Some(arguments) = item.get("arguments").or_else(|| item.get("input")) {
        partial.arguments.push_str(&canonical_arguments(arguments));
    }
}

fn set_arguments(partial: &mut PartialToolCall, item: &Value) {
    if let Some(arguments) = item.get("arguments").or_else(|| item.get("input")) {
        partial.arguments = canonical_arguments(arguments);
    }
}

fn append_string(target: &mut String, value: Option<&str>) {
    if let Some(value) = value {
        target.push_str(value);
    }
}

fn set_string(target: &mut String, value: Option<&str>) {
    if let Some(value) = value {
        *target = value.to_string();
    }
}

fn responses_call_key(event: &Value, item: &Value) -> String {
    event
        .get("output_index")
        .and_then(Value::as_u64)
        .map(|index| format!("responses:index:{index}"))
        .or_else(|| {
            event
                .get("item_id")
                .or_else(|| item.get("id"))
                .or_else(|| item.get("call_id"))
                .and_then(Value::as_str)
                .map(|id| format!("responses:id:{id}"))
        })
        .unwrap_or_else(|| "responses:index:0".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonicalizes_chat_responses_and_anthropic_calls() {
        let chat = canonical_tool_calls(&json!({
            "choices": [{"message": {"tool_calls": [{
                "function": {"name": "Delete.Record", "arguments": "{\"id\":7}"}
            }]}}]
        }))
        .expect("chat calls");
        assert_eq!(
            chat,
            [CanonicalToolCall {
                name: "delete.record".to_string(),
                arguments: "{\"id\":7}".to_string(),
            }]
        );

        let responses = canonical_tool_calls(&json!({
            "output": [{"type": "function_call", "name": "send_email", "arguments": "{\"to\":\"a@example.com\"}"}]
        }))
        .expect("responses calls");
        assert_eq!(responses[0].name, "send_email");

        let anthropic = canonical_tool_calls(&json!({
            "content": [{"type": "tool_use", "name": "wire_money", "input": {"amount": 5000}}]
        }))
        .expect("anthropic calls");
        assert_eq!(anthropic[0].arguments, "{\"amount\":5000}");
    }

    #[test]
    fn assembles_every_supported_stream_fragment() {
        let mut calls = StreamingToolCallAccumulator::default();
        for payload in [
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"delete_","arguments":"{\"id\":"}}]}}]}"#,
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"record","arguments":"7}"}}]}}]}"#,
            r#"{"type":"response.output_item.added","output_index":1,"item":{"type":"function_call","name":"send_email","arguments":""}}"#,
            r#"{"type":"response.function_call_arguments.delta","output_index":1,"delta":"{\"to\":\"a@"}"#,
            r#"{"type":"response.function_call_arguments.done","output_index":1,"arguments":"{\"to\":\"a@example.com\"}"}"#,
            r#"{"type":"content_block_start","index":2,"content_block":{"type":"tool_use","name":"wire_money","input":{}}}"#,
            r#"{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"amount\":5000}"}}"#,
        ] {
            calls.ingest_sse_payload(payload).expect("ingest");
        }
        let calls = calls.finish().expect("complete calls");
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].name, "delete_record");
        assert_eq!(calls[1].name, "send_email");
        assert_eq!(calls[2].name, "wire_money");
    }

    #[test]
    fn malformed_structured_calls_fail_closed() {
        let error = canonical_tool_calls(&json!({
            "output": [{"type": "function_call", "arguments": "{\"id\":1}"}]
        }))
        .expect_err("missing name");
        assert_eq!(error, ToolCallParseError::MissingName);

        let mut calls = StreamingToolCallAccumulator::default();
        calls
            .ingest_sse_payload(
                r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"delete","arguments":"{"}}]}}]}"#,
            )
            .expect("ingest");
        assert_eq!(
            calls.finish().expect_err("partial arguments"),
            ToolCallParseError::IncompleteArguments
        );
    }
}
