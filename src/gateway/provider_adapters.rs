// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Provider adapter trait and implementations for upstream provider calls.
//!
//! Each adapter translates between the Verdictan gateway's normalized
//! request format and a specific provider's native API format.

use serde::{Deserialize, Serialize};

use super::format_translation::{infer_request_format, translate_request, ProviderFormat};
use super::provider_execution::{ProviderCredential, RequestOptions, TokenUsage};

// ─── Trait ───────────────────────────────────────────────────────────────────

/// A provider adapter translates requests/responses between the gateway's
/// normalized format and a specific upstream provider's API.
pub trait ProviderAdapter: Send + Sync {
    /// Provider identifier (e.g., "openai", "anthropic").
    fn provider_id(&self) -> &str;

    /// Supported API formats for this provider.
    fn supported_formats(&self) -> &[ApiFormat];

    /// Build the upstream HTTP request from a normalized gateway request body.
    fn build_upstream_request(
        &self,
        body: &serde_json::Value,
        credential: &ProviderCredential,
        options: &RequestOptions,
        format: ApiFormat,
    ) -> Result<UpstreamRequest, AdapterError>;

    /// Extract token usage from the provider's response.
    fn extract_usage(&self, response_body: &serde_json::Value) -> Option<TokenUsage>;

    /// Apply ZDR overrides to the request body (set store=false, etc.).
    fn apply_zdr_overrides(&self, body: &mut serde_json::Value);
}

// ─── Types ───────────────────────────────────────────────────────────────────

/// The API format being used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiFormat {
    /// OpenAI Chat Completions API (`/v1/chat/completions`)
    OpenAiChatCompletions,
    /// OpenAI Responses API (`/v1/responses`)
    OpenAiResponses,
    /// OpenAI Embeddings API (`/v1/embeddings`)
    OpenAiEmbeddings,
    /// OpenAI Audio Transcriptions API (`/v1/audio/transcriptions`)
    OpenAiAudioTranscriptions,
    /// OpenAI Audio Speech API (`/v1/audio/speech`)
    OpenAiAudioSpeech,
    /// Anthropic Messages API (`/v1/messages`)
    AnthropicMessages,
}

impl ApiFormat {
    fn route_native_format(self) -> ProviderFormat {
        match self {
            Self::AnthropicMessages => ProviderFormat::Anthropic,
            Self::OpenAiChatCompletions
            | Self::OpenAiResponses
            | Self::OpenAiEmbeddings
            | Self::OpenAiAudioTranscriptions
            | Self::OpenAiAudioSpeech => ProviderFormat::OpenAI,
        }
    }
}

/// A fully constructed upstream request ready to send.
#[derive(Debug, Clone)]
pub struct UpstreamRequest {
    /// Target URL.
    pub url: String,
    /// HTTP method (always POST for LLM APIs).
    pub method: String,
    /// Headers to include.
    pub headers: Vec<(String, String)>,
    /// Request body.
    pub body: serde_json::Value,
}

/// Errors that can occur during adapter operations.
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("Unsupported model: {0}")]
    UnsupportedModel(String),
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    #[error("Provider error: {0}")]
    ProviderError(String),
}

/// Normalize provider `usage` objects from Chat, Responses, and Messages into a
/// single [`TokenUsage`] shape for reservation settlement.
///
/// Accepts the common field aliases used by each family:
/// - Chat Completions: `prompt_tokens` / `completion_tokens` /
///   `prompt_tokens_details.cached_tokens`
/// - Responses: `input_tokens` / `output_tokens` /
///   `input_tokens_details.cached_tokens`
/// - Anthropic Messages: `input_tokens` / `output_tokens` /
///   `cache_read_input_tokens`
///
/// When `total_tokens` is absent, it is derived as `input + output`.
pub fn normalize_provider_usage(response_body: &serde_json::Value) -> Option<TokenUsage> {
    let usage = response_body.get("usage")?;
    let input_tokens = usage
        .get("prompt_tokens")
        .or_else(|| usage.get("input_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let output_tokens = usage
        .get("completion_tokens")
        .or_else(|| usage.get("output_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let total_tokens = usage
        .get("total_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| input_tokens.saturating_add(output_tokens));
    let cached_input_tokens = usage
        .get("prompt_tokens_details")
        .and_then(|d| d.get("cached_tokens"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            usage
                .get("input_tokens_details")
                .and_then(|d| d.get("cached_tokens"))
                .and_then(|v| v.as_u64())
        })
        .or_else(|| {
            usage
                .get("cache_read_input_tokens")
                .and_then(|v| v.as_u64())
        })
        .or_else(|| usage.get("cached_input_tokens").and_then(|v| v.as_u64()));

    Some(TokenUsage {
        input_tokens,
        output_tokens,
        total_tokens,
        cached_input_tokens,
    })
}

// ─── OpenAI Adapter ──────────────────────────────────────────────────────────

/// Adapter for OpenAI Chat Completions and Responses APIs.
pub struct OpenAiAdapter {
    /// Base URL for OpenAI API.
    pub base_url: String,
}

impl Default for OpenAiAdapter {
    fn default() -> Self {
        Self {
            base_url: "https://api.openai.com".to_string(),
        }
    }
}

impl ProviderAdapter for OpenAiAdapter {
    fn provider_id(&self) -> &str {
        "openai"
    }

    fn supported_formats(&self) -> &[ApiFormat] {
        &[
            ApiFormat::OpenAiChatCompletions,
            ApiFormat::OpenAiResponses,
            ApiFormat::OpenAiEmbeddings,
            ApiFormat::OpenAiAudioTranscriptions,
            ApiFormat::OpenAiAudioSpeech,
        ]
    }

    fn build_upstream_request(
        &self,
        body: &serde_json::Value,
        credential: &ProviderCredential,
        options: &RequestOptions,
        format: ApiFormat,
    ) -> Result<UpstreamRequest, AdapterError> {
        let public_path = match format {
            ApiFormat::OpenAiChatCompletions => "/v1/chat/completions",
            ApiFormat::OpenAiResponses => "/v1/responses",
            ApiFormat::OpenAiEmbeddings => "/v1/embeddings",
            ApiFormat::OpenAiAudioTranscriptions => "/v1/audio/transcriptions",
            ApiFormat::OpenAiAudioSpeech => "/v1/audio/speech",
            _ => {
                return Err(AdapterError::InvalidRequest(
                    "OpenAI adapter does not support this format".to_string(),
                ))
            }
        };
        let path = super::provider_catalog::provider_path_template_for_public_path(
            self.provider_id(),
            public_path,
        )
        .unwrap_or(public_path);

        let source_format = infer_request_format(body);
        let mut request_body =
            translate_request(body.clone(), source_format, ProviderFormat::OpenAI)
                .map_err(|error| AdapterError::InvalidRequest(error.to_string()))?;

        // Apply ZDR override if configured
        if options.zdr_override {
            self.apply_zdr_overrides(&mut request_body);
        }

        let headers = vec![
            (
                "Authorization".to_string(),
                format!("Bearer {}", credential.api_key),
            ),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        Ok(UpstreamRequest {
            url: format!("{}{}", self.base_url, path),
            method: "POST".to_string(),
            headers,
            body: request_body,
        })
    }

    fn extract_usage(&self, response_body: &serde_json::Value) -> Option<TokenUsage> {
        normalize_provider_usage(response_body)
    }

    fn apply_zdr_overrides(&self, body: &mut serde_json::Value) {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("store".to_string(), serde_json::Value::Bool(false));
        }
    }
}

// ─── Anthropic Adapter ───────────────────────────────────────────────────────

/// Adapter for Anthropic Messages API.
pub struct AnthropicAdapter {
    /// Base URL for Anthropic API.
    pub base_url: String,
    /// API version header value.
    pub api_version: String,
}

impl Default for AnthropicAdapter {
    fn default() -> Self {
        Self {
            base_url: "https://api.anthropic.com".to_string(),
            api_version: "2023-06-01".to_string(),
        }
    }
}

impl ProviderAdapter for AnthropicAdapter {
    fn provider_id(&self) -> &str {
        "anthropic"
    }

    fn supported_formats(&self) -> &[ApiFormat] {
        &[ApiFormat::AnthropicMessages]
    }

    fn build_upstream_request(
        &self,
        body: &serde_json::Value,
        credential: &ProviderCredential,
        _options: &RequestOptions,
        format: ApiFormat,
    ) -> Result<UpstreamRequest, AdapterError> {
        if format != ApiFormat::AnthropicMessages {
            return Err(AdapterError::InvalidRequest(
                "Anthropic adapter only supports Messages format".to_string(),
            ));
        }

        let source_format = if format == ApiFormat::AnthropicMessages
            && (body.get("anthropic_version").is_some()
                || body.get("system").is_some()
                || body
                    .get("tools")
                    .and_then(|value| value.as_array())
                    .is_some_and(|tools| {
                        tools.iter().any(|tool| {
                            tool.get("name").is_some() || tool.get("input_schema").is_some()
                        })
                    })
                || body
                    .get("messages")
                    .and_then(|value| value.as_array())
                    .is_some_and(|messages| {
                        messages.iter().any(|message| {
                            message
                                .get("content")
                                .and_then(|value| value.as_array())
                                .is_some_and(|parts| {
                                    parts.iter().any(|part| {
                                        matches!(
                                            part.get("type").and_then(|value| value.as_str()),
                                            Some(
                                                "image"
                                                    | "document"
                                                    | "tool_use"
                                                    | "tool_result"
                                                    | "thinking"
                                            )
                                        )
                                    })
                                })
                        })
                    })) {
            format.route_native_format()
        } else {
            infer_request_format(body)
        };
        let mut request_body =
            translate_request(body.clone(), source_format, ProviderFormat::Anthropic)
                .map_err(|error| AdapterError::InvalidRequest(error.to_string()))?;

        // Preserve governance-relevant fields so Messages input/tool/streaming
        // stages see the same contract as Chat/Responses after translation.
        if let Some(object) = request_body.as_object_mut() {
            if let Some(stream) = body.get("stream") {
                object.insert("stream".to_string(), stream.clone());
            }
            if let Some(tools) = body.get("tools") {
                object.entry("tools".to_string()).or_insert(tools.clone());
            }
            if let Some(tool_choice) = body.get("tool_choice") {
                object
                    .entry("tool_choice".to_string())
                    .or_insert(tool_choice.clone());
            }
            if let Some(system) = body.get("system") {
                object.entry("system".to_string()).or_insert(system.clone());
            }
        }

        let mut headers = vec![
            ("x-api-key".to_string(), credential.api_key.clone()),
            ("anthropic-version".to_string(), self.api_version.clone()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        // Add beta header if extended thinking is requested
        if body.get("thinking").is_some() {
            headers.push((
                "anthropic-beta".to_string(),
                "interleaved-thinking-2025-05-14".to_string(),
            ));
        }

        Ok(UpstreamRequest {
            url: format!("{}/v1/messages", self.base_url),
            method: "POST".to_string(),
            headers,
            body: request_body,
        })
    }

    fn extract_usage(&self, response_body: &serde_json::Value) -> Option<TokenUsage> {
        normalize_provider_usage(response_body)
    }

    fn apply_zdr_overrides(&self, _body: &mut serde_json::Value) {
        // Anthropic doesn't have a `store` parameter — ZDR is handled
        // via provider-level contractual agreement. No body modification needed.
    }
}

// ─── Registry ────────────────────────────────────────────────────────────────

/// Registry of available provider adapters.
pub struct AdapterRegistry {
    adapters: Vec<Box<dyn ProviderAdapter>>,
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AdapterRegistry {
    pub fn new() -> Self {
        Self {
            adapters: vec![
                Box::new(OpenAiAdapter::default()),
                Box::new(AnthropicAdapter::default()),
            ],
        }
    }

    /// Find adapter for a given provider.
    pub fn get(&self, provider_id: &str) -> Option<&dyn ProviderAdapter> {
        self.adapters
            .iter()
            .find(|a| a.provider_id() == provider_id)
            .map(|a| a.as_ref())
    }

    /// Resolve which format to use based on the request path/hints.
    fn resolve_format(path: &str, provider: &str) -> ApiFormat {
        match (path, provider) {
            (p, _) if p.contains("/responses") => ApiFormat::OpenAiResponses,
            (p, _) if p.contains("/embeddings") => ApiFormat::OpenAiEmbeddings,
            (p, _) if p.contains("/audio/transcriptions") => ApiFormat::OpenAiAudioTranscriptions,
            (p, _) if p.contains("/audio/speech") => ApiFormat::OpenAiAudioSpeech,
            (p, _) if p.contains("/messages") => ApiFormat::AnthropicMessages,
            (_, "anthropic") => ApiFormat::AnthropicMessages,
            _ => ApiFormat::OpenAiChatCompletions,
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

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
    use serde_json::json;

    #[test]
    fn openai_adapter_builds_chat_completions_request() {
        let adapter = OpenAiAdapter::default();
        let body = json!({
            "model": "gpt-5.5",
            "messages": [{"role": "user", "content": "Hello"}]
        });
        let cred = ProviderCredential {
            credential_id: "cred-1".to_string(),
            provider: "openai".to_string(),
            api_key: "sk-test-key".to_string(),
            region: Some("us".to_string()),
            zdr_eligible: false,
        };
        let opts = RequestOptions::default();
        let req = adapter
            .build_upstream_request(&body, &cred, &opts, ApiFormat::OpenAiChatCompletions)
            .expect("should build request");

        assert_eq!(req.url, "https://api.openai.com/v1/chat/completions");
        assert!(req
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer sk-test-key"));
    }

    #[test]
    fn openai_adapter_extracts_usage() {
        let adapter = OpenAiAdapter::default();
        let response = json!({
            "usage": {
                "prompt_tokens": 25,
                "completion_tokens": 100,
                "total_tokens": 125
            }
        });
        let usage = adapter.extract_usage(&response).expect("should extract");
        assert_eq!(usage.input_tokens, 25);
        assert_eq!(usage.output_tokens, 100);
        assert_eq!(usage.total_tokens, 125);
    }

    #[test]
    fn openai_adapter_extracts_chat_cached_tokens_and_derives_total() {
        let adapter = OpenAiAdapter::default();
        let response = json!({
            "usage": {
                "prompt_tokens": 40,
                "completion_tokens": 10,
                "prompt_tokens_details": {
                    "cached_tokens": 12
                }
            }
        });
        let usage = adapter.extract_usage(&response).expect("should extract");
        assert_eq!(usage.input_tokens, 40);
        assert_eq!(usage.output_tokens, 10);
        assert_eq!(usage.total_tokens, 50);
        assert_eq!(usage.cached_input_tokens, Some(12));
    }

    #[test]
    fn openai_adapter_extracts_responses_usage_with_cached_tokens() {
        let adapter = OpenAiAdapter::default();
        let response = json!({
            "usage": {
                "input_tokens": 20,
                "output_tokens": 8,
                "total_tokens": 28,
                "input_tokens_details": {
                    "cached_tokens": 6
                }
            }
        });
        let usage = adapter.extract_usage(&response).expect("should extract");
        assert_eq!(usage.input_tokens, 20);
        assert_eq!(usage.output_tokens, 8);
        assert_eq!(usage.total_tokens, 28);
        assert_eq!(usage.cached_input_tokens, Some(6));
    }

    #[test]
    fn normalize_provider_usage_is_identical_across_chat_responses_messages() {
        let chat = normalize_provider_usage(&json!({
            "usage": {
                "prompt_tokens": 30,
                "completion_tokens": 5,
                "prompt_tokens_details": {"cached_tokens": 4}
            }
        }))
        .expect("chat");
        let responses = normalize_provider_usage(&json!({
            "usage": {
                "input_tokens": 30,
                "output_tokens": 5,
                "input_tokens_details": {"cached_tokens": 4}
            }
        }))
        .expect("responses");
        let messages = normalize_provider_usage(&json!({
            "usage": {
                "input_tokens": 30,
                "output_tokens": 5,
                "cache_read_input_tokens": 4
            }
        }))
        .expect("messages");

        assert_eq!(chat.input_tokens, responses.input_tokens);
        assert_eq!(chat.output_tokens, responses.output_tokens);
        assert_eq!(chat.total_tokens, responses.total_tokens);
        assert_eq!(chat.cached_input_tokens, responses.cached_input_tokens);
        assert_eq!(chat.input_tokens, messages.input_tokens);
        assert_eq!(chat.output_tokens, messages.output_tokens);
        assert_eq!(chat.total_tokens, messages.total_tokens);
        assert_eq!(chat.cached_input_tokens, messages.cached_input_tokens);
    }

    #[test]
    fn openai_adapter_builds_audio_transcription_request() {
        let adapter = OpenAiAdapter::default();
        let body = json!({
            "model": "gpt-4o-mini-transcribe",
            "input_audio": {"data": "Zm9v", "format": "mp3"}
        });
        let cred = ProviderCredential {
            credential_id: "cred-1".to_string(),
            provider: "openai".to_string(),
            api_key: "sk-test-key".to_string(),
            region: Some("us".to_string()),
            zdr_eligible: false,
        };
        let opts = RequestOptions::default();
        let req = adapter
            .build_upstream_request(&body, &cred, &opts, ApiFormat::OpenAiAudioTranscriptions)
            .expect("should build request");

        assert_eq!(req.url, "https://api.openai.com/v1/audio/transcriptions");
    }

    #[test]
    fn openai_adapter_builds_audio_speech_request() {
        let adapter = OpenAiAdapter::default();
        let body = json!({
            "model": "gpt-4o-mini-tts",
            "input": "hello",
            "voice": "alloy"
        });
        let cred = ProviderCredential {
            credential_id: "cred-1".to_string(),
            provider: "openai".to_string(),
            api_key: "sk-test-key".to_string(),
            region: Some("us".to_string()),
            zdr_eligible: false,
        };
        let opts = RequestOptions::default();
        let req = adapter
            .build_upstream_request(&body, &cred, &opts, ApiFormat::OpenAiAudioSpeech)
            .expect("should build request");

        assert_eq!(req.url, "https://api.openai.com/v1/audio/speech");
    }

    #[test]
    fn openai_adapter_applies_zdr_override_while_building_request() {
        let adapter = OpenAiAdapter::default();
        let body = json!({
            "model": "gpt-5.5",
            "messages": [{"role": "user", "content": "Hello"}],
            "store": true
        });
        let cred = ProviderCredential {
            credential_id: "cred-1".to_string(),
            provider: "openai".to_string(),
            api_key: "sk-test-key".to_string(),
            region: Some("us".to_string()),
            zdr_eligible: true,
        };
        let opts = RequestOptions {
            zdr_override: true,
            ..RequestOptions::default()
        };
        let req = adapter
            .build_upstream_request(&body, &cred, &opts, ApiFormat::OpenAiChatCompletions)
            .expect("should build request");

        assert_eq!(req.body["store"], json!(false));
    }

    #[test]
    fn openai_adapter_applies_zdr_override() {
        let adapter = OpenAiAdapter::default();
        let mut body = json!({"model": "gpt-5.5", "store": true});
        adapter.apply_zdr_overrides(&mut body);
        assert_eq!(body["store"], json!(false));
    }

    #[test]
    fn openai_adapter_rejects_unsupported_format() {
        let adapter = OpenAiAdapter::default();
        let body = json!({
            "model": "gpt-5.5",
            "messages": [{"role": "user", "content": "Hello"}]
        });
        let cred = ProviderCredential {
            credential_id: "cred-1".to_string(),
            provider: "openai".to_string(),
            api_key: "sk-test-key".to_string(),
            region: Some("us".to_string()),
            zdr_eligible: false,
        };
        let opts = RequestOptions::default();
        let error = adapter
            .build_upstream_request(&body, &cred, &opts, ApiFormat::AnthropicMessages)
            .expect_err("unsupported format should fail");

        assert!(matches!(
            error,
            AdapterError::InvalidRequest(message)
                if message == "OpenAI adapter does not support this format"
        ));
    }

    #[test]
    fn anthropic_adapter_builds_messages_request() {
        let adapter = AnthropicAdapter::default();
        let body = json!({
            "model": "claude-opus-4-8",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": "Hello"}]
        });
        let cred = ProviderCredential {
            credential_id: "cred-2".to_string(),
            provider: "anthropic".to_string(),
            api_key: "sk-ant-test".to_string(),
            region: None,
            zdr_eligible: true,
        };
        let opts = RequestOptions::default();
        let req = adapter
            .build_upstream_request(&body, &cred, &opts, ApiFormat::AnthropicMessages)
            .expect("should build request");

        assert_eq!(req.url, "https://api.anthropic.com/v1/messages");
        assert!(req
            .headers
            .iter()
            .any(|(k, v)| k == "x-api-key" && v == "sk-ant-test"));
        assert!(req
            .headers
            .iter()
            .any(|(k, v)| k == "anthropic-version" && v == "2023-06-01"));
    }

    #[test]
    fn anthropic_adapter_adds_beta_header_for_thinking() {
        let adapter = AnthropicAdapter::default();
        let body = json!({
            "model": "claude-opus-4-8",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": "Think about this"}],
            "thinking": {"type": "enabled", "budget_tokens": 10000}
        });
        let cred = ProviderCredential {
            credential_id: "cred-3".to_string(),
            provider: "anthropic".to_string(),
            api_key: "sk-ant-test".to_string(),
            region: None,
            zdr_eligible: false,
        };
        let opts = RequestOptions::default();
        let req = adapter
            .build_upstream_request(&body, &cred, &opts, ApiFormat::AnthropicMessages)
            .expect("should build request");

        assert!(req.headers.iter().any(|(k, _)| k == "anthropic-beta"));
    }

    #[test]
    fn anthropic_adapter_rejects_non_messages_format() {
        let adapter = AnthropicAdapter::default();
        let body = json!({
            "model": "claude-opus-4-8",
            "messages": [{"role": "user", "content": "Hello"}]
        });
        let cred = ProviderCredential {
            credential_id: "cred-2".to_string(),
            provider: "anthropic".to_string(),
            api_key: "sk-ant-test".to_string(),
            region: None,
            zdr_eligible: true,
        };
        let opts = RequestOptions::default();
        let error = adapter
            .build_upstream_request(&body, &cred, &opts, ApiFormat::OpenAiResponses)
            .expect_err("unsupported format should fail");

        assert!(matches!(
            error,
            AdapterError::InvalidRequest(message)
                if message == "Anthropic adapter only supports Messages format"
        ));
    }

    #[test]
    fn anthropic_adapter_extracts_usage_with_cache() {
        let adapter = AnthropicAdapter::default();
        let response = json!({
            "usage": {
                "input_tokens": 30,
                "output_tokens": 150,
                "cache_creation_input_tokens": 5,
                "cache_read_input_tokens": 10
            }
        });
        let usage = adapter.extract_usage(&response).expect("should extract");
        assert_eq!(usage.input_tokens, 30);
        assert_eq!(usage.output_tokens, 150);
        assert_eq!(usage.total_tokens, 180);
        assert_eq!(usage.cached_input_tokens, Some(10));
    }

    #[test]
    fn anthropic_adapter_preserves_stream_tools_for_governance() {
        let adapter = AnthropicAdapter::default();
        let body = json!({
            "model": "claude-opus-4-8",
            "max_tokens": 128,
            "stream": true,
            "system": "Be concise",
            "tools": [{
                "name": "lookup",
                "description": "Lookup a value",
                "input_schema": {"type": "object", "properties": {}}
            }],
            "tool_choice": {"type": "auto"},
            "messages": [{"role": "user", "content": "Hello"}]
        });
        let cred = ProviderCredential {
            credential_id: "cred-gov".to_string(),
            provider: "anthropic".to_string(),
            api_key: "sk-ant-test".to_string(),
            region: None,
            zdr_eligible: false,
        };
        let req = adapter
            .build_upstream_request(
                &body,
                &cred,
                &RequestOptions::default(),
                ApiFormat::AnthropicMessages,
            )
            .expect("build request");
        assert_eq!(req.body.get("stream"), Some(&json!(true)));
        assert!(req
            .body
            .get("tools")
            .and_then(|v| v.as_array())
            .is_some_and(|t| !t.is_empty()));
        assert!(req.body.get("tool_choice").is_some());
        assert_eq!(req.body.get("system"), Some(&json!("Be concise")));
    }

    #[test]
    fn registry_finds_adapters() {
        let registry = AdapterRegistry::new();
        assert!(registry.get("openai").is_some());
        assert!(registry.get("anthropic").is_some());
        assert!(registry.get("unknown").is_none());
    }

    #[test]
    fn resolve_format_works() {
        assert_eq!(
            AdapterRegistry::resolve_format("/v1/chat/completions", "openai"),
            ApiFormat::OpenAiChatCompletions
        );
        assert_eq!(
            AdapterRegistry::resolve_format("/v1/responses", "openai"),
            ApiFormat::OpenAiResponses
        );
        assert_eq!(
            AdapterRegistry::resolve_format("/v1/messages", "anthropic"),
            ApiFormat::AnthropicMessages
        );
        assert_eq!(
            AdapterRegistry::resolve_format("/v1/embeddings", "openai"),
            ApiFormat::OpenAiEmbeddings
        );
        assert_eq!(
            AdapterRegistry::resolve_format("/v1/audio/transcriptions", "openai"),
            ApiFormat::OpenAiAudioTranscriptions
        );
        assert_eq!(
            AdapterRegistry::resolve_format("/v1/audio/speech", "openai"),
            ApiFormat::OpenAiAudioSpeech
        );
        assert_eq!(
            AdapterRegistry::resolve_format("/v1/something", "anthropic"),
            ApiFormat::AnthropicMessages
        );
    }
}
