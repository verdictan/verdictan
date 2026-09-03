// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Provider-independent runtime capability contracts.
//!
//! This module owns the request families, modalities, interaction features,
//! transport modes, and provider capability contract that the gateway uses to
//! decide whether a provider can serve an incoming request. The definitions do
//! not depend on who owns the upstream provider credential.

use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

macro_rules! capability_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value),+
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

capability_enum!(RequestFamily {
    ChatCompletions => "chat_completions",
    Completions => "completions",
    Responses => "responses",
    Messages => "messages",
    Embeddings => "embeddings",
    AudioTranscriptions => "audio_transcriptions",
    AudioSpeech => "audio_speech",
});

capability_enum!(InputModality {
    Text => "text",
    Image => "image",
    Pdf => "pdf",
    Audio => "audio",
});

capability_enum!(OutputModality {
    Text => "text",
    Audio => "audio",
    EmbeddingVector => "embedding_vector",
});

capability_enum!(InteractionFeature {
    ToolCalls => "tool_calls",
    ToolResults => "tool_results",
    ExtendedThinking => "extended_thinking",
    ParallelToolCalls => "parallel_tool_calls",
    StrictToolUse => "strict_tool_use",
    InterleavedThinking => "interleaved_thinking",
    FineGrainedToolStreaming => "fine_grained_tool_streaming",
});

capability_enum!(TransportMode {
    Json => "json",
    Sse => "sse",
    BinaryAudio => "binary_audio",
});

capability_enum!(ResponseFormatFeature {
    JsonObject => "json_object",
    JsonSchema => "json_schema",
});

capability_enum!(RoutingPolicyFeature {
    AllowFallbacks => "allow_fallbacks",
    RequireParameters => "require_parameters",
    DataCollection => "data_collection",
    Zdr => "zdr",
    ShadowRouting => "shadow_routing",
});

capability_enum!(CachingFeature {
    CacheControl => "cache_control",
    StickyRouting => "sticky_routing",
    SessionId => "session_id",
    SessionHeaderAlias => "session_header_alias",
});

capability_enum!(PluginFeature {
    PdfInputs => "pdf_inputs",
    ResponseHealing => "response_healing",
    ContextCompression => "context_compression",
    WebSearch => "web_search",
    PluginEnvelopes => "plugin_envelopes",
    OrgDefaults => "org_defaults",
    ForcedOn => "forced_on",
    PreventOverrides => "prevent_overrides",
});

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeCapabilityContract {
    #[serde(default)]
    pub request_families: Vec<RequestFamily>,
    #[serde(default)]
    pub input_modalities: Vec<InputModality>,
    #[serde(default)]
    pub output_modalities: Vec<OutputModality>,
    #[serde(default)]
    pub interaction_features: Vec<InteractionFeature>,
    #[serde(default)]
    pub transport_modes: Vec<TransportMode>,
    #[serde(default)]
    pub response_format_features: Vec<ResponseFormatFeature>,
    #[serde(default)]
    pub routing_policy_features: Vec<RoutingPolicyFeature>,
    #[serde(default)]
    pub caching_features: Vec<CachingFeature>,
    #[serde(default)]
    pub plugin_features: Vec<PluginFeature>,
    #[serde(default)]
    pub beta_headers: Vec<String>,
}

impl RuntimeCapabilityContract {
    pub fn new(
        request_families: Vec<RequestFamily>,
        input_modalities: Vec<InputModality>,
        output_modalities: Vec<OutputModality>,
        interaction_features: Vec<InteractionFeature>,
        transport_modes: Vec<TransportMode>,
        response_format_features: Vec<ResponseFormatFeature>,
    ) -> Self {
        Self {
            request_families,
            input_modalities,
            output_modalities,
            interaction_features,
            transport_modes,
            response_format_features,
            routing_policy_features: Vec::new(),
            caching_features: Vec::new(),
            plugin_features: Vec::new(),
            beta_headers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCapabilityRequest {
    pub family: RequestFamily,
    pub input_modalities: Vec<InputModality>,
    pub output_modalities: Vec<OutputModality>,
    pub interaction_features: Vec<InteractionFeature>,
    pub transport_mode: TransportMode,
    pub response_format_feature: Option<ResponseFormatFeature>,
    pub routing_policy_features: Vec<RoutingPolicyFeature>,
    pub caching_features: Vec<CachingFeature>,
    pub plugin_features: Vec<PluginFeature>,
    pub beta_headers: Vec<String>,
    pub requires_strict_mode: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityFeatureKind {
    Family,
    Modality,
    Transport,
    ResponseFormat,
    Tooling,
    Routing,
    Caching,
    Plugin,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeCapabilityError {
    #[error("provider publishes no runtime capability contract")]
    MissingContract,
    #[error("unsupported request family: {family}")]
    UnsupportedFamily { family: RequestFamily },
    #[error("unsupported input modality: {modality}")]
    UnsupportedInputModality { modality: InputModality },
    #[error("unsupported output modality: {modality}")]
    UnsupportedOutputModality { modality: OutputModality },
    #[error("unsupported transport mode: {transport}")]
    UnsupportedTransport { transport: TransportMode },
    #[error("unsupported structured-output feature: {feature}")]
    UnsupportedResponseFormat { feature: ResponseFormatFeature },
    #[error("strict mode is not supported")]
    StrictModeUnsupported,
    #[error("unsupported tooling feature: {feature}")]
    UnsupportedInteractionFeature { feature: InteractionFeature },
    #[error("unsupported routing feature: {feature}")]
    UnsupportedRoutingFeature { feature: RoutingPolicyFeature },
    #[error("unsupported caching feature: {feature}")]
    UnsupportedCachingFeature { feature: CachingFeature },
    #[error("unsupported plugin feature: {feature}")]
    UnsupportedPluginFeature { feature: PluginFeature },
    #[error("unsupported beta header: {header}")]
    UnsupportedBetaHeader { header: String },
    #[error("model '{model}' does not support tool use")]
    UnsupportedModelTooling { model: String },
    #[error("model '{model}' does not support structured output '{feature}'")]
    UnsupportedModelResponseFormat { model: String, feature: String },
    #[error(
        "model '{model}' only supports up to {max_output_tokens} output tokens (requested {requested})"
    )]
    MaxOutputTokensExceeded {
        model: String,
        requested: u32,
        max_output_tokens: u32,
    },
}

impl RuntimeCapabilityError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingContract => "capability.missing_contract",
            Self::UnsupportedFamily { .. } => "capability.unsupported_family",
            Self::UnsupportedInputModality { .. } | Self::UnsupportedOutputModality { .. } => {
                "capability.unsupported_modality"
            }
            Self::UnsupportedTransport { .. } => "capability.unsupported_transport",
            Self::UnsupportedResponseFormat { .. } => {
                "runtime.structured_output.unsupported_feature"
            }
            Self::StrictModeUnsupported => "runtime.structured_output.strict_mode_unsupported",
            Self::UnsupportedInteractionFeature { .. } => "runtime.tooling.unsupported_feature",
            Self::UnsupportedRoutingFeature {
                feature: RoutingPolicyFeature::RequireParameters,
            } => "runtime.parameter_compatibility",
            Self::UnsupportedRoutingFeature { .. }
            | Self::UnsupportedCachingFeature { .. }
            | Self::UnsupportedPluginFeature { .. } => "routing.no_eligible_provider",
            Self::UnsupportedBetaHeader { .. } => "runtime.beta_header.unsupported",
            Self::UnsupportedModelTooling { .. } => "runtime.tooling.unsupported_feature",
            Self::UnsupportedModelResponseFormat { .. } => {
                "runtime.structured_output.unsupported_feature"
            }
            Self::MaxOutputTokensExceeded { .. } => "runtime.max_output_tokens.exceeded",
        }
    }

    pub fn browser_safe_message(&self) -> String {
        match self {
            Self::MissingContract => {
                "The selected provider publishes no runtime capability contract.".to_string()
            }
            Self::UnsupportedFamily { family } => format!(
                "The selected provider does not support the '{}' request family.",
                family.as_str()
            ),
            Self::UnsupportedInputModality { modality } => format!(
                "The selected provider does not support '{}' input for this request.",
                modality.as_str()
            ),
            Self::UnsupportedOutputModality { modality } => format!(
                "The selected provider does not support '{}' output for this request.",
                modality.as_str()
            ),
            Self::UnsupportedTransport { transport } => format!(
                "The selected provider does not support '{}' transport for this request.",
                transport.as_str()
            ),
            Self::UnsupportedResponseFormat { feature } => format!(
                "The selected provider does not support '{}' structured output.",
                feature.as_str()
            ),
            Self::StrictModeUnsupported => {
                "The selected provider does not support strict mode for this request.".to_string()
            }
            Self::UnsupportedInteractionFeature { feature } => format!(
                "The selected provider does not support '{}' tooling semantics.",
                feature.as_str()
            ),
            Self::UnsupportedRoutingFeature { feature } => format!(
                "The selected provider cannot satisfy '{}' routing semantics.",
                feature.as_str()
            ),
            Self::UnsupportedCachingFeature { feature } => format!(
                "The selected provider cannot satisfy '{}' caching semantics.",
                feature.as_str()
            ),
            Self::UnsupportedPluginFeature { feature } => format!(
                "The selected provider does not support the '{}' plugin envelope.",
                feature.as_str()
            ),
            Self::UnsupportedBetaHeader { header } => format!(
                "The selected provider does not support the '{}' beta header.",
                header
            ),
            Self::UnsupportedModelTooling { model } => {
                format!("The resolved model '{}' does not support tool use.", model)
            }
            Self::UnsupportedModelResponseFormat { model, feature } => format!(
                "The resolved model '{}' does not support '{}' structured output.",
                model, feature
            ),
            Self::MaxOutputTokensExceeded {
                model,
                requested,
                max_output_tokens,
            } => format!(
                "The resolved model '{}' allows at most {} output tokens, but the request asked for {}.",
                model, max_output_tokens, requested
            ),
        }
    }

    pub fn details(&self) -> Value {
        match self {
            Self::UnsupportedModelTooling { model } => serde_json::json!({
                "model": model,
                "feature": "tools",
            }),
            Self::UnsupportedModelResponseFormat { model, feature } => serde_json::json!({
                "model": model,
                "feature": feature,
            }),
            Self::MaxOutputTokensExceeded {
                model,
                requested,
                max_output_tokens,
            } => serde_json::json!({
                "model": model,
                "requested_max_tokens": requested,
                "max_output_tokens": max_output_tokens,
            }),
            _ => serde_json::json!({}),
        }
    }
}

/// Validate a request against a provider capability contract.
///
/// `allow_missing_contract` covers providers that the runtime resolves without a
/// published contract, such as explicit execution targets. Providers that the
/// gateway cannot classify fail closed.
pub fn validate_runtime_capability_contract(
    contract: Option<&RuntimeCapabilityContract>,
    request: &RuntimeCapabilityRequest,
    allow_missing_contract: bool,
) -> Result<(), RuntimeCapabilityError> {
    let Some(contract) = contract else {
        return if allow_missing_contract {
            Ok(())
        } else {
            Err(RuntimeCapabilityError::MissingContract)
        };
    };

    if !contract.request_families.contains(&request.family) {
        return Err(RuntimeCapabilityError::UnsupportedFamily {
            family: request.family,
        });
    }

    for modality in &request.input_modalities {
        if !contract.input_modalities.contains(modality) {
            return Err(RuntimeCapabilityError::UnsupportedInputModality {
                modality: *modality,
            });
        }
    }

    for modality in &request.output_modalities {
        if !contract.output_modalities.contains(modality) {
            return Err(RuntimeCapabilityError::UnsupportedOutputModality {
                modality: *modality,
            });
        }
    }

    if !contract.transport_modes.contains(&request.transport_mode) {
        return Err(RuntimeCapabilityError::UnsupportedTransport {
            transport: request.transport_mode,
        });
    }

    if let Some(feature) = request.response_format_feature {
        if !contract.response_format_features.contains(&feature) {
            return Err(RuntimeCapabilityError::UnsupportedResponseFormat { feature });
        }
    }

    if request.requires_strict_mode
        && !contract
            .interaction_features
            .contains(&InteractionFeature::StrictToolUse)
    {
        return Err(RuntimeCapabilityError::StrictModeUnsupported);
    }

    for feature in &request.interaction_features {
        if !contract.interaction_features.contains(feature) {
            return Err(RuntimeCapabilityError::UnsupportedInteractionFeature {
                feature: *feature,
            });
        }
    }

    for feature in &request.routing_policy_features {
        if !contract.routing_policy_features.contains(feature) {
            return Err(RuntimeCapabilityError::UnsupportedRoutingFeature { feature: *feature });
        }
    }

    for feature in &request.caching_features {
        if !contract.caching_features.contains(feature) {
            return Err(RuntimeCapabilityError::UnsupportedCachingFeature { feature: *feature });
        }
    }

    for feature in &request.plugin_features {
        if !contract.plugin_features.contains(feature) {
            return Err(RuntimeCapabilityError::UnsupportedPluginFeature { feature: *feature });
        }
    }

    for header in &request.beta_headers {
        if !contract
            .beta_headers
            .iter()
            .any(|candidate| candidate == header)
        {
            return Err(RuntimeCapabilityError::UnsupportedBetaHeader {
                header: header.clone(),
            });
        }
    }

    Ok(())
}

fn request_capability_contract(path: &str, body: &Value) -> Option<RuntimeCapabilityRequest> {
    request_capability_contract_with_headers(path, body, &HeaderMap::new())
}

pub fn request_capability_contract_with_headers(
    path: &str,
    body: &Value,
    headers: &HeaderMap,
) -> Option<RuntimeCapabilityRequest> {
    let family = match path {
        "/v1/chat/completions" => RequestFamily::ChatCompletions,
        "/v1/completions" => RequestFamily::Completions,
        "/v1/responses" => RequestFamily::Responses,
        "/v1/messages" => RequestFamily::Messages,
        "/v1/embeddings" => RequestFamily::Embeddings,
        "/v1/audio/transcriptions" => RequestFamily::AudioTranscriptions,
        "/v1/audio/speech" => RequestFamily::AudioSpeech,
        _ => return None,
    };

    let mut input_modalities = match family {
        RequestFamily::AudioTranscriptions => vec![InputModality::Audio],
        _ => vec![InputModality::Text],
    };
    if !matches!(family, RequestFamily::AudioTranscriptions) {
        collect_modalities(body, &mut input_modalities);
    }
    let output_modalities = match family {
        RequestFamily::Embeddings => vec![OutputModality::EmbeddingVector],
        RequestFamily::AudioSpeech => vec![OutputModality::Audio],
        _ => vec![OutputModality::Text],
    };

    let transport_mode = if matches!(
        family,
        RequestFamily::Embeddings | RequestFamily::AudioTranscriptions
    ) {
        TransportMode::Json
    } else if matches!(family, RequestFamily::AudioSpeech) {
        TransportMode::BinaryAudio
    } else if body
        .get("stream")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        TransportMode::Sse
    } else {
        TransportMode::Json
    };

    let mut interaction_features = Vec::new();
    if body
        .get("tools")
        .and_then(|value| value.as_array())
        .is_some_and(|tools| !tools.is_empty())
    {
        push_unique(&mut interaction_features, InteractionFeature::ToolCalls);
    }
    if body
        .get("parallel_tool_calls")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        push_unique(
            &mut interaction_features,
            InteractionFeature::ParallelToolCalls,
        );
    }
    if request_contains_tool_results(body) {
        push_unique(&mut interaction_features, InteractionFeature::ToolResults);
    }
    if request_contains_thinking(body) {
        push_unique(
            &mut interaction_features,
            InteractionFeature::ExtendedThinking,
        );
    }

    let mut requires_strict_mode = false;
    if body
        .get("tools")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .any(|tool| {
            tool.pointer("/function/strict")
                .and_then(|value| value.as_bool())
                .unwrap_or(false)
        })
    {
        requires_strict_mode = true;
    }

    let response_format_feature = body
        .get("response_format")
        .and_then(|value| value.get("type"))
        .and_then(|value| value.as_str())
        .and_then(|value| match value {
            "json_object" => Some(ResponseFormatFeature::JsonObject),
            "json_schema" => Some(ResponseFormatFeature::JsonSchema),
            _ => None,
        });
    if body
        .pointer("/response_format/json_schema/strict")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        requires_strict_mode = true;
    }

    let mut routing_policy_features = Vec::new();
    if body
        .pointer("/provider/allow_fallbacks")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        push_unique(
            &mut routing_policy_features,
            RoutingPolicyFeature::AllowFallbacks,
        );
    }
    if body
        .pointer("/provider/require_parameters")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        push_unique(
            &mut routing_policy_features,
            RoutingPolicyFeature::RequireParameters,
        );
    }
    if body.pointer("/provider/data_collection").is_some() {
        push_unique(
            &mut routing_policy_features,
            RoutingPolicyFeature::DataCollection,
        );
    }
    if body.pointer("/provider/zdr").is_some() {
        push_unique(&mut routing_policy_features, RoutingPolicyFeature::Zdr);
    }

    let mut caching_features = Vec::new();
    if body.get("cache_control").is_some() {
        push_unique(&mut caching_features, CachingFeature::CacheControl);
    }
    if body.get("session_id").is_some() {
        push_unique(&mut caching_features, CachingFeature::SessionId);
    }
    if headers.get("x-session-id").is_some() {
        push_unique(&mut caching_features, CachingFeature::SessionHeaderAlias);
    }

    let mut plugin_features = Vec::new();
    if let Some(plugins) = body.get("plugins").and_then(|value| value.as_array()) {
        push_unique(&mut plugin_features, PluginFeature::PluginEnvelopes);
        for plugin in plugins {
            let enabled = plugin
                .get("enabled")
                .and_then(|value| value.as_bool())
                .unwrap_or(true);
            if !enabled {
                continue;
            }
            let Some(id) = plugin.get("id").and_then(|value| value.as_str()) else {
                continue;
            };
            let feature = match id {
                "pdf-inputs" => Some(PluginFeature::PdfInputs),
                "response-healing" => Some(PluginFeature::ResponseHealing),
                "context-compression" => Some(PluginFeature::ContextCompression),
                "web-search" => Some(PluginFeature::WebSearch),
                _ => None,
            };
            if let Some(feature) = feature {
                push_unique(&mut plugin_features, feature);
            }
        }
    }

    let mut beta_headers = requested_beta_headers(path, body, headers);
    for header in &beta_headers {
        match header.as_str() {
            "interleaved-thinking-2025-05-14" => {
                push_unique(
                    &mut interaction_features,
                    InteractionFeature::InterleavedThinking,
                );
            }
            "fine-grained-tool-streaming-2025-05-14" => {
                push_unique(
                    &mut interaction_features,
                    InteractionFeature::FineGrainedToolStreaming,
                );
            }
            _ => {}
        }
    }
    beta_headers.sort_unstable();
    beta_headers.dedup();

    Some(RuntimeCapabilityRequest {
        family,
        input_modalities,
        output_modalities,
        interaction_features,
        transport_mode,
        response_format_feature,
        routing_policy_features,
        caching_features,
        plugin_features,
        beta_headers,
        requires_strict_mode,
    })
}

fn requested_beta_headers(path: &str, body: &Value, headers: &HeaderMap) -> Vec<String> {
    let mut requested = headers
        .get("anthropic-beta")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if path == "/v1/messages" && request_contains_thinking(body) {
        push_unique(
            &mut requested,
            "interleaved-thinking-2025-05-14".to_string(),
        );
    }

    requested
}

fn collect_modalities(body: &Value, input_modalities: &mut Vec<InputModality>) {
    visit_value(body, &mut |value| {
        if let Some(kind) = value.get("type").and_then(|field| field.as_str()) {
            match kind {
                "image" | "image_url" | "input_image" => {
                    push_unique(input_modalities, InputModality::Image);
                }
                "audio" | "input_audio" => {
                    push_unique(input_modalities, InputModality::Audio);
                }
                "document" | "file" | "input_file" if is_pdf_file_value(value) => {
                    push_unique(input_modalities, InputModality::Pdf);
                }
                _ => {}
            }
        }
    });
}

fn is_pdf_file_value(value: &Value) -> bool {
    value
        .get("media_type")
        .and_then(|field| field.as_str())
        .is_some_and(|media_type| media_type.eq_ignore_ascii_case("application/pdf"))
        || value
            .get("mime_type")
            .and_then(|field| field.as_str())
            .is_some_and(|media_type| media_type.eq_ignore_ascii_case("application/pdf"))
        || value
            .get("filename")
            .and_then(|field| field.as_str())
            .is_some_and(|filename| filename.to_ascii_lowercase().ends_with(".pdf"))
}

fn request_contains_tool_results(body: &Value) -> bool {
    let mut found = false;
    visit_value(body, &mut |value| {
        if value
            .get("type")
            .and_then(|field| field.as_str())
            .is_some_and(|kind| kind == "tool_result")
        {
            found = true;
        }
    });
    found
}

fn request_contains_thinking(body: &Value) -> bool {
    if body
        .get("thinking")
        .and_then(|value| value.get("type"))
        .and_then(|field| field.as_str())
        .is_some_and(|kind| kind == "enabled")
    {
        return true;
    }

    let mut found = false;
    visit_value(body, &mut |value| {
        if value
            .get("type")
            .and_then(|field| field.as_str())
            .is_some_and(|kind| kind == "thinking")
        {
            found = true;
        }
    });
    found
}

fn visit_value(value: &Value, visitor: &mut impl FnMut(&Value)) {
    match value {
        Value::Array(items) => {
            for item in items {
                visit_value(item, visitor);
            }
        }
        Value::Object(map) => {
            visitor(value);
            for item in map.values() {
                visit_value(item, visitor);
            }
        }
        _ => {}
    }
}

fn push_unique<T>(items: &mut Vec<T>, candidate: T)
where
    T: PartialEq,
{
    if !items.contains(&candidate) {
        items.push(candidate);
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
    use axum::http::HeaderValue;
    use serde_json::json;

    fn base_request() -> RuntimeCapabilityRequest {
        RuntimeCapabilityRequest {
            family: RequestFamily::ChatCompletions,
            input_modalities: vec![InputModality::Text],
            output_modalities: vec![OutputModality::Text],
            interaction_features: vec![InteractionFeature::ToolCalls],
            transport_mode: TransportMode::Json,
            response_format_feature: Some(ResponseFormatFeature::JsonObject),
            routing_policy_features: vec![RoutingPolicyFeature::AllowFallbacks],
            caching_features: vec![CachingFeature::CacheControl],
            plugin_features: vec![PluginFeature::PluginEnvelopes],
            beta_headers: vec!["fine-grained-tool-streaming-2025-05-14".to_string()],
            requires_strict_mode: false,
        }
    }

    fn base_contract() -> RuntimeCapabilityContract {
        RuntimeCapabilityContract {
            request_families: vec![RequestFamily::ChatCompletions, RequestFamily::Messages],
            input_modalities: vec![
                InputModality::Text,
                InputModality::Image,
                InputModality::Audio,
                InputModality::Pdf,
            ],
            output_modalities: vec![
                OutputModality::Text,
                OutputModality::Audio,
                OutputModality::EmbeddingVector,
            ],
            interaction_features: vec![
                InteractionFeature::ToolCalls,
                InteractionFeature::ParallelToolCalls,
                InteractionFeature::ToolResults,
                InteractionFeature::ExtendedThinking,
                InteractionFeature::StrictToolUse,
                InteractionFeature::InterleavedThinking,
                InteractionFeature::FineGrainedToolStreaming,
            ],
            transport_modes: vec![
                TransportMode::Json,
                TransportMode::Sse,
                TransportMode::BinaryAudio,
            ],
            response_format_features: vec![
                ResponseFormatFeature::JsonObject,
                ResponseFormatFeature::JsonSchema,
            ],
            routing_policy_features: vec![
                RoutingPolicyFeature::AllowFallbacks,
                RoutingPolicyFeature::RequireParameters,
                RoutingPolicyFeature::DataCollection,
                RoutingPolicyFeature::Zdr,
            ],
            caching_features: vec![
                CachingFeature::CacheControl,
                CachingFeature::SessionId,
                CachingFeature::SessionHeaderAlias,
            ],
            plugin_features: vec![
                PluginFeature::PluginEnvelopes,
                PluginFeature::PdfInputs,
                PluginFeature::ResponseHealing,
                PluginFeature::ContextCompression,
                PluginFeature::WebSearch,
            ],
            beta_headers: vec![
                "fine-grained-tool-streaming-2025-05-14".to_string(),
                "interleaved-thinking-2025-05-14".to_string(),
            ],
        }
    }

    #[test]
    fn new_contract_leaves_optional_feature_sets_empty() {
        let contract = RuntimeCapabilityContract::new(
            vec![RequestFamily::Responses],
            vec![InputModality::Text],
            vec![OutputModality::Text],
            vec![InteractionFeature::ToolCalls],
            vec![TransportMode::Json],
            vec![ResponseFormatFeature::JsonObject],
        );

        assert!(contract.routing_policy_features.is_empty());
        assert!(contract.caching_features.is_empty());
        assert!(contract.plugin_features.is_empty());
        assert!(contract.beta_headers.is_empty());
    }

    #[test]
    fn capability_enums_expose_stable_strings_and_display() {
        assert_eq!(RequestFamily::AudioSpeech.as_str(), "audio_speech");
        assert_eq!(RequestFamily::AudioSpeech.to_string(), "audio_speech");

        assert_eq!(InputModality::Pdf.as_str(), "pdf");
        assert_eq!(InputModality::Pdf.to_string(), "pdf");

        assert_eq!(OutputModality::EmbeddingVector.as_str(), "embedding_vector");
        assert_eq!(
            OutputModality::EmbeddingVector.to_string(),
            "embedding_vector"
        );

        assert_eq!(
            InteractionFeature::FineGrainedToolStreaming.as_str(),
            "fine_grained_tool_streaming"
        );
        assert_eq!(
            InteractionFeature::FineGrainedToolStreaming.to_string(),
            "fine_grained_tool_streaming"
        );

        assert_eq!(TransportMode::BinaryAudio.as_str(), "binary_audio");
        assert_eq!(TransportMode::BinaryAudio.to_string(), "binary_audio");

        assert_eq!(ResponseFormatFeature::JsonSchema.as_str(), "json_schema");
        assert_eq!(ResponseFormatFeature::JsonSchema.to_string(), "json_schema");

        assert_eq!(
            RoutingPolicyFeature::ShadowRouting.as_str(),
            "shadow_routing"
        );
        assert_eq!(
            RoutingPolicyFeature::ShadowRouting.to_string(),
            "shadow_routing"
        );

        assert_eq!(
            CachingFeature::SessionHeaderAlias.as_str(),
            "session_header_alias"
        );
        assert_eq!(
            CachingFeature::SessionHeaderAlias.to_string(),
            "session_header_alias"
        );

        assert_eq!(
            PluginFeature::PreventOverrides.as_str(),
            "prevent_overrides"
        );
        assert_eq!(
            PluginFeature::PreventOverrides.to_string(),
            "prevent_overrides"
        );
    }

    #[test]
    fn validate_contract_accepts_advertised_capabilities() {
        let contract = base_contract();
        let request = base_request();

        assert!(validate_runtime_capability_contract(Some(&contract), &request, false).is_ok());
    }

    #[test]
    fn validate_contract_handles_missing_contract() {
        let request = base_request();

        assert_eq!(
            validate_runtime_capability_contract(None, &request, false).unwrap_err(),
            RuntimeCapabilityError::MissingContract
        );
        assert!(validate_runtime_capability_contract(None, &request, true).is_ok());
    }

    #[test]
    fn validate_contract_returns_specific_feature_errors() {
        let mut request = base_request();
        let mut contract = base_contract();
        contract.request_families.clear();
        assert_eq!(
            validate_runtime_capability_contract(Some(&contract), &request, false).unwrap_err(),
            RuntimeCapabilityError::UnsupportedFamily {
                family: RequestFamily::ChatCompletions,
            }
        );

        request = base_request();
        contract = base_contract();
        request.input_modalities.push(InputModality::Image);
        contract.input_modalities = vec![InputModality::Text];
        assert_eq!(
            validate_runtime_capability_contract(Some(&contract), &request, false).unwrap_err(),
            RuntimeCapabilityError::UnsupportedInputModality {
                modality: InputModality::Image,
            }
        );

        request = base_request();
        contract = base_contract();
        request.output_modalities.push(OutputModality::Audio);
        contract.output_modalities = vec![OutputModality::Text];
        assert_eq!(
            validate_runtime_capability_contract(Some(&contract), &request, false).unwrap_err(),
            RuntimeCapabilityError::UnsupportedOutputModality {
                modality: OutputModality::Audio,
            }
        );

        request = base_request();
        contract = base_contract();
        request.transport_mode = TransportMode::Sse;
        contract.transport_modes = vec![TransportMode::Json];
        assert_eq!(
            validate_runtime_capability_contract(Some(&contract), &request, false).unwrap_err(),
            RuntimeCapabilityError::UnsupportedTransport {
                transport: TransportMode::Sse,
            }
        );

        request = base_request();
        contract = base_contract();
        request.response_format_feature = Some(ResponseFormatFeature::JsonSchema);
        contract.response_format_features = vec![ResponseFormatFeature::JsonObject];
        assert_eq!(
            validate_runtime_capability_contract(Some(&contract), &request, false).unwrap_err(),
            RuntimeCapabilityError::UnsupportedResponseFormat {
                feature: ResponseFormatFeature::JsonSchema,
            }
        );

        request = base_request();
        contract = base_contract();
        request.requires_strict_mode = true;
        contract.interaction_features = vec![InteractionFeature::ToolCalls];
        assert_eq!(
            validate_runtime_capability_contract(Some(&contract), &request, false).unwrap_err(),
            RuntimeCapabilityError::StrictModeUnsupported
        );

        request = base_request();
        contract = base_contract();
        request.interaction_features = vec![InteractionFeature::ParallelToolCalls];
        contract.interaction_features = vec![InteractionFeature::ToolCalls];
        assert_eq!(
            validate_runtime_capability_contract(Some(&contract), &request, false).unwrap_err(),
            RuntimeCapabilityError::UnsupportedInteractionFeature {
                feature: InteractionFeature::ParallelToolCalls,
            }
        );

        request = base_request();
        contract = base_contract();
        request.routing_policy_features = vec![RoutingPolicyFeature::RequireParameters];
        contract.routing_policy_features = vec![RoutingPolicyFeature::AllowFallbacks];
        assert_eq!(
            validate_runtime_capability_contract(Some(&contract), &request, false).unwrap_err(),
            RuntimeCapabilityError::UnsupportedRoutingFeature {
                feature: RoutingPolicyFeature::RequireParameters,
            }
        );

        request = base_request();
        contract = base_contract();
        request.caching_features = vec![CachingFeature::SessionHeaderAlias];
        contract.caching_features = vec![CachingFeature::CacheControl];
        assert_eq!(
            validate_runtime_capability_contract(Some(&contract), &request, false).unwrap_err(),
            RuntimeCapabilityError::UnsupportedCachingFeature {
                feature: CachingFeature::SessionHeaderAlias,
            }
        );

        request = base_request();
        contract = base_contract();
        request.plugin_features = vec![PluginFeature::WebSearch];
        contract.plugin_features = vec![PluginFeature::PluginEnvelopes];
        assert_eq!(
            validate_runtime_capability_contract(Some(&contract), &request, false).unwrap_err(),
            RuntimeCapabilityError::UnsupportedPluginFeature {
                feature: PluginFeature::WebSearch,
            }
        );

        request = base_request();
        contract = base_contract();
        request.beta_headers = vec!["missing-header".to_string()];
        contract.beta_headers.clear();
        assert_eq!(
            validate_runtime_capability_contract(Some(&contract), &request, false).unwrap_err(),
            RuntimeCapabilityError::UnsupportedBetaHeader {
                header: "missing-header".to_string(),
            }
        );
    }

    #[test]
    fn runtime_capability_error_metadata_is_stable() {
        let routing_error = RuntimeCapabilityError::UnsupportedRoutingFeature {
            feature: RoutingPolicyFeature::RequireParameters,
        };
        assert_eq!(routing_error.code(), "runtime.parameter_compatibility");
        assert!(routing_error
            .browser_safe_message()
            .contains("require_parameters"));
        assert_eq!(routing_error.details(), json!({}));

        let response_error = RuntimeCapabilityError::UnsupportedModelResponseFormat {
            model: "gpt-5.4-mini".to_string(),
            feature: "json_schema".to_string(),
        };
        assert_eq!(
            response_error.code(),
            "runtime.structured_output.unsupported_feature"
        );
        assert_eq!(
            response_error.details(),
            json!({
                "model": "gpt-5.4-mini",
                "feature": "json_schema",
            })
        );
        assert!(response_error
            .browser_safe_message()
            .contains("gpt-5.4-mini"));

        let token_error = RuntimeCapabilityError::MaxOutputTokensExceeded {
            model: "claude-opus-4-8".to_string(),
            requested: 4096,
            max_output_tokens: 2048,
        };
        assert_eq!(token_error.code(), "runtime.max_output_tokens.exceeded");
        assert_eq!(
            token_error.details(),
            json!({
                "model": "claude-opus-4-8",
                "requested_max_tokens": 4096,
                "max_output_tokens": 2048,
            })
        );
    }

    #[test]
    fn runtime_capability_error_metadata_covers_remaining_variants() {
        let missing = RuntimeCapabilityError::MissingContract;
        assert_eq!(missing.code(), "capability.missing_contract");
        assert!(missing
            .browser_safe_message()
            .contains("no runtime capability contract"));
        assert_eq!(missing.details(), json!({}));

        let family = RuntimeCapabilityError::UnsupportedFamily {
            family: RequestFamily::Messages,
        };
        assert_eq!(family.code(), "capability.unsupported_family");
        assert!(family.browser_safe_message().contains("messages"));

        let input = RuntimeCapabilityError::UnsupportedInputModality {
            modality: InputModality::Image,
        };
        assert_eq!(input.code(), "capability.unsupported_modality");
        assert!(input.browser_safe_message().contains("'image' input"));

        let output = RuntimeCapabilityError::UnsupportedOutputModality {
            modality: OutputModality::Audio,
        };
        assert_eq!(output.code(), "capability.unsupported_modality");
        assert!(output.browser_safe_message().contains("'audio' output"));

        let transport = RuntimeCapabilityError::UnsupportedTransport {
            transport: TransportMode::Sse,
        };
        assert_eq!(transport.code(), "capability.unsupported_transport");
        assert!(transport.browser_safe_message().contains("'sse' transport"));

        let response = RuntimeCapabilityError::UnsupportedResponseFormat {
            feature: ResponseFormatFeature::JsonObject,
        };
        assert_eq!(
            response.code(),
            "runtime.structured_output.unsupported_feature"
        );
        assert!(response.browser_safe_message().contains("json_object"));

        let strict = RuntimeCapabilityError::StrictModeUnsupported;
        assert_eq!(
            strict.code(),
            "runtime.structured_output.strict_mode_unsupported"
        );
        assert!(strict.browser_safe_message().contains("strict mode"));

        let interaction = RuntimeCapabilityError::UnsupportedInteractionFeature {
            feature: InteractionFeature::ToolResults,
        };
        assert_eq!(interaction.code(), "runtime.tooling.unsupported_feature");
        assert!(interaction.browser_safe_message().contains("tool_results"));

        let routing = RuntimeCapabilityError::UnsupportedRoutingFeature {
            feature: RoutingPolicyFeature::ShadowRouting,
        };
        assert_eq!(routing.code(), "routing.no_eligible_provider");
        assert!(routing.browser_safe_message().contains("shadow_routing"));

        let caching = RuntimeCapabilityError::UnsupportedCachingFeature {
            feature: CachingFeature::StickyRouting,
        };
        assert_eq!(caching.code(), "routing.no_eligible_provider");
        assert!(caching.browser_safe_message().contains("sticky_routing"));

        let plugin = RuntimeCapabilityError::UnsupportedPluginFeature {
            feature: PluginFeature::ForcedOn,
        };
        assert_eq!(plugin.code(), "routing.no_eligible_provider");
        assert!(plugin.browser_safe_message().contains("forced_on"));

        let beta = RuntimeCapabilityError::UnsupportedBetaHeader {
            header: "beta-2026-01-01".to_string(),
        };
        assert_eq!(beta.code(), "runtime.beta_header.unsupported");
        assert!(beta.browser_safe_message().contains("beta-2026-01-01"));

        let tooling = RuntimeCapabilityError::UnsupportedModelTooling {
            model: "gpt-5.4-mini".to_string(),
        };
        assert_eq!(tooling.code(), "runtime.tooling.unsupported_feature");
        assert!(tooling.browser_safe_message().contains("gpt-5.4-mini"));
        assert_eq!(
            tooling.details(),
            json!({
                "model": "gpt-5.4-mini",
                "feature": "tools",
            })
        );
    }

    #[test]
    fn request_contract_extracts_chat_request_features() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "anthropic-beta",
            HeaderValue::from_static(
                "fine-grained-tool-streaming-2025-05-14, interleaved-thinking-2025-05-14, fine-grained-tool-streaming-2025-05-14",
            ),
        );
        headers.insert(
            "x-session-id",
            HeaderValue::from_static("session-from-header"),
        );

        let request = request_capability_contract_with_headers(
            "/v1/chat/completions",
            &json!({
                "stream": true,
                "parallel_tool_calls": true,
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "strict": true
                    }
                },
                "provider": {
                    "allow_fallbacks": true,
                    "require_parameters": true,
                    "data_collection": false,
                    "zdr": false
                },
                "cache_control": {"type": "ephemeral"},
                "session_id": "session-in-body",
                "tools": [{
                    "function": {
                        "strict": true
                    }
                }],
                "plugins": [
                    {"id": "response-healing", "enabled": true},
                    {"id": "pdf-inputs", "enabled": false},
                    {"id": "web-search"}
                ],
                "input": [
                    {"type": "input_image"},
                    {"type": "input_audio"},
                    {"type": "document", "mime_type": "application/pdf"}
                ],
                "messages": [{
                    "content": [
                        {"type": "tool_result"},
                        {"type": "thinking"}
                    ]
                }]
            }),
            &headers,
        )
        .expect("chat completions request should be recognized");

        assert_eq!(request.family, RequestFamily::ChatCompletions);
        assert_eq!(
            request.input_modalities,
            vec![
                InputModality::Text,
                InputModality::Image,
                InputModality::Audio,
                InputModality::Pdf,
            ]
        );
        assert_eq!(request.output_modalities, vec![OutputModality::Text]);
        assert_eq!(request.transport_mode, TransportMode::Sse);
        assert_eq!(
            request.response_format_feature,
            Some(ResponseFormatFeature::JsonSchema)
        );
        assert!(request.requires_strict_mode);
        assert!(request
            .interaction_features
            .contains(&InteractionFeature::ToolCalls));
        assert!(request
            .interaction_features
            .contains(&InteractionFeature::ParallelToolCalls));
        assert!(request
            .interaction_features
            .contains(&InteractionFeature::ToolResults));
        assert!(request
            .interaction_features
            .contains(&InteractionFeature::ExtendedThinking));
        assert!(request
            .interaction_features
            .contains(&InteractionFeature::InterleavedThinking));
        assert!(request
            .interaction_features
            .contains(&InteractionFeature::FineGrainedToolStreaming));
        assert_eq!(
            request.routing_policy_features,
            vec![
                RoutingPolicyFeature::AllowFallbacks,
                RoutingPolicyFeature::RequireParameters,
                RoutingPolicyFeature::DataCollection,
                RoutingPolicyFeature::Zdr,
            ]
        );
        assert_eq!(
            request.caching_features,
            vec![
                CachingFeature::CacheControl,
                CachingFeature::SessionId,
                CachingFeature::SessionHeaderAlias,
            ]
        );
        assert_eq!(
            request.plugin_features,
            vec![
                PluginFeature::PluginEnvelopes,
                PluginFeature::ResponseHealing,
                PluginFeature::WebSearch,
            ]
        );
        assert_eq!(
            request.beta_headers,
            vec![
                "fine-grained-tool-streaming-2025-05-14".to_string(),
                "interleaved-thinking-2025-05-14".to_string(),
            ]
        );
    }

    #[test]
    fn request_contract_messages_add_interleaved_beta_header_from_thinking() {
        let request = request_capability_contract(
            "/v1/messages",
            &json!({
                "messages": [{
                    "content": [{"type": "thinking"}]
                }]
            }),
        )
        .expect("messages request should be recognized");

        assert_eq!(request.family, RequestFamily::Messages);
        assert_eq!(request.transport_mode, TransportMode::Json);
        assert!(request
            .interaction_features
            .contains(&InteractionFeature::ExtendedThinking));
        assert!(request
            .interaction_features
            .contains(&InteractionFeature::InterleavedThinking));
        assert_eq!(
            request.beta_headers,
            vec!["interleaved-thinking-2025-05-14".to_string()]
        );
    }

    #[test]
    fn request_contract_messages_add_interleaved_beta_header_from_enabled_thinking_config() {
        let request = request_capability_contract(
            "/v1/messages",
            &json!({
                "thinking": {
                    "type": "enabled",
                    "budget_tokens": 32
                },
                "messages": [{
                    "role": "user",
                    "content": "hello"
                }]
            }),
        )
        .expect("messages request should be recognized");

        assert!(request
            .interaction_features
            .contains(&InteractionFeature::ExtendedThinking));
        assert!(request
            .interaction_features
            .contains(&InteractionFeature::InterleavedThinking));
        assert_eq!(
            request.beta_headers,
            vec!["interleaved-thinking-2025-05-14".to_string()]
        );
    }

    #[test]
    fn request_contract_extracts_responses_request_features_without_message_beta_injection() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-session-id",
            HeaderValue::from_static("response-session-header"),
        );

        let request = request_capability_contract_with_headers(
            "/v1/responses",
            &json!({
                "stream": true,
                "parallel_tool_calls": true,
                "response_format": {
                    "type": "json_object"
                },
                "provider": {
                    "data_collection": false,
                    "zdr": true
                },
                "cache_control": {"type": "ephemeral"},
                "session_id": "response-session-body",
                "tools": [{
                    "function": {
                        "name": "lookup_policy"
                    }
                }],
                "plugins": [
                    {"id": "context-compression", "enabled": true},
                    {"id": "pdf-inputs", "enabled": true},
                    {"id": "web-search", "enabled": false},
                    {"id": "unknown-plugin", "enabled": true}
                ],
                "input": [
                    {"type": "input_image"},
                    {"type": "input_audio"},
                    {"type": "document", "filename": "evidence.pdf"},
                    {"type": "tool_result"},
                    {"type": "thinking"}
                ]
            }),
            &headers,
        )
        .expect("responses request should be recognized");

        assert_eq!(request.family, RequestFamily::Responses);
        assert_eq!(
            request.input_modalities,
            vec![
                InputModality::Text,
                InputModality::Image,
                InputModality::Audio,
                InputModality::Pdf,
            ]
        );
        assert_eq!(request.output_modalities, vec![OutputModality::Text]);
        assert_eq!(request.transport_mode, TransportMode::Sse);
        assert_eq!(
            request.response_format_feature,
            Some(ResponseFormatFeature::JsonObject)
        );
        assert!(request
            .interaction_features
            .contains(&InteractionFeature::ToolCalls));
        assert!(request
            .interaction_features
            .contains(&InteractionFeature::ParallelToolCalls));
        assert!(request
            .interaction_features
            .contains(&InteractionFeature::ToolResults));
        assert!(request
            .interaction_features
            .contains(&InteractionFeature::ExtendedThinking));
        assert!(!request
            .interaction_features
            .contains(&InteractionFeature::InterleavedThinking));
        assert_eq!(
            request.routing_policy_features,
            vec![
                RoutingPolicyFeature::DataCollection,
                RoutingPolicyFeature::Zdr,
            ]
        );
        assert_eq!(
            request.caching_features,
            vec![
                CachingFeature::CacheControl,
                CachingFeature::SessionId,
                CachingFeature::SessionHeaderAlias,
            ]
        );
        assert_eq!(
            request.plugin_features,
            vec![
                PluginFeature::PluginEnvelopes,
                PluginFeature::ContextCompression,
                PluginFeature::PdfInputs,
            ]
        );
        assert!(request.beta_headers.is_empty());
    }

    #[test]
    fn request_contract_maps_other_supported_families() {
        let embeddings = request_capability_contract("/v1/embeddings", &json!({}))
            .expect("embeddings request should be recognized");
        assert_eq!(embeddings.family, RequestFamily::Embeddings);
        assert_eq!(
            embeddings.output_modalities,
            vec![OutputModality::EmbeddingVector]
        );
        assert_eq!(embeddings.transport_mode, TransportMode::Json);

        let speech = request_capability_contract("/v1/audio/speech", &json!({}))
            .expect("audio speech request should be recognized");
        assert_eq!(speech.family, RequestFamily::AudioSpeech);
        assert_eq!(speech.output_modalities, vec![OutputModality::Audio]);
        assert_eq!(speech.transport_mode, TransportMode::BinaryAudio);

        let transcription = request_capability_contract(
            "/v1/audio/transcriptions",
            &json!({"type": "input_image"}),
        )
        .expect("audio transcription request should be recognized");
        assert_eq!(transcription.family, RequestFamily::AudioTranscriptions);
        assert_eq!(transcription.input_modalities, vec![InputModality::Audio]);
        assert_eq!(transcription.transport_mode, TransportMode::Json);

        assert!(request_capability_contract("/v1/unknown", &json!({})).is_none());
    }

    #[test]
    fn request_helper_functions_cover_nested_traversal_without_duplicates() {
        let mut headers = HeaderMap::new();
        headers.insert("anthropic-beta", HeaderValue::from_static("alpha, , beta"));

        let thinking_body = json!({
            "messages": [{
                "content": [
                    {"type": "thinking"},
                    {"type": "tool_result"},
                    {"type": "input_image"},
                    {"type": "input_audio"},
                    {"type": "input_file", "filename": "evidence.pdf"},
                    {"type": "file", "mime_type": "application/pdf"}
                ]
            }]
        });

        assert_eq!(
            requested_beta_headers("/v1/messages", &thinking_body, &headers),
            vec![
                "alpha".to_string(),
                "beta".to_string(),
                "interleaved-thinking-2025-05-14".to_string(),
            ]
        );
        assert!(request_contains_tool_results(&thinking_body));
        assert!(request_contains_thinking(&thinking_body));
        assert!(!request_contains_tool_results(&json!({"messages": []})));
        assert!(!request_contains_thinking(&json!({"messages": []})));

        let mut modalities = vec![InputModality::Text];
        collect_modalities(&thinking_body, &mut modalities);
        assert_eq!(
            modalities,
            vec![
                InputModality::Text,
                InputModality::Image,
                InputModality::Audio,
                InputModality::Pdf,
            ]
        );

        let mut visited = 0;
        visit_value(&thinking_body, &mut |_| visited += 1);
        assert!(visited >= 6);

        let mut unique = vec![1, 2];
        push_unique(&mut unique, 2);
        push_unique(&mut unique, 3);
        assert_eq!(unique, vec![1, 2, 3]);
    }

    // ── RequestFamily ───────────────────────────────────────────────────

    #[test]
    fn request_family_as_str() {
        assert_eq!(RequestFamily::ChatCompletions.as_str(), "chat_completions");
        assert_eq!(RequestFamily::Responses.as_str(), "responses");
        assert_eq!(RequestFamily::Messages.as_str(), "messages");
        assert_eq!(RequestFamily::Embeddings.as_str(), "embeddings");
        assert_eq!(
            RequestFamily::AudioTranscriptions.as_str(),
            "audio_transcriptions"
        );
        assert_eq!(RequestFamily::AudioSpeech.as_str(), "audio_speech");
    }

    #[test]
    fn request_family_display() {
        assert_eq!(
            RequestFamily::ChatCompletions.to_string(),
            "chat_completions"
        );
    }

    #[test]
    fn request_family_serde_roundtrip() {
        for family in [
            RequestFamily::ChatCompletions,
            RequestFamily::Responses,
            RequestFamily::Messages,
            RequestFamily::Embeddings,
            RequestFamily::AudioTranscriptions,
            RequestFamily::AudioSpeech,
        ] {
            let json = serde_json::to_string(&family).unwrap();
            let recovered: RequestFamily = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, family);
        }
    }

    // ── InputModality ───────────────────────────────────────────────────

    #[test]
    fn input_modality_as_str() {
        assert_eq!(InputModality::Text.as_str(), "text");
        assert_eq!(InputModality::Image.as_str(), "image");
        assert_eq!(InputModality::Pdf.as_str(), "pdf");
        assert_eq!(InputModality::Audio.as_str(), "audio");
    }

    #[test]
    fn input_modality_serde_roundtrip() {
        for modality in [
            InputModality::Text,
            InputModality::Image,
            InputModality::Pdf,
            InputModality::Audio,
        ] {
            let json = serde_json::to_string(&modality).unwrap();
            let recovered: InputModality = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, modality);
        }
    }

    // ── OutputModality ──────────────────────────────────────────────────

    #[test]
    fn output_modality_as_str() {
        assert_eq!(OutputModality::Text.as_str(), "text");
        assert_eq!(OutputModality::Audio.as_str(), "audio");
        assert_eq!(OutputModality::EmbeddingVector.as_str(), "embedding_vector");
    }

    // ── InteractionFeature ──────────────────────────────────────────────

    #[test]
    fn interaction_feature_as_str() {
        assert_eq!(InteractionFeature::ToolCalls.as_str(), "tool_calls");
        assert_eq!(InteractionFeature::ToolResults.as_str(), "tool_results");
        assert_eq!(
            InteractionFeature::ExtendedThinking.as_str(),
            "extended_thinking"
        );
        assert_eq!(
            InteractionFeature::ParallelToolCalls.as_str(),
            "parallel_tool_calls"
        );
        assert_eq!(
            InteractionFeature::StrictToolUse.as_str(),
            "strict_tool_use"
        );
        assert_eq!(
            InteractionFeature::InterleavedThinking.as_str(),
            "interleaved_thinking"
        );
    }

    // ── TransportMode ───────────────────────────────────────────────────

    #[test]
    fn transport_mode_as_str() {
        assert_eq!(TransportMode::Json.as_str(), "json");
        assert_eq!(TransportMode::Sse.as_str(), "sse");
        assert_eq!(TransportMode::BinaryAudio.as_str(), "binary_audio");
    }

    #[test]
    fn is_pdf_file_value_detects_pdf_metadata() {
        assert!(is_pdf_file_value(&json!({"media_type": "application/pdf"})));
        assert!(is_pdf_file_value(&json!({"mime_type": "application/pdf"})));
        assert!(is_pdf_file_value(&json!({"filename": "Evidence.PDF"})));
        assert!(!is_pdf_file_value(&json!({"filename": "notes.txt"})));
    }

    // ── RuntimeCapabilityContract validation ───────────────────────────

    #[test]
    fn validate_contract_passes_when_all_satisfied() {
        let contract = base_contract();
        let request = base_request();
        assert!(validate_runtime_capability_contract(Some(&contract), &request, false).is_ok());
    }

    #[test]
    fn validate_contract_none_with_missing_contract_allowed() {
        let request = base_request();
        assert!(validate_runtime_capability_contract(None, &request, true).is_ok());
    }

    #[test]
    fn validate_contract_none_without_allowance_returns_error() {
        let request = base_request();
        let result = validate_runtime_capability_contract(None, &request, false);
        assert!(result.is_err());
    }

    // ── RuntimeCapabilityError ──────────────────────────────────────────

    #[test]
    fn missing_contract_error_has_code() {
        let err = RuntimeCapabilityError::MissingContract;
        assert_eq!(err.code(), "capability.missing_contract");
    }
}

#[cfg(test)]
mod coverage_expansion_runtime_capability_tests {
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

    // ── RequestFamily ───────────────────────────────────────────────────

    #[test]
    fn request_family_as_str() {
        assert_eq!(RequestFamily::ChatCompletions.as_str(), "chat_completions");
        assert_eq!(RequestFamily::Responses.as_str(), "responses");
        assert_eq!(RequestFamily::Messages.as_str(), "messages");
        assert_eq!(RequestFamily::Embeddings.as_str(), "embeddings");
        assert_eq!(
            RequestFamily::AudioTranscriptions.as_str(),
            "audio_transcriptions"
        );
        assert_eq!(RequestFamily::AudioSpeech.as_str(), "audio_speech");
    }

    #[test]
    fn request_family_display() {
        assert_eq!(
            format!("{}", RequestFamily::ChatCompletions),
            "chat_completions"
        );
    }

    #[test]
    fn request_family_serde() {
        let serialized = serde_json::to_value(RequestFamily::Embeddings).unwrap();
        assert_eq!(serialized, json!("embeddings"));
    }

    // ── InputModality ───────────────────────────────────────────────────

    #[test]
    fn input_modality_as_str() {
        assert_eq!(InputModality::Text.as_str(), "text");
        assert_eq!(InputModality::Image.as_str(), "image");
        assert_eq!(InputModality::Pdf.as_str(), "pdf");
        assert_eq!(InputModality::Audio.as_str(), "audio");
    }

    // ── OutputModality ──────────────────────────────────────────────────

    #[test]
    fn output_modality_as_str() {
        assert_eq!(OutputModality::Text.as_str(), "text");
        assert_eq!(OutputModality::Audio.as_str(), "audio");
        assert_eq!(OutputModality::EmbeddingVector.as_str(), "embedding_vector");
    }

    // ── InteractionFeature ──────────────────────────────────────────────

    #[test]
    fn interaction_feature_as_str() {
        assert_eq!(InteractionFeature::ToolCalls.as_str(), "tool_calls");
        assert_eq!(InteractionFeature::ToolResults.as_str(), "tool_results");
        assert_eq!(
            InteractionFeature::ExtendedThinking.as_str(),
            "extended_thinking"
        );
        assert_eq!(
            InteractionFeature::ParallelToolCalls.as_str(),
            "parallel_tool_calls"
        );
        assert_eq!(
            InteractionFeature::StrictToolUse.as_str(),
            "strict_tool_use"
        );
        assert_eq!(
            InteractionFeature::InterleavedThinking.as_str(),
            "interleaved_thinking"
        );
        assert_eq!(
            InteractionFeature::FineGrainedToolStreaming.as_str(),
            "fine_grained_tool_streaming"
        );
    }

    // ── TransportMode ───────────────────────────────────────────────────

    #[test]
    fn transport_mode_as_str() {
        assert_eq!(TransportMode::Json.as_str(), "json");
        assert_eq!(TransportMode::Sse.as_str(), "sse");
        assert_eq!(TransportMode::BinaryAudio.as_str(), "binary_audio");
    }

    // ── RuntimeCapabilityError code and message ─────────────────────────

    #[test]
    fn runtime_capability_error_codes() {
        assert_eq!(
            RuntimeCapabilityError::MissingContract.code(),
            "capability.missing_contract"
        );
        assert_eq!(
            RuntimeCapabilityError::UnsupportedFamily {
                family: RequestFamily::ChatCompletions
            }
            .code(),
            "capability.unsupported_family"
        );
        assert_eq!(
            RuntimeCapabilityError::UnsupportedInputModality {
                modality: InputModality::Image
            }
            .code(),
            "capability.unsupported_modality"
        );
        assert_eq!(
            RuntimeCapabilityError::UnsupportedOutputModality {
                modality: OutputModality::Audio
            }
            .code(),
            "capability.unsupported_modality"
        );
        assert_eq!(
            RuntimeCapabilityError::UnsupportedTransport {
                transport: TransportMode::Sse
            }
            .code(),
            "capability.unsupported_transport"
        );
        assert_eq!(
            RuntimeCapabilityError::UnsupportedResponseFormat {
                feature: ResponseFormatFeature::JsonSchema
            }
            .code(),
            "runtime.structured_output.unsupported_feature"
        );
        assert_eq!(
            RuntimeCapabilityError::StrictModeUnsupported.code(),
            "runtime.structured_output.strict_mode_unsupported"
        );
        assert_eq!(
            RuntimeCapabilityError::UnsupportedInteractionFeature {
                feature: InteractionFeature::ToolCalls
            }
            .code(),
            "runtime.tooling.unsupported_feature"
        );
        assert_eq!(
            RuntimeCapabilityError::UnsupportedRoutingFeature {
                feature: RoutingPolicyFeature::RequireParameters
            }
            .code(),
            "runtime.parameter_compatibility"
        );
        assert_eq!(
            RuntimeCapabilityError::UnsupportedRoutingFeature {
                feature: RoutingPolicyFeature::AllowFallbacks
            }
            .code(),
            "routing.no_eligible_provider"
        );
        assert_eq!(
            RuntimeCapabilityError::UnsupportedCachingFeature {
                feature: CachingFeature::CacheControl
            }
            .code(),
            "routing.no_eligible_provider"
        );
        assert_eq!(
            RuntimeCapabilityError::UnsupportedPluginFeature {
                feature: PluginFeature::PdfInputs
            }
            .code(),
            "routing.no_eligible_provider"
        );
        assert_eq!(
            RuntimeCapabilityError::UnsupportedBetaHeader {
                header: "test".to_string()
            }
            .code(),
            "runtime.beta_header.unsupported"
        );
        assert_eq!(
            RuntimeCapabilityError::UnsupportedModelTooling {
                model: "gpt-5.4".to_string()
            }
            .code(),
            "runtime.tooling.unsupported_feature"
        );
        assert_eq!(
            RuntimeCapabilityError::UnsupportedModelResponseFormat {
                model: "gpt-5.4".to_string(),
                feature: "json_schema".to_string()
            }
            .code(),
            "runtime.structured_output.unsupported_feature"
        );
        assert_eq!(
            RuntimeCapabilityError::MaxOutputTokensExceeded {
                model: "gpt-5.4".to_string(),
                requested: 20000,
                max_output_tokens: 16384,
            }
            .code(),
            "runtime.max_output_tokens.exceeded"
        );
    }

    #[test]
    fn runtime_capability_error_browser_safe_messages() {
        let msg = RuntimeCapabilityError::MissingContract.browser_safe_message();
        assert!(msg.contains("no runtime capability contract"));

        let msg = RuntimeCapabilityError::UnsupportedFamily {
            family: RequestFamily::Embeddings,
        }
        .browser_safe_message();
        assert!(msg.contains("embeddings"));

        let msg = RuntimeCapabilityError::StrictModeUnsupported.browser_safe_message();
        assert!(msg.contains("strict mode"));

        let msg = RuntimeCapabilityError::MaxOutputTokensExceeded {
            model: "gpt-5.4".to_string(),
            requested: 20000,
            max_output_tokens: 16384,
        }
        .browser_safe_message();
        assert!(msg.contains("16384"));
        assert!(msg.contains("20000"));
    }

    #[test]
    fn runtime_capability_error_details() {
        let details = RuntimeCapabilityError::UnsupportedModelTooling {
            model: "test-model".to_string(),
        }
        .details();
        assert_eq!(details["model"], "test-model");
        assert_eq!(details["feature"], "tools");

        let details = RuntimeCapabilityError::MaxOutputTokensExceeded {
            model: "m".to_string(),
            requested: 1000,
            max_output_tokens: 500,
        }
        .details();
        assert_eq!(details["requested_max_tokens"], 1000);
        assert_eq!(details["max_output_tokens"], 500);

        let details = RuntimeCapabilityError::MissingContract.details();
        assert_eq!(details, json!({}));
    }

    // ── validate_runtime_capability_contract ────────────────────────────

    #[test]
    fn validate_contract_none_with_missing_contract_allowed_passes() {
        let request = RuntimeCapabilityRequest {
            family: RequestFamily::ChatCompletions,
            input_modalities: vec![InputModality::Text],
            output_modalities: vec![OutputModality::Text],
            interaction_features: vec![],
            transport_mode: TransportMode::Json,
            response_format_feature: None,
            routing_policy_features: vec![],
            caching_features: vec![],
            plugin_features: vec![],
            beta_headers: vec![],
            requires_strict_mode: false,
        };
        assert!(validate_runtime_capability_contract(None, &request, true).is_ok());
    }

    #[test]
    fn validate_contract_none_without_allowance_fails() {
        let request = RuntimeCapabilityRequest {
            family: RequestFamily::ChatCompletions,
            input_modalities: vec![InputModality::Text],
            output_modalities: vec![OutputModality::Text],
            interaction_features: vec![],
            transport_mode: TransportMode::Json,
            response_format_feature: None,
            routing_policy_features: vec![],
            caching_features: vec![],
            plugin_features: vec![],
            beta_headers: vec![],
            requires_strict_mode: false,
        };
        let result = validate_runtime_capability_contract(None, &request, false);
        assert!(matches!(
            result,
            Err(RuntimeCapabilityError::MissingContract)
        ));
    }

    #[test]
    fn validate_contract_unsupported_family() {
        let contract = RuntimeCapabilityContract::new(
            vec![RequestFamily::ChatCompletions],
            vec![InputModality::Text],
            vec![OutputModality::Text],
            vec![],
            vec![TransportMode::Json],
            vec![],
        );
        let request = RuntimeCapabilityRequest {
            family: RequestFamily::Embeddings,
            input_modalities: vec![InputModality::Text],
            output_modalities: vec![OutputModality::EmbeddingVector],
            interaction_features: vec![],
            transport_mode: TransportMode::Json,
            response_format_feature: None,
            routing_policy_features: vec![],
            caching_features: vec![],
            plugin_features: vec![],
            beta_headers: vec![],
            requires_strict_mode: false,
        };
        let result = validate_runtime_capability_contract(Some(&contract), &request, false);
        assert!(matches!(
            result,
            Err(RuntimeCapabilityError::UnsupportedFamily { .. })
        ));
    }

    #[test]
    fn validate_contract_unsupported_input_modality() {
        let contract = RuntimeCapabilityContract::new(
            vec![RequestFamily::ChatCompletions],
            vec![InputModality::Text],
            vec![OutputModality::Text],
            vec![],
            vec![TransportMode::Json],
            vec![],
        );
        let request = RuntimeCapabilityRequest {
            family: RequestFamily::ChatCompletions,
            input_modalities: vec![InputModality::Text, InputModality::Image],
            output_modalities: vec![OutputModality::Text],
            interaction_features: vec![],
            transport_mode: TransportMode::Json,
            response_format_feature: None,
            routing_policy_features: vec![],
            caching_features: vec![],
            plugin_features: vec![],
            beta_headers: vec![],
            requires_strict_mode: false,
        };
        let result = validate_runtime_capability_contract(Some(&contract), &request, false);
        assert!(matches!(
            result,
            Err(RuntimeCapabilityError::UnsupportedInputModality { .. })
        ));
    }

    #[test]
    fn validate_contract_unsupported_transport() {
        let contract = RuntimeCapabilityContract::new(
            vec![RequestFamily::ChatCompletions],
            vec![InputModality::Text],
            vec![OutputModality::Text],
            vec![],
            vec![TransportMode::Json],
            vec![],
        );
        let request = RuntimeCapabilityRequest {
            family: RequestFamily::ChatCompletions,
            input_modalities: vec![InputModality::Text],
            output_modalities: vec![OutputModality::Text],
            interaction_features: vec![],
            transport_mode: TransportMode::Sse,
            response_format_feature: None,
            routing_policy_features: vec![],
            caching_features: vec![],
            plugin_features: vec![],
            beta_headers: vec![],
            requires_strict_mode: false,
        };
        let result = validate_runtime_capability_contract(Some(&contract), &request, false);
        assert!(matches!(
            result,
            Err(RuntimeCapabilityError::UnsupportedTransport { .. })
        ));
    }

    #[test]
    fn validate_contract_strict_mode_unsupported() {
        let contract = RuntimeCapabilityContract::new(
            vec![RequestFamily::ChatCompletions],
            vec![InputModality::Text],
            vec![OutputModality::Text],
            vec![InteractionFeature::ToolCalls],
            vec![TransportMode::Json],
            vec![],
        );
        let request = RuntimeCapabilityRequest {
            family: RequestFamily::ChatCompletions,
            input_modalities: vec![InputModality::Text],
            output_modalities: vec![OutputModality::Text],
            interaction_features: vec![],
            transport_mode: TransportMode::Json,
            response_format_feature: None,
            routing_policy_features: vec![],
            caching_features: vec![],
            plugin_features: vec![],
            beta_headers: vec![],
            requires_strict_mode: true,
        };
        let result = validate_runtime_capability_contract(Some(&contract), &request, false);
        assert!(matches!(
            result,
            Err(RuntimeCapabilityError::StrictModeUnsupported)
        ));
    }

    #[test]
    fn validate_contract_all_supported_passes() {
        let contract = RuntimeCapabilityContract::new(
            vec![RequestFamily::ChatCompletions],
            vec![InputModality::Text, InputModality::Image],
            vec![OutputModality::Text],
            vec![
                InteractionFeature::ToolCalls,
                InteractionFeature::StrictToolUse,
            ],
            vec![TransportMode::Json, TransportMode::Sse],
            vec![ResponseFormatFeature::JsonObject],
        );
        let request = RuntimeCapabilityRequest {
            family: RequestFamily::ChatCompletions,
            input_modalities: vec![InputModality::Text],
            output_modalities: vec![OutputModality::Text],
            interaction_features: vec![InteractionFeature::ToolCalls],
            transport_mode: TransportMode::Sse,
            response_format_feature: Some(ResponseFormatFeature::JsonObject),
            routing_policy_features: vec![],
            caching_features: vec![],
            plugin_features: vec![],
            beta_headers: vec![],
            requires_strict_mode: true,
        };
        assert!(validate_runtime_capability_contract(Some(&contract), &request, false).is_ok());
    }

    // ── request_capability_contract ─────────────────────────────────────

    #[test]
    fn request_capability_contract_unknown_path_returns_none() {
        let body = json!({});
        assert!(request_capability_contract("/v1/unknown", &body).is_none());
    }

    #[test]
    fn request_capability_contract_chat_completions_basic() {
        let body = json!({"model": "gpt-5.4", "messages": [{"role": "user", "content": "hi"}]});
        let req = request_capability_contract("/v1/chat/completions", &body).unwrap();
        assert_eq!(req.family, RequestFamily::ChatCompletions);
        assert_eq!(req.transport_mode, TransportMode::Json);
        assert!(req.input_modalities.contains(&InputModality::Text));
    }

    #[test]
    fn request_capability_contract_streaming() {
        let body = json!({"model": "gpt-5.4", "stream": true, "messages": []});
        let req = request_capability_contract("/v1/chat/completions", &body).unwrap();
        assert_eq!(req.transport_mode, TransportMode::Sse);
    }

    #[test]
    fn request_capability_contract_with_tools() {
        let body = json!({
            "model": "gpt-5.4",
            "messages": [],
            "tools": [{"type": "function", "function": {"name": "test", "strict": true}}]
        });
        let req = request_capability_contract("/v1/chat/completions", &body).unwrap();
        assert!(req
            .interaction_features
            .contains(&InteractionFeature::ToolCalls));
        assert!(req.requires_strict_mode);
    }

    #[test]
    fn request_capability_contract_embeddings() {
        let body = json!({"model": "text-embedding-ada-002", "input": "test"});
        let req = request_capability_contract("/v1/embeddings", &body).unwrap();
        assert_eq!(req.family, RequestFamily::Embeddings);
        assert_eq!(req.transport_mode, TransportMode::Json);
        assert!(req
            .output_modalities
            .contains(&OutputModality::EmbeddingVector));
    }

    #[test]
    fn request_capability_contract_audio_speech() {
        let body = json!({"model": "tts-1", "input": "Hello", "voice": "alloy"});
        let req = request_capability_contract("/v1/audio/speech", &body).unwrap();
        assert_eq!(req.family, RequestFamily::AudioSpeech);
        assert_eq!(req.transport_mode, TransportMode::BinaryAudio);
        assert!(req.output_modalities.contains(&OutputModality::Audio));
    }

    #[test]
    fn request_capability_contract_audio_transcription() {
        let body = json!({"model": "whisper-1"});
        let req = request_capability_contract("/v1/audio/transcriptions", &body).unwrap();
        assert_eq!(req.family, RequestFamily::AudioTranscriptions);
        assert!(req.input_modalities.contains(&InputModality::Audio));
    }

    #[test]
    fn request_capability_contract_with_image_content() {
        let body = json!({
            "model": "gpt-5.4",
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "describe"},
                    {"type": "image_url", "image_url": {"url": "https://example.com/img.png"}}
                ]
            }]
        });
        let req = request_capability_contract("/v1/chat/completions", &body).unwrap();
        assert!(req.input_modalities.contains(&InputModality::Image));
    }

    #[test]
    fn request_capability_contract_response_format_json_schema() {
        let body = json!({
            "model": "gpt-5.4",
            "messages": [],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"strict": true, "schema": {}}
            }
        });
        let req = request_capability_contract("/v1/chat/completions", &body).unwrap();
        assert_eq!(
            req.response_format_feature,
            Some(ResponseFormatFeature::JsonSchema)
        );
        assert!(req.requires_strict_mode);
    }

    // ── RuntimeCapabilityContract::new ───────────────────────────────────

    #[test]
    fn runtime_capability_contract_new_keeps_requested_families() {
        let contract = RuntimeCapabilityContract::new(
            vec![RequestFamily::ChatCompletions],
            vec![InputModality::Text],
            vec![OutputModality::Text],
            vec![],
            vec![TransportMode::Json],
            vec![],
        );
        assert_eq!(
            contract.request_families,
            vec![RequestFamily::ChatCompletions]
        );
        assert!(contract.beta_headers.is_empty());
    }
}
