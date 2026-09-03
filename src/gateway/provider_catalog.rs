// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::{str::FromStr, sync::Arc};

use bigdecimal::BigDecimal;
use tokio::sync::RwLock;

use super::{
    format_translation::ProviderFormat,
    provider_auth::ProviderType,
    runtime_capabilities::{
        CachingFeature, InputModality, InteractionFeature, OutputModality, PluginFeature,
        RequestFamily, ResponseFormatFeature, RoutingPolicyFeature, RuntimeCapabilityContract,
        TransportMode,
    },
};

#[derive(Debug, Clone, Copy)]
pub struct ProviderProfile {
    pub provider_type: ProviderType,
    pub format: ProviderFormat,
    pub api_key_header: &'static str,
    pub api_key_prefix: &'static str,
    pub path_template: Option<&'static str>,
}

fn published_contract(
    request_families: &[RequestFamily],
    input_modalities: &[InputModality],
    output_modalities: &[OutputModality],
    interaction_features: &[InteractionFeature],
    transport_modes: &[TransportMode],
    response_format_features: &[ResponseFormatFeature],
) -> RuntimeCapabilityContract {
    RuntimeCapabilityContract::new(
        request_families.to_vec(),
        input_modalities.to_vec(),
        output_modalities.to_vec(),
        interaction_features.to_vec(),
        transport_modes.to_vec(),
        response_format_features.to_vec(),
    )
}

fn gateway_routing_policy_features() -> Vec<RoutingPolicyFeature> {
    vec![
        RoutingPolicyFeature::AllowFallbacks,
        RoutingPolicyFeature::RequireParameters,
        RoutingPolicyFeature::DataCollection,
        RoutingPolicyFeature::Zdr,
        RoutingPolicyFeature::ShadowRouting,
    ]
}

fn gateway_caching_features() -> Vec<CachingFeature> {
    vec![
        CachingFeature::CacheControl,
        CachingFeature::StickyRouting,
        CachingFeature::SessionId,
        CachingFeature::SessionHeaderAlias,
    ]
}

fn text_plugin_features() -> Vec<PluginFeature> {
    vec![
        PluginFeature::ResponseHealing,
        PluginFeature::ContextCompression,
        PluginFeature::PluginEnvelopes,
        PluginFeature::OrgDefaults,
        PluginFeature::ForcedOn,
        PluginFeature::PreventOverrides,
    ]
}

const OPENAI_ALIASES: &[&str] = &[
    "openai",
    "open-ai",
    "openai-chat",
    "openai-responses",
    "aimlapi",
    "ai-ml-api",
    "ai21",
    "alibaba",
    "qwen",
    "dashscope",
    "openrouter",
    "groq",
    "mistral",
    "mistral-ai",
    "perplexity",
    "perplexity-ai",
    "cloudflare-gateway",
    "cloudera",
    "docker",
    "docker-model-runner",
    "togetherai",
    "together-ai",
    "together",
    "deepseek",
    "xai",
    "x-ai",
    "grok",
    "cerebras",
    "voyage",
    "nscale",
    "cometapi",
    "hyperbolic",
    "vercel",
    "vercel-ai",
    "truefoundry",
    "quiverai",
    "fireworks",
    "fireworks-ai",
    "envoy",
    "f5",
    "sambanova",
    "moonshot",
    "moonshot-ai",
    "moonshot-kimi",
    "kimi",
    "minimax",
    "novita",
    "novita-ai",
    "friendli",
    "friendli-ai",
    "jina",
    "jina-ai",
    "inference-net",
    "inference-networks",
    "parasail",
    "parasail-ai",
    "targon",
    "nebius",
    "nebius-ai",
    "lepton",
    "lepton-ai",
    "cloudflare-ai-gateway",
    "github-models",
    "github",
    "portkey",
    "helicone",
    "litellm",
    "litellm-embedding",
    "lmstudio",
    "localai",
    "ollama",
    "llamafile",
    "llama",
    "llama-cpp",
    "llama.cpp",
    "llamaapi",
    "vllm",
    "text-generation-webui",
    "anyscale",
    "byteplus",
    "claude-platform-aws",
    "deepbricks",
    "deepinfra",
    "ember-cloud",
    "lambda",
    "lemonfox-ai",
    "modal",
    "nomic-ai",
    "oracle",
    "segmind",
    "zhipu",
    "triton-inference",
    "predibase",
    "jfrog",
    "openllm",
    "openclaw",
    "modelscope-openai",
    "runpod-openai",
    "scaleway-ai",
    "together-enterprise",
    "baseten-openai",
    "zhipu-openai",
    "01-ai-openai",
    "baichuan-openai",
    "openai-compatible",
    "compat-openai",
    "custom-openai",
];

const CLOUDFLARE_AI_ALIASES: &[&str] = &["cloudflare-ai", "cloudflare-workers-ai", "workers-ai"];

const TRANSFORMERS_ALIASES: &[&str] = &["transformers", "transformersjs", "transformers.js"];

const QUIVERAI_ALIASES: &[&str] = &["quiverai"];

const SNOWFLAKE_ALIASES: &[&str] = &["snowflake", "snowflake-cortex"];

const ANTHROPIC_ALIASES: &[&str] = &[
    "anthropic",
    "claude",
    "claude-code",
    "claude-sdk",
    "claude-agent-sdk",
    "anthropic-messages",
];

const COHERE_ALIASES: &[&str] = &[
    "cohere",
    "cohere-chat",
    "cohere-command",
    "cohere-command-r",
    "cohere-command-r-plus",
    "cohere-embed",
];

const HUGGINGFACE_ALIASES: &[&str] = &[
    "huggingface",
    "hugging-face",
    "hf",
    "hf-inference",
    "hf-feature-extraction",
    "hf-text-generation",
    "hf-text-classification",
    "hf-sentence-similarity",
    "text-embeddings-inference",
    "tei",
    "inference-endpoints",
];

const REPLICATE_ALIASES: &[&str] = &[
    "replicate",
    "replicate-predictions",
    "replicate-models",
    "replicate-inference",
    "fal",
    "fal-ai",
];

const DATABRICKS_ALIASES: &[&str] = &[
    "databricks",
    "databricks-serving",
    "databricks-mosaic",
    "mosaic-ai",
    "databricks-foundation-models",
];

const WATSONX_ALIASES: &[&str] = &[
    "watsonx",
    "watsonx-ai",
    "ibm-watsonx",
    "watsonx-text",
    "watsonx-ml",
];

const BEDROCK_ALIASES: &[&str] = &[
    "bedrock",
    "aws-bedrock",
    "amazon-bedrock",
    "bedrock-converse",
    "bedrock-embed",
];

const VERTEX_ALIASES: &[&str] = &["vertex", "google-vertex", "vertex-ai", "google-vertex-ai"];

const GOOGLE_AI_STUDIO_ALIASES: &[&str] = &[
    "google",
    "google-ai-studio",
    "google-gemini",
    "gemini",
    "generativelanguage",
    "google-live",
];

const SAGEMAKER_ALIASES: &[&str] = &["sagemaker", "amazon-sagemaker", "aws-sagemaker"];

const AZURE_ALIASES: &[&str] = &[
    "azure",
    "azure-openai",
    "azure-ai-foundry",
    "azure-foundry",
    "entra-openai",
];

const ELEVENLABS_ALIASES: &[&str] = &[
    "elevenlabs",
    "eleven-labs",
    "elevenlabs-tts",
    "elevenlabs-conversational",
];

const MODELSLAB_ALIASES: &[&str] = &["modelslab", "models-lab", "modelslab-ai"];

const IBM_BAM_ALIASES: &[&str] = &["ibm-bam", "bam", "ibm-bam-ai"];

fn supported_provider_aliases() -> Vec<&'static str> {
    let mut aliases = Vec::new();
    aliases.extend_from_slice(OPENAI_ALIASES);
    aliases.extend_from_slice(CLOUDFLARE_AI_ALIASES);
    aliases.extend_from_slice(TRANSFORMERS_ALIASES);
    aliases.extend_from_slice(ANTHROPIC_ALIASES);
    aliases.extend_from_slice(COHERE_ALIASES);
    aliases.extend_from_slice(HUGGINGFACE_ALIASES);
    aliases.extend_from_slice(REPLICATE_ALIASES);
    aliases.extend_from_slice(DATABRICKS_ALIASES);
    aliases.extend_from_slice(WATSONX_ALIASES);
    aliases.extend_from_slice(BEDROCK_ALIASES);
    aliases.extend_from_slice(VERTEX_ALIASES);
    aliases.extend_from_slice(GOOGLE_AI_STUDIO_ALIASES);
    aliases.extend_from_slice(SAGEMAKER_ALIASES);
    aliases.extend_from_slice(SNOWFLAKE_ALIASES);
    aliases.extend_from_slice(AZURE_ALIASES);
    aliases.extend_from_slice(ELEVENLABS_ALIASES);
    aliases.extend_from_slice(MODELSLAB_ALIASES);
    aliases.extend_from_slice(IBM_BAM_ALIASES);
    aliases.sort_unstable();
    aliases.dedup();
    aliases
}

pub(crate) fn normalized_provider_alias(value: &str) -> String {
    let trimmed = value
        .split(':')
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase();
    trimmed.replace(['_', ' '], "-")
}

pub(crate) fn provider_status_page_url(provider: &str) -> &'static str {
    let alias = provider
        .split(':')
        .next()
        .unwrap_or(provider)
        .trim()
        .to_ascii_lowercase();
    let alias = alias.as_str();
    if OPENAI_ALIASES.contains(&alias) || alias == "openai" {
        "status.openai.com"
    } else if ANTHROPIC_ALIASES.contains(&alias) || alias == "anthropic" {
        "status.anthropic.com"
    } else if alias.contains("azure") || AZURE_ALIASES.contains(&alias) {
        "status.azure.com"
    } else if GOOGLE_AI_STUDIO_ALIASES.contains(&alias)
        || VERTEX_ALIASES.contains(&alias)
        || alias.contains("google")
    {
        "status.cloud.google.com"
    } else if BEDROCK_ALIASES.contains(&alias) || alias.contains("aws") {
        "health.aws.amazon.com"
    } else if alias.contains("cohere") || COHERE_ALIASES.contains(&alias) {
        "status.cohere.com"
    } else {
        "the provider's status page"
    }
}

pub(crate) fn provider_path_template_for_public_path(
    provider: &str,
    public_path: &str,
) -> Option<&'static str> {
    let alias = normalized_provider_alias(provider);
    let alias = alias.as_str();

    if alias == "openrouter" {
        return match public_path {
            "/v1/chat/completions" | "/v1/responses" => Some("/api/v1/chat/completions"),
            "/v1/embeddings" => Some("/api/v1/embeddings"),
            "/v1/audio/transcriptions" => Some("/api/v1/audio/transcriptions"),
            "/v1/audio/speech" => Some("/api/v1/audio/speech"),
            _ => None,
        };
    }

    if alias == "quiverai" {
        return match public_path {
            "/v1/chat/completions" => Some("/svgs/generations"),
            _ => None,
        };
    }

    if alias == "voyage" {
        return match public_path {
            "/v1/embeddings" => Some("/v1/embeddings"),
            _ => None,
        };
    }

    if OPENAI_ALIASES.contains(&alias)
        || CLOUDFLARE_AI_ALIASES.contains(&alias)
        || SNOWFLAKE_ALIASES.contains(&alias)
        || AZURE_ALIASES.contains(&alias)
    {
        return match public_path {
            "/v1/chat/completions" => Some("/v1/chat/completions"),
            "/v1/responses" => Some("/v1/responses"),
            "/v1/embeddings" => Some("/v1/embeddings"),
            "/v1/audio/transcriptions" => Some("/v1/audio/transcriptions"),
            "/v1/audio/speech" => Some("/v1/audio/speech"),
            _ => None,
        };
    }

    if ELEVENLABS_ALIASES.contains(&alias) {
        return match public_path {
            "/v1/audio/speech" => Some("/v1/text-to-speech"),
            _ => None,
        };
    }

    None
}

/// Providers that are present in catalog metadata for display and pricing but
/// cannot be dispatched at runtime because their adapters are unavailable.
pub(crate) const UNAVAILABLE_PROVIDER_ALIASES: &[&[&str]] = &[];

/// Returns `true` when the normalized alias maps to a provider whose runtime
/// adapter has been removed. These providers are retained for catalog display
/// and pricing resolution but must not be dispatched.
pub(crate) fn is_unavailable_provider(provider: &str) -> bool {
    let alias = normalized_provider_alias(provider);
    UNAVAILABLE_PROVIDER_ALIASES
        .iter()
        .any(|group| group.contains(&alias.as_str()))
}

/// Human-readable message for rejected unavailable providers.
pub(crate) fn unavailable_provider_message(provider: &str) -> String {
    format!(
        "provider '{}' is not available for runtime dispatch; \
         use an OpenAI-compatible, Azure, Google, or other supported adapter instead",
        provider
    )
}

pub(crate) fn exact_udr_provider_id(provider: &str) -> Option<&'static str> {
    let alias = normalized_provider_alias(provider);
    let alias = alias.as_str();

    if ANTHROPIC_ALIASES.contains(&alias) {
        return Some("anthropic");
    }
    if BEDROCK_ALIASES.contains(&alias) {
        return Some("aws-bedrock");
    }
    if COHERE_ALIASES.contains(&alias) {
        return Some("cohere");
    }
    if WATSONX_ALIASES.contains(&alias) {
        return Some("watsonx");
    }

    None
}

pub(crate) fn validate_exact_udr_provider_id(provider: &str) -> Result<(), String> {
    let Some(expected) = exact_udr_provider_id(provider) else {
        return Ok(());
    };
    let actual = normalized_provider_alias(provider);
    if actual == expected {
        return Ok(());
    }

    Err(format!(
        "provider '{provider}' must use exact provider id '{expected}'; aliases remain rejected for UDR Phase 2-3"
    ))
}

pub fn profile_for_provider(provider: &str) -> Option<ProviderProfile> {
    let alias = normalized_provider_alias(provider);

    if QUIVERAI_ALIASES.contains(&alias.as_str()) {
        return Some(ProviderProfile {
            provider_type: ProviderType::Generic,
            format: ProviderFormat::OpenAI,
            api_key_header: "Authorization",
            api_key_prefix: "Bearer ",
            path_template: Some("/svgs/generations"),
        });
    }

    if OPENAI_ALIASES.contains(&alias.as_str()) {
        return Some(ProviderProfile {
            provider_type: ProviderType::OpenAI,
            format: ProviderFormat::OpenAI,
            api_key_header: "Authorization",
            api_key_prefix: "Bearer ",
            path_template: None,
        });
    }

    if CLOUDFLARE_AI_ALIASES.contains(&alias.as_str()) {
        return Some(ProviderProfile {
            provider_type: ProviderType::CloudflareAi,
            format: ProviderFormat::OpenAI,
            api_key_header: "Authorization",
            api_key_prefix: "Bearer ",
            path_template: None,
        });
    }

    if ANTHROPIC_ALIASES.contains(&alias.as_str()) {
        return Some(ProviderProfile {
            provider_type: ProviderType::Anthropic,
            format: ProviderFormat::Anthropic,
            api_key_header: "x-api-key",
            api_key_prefix: "",
            path_template: Some("/v1/messages"),
        });
    }

    if COHERE_ALIASES.contains(&alias.as_str()) {
        return Some(ProviderProfile {
            provider_type: ProviderType::Cohere,
            format: ProviderFormat::Cohere,
            api_key_header: "Authorization",
            api_key_prefix: "Bearer ",
            path_template: Some("/v2/chat"),
        });
    }

    if HUGGINGFACE_ALIASES.contains(&alias.as_str()) {
        return Some(ProviderProfile {
            provider_type: ProviderType::HuggingFace,
            format: ProviderFormat::HuggingFace,
            api_key_header: "Authorization",
            api_key_prefix: "Bearer ",
            path_template: Some("/models/{model}"),
        });
    }

    if REPLICATE_ALIASES.contains(&alias.as_str()) {
        return Some(ProviderProfile {
            provider_type: ProviderType::Replicate,
            format: ProviderFormat::Replicate,
            api_key_header: "Authorization",
            api_key_prefix: "Token ",
            path_template: Some("/v1/models/{model}/predictions"),
        });
    }

    if DATABRICKS_ALIASES.contains(&alias.as_str()) {
        return Some(ProviderProfile {
            provider_type: ProviderType::Databricks,
            format: ProviderFormat::OpenAI,
            api_key_header: "Authorization",
            api_key_prefix: "Bearer ",
            path_template: Some("/serving-endpoints/{model}/invocations"),
        });
    }

    if WATSONX_ALIASES.contains(&alias.as_str()) {
        return Some(ProviderProfile {
            provider_type: ProviderType::WatsonX,
            format: ProviderFormat::WatsonX,
            api_key_header: "Authorization",
            api_key_prefix: "Bearer ",
            path_template: Some("/ml/v1/text/generation?version=2024-05-01"),
        });
    }

    if BEDROCK_ALIASES.contains(&alias.as_str()) {
        return Some(ProviderProfile {
            provider_type: ProviderType::AwsBedrock,
            format: ProviderFormat::Anthropic,
            api_key_header: "Authorization",
            api_key_prefix: "Bearer ",
            path_template: None,
        });
    }

    if GOOGLE_AI_STUDIO_ALIASES.contains(&alias.as_str()) {
        return Some(ProviderProfile {
            provider_type: ProviderType::GoogleAiStudio,
            format: ProviderFormat::GoogleGemini,
            api_key_header: "x-goog-api-key",
            api_key_prefix: "",
            path_template: Some("/v1beta/models/{model}:generateContent"),
        });
    }

    if VERTEX_ALIASES.contains(&alias.as_str()) {
        return Some(ProviderProfile {
            provider_type: ProviderType::GoogleVertex,
            format: ProviderFormat::GoogleGemini,
            api_key_header: "Authorization",
            api_key_prefix: "Bearer ",
            path_template: None,
        });
    }

    if SAGEMAKER_ALIASES.contains(&alias.as_str()) {
        return Some(ProviderProfile {
            provider_type: ProviderType::SageMaker,
            format: ProviderFormat::OpenAI,
            api_key_header: "Authorization",
            api_key_prefix: "Bearer ",
            path_template: Some("/endpoints/{model}/invocations"),
        });
    }

    if SNOWFLAKE_ALIASES.contains(&alias.as_str()) {
        return Some(ProviderProfile {
            provider_type: ProviderType::SnowflakeCortex,
            format: ProviderFormat::OpenAI,
            api_key_header: "Authorization",
            api_key_prefix: "Bearer ",
            path_template: None,
        });
    }

    if AZURE_ALIASES.contains(&alias.as_str()) {
        return Some(ProviderProfile {
            provider_type: ProviderType::AzureOpenAI,
            format: ProviderFormat::OpenAI,
            api_key_header: "api-key",
            api_key_prefix: "",
            path_template: None,
        });
    }

    if ELEVENLABS_ALIASES.contains(&alias.as_str()) {
        return Some(ProviderProfile {
            provider_type: ProviderType::Generic,
            format: ProviderFormat::OpenAI,
            api_key_header: "xi-api-key",
            api_key_prefix: "",
            path_template: Some("/v1/text-to-speech"),
        });
    }

    if MODELSLAB_ALIASES.contains(&alias.as_str()) {
        return Some(ProviderProfile {
            provider_type: ProviderType::Generic,
            format: ProviderFormat::OpenAI,
            api_key_header: "Authorization",
            api_key_prefix: "Bearer ",
            path_template: Some("/v6/images/text2img"),
        });
    }

    if IBM_BAM_ALIASES.contains(&alias.as_str()) {
        return Some(ProviderProfile {
            provider_type: ProviderType::Generic,
            format: ProviderFormat::WatsonX,
            api_key_header: "Authorization",
            api_key_prefix: "Bearer ",
            path_template: Some("/v1/generate"),
        });
    }

    None
}

pub(crate) fn infer_provider_from_base_url(base_url: &str) -> Option<&'static str> {
    let lower = base_url.to_ascii_lowercase();
    if lower.contains("api.openai.com") {
        return Some("openai");
    }
    if lower.contains("api.anthropic.com") {
        return Some("anthropic");
    }
    if lower.contains("generativelanguage.googleapis.com")
        || lower.contains("aiplatform.googleapis.com")
    {
        return Some("google");
    }
    if lower.contains("api.mistral.ai") {
        return Some("mistral");
    }
    if lower.contains("api.groq.com") {
        return Some("groq");
    }
    if lower.contains("api.cohere.com") || lower.contains("api.cohere.ai") {
        return Some("cohere");
    }
    if lower.contains("api.deepseek.com") {
        return Some("deepseek");
    }
    if lower.contains("openrouter.ai") {
        return Some("openrouter");
    }
    if lower.contains("api.together.xyz") || lower.contains("api.together.ai") {
        return Some("together");
    }
    if lower.contains("api.fireworks.ai") {
        return Some("fireworks");
    }
    if lower.contains("models.github.ai") || lower.contains("models.inference.ai.azure.com") {
        return Some("openai");
    }
    None
}

pub fn capability_contract_for_provider(provider: &str) -> Option<RuntimeCapabilityContract> {
    let alias = normalized_provider_alias(provider);
    let alias = alias.as_str();

    if matches!(alias, "anthropic" | "anthropic-messages") {
        let mut contract = published_contract(
            &[
                RequestFamily::ChatCompletions,
                RequestFamily::Responses,
                RequestFamily::Messages,
            ],
            &[
                InputModality::Text,
                InputModality::Image,
                InputModality::Pdf,
            ],
            &[OutputModality::Text],
            &[
                InteractionFeature::ToolCalls,
                InteractionFeature::ToolResults,
                InteractionFeature::ExtendedThinking,
                InteractionFeature::InterleavedThinking,
                InteractionFeature::FineGrainedToolStreaming,
            ],
            &[TransportMode::Json, TransportMode::Sse],
            &[],
        );
        contract.routing_policy_features = gateway_routing_policy_features();
        contract.caching_features = gateway_caching_features();
        contract.plugin_features = text_plugin_features();
        contract.beta_headers = vec![
            "interleaved-thinking-2025-05-14".to_string(),
            "fine-grained-tool-streaming-2025-05-14".to_string(),
        ];
        return Some(contract);
    }

    if alias == "aws-bedrock" {
        let mut contract = published_contract(
            &[
                RequestFamily::ChatCompletions,
                RequestFamily::Responses,
                RequestFamily::Messages,
            ],
            &[
                InputModality::Text,
                InputModality::Image,
                InputModality::Pdf,
            ],
            &[OutputModality::Text],
            &[
                InteractionFeature::ToolCalls,
                InteractionFeature::ToolResults,
            ],
            &[TransportMode::Json, TransportMode::Sse],
            &[],
        );
        contract.routing_policy_features = gateway_routing_policy_features();
        contract.caching_features = gateway_caching_features();
        contract.plugin_features = text_plugin_features();
        return Some(contract);
    }

    if alias == "cohere" {
        let mut contract = published_contract(
            &[RequestFamily::ChatCompletions, RequestFamily::Responses],
            &[InputModality::Text],
            &[OutputModality::Text],
            &[
                InteractionFeature::ToolCalls,
                InteractionFeature::ToolResults,
            ],
            &[TransportMode::Json, TransportMode::Sse],
            &[
                ResponseFormatFeature::JsonObject,
                ResponseFormatFeature::JsonSchema,
            ],
        );
        contract.routing_policy_features = gateway_routing_policy_features();
        contract.caching_features = gateway_caching_features();
        contract.plugin_features = text_plugin_features();
        return Some(contract);
    }

    if alias == "watsonx" {
        let mut contract = published_contract(
            &[RequestFamily::ChatCompletions, RequestFamily::Responses],
            &[InputModality::Text],
            &[OutputModality::Text],
            &[
                InteractionFeature::ToolCalls,
                InteractionFeature::ToolResults,
            ],
            &[TransportMode::Json, TransportMode::Sse],
            &[
                ResponseFormatFeature::JsonObject,
                ResponseFormatFeature::JsonSchema,
            ],
        );
        contract.routing_policy_features = gateway_routing_policy_features();
        contract.caching_features = gateway_caching_features();
        contract.plugin_features = text_plugin_features();
        return Some(contract);
    }

    if alias == "voyage" {
        return Some(published_contract(
            &[RequestFamily::Embeddings],
            &[InputModality::Text],
            &[OutputModality::EmbeddingVector],
            &[],
            &[TransportMode::Json],
            &[],
        ));
    }

    if alias == "elevenlabs" || alias == "eleven-labs" {
        return Some(published_contract(
            &[RequestFamily::AudioSpeech],
            &[InputModality::Text],
            &[OutputModality::Audio],
            &[],
            &[TransportMode::BinaryAudio],
            &[],
        ));
    }

    if OPENAI_ALIASES.contains(&alias)
        || CLOUDFLARE_AI_ALIASES.contains(&alias)
        || SNOWFLAKE_ALIASES.contains(&alias)
        || AZURE_ALIASES.contains(&alias)
        || HUGGINGFACE_ALIASES.contains(&alias)
        || REPLICATE_ALIASES.contains(&alias)
        || DATABRICKS_ALIASES.contains(&alias)
        || VERTEX_ALIASES.contains(&alias)
        || GOOGLE_AI_STUDIO_ALIASES.contains(&alias)
        || SAGEMAKER_ALIASES.contains(&alias)
        || CLOUDFLARE_AI_ALIASES.contains(&alias)
        || MODELSLAB_ALIASES.contains(&alias)
        || IBM_BAM_ALIASES.contains(&alias)
    {
        let mut request_families = vec![
            RequestFamily::ChatCompletions,
            RequestFamily::Completions,
            RequestFamily::Messages,
        ];
        if supports_responses_family(alias) {
            request_families.push(RequestFamily::Responses);
        }
        if supports_embeddings_family(alias) {
            request_families.push(RequestFamily::Embeddings);
        }
        if supports_audio_transcriptions_family(alias) {
            request_families.push(RequestFamily::AudioTranscriptions);
        }
        if supports_audio_speech_family(alias) {
            request_families.push(RequestFamily::AudioSpeech);
        }

        let mut input_modalities = vec![InputModality::Text];
        if request_families.contains(&RequestFamily::AudioTranscriptions) {
            input_modalities.push(InputModality::Audio);
        }
        let mut output_modalities = vec![OutputModality::Text];
        if request_families.contains(&RequestFamily::Embeddings) {
            output_modalities.push(OutputModality::EmbeddingVector);
        }
        if request_families.contains(&RequestFamily::AudioSpeech) {
            output_modalities.push(OutputModality::Audio);
        }
        let mut interaction_features = vec![
            InteractionFeature::ToolCalls,
            InteractionFeature::ToolResults,
        ];
        let mut response_format_features = Vec::new();
        if supports_structured_outputs(alias) {
            interaction_features.push(InteractionFeature::ParallelToolCalls);
            interaction_features.push(InteractionFeature::StrictToolUse);
            response_format_features.push(ResponseFormatFeature::JsonObject);
            response_format_features.push(ResponseFormatFeature::JsonSchema);
        }

        let mut transport_modes = vec![TransportMode::Json, TransportMode::Sse];
        if request_families.contains(&RequestFamily::AudioSpeech) {
            transport_modes.push(TransportMode::BinaryAudio);
        }
        if request_families.len() == 1 && request_families.contains(&RequestFamily::Embeddings) {
            transport_modes = vec![TransportMode::Json];
        }

        let mut contract = published_contract(
            &request_families,
            &input_modalities,
            &output_modalities,
            &interaction_features,
            &transport_modes,
            &response_format_features,
        );
        contract.routing_policy_features = gateway_routing_policy_features();
        contract.caching_features = gateway_caching_features();
        contract.plugin_features = text_plugin_features();
        return Some(contract);
    }

    None
}

fn supports_responses_family(alias: &str) -> bool {
    matches!(
        alias,
        "openai"
            | "openai-chat"
            | "openai-responses"
            | "openrouter"
            | "groq"
            | "github"
            | "github-models"
            | "azure"
            | "azure-openai"
    )
}

fn supports_embeddings_family(alias: &str) -> bool {
    matches!(
        alias,
        "openai"
            | "aimlapi"
            | "ai-ml-api"
            | "alibaba"
            | "qwen"
            | "mistral"
            | "togetherai"
            | "together-ai"
            | "together"
            | "voyage"
            | "vercel"
            | "vercel-ai"
            | "ollama"
            | "localai"
            | "vllm"
            | "litellm"
            | "litellm-embedding"
            | "openllm"
            | "cloudflare-ai"
            | "snowflake"
            | "sagemaker"
            | "huggingface"
            | "hf"
    )
}

fn supports_audio_transcriptions_family(alias: &str) -> bool {
    matches!(
        alias,
        "openai" | "openai-chat" | "openai-responses" | "openrouter" | "azure" | "azure-openai"
    )
}

fn supports_audio_speech_family(alias: &str) -> bool {
    matches!(
        alias,
        "openai" | "openai-chat" | "openai-responses" | "openrouter" | "azure" | "azure-openai"
    )
}

fn supports_structured_outputs(alias: &str) -> bool {
    matches!(
        alias,
        "openai"
            | "openai-chat"
            | "openai-responses"
            | "openrouter"
            | "groq"
            | "github"
            | "github-models"
            | "azure"
            | "azure-openai"
    )
}

// ── Catalog-backed provider resolution ──────────────────────────────────────

const CATALOG_PRICE_MAX_INTEGER_DIGITS: usize = 14;
const CATALOG_PRICE_MAX_FRACTION_DIGITS: usize = 24;

/// Parse the API catalog's canonical NUMERIC(38,24) wire representation.
///
/// Catalog prices intentionally remain strings in cached snapshots so that an
/// absent price is distinct from an explicit zero and no precision is lost at
/// the control-plane/data-plane boundary.
pub(crate) fn parse_exact_catalog_price(value: &str) -> Result<BigDecimal, String> {
    if value.starts_with('-') {
        return Err("must be non-negative".to_string());
    }

    let (integer, fraction) = value.split_once('.').unwrap_or((value, ""));
    let canonical = !integer.is_empty()
        && integer.bytes().all(|byte| byte.is_ascii_digit())
        && fraction.bytes().all(|byte| byte.is_ascii_digit())
        && (integer == "0" || !integer.starts_with('0'))
        && (!value.contains('.') || (!fraction.is_empty() && !fraction.ends_with('0')))
        && integer.trim_start_matches('0').len().max(1) <= CATALOG_PRICE_MAX_INTEGER_DIGITS
        && fraction.len() <= CATALOG_PRICE_MAX_FRACTION_DIGITS;
    if !canonical {
        return Err("must be a canonical non-negative NUMERIC(38,24) decimal string".to_string());
    }

    let parsed =
        BigDecimal::from_str(value).map_err(|error| format!("is not an exact decimal: {error}"))?;
    if parsed < 0_u8 {
        return Err("must be non-negative".to_string());
    }
    let normalized = parsed.normalized();
    if normalized.to_string() != value {
        return Err("must be a canonical non-negative NUMERIC(38,24) decimal string".to_string());
    }
    Ok(normalized)
}

/// Cached catalog data pulled from the API control plane.
#[derive(Debug, Clone, Default)]
pub struct CatalogSnapshot {
    pub version: i64,
    pub providers: Vec<CatalogProvider>,
    pub models: Vec<CatalogModel>,
    pub synced_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone)]
pub struct CatalogProvider {
    pub id: String,
    pub display_name: String,
    pub provider_type: String,
}

#[derive(Debug, Clone)]
pub struct CatalogModel {
    pub id: String,
    pub provider_id: String,
    pub model_type: String,
    pub context_window: Option<i32>,
    pub max_output_tokens: Option<i32>,
    pub supported_features: Vec<String>,
    pub input_token_price: Option<String>,
    pub output_token_price: Option<String>,
    pub cached_input_read_price: Option<String>,
    pub parameter_overrides: serde_json::Map<String, serde_json::Value>,
    pub removed_params: Vec<String>,
}

/// Pricing snapshot resolved from the catalog for a specific model.
#[derive(Debug, Clone)]
pub struct CatalogModelPricing {
    pub input_token_price: Option<String>,
    pub output_token_price: Option<String>,
    pub cached_input_read_price: Option<String>,
}

/// Result of validating whether a model supports the requested features.
#[derive(Debug)]
pub enum FeatureValidation {
    Supported,
    Unsupported(Vec<String>),
    ModelNotInCatalog,
}

/// Resolves provider and model metadata from the cached catalog, with fallback
/// to hardcoded profiles when the catalog is unavailable.
#[derive(Clone)]
pub struct CatalogBackedProviderResolver {
    catalog: Arc<RwLock<CatalogSnapshot>>,
}

impl Default for CatalogBackedProviderResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl CatalogBackedProviderResolver {
    pub fn new() -> Self {
        Self {
            catalog: Arc::new(RwLock::new(CatalogSnapshot::default())),
        }
    }

    fn catalog_ref(&self) -> Arc<RwLock<CatalogSnapshot>> {
        self.catalog.clone()
    }

    /// Return the latest cached snapshot without waiting for the async lock.
    pub fn cached_snapshot(&self) -> CatalogSnapshot {
        self.catalog
            .try_read()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// Update the cached catalog snapshot from API response data.
    pub async fn update_snapshot(&self, snapshot: CatalogSnapshot) {
        let mut guard = self.catalog.write().await;
        let version = snapshot.version;
        let model_count = snapshot.models.len();
        let provider_count = snapshot.providers.len();
        *guard = snapshot;
        tracing::info!(
            catalog_version = version,
            model_count,
            provider_count,
            "catalog snapshot updated from API"
        );
    }

    /// Get pricing for a specific model from the cached catalog.
    async fn get_pricing(&self, provider_id: &str, model_id: &str) -> Option<CatalogModelPricing> {
        let guard = self.catalog.read().await;
        guard
            .models
            .iter()
            .find(|m| m.id == model_id && m.provider_id == provider_id)
            .map(|m| CatalogModelPricing {
                input_token_price: m.input_token_price.clone(),
                output_token_price: m.output_token_price.clone(),
                cached_input_read_price: m.cached_input_read_price.clone(),
            })
    }

    /// Check if a model supports the requested features.
    async fn validate_features(
        &self,
        provider_id: &str,
        model_id: &str,
        features: &[&str],
    ) -> FeatureValidation {
        let guard = self.catalog.read().await;
        match guard
            .models
            .iter()
            .find(|m| m.id == model_id && m.provider_id == provider_id)
        {
            Some(model) => {
                let unsupported: Vec<String> = features
                    .iter()
                    .filter(|f| !model.supported_features.contains(&f.to_string()))
                    .map(|f| f.to_string())
                    .collect();
                if unsupported.is_empty() {
                    FeatureValidation::Supported
                } else {
                    FeatureValidation::Unsupported(unsupported)
                }
            }
            None => FeatureValidation::ModelNotInCatalog,
        }
    }

    /// Get the current catalog version.
    pub async fn catalog_version(&self) -> i64 {
        self.catalog.read().await.version
    }

    /// Returns `true` when the catalog has been populated at least once.
    async fn is_populated(&self) -> bool {
        self.catalog.read().await.synced_at.is_some()
    }

    /// Resolve a `ProviderProfile` from the catalog, falling back to the
    /// hardcoded profile when the model is not present in the catalog.
    async fn resolve_profile(&self, provider: &str) -> Option<ProviderProfile> {
        let guard = self.catalog.read().await;
        let alias = normalized_provider_alias(provider);
        if guard.synced_at.is_some()
            && guard
                .providers
                .iter()
                .any(|p| normalized_provider_alias(&p.id) == alias)
        {
            drop(guard);
            return profile_for_provider(provider);
        }
        drop(guard);
        profile_for_provider(provider)
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
    use chrono::{TimeZone, Utc};

    fn synced_at() -> chrono::DateTime<chrono::Utc> {
        Utc.with_ymd_and_hms(2026, 6, 5, 0, 0, 0)
            .single()
            .expect("valid synced_at timestamp")
    }

    fn sample_snapshot() -> CatalogSnapshot {
        CatalogSnapshot {
            version: 7,
            providers: vec![CatalogProvider {
                id: "azure-openai".to_string(),
                display_name: "Azure OpenAI".to_string(),
                provider_type: "azure-openai".to_string(),
            }],
            models: vec![CatalogModel {
                id: "gpt-4o".to_string(),
                provider_id: "azure-openai".to_string(),
                model_type: "chat".to_string(),
                context_window: Some(128_000),
                max_output_tokens: Some(16_384),
                supported_features: vec!["tool_calls".to_string(), "json_schema".to_string()],
                input_token_price: Some("1".to_string()),
                output_token_price: Some("2".to_string()),
                cached_input_read_price: Some("0.5".to_string()),
                parameter_overrides: serde_json::Map::new(),
                removed_params: vec!["temperature".to_string()],
            }],
            synced_at: Some(synced_at()),
        }
    }

    #[test]
    fn exact_catalog_price_parser_preserves_precision_and_rejects_invalid_values() {
        let exact = "0.00007499999999999999";
        assert_eq!(
            parse_exact_catalog_price(exact)
                .expect("exact catalog price")
                .to_string(),
            exact
        );
        assert_eq!(
            parse_exact_catalog_price("0")
                .expect("explicit zero")
                .to_string(),
            "0"
        );

        for invalid in ["-0.1", "0.0000700", "01", "1e-6", "not-a-price"] {
            assert!(
                parse_exact_catalog_price(invalid).is_err(),
                "{invalid} must be rejected"
            );
        }
    }

    fn assert_profile(
        profile: ProviderProfile,
        provider_type: ProviderType,
        format: ProviderFormat,
        api_key_header: &'static str,
        api_key_prefix: &'static str,
        path_template: Option<&'static str>,
    ) {
        assert_eq!(profile.provider_type, provider_type);
        assert_eq!(profile.format, format);
        assert_eq!(profile.api_key_header, api_key_header);
        assert_eq!(profile.api_key_prefix, api_key_prefix);
        assert_eq!(profile.path_template, path_template);
    }

    #[test]
    fn supported_provider_aliases_are_sorted_and_deduplicated() {
        let aliases = supported_provider_aliases();

        assert!(aliases.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(aliases.contains(&"openai"));
        assert!(aliases.contains(&"azure-openai"));
        assert!(aliases.contains(&"elevenlabs"));
    }

    #[test]
    fn normalized_provider_alias_strips_suffixes_and_normalizes_separators() {
        assert_eq!(
            normalized_provider_alias(" Azure_OpenAI : deployment "),
            "azure-openai"
        );
        assert_eq!(
            normalized_provider_alias("Google AI Studio"),
            "google-ai-studio"
        );
    }

    #[test]
    fn provider_status_page_url_maps_known_status_domains_and_falls_back() {
        assert_eq!(
            provider_status_page_url("openai-responses:primary"),
            "status.openai.com"
        );
        assert_eq!(provider_status_page_url("azure_openai"), "status.azure.com");
        assert_eq!(
            provider_status_page_url("vertex-ai"),
            "status.cloud.google.com"
        );
        assert_eq!(
            provider_status_page_url("aws-bedrock"),
            "health.aws.amazon.com"
        );
        assert_eq!(
            provider_status_page_url("unknown-provider"),
            "the provider's status page"
        );
    }

    #[test]
    fn provider_path_template_for_public_path_resolves_special_and_shared_routes() {
        assert_eq!(
            provider_path_template_for_public_path("openrouter", "/v1/chat/completions"),
            Some("/api/v1/chat/completions")
        );
        assert_eq!(
            provider_path_template_for_public_path("quiverai", "/v1/chat/completions"),
            Some("/svgs/generations")
        );
        assert_eq!(
            provider_path_template_for_public_path("voyage", "/v1/embeddings"),
            Some("/v1/embeddings")
        );
        assert_eq!(
            provider_path_template_for_public_path("Azure OpenAI", "/v1/audio/speech"),
            Some("/v1/audio/speech")
        );
        assert_eq!(
            provider_path_template_for_public_path("elevenlabs", "/v1/audio/speech"),
            Some("/v1/text-to-speech")
        );
        assert_eq!(
            provider_path_template_for_public_path("openrouter", "/v1/unknown"),
            None
        );
    }

    #[test]
    fn profile_for_provider_returns_expected_profiles() {
        let quiverai = profile_for_provider("quiverai").expect("quiverai profile");
        assert_profile(
            quiverai,
            ProviderType::Generic,
            ProviderFormat::OpenAI,
            "Authorization",
            "Bearer ",
            Some("/svgs/generations"),
        );

        let azure = profile_for_provider(" Azure_OpenAI : deployment ").expect("azure profile");
        assert_profile(
            azure,
            ProviderType::AzureOpenAI,
            ProviderFormat::OpenAI,
            "api-key",
            "",
            None,
        );

        let ibm_bam = profile_for_provider("ibm-bam").expect("ibm bam profile");
        assert_profile(
            ibm_bam,
            ProviderType::Generic,
            ProviderFormat::WatsonX,
            "Authorization",
            "Bearer ",
            Some("/v1/generate"),
        );

        assert!(profile_for_provider("not-a-provider").is_none());
    }

    #[test]
    fn infer_provider_from_base_url_maps_known_hosts() {
        assert_eq!(
            infer_provider_from_base_url("https://api.openai.com/v1/chat/completions"),
            Some("openai")
        );
        assert_eq!(
            infer_provider_from_base_url("https://generativelanguage.googleapis.com/v1beta/models"),
            Some("google")
        );
        assert_eq!(
            infer_provider_from_base_url("https://models.github.ai/inference"),
            Some("openai")
        );
        assert_eq!(
            infer_provider_from_base_url("https://example.invalid/provider"),
            None
        );
    }

    #[test]
    fn capability_contract_for_provider_builds_anthropic_contract() {
        let contract =
            capability_contract_for_provider("anthropic-messages").expect("anthropic contract");

        assert_eq!(
            contract.request_families,
            vec![
                RequestFamily::ChatCompletions,
                RequestFamily::Responses,
                RequestFamily::Messages,
            ]
        );
        assert_eq!(
            contract.input_modalities,
            vec![
                InputModality::Text,
                InputModality::Image,
                InputModality::Pdf,
            ]
        );
        assert_eq!(contract.output_modalities, vec![OutputModality::Text]);
        assert!(contract
            .interaction_features
            .contains(&InteractionFeature::ExtendedThinking));
        assert!(contract
            .interaction_features
            .contains(&InteractionFeature::InterleavedThinking));
        assert!(contract
            .interaction_features
            .contains(&InteractionFeature::FineGrainedToolStreaming));
        assert_eq!(
            contract.transport_modes,
            vec![TransportMode::Json, TransportMode::Sse]
        );
        assert_eq!(
            contract.beta_headers,
            vec![
                "interleaved-thinking-2025-05-14".to_string(),
                "fine-grained-tool-streaming-2025-05-14".to_string(),
            ]
        );
        assert_eq!(
            contract.routing_policy_features,
            gateway_routing_policy_features()
        );
        assert_eq!(contract.caching_features, gateway_caching_features());
        assert_eq!(contract.plugin_features, text_plugin_features());
    }

    #[test]
    fn capability_contract_for_provider_builds_openai_family_contract() {
        let contract = capability_contract_for_provider("openai").expect("openai contract");

        assert!(contract
            .request_families
            .contains(&RequestFamily::ChatCompletions));
        assert!(contract.request_families.contains(&RequestFamily::Messages));
        assert!(contract
            .request_families
            .contains(&RequestFamily::Responses));
        assert!(contract
            .request_families
            .contains(&RequestFamily::Embeddings));
        assert!(contract
            .request_families
            .contains(&RequestFamily::AudioTranscriptions));
        assert!(contract
            .request_families
            .contains(&RequestFamily::AudioSpeech));
        assert!(contract.input_modalities.contains(&InputModality::Text));
        assert!(contract.input_modalities.contains(&InputModality::Audio));
        assert!(contract.output_modalities.contains(&OutputModality::Text));
        assert!(contract
            .output_modalities
            .contains(&OutputModality::EmbeddingVector));
        assert!(contract.output_modalities.contains(&OutputModality::Audio));
        assert!(contract
            .interaction_features
            .contains(&InteractionFeature::ParallelToolCalls));
        assert!(contract
            .interaction_features
            .contains(&InteractionFeature::StrictToolUse));
        assert!(contract
            .transport_modes
            .contains(&TransportMode::BinaryAudio));
        assert!(contract
            .response_format_features
            .contains(&ResponseFormatFeature::JsonObject));
        assert!(contract
            .response_format_features
            .contains(&ResponseFormatFeature::JsonSchema));
        assert!(contract.beta_headers.is_empty());
    }

    #[test]
    fn capability_contract_for_provider_handles_special_cases_and_unknowns() {
        let voyage = capability_contract_for_provider("voyage").expect("voyage contract");
        assert_eq!(voyage.request_families, vec![RequestFamily::Embeddings]);
        assert_eq!(voyage.input_modalities, vec![InputModality::Text]);
        assert_eq!(
            voyage.output_modalities,
            vec![OutputModality::EmbeddingVector]
        );
        assert_eq!(voyage.transport_modes, vec![TransportMode::Json]);

        let elevenlabs =
            capability_contract_for_provider("elevenlabs").expect("elevenlabs contract");
        assert_eq!(
            elevenlabs.request_families,
            vec![RequestFamily::AudioSpeech]
        );
        assert_eq!(elevenlabs.input_modalities, vec![InputModality::Text]);
        assert_eq!(elevenlabs.output_modalities, vec![OutputModality::Audio]);
        assert_eq!(elevenlabs.transport_modes, vec![TransportMode::BinaryAudio]);

        assert!(capability_contract_for_provider("not-a-provider").is_none());
    }

    #[tokio::test]
    async fn cached_snapshot_returns_default_while_write_locked() {
        let resolver = CatalogBackedProviderResolver::new();
        let catalog = resolver.catalog_ref();
        let _guard = catalog.write().await;

        let snapshot = resolver.cached_snapshot();
        assert_eq!(snapshot.version, 0);
        assert!(snapshot.providers.is_empty());
        assert!(snapshot.models.is_empty());
        assert!(snapshot.synced_at.is_none());
    }

    #[tokio::test]
    async fn catalog_backed_resolver_resolves_pricing_versions_and_profiles() {
        let resolver = CatalogBackedProviderResolver::new();

        assert_eq!(resolver.catalog_version().await, 0);
        assert!(!resolver.is_populated().await);

        let fallback_profile = resolver
            .resolve_profile("openai")
            .await
            .expect("fallback openai profile");
        assert_eq!(fallback_profile.provider_type, ProviderType::OpenAI);

        resolver.update_snapshot(sample_snapshot()).await;

        assert_eq!(resolver.catalog_version().await, 7);
        assert!(resolver.is_populated().await);
        assert_eq!(resolver.cached_snapshot().version, 7);

        let pricing = resolver
            .get_pricing("azure-openai", "gpt-4o")
            .await
            .expect("catalog pricing");
        assert_eq!(pricing.input_token_price.as_deref(), Some("1"));
        assert_eq!(pricing.output_token_price.as_deref(), Some("2"));
        assert_eq!(pricing.cached_input_read_price.as_deref(), Some("0.5"));
        assert!(resolver
            .get_pricing("azure-openai", "missing-model")
            .await
            .is_none());

        let synced_match = resolver
            .resolve_profile(" Azure_OpenAI : deployment ")
            .await
            .expect("synced azure profile");
        assert_eq!(synced_match.provider_type, ProviderType::AzureOpenAI);

        let synced_fallback = resolver
            .resolve_profile("openai")
            .await
            .expect("synced fallback openai profile");
        assert_eq!(synced_fallback.provider_type, ProviderType::OpenAI);
    }

    #[tokio::test]
    async fn validate_features_reports_supported_unsupported_and_missing_models() {
        let resolver = CatalogBackedProviderResolver::new();
        resolver.update_snapshot(sample_snapshot()).await;

        match resolver
            .validate_features("azure-openai", "gpt-4o", &["tool_calls", "json_schema"])
            .await
        {
            FeatureValidation::Supported => {}
            other => panic!("expected supported features, got {other:?}"),
        }

        match resolver
            .validate_features("azure-openai", "gpt-4o", &["tool_calls", "audio"])
            .await
        {
            FeatureValidation::Unsupported(features) => {
                assert_eq!(features, vec!["audio".to_string()]);
            }
            other => panic!("expected unsupported features, got {other:?}"),
        }

        match resolver
            .validate_features("azure-openai", "missing-model", &["tool_calls"])
            .await
        {
            FeatureValidation::ModelNotInCatalog => {}
            other => panic!("expected missing catalog model, got {other:?}"),
        }
    }

    #[test]
    fn is_unavailable_provider_allows_dispatchable_adapters() {
        assert!(!is_unavailable_provider("anthropic"));
        assert!(!is_unavailable_provider("claude"));
        assert!(!is_unavailable_provider("claude-code"));
        assert!(!is_unavailable_provider("aws-bedrock"));
        assert!(!is_unavailable_provider("bedrock"));
        assert!(!is_unavailable_provider("cohere"));
        assert!(!is_unavailable_provider("cohere-chat"));
        assert!(!is_unavailable_provider("watsonx"));
        assert!(!is_unavailable_provider("ibm-watsonx"));
    }

    #[test]
    fn is_unavailable_provider_allows_supported_providers() {
        assert!(!is_unavailable_provider("openai"));
        assert!(!is_unavailable_provider("azure-openai"));
        assert!(!is_unavailable_provider("google-ai-studio"));
        assert!(!is_unavailable_provider("groq"));
        assert!(!is_unavailable_provider("deepseek"));
        assert!(!is_unavailable_provider("ollama"));
    }

    #[test]
    fn unavailable_provider_message_includes_provider_name() {
        let msg = unavailable_provider_message("anthropic");
        assert!(msg.contains("anthropic"));
        assert!(msg.contains("not available"));
    }
}
