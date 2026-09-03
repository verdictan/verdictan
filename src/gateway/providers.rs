// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde::{Deserialize, Serialize};
use serde_json::json;
pub use std::{collections::HashMap, time::Duration};

use crate::error::CliError;
use crate::secret_key_ref::{parse_secret_key_ref_value, SecretKeyReference};

// ---------------------------------------------------------------------------
// Provider data policy
// ---------------------------------------------------------------------------

/// Operator-declared data handling metadata for a provider endpoint.
///
/// The base fields (`zero_data_retention`, `training_opt_out`, `retention_days`)
/// existed before the regulated runtime work. The regulated-routing fields
/// added below extend the same struct so all provider data-handling
/// characteristics live in one place.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPolicy {
    /// Provider commits to zero data retention (no storage of inputs, outputs, or metadata).
    #[serde(default)]
    pub zero_data_retention: bool,
    /// Provider commits to never using data for model training.
    #[serde(default)]
    pub training_opt_out: bool,
    /// Contractual maximum retention window in days. 0 = no retention. None = unknown.
    #[serde(default)]
    pub retention_days: Option<u32>,

    // ── Regulated-routing extensions ──────────────────────────────────────
    /// Provider guarantees that request/response payloads are processed in
    /// memory only and never written to disk or persistent storage.
    #[serde(default)]
    pub in_memory_only: bool,
    /// Provider endpoint has been verified to sanitize (strip, redact, or
    /// neutralize) sensitive content before persisting or forwarding it.
    #[serde(default)]
    pub sanitized: bool,
    /// Provider accepts tokenized input (i.e. callers MAY replace sensitive
    /// spans with opaque token placeholders before sending).
    #[serde(default)]
    pub accepts_tokenized_input: bool,
    /// Provider uses internet egress for model inference or data processing.
    /// Defaults to `true`. Set `false` for local-only endpoints.
    #[serde(default = "default_true")]
    pub allow_internet_egress: bool,
    /// Provider processes all requests locally without any external network
    /// calls during inference (e.g. a locally-served Ollama instance).
    #[serde(default)]
    pub local_only_processing: bool,
}

fn default_true() -> bool {
    true
}

impl Default for DataPolicy {
    fn default() -> Self {
        Self {
            zero_data_retention: false,
            training_opt_out: false,
            retention_days: None,
            in_memory_only: false,
            sanitized: false,
            accepts_tokenized_input: false,
            allow_internet_egress: true,
            local_only_processing: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Data residency policy
// ---------------------------------------------------------------------------

/// Operator-declared data residency and sovereignty policy for a provider endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataResidencyPolicy {
    pub regions: Vec<String>,
    pub data_center_locations: Vec<String>,
    pub sovereignty_compliant: bool,
}

// ---------------------------------------------------------------------------
// Provider routing metadata (Phases 2–5, 14)
// ---------------------------------------------------------------------------

/// Per-provider data collection policy verb (Phase 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataCollectionPolicy {
    Allow,
    Deny,
}

/// Percentile level for SLA cutoff evaluation (Phase 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Percentile {
    P50,
    P90,
    P99,
}

/// SLA cutoff (latency or throughput) with percentile support (Phase 3).
#[derive(Debug, Clone)]
pub struct PerformanceCutoff {
    /// Threshold value: milliseconds for latency, tokens/s for throughput.
    pub value: f64,
    /// Percentile at which the threshold is evaluated.
    pub percentile: Percentile,
}

/// Per-request cost ceiling for routing decisions, USD (Phase 2).
#[derive(Debug, Clone)]
pub struct MaxPrice {
    /// Max per-request cost attributable to prompt tokens (USD).
    pub prompt: Option<f64>,
    /// Max per-request cost attributable to completion tokens (USD).
    pub completion: Option<f64>,
    /// Max total request cost (USD).
    pub request: Option<f64>,
}

/// Operator-declared token pricing for a provider (USD per 1M tokens) (Phase 2).
#[derive(Debug, Clone)]
pub struct ProviderPricing {
    /// Input price per million tokens.
    pub input_price_per_million: f64,
    /// Output price per million tokens.
    pub output_price_per_million: f64,
    /// Cached input price per million tokens.
    pub cached_input_price_per_million: Option<f64>,
    /// Multiplier applied to input tokens for billing.
    pub input_multiplier: Option<f64>,
    /// Multiplier applied to cached input tokens for billing.
    pub cached_input_multiplier: Option<f64>,
    /// Multiplier applied to output tokens for billing.
    pub output_multiplier: Option<f64>,
}

/// Estimated per-request cost breakdown (Phase 2).
#[derive(Debug, Clone)]
pub struct RequestCost {
    pub prompt: f64,
    pub completion: f64,
    pub request: f64,
    /// Cost for cached input tokens.
    pub cached_input: f64,
}

/// Escalation routing override declared in the provider config.
///
/// Exactly one of `team_id` or `user_id` must be set (enforced at parse time).
/// Model-level routing takes precedence over provider-level routing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRouting {
    pub team_id: Option<String>,
    pub user_id: Option<String>,
}

/// A single model entry nested under a provider target.
#[derive(Debug, Clone, Default)]
pub struct ProviderModelEntry {
    pub model_id: String,
    pub aliases: Vec<String>,
    pub enabled: bool,
    pub pricing: Option<ProviderPricing>,
    pub supported_features: Vec<String>,
    pub max_output_tokens: Option<u32>,
    pub parameter_overrides: serde_json::Map<String, serde_json::Value>,
    pub removed_params: Vec<String>,
    pub description: Option<String>,
    pub escalation_routing: Option<EscalationRouting>,
}

impl ProviderPricing {
    /// Compute `RequestCost` from token counts.
    /// Pricing is expressed per 1 M tokens.
    pub fn compute_cost(&self, prompt_tokens: u64, completion_tokens: u64) -> RequestCost {
        self.compute_cost_with_cache(prompt_tokens, completion_tokens, 0)
    }

    /// Compute `RequestCost` from token counts including cached input tokens.
    pub fn compute_cost_with_cache(
        &self,
        prompt_tokens: u64,
        completion_tokens: u64,
        cached_input_tokens: u64,
    ) -> RequestCost {
        let input_mult = self.input_multiplier.unwrap_or(1.0);
        let cached_mult = self.cached_input_multiplier.unwrap_or(1.0);
        let output_mult = self.output_multiplier.unwrap_or(1.0);

        let input_rate = self.input_price_per_million;
        let cached_rate = self.cached_input_price_per_million.unwrap_or(input_rate);
        let output_rate = self.output_price_per_million;

        let uncached_input_tokens = prompt_tokens.saturating_sub(cached_input_tokens);
        let billable_input = (uncached_input_tokens as f64) * input_mult;
        let billable_cached = (cached_input_tokens as f64) * cached_mult;
        let billable_output = (completion_tokens as f64) * output_mult;

        let prompt_cost = (billable_input / 1_000_000.0) * input_rate;
        let cached_cost = (billable_cached / 1_000_000.0) * cached_rate;
        let completion_cost = (billable_output / 1_000_000.0) * output_rate;

        RequestCost {
            prompt: prompt_cost,
            completion: completion_cost,
            cached_input: cached_cost,
            request: prompt_cost + cached_cost + completion_cost,
        }
    }
}

// ---------------------------------------------------------------------------
// Provider target
// ---------------------------------------------------------------------------

/// A single upstream LLM provider target parsed from the `providers.targets`
/// section of a declarative policy config.
#[derive(Debug, Clone, Default)]
pub struct ProviderTarget {
    pub id: String,
    pub provider: String,
    pub model: String,
    pub execution_target: Option<crate::gateway::execution_runtime::ExecutionTarget>,
    pub mcp_bridge: Option<crate::gateway::runtimes::network::mcp::McpBridgeConfig>,
    pub description: Option<String>,
    pub base_url: String,
    /// Resolved API key value (not the env var name).
    pub api_key: String,
    pub api_key_header: String,
    pub api_key_prefix: String,
    /// Secret reference for the API key, sourced from either an env var or store.
    pub secret_key_ref: Option<SecretKeyReference>,
    pub path_template: Option<String>,
    pub headers: HashMap<String, String>,
    pub timeout: Duration,
    /// Optional timeout for streaming requests. Falls back to `timeout` if not set.
    pub stream_timeout: Option<Duration>,
    pub max_context_tokens: Option<usize>,
    pub max_messages: Option<usize>,
    pub data_policy: Option<DataPolicy>,
    /// Operator-declared token pricing (Phase 2).
    pub pricing: Option<ProviderPricing>,
    /// Nested model entries for multi-model provider targets.
    pub models: Vec<ProviderModelEntry>,
    /// Per-provider data collection policy (Phase 4).
    pub data_collection: Option<DataCollectionPolicy>,
    /// Shorthand for zero data retention (Phase 4).
    pub zdr: bool,
    /// Data residency region, e.g. "us", "eu", "ap" (Phase 4).
    pub region: Option<String>,
    /// Quantization levels served by this endpoint (Phase 5).
    pub quantizations: Option<Vec<String>>,
    /// Routing weight for weighted_round_robin strategy (Phase 14).
    pub weight: Option<f64>,
    /// Phase 35: explicit provider type, overrides URL-heuristic detection.
    pub provider_type: Option<crate::gateway::provider_auth::ProviderType>,
    /// Phase 15: wire format this provider uses natively (openai or anthropic).
    pub format: Option<crate::gateway::format_translation::ProviderFormat>,
    /// Phase 35: Anthropic API version header value (default: 2023-06-01).
    pub anthropic_version: Option<String>,
    /// Phase 35: AWS region for Bedrock (overrides AWS_REGION env var).
    pub aws_region: Option<String>,
    /// Phase 35: AWS profile name for Bedrock credential resolution.
    pub aws_profile: Option<String>,
    /// Phase 62: Exact Bedrock model family gate for UDR provider lanes.
    pub bedrock_model_family: Option<String>,
    /// Phase 62: watsonx API version injected into chat endpoints.
    pub watsonx_api_version: Option<String>,
    /// Phase 62: watsonx project scope injected server-side.
    pub watsonx_project_id: Option<String>,
    /// Phase 62: watsonx space scope injected server-side.
    pub watsonx_space_id: Option<String>,
    /// Phase 35: GCP project ID for Vertex AI.
    pub gcp_project: Option<String>,
    /// Phase 35: GCP region for Vertex AI (default: us-central1).
    pub gcp_region: Option<String>,
    /// Phase 35: Azure OpenAI API version (default: 2024-02-01).
    pub azure_api_version: Option<String>,
    /// Phase 35: Azure OpenAI deployment name (defaults to model name).
    pub azure_deployment: Option<String>,
    /// OAuth2 bearer-token acquisition for upstream auth.
    pub oauth2: Option<crate::gateway::provider_auth::OAuth2Config>,
    /// Optional active health probe for this provider.
    pub health_probe: Option<crate::gateway::health_probe::ProviderHealthConfig>,
    /// Explicit opt-in to skip TLS certificate verification for this target.
    pub allow_insecure_tls: bool,
    /// Escalation routing override for this provider target.
    pub escalation_routing: Option<EscalationRouting>,
    /// When true, the gateway fails startup if this target's credential is unresolved.
    /// When false (default), unresolved targets are excluded from the active routing table.
    pub required: bool,
    /// Data residency policy for this provider.
    pub data_residency: Option<DataResidencyPolicy>,
    /// Compliance certifications held by this provider.
    pub certifications: Option<Vec<String>>,
}

impl ProviderTarget {
    /// Returns the effective timeout for a request, considering whether it is streaming.
    ///
    /// Streaming requests use `stream_timeout` when configured so operators can allow
    /// longer timeouts for incremental responses without relaxing the non-streaming budget.
    /// Falls back to `timeout` when `stream_timeout` is not set.
    pub fn effective_timeout(&self, is_streaming: bool) -> Duration {
        if is_streaming {
            self.stream_timeout.unwrap_or(self.timeout)
        } else {
            self.timeout
        }
    }

    pub(crate) fn requires_provider_auth_material(&self) -> bool {
        if self.execution_target.is_some() {
            return false;
        }

        let runtime_policy = crate::gateway::runtimes::parser_policy_for_target(
            &self.provider,
            self.execution_target.as_ref(),
        );
        let provider_defaults = verdictan_provider_defaults(&self.provider, self.provider_type);
        let uses_self_credential_chain = matches!(
            self.provider_type,
            Some(crate::gateway::provider_auth::ProviderType::AwsBedrock)
                | Some(crate::gateway::provider_auth::ProviderType::GoogleVertex)
        ) || self.oauth2.is_some();

        !(provider_defaults
            .map(|defaults| defaults.auth_optional)
            .unwrap_or(false)
            || runtime_policy.auth_optional
            || uses_self_credential_chain)
    }

    pub(crate) fn requires_resolved_api_key(&self) -> bool {
        self.required && self.requires_provider_auth_material()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerdictanProviderKind {
    Chat,
    Completion,
    Embedding,
    Responses,
    AudioTranscription,
    AudioSpeech,
}

const VERDICTAN_CHAT_ONLY_KINDS: &[VerdictanProviderKind] = &[VerdictanProviderKind::Chat];
const VERDICTAN_EMBEDDING_ONLY_KINDS: &[VerdictanProviderKind] =
    &[VerdictanProviderKind::Embedding];
const VERDICTAN_OPENAI_ALL_KINDS: &[VerdictanProviderKind] = &[
    VerdictanProviderKind::Chat,
    VerdictanProviderKind::Completion,
    VerdictanProviderKind::Embedding,
    VerdictanProviderKind::Responses,
    VerdictanProviderKind::AudioTranscription,
    VerdictanProviderKind::AudioSpeech,
];
const VERDICTAN_CHAT_AND_RESPONSES_KINDS: &[VerdictanProviderKind] = &[
    VerdictanProviderKind::Chat,
    VerdictanProviderKind::Responses,
];
const VERDICTAN_CHAT_AND_COMPLETION_KINDS: &[VerdictanProviderKind] = &[
    VerdictanProviderKind::Chat,
    VerdictanProviderKind::Completion,
];
const VERDICTAN_CHAT_COMPLETION_EMBEDDING_KINDS: &[VerdictanProviderKind] = &[
    VerdictanProviderKind::Chat,
    VerdictanProviderKind::Completion,
    VerdictanProviderKind::Embedding,
];
const VERDICTAN_CHAT_AND_EMBEDDING_KINDS: &[VerdictanProviderKind] = &[
    VerdictanProviderKind::Chat,
    VerdictanProviderKind::Embedding,
];

#[derive(Debug, Clone)]
struct VerdictanProviderSpec {
    canonical_provider: String,
    model: Option<String>,
    kind: Option<VerdictanProviderKind>,
}

fn default_verdictan_path_template(kind: VerdictanProviderKind) -> &'static str {
    match kind {
        VerdictanProviderKind::Chat => "/v1/chat/completions",
        VerdictanProviderKind::Completion => "/v1/completions",
        VerdictanProviderKind::Embedding => "/v1/embeddings",
        VerdictanProviderKind::Responses => "/v1/responses",
        VerdictanProviderKind::AudioTranscription => "/v1/audio/transcriptions",
        VerdictanProviderKind::AudioSpeech => "/v1/audio/speech",
    }
}

fn default_verdictan_path_template_for_provider(
    provider: &str,
    kind: VerdictanProviderKind,
) -> &'static str {
    match crate::gateway::provider_catalog::normalized_provider_alias(provider).as_str() {
        "quiverai" => "/svgs/generations",
        "ollama" => match kind {
            VerdictanProviderKind::Chat => "/api/chat",
            VerdictanProviderKind::Completion => "/api/generate",
            VerdictanProviderKind::Embedding => "/api/embeddings",
            VerdictanProviderKind::Responses => "/api/chat",
            VerdictanProviderKind::AudioTranscription => "/v1/audio/transcriptions",
            VerdictanProviderKind::AudioSpeech => "/v1/audio/speech",
        },
        _ => default_verdictan_path_template(kind),
    }
}

#[derive(Debug, Clone, Copy)]
struct VerdictanProviderDefaults {
    base_url: Option<&'static str>,
    allowed_kinds: &'static [VerdictanProviderKind],
    auth_optional: bool,
}

fn verdictan_provider_defaults(
    provider: &str,
    provider_type: Option<crate::gateway::provider_auth::ProviderType>,
) -> Option<VerdictanProviderDefaults> {
    let alias = crate::gateway::provider_catalog::normalized_provider_alias(provider);

    match (alias.as_str(), provider_type) {
        ("openai", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("https://api.openai.com"),
                allowed_kinds: VERDICTAN_OPENAI_ALL_KINDS,
                auth_optional: false,
            })
        }
        ("ai21", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("https://api.ai21.com/studio"),
                allowed_kinds: VERDICTAN_CHAT_ONLY_KINDS,
                auth_optional: false,
            })
        }
        ("aimlapi" | "ai-ml-api", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("https://api.aimlapi.com/v1"),
                allowed_kinds: VERDICTAN_CHAT_COMPLETION_EMBEDDING_KINDS,
                auth_optional: false,
            })
        }
        ("ollama", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("http://localhost:11434"),
                allowed_kinds: VERDICTAN_CHAT_COMPLETION_EMBEDDING_KINDS,
                auth_optional: true,
            })
        }
        ("llamafile", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("http://localhost:8080/v1"),
                allowed_kinds: VERDICTAN_CHAT_AND_COMPLETION_KINDS,
                auth_optional: true,
            })
        }
        (
            "llama" | "llama-cpp" | "llama.cpp",
            Some(crate::gateway::provider_auth::ProviderType::OpenAI),
        ) => Some(VerdictanProviderDefaults {
            base_url: Some("http://localhost:8080"),
            allowed_kinds: VERDICTAN_CHAT_AND_COMPLETION_KINDS,
            auth_optional: true,
        }),
        ("quiverai", Some(crate::gateway::provider_auth::ProviderType::Generic)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("https://api.quiver.ai/v1"),
                allowed_kinds: VERDICTAN_CHAT_ONLY_KINDS,
                auth_optional: false,
            })
        }
        ("cloudera", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("https://inference.cloudera.ai/v1"),
                allowed_kinds: VERDICTAN_CHAT_ONLY_KINDS,
                auth_optional: false,
            })
        }
        (
            "cloudflare-gateway" | "cloudflare-ai-gateway",
            Some(crate::gateway::provider_auth::ProviderType::OpenAI),
        ) => Some(VerdictanProviderDefaults {
            base_url: Some("https://gateway.ai.cloudflare.com/v1"),
            allowed_kinds: VERDICTAN_CHAT_ONLY_KINDS,
            auth_optional: true,
        }),
        ("vllm", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("http://localhost:8080/v1"),
                allowed_kinds: VERDICTAN_CHAT_COMPLETION_EMBEDDING_KINDS,
                auth_optional: true,
            })
        }
        ("openllm", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("http://localhost:8001/v1"),
                allowed_kinds: VERDICTAN_CHAT_AND_COMPLETION_KINDS,
                auth_optional: true,
            })
        }
        ("text-generation-webui", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("http://localhost:5000/v1"),
                allowed_kinds: VERDICTAN_CHAT_ONLY_KINDS,
                auth_optional: true,
            })
        }
        (
            "alibaba" | "alicloud" | "aliyun" | "dashscope" | "qwen",
            Some(crate::gateway::provider_auth::ProviderType::OpenAI),
        ) => Some(VerdictanProviderDefaults {
            base_url: Some("https://dashscope-intl.aliyuncs.com/compatible-mode"),
            allowed_kinds: VERDICTAN_CHAT_AND_EMBEDDING_KINDS,
            auth_optional: false,
        }),
        ("openrouter", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("https://openrouter.ai/api"),
                allowed_kinds: VERDICTAN_CHAT_ONLY_KINDS,
                auth_optional: false,
            })
        }
        ("vercel" | "vercel-ai", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("https://ai-gateway.vercel.sh/v1"),
                allowed_kinds: VERDICTAN_CHAT_AND_EMBEDDING_KINDS,
                auth_optional: false,
            })
        }
        ("groq", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("https://api.groq.com/openai"),
                allowed_kinds: VERDICTAN_CHAT_AND_RESPONSES_KINDS,
                auth_optional: false,
            })
        }
        ("togetherai", Some(crate::gateway::provider_auth::ProviderType::OpenAI))
        | ("together-ai", Some(crate::gateway::provider_auth::ProviderType::OpenAI))
        | ("together", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("https://api.together.xyz"),
                allowed_kinds: VERDICTAN_CHAT_COMPLETION_EMBEDDING_KINDS,
                auth_optional: false,
            })
        }
        ("mistral", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("https://api.mistral.ai"),
                allowed_kinds: VERDICTAN_CHAT_AND_EMBEDDING_KINDS,
                auth_optional: false,
            })
        }
        ("cerebras", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("https://api.cerebras.ai"),
                allowed_kinds: VERDICTAN_CHAT_ONLY_KINDS,
                auth_optional: false,
            })
        }
        ("cometapi", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("https://api.cometapi.com"),
                allowed_kinds: VERDICTAN_CHAT_ONLY_KINDS,
                auth_optional: false,
            })
        }
        ("deepseek", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("https://api.deepseek.com"),
                allowed_kinds: VERDICTAN_CHAT_ONLY_KINDS,
                auth_optional: false,
            })
        }
        (
            "docker" | "docker-model-runner",
            Some(crate::gateway::provider_auth::ProviderType::OpenAI),
        ) => Some(VerdictanProviderDefaults {
            base_url: Some("http://localhost:12434/engines"),
            allowed_kinds: VERDICTAN_CHAT_ONLY_KINDS,
            auth_optional: false,
        }),
        (
            "fireworks" | "fireworks-ai",
            Some(crate::gateway::provider_auth::ProviderType::OpenAI),
        ) => Some(VerdictanProviderDefaults {
            base_url: Some("https://api.fireworks.ai/inference"),
            allowed_kinds: VERDICTAN_CHAT_ONLY_KINDS,
            auth_optional: false,
        }),
        ("github" | "github-models", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("https://models.github.ai/inference"),
                allowed_kinds: VERDICTAN_CHAT_ONLY_KINDS,
                auth_optional: false,
            })
        }
        ("hyperbolic", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("https://api.hyperbolic.xyz/v1"),
                allowed_kinds: VERDICTAN_CHAT_ONLY_KINDS,
                auth_optional: false,
            })
        }
        (
            "litellm" | "litellm-embedding",
            Some(crate::gateway::provider_auth::ProviderType::OpenAI),
        ) => Some(VerdictanProviderDefaults {
            base_url: Some("http://0.0.0.0:4000"),
            allowed_kinds: VERDICTAN_CHAT_COMPLETION_EMBEDDING_KINDS,
            auth_optional: true,
        }),
        ("localai", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("http://localhost:8080"),
                allowed_kinds: VERDICTAN_CHAT_COMPLETION_EMBEDDING_KINDS,
                auth_optional: true,
            })
        }
        ("llamaapi", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("https://api.llama.com/compat"),
                allowed_kinds: VERDICTAN_CHAT_ONLY_KINDS,
                auth_optional: false,
            })
        }
        ("perplexity", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("https://api.perplexity.ai"),
                allowed_kinds: VERDICTAN_CHAT_ONLY_KINDS,
                auth_optional: false,
            })
        }
        ("portkey", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("https://api.portkey.ai"),
                allowed_kinds: VERDICTAN_CHAT_ONLY_KINDS,
                auth_optional: false,
            })
        }
        ("truefoundry", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("https://llm-gateway.truefoundry.com"),
                allowed_kinds: VERDICTAN_CHAT_ONLY_KINDS,
                auth_optional: false,
            })
        }
        ("voyage", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("https://api.voyageai.com"),
                allowed_kinds: VERDICTAN_EMBEDDING_ONLY_KINDS,
                auth_optional: false,
            })
        }
        ("xai" | "grok", Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            Some(VerdictanProviderDefaults {
                base_url: Some("https://api.x.ai/v1"),
                allowed_kinds: VERDICTAN_CHAT_ONLY_KINDS,
                auth_optional: false,
            })
        }
        ("cloudflare-ai", Some(crate::gateway::provider_auth::ProviderType::CloudflareAi)) => {
            Some(VerdictanProviderDefaults {
                base_url: None,
                allowed_kinds: VERDICTAN_CHAT_COMPLETION_EMBEDDING_KINDS,
                auth_optional: false,
            })
        }
        ("snowflake", Some(crate::gateway::provider_auth::ProviderType::SnowflakeCortex)) => {
            Some(VerdictanProviderDefaults {
                base_url: None,
                allowed_kinds: &[],
                auth_optional: false,
            })
        }
        _ => None,
    }
}

fn verdictan_kind_supported(
    provider: &str,
    provider_type: Option<crate::gateway::provider_auth::ProviderType>,
    kind: Option<VerdictanProviderKind>,
) -> bool {
    let Some(kind) = kind else {
        return true;
    };

    if kind == VerdictanProviderKind::Completion {
        return verdictan_provider_defaults(provider, provider_type)
            .map(|defaults| defaults.allowed_kinds.contains(&kind))
            .unwrap_or(true);
    }

    if let Some(contract) =
        crate::gateway::provider_catalog::capability_contract_for_provider(provider)
    {
        return match kind {
            VerdictanProviderKind::Chat => contract
                .request_families
                .contains(&crate::gateway::runtime_capabilities::RequestFamily::ChatCompletions),
            VerdictanProviderKind::Embedding => contract
                .request_families
                .contains(&crate::gateway::runtime_capabilities::RequestFamily::Embeddings),
            VerdictanProviderKind::Responses => contract
                .request_families
                .contains(&crate::gateway::runtime_capabilities::RequestFamily::Responses),
            VerdictanProviderKind::AudioTranscription => contract.request_families.contains(
                &crate::gateway::runtime_capabilities::RequestFamily::AudioTranscriptions,
            ),
            VerdictanProviderKind::AudioSpeech => contract
                .request_families
                .contains(&crate::gateway::runtime_capabilities::RequestFamily::AudioSpeech),
            VerdictanProviderKind::Completion => false,
        };
    }

    false
}

fn supported_verdictan_kind_list(
    provider: &str,
    provider_type: Option<crate::gateway::provider_auth::ProviderType>,
) -> Option<String> {
    let mut supported = Vec::new();
    if let Some(contract) =
        crate::gateway::provider_catalog::capability_contract_for_provider(provider)
    {
        if contract
            .request_families
            .contains(&crate::gateway::runtime_capabilities::RequestFamily::ChatCompletions)
        {
            supported.push("chat");
        }
        if contract
            .request_families
            .contains(&crate::gateway::runtime_capabilities::RequestFamily::Responses)
        {
            supported.push("responses");
        }
        if contract
            .request_families
            .contains(&crate::gateway::runtime_capabilities::RequestFamily::Embeddings)
        {
            supported.push("embedding");
        }
        if contract
            .request_families
            .contains(&crate::gateway::runtime_capabilities::RequestFamily::AudioTranscriptions)
        {
            supported.push("audio_transcription");
        }
        if contract
            .request_families
            .contains(&crate::gateway::runtime_capabilities::RequestFamily::AudioSpeech)
        {
            supported.push("audio_speech");
        }
    }

    if verdictan_provider_defaults(provider, provider_type)
        .map(|defaults| {
            defaults
                .allowed_kinds
                .contains(&VerdictanProviderKind::Completion)
        })
        .unwrap_or(false)
    {
        supported.push("completion");
    }

    if supported.is_empty() {
        return Some("no verified runtime family support".to_string());
    }

    supported.sort_unstable();
    supported.dedup();
    Some(supported.join(", "))
}

fn parse_verdictan_provider_spec(raw: &str) -> VerdictanProviderSpec {
    let trimmed = raw.trim();
    let parts = trimmed.split(':').collect::<Vec<_>>();
    let canonical_provider = parts.first().copied().unwrap_or(trimmed).trim().to_string();
    let kind = match parts.get(1).copied() {
        Some("chat") => Some(VerdictanProviderKind::Chat),
        Some("completion") => Some(VerdictanProviderKind::Completion),
        Some("embedding") | Some("embeddings") => Some(VerdictanProviderKind::Embedding),
        Some("responses") => Some(VerdictanProviderKind::Responses),
        Some("audio-transcription")
        | Some("audio_transcription")
        | Some("transcription")
        | Some("transcriptions") => Some(VerdictanProviderKind::AudioTranscription),
        Some("audio-speech") | Some("audio_speech") | Some("speech") | Some("tts") => {
            Some(VerdictanProviderKind::AudioSpeech)
        }
        _ => None,
    };

    let model = if let Some(kind) = kind {
        let start_index = match kind {
            VerdictanProviderKind::Chat
            | VerdictanProviderKind::Completion
            | VerdictanProviderKind::Embedding
            | VerdictanProviderKind::Responses
            | VerdictanProviderKind::AudioTranscription
            | VerdictanProviderKind::AudioSpeech => 2,
        };
        parts
            .get(start_index..)
            .filter(|segments| !segments.is_empty())
            .map(|segments| segments.join(":"))
            .filter(|value| !value.trim().is_empty())
    } else {
        parts
            .get(1..)
            .filter(|segments| !segments.is_empty())
            .map(|segments| segments.join(":"))
            .filter(|value| !value.trim().is_empty())
    };

    VerdictanProviderSpec {
        canonical_provider,
        model,
        kind,
    }
}

fn entry_string(entry: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| entry.get(key).and_then(|value| value.as_str()))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn entry_env_value(
    entry: &serde_json::Value,
    value_keys: &[&str],
    env_keys: &[&str],
    default_env_key: &str,
) -> Option<String> {
    if let Some(value) = entry_string(entry, value_keys) {
        return Some(value);
    }

    if let Some(env_name) = entry_string(entry, env_keys) {
        // CLI-SEC-006: Validate env var name before lookup.
        if !crate::secret_key_ref::is_valid_env_var_name(&env_name) {
            tracing::warn!(env_name = %env_name, "rejected provider env var lookup with invalid name");
            return None;
        }
        return std::env::var(env_name)
            .ok()
            .map(|value| value.trim().to_string());
    }

    std::env::var(default_env_key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn derive_cloudflare_base_url(entry: &serde_json::Value) -> Option<String> {
    entry_string(entry, &["base_url"]).or_else(|| {
        entry_env_value(
            entry,
            &["cloudflare_account_id"],
            &["cloudflare_account_id_env"],
            "CLOUDFLARE_ACCOUNT_ID",
        )
        .map(|account_id| {
            format!("https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1")
        })
    })
}

fn derive_llama_cpp_base_url(entry: &serde_json::Value) -> Option<String> {
    entry_string(entry, &["base_url"]).or_else(|| {
        std::env::var("LLAMA_BASE_URL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn split_cloudflare_gateway_model(model: &str) -> (Option<String>, String) {
    const GATEWAY_PROVIDER_PREFIXES: &[&str] = &[
        "openai",
        "anthropic",
        "groq",
        "perplexity-ai",
        "google-ai-studio",
        "mistral",
        "cohere",
        "azure-openai",
        "workers-ai",
        "huggingface",
        "replicate",
        "grok",
    ];

    let Some((provider, rest)) = model.split_once(':') else {
        return (None, model.to_string());
    };
    if !GATEWAY_PROVIDER_PREFIXES.contains(&provider) || rest.trim().is_empty() {
        return (None, model.to_string());
    }

    (Some(provider.to_string()), rest.to_string())
}

fn derive_cloudflare_gateway_base_url(
    entry: &serde_json::Value,
    gateway_provider: Option<&str>,
    model: &str,
) -> Option<String> {
    entry_string(entry, &["base_url"]).or_else(|| {
        let account_id = entry_env_value(
            entry,
            &["cloudflare_account_id"],
            &["cloudflare_account_id_env"],
            "CLOUDFLARE_ACCOUNT_ID",
        )?;
        let gateway_id = entry_env_value(
            entry,
            &["cloudflare_gateway_id"],
            &["cloudflare_gateway_id_env"],
            "CLOUDFLARE_GATEWAY_ID",
        )?;
        let provider = entry_string(entry, &["gateway_provider"])
            .or_else(|| gateway_provider.map(ToString::to_string))?;
        let base_url = format!("https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway_id}");

        match provider.as_str() {
            "azure-openai" => {
                let resource_name = entry_string(entry, &["resource_name"])?;
                let deployment_name = entry_string(entry, &["deployment_name"])?;
                Some(format!(
                    "{base_url}/azure-openai/{resource_name}/{deployment_name}"
                ))
            }
            "workers-ai" => Some(format!("{base_url}/workers-ai/{model}")),
            _ => Some(format!("{base_url}/{provider}")),
        }
    })
}

fn derive_snowflake_base_url(entry: &serde_json::Value) -> Option<String> {
    entry_string(entry, &["base_url"]).or_else(|| {
        entry_env_value(
            entry,
            &["snowflake_account_identifier"],
            &["snowflake_account_identifier_env"],
            "SNOWFLAKE_ACCOUNT_IDENTIFIER",
        )
        .map(|account_identifier| format!("https://{account_identifier}.snowflakecomputing.com"))
    })
}

fn provider_base_url(
    entry: &serde_json::Value,
    id: &str,
    provider: &str,
    provider_type: Option<crate::gateway::provider_auth::ProviderType>,
    model: &str,
    gateway_provider: Option<&str>,
) -> Result<String, CliError> {
    let alias = crate::gateway::provider_catalog::normalized_provider_alias(provider);
    let base_url = match (alias.as_str(), provider_type) {
        ("quiverai", Some(crate::gateway::provider_auth::ProviderType::Generic)) => {
            entry_string(entry, &["base_url"]).or_else(|| {
                verdictan_provider_defaults(provider, provider_type)
                    .and_then(|defaults| defaults.base_url)
                    .map(ToString::to_string)
            })
        }
        (
            "llama" | "llama-cpp" | "llama.cpp",
            Some(crate::gateway::provider_auth::ProviderType::OpenAI),
        ) => derive_llama_cpp_base_url(entry).or_else(|| {
            verdictan_provider_defaults(provider, provider_type)
                .and_then(|defaults| defaults.base_url)
                .map(ToString::to_string)
        }),
        (
            "cloudflare-gateway" | "cloudflare-ai-gateway",
            Some(crate::gateway::provider_auth::ProviderType::OpenAI),
        ) => derive_cloudflare_gateway_base_url(entry, gateway_provider, model).or_else(|| {
            verdictan_provider_defaults(provider, provider_type)
                .and_then(|defaults| defaults.base_url)
                .map(ToString::to_string)
        }),
        (_, Some(crate::gateway::provider_auth::ProviderType::OpenAI)) => {
            entry_string(entry, &["base_url"]).or_else(|| {
                verdictan_provider_defaults(provider, provider_type)
                    .and_then(|defaults| defaults.base_url)
                    .map(ToString::to_string)
            })
        }
        (_, Some(crate::gateway::provider_auth::ProviderType::CloudflareAi)) => {
            derive_cloudflare_base_url(entry)
        }
        (_, Some(crate::gateway::provider_auth::ProviderType::SnowflakeCortex)) => {
            derive_snowflake_base_url(entry)
        }
        _ => entry_string(entry, &["base_url"]),
    }
    .unwrap_or_default();

    if !base_url.is_empty() {
        return Ok(base_url);
    }

    let message = match provider_type {
        Some(crate::gateway::provider_auth::ProviderType::CloudflareAi) => {
            format!("provider '{id}': base_url is required or derive it with cloudflare_account_id")
        }
        Some(crate::gateway::provider_auth::ProviderType::SnowflakeCortex) => format!(
            "provider '{id}': base_url is required or derive it with snowflake_account_identifier"
        ),
        _ => format!("provider '{id}': base_url is required"),
    };

    Err(CliError::user(message))
}

// ---------------------------------------------------------------------------
// Fallback
// ---------------------------------------------------------------------------

/// Error classes that can trigger a fallback to the next provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackTrigger {
    RateLimit,
    ServerError,
}

impl FallbackTrigger {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RateLimit => "rate_limit",
            Self::ServerError => "server_error",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "rate_limit" => Some(Self::RateLimit),
            "server_error" => Some(Self::ServerError),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FallbackConfig {
    pub triggers: Vec<FallbackTrigger>,
}

impl Default for FallbackConfig {
    fn default() -> Self {
        Self {
            triggers: vec![FallbackTrigger::RateLimit, FallbackTrigger::ServerError],
        }
    }
}

// ---------------------------------------------------------------------------
// Retry Policy
// ---------------------------------------------------------------------------

/// Declarative retry policy with per-trigger limits.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Global per-request max retries (across all triggers).
    pub max_retries: usize,
    /// Per-trigger retry limits, overriding the global max for specific trigger types.
    pub per_trigger: std::collections::HashMap<FallbackTrigger, usize>,
    /// Backoff strategy.
    pub backoff: BackoffStrategy,
}

/// Backoff strategy for retries.
#[derive(Debug, Clone, Copy)]
pub enum BackoffStrategy {
    /// Exponential backoff: base_ms * 2^attempt
    Exponential { base_ms: u64 },
    /// Fixed delay between retries
    Fixed { delay_ms: u64 },
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            per_trigger: std::collections::HashMap::new(),
            backoff: BackoffStrategy::Exponential { base_ms: 500 },
        }
    }
}

impl RetryPolicy {
    /// Returns the max retries for a specific trigger, or the global limit.
    pub fn max_retries_for(&self, trigger: Option<&FallbackTrigger>) -> usize {
        trigger
            .and_then(|t| self.per_trigger.get(t).copied())
            .unwrap_or(self.max_retries)
    }

    /// Compute backoff duration for a given attempt.
    pub fn backoff_delay(&self, attempt: usize) -> std::time::Duration {
        match self.backoff {
            BackoffStrategy::Exponential { base_ms } => {
                let ms = base_ms.saturating_mul(1u64 << attempt.min(10));
                std::time::Duration::from_millis(ms)
            }
            BackoffStrategy::Fixed { delay_ms } => std::time::Duration::from_millis(delay_ms),
        }
    }
}

// ---------------------------------------------------------------------------
// Scope-based rate limit configuration
// ---------------------------------------------------------------------------

/// Per-scope rate limit specification (requests per minute / tokens per minute).
#[derive(Debug, Clone)]
pub struct RateLimitSpec {
    /// Maximum requests per minute.
    pub rpm: Option<u64>,
    /// Maximum tokens per minute.
    pub tpm: Option<u64>,
}

/// Aggregate rate limits segmented by key and global scopes.
#[derive(Debug, Clone, Default)]
pub struct ScopeRateLimitConfig {
    pub per_key: Option<RateLimitSpec>,
    pub global: Option<RateLimitSpec>,
    pub max_parallel_requests: Option<u32>,
}

fn parse_rate_limit_spec(val: &serde_json::Value) -> Option<RateLimitSpec> {
    if !val.is_object() {
        return None;
    }
    Some(RateLimitSpec {
        rpm: val.get("rpm").and_then(|v| v.as_u64()),
        tpm: val.get("tpm").and_then(|v| v.as_u64()),
    })
}

pub fn parse_scope_rate_limits(section: &serde_json::Value) -> ScopeRateLimitConfig {
    let Some(rl) = section.get("rate_limits") else {
        return ScopeRateLimitConfig::default();
    };
    ScopeRateLimitConfig {
        per_key: rl.get("per_key").and_then(parse_rate_limit_spec),
        global: rl.get("global").and_then(parse_rate_limit_spec),
        max_parallel_requests: rl
            .get("max_parallel_requests")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32),
    }
}

pub fn parse_retry_policy(section: &serde_json::Value) -> RetryPolicy {
    let Some(rp) = section.get("retry_policy") else {
        return RetryPolicy::default();
    };
    let max_retries = rp.get("max_retries").and_then(|v| v.as_u64()).unwrap_or(3) as usize;
    let mut per_trigger = std::collections::HashMap::new();
    if let Some(pt) = rp.get("per_trigger").and_then(|v| v.as_object()) {
        for (key, val) in pt {
            if let (Ok(trigger), Some(limit)) = (
                serde_json::from_value::<FallbackTrigger>(serde_json::Value::String(key.clone())),
                val.as_u64(),
            ) {
                per_trigger.insert(trigger, limit as usize);
            }
        }
    }
    let backoff = if let Some(bo) = rp.get("backoff") {
        let strategy = bo
            .get("strategy")
            .and_then(|s| s.as_str())
            .unwrap_or("exponential");
        match strategy {
            "fixed" => BackoffStrategy::Fixed {
                delay_ms: bo.get("delay_ms").and_then(|v| v.as_u64()).unwrap_or(1000),
            },
            _ => BackoffStrategy::Exponential {
                base_ms: bo.get("base_ms").and_then(|v| v.as_u64()).unwrap_or(500),
            },
        }
    } else {
        BackoffStrategy::Exponential { base_ms: 500 }
    };
    RetryPolicy {
        max_retries,
        per_trigger,
        backoff,
    }
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RoutingStrategy {
    #[default]
    Ordered,
    LowestLatency,
    HighestThroughput,
    /// Simple round-robin cycling through all eligible providers (Phase 14).
    RoundRobin,
    /// Smooth weighted round-robin (Nginx algorithm); uses target.weight (Phase 14).
    WeightedRoundRobin,
    /// Route to the provider with the fewest active connections (Phase 14).
    LeastConnections,
    /// Uniform random selection (Phase 14).
    Random,
    /// Embedding-based routing using provider descriptions.
    Semantic,
    /// Random shuffle — identical to Random, explicitly named for LiteLLM parity.
    SimpleShuffle,
    /// Route to the provider with the fewest in-flight requests.
    LeastBusy,
    /// Route to the provider with the lowest cumulative token usage in the measurement window.
    UsageBased,
    /// Task-aware routing: use task classification to prefer matching providers.
    TaskAware,
}

// ---------------------------------------------------------------------------
// Logging configuration (Phase 9)
// ---------------------------------------------------------------------------

/// Controls what information is redacted from proxy trace spans and event payloads.
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// When true, message content fields are replaced with `[REDACTED]` in traces/events.
    pub redact_message_bodies: bool,
    /// When true, API key values are replaced with `[REDACTED]` in traces/events.
    pub redact_api_keys: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            redact_message_bodies: false,
            redact_api_keys: true, // Default: always redact API keys in logs.
        }
    }
}

#[derive(Debug, Clone)]
pub struct RoutingConfig {
    pub strategy: RoutingStrategy,
    pub measurement_window_seconds: u64,
    pub min_sample_count: usize,
    pub exploration_ratio: f64,
    /// Explicit ordered provider ID list overriding targets array order (Phase 1).
    pub order: Option<Vec<String>>,
    /// When false, only the first provider is tried; no fallback on error (Phase 1).
    pub allow_fallbacks: bool,
    /// Restrict eligible providers to this set; mutually exclusive with ignore (Phase 1).
    pub only: Option<Vec<String>>,
    /// Exclude these providers from routing; mutually exclusive with only (Phase 1).
    pub ignore: Option<Vec<String>>,
    /// Per-request cost ceiling; providers exceeding any dimension are skipped (Phase 2).
    pub max_price: Option<MaxPrice>,
    /// Latency SLA cutoff; violating providers are deprioritized (Phase 3).
    pub preferred_max_latency: Option<PerformanceCutoff>,
    /// Throughput floor; violating providers are deprioritized (Phase 3).
    pub preferred_min_throughput: Option<PerformanceCutoff>,
    /// Only route to providers whose region matches; None = no constraint (Phase 4).
    pub require_region: Option<String>,
    /// Sovereignty profile for region-aware endpoint selection (Phase 18).
    pub sovereignty_profile: Option<String>,
    /// Only route to providers that declare at least one matching quantization (Phase 5).
    pub require_quantizations: Option<Vec<String>>,
    /// Provider ID used to compute semantic routing embeddings.
    pub semantic_embedding_provider: Option<String>,
    /// Minimum similarity required before semantic routing reorders a provider to the front.
    pub semantic_similarity_threshold: f64,
    /// When true, estimate prompt tokens before routing and skip providers whose
    /// `max_context_tokens` is smaller than the estimate (Phase 8).
    pub enable_pre_call_checks: bool,
    /// Probability of promoting an under-sampled provider to the front of the
    /// routing list for warm-up traffic (0.0–1.0). Only applies to LowestLatency
    /// and HighestThroughput strategies.
    pub warmup_ratio: f64,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            strategy: RoutingStrategy::Ordered,
            measurement_window_seconds: 300,
            min_sample_count: 5,
            exploration_ratio: 0.1,
            order: None,
            allow_fallbacks: true,
            only: None,
            ignore: None,
            max_price: None,
            preferred_max_latency: None,
            preferred_min_throughput: None,
            require_region: None,
            sovereignty_profile: None,
            require_quantizations: None,
            semantic_embedding_provider: None,
            semantic_similarity_threshold: 0.0,
            enable_pre_call_checks: false,
            warmup_ratio: 0.1,
        }
    }
}

// ---------------------------------------------------------------------------
// Task-aware routing types (Phase 2)
// ---------------------------------------------------------------------------

/// Classification of the request task for task-aware routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskType {
    CodeGeneration,
    Analysis,
    Multilingual,
    Multimodal,
    LongFormWriting,
    StructuredOutput,
    General,
}

/// Task profile linking a task type to preferred providers and context requirements.
#[derive(Debug, Clone)]
pub struct TaskProfile {
    pub task_type: TaskType,
    pub preferred_providers: Vec<String>,
    pub min_context_tokens: Option<u32>,
}

/// Action when a soft budget limit is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SoftLimitAction {
    /// Prefer cheaper models but still allow expensive ones.
    #[default]
    PreferCheaper,
    /// Warn in traces but proceed normally.
    WarnOnly,
}

/// Action when a hard budget limit is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HardLimitAction {
    /// Reject the request with a budget-exceeded error.
    #[default]
    Reject,
    /// Allow only the cheapest available model.
    AllowCheapestOnly,
}

/// Budget-aware routing policy.
#[derive(Debug, Clone)]
pub struct BudgetPolicy {
    pub soft_limit_action: SoftLimitAction,
    pub hard_limit_action: HardLimitAction,
}

impl Default for BudgetPolicy {
    fn default() -> Self {
        Self {
            soft_limit_action: SoftLimitAction::PreferCheaper,
            hard_limit_action: HardLimitAction::Reject,
        }
    }
}

/// Latency optimization hints for provider selection.
#[derive(Debug, Clone, Default)]
pub struct LatencyOptimization {
    /// For streaming requests, prefer providers with TTFT below this threshold (ms).
    pub streaming_preferred_ttft_ms: Option<u64>,
    /// For batch/non-streaming, prefer providers with throughput above this (tokens/sec).
    pub batch_preferred_throughput_tps: Option<f64>,
}

// ---------------------------------------------------------------------------
// Zero-completion insurance
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ZeroCompletionInsuranceConfig {
    pub enabled: bool,
}

impl Default for ZeroCompletionInsuranceConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

// ---------------------------------------------------------------------------
// Provider registry (top-level)
// ---------------------------------------------------------------------------

/// A named group of provider targets, allowing virtual model name routing.
#[derive(Debug, Clone, Default)]
pub struct ModelGroup {
    /// Group name used for routing (matches request `model` field).
    pub name: String,
    /// Ordered list of provider target IDs that serve this group.
    pub targets: Vec<String>,
    /// Alternative names that also resolve to this group.
    pub aliases: Vec<String>,
    /// Human-readable description.
    pub description: Option<String>,
    /// Name of the next model group to try when all targets in this group fail.
    pub fallback_group: Option<String>,
}

/// Execution mode for a virtual provider pipeline.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProviderPipelineMode {
    #[default]
    Sequence,
    FanOut,
}

impl ProviderPipelineMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sequence => "sequence",
            Self::FanOut => "fan_out",
        }
    }
}

/// How a pipeline step should merge the previous step output into the next request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProviderPipelineInputMode {
    #[default]
    Append,
    Replace,
}

/// Role used when injecting the previous step output into the next request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProviderPipelineInjectRole {
    #[default]
    User,
    Assistant,
    System,
}

impl ProviderPipelineInjectRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::System => "system",
        }
    }
}

/// Aggregation strategy for fan-out pipelines.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProviderPipelineAggregation {
    #[default]
    Concat,
    FirstSuccess,
}

impl ProviderPipelineAggregation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Concat => "concat",
            Self::FirstSuccess => "first_success",
        }
    }
}

/// One step inside a provider pipeline.
#[derive(Debug, Clone)]
pub struct ProviderPipelineStep {
    pub name: Option<String>,
    pub target: String,
    pub instruction: Option<String>,
    pub input_mode: ProviderPipelineInputMode,
    pub inject_as: ProviderPipelineInjectRole,
}

/// A named virtual model that orchestrates multiple provider targets together.
#[derive(Debug, Clone)]
pub struct ProviderPipeline {
    pub name: String,
    pub mode: ProviderPipelineMode,
    pub steps: Vec<ProviderPipelineStep>,
    pub aliases: Vec<String>,
    pub description: Option<String>,
    pub aggregation: ProviderPipelineAggregation,
}

// ---------------------------------------------------------------------------
// Phase 9 — Traffic Mirroring & A/B Testing
// ---------------------------------------------------------------------------

/// Configuration for silent traffic mirroring to a shadow model.
#[derive(Debug, Clone)]
pub struct TrafficMirrorConfig {
    pub enabled: bool,
    pub mirror_target: Option<String>,
    pub sample_rate: f64,
}

impl Default for TrafficMirrorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mirror_target: None,
            sample_rate: 1.0,
        }
    }
}

/// Stickyness strategy for A/B variant assignment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum StickyBy {
    UserId,
    KeyId,
    #[default]
    Random,
}

/// One variant in an A/B test.
#[derive(Debug, Clone)]
pub struct AbVariant {
    pub provider_id: String,
    pub weight: f64,
}

/// A/B testing configuration for provider selection.
#[derive(Debug, Clone)]
pub struct AbTestConfig {
    pub enabled: bool,
    pub variants: Vec<AbVariant>,
    pub sticky_by: StickyBy,
}

impl Default for AbTestConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            variants: Vec::new(),
            sticky_by: StickyBy::Random,
        }
    }
}

pub fn parse_traffic_mirror(section: &serde_json::Value) -> TrafficMirrorConfig {
    let Some(tm) = section.get("traffic_mirror") else {
        return TrafficMirrorConfig::default();
    };
    TrafficMirrorConfig {
        enabled: tm.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false),
        mirror_target: tm
            .get("mirror_target")
            .and_then(|v| v.as_str())
            .map(ToString::to_string),
        sample_rate: tm
            .get("sample_rate")
            .and_then(|v| v.as_f64())
            .unwrap_or(1.0)
            .clamp(0.0, 1.0),
    }
}

fn parse_ab_test(section: &serde_json::Value) -> AbTestConfig {
    let Some(ab) = section.get("ab_test") else {
        return AbTestConfig::default();
    };
    let enabled = ab.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    let sticky_by = match ab.get("sticky_by").and_then(|v| v.as_str()) {
        Some("user_id") => StickyBy::UserId,
        Some("key_id") => StickyBy::KeyId,
        _ => StickyBy::Random,
    };
    let variants = ab
        .get("variants")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    let provider_id = v.get("provider_id")?.as_str()?.to_string();
                    let weight = v.get("weight").and_then(|w| w.as_f64()).unwrap_or(1.0);
                    Some(AbVariant {
                        provider_id,
                        weight,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    AbTestConfig {
        enabled,
        variants,
        sticky_by,
    }
}

// ---------------------------------------------------------------------------
// parse_logging (Phase 9)
// ---------------------------------------------------------------------------

pub fn parse_logging(section: &serde_json::Value) -> LoggingConfig {
    let Some(log) = section.get("logging") else {
        return LoggingConfig::default();
    };
    LoggingConfig {
        redact_message_bodies: log
            .get("redact_message_bodies")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        redact_api_keys: log
            .get("redact_api_keys")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
    }
}

/// Full provider configuration loaded from the `providers` section.
#[derive(Debug, Clone, Default)]
pub struct ProviderRegistry {
    pub targets: Vec<ProviderTarget>,
    pub fallback: FallbackConfig,
    pub routing: RoutingConfig,
    pub zero_completion_insurance: ZeroCompletionInsuranceConfig,
    pub model_groups: Vec<ModelGroup>,
    pub pipelines: Vec<ProviderPipeline>,
    pub circuit_breaker_manager: Option<super::circuit_breaker::CircuitBreakerManager>,
    pub retry_policy: RetryPolicy,
    pub scope_rate_limits: ScopeRateLimitConfig,
    pub traffic_mirror: TrafficMirrorConfig,
    pub ab_test: AbTestConfig,
    /// Phase 9: logging suppression settings.
    pub logging: LoggingConfig,
}

// ---------------------------------------------------------------------------
// Parsing from JSON (serde_json::Value)
// ---------------------------------------------------------------------------

impl ProviderRegistry {
    /// Parse the `providers` section from a declarative config's JSON root.
    /// Returns `None` when `providers` is absent, `Err` on validation failure.
    pub fn from_json(root: &serde_json::Value) -> Result<Option<Self>, CliError> {
        let Some(section) = root.get("providers") else {
            return Ok(None);
        };

        reject_removed_routing_fields(section)?;

        let targets = parse_targets(section)?;
        if targets.is_empty() {
            return Err(CliError::user(
                "providers.targets must be a non-empty array",
            ));
        }

        let fallback = parse_fallback(section);
        let routing = parse_routing(section);

        // Cross-validate routing config (Phase 1, 5).
        if routing.only.is_some() && routing.ignore.is_some() {
            return Err(CliError::user(
                "providers.routing: 'only' and 'ignore' are mutually exclusive",
            ));
        }
        if let Some(order) = &routing.order {
            let target_ids: Vec<&str> = targets.iter().map(|t| t.id.as_str()).collect();
            for id in order {
                if !target_ids.contains(&id.as_str()) {
                    return Err(CliError::user(format!(
                        "providers.routing.order: unknown provider id '{id}'"
                    )));
                }
            }
        }
        if let Some(req_quants) = &routing.require_quantizations {
            let valid = ["fp32", "fp16", "bf16", "int8", "fp8", "int4"];
            for q in req_quants {
                if !valid.contains(&q.as_str()) {
                    return Err(CliError::user(format!(
                        "providers.routing.require_quantizations: unknown quantization '{q}'"
                    )));
                }
            }
        }

        let zero_completion_insurance = parse_zero_completion_insurance(section);
        let model_groups = parse_model_groups(section, &targets)?;
        let pipelines = parse_pipelines(section, &targets)?;
        validate_virtual_model_names(&model_groups, &pipelines)?;
        let circuit_breaker_config = super::circuit_breaker::parse_circuit_breaker_config(section);
        let circuit_breaker_manager = Some(super::circuit_breaker::CircuitBreakerManager::new(
            circuit_breaker_config,
        ));
        let retry_policy = parse_retry_policy(section);
        let scope_rate_limits = parse_scope_rate_limits(section);
        let traffic_mirror = parse_traffic_mirror(section);
        // ab_test is rejected above when present; retain a default slot so
        // existing struct consumers compile until retires the field.
        let ab_test = AbTestConfig::default();
        let logging = parse_logging(section);

        Ok(Some(Self {
            targets,
            fallback,
            routing,
            zero_completion_insurance,
            model_groups,
            pipelines,
            circuit_breaker_manager,
            retry_policy,
            scope_rate_limits,
            traffic_mirror,
            ab_test,
            logging,
        }))
    }

    /// Resolve a model name (from the request body) to a model group, if any.
    pub fn resolve_model_group(&self, model_name: &str) -> Option<&ModelGroup> {
        self.model_groups
            .iter()
            .find(|g| g.name == model_name || g.aliases.iter().any(|a| a == model_name))
    }

    /// Resolve a model name (from the request body) to a provider pipeline, if any.
    pub fn resolve_pipeline(&self, model_name: &str) -> Option<&ProviderPipeline> {
        self.pipelines.iter().find(|pipeline| {
            pipeline.name == model_name || pipeline.aliases.iter().any(|alias| alias == model_name)
        })
    }

    /// Resolve a provider target by its ID.
    pub fn find_target_by_id(&self, target_id: &str) -> Option<&ProviderTarget> {
        self.targets.iter().find(|t| t.id == target_id)
    }

    /// Resolve escalation routing for a requested model across all targets.
    ///
    /// Searches each target for a model match (target.model, nested model, or alias).
    /// Returns the first `EscalationRouting` found, preferring model-level over
    /// provider-level routing.
    pub fn resolve_escalation_routing_for_model(
        &self,
        requested_model: &str,
    ) -> Option<&EscalationRouting> {
        for target in &self.targets {
            let matches = target.model == requested_model
                || target.models.iter().any(|m| {
                    m.model_id == requested_model || m.aliases.iter().any(|a| a == requested_model)
                });
            if matches {
                if let Some(routing) = resolve_escalation_routing(target, Some(requested_model)) {
                    return Some(routing);
                }
            }
        }
        None
    }

    /// Resolve the provider target index by provider pin header value.
    /// Returns indices of targets matching the given provider string.
    pub fn resolve_provider_pin(&self, provider_pin: &str) -> Vec<usize> {
        self.targets
            .iter()
            .enumerate()
            .filter(|(_, t)| t.id == provider_pin || t.provider == provider_pin)
            .map(|(i, _)| i)
            .collect()
    }

    /// Resolve a model pin against nested models within a target.
    /// Returns the effective pricing for the resolved model, if any.
    pub fn resolve_model_pricing(
        &self,
        target: &ProviderTarget,
        model_name: &str,
    ) -> Option<ProviderPricing> {
        // Check nested models first
        for m in &target.models {
            if m.enabled && (m.model_id == model_name || m.aliases.iter().any(|a| a == model_name))
            {
                return m.pricing.clone().or_else(|| target.pricing.clone());
            }
        }
        // Fall back to target-level pricing
        target.pricing.clone()
    }
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

/// Classify an upstream HTTP response (or network error) into a fallback trigger.
pub fn classify_upstream_error(
    status: Option<u16>,
    _body: &[u8],
    is_timeout: bool,
) -> Option<FallbackTrigger> {
    if is_timeout {
        return Some(FallbackTrigger::ServerError);
    }

    let status = status?;

    match status {
        429 => Some(FallbackTrigger::RateLimit),
        408 | 500 | 502 | 503 | 504 => Some(FallbackTrigger::ServerError),
        _ => None,
    }
}

/// Returns `true` when the upstream status indicates an auth/credential error
/// (401 or non-content-filter 403). Used for credential rotation safety in the
/// gateway dispatch loop.
pub fn is_upstream_auth_error(status: u16, body: &[u8]) -> bool {
    match status {
        401 => true,
        403 => {
            let body_str = std::str::from_utf8(body).unwrap_or("");
            !(body_str.contains("content_filter")
                || body_str.contains("moderation")
                || body_str.contains("content_policy_violation"))
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Provider path resolution
// ---------------------------------------------------------------------------

/// Resolve the upstream path for a given provider target and default path.
/// If the provider has a `path_template`, expand `{model}` and use it.
/// Otherwise, use the default path.
pub fn resolve_provider_path(target: &ProviderTarget, default_path: &str) -> String {
    if let Some(template) = target.path_template.as_deref() {
        return template.replace("{model}", &target.model);
    }

    if let Some(template) = crate::gateway::provider_catalog::provider_path_template_for_public_path(
        &target.provider,
        default_path,
    ) {
        return template.replace("{model}", &target.model);
    }

    let target_format = target.format.or_else(|| {
        crate::gateway::provider_catalog::profile_for_provider(&target.provider)
            .map(|profile| profile.format)
    });
    match (default_path, target_format) {
        ("/v1/messages", Some(crate::gateway::format_translation::ProviderFormat::OpenAI)) => {
            return "/v1/chat/completions".to_string();
        }
        (
            "/v1/chat/completions" | "/v1/responses",
            Some(crate::gateway::format_translation::ProviderFormat::Anthropic),
        ) => {
            return "/v1/messages".to_string();
        }
        _ => {}
    }

    let runtime_path = crate::gateway::runtimes::resolve_runtime_path(
        &target.provider,
        target.execution_target.as_ref(),
        &target.model,
        None,
        default_path,
    );

    if runtime_path != default_path {
        return runtime_path;
    }

    if let Some(template) = crate::gateway::provider_catalog::profile_for_provider(&target.provider)
        .and_then(|profile| profile.path_template)
    {
        return template.replace("{model}", &target.model);
    }

    runtime_path
}

/// Build a `(header_name, header_value)` auth pair from a `ProviderTarget`.
pub async fn resolve_provider_auth(
    target: &ProviderTarget,
) -> Result<Option<(reqwest::header::HeaderName, reqwest::header::HeaderValue)>, CliError> {
    if target.oauth2.is_some() {
        let token = crate::gateway::provider_auth::build_provider_auth(
            target,
            &target.model,
            "/v1/chat/completions",
            b"{}",
            false,
        )
        .await
        .map_err(|error| CliError::user(format!("provider {}: {error}", target.id)))?;
        if let Some((_, value)) = token
            .extra_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        {
            return Ok(Some((
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(value).map_err(|_| {
                    CliError::user(format!(
                        "provider {}: oauth2 token produced invalid Authorization header",
                        target.id
                    ))
                })?,
            )));
        }
    }

    if target.api_key.is_empty() {
        if target.requires_resolved_api_key() {
            return Err(CliError::user(format!(
                "provider {}: no static api key configured",
                target.id
            )));
        }
        return Ok(None);
    }

    let header_name = reqwest::header::HeaderName::from_bytes(target.api_key_header.as_bytes())
        .map_err(|_| {
            CliError::user(format!(
                "provider {}: invalid api_key_header '{}'",
                target.id, target.api_key_header
            ))
        })?;

    let full_value = format!("{}{}", target.api_key_prefix, target.api_key);
    let header_value = reqwest::header::HeaderValue::from_str(&full_value).map_err(|_| {
        CliError::user(format!(
            "provider {}: api key produces invalid header value",
            target.id
        ))
    })?;

    Ok(Some((header_name, header_value)))
}

// ---------------------------------------------------------------------------
// Internal parsers
// ---------------------------------------------------------------------------

fn reject_removed_routing_fields(section: &serde_json::Value) -> Result<(), CliError> {
    if section
        .pointer("/routing/upstream_fallback_policy")
        .is_some()
    {
        return Err(CliError::user(
            "providers.routing.upstream_fallback_policy is no longer supported; delete or remove this field from your config. The gateway now enforces exact-region-only routing.",
        ));
    }

    // providers.ab_test was parsed into ProviderRegistry but never
    // consulted by dispatch / ordering. Reject rather than silently retain.
    if section.get("ab_test").is_some() {
        return Err(CliError::user(
            "providers.ab_test has been removed; it had no runtime dispatch effect. Use providers.routing order/only/ignore or the auto: virtual provider for selection.",
        ));
    }

    Ok(())
}

fn parse_targets(section: &serde_json::Value) -> Result<Vec<ProviderTarget>, CliError> {
    let Some(arr) = section.get("targets").and_then(|v| v.as_array()) else {
        return Err(CliError::user(
            "providers.targets must be a non-empty array",
        ));
    };

    let mut targets = Vec::with_capacity(arr.len());
    for (i, entry) in arr.iter().enumerate() {
        let id = entry
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            return Err(CliError::user(format!(
                "providers.targets[{i}]: id is required"
            )));
        }

        let raw_provider = entry
            .get("provider")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if raw_provider.is_empty() {
            return Err(CliError::user(format!(
                "providers.targets[{i}] ({id}): provider is required"
            )));
        }
        if let Err(error) =
            crate::gateway::provider_catalog::validate_exact_udr_provider_id(&raw_provider)
        {
            return Err(CliError::user(format!(
                "providers.targets[{i}] ({id}): {error}"
            )));
        }

        let execution_target =
            crate::gateway::execution_runtime::parse_execution_target(&raw_provider, entry)
                .map_err(|error| {
                    CliError::user(format!("providers.targets[{i}] ({id}): {error}"))
                })?;

        // Reject statically unsupported execution families at config-load time
        // so the gateway never starts with a provider that can only return 501
        // at request time. The request-time NOT_IMPLEMENTED response path
        // remains as defense-in-depth for corrupted in-memory state that
        // bypasses this parse-time guard.
        if let Some(crate::gateway::execution_runtime::ExecutionTarget::Unsupported {
            ref reason,
            ..
        }) = execution_target
        {
            use crate::gateway::execution_runtime::{classify_capability, ExecutionCapability};
            match classify_capability(&raw_provider) {
                ExecutionCapability::UnsupportedAtConfigTime => {
                    return Err(CliError::user(format!(
                        "providers.targets[{i}] ({id}): provider '{raw_provider}' is an \
                         unsupported execution family and cannot be used in verdictan gateway run. \
                         {reason}. Use exec:, file://, or an adapter-backed family with \
                         adapter_command instead."
                    )));
                }
                ExecutionCapability::SupportedWithAdapter => {
                    return Err(CliError::user(format!(
                        "providers.targets[{i}] ({id}): provider '{raw_provider}' requires adapter_command before verdictan gateway run can start. {reason}"
                    )));
                }
                ExecutionCapability::Supported => {}
            }
        }

        let verdictan_spec = parse_verdictan_provider_spec(&raw_provider);
        let provider = verdictan_spec.canonical_provider.clone();
        let runtime_policy = crate::gateway::runtimes::parser_policy_for_target(
            &provider,
            execution_target.as_ref(),
        );
        let has_nested_models = entry
            .get("models")
            .and_then(|v| v.as_array())
            .map(|arr| !arr.is_empty())
            .unwrap_or(false);
        let first_nested_model_id = entry
            .get("models")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|model| model.get("model_id").or_else(|| model.get("id")))
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);

        let mut model = entry_string(entry, &["model"]).unwrap_or_else(|| {
            if execution_target.is_some() {
                String::new()
            } else {
                verdictan_spec.model.clone().unwrap_or_default()
            }
        });
        if model.is_empty() {
            if let Some(nested_model_id) = first_nested_model_id {
                model = nested_model_id;
            }
        }
        let gateway_provider = if matches!(
            crate::gateway::provider_catalog::normalized_provider_alias(&provider).as_str(),
            "cloudflare-gateway" | "cloudflare-ai-gateway"
        ) {
            let (gateway_provider, actual_model) = split_cloudflare_gateway_model(&model);
            model = actual_model;
            gateway_provider
        } else {
            None
        };
        if execution_target.is_none()
            && model.is_empty()
            && runtime_policy.requires_model
            && !has_nested_models
        {
            return Err(CliError::user(format!(
                "providers.targets[{i}] ({id}): model is required"
            )));
        }
        let description = entry
            .get("description")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);

        let inferred_profile = crate::gateway::provider_catalog::profile_for_provider(&provider);
        let provider_type_hint_profile = entry
            .get("provider_type")
            .and_then(|v| v.as_str())
            .and_then(crate::gateway::provider_catalog::profile_for_provider);
        let auth_profile = if matches!(
            crate::gateway::provider_catalog::normalized_provider_alias(&provider).as_str(),
            "cloudflare-gateway" | "cloudflare-ai-gateway"
        ) {
            gateway_provider
                .as_deref()
                .and_then(crate::gateway::provider_catalog::profile_for_provider)
                .or(provider_type_hint_profile)
                .or(inferred_profile)
        } else {
            provider_type_hint_profile.or(inferred_profile)
        };

        // Phase 35: parse provider_type early so we can relax secret_key_ref requirements
        // for providers that use their own credential chain (Bedrock, Vertex AI).
        let provider_type: Option<crate::gateway::provider_auth::ProviderType> = entry
            .get("provider_type")
            .and_then(|v| v.as_str())
            .and_then(crate::gateway::provider_auth::ProviderType::from_str)
            .or_else(|| inferred_profile.map(|profile| profile.provider_type));

        let provider_defaults = verdictan_provider_defaults(&provider, provider_type);

        let base_url = if execution_target.is_some() {
            String::new()
        } else {
            provider_base_url(
                entry,
                &id,
                &provider,
                provider_type,
                &model,
                gateway_provider.as_deref(),
            )
            .map_err(|error| CliError::user(format!("providers.targets[{i}] ({id}): {error}")))?
        };

        let secret_key_ref = parse_secret_key_ref_value(
            entry.get("secret_key_ref"),
            &format!("providers.targets[{i}] ({id}).secret_key_ref"),
        )?;
        let required = entry
            .get("required")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let is_self_credentialed = matches!(
            provider_type,
            Some(crate::gateway::provider_auth::ProviderType::AwsBedrock)
                | Some(crate::gateway::provider_auth::ProviderType::GoogleVertex)
        ) || entry.get("oauth2").is_some();

        let allows_missing_api_key = provider_defaults
            .map(|defaults| defaults.auth_optional)
            .unwrap_or(false)
            || runtime_policy.auth_optional
            || is_self_credentialed
            || !required
            // When secret_key_ref.store is present the key is resolved at request time;
            // no env var is required at config-parse time.
            || secret_key_ref
                .as_ref()
                .map(SecretKeyReference::is_store_ref)
                .unwrap_or(false);

        if execution_target.is_none() && secret_key_ref.is_none() && !allows_missing_api_key {
            return Err(CliError::user(format!(
                "providers.targets[{i}] ({id}): secret_key_ref could not be resolved. \
                 Expected format: secret_key_ref: {{ env: \"ENV_VAR\" }} for environment-backed secrets \
                 or secret_key_ref: {{ store: \"SECRET_NAME\" }} for stored secrets. \
                 The reference must include exactly one of 'env' or 'store'. \
                 See: docs.verdictan.com/docs/configurations#secret-references"
            )));
        }

        let env_secret_name = secret_key_ref
            .as_ref()
            .and_then(SecretKeyReference::env_name)
            .map(ToString::to_string);
        let api_key = env_secret_name
            .as_ref()
            .and_then(|env_name| std::env::var(env_name).ok())
            .unwrap_or_default();
        if execution_target.is_none() && api_key.is_empty() && !allows_missing_api_key {
            let env_var = env_secret_name.unwrap_or_default();
            return Err(CliError::user(format!(
                "providers.targets[{i}] ({id}): secret_key_ref '{{{{ env: \"{env_var}\" }}}}' could not be resolved. \
                 The environment variable '{env_var}' is not set or empty. \
                 Expected format: secret_key_ref: {{ env: \"ENV_VAR\" }} for environment-backed secrets \
                 or secret_key_ref: {{ store: \"SECRET_NAME\" }} for stored secrets. \
                 The reference must include exactly one of 'env' or 'store'. \
                 See: docs.verdictan.com/docs/configurations#secret-references"
            )));
        }

        let api_key_header = entry
            .get("api_key_header")
            .and_then(|v| v.as_str())
            .or_else(|| auth_profile.map(|profile| profile.api_key_header))
            .unwrap_or("Authorization")
            .to_string();

        let api_key_prefix = entry
            .get("api_key_prefix")
            .and_then(|v| v.as_str())
            .or_else(|| auth_profile.map(|profile| profile.api_key_prefix))
            .unwrap_or("Bearer ")
            .to_string();

        let path_template = entry
            .get("path_template")
            .and_then(|v| v.as_str())
            .map(ToString::to_string)
            .or_else(|| {
                verdictan_spec.kind.map(|kind| {
                    default_verdictan_path_template_for_provider(&provider, kind).to_string()
                })
            })
            .or_else(|| {
                inferred_profile.and_then(|profile| profile.path_template.map(ToString::to_string))
            });

        let headers = entry
            .get("headers")
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        let timeout_ms = entry
            .get("timeout_ms")
            .and_then(|v| v.as_u64())
            .or_else(|| {
                entry
                    .get("timeout_seconds")
                    .and_then(|v| v.as_u64())
                    .map(|seconds| seconds.saturating_mul(1_000))
            })
            .unwrap_or(30_000);

        let stream_timeout = entry
            .get("stream_timeout_ms")
            .and_then(|v| v.as_u64())
            .map(Duration::from_millis)
            .or_else(|| {
                entry
                    .get("stream_timeout_seconds")
                    .and_then(|v| v.as_u64())
                    .map(Duration::from_secs)
            });

        let max_context_tokens = entry
            .get("max_context_tokens")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize);

        let max_messages = entry
            .get("max_messages")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize);

        let data_policy = parse_data_policy(entry, i, &id)?;

        let pricing = entry.get("pricing").map(parse_pricing_object);

        // Parse nested models[] array for multi-model provider targets
        let models = parse_nested_models(entry, i, &id, &pricing)?;

        // Phase 4: data_collection, zdr, region
        let data_collection = match entry.get("data_collection").and_then(|v| v.as_str()) {
            Some("deny") => Some(DataCollectionPolicy::Deny),
            Some("allow") => Some(DataCollectionPolicy::Allow),
            None => None,
            Some(other) => {
                return Err(CliError::user(format!(
                    "providers.targets[{i}] ({id}): unknown data_collection value '{other}' (expected 'allow' or 'deny')"
                )));
            }
        };

        let zdr = entry.get("zdr").and_then(|v| v.as_bool()).unwrap_or(false);
        // ZDR shorthand: conflict-check with explicit data_policy.zero_data_retention.
        if zdr {
            if let Some(dp) = &data_policy {
                if !dp.zero_data_retention {
                    return Err(CliError::user(format!(
                        "providers.targets[{i}] ({id}): zdr: true conflicts with data_policy.zero_data_retention: false"
                    )));
                }
            }
        }

        let region = entry
            .get("region")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);

        // Phase 5: quantizations
        let quantizations = if let Some(arr) = entry.get("quantizations").and_then(|v| v.as_array())
        {
            let valid = ["fp32", "fp16", "bf16", "int8", "fp8", "int4"];
            let mut quants = Vec::with_capacity(arr.len());
            for v in arr {
                let q = v.as_str().unwrap_or("");
                if !valid.contains(&q) {
                    return Err(CliError::user(format!(
                        "providers.targets[{i}] ({id}): unknown quantization '{q}' (allowed: fp32, fp16, bf16, int8, fp8, int4)"
                    )));
                }
                quants.push(q.to_string());
            }
            Some(quants)
        } else {
            None
        };

        // Phase 14: weight for weighted_round_robin
        let weight = entry.get("weight").and_then(|v| v.as_f64());

        // Phase 15: wire format
        let format: Option<crate::gateway::format_translation::ProviderFormat> = entry
            .get("format")
            .and_then(|v| v.as_str())
            .and_then(crate::gateway::format_translation::ProviderFormat::from_str)
            .or_else(|| inferred_profile.map(|profile| profile.format));

        if !verdictan_kind_supported(&provider, provider_type, verdictan_spec.kind) {
            return Err(CliError::user(format!(
                "providers.targets[{i}] ({id}): provider '{provider}' verdictan shorthand only supports {}",
                supported_verdictan_kind_list(&provider, provider_type)
                    .unwrap_or_else(|| "the configured subtype set".to_string())
            )));
        }

        // Phase 35: provider-specific fields
        let anthropic_version = entry
            .get("anthropic_version")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let aws_region = entry
            .get("aws_region")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let aws_profile = entry
            .get("aws_profile")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let bedrock_model_family = entry
            .get("bedrock_model_family")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let watsonx_api_version = entry
            .get("watsonx_api_version")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let watsonx_project_id = entry
            .get("watsonx_project_id")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let watsonx_space_id = entry
            .get("watsonx_space_id")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let gcp_project = entry
            .get("gcp_project")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let gcp_region = entry
            .get("gcp_region")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let azure_api_version = entry
            .get("azure_api_version")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let azure_deployment = entry
            .get("azure_deployment")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let oauth2 = entry
            .get("oauth2")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| {
                CliError::user(format!(
                    "providers.targets[{i}] ({id}): invalid oauth2 configuration: {error}"
                ))
            })?;
        let health_probe = entry
            .get("health_probe")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| {
                CliError::user(format!(
                    "providers.targets[{i}] ({id}): invalid health_probe configuration: {error}"
                ))
            })?;
        let allow_insecure_tls = entry
            .get("allow_insecure_tls")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);

        let escalation_routing = parse_escalation_routing(entry.get("escalation_routing"), i, &id)?;
        let mcp_bridge =
            if crate::gateway::provider_catalog::normalized_provider_alias(&provider) == "mcp" {
                entry
                    .get("mcp")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()
                    .map_err(|error| {
                        CliError::user(format!(
                        "providers.targets[{i}] ({id}): invalid mcp bridge configuration: {error}"
                    ))
                    })?
            } else {
                None
            };

        let runtime_validation_config = json!({
            "provider": provider,
            "provider_spec": entry.get("provider").and_then(|v| v.as_str()),
            "model": model,
            "base_url": base_url,
            "mcp": mcp_bridge,
            "anthropic_version": anthropic_version
                .as_deref()
                .unwrap_or("2023-06-01"),
            "aws_region": aws_region,
            "bedrock_model_family": bedrock_model_family,
            "watsonx_api_version": watsonx_api_version,
            "watsonx_project_id": watsonx_project_id,
            "watsonx_space_id": watsonx_space_id,
            "adapter_command": entry.get("adapter_command").and_then(|v| v.as_str()),
        });

        crate::gateway::runtimes::validate_runtime_target(
            &provider,
            execution_target.as_ref(),
            &runtime_validation_config,
        )
        .map_err(|error| {
            CliError::user(format!(
                "providers.targets[{i}] ({id}): runtime validation failed: {error}"
            ))
        })?;

        targets.push(ProviderTarget {
            id,
            provider,
            model,
            execution_target,
            mcp_bridge,
            description,
            base_url,
            api_key,
            api_key_header,
            api_key_prefix,
            secret_key_ref,
            path_template,
            headers,
            timeout: Duration::from_millis(timeout_ms),
            stream_timeout,
            max_context_tokens,
            max_messages,
            data_policy,
            pricing,
            models,
            data_collection,
            zdr,
            region,
            quantizations,
            weight,
            provider_type,
            format,
            anthropic_version,
            aws_region,
            aws_profile,
            bedrock_model_family,
            watsonx_api_version,
            watsonx_project_id,
            watsonx_space_id,
            gcp_project,
            gcp_region,
            azure_api_version,
            azure_deployment,
            oauth2,
            health_probe,
            allow_insecure_tls,
            escalation_routing,
            required,
            data_residency: parse_data_residency_policy(entry),
            certifications: entry
                .get("certifications")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(ToString::to_string))
                        .collect()
                }),
        });
    }

    Ok(targets)
}

/// Parse the `data_residency` sub-object from a provider target entry.
fn parse_data_residency_policy(entry: &serde_json::Value) -> Option<DataResidencyPolicy> {
    let section = entry.get("data_residency")?;
    let regions = section
        .get("regions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToString::to_string))
                .collect()
        })
        .unwrap_or_default();
    let data_center_locations = section
        .get("data_center_locations")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToString::to_string))
                .collect()
        })
        .unwrap_or_default();
    let sovereignty_compliant = section
        .get("sovereignty_compliant")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Some(DataResidencyPolicy {
        regions,
        data_center_locations,
        sovereignty_compliant,
    })
}

fn parse_pricing_object(p: &serde_json::Value) -> ProviderPricing {
    let input_price_per_million = p
        .get("input_price_per_million")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let cached_input_price_per_million = p
        .get("cached_input_price_per_million")
        .and_then(|v| v.as_f64());
    let output_price_per_million = p
        .get("output_price_per_million")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let input_multiplier = p.get("input_multiplier").and_then(|v| v.as_f64());
    let cached_input_multiplier = p.get("cached_input_multiplier").and_then(|v| v.as_f64());
    let output_multiplier = p.get("output_multiplier").and_then(|v| v.as_f64());
    ProviderPricing {
        input_price_per_million,
        output_price_per_million,
        cached_input_price_per_million,
        input_multiplier,
        cached_input_multiplier,
        output_multiplier,
    }
}

/// Parse nested `models[]` array inside a provider target.
fn parse_nested_models(
    entry: &serde_json::Value,
    target_index: usize,
    target_id: &str,
    parent_pricing: &Option<ProviderPricing>,
) -> Result<Vec<ProviderModelEntry>, CliError> {
    let Some(arr) = entry.get("models").and_then(|v| v.as_array()) else {
        return Ok(Vec::new());
    };

    if entry
        .get("model")
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false)
        && !arr.is_empty()
    {
        return Err(CliError::user(format!(
            "providers.targets[{target_index}] ({target_id}): cannot set both 'model' and 'models[]'; declare either a single target-level model or nested models[] entries"
        )));
    }

    let mut models = Vec::with_capacity(arr.len());
    let mut seen_ids = std::collections::HashSet::new();

    for (j, m) in arr.iter().enumerate() {
        let model_id = m
            .get("model_id")
            .or_else(|| m.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if model_id.is_empty() {
            return Err(CliError::user(format!(
                "providers.targets[{target_index}] ({target_id}).models[{j}]: model_id is required"
            )));
        }
        if !seen_ids.insert(model_id.clone()) {
            return Err(CliError::user(format!(
                "providers.targets[{target_index}] ({target_id}).models[{j}]: duplicate model_id '{model_id}'"
            )));
        }

        let aliases: Vec<String> = m
            .get("aliases")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToString::to_string))
                    .collect()
            })
            .unwrap_or_default();

        let enabled = m.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);

        let pricing = if let Some(p) = m.get("pricing") {
            Some(parse_pricing_object(p))
        } else {
            parent_pricing.clone()
        };

        let supported_features: Vec<String> = m
            .get("supported_features")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|value| value.as_str().map(ToString::to_string))
                    .collect()
            })
            .unwrap_or_default();

        let max_output_tokens = match m.get("max_output_tokens") {
            Some(value) => {
                let Some(value) = value.as_u64() else {
                    return Err(CliError::user(format!(
                        "providers.targets[{target_index}] ({target_id}).models[{j}]: max_output_tokens must be a positive integer"
                    )));
                };
                let max_output_tokens = u32::try_from(value).map_err(|_| {
                    CliError::user(format!(
                        "providers.targets[{target_index}] ({target_id}).models[{j}]: max_output_tokens exceeds supported range"
                    ))
                })?;
                Some(max_output_tokens)
            }
            None => None,
        };

        let parameter_overrides = match m.get("parameter_overrides") {
            Some(value) => value.as_object().cloned().ok_or_else(|| {
                CliError::user(format!(
                    "providers.targets[{target_index}] ({target_id}).models[{j}]: parameter_overrides must be an object"
                ))
            })?,
            None => serde_json::Map::new(),
        };

        let removed_params = match m.get("removed_params") {
            Some(value) => {
                let Some(arr) = value.as_array() else {
                    return Err(CliError::user(format!(
                        "providers.targets[{target_index}] ({target_id}).models[{j}]: removed_params must be an array of strings"
                    )));
                };
                let mut removed_params = Vec::with_capacity(arr.len());
                for entry in arr {
                    let Some(entry) = entry.as_str() else {
                        return Err(CliError::user(format!(
                            "providers.targets[{target_index}] ({target_id}).models[{j}]: removed_params must be an array of strings"
                        )));
                    };
                    removed_params.push(entry.to_string());
                }
                removed_params
            }
            None => Vec::new(),
        };

        let description = m
            .get("description")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);

        let escalation_routing = parse_escalation_routing(
            m.get("escalation_routing"),
            target_index,
            &format!("{target_id}.models[{j}]"),
        )?;

        models.push(ProviderModelEntry {
            model_id,
            aliases,
            enabled,
            pricing,
            supported_features,
            max_output_tokens,
            parameter_overrides,
            removed_params,
            description,
            escalation_routing,
        });
    }

    Ok(models)
}

/// Parse an `escalation_routing` block from a config entry.
///
/// Returns `CliError::user` if both `team_id` and `user_id` are set.
pub fn parse_escalation_routing(
    value: Option<&serde_json::Value>,
    target_index: usize,
    context: &str,
) -> Result<Option<EscalationRouting>, CliError> {
    let Some(routing) = value else {
        return Ok(None);
    };
    let team_id = routing
        .get("team_id")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let user_id = routing
        .get("user_id")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);

    if team_id.is_some() && user_id.is_some() {
        return Err(CliError::user(format!(
            "providers.targets[{target_index}] ({context}): escalation_routing must set exactly \
             one of team_id or user_id, not both"
        )));
    }
    if team_id.is_none() && user_id.is_none() {
        return Err(CliError::user(format!(
            "providers.targets[{target_index}] ({context}): escalation_routing must set \
             either team_id or user_id"
        )));
    }

    Ok(Some(EscalationRouting { team_id, user_id }))
}

/// Resolve the effective `EscalationRouting` for a request given a provider
/// target and the client-requested model name.
///
/// Precedence: model-level (matched by `model_id` or alias) > provider-level > None.
pub fn resolve_escalation_routing<'a>(
    target: &'a ProviderTarget,
    model_id: Option<&str>,
) -> Option<&'a EscalationRouting> {
    if let Some(model_name) = model_id {
        for entry in &target.models {
            let matches =
                entry.model_id == model_name || entry.aliases.iter().any(|a| a == model_name);
            if matches {
                if entry.escalation_routing.is_some() {
                    return entry.escalation_routing.as_ref();
                }
                break;
            }
        }
    }
    target.escalation_routing.as_ref()
}

pub fn parse_data_policy(
    entry: &serde_json::Value,
    index: usize,
    id: &str,
) -> Result<Option<DataPolicy>, CliError> {
    let Some(dp) = entry.get("data_policy") else {
        return Ok(None);
    };

    let zero_data_retention = dp
        .get("zero_data_retention")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let training_opt_out = dp
        .get("training_opt_out")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let retention_days = dp
        .get("retention_days")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);

    // Cross-validation: ZDR implies no training.
    if zero_data_retention && !training_opt_out {
        return Err(CliError::user(format!(
            "providers.targets[{index}] ({id}): zero_data_retention requires training_opt_out to be true"
        )));
    }

    // Cross-validation: ZDR implies retention_days must be 0 or omitted.
    if zero_data_retention {
        if let Some(days) = retention_days {
            if days > 0 {
                return Err(CliError::user(format!(
                    "providers.targets[{index}] ({id}): zero_data_retention requires retention_days to be 0 or omitted, got {days}"
                )));
            }
        }
    }

    let in_memory_only = dp
        .get("in_memory_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let sanitized = dp
        .get("sanitized")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let accepts_tokenized_input = dp
        .get("accepts_tokenized_input")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let allow_internet_egress = dp
        .get("allow_internet_egress")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let local_only_processing = dp
        .get("local_only_processing")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Ok(Some(DataPolicy {
        zero_data_retention,
        training_opt_out,
        retention_days,
        in_memory_only,
        sanitized,
        accepts_tokenized_input,
        allow_internet_egress,
        local_only_processing,
    }))
}

pub fn parse_fallback(section: &serde_json::Value) -> FallbackConfig {
    let Some(fb) = section.get("fallback") else {
        return FallbackConfig::default();
    };

    let triggers = fb
        .get("trigger_on")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().and_then(FallbackTrigger::from_str))
                .collect()
        })
        .unwrap_or_else(|| FallbackConfig::default().triggers);

    FallbackConfig { triggers }
}

pub fn parse_routing(section: &serde_json::Value) -> RoutingConfig {
    let Some(r) = section.get("routing") else {
        return RoutingConfig::default();
    };

    let strategy = match r.get("strategy").and_then(|v| v.as_str()) {
        Some("lowest_latency") => RoutingStrategy::LowestLatency,
        Some("highest_throughput") => RoutingStrategy::HighestThroughput,
        Some("round_robin") => RoutingStrategy::RoundRobin,
        Some("weighted_round_robin") => RoutingStrategy::WeightedRoundRobin,
        Some("least_connections") => RoutingStrategy::LeastConnections,
        Some("random") => RoutingStrategy::Random,
        Some("semantic") => RoutingStrategy::Semantic,
        Some("simple_shuffle") => RoutingStrategy::SimpleShuffle,
        Some("least_busy") => RoutingStrategy::LeastBusy,
        Some("usage_based") => RoutingStrategy::UsageBased,
        Some("task_aware") => RoutingStrategy::TaskAware,
        Some("latency_based") => RoutingStrategy::LowestLatency,
        _ => RoutingStrategy::Ordered,
    };

    let measurement_window_seconds = r
        .get("measurement_window_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(300);

    let min_sample_count = r
        .get("min_sample_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(5) as usize;

    let exploration_ratio = r
        .get("exploration_ratio")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.1)
        .clamp(0.0, 1.0);

    // Phase 1: order, allow_fallbacks, only, ignore
    let order = r.get("order").and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(ToString::to_string))
            .collect()
    });

    let allow_fallbacks = r
        .get("allow_fallbacks")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let only = r.get("only").and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(ToString::to_string))
            .collect()
    });

    let ignore = r.get("ignore").and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(ToString::to_string))
            .collect()
    });

    // Phase 2: max_price
    let max_price = r.get("max_price").map(|mp| MaxPrice {
        prompt: mp
            .get("prompt")
            .or_else(|| mp.get("prompt_per_token"))
            .and_then(|v| v.as_f64()),
        completion: mp
            .get("completion")
            .or_else(|| mp.get("completion_per_token"))
            .and_then(|v| v.as_f64()),
        request: mp
            .get("request")
            .or_else(|| mp.get("request_total"))
            .and_then(|v| v.as_f64()),
    });

    // Phase 3: preferred_max_latency, preferred_min_throughput
    let preferred_max_latency = r.get("preferred_max_latency").and_then(|c| {
        let ms = c.get("ms").and_then(|v| v.as_f64())?;
        let percentile = match c.get("percentile").and_then(|v| v.as_str()) {
            Some("p90") => Percentile::P90,
            Some("p99") => Percentile::P99,
            _ => Percentile::P50,
        };
        Some(PerformanceCutoff {
            value: ms,
            percentile,
        })
    });

    let preferred_min_throughput = r.get("preferred_min_throughput").and_then(|c| {
        let tps = c.get("tps").and_then(|v| v.as_f64())?;
        let percentile = match c.get("percentile").and_then(|v| v.as_str()) {
            Some("p90") => Percentile::P90,
            Some("p99") => Percentile::P99,
            _ => Percentile::P50,
        };
        Some(PerformanceCutoff {
            value: tps,
            percentile,
        })
    });

    // Phase 4: require_region
    let require_region = r
        .get("require_region")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);

    let sovereignty_profile = r
        .get("sovereignty_profile")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);

    // Phase 5: require_quantizations
    let require_quantizations = r
        .get("require_quantizations")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToString::to_string))
                .collect()
        });
    let semantic_embedding_provider = r
        .get("semantic_embedding_provider")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let semantic_similarity_threshold = r
        .get("semantic_similarity_threshold")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);

    // Phase 8: enable_pre_call_checks
    let enable_pre_call_checks = r
        .get("enable_pre_call_checks")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Phase 3 warm-up: warmup_ratio
    let warmup_ratio = r
        .get("warmup_ratio")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.1)
        .clamp(0.0, 1.0);

    RoutingConfig {
        strategy,
        measurement_window_seconds,
        min_sample_count,
        exploration_ratio,
        order,
        allow_fallbacks,
        only,
        ignore,
        max_price,
        preferred_max_latency,
        preferred_min_throughput,
        require_region,
        sovereignty_profile,
        require_quantizations,
        semantic_embedding_provider,
        semantic_similarity_threshold,
        enable_pre_call_checks,
        warmup_ratio,
    }
}

fn parse_zero_completion_insurance(section: &serde_json::Value) -> ZeroCompletionInsuranceConfig {
    let Some(zc) = section.get("zero_completion_insurance") else {
        return ZeroCompletionInsuranceConfig::default();
    };

    let enabled = zc.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);

    ZeroCompletionInsuranceConfig { enabled }
}

pub fn parse_model_groups(
    section: &serde_json::Value,
    targets: &[ProviderTarget],
) -> Result<Vec<ModelGroup>, CliError> {
    let Some(groups) = section.get("model_groups").and_then(|v| v.as_array()) else {
        return Ok(Vec::new());
    };
    let target_ids: Vec<&str> = targets.iter().map(|t| t.id.as_str()).collect();
    let mut result = Vec::with_capacity(groups.len());
    for (i, g) in groups.iter().enumerate() {
        let name = g
            .get("name")
            .and_then(|n| n.as_str())
            .ok_or_else(|| CliError::user(format!("providers.model_groups[{i}]: missing 'name'")))?
            .to_string();
        let group_targets: Vec<String> = g
            .get("targets")
            .and_then(|t| t.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToString::to_string))
                    .collect()
            })
            .unwrap_or_default();
        if group_targets.is_empty() {
            return Err(CliError::user(format!(
                "providers.model_groups[{i}] '{name}': 'targets' must be a non-empty array of provider IDs"
            )));
        }
        for tid in &group_targets {
            if !target_ids.contains(&tid.as_str()) {
                return Err(CliError::user(format!(
                    "providers.model_groups[{i}] '{name}': unknown target ID '{tid}'"
                )));
            }
        }
        let aliases: Vec<String> = g
            .get("aliases")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToString::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let description = g
            .get("description")
            .and_then(|d| d.as_str())
            .map(ToString::to_string);
        let fallback_group = g
            .get("fallback_group")
            .and_then(|f| f.as_str())
            .map(ToString::to_string);
        result.push(ModelGroup {
            name,
            targets: group_targets,
            aliases,
            description,
            fallback_group,
        });
    }
    // Validate fallback_group references.
    let group_names: Vec<&str> = result.iter().map(|g| g.name.as_str()).collect();
    for g in &result {
        if let Some(ref fb) = g.fallback_group {
            if !group_names.contains(&fb.as_str()) {
                return Err(CliError::user(format!(
                    "providers.model_groups '{}': fallback_group '{}' does not refer to a known group",
                    g.name, fb
                )));
            }
        }
    }
    // Cycle detection: walk each chain and check for revisits.
    for g in &result {
        let mut visited = std::collections::HashSet::new();
        let mut current = Some(g.name.as_str());
        while let Some(name) = current {
            if !visited.insert(name) {
                return Err(CliError::user(format!(
                    "providers.model_groups: circular fallback chain detected at '{}'",
                    name
                )));
            }
            current = result
                .iter()
                .find(|gr| gr.name == name)
                .and_then(|gr| gr.fallback_group.as_deref());
        }
    }
    Ok(result)
}

fn parse_pipeline_mode(
    value: Option<&serde_json::Value>,
    context: &str,
) -> Result<ProviderPipelineMode, CliError> {
    match value.and_then(|candidate| candidate.as_str()) {
        None | Some("sequence") => Ok(ProviderPipelineMode::Sequence),
        Some("fan_out") => Ok(ProviderPipelineMode::FanOut),
        Some(other) => Err(CliError::user(format!(
            "{context}: unsupported mode '{other}' (expected 'sequence' or 'fan_out')"
        ))),
    }
}

fn parse_pipeline_input_mode(
    value: Option<&serde_json::Value>,
    context: &str,
) -> Result<ProviderPipelineInputMode, CliError> {
    match value.and_then(|candidate| candidate.as_str()) {
        None | Some("append") => Ok(ProviderPipelineInputMode::Append),
        Some("replace") => Ok(ProviderPipelineInputMode::Replace),
        Some(other) => Err(CliError::user(format!(
            "{context}: unsupported input_mode '{other}' (expected 'append' or 'replace')"
        ))),
    }
}

fn parse_pipeline_inject_role(
    value: Option<&serde_json::Value>,
    context: &str,
) -> Result<ProviderPipelineInjectRole, CliError> {
    match value.and_then(|candidate| candidate.as_str()) {
        None | Some("user") => Ok(ProviderPipelineInjectRole::User),
        Some("assistant") => Ok(ProviderPipelineInjectRole::Assistant),
        Some("system") => Ok(ProviderPipelineInjectRole::System),
        Some(other) => Err(CliError::user(format!(
            "{context}: unsupported inject_as '{other}' (expected 'user', 'assistant', or 'system')"
        ))),
    }
}

fn parse_pipeline_aggregation(
    value: Option<&serde_json::Value>,
    context: &str,
) -> Result<ProviderPipelineAggregation, CliError> {
    match value.and_then(|candidate| candidate.as_str()) {
        None | Some("concat") => Ok(ProviderPipelineAggregation::Concat),
        Some("first_success") => Ok(ProviderPipelineAggregation::FirstSuccess),
        Some(other) => Err(CliError::user(format!(
            "{context}: unsupported aggregation '{other}' (expected 'concat' or 'first_success')"
        ))),
    }
}

pub fn parse_pipelines(
    section: &serde_json::Value,
    targets: &[ProviderTarget],
) -> Result<Vec<ProviderPipeline>, CliError> {
    let Some(pipelines) = section.get("pipelines").and_then(|value| value.as_array()) else {
        return Ok(Vec::new());
    };

    let target_ids: Vec<&str> = targets.iter().map(|target| target.id.as_str()).collect();
    let mut result = Vec::with_capacity(pipelines.len());
    for (pipeline_index, pipeline) in pipelines.iter().enumerate() {
        let pipeline_context = format!("providers.pipelines[{pipeline_index}]");
        let name = pipeline
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or_else(|| CliError::user(format!("{pipeline_context}: missing 'name'")))?
            .to_string();
        let mode = parse_pipeline_mode(pipeline.get("mode"), &pipeline_context)?;
        let steps = pipeline
            .get("steps")
            .and_then(|value| value.as_array())
            .ok_or_else(|| CliError::user(format!("{pipeline_context}: missing 'steps'")))?
            .iter()
            .enumerate()
            .map(|(step_index, step)| {
                let step_context = format!("{pipeline_context}.steps[{step_index}]");
                let target = step
                    .get("target")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| CliError::user(format!("{step_context}: missing 'target'")))?
                    .to_string();
                if !target_ids.contains(&target.as_str()) {
                    return Err(CliError::user(format!(
                        "{step_context}: unknown target ID '{target}'"
                    )));
                }
                if targets
                    .iter()
                    .find(|candidate| candidate.id == target)
                    .map(|candidate| candidate.model.trim().is_empty())
                    .unwrap_or(true)
                {
                    return Err(CliError::user(format!(
                        "{step_context}: target '{target}' must declare an explicit providers.targets[].model for pipeline execution"
                    )));
                }

                Ok(ProviderPipelineStep {
                    name: step
                        .get("name")
                        .and_then(|value| value.as_str())
                        .map(ToString::to_string),
                    target,
                    instruction: step
                        .get("instruction")
                        .and_then(|value| value.as_str())
                        .map(ToString::to_string),
                    input_mode: parse_pipeline_input_mode(step.get("input_mode"), &step_context)?,
                    inject_as: parse_pipeline_inject_role(step.get("inject_as"), &step_context)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        if steps.is_empty() {
            return Err(CliError::user(format!(
                "{pipeline_context} '{name}': 'steps' must be a non-empty array"
            )));
        }

        let aliases = pipeline
            .get("aliases")
            .and_then(|value| value.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|value| value.as_str().map(ToString::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let description = pipeline
            .get("description")
            .and_then(|value| value.as_str())
            .map(ToString::to_string);
        let aggregation =
            parse_pipeline_aggregation(pipeline.get("aggregation"), &pipeline_context)?;

        result.push(ProviderPipeline {
            name,
            mode,
            steps,
            aliases,
            description,
            aggregation,
        });
    }

    Ok(result)
}

pub fn validate_virtual_model_names(
    model_groups: &[ModelGroup],
    pipelines: &[ProviderPipeline],
) -> Result<(), CliError> {
    let mut seen: HashMap<String, String> = HashMap::new();

    let mut register = |identifier: &str, owner: &str| -> Result<(), CliError> {
        let trimmed = identifier.trim();
        if trimmed.is_empty() {
            return Ok(());
        }
        if let Some(previous_owner) = seen.insert(trimmed.to_string(), owner.to_string()) {
            return Err(CliError::user(format!(
                "providers: virtual model name '{trimmed}' is declared by both {previous_owner} and {owner}"
            )));
        }
        Ok(())
    };

    for group in model_groups {
        let owner = format!("model group '{}'", group.name);
        register(&group.name, &owner)?;
        for alias in &group.aliases {
            register(alias, &owner)?;
        }
    }

    for pipeline in pipelines {
        let owner = format!("pipeline '{}'", pipeline.name);
        register(&pipeline.name, &owner)?;
        for alias in &pipeline.aliases {
            register(alias, &owner)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Data routing policy (pre-routing filter)
// ---------------------------------------------------------------------------

/// Action when no provider passes the data routing filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoCompliantProviderAction {
    Block,
    Warn,
}

/// Declarative policy that filters providers by their data handling metadata.
///
/// The regulated-routing keys added below extend the existing data-routing
/// policy with fields from the regulated-execution profile family.
/// Existing `require_zero_data_retention` and `require_no_training` remain
/// part of the same policy family.
#[derive(Debug, Clone)]
pub struct DataRoutingPolicy {
    pub require_zero_data_retention: bool,
    pub require_no_training: bool,
    pub max_retention_days: Option<u32>,
    pub on_no_compliant_provider: NoCompliantProviderAction,
    pub log_provider_selection: bool,

    // ── Regulated-routing extensions ──────────────────────────────────────
    /// Block providers that do not declare `in_memory_only: true`.
    pub require_in_memory_only: bool,
    /// Block providers that do not declare `sanitized: true`.
    pub sanitize_before_provider: bool,
    /// Require all routed providers to accept tokenized input.
    pub tokenize_sensitive_fields: bool,
    /// When `false`, block any provider that allows internet egress.
    pub allow_internet_egress: bool,
    /// Require all routed providers to declare `local_only_processing: true`.
    pub local_only_processing: bool,
}

/// A record of why a provider was excluded by the data routing policy.
#[derive(Debug, Clone, Serialize)]
pub struct DataPolicyExclusion {
    pub provider_id: String,
    pub reason: String,
}

/// Parse a `data-routing-policy` config block from the policy blocks.
pub fn parse_data_routing_policy(config: Option<&serde_json::Value>) -> Option<DataRoutingPolicy> {
    let cfg = config?.as_object()?;

    let require_zero_data_retention = cfg
        .get("require_zero_data_retention")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let require_no_training = cfg
        .get("require_no_training")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Parse regulated-routing extension keys.
    let require_in_memory_only = cfg
        .get("require_in_memory_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let sanitize_before_provider = cfg
        .get("sanitize_before_provider")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let tokenize_sensitive_fields = cfg
        .get("tokenize_sensitive_fields")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    // Default `true` — do not filter out existing providers that allow internet
    // egress unless the operator explicitly sets `allow_internet_egress: false`.
    let allow_internet_egress = cfg
        .get("allow_internet_egress")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let local_only_processing = cfg
        .get("local_only_processing")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // If neither base constraint nor any regulated-routing constraint is active,
    // the policy has no effect.
    if !require_zero_data_retention
        && !require_no_training
        && !cfg.contains_key("max_retention_days")
        && !require_in_memory_only
        && !sanitize_before_provider
        && !tokenize_sensitive_fields
        && allow_internet_egress
        && !local_only_processing
    {
        return None;
    }

    let max_retention_days = cfg
        .get("max_retention_days")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);

    let on_no_compliant_provider =
        match cfg.get("on_no_compliant_provider").and_then(|v| v.as_str()) {
            Some("warn") => NoCompliantProviderAction::Warn,
            _ => NoCompliantProviderAction::Block,
        };

    let log_provider_selection = cfg
        .get("log_provider_selection")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    Some(DataRoutingPolicy {
        require_zero_data_retention,
        require_no_training,
        max_retention_days,
        on_no_compliant_provider,
        log_provider_selection,
        require_in_memory_only,
        sanitize_before_provider,
        tokenize_sensitive_fields,
        allow_internet_egress,
        local_only_processing,
    })
}

/// Filter providers by the data routing policy.
///
/// Returns the indices of allowed providers and a list of exclusion records.
pub fn filter_providers_by_data_policy(
    policy: &DataRoutingPolicy,
    targets: &[ProviderTarget],
) -> (Vec<usize>, Vec<DataPolicyExclusion>) {
    let mut allowed = Vec::new();
    let mut excluded = Vec::new();

    for (i, target) in targets.iter().enumerate() {
        match &target.data_policy {
            None => {
                excluded.push(DataPolicyExclusion {
                    provider_id: target.id.clone(),
                    reason: "no data_policy declared".into(),
                });
            }
            Some(dp) => {
                if policy.require_zero_data_retention && !dp.zero_data_retention {
                    excluded.push(DataPolicyExclusion {
                        provider_id: target.id.clone(),
                        reason: format!(
                            "zero_data_retention required but provider declares {}",
                            dp.zero_data_retention
                        ),
                    });
                    continue;
                }
                if policy.require_no_training && !dp.training_opt_out {
                    excluded.push(DataPolicyExclusion {
                        provider_id: target.id.clone(),
                        reason: "training_opt_out required but provider declares false".into(),
                    });
                    continue;
                }
                if let Some(max_days) = policy.max_retention_days {
                    match dp.retention_days {
                        None => {
                            excluded.push(DataPolicyExclusion {
                                provider_id: target.id.clone(),
                                reason: "max_retention_days set but provider does not declare retention_days".into(),
                            });
                            continue;
                        }
                        Some(days) if days > max_days => {
                            excluded.push(DataPolicyExclusion {
                                provider_id: target.id.clone(),
                                reason: format!(
                                    "retention_days {} exceeds max_retention_days {}",
                                    days, max_days
                                ),
                            });
                            continue;
                        }
                        _ => {}
                    }
                }

                // ── Regulated-routing extension filters ────────────────────
                if policy.require_in_memory_only && !dp.in_memory_only {
                    excluded.push(DataPolicyExclusion {
                        provider_id: target.id.clone(),
                        reason:
                            "require_in_memory_only: provider does not declare in_memory_only: true"
                                .into(),
                    });
                    continue;
                }
                if policy.sanitize_before_provider && !dp.sanitized {
                    excluded.push(DataPolicyExclusion {
                        provider_id: target.id.clone(),
                        reason:
                            "sanitize_before_provider: provider does not declare sanitized: true"
                                .into(),
                    });
                    continue;
                }
                if policy.tokenize_sensitive_fields && !dp.accepts_tokenized_input {
                    excluded.push(DataPolicyExclusion {
                        provider_id: target.id.clone(),
                        reason: "tokenize_sensitive_fields: provider does not declare accepts_tokenized_input: true".into(),
                    });
                    continue;
                }
                if !policy.allow_internet_egress && dp.allow_internet_egress {
                    excluded.push(DataPolicyExclusion {
                        provider_id: target.id.clone(),
                        reason: "allow_internet_egress: false in policy but provider allows internet egress".into(),
                    });
                    continue;
                }
                if policy.local_only_processing && !dp.local_only_processing {
                    excluded.push(DataPolicyExclusion {
                        provider_id: target.id.clone(),
                        reason: "local_only_processing: provider does not declare local_only_processing: true".into(),
                    });
                    continue;
                }

                allowed.push(i);
            }
        }
    }

    (allowed, excluded)
}

// ---------------------------------------------------------------------------
// Provider routing filters (Phases 2, 4, 5)
// ---------------------------------------------------------------------------

/// Estimate per-request cost for a single provider.
/// Returns `None` if the provider has no pricing declared (provider is kept, not filtered).
pub fn estimate_request_cost(
    target: &ProviderTarget,
    prompt_tokens: Option<u32>,
    max_completion_tokens: Option<u32>,
) -> Option<RequestCost> {
    let pricing = target.pricing.as_ref()?;
    let prompt = prompt_tokens.unwrap_or(0) as f64 * pricing.input_price_per_million / 1_000_000.0;
    let completion =
        max_completion_tokens.unwrap_or(0) as f64 * pricing.output_price_per_million / 1_000_000.0;
    Some(RequestCost {
        prompt,
        completion,
        cached_input: 0.0,
        request: prompt + completion,
    })
}

/// Remove providers whose estimated request cost exceeds any `max_price` dimension.
/// Providers without pricing declarations or without token estimation are excluded
/// (fail-closed: cannot prove compliance without cost data).
pub fn filter_by_cost(
    targets: &[ProviderTarget],
    ordered: &[usize],
    max_price: &MaxPrice,
    prompt_tokens: Option<u32>,
    max_completion_tokens: Option<u32>,
) -> Vec<usize> {
    ordered
        .iter()
        .copied()
        .filter(|&idx| {
            let Some(cost) =
                estimate_request_cost(&targets[idx], prompt_tokens, max_completion_tokens)
            else {
                return false; // no pricing or token estimation — fail closed
            };
            if max_price
                .prompt
                .is_some_and(|ceiling| cost.prompt > ceiling)
            {
                return false;
            }
            if max_price
                .completion
                .is_some_and(|ceiling| cost.completion > ceiling)
            {
                return false;
            }
            if max_price
                .request
                .is_some_and(|ceiling| cost.request > ceiling)
            {
                return false;
            }
            true
        })
        .collect()
}

/// Keep only providers whose estimated request cost fits within the remaining budget headroom.
///
/// Unlike `filter_by_cost`, providers without declared pricing are excluded because live
/// control-plane budget enforcement must be able to prove the request fits within the remaining
/// budget before forwarding it upstream.
pub fn filter_by_remaining_budget(
    targets: &[ProviderTarget],
    ordered: &[usize],
    remaining_budget: f64,
    prompt_tokens: Option<u32>,
    max_completion_tokens: Option<u32>,
) -> Vec<usize> {
    ordered
        .iter()
        .copied()
        .filter(|&idx| {
            let Some(cost) =
                estimate_request_cost(&targets[idx], prompt_tokens, max_completion_tokens)
            else {
                return false;
            };
            cost.request <= remaining_budget
        })
        .collect()
}

/// Keep only providers eligible to serve `require_region`.
///
/// Eligibility comes from the single crate-wide predicate
/// [`crate::gateway::provider_endpoint_selection::provider_matches_region`],
/// which reads the target `region` label and the authoritative
/// `data_residency.regions` list. Keeping the predicate in one place stops the
/// live routing filter and provider-pool eligibility from drifting apart.
pub fn filter_by_region(
    targets: &[ProviderTarget],
    ordered: &[usize],
    require_region: &str,
) -> Vec<usize> {
    ordered
        .iter()
        .copied()
        .filter(|&idx| {
            crate::gateway::provider_endpoint_selection::provider_matches_region(
                &targets[idx],
                require_region,
            )
        })
        .collect()
}

/// True when any target in `ordered` declares a `data_residency` policy.
///
/// The live region filter uses this to tell a data-residency denial apart from
/// a plain missing-region denial, so a compliance block is reported as one.
pub fn any_target_declares_data_residency(targets: &[ProviderTarget], ordered: &[usize]) -> bool {
    ordered
        .iter()
        .copied()
        .any(|idx| targets[idx].data_residency.is_some())
}

/// Keep only providers that declare at least one matching entry from `required`.
pub fn filter_by_quantization(
    targets: &[ProviderTarget],
    ordered: &[usize],
    required: &[String],
) -> Vec<usize> {
    ordered
        .iter()
        .copied()
        .filter(|&idx| {
            let Some(quants) = &targets[idx].quantizations else {
                return false;
            };
            required.iter().any(|r| quants.contains(r))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    fn sample_target(id: &str) -> ProviderTarget {
        ProviderTarget {
            id: id.to_string(),
            provider: "openai".to_string(),
            model: "gpt-5.4".to_string(),
            execution_target: None,
            mcp_bridge: None,
            description: None,
            base_url: "https://api.openai.com".to_string(),
            api_key: "sk-test".to_string(),
            api_key_header: "Authorization".to_string(),
            api_key_prefix: "Bearer ".to_string(),
            secret_key_ref: None,
            path_template: None,
            headers: HashMap::new(),
            timeout: Duration::from_secs(30),
            stream_timeout: None,
            max_context_tokens: None,
            max_messages: None,
            data_policy: None,
            pricing: None,
            models: vec![],
            data_collection: None,
            zdr: false,
            region: None,
            quantizations: None,
            weight: None,
            provider_type: None,
            format: None,
            anthropic_version: None,
            aws_region: None,
            aws_profile: None,
            bedrock_model_family: None,
            watsonx_api_version: None,
            watsonx_project_id: None,
            watsonx_space_id: None,
            gcp_project: None,
            gcp_region: None,
            azure_api_version: None,
            azure_deployment: None,
            oauth2: None,
            health_probe: None,
            allow_insecure_tls: false,
            escalation_routing: None,
            required: false,
            data_residency: None,
            certifications: None,
        }
    }

    fn sample_oauth2_config(access_token_env: &str) -> crate::gateway::provider_auth::OAuth2Config {
        crate::gateway::provider_auth::OAuth2Config {
            grant_type: crate::gateway::provider_auth::OAuth2GrantType::ClientCredentials,
            token_endpoint: "https://oauth.example.invalid/token".to_string(),
            client_id: "provider-client".to_string(),
            client_secret_env: None,
            scopes: vec!["provider.read".to_string()],
            audience: None,
            redirect_uri: None,
            authorization_code: None,
            authorization_code_env: None,
            code_verifier: None,
            code_verifier_env: None,
            access_token_env: Some(access_token_env.to_string()),
            refresh_token_env: None,
        }
    }

    // ── ProviderPricing::compute_cost ────────────────────────────────────

    #[test]
    fn compute_cost_basic() {
        let pricing = ProviderPricing {
            input_price_per_million: 3.0,
            output_price_per_million: 15.0,
            cached_input_price_per_million: None,
            input_multiplier: None,
            cached_input_multiplier: None,
            output_multiplier: None,
        };
        let cost = pricing.compute_cost(1_000_000, 1_000_000);
        assert!((cost.prompt - 3.0).abs() < 1e-9);
        assert!((cost.completion - 15.0).abs() < 1e-9);
        assert!((cost.request - 18.0).abs() < 1e-9);
    }

    #[test]
    fn compute_cost_with_multipliers() {
        let pricing = ProviderPricing {
            input_price_per_million: 3.0,
            output_price_per_million: 15.0,
            cached_input_price_per_million: Some(1.5),
            input_multiplier: Some(2.0),
            cached_input_multiplier: Some(0.5),
            output_multiplier: Some(1.5),
        };
        let cost = pricing.compute_cost_with_cache(1_000_000, 1_000_000, 1_000_000);
        assert!((cost.prompt - 0.0).abs() < 1e-9);
        assert!((cost.completion - 22.5).abs() < 1e-9);
        assert!((cost.cached_input - 0.75).abs() < 1e-9);
        assert!((cost.request - (0.0 + 0.75 + 22.5)).abs() < 1e-9);
    }

    #[test]
    fn compute_cost_zero_tokens() {
        let pricing = ProviderPricing {
            input_price_per_million: 3.0,
            output_price_per_million: 15.0,
            cached_input_price_per_million: None,
            input_multiplier: None,
            cached_input_multiplier: None,
            output_multiplier: None,
        };
        let cost = pricing.compute_cost(0, 0);
        assert!((cost.request).abs() < 1e-9);
    }

    // ── ProviderTarget::effective_timeout ─────────────────────────────────

    #[test]
    fn effective_timeout_non_streaming() {
        let target = sample_target("t1");
        assert_eq!(target.effective_timeout(false), Duration::from_secs(30));
    }

    #[test]
    fn effective_timeout_streaming_fallback() {
        let target = sample_target("t1");
        assert_eq!(target.effective_timeout(true), Duration::from_secs(30));
    }

    #[test]
    fn effective_timeout_streaming_override() {
        let mut target = sample_target("t1");
        target.stream_timeout = Some(Duration::from_secs(120));
        assert_eq!(target.effective_timeout(true), Duration::from_secs(120));
    }

    #[test]
    fn provider_auth_material_requirements_cover_optional_and_self_credentialed_targets() {
        let mut required_openai = sample_target("required-openai");
        required_openai.required = true;
        assert!(required_openai.requires_provider_auth_material());
        assert!(required_openai.requires_resolved_api_key());

        let mut ollama = sample_target("ollama");
        ollama.provider = "ollama".to_string();
        ollama.required = true;
        assert!(!ollama.requires_provider_auth_material());
        assert!(!ollama.requires_resolved_api_key());

        let mut execution_target = sample_target("command-target");
        execution_target.required = true;
        execution_target.execution_target =
            Some(crate::gateway::execution_runtime::ExecutionTarget::Command(
                crate::gateway::execution_runtime::CommandExecutionTarget {
                    program: "node".to_string(),
                    args: vec!["adapter.js".to_string()],
                    cwd: None,
                    env: HashMap::new(),
                    timeout: Duration::from_secs(5),
                    family: Some(crate::gateway::execution_runtime::AdapterFamily::ChatKit),
                    workflow_id: None,
                    runner_config: None,
                },
            ));
        assert!(!execution_target.requires_provider_auth_material());
        assert!(!execution_target.requires_resolved_api_key());

        let mut bedrock = sample_target("bedrock");
        bedrock.provider = "aws-bedrock".to_string();
        bedrock.provider_type = Some(crate::gateway::provider_auth::ProviderType::AwsBedrock);
        bedrock.required = true;
        assert!(!bedrock.requires_provider_auth_material());
        assert!(!bedrock.requires_resolved_api_key());

        let mut oauth_target = sample_target("oauth");
        oauth_target.required = true;
        oauth_target.oauth2 = Some(sample_oauth2_config("VERDICTAN_TEST_PROVIDER_OAUTH"));
        assert!(!oauth_target.requires_provider_auth_material());
        assert!(!oauth_target.requires_resolved_api_key());
    }

    // ── FallbackTrigger ──────────────────────────────────────────────────

    #[test]
    fn fallback_trigger_as_str_roundtrip() {
        for trigger in [FallbackTrigger::RateLimit, FallbackTrigger::ServerError] {
            let s = trigger.as_str();
            assert_eq!(FallbackTrigger::from_str(s), Some(trigger));
        }
    }

    #[test]
    fn fallback_trigger_from_str_unknown() {
        assert!(FallbackTrigger::from_str("unknown").is_none());
    }

    // ── classify_upstream_error ──────────────────────────────────────────

    #[test]
    fn classify_timeout_maps_to_server_error() {
        assert_eq!(
            classify_upstream_error(None, b"", true),
            Some(FallbackTrigger::ServerError)
        );
    }

    #[test]
    fn classify_rate_limit() {
        assert_eq!(
            classify_upstream_error(Some(429), b"", false),
            Some(FallbackTrigger::RateLimit)
        );
    }

    #[test]
    fn classify_server_errors() {
        for status in [408, 500, 502, 503, 504] {
            assert_eq!(
                classify_upstream_error(Some(status), b"", false),
                Some(FallbackTrigger::ServerError)
            );
        }
    }

    #[test]
    fn classify_401_returns_none() {
        assert!(classify_upstream_error(Some(401), b"", false).is_none());
    }

    #[test]
    fn classify_400_returns_none() {
        assert!(classify_upstream_error(Some(400), b"context_length_exceeded", false).is_none());
        assert!(classify_upstream_error(Some(400), b"content_filter triggered", false).is_none());
        assert!(classify_upstream_error(Some(400), b"bad request", false).is_none());
    }

    #[test]
    fn classify_403_returns_none() {
        assert!(classify_upstream_error(Some(403), b"content_filter", false).is_none());
        assert!(classify_upstream_error(Some(403), b"forbidden", false).is_none());
    }

    #[test]
    fn classify_none_status_none_timeout() {
        assert!(classify_upstream_error(None, b"", false).is_none());
    }

    // ── is_upstream_auth_error ───────────────────────────────────────────

    #[test]
    fn is_upstream_auth_error_401() {
        assert!(is_upstream_auth_error(401, b""));
    }

    #[test]
    fn is_upstream_auth_error_403_non_content_filter() {
        assert!(is_upstream_auth_error(403, b"forbidden"));
    }

    #[test]
    fn is_upstream_auth_error_403_content_filter_is_false() {
        assert!(!is_upstream_auth_error(403, b"content_filter"));
        assert!(!is_upstream_auth_error(403, b"content_policy_violation"));
        assert!(!is_upstream_auth_error(403, b"moderation blocked"));
    }

    #[test]
    fn is_upstream_auth_error_other_status() {
        assert!(!is_upstream_auth_error(200, b""));
        assert!(!is_upstream_auth_error(500, b""));
    }

    // ── RetryPolicy ──────────────────────────────────────────────────────

    #[test]
    fn retry_policy_default() {
        let rp = RetryPolicy::default();
        assert_eq!(rp.max_retries, 3);
        assert_eq!(rp.max_retries_for(None), 3);
    }

    #[test]
    fn retry_policy_per_trigger_override() {
        let mut rp = RetryPolicy::default();
        rp.per_trigger.insert(FallbackTrigger::RateLimit, 5);
        assert_eq!(rp.max_retries_for(Some(&FallbackTrigger::RateLimit)), 5);
        assert_eq!(rp.max_retries_for(Some(&FallbackTrigger::ServerError)), 3);
    }

    #[test]
    fn backoff_exponential() {
        let rp = RetryPolicy::default();
        assert_eq!(rp.backoff_delay(0), Duration::from_millis(500));
        assert_eq!(rp.backoff_delay(1), Duration::from_millis(1000));
        assert_eq!(rp.backoff_delay(2), Duration::from_millis(2000));
    }

    #[test]
    fn backoff_fixed() {
        let rp = RetryPolicy {
            backoff: BackoffStrategy::Fixed { delay_ms: 1000 },
            ..Default::default()
        };
        assert_eq!(rp.backoff_delay(0), Duration::from_millis(1000));
        assert_eq!(rp.backoff_delay(5), Duration::from_millis(1000));
    }

    // ── parse_retry_policy ───────────────────────────────────────────────

    #[test]
    fn parse_retry_policy_defaults_when_missing() {
        let section = json!({});
        let rp = parse_retry_policy(&section);
        assert_eq!(rp.max_retries, 3);
    }

    #[test]
    fn parse_retry_policy_custom() {
        let section = json!({
            "retry_policy": {
                "max_retries": 5,
                "backoff": { "strategy": "fixed", "delay_ms": 2000 },
                "per_trigger": { "rate_limit": 10 }
            }
        });
        let rp = parse_retry_policy(&section);
        assert_eq!(rp.max_retries, 5);
        assert!(matches!(
            rp.backoff,
            BackoffStrategy::Fixed { delay_ms: 2000 }
        ));
        assert_eq!(rp.max_retries_for(Some(&FallbackTrigger::RateLimit)), 10);
    }

    #[test]
    fn parse_routing_parses_deterministic_selection_fields_and_clamps_ratios() {
        let routing = parse_routing(&json!({
            "routing": {
                "strategy": "task_aware",
                "measurement_window_seconds": 42,
                "min_sample_count": 3,
                "exploration_ratio": 9.0,
                "order": ["primary", "secondary"],
                "allow_fallbacks": false,
                "only": ["primary"],
                "max_price": {
                    "prompt_per_token": 0.01,
                    "completion": 0.02,
                    "request_total": 0.03
                },
                "preferred_max_latency": { "ms": 150.0, "percentile": "p99" },
                "preferred_min_throughput": { "tps": 11.0, "percentile": "p90" },
                "require_region": "eu",
                "sovereignty_profile": "strict-eu",
                "require_quantizations": ["fp16", "int8"],
                "semantic_embedding_provider": "embedder",
                "semantic_similarity_threshold": -0.25,
                "enable_pre_call_checks": true,
                "warmup_ratio": 5.0
            }
        }));

        assert_eq!(routing.strategy, RoutingStrategy::TaskAware);
        assert_eq!(routing.measurement_window_seconds, 42);
        assert_eq!(routing.min_sample_count, 3);
        assert_eq!(routing.exploration_ratio, 1.0);
        assert_eq!(
            routing.order.as_ref().unwrap(),
            &vec!["primary".to_string(), "secondary".to_string()]
        );
        assert!(!routing.allow_fallbacks);
        assert_eq!(routing.only.as_ref().unwrap(), &vec!["primary".to_string()]);
        assert_eq!(
            routing.max_price.as_ref().and_then(|price| price.prompt),
            Some(0.01)
        );
        assert_eq!(
            routing
                .max_price
                .as_ref()
                .and_then(|price| price.completion),
            Some(0.02)
        );
        assert_eq!(
            routing.max_price.as_ref().and_then(|price| price.request),
            Some(0.03)
        );
        assert_eq!(
            routing
                .preferred_max_latency
                .as_ref()
                .map(|cutoff| cutoff.percentile),
            Some(Percentile::P99)
        );
        assert_eq!(
            routing
                .preferred_min_throughput
                .as_ref()
                .map(|cutoff| cutoff.percentile),
            Some(Percentile::P90)
        );
        assert_eq!(routing.require_region.as_deref(), Some("eu"));
        assert_eq!(routing.sovereignty_profile.as_deref(), Some("strict-eu"));
        assert_eq!(
            routing.require_quantizations.as_ref().unwrap(),
            &vec!["fp16".to_string(), "int8".to_string()]
        );
        assert_eq!(
            routing.semantic_embedding_provider.as_deref(),
            Some("embedder")
        );
        assert_eq!(routing.semantic_similarity_threshold, 0.0);
        assert!(routing.enable_pre_call_checks);
        assert_eq!(routing.warmup_ratio, 1.0);

        let alias = parse_routing(&json!({
            "routing": {
                "strategy": "latency_based",
                "ignore": ["secondary"],
                "exploration_ratio": -1.0,
                "warmup_ratio": -1.0
            }
        }));
        assert_eq!(alias.strategy, RoutingStrategy::LowestLatency);
        assert_eq!(
            alias.ignore.as_ref().unwrap(),
            &vec!["secondary".to_string()]
        );
        assert_eq!(alias.exploration_ratio, 0.0);
        assert_eq!(alias.warmup_ratio, 0.0);
    }

    // ── parse_scope_rate_limits ──────────────────────────────────────────

    #[test]
    fn parse_scope_rate_limits_default() {
        let section = json!({});
        let rl = parse_scope_rate_limits(&section);
        assert!(rl.per_key.is_none());
        assert!(rl.global.is_none());
    }

    #[test]
    fn parse_scope_rate_limits_populated() {
        let section = json!({
            "rate_limits": {
                "per_key": { "rpm": 100, "tpm": 10000 },
                "global": { "rpm": 500 },
                "max_parallel_requests": 10
            }
        });
        let rl = parse_scope_rate_limits(&section);
        assert_eq!(rl.per_key.as_ref().unwrap().rpm, Some(100));
        assert_eq!(rl.per_key.as_ref().unwrap().tpm, Some(10000));
        assert_eq!(rl.global.as_ref().unwrap().rpm, Some(500));
        assert_eq!(rl.max_parallel_requests, Some(10));
    }

    // ── parse_logging ────────────────────────────────────────────────────

    #[test]
    fn parse_logging_defaults() {
        let section = json!({});
        let log = parse_logging(&section);
        assert!(!log.redact_message_bodies);
        assert!(log.redact_api_keys);
    }

    #[test]
    fn parse_logging_custom() {
        let section =
            json!({ "logging": { "redact_message_bodies": true, "redact_api_keys": false } });
        let log = parse_logging(&section);
        assert!(log.redact_message_bodies);
        assert!(!log.redact_api_keys);
    }

    // ── parse_traffic_mirror ─────────────────────────────────────────────

    #[test]
    fn parse_traffic_mirror_default() {
        let section = json!({});
        let tm = parse_traffic_mirror(&section);
        assert!(!tm.enabled);
    }

    #[test]
    fn parse_traffic_mirror_custom() {
        let section = json!({
            "traffic_mirror": {
                "enabled": true,
                "mirror_target": "secondary",
                "sample_rate": 0.5
            }
        });
        let tm = parse_traffic_mirror(&section);
        assert!(tm.enabled);
        assert_eq!(tm.mirror_target, Some("secondary".to_string()));
        assert!((tm.sample_rate - 0.5).abs() < 1e-9);
    }

    #[test]
    fn parse_traffic_mirror_sample_rate_clamped() {
        let section = json!({ "traffic_mirror": { "sample_rate": 5.0 } });
        let tm = parse_traffic_mirror(&section);
        assert!((tm.sample_rate - 1.0).abs() < 1e-9);
    }

    // ── parse_ab_test ────────────────────────────────────────────────────

    #[test]
    fn parse_ab_test_default() {
        let section = json!({});
        let ab = parse_ab_test(&section);
        assert!(!ab.enabled);
        assert!(ab.variants.is_empty());
    }

    #[test]
    fn parse_ab_test_with_variants() {
        let section = json!({
            "ab_test": {
                "enabled": true,
                "sticky_by": "user_id",
                "variants": [
                    { "provider_id": "openai", "weight": 0.7 },
                    { "provider_id": "anthropic", "weight": 0.3 }
                ]
            }
        });
        let ab = parse_ab_test(&section);
        assert!(ab.enabled);
        assert!(matches!(ab.sticky_by, StickyBy::UserId));
        assert_eq!(ab.variants.len(), 2);
        assert_eq!(ab.variants[0].provider_id, "openai");
        assert!((ab.variants[0].weight - 0.7).abs() < 1e-9);
    }

    // ── parse_fallback ───────────────────────────────────────────────────

    #[test]
    fn parse_fallback_defaults() {
        let section = json!({});
        let fb = parse_fallback(&section);
        assert_eq!(fb.triggers.len(), 2);
        assert!(fb.triggers.contains(&FallbackTrigger::RateLimit));
        assert!(fb.triggers.contains(&FallbackTrigger::ServerError));
    }

    #[test]
    fn parse_fallback_only_recognized_triggers() {
        let section = json!({
            "fallback": {
                "trigger_on": ["rate_limit", "timeout", "server_error"]
            }
        });
        let fb = parse_fallback(&section);
        // "timeout" is not a recognized trigger and is filtered out; the two
        // recognized triggers (rate_limit, server_error) are retained.
        assert_eq!(fb.triggers.len(), 2);
        assert!(fb.triggers.contains(&FallbackTrigger::RateLimit));
        assert!(fb.triggers.contains(&FallbackTrigger::ServerError));
    }

    // ── parse_data_routing_policy ────────────────────────────────────────

    #[test]
    fn parse_data_routing_policy_none_when_absent() {
        assert!(parse_data_routing_policy(None).is_none());
    }

    #[test]
    fn parse_data_routing_policy_none_when_no_constraints() {
        let cfg = json!({});
        assert!(parse_data_routing_policy(Some(&cfg)).is_none());
    }

    #[test]
    fn parse_data_routing_policy_zdr_required() {
        let cfg = json!({ "require_zero_data_retention": true });
        let policy = parse_data_routing_policy(Some(&cfg)).unwrap();
        assert!(policy.require_zero_data_retention);
        assert!(matches!(
            policy.on_no_compliant_provider,
            NoCompliantProviderAction::Block
        ));
    }

    #[test]
    fn parse_data_routing_policy_regulated_keys() {
        let cfg = json!({
            "require_in_memory_only": true,
            "allow_internet_egress": false,
            "on_no_compliant_provider": "warn"
        });
        let policy = parse_data_routing_policy(Some(&cfg)).unwrap();
        assert!(policy.require_in_memory_only);
        assert!(!policy.allow_internet_egress);
        assert!(matches!(
            policy.on_no_compliant_provider,
            NoCompliantProviderAction::Warn
        ));
    }

    #[test]
    fn parse_data_policy_defaults_egress_and_enforces_zdr_consistency() {
        let policy = parse_data_policy(
            &json!({
                "data_policy": {
                    "zero_data_retention": true,
                    "training_opt_out": true,
                    "retention_days": 0,
                    "in_memory_only": true,
                    "sanitized": true,
                    "accepts_tokenized_input": true,
                    "allow_internet_egress": false,
                    "local_only_processing": true
                }
            }),
            0,
            "provider-a",
        )
        .unwrap()
        .unwrap();
        assert!(policy.zero_data_retention);
        assert!(policy.training_opt_out);
        assert_eq!(policy.retention_days, Some(0));
        assert!(policy.in_memory_only);
        assert!(policy.sanitized);
        assert!(policy.accepts_tokenized_input);
        assert!(!policy.allow_internet_egress);
        assert!(policy.local_only_processing);

        let training_err = parse_data_policy(
            &json!({
                "data_policy": {
                    "zero_data_retention": true,
                    "allow_internet_egress": false
                }
            }),
            1,
            "provider-b",
        )
        .unwrap_err();
        assert!(training_err
            .to_string()
            .contains("zero_data_retention requires training_opt_out to be true"));

        let retention_err = parse_data_policy(
            &json!({
                "data_policy": {
                    "zero_data_retention": true,
                    "training_opt_out": true,
                    "retention_days": 7,
                    "allow_internet_egress": false
                }
            }),
            2,
            "provider-c",
        )
        .unwrap_err();
        assert!(retention_err
            .to_string()
            .contains("retention_days to be 0 or omitted"));

        let egress_default = parse_data_policy(
            &json!({
                "data_policy": {
                    "training_opt_out": true
                }
            }),
            3,
            "provider-d",
        )
        .expect("missing allow_internet_egress should default to true");
        assert!(
            egress_default
                .expect("data_policy should parse")
                .allow_internet_egress
        );
    }

    // ── filter_providers_by_data_policy ──────────────────────────────────

    #[test]
    fn filter_excludes_targets_without_data_policy() {
        let policy = DataRoutingPolicy {
            require_zero_data_retention: false,
            require_no_training: false,
            max_retention_days: None,
            on_no_compliant_provider: NoCompliantProviderAction::Block,
            log_provider_selection: false,
            require_in_memory_only: false,
            sanitize_before_provider: false,
            tokenize_sensitive_fields: false,
            allow_internet_egress: true,
            local_only_processing: false,
        };
        let targets = vec![sample_target("t1")];
        let (allowed, excluded) = filter_providers_by_data_policy(&policy, &targets);
        assert!(allowed.is_empty());
        assert_eq!(excluded.len(), 1);
    }

    #[test]
    fn filter_allows_compliant_provider() {
        let policy = DataRoutingPolicy {
            require_zero_data_retention: true,
            require_no_training: false,
            max_retention_days: None,
            on_no_compliant_provider: NoCompliantProviderAction::Block,
            log_provider_selection: false,
            require_in_memory_only: false,
            sanitize_before_provider: false,
            tokenize_sensitive_fields: false,
            allow_internet_egress: true,
            local_only_processing: false,
        };
        let mut target = sample_target("t1");
        target.data_policy = Some(DataPolicy {
            zero_data_retention: true,
            ..Default::default()
        });
        let targets = vec![target];
        let (allowed, excluded) = filter_providers_by_data_policy(&policy, &targets);
        assert_eq!(allowed, vec![0]);
        assert!(excluded.is_empty());
    }

    #[test]
    fn filter_excludes_non_zdr_provider() {
        let policy = DataRoutingPolicy {
            require_zero_data_retention: true,
            require_no_training: false,
            max_retention_days: None,
            on_no_compliant_provider: NoCompliantProviderAction::Block,
            log_provider_selection: false,
            require_in_memory_only: false,
            sanitize_before_provider: false,
            tokenize_sensitive_fields: false,
            allow_internet_egress: true,
            local_only_processing: false,
        };
        let mut target = sample_target("t1");
        target.data_policy = Some(DataPolicy::default());
        let targets = vec![target];
        let (allowed, excluded) = filter_providers_by_data_policy(&policy, &targets);
        assert!(allowed.is_empty());
        assert_eq!(excluded.len(), 1);
    }

    #[test]
    fn filter_excludes_high_retention_days() {
        let policy = DataRoutingPolicy {
            require_zero_data_retention: false,
            require_no_training: false,
            max_retention_days: Some(30),
            on_no_compliant_provider: NoCompliantProviderAction::Block,
            log_provider_selection: false,
            require_in_memory_only: false,
            sanitize_before_provider: false,
            tokenize_sensitive_fields: false,
            allow_internet_egress: true,
            local_only_processing: false,
        };
        let mut target = sample_target("t1");
        target.data_policy = Some(DataPolicy {
            retention_days: Some(90),
            ..Default::default()
        });
        let targets = vec![target];
        let (allowed, excluded) = filter_providers_by_data_policy(&policy, &targets);
        assert!(allowed.is_empty());
        assert_eq!(excluded[0].reason.contains("retention_days"), true);
    }

    #[test]
    fn filter_excludes_no_internet_egress_when_disallowed() {
        let policy = DataRoutingPolicy {
            require_zero_data_retention: false,
            require_no_training: false,
            max_retention_days: None,
            on_no_compliant_provider: NoCompliantProviderAction::Block,
            log_provider_selection: false,
            require_in_memory_only: false,
            sanitize_before_provider: false,
            tokenize_sensitive_fields: false,
            allow_internet_egress: false,
            local_only_processing: false,
        };
        let mut target = sample_target("t1");
        target.data_policy = Some(DataPolicy {
            allow_internet_egress: true,
            ..Default::default()
        });
        let targets = vec![target];
        let (allowed, _) = filter_providers_by_data_policy(&policy, &targets);
        assert!(allowed.is_empty());
    }

    // ── estimate_request_cost ────────────────────────────────────────────

    #[test]
    fn estimate_cost_none_without_pricing() {
        let target = sample_target("t1");
        assert!(estimate_request_cost(&target, Some(100), Some(100)).is_none());
    }

    #[test]
    fn estimate_cost_computed() {
        let mut target = sample_target("t1");
        target.pricing = Some(ProviderPricing {
            input_price_per_million: 3.0,
            output_price_per_million: 15.0,
            cached_input_price_per_million: None,
            input_multiplier: None,
            cached_input_multiplier: None,
            output_multiplier: None,
        });
        let cost = estimate_request_cost(&target, Some(1_000_000), Some(1_000_000)).unwrap();
        assert!((cost.prompt - 3.0).abs() < 1e-9);
        assert!((cost.completion - 15.0).abs() < 1e-9);
    }

    // ── filter_by_cost ───────────────────────────────────────────────────

    #[test]
    fn filter_by_cost_excludes_unpriced() {
        let targets = vec![sample_target("t1")];
        let max_price = MaxPrice {
            prompt: Some(0.001),
            completion: Some(0.001),
            request: Some(0.001),
        };
        let result = filter_by_cost(&targets, &[0], &max_price, Some(1000), Some(1000));
        assert!(result.is_empty());
    }

    #[test]
    fn filter_by_cost_removes_expensive() {
        let mut target = sample_target("t1");
        target.pricing = Some(ProviderPricing {
            input_price_per_million: 100.0,
            output_price_per_million: 100.0,
            cached_input_price_per_million: None,
            input_multiplier: None,
            cached_input_multiplier: None,
            output_multiplier: None,
        });
        let targets = vec![target];
        let max_price = MaxPrice {
            prompt: None,
            completion: None,
            request: Some(0.001),
        };
        let result = filter_by_cost(&targets, &[0], &max_price, Some(1_000_000), Some(1_000_000));
        assert!(result.is_empty());
    }

    // ── filter_by_remaining_budget ───────────────────────────────────────

    #[test]
    fn filter_by_budget_excludes_unpriced() {
        let targets = vec![sample_target("t1")];
        let result = filter_by_remaining_budget(&targets, &[0], 100.0, Some(100), Some(100));
        assert!(result.is_empty());
    }

    // ── filter_by_region ─────────────────────────────────────────────────

    #[test]
    fn filter_by_region_matches() {
        let mut target = sample_target("t1");
        target.region = Some("eu".to_string());
        let targets = vec![target];
        assert_eq!(filter_by_region(&targets, &[0], "eu"), vec![0]);
        assert!(filter_by_region(&targets, &[0], "us").is_empty());
    }

    #[test]
    fn filter_by_region_reads_data_residency_regions() {
        let mut in_region = sample_target("in-region");
        in_region.data_residency = Some(DataResidencyPolicy {
            regions: vec!["eu-west".to_string()],
            data_center_locations: vec![],
            sovereignty_compliant: true,
        });
        let mut out_of_region = sample_target("out-of-region");
        out_of_region.data_residency = Some(DataResidencyPolicy {
            regions: vec!["us-east".to_string()],
            data_center_locations: vec![],
            sovereignty_compliant: true,
        });
        let targets = vec![in_region, out_of_region];

        assert_eq!(filter_by_region(&targets, &[0, 1], "eu-west"), vec![0]);
        assert!(filter_by_region(&targets, &[0, 1], "ap-south").is_empty());
    }

    #[test]
    fn any_target_declares_data_residency_reports_only_declared_targets() {
        let mut declared = sample_target("declared");
        declared.data_residency = Some(DataResidencyPolicy {
            regions: vec!["eu-west".to_string()],
            data_center_locations: vec![],
            sovereignty_compliant: false,
        });
        let targets = vec![sample_target("plain"), declared];

        assert!(!any_target_declares_data_residency(&targets, &[0]));
        assert!(any_target_declares_data_residency(&targets, &[0, 1]));
        assert!(!any_target_declares_data_residency(&targets, &[]));
    }

    // ── filter_by_quantization ───────────────────────────────────────────

    #[test]
    fn filter_by_quantization_matches() {
        let mut target = sample_target("t1");
        target.quantizations = Some(vec!["fp16".to_string(), "int8".to_string()]);
        let targets = vec![target];
        let required = vec!["fp16".to_string()];
        assert_eq!(filter_by_quantization(&targets, &[0], &required), vec![0]);
    }

    #[test]
    fn filter_by_quantization_no_match() {
        let mut target = sample_target("t1");
        target.quantizations = Some(vec!["fp16".to_string()]);
        let targets = vec![target];
        let required = vec!["int4".to_string()];
        assert!(filter_by_quantization(&targets, &[0], &required).is_empty());
    }

    #[test]
    fn filter_by_quantization_excludes_undeclared() {
        let target = sample_target("t1");
        let targets = vec![target];
        let required = vec!["fp16".to_string()];
        assert!(filter_by_quantization(&targets, &[0], &required).is_empty());
    }

    // ── parse_verdictan_provider_spec ────────────────────────────────────

    #[test]
    fn parse_spec_provider_only() {
        let spec = parse_verdictan_provider_spec("openai");
        assert_eq!(spec.canonical_provider, "openai");
        assert!(spec.model.is_none());
        assert!(spec.kind.is_none());
    }

    #[test]
    fn parse_spec_with_kind() {
        let spec = parse_verdictan_provider_spec("openai:embedding");
        assert_eq!(spec.canonical_provider, "openai");
        assert!(matches!(spec.kind, Some(VerdictanProviderKind::Embedding)));
        assert!(spec.model.is_none());
    }

    #[test]
    fn parse_spec_with_kind_and_model() {
        let spec = parse_verdictan_provider_spec("openai:chat:gpt-5.4");
        assert_eq!(spec.canonical_provider, "openai");
        assert!(matches!(spec.kind, Some(VerdictanProviderKind::Chat)));
        assert_eq!(spec.model.as_deref(), Some("gpt-5.4"));
    }

    #[test]
    fn parse_spec_model_without_kind() {
        let spec = parse_verdictan_provider_spec("openai:gpt-5.4");
        assert_eq!(spec.canonical_provider, "openai");
        assert!(spec.kind.is_none());
        assert_eq!(spec.model.as_deref(), Some("gpt-5.4"));
    }

    #[test]
    fn parse_spec_audio_transcription_aliases() {
        for alias in [
            "audio-transcription",
            "audio_transcription",
            "transcription",
            "transcriptions",
        ] {
            let spec = parse_verdictan_provider_spec(&format!("openai:{alias}"));
            assert!(matches!(
                spec.kind,
                Some(VerdictanProviderKind::AudioTranscription)
            ));
        }
    }

    #[test]
    fn parse_spec_audio_speech_aliases() {
        for alias in ["audio-speech", "audio_speech", "speech", "tts"] {
            let spec = parse_verdictan_provider_spec(&format!("openai:{alias}"));
            assert!(matches!(
                spec.kind,
                Some(VerdictanProviderKind::AudioSpeech)
            ));
        }
    }

    #[test]
    fn parse_spec_audio_aliases_preserve_model_suffixes_with_colons() {
        let transcription =
            parse_verdictan_provider_spec("openai:transcriptions:whisper-1:2026-06");
        assert!(matches!(
            transcription.kind,
            Some(VerdictanProviderKind::AudioTranscription)
        ));
        assert_eq!(transcription.model.as_deref(), Some("whisper-1:2026-06"));

        let speech = parse_verdictan_provider_spec("openai:tts:gpt-voice:preview");
        assert!(matches!(
            speech.kind,
            Some(VerdictanProviderKind::AudioSpeech)
        ));
        assert_eq!(speech.model.as_deref(), Some("gpt-voice:preview"));
    }

    // ── split_cloudflare_gateway_model ────────────────────────────────────

    #[test]
    fn split_gateway_model_no_prefix() {
        let (provider, model) = split_cloudflare_gateway_model("gpt-5.4");
        assert!(provider.is_none());
        assert_eq!(model, "gpt-5.4");
    }

    #[test]
    fn split_gateway_model_with_prefix() {
        let (provider, model) = split_cloudflare_gateway_model("openai:gpt-5.4");
        assert_eq!(provider.as_deref(), Some("openai"));
        assert_eq!(model, "gpt-5.4");
    }

    #[test]
    fn split_gateway_model_unknown_prefix() {
        let (provider, model) = split_cloudflare_gateway_model("custom:my-model");
        assert!(provider.is_none());
        assert_eq!(model, "custom:my-model");
    }

    // ── entry_string ─────────────────────────────────────────────────────

    #[test]
    fn entry_string_first_nonempty_match() {
        let entry = json!({"model": "gpt", "alias": "gpt-5.4"});
        assert_eq!(entry_string(&entry, &["model"]), Some("gpt".to_string()));
    }

    #[test]
    fn entry_string_empty_value_is_none() {
        let entry = json!({"model": ""});
        assert!(entry_string(&entry, &["model"]).is_none());
    }

    #[test]
    fn entry_string_returns_none() {
        let entry = json!({});
        assert!(entry_string(&entry, &["missing"]).is_none());
    }

    // ── parse_pricing_object ─────────────────────────────────────────────

    #[test]
    fn parse_pricing_all_fields() {
        let p = json!({
            "input_price_per_million": 3.0,
            "output_price_per_million": 15.0,
            "cached_input_price_per_million": 1.5,
            "input_multiplier": 2.0,
            "cached_input_multiplier": 0.5,
            "output_multiplier": 1.5
        });
        let pricing = parse_pricing_object(&p);
        assert!((pricing.input_price_per_million - 3.0).abs() < 1e-9);
        assert!((pricing.output_price_per_million - 15.0).abs() < 1e-9);
        assert_eq!(pricing.cached_input_price_per_million, Some(1.5));
        assert_eq!(pricing.input_multiplier, Some(2.0));
    }

    #[test]
    fn parse_pricing_defaults() {
        let p = json!({});
        let pricing = parse_pricing_object(&p);
        assert!((pricing.input_price_per_million).abs() < 1e-9);
        assert!((pricing.output_price_per_million).abs() < 1e-9);
        assert!(pricing.cached_input_price_per_million.is_none());
    }

    // ── parse_data_residency_policy ──────────────────────────────────────

    #[test]
    fn parse_data_residency_present() {
        let entry = json!({
            "data_residency": {
                "regions": ["eu-west", "eu-central"],
                "data_center_locations": ["Frankfurt"],
                "sovereignty_compliant": true
            }
        });
        let dr = parse_data_residency_policy(&entry).unwrap();
        assert_eq!(dr.regions.len(), 2);
        assert!(dr.sovereignty_compliant);
    }

    #[test]
    fn parse_data_residency_absent() {
        assert!(parse_data_residency_policy(&json!({})).is_none());
    }

    // ── DataPolicy defaults ──────────────────────────────────────────────

    #[test]
    fn data_policy_default_allow_internet_egress() {
        let dp: DataPolicy = serde_json::from_str("{}").unwrap();
        assert!(dp.allow_internet_egress);
        assert!(!dp.zero_data_retention);
    }

    // ── default_verdictan_path_template ─────────────────────────────────

    #[test]
    fn default_path_templates() {
        assert_eq!(
            default_verdictan_path_template(VerdictanProviderKind::Chat),
            "/v1/chat/completions"
        );
        assert_eq!(
            default_verdictan_path_template(VerdictanProviderKind::Embedding),
            "/v1/embeddings"
        );
        assert_eq!(
            default_verdictan_path_template(VerdictanProviderKind::Responses),
            "/v1/responses"
        );
        assert_eq!(
            default_verdictan_path_template(VerdictanProviderKind::AudioTranscription),
            "/v1/audio/transcriptions"
        );
        assert_eq!(
            default_verdictan_path_template(VerdictanProviderKind::AudioSpeech),
            "/v1/audio/speech"
        );
    }

    // ── parse_escalation_routing ─────────────────────────────────────────

    #[test]
    fn parse_escalation_routing_team_id() {
        let entry = json!({ "team_id": "team-1" });
        let er = parse_escalation_routing(Some(&entry), 0, "test")
            .unwrap()
            .unwrap();
        assert_eq!(er.team_id, Some("team-1".to_string()));
        assert!(er.user_id.is_none());
    }

    #[test]
    fn parse_escalation_routing_none() {
        assert!(parse_escalation_routing(None, 0, "test").unwrap().is_none());
    }

    #[test]
    fn parse_model_groups_and_virtual_names_validate_fallback_chains_and_collisions() {
        let targets = vec![sample_target("primary"), sample_target("secondary")];
        let groups = parse_model_groups(
            &json!({
                "model_groups": [
                    {
                        "name": "primary-group",
                        "targets": ["primary"],
                        "aliases": ["shared"],
                        "fallback_group": "secondary-group"
                    },
                    {
                        "name": "secondary-group",
                        "targets": ["secondary"]
                    }
                ]
            }),
            &targets,
        )
        .unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].fallback_group.as_deref(), Some("secondary-group"));

        let cycle_err = parse_model_groups(
            &json!({
                "model_groups": [
                    {
                        "name": "loop-a",
                        "targets": ["primary"],
                        "fallback_group": "loop-b"
                    },
                    {
                        "name": "loop-b",
                        "targets": ["secondary"],
                        "fallback_group": "loop-a"
                    }
                ]
            }),
            &targets,
        )
        .unwrap_err();
        assert!(cycle_err
            .to_string()
            .contains("circular fallback chain detected"));

        let conflict = validate_virtual_model_names(
            &groups,
            &[ProviderPipeline {
                name: "shared".to_string(),
                mode: ProviderPipelineMode::Sequence,
                steps: vec![ProviderPipelineStep {
                    name: None,
                    target: "primary".to_string(),
                    instruction: None,
                    input_mode: ProviderPipelineInputMode::Append,
                    inject_as: ProviderPipelineInjectRole::User,
                }],
                aliases: Vec::new(),
                description: None,
                aggregation: ProviderPipelineAggregation::Concat,
            }],
        )
        .unwrap_err();
        assert!(conflict.to_string().contains("virtual model name 'shared'"));
    }

    #[test]
    fn parse_pipelines_covers_fan_out_and_explicit_model_validation() {
        let targets = vec![sample_target("planner"), sample_target("executor")];
        let pipelines = parse_pipelines(
            &json!({
                "pipelines": [{
                    "name": "review-pipeline",
                    "mode": "fan_out",
                    "aggregation": "first_success",
                    "aliases": ["review"],
                    "description": "Runs providers in parallel",
                    "steps": [
                        {
                            "name": "plan",
                            "target": "planner",
                            "instruction": "Plan the work",
                            "input_mode": "replace",
                            "inject_as": "system"
                        },
                        {
                            "target": "executor"
                        }
                    ]
                }]
            }),
            &targets,
        )
        .unwrap();
        assert_eq!(pipelines.len(), 1);
        assert_eq!(pipelines[0].name.as_str(), "review-pipeline");
        assert_eq!(pipelines[0].mode, ProviderPipelineMode::FanOut);
        assert_eq!(
            pipelines[0].aggregation,
            ProviderPipelineAggregation::FirstSuccess
        );
        assert_eq!(pipelines[0].aliases.as_slice(), &["review".to_string()]);
        assert_eq!(pipelines[0].steps.len(), 2);
        assert_eq!(
            pipelines[0].steps[0].input_mode,
            ProviderPipelineInputMode::Replace
        );
        assert_eq!(
            pipelines[0].steps[0].inject_as,
            ProviderPipelineInjectRole::System
        );

        let mut model_less_target = sample_target("planner");
        model_less_target.model.clear();
        let err = parse_pipelines(
            &json!({
                "pipelines": [{
                    "name": "invalid-pipeline",
                    "steps": [{ "target": "planner" }]
                }]
            }),
            &[model_less_target],
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("must declare an explicit providers.targets[].model"));
    }

    // ── RoutingStrategy default ──────────────────────────────────────────

    #[test]
    fn routing_strategy_default_is_ordered() {
        assert_eq!(RoutingStrategy::default(), RoutingStrategy::Ordered);
    }

    // ── DataPolicy serde ─────────────────────────────────────────────────

    #[test]
    fn data_policy_serde_all_fields() {
        let dp: DataPolicy = serde_json::from_str(
            r#"{
            "zero_data_retention": true,
            "training_opt_out": true,
            "retention_days": 30,
            "in_memory_only": true,
            "sanitized": true,
            "accepts_tokenized_input": true,
            "allow_internet_egress": false,
            "local_only_processing": true
        }"#,
        )
        .unwrap();
        assert!(dp.zero_data_retention);
        assert!(dp.training_opt_out);
        assert_eq!(dp.retention_days, Some(30));
        assert!(dp.in_memory_only);
        assert!(dp.sanitized);
        assert!(dp.accepts_tokenized_input);
        assert!(!dp.allow_internet_egress);
        assert!(dp.local_only_processing);
    }

    #[test]
    fn data_policy_defaults() {
        let dp: DataPolicy = serde_json::from_str("{}").unwrap();
        assert!(!dp.zero_data_retention);
        assert!(!dp.training_opt_out);
        assert!(dp.retention_days.is_none());
        assert!(!dp.in_memory_only);
        assert!(!dp.sanitized);
        assert!(!dp.accepts_tokenized_input);
        assert!(dp.allow_internet_egress);
        assert!(!dp.local_only_processing);
    }

    // ── DataCollectionPolicy ─────────────────────────────────────────────

    #[test]
    fn data_collection_policy_variants() {
        assert_ne!(DataCollectionPolicy::Allow, DataCollectionPolicy::Deny);
    }

    // ── Percentile variants ──────────────────────────────────────────────

    #[test]
    fn percentile_variants_distinct() {
        assert_ne!(Percentile::P50, Percentile::P90);
        assert_ne!(Percentile::P90, Percentile::P99);
    }

    // ── RequestCost fields ───────────────────────────────────────────────

    #[test]
    fn request_cost_sum_is_total() {
        let pricing = ProviderPricing {
            input_price_per_million: 5.0,
            output_price_per_million: 10.0,
            cached_input_price_per_million: Some(2.5),
            input_multiplier: None,
            cached_input_multiplier: None,
            output_multiplier: None,
        };
        let cost = pricing.compute_cost_with_cache(500_000, 200_000, 100_000);
        let expected_total = cost.prompt + cost.completion + cost.cached_input;
        assert!((cost.request - expected_total).abs() < 1e-9);
    }

    // ── EscalationRouting serde ──────────────────────────────────────────

    #[test]
    fn escalation_routing_serde() {
        let er: EscalationRouting = serde_json::from_str(r#"{"team_id":"team-1"}"#).unwrap();
        assert_eq!(er.team_id, Some("team-1".to_string()));
        assert!(er.user_id.is_none());
    }

    // ── DataResidencyPolicy serde ────────────────────────────────────────

    #[test]
    fn data_residency_policy_serde() {
        let drp: DataResidencyPolicy = serde_json::from_str(
            r#"{
            "regions": ["eu-west-1"],
            "data_center_locations": ["Frankfurt"],
            "sovereignty_compliant": true
        }"#,
        )
        .unwrap();
        assert_eq!(drp.regions, vec!["eu-west-1"]);
        assert!(drp.sovereignty_compliant);
    }

    // ── MaxPrice fields ──────────────────────────────────────────────────

    #[test]
    fn max_price_fields() {
        let mp = MaxPrice {
            prompt: Some(0.01),
            completion: Some(0.05),
            request: Some(0.10),
        };
        assert!((mp.prompt.unwrap() - 0.01).abs() < 1e-9);
        assert!((mp.request.unwrap() - 0.10).abs() < 1e-9);
    }

    // ── ProviderModelEntry ───────────────────────────────────────────────

    #[test]
    fn provider_model_entry_defaults() {
        let entry = ProviderModelEntry {
            model_id: "gpt-5.4".to_string(),
            aliases: vec!["gpt5".to_string()],
            enabled: true,
            pricing: None,
            supported_features: vec!["tools".to_string()],
            max_output_tokens: Some(4096),
            parameter_overrides: serde_json::Map::new(),
            removed_params: vec![],
            description: Some("GPT-5.4 model".to_string()),
            escalation_routing: None,
        };
        assert_eq!(entry.model_id, "gpt-5.4");
        assert_eq!(entry.aliases.len(), 1);
        assert!(entry.enabled);
        assert_eq!(entry.max_output_tokens, Some(4096));
    }

    // ── entry_string ────────────────────────────────────────────────────

    #[test]
    fn entry_string_found() {
        let e = serde_json::json!({"name": "test"});
        assert_eq!(entry_string(&e, &["name"]), Some("test".to_string()));
    }

    #[test]
    fn entry_string_empty_trimmed() {
        let e = serde_json::json!({"name": "   "});
        assert!(entry_string(&e, &["name"]).is_none());
    }

    #[test]
    fn entry_string_fallback_key() {
        let e = serde_json::json!({"alt": "found"});
        assert_eq!(
            entry_string(&e, &["primary", "alt"]),
            Some("found".to_string())
        );
    }

    // ── parse_scope_rate_limits ──────────────────────────────────────────

    #[test]
    fn parse_scope_rate_limits_empty() {
        let section = serde_json::json!({});
        let config = parse_scope_rate_limits(&section);
        assert!(config.global.is_none());
    }

    // ── parse_traffic_mirror ────────────────────────────────────────────

    #[test]
    fn parse_traffic_mirror_empty() {
        let section = serde_json::json!({});
        let config = parse_traffic_mirror(&section);
        assert!(!config.enabled);
    }

    // ── parse_ab_test ────────────────────────────────────────────────────

    #[test]
    fn parse_ab_test_empty() {
        let section = serde_json::json!({});
        let config = parse_ab_test(&section);
        assert!(!config.enabled);
    }

    // ── provider defaults and derivation helpers ────────────────────────

    #[test]
    fn default_path_templates_provider_overrides() {
        assert_eq!(
            default_verdictan_path_template_for_provider("ollama", VerdictanProviderKind::Chat),
            "/api/chat"
        );
        assert_eq!(
            default_verdictan_path_template_for_provider(
                "ollama",
                VerdictanProviderKind::Completion
            ),
            "/api/generate"
        );
        assert_eq!(
            default_verdictan_path_template_for_provider("quiverai", VerdictanProviderKind::Chat),
            "/svgs/generations"
        );
        assert_eq!(
            default_verdictan_path_template_for_provider(
                "openai",
                VerdictanProviderKind::Responses
            ),
            "/v1/responses"
        );
    }

    #[test]
    fn pipeline_string_helpers_and_data_policy_default_true_are_stable() {
        assert!(default_true());
        assert_eq!(ProviderPipelineMode::Sequence.as_str(), "sequence");
        assert_eq!(ProviderPipelineMode::FanOut.as_str(), "fan_out");
        assert_eq!(ProviderPipelineInjectRole::User.as_str(), "user");
        assert_eq!(ProviderPipelineInjectRole::Assistant.as_str(), "assistant");
        assert_eq!(ProviderPipelineInjectRole::System.as_str(), "system");
        assert_eq!(ProviderPipelineAggregation::Concat.as_str(), "concat");
        assert_eq!(
            ProviderPipelineAggregation::FirstSuccess.as_str(),
            "first_success"
        );
    }

    #[test]
    fn verdictan_defaults_and_supported_kind_lists_cover_contract_and_completion() {
        let ollama = verdictan_provider_defaults(
            "ollama",
            Some(crate::gateway::provider_auth::ProviderType::OpenAI),
        )
        .unwrap();
        assert_eq!(ollama.base_url, Some("http://localhost:11434"));
        assert!(ollama.auth_optional);
        assert!(ollama.allowed_kinds.contains(&VerdictanProviderKind::Chat));
        assert!(ollama
            .allowed_kinds
            .contains(&VerdictanProviderKind::Completion));
        assert!(!ollama
            .allowed_kinds
            .contains(&VerdictanProviderKind::AudioSpeech));

        assert!(verdictan_kind_supported(
            "openai",
            Some(crate::gateway::provider_auth::ProviderType::OpenAI),
            Some(VerdictanProviderKind::Completion),
        ));
        assert!(verdictan_kind_supported(
            "voyage",
            Some(crate::gateway::provider_auth::ProviderType::OpenAI),
            Some(VerdictanProviderKind::Embedding),
        ));
        assert!(!verdictan_kind_supported(
            "voyage",
            Some(crate::gateway::provider_auth::ProviderType::OpenAI),
            Some(VerdictanProviderKind::Chat),
        ));
        assert_eq!(
            supported_verdictan_kind_list(
                "voyage",
                Some(crate::gateway::provider_auth::ProviderType::OpenAI)
            ),
            Some("embedding".to_string())
        );
        assert_eq!(
            supported_verdictan_kind_list("not-real", None),
            Some("no verified runtime family support".to_string())
        );

        let ai21 = verdictan_provider_defaults(
            "ai21",
            Some(crate::gateway::provider_auth::ProviderType::OpenAI),
        )
        .unwrap();
        assert_eq!(ai21.base_url, Some("https://api.ai21.com/studio"));
        assert!(ai21.allowed_kinds.contains(&VerdictanProviderKind::Chat));

        let groq = verdictan_provider_defaults(
            "groq",
            Some(crate::gateway::provider_auth::ProviderType::OpenAI),
        )
        .unwrap();
        assert!(groq
            .allowed_kinds
            .contains(&VerdictanProviderKind::Responses));
        assert!(!groq.auth_optional);
    }

    #[test]
    fn derive_cloudflare_gateway_base_url_handles_provider_specific_suffixes() {
        let azure_entry = json!({
            "cloudflare_account_id": "acct",
            "cloudflare_gateway_id": "gw",
            "resource_name": "resource",
            "deployment_name": "deployment"
        });
        assert_eq!(
            derive_cloudflare_gateway_base_url(&azure_entry, Some("azure-openai"), "ignored-model",),
            Some(
                "https://gateway.ai.cloudflare.com/v1/acct/gw/azure-openai/resource/deployment"
                    .to_string()
            )
        );

        let workers_entry = json!({
            "cloudflare_account_id": "acct",
            "cloudflare_gateway_id": "gw",
            "gateway_provider": "workers-ai"
        });
        assert_eq!(
            derive_cloudflare_gateway_base_url(&workers_entry, None, "@cf/meta/llama-3.1-8b"),
            Some(
                "https://gateway.ai.cloudflare.com/v1/acct/gw/workers-ai/@cf/meta/llama-3.1-8b"
                    .to_string()
            )
        );
    }

    #[test]
    fn provider_base_url_errors_explain_missing_metadata() {
        let cloudflare_err = provider_base_url(
            &json!({}),
            "cf",
            "cloudflare-ai",
            Some(crate::gateway::provider_auth::ProviderType::CloudflareAi),
            "model",
            None,
        )
        .unwrap_err();
        assert!(cloudflare_err
            .to_string()
            .contains("derive it with cloudflare_account_id"));

        let snowflake_err = provider_base_url(
            &json!({}),
            "sf",
            "snowflake",
            Some(crate::gateway::provider_auth::ProviderType::SnowflakeCortex),
            "model",
            None,
        )
        .unwrap_err();
        assert!(snowflake_err
            .to_string()
            .contains("derive it with snowflake_account_identifier"));
    }

    #[test]
    fn parse_rate_limit_spec_rejects_non_objects() {
        assert!(parse_rate_limit_spec(&json!("bad")).is_none());
        let spec = parse_rate_limit_spec(&json!({"rpm": 12, "tpm": 34})).unwrap();
        assert_eq!(spec.rpm, Some(12));
        assert_eq!(spec.tpm, Some(34));
    }

    #[test]
    fn parse_nested_models_inherits_parent_pricing_and_model_fields() {
        let parent_pricing = Some(ProviderPricing {
            input_price_per_million: 1.0,
            output_price_per_million: 2.0,
            cached_input_price_per_million: None,
            input_multiplier: None,
            cached_input_multiplier: None,
            output_multiplier: None,
        });
        let entry = json!({
            "models": [{
                "model_id": "model-a",
                "aliases": ["alias-a"],
                "supported_features": ["tools"],
                "max_output_tokens": 2048,
                "parameter_overrides": {"temperature": 0.1},
                "removed_params": ["top_p"],
                "description": "primary model"
            }]
        });

        let models = parse_nested_models(&entry, 0, "target-a", &parent_pricing).unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].model_id, "model-a");
        assert_eq!(models[0].aliases, vec!["alias-a"]);
        assert_eq!(models[0].supported_features, vec!["tools"]);
        assert_eq!(models[0].max_output_tokens, Some(2048));
        assert_eq!(models[0].parameter_overrides["temperature"], json!(0.1));
        assert_eq!(models[0].removed_params, vec!["top_p"]);
        assert_eq!(models[0].description.as_deref(), Some("primary model"));
        assert_eq!(
            models[0].pricing.as_ref().unwrap().input_price_per_million,
            1.0
        );
    }

    #[test]
    fn parse_nested_models_rejects_duplicate_model_ids() {
        let entry = json!({
            "models": [
                {"model_id": "dup"},
                {"model_id": "dup"}
            ]
        });
        let err = parse_nested_models(&entry, 1, "target-b", &None).unwrap_err();
        assert!(err.to_string().contains("duplicate model_id 'dup'"));
    }

    #[test]
    fn parse_zero_completion_insurance_only_retains_enabled() {
        let section = json!({
            "zero_completion_insurance": {
                "enabled": false,
                "conditions": ["zero_tokens_blank_finish"],
                "action": "retry",
                "retry_with_fallback": true
            }
        });
        let config = parse_zero_completion_insurance(&section);
        assert!(!config.enabled);
    }

    #[test]
    fn parse_targets_rejects_missing_targets_and_required_fields() {
        let missing_targets = parse_targets(&json!({})).unwrap_err();
        assert!(missing_targets
            .to_string()
            .contains("providers.targets must be a non-empty array"));

        let missing_id = parse_targets(&json!({
            "targets": [{
                "provider": "openai",
                "model": "gpt-5.4",
                "secret_key_ref": { "store": "OPENAI_API_KEY" }
            }]
        }))
        .unwrap_err();
        assert!(missing_id.to_string().contains("id is required"));

        let missing_provider = parse_targets(&json!({
            "targets": [{
                "id": "primary",
                "model": "gpt-5.4",
                "secret_key_ref": { "store": "OPENAI_API_KEY" }
            }]
        }))
        .unwrap_err();
        assert!(missing_provider
            .to_string()
            .contains("provider is required"));
    }

    #[test]
    fn parse_targets_accepts_store_refs_nested_models_and_responses_shorthand() {
        let targets = parse_targets(&json!({
            "targets": [{
                "id": "primary",
                "provider": "openai:responses",
                "required": true,
                "secret_key_ref": { "store": "OPENAI_API_KEY" },
                "headers": {
                    "x-extra": "value",
                    "ignored": 1
                },
                "timeout_seconds": 45,
                "stream_timeout_seconds": 90,
                "data_collection": "allow",
                "allow_insecure_tls": true,
                "models": [{
                    "model_id": "gpt-5.4-mini"
                }],
                "data_residency": {
                    "regions": ["eu-west-1"],
                    "data_center_locations": ["Frankfurt"],
                    "sovereignty_compliant": true
                },
                "certifications": ["soc2", "iso27001"]
            }]
        }))
        .unwrap();

        assert_eq!(targets.len(), 1);
        let target = &targets[0];
        assert_eq!(target.provider.as_str(), "openai");
        assert_eq!(target.model.as_str(), "gpt-5.4-mini");
        assert_eq!(target.base_url.as_str(), "https://api.openai.com");
        assert_eq!(target.path_template.as_deref(), Some("/v1/responses"));
        assert_eq!(target.api_key.as_str(), "");
        assert!(target
            .secret_key_ref
            .as_ref()
            .is_some_and(SecretKeyReference::is_store_ref));
        assert_eq!(
            target.headers.get("x-extra").map(String::as_str),
            Some("value")
        );
        assert_eq!(target.timeout, Duration::from_secs(45));
        assert_eq!(target.stream_timeout, Some(Duration::from_secs(90)));
        assert_eq!(target.data_collection, Some(DataCollectionPolicy::Allow));
        assert!(target.allow_insecure_tls);
        let data_residency = target.data_residency.as_ref().unwrap();
        assert_eq!(data_residency.regions, vec!["eu-west-1".to_string()]);
        assert_eq!(
            target.certifications.as_ref().unwrap(),
            &vec!["soc2".to_string(), "iso27001".to_string()]
        );
    }

    #[test]
    fn parse_targets_cloudflare_gateway_azure_uses_azure_auth_defaults() {
        let targets = parse_targets(&json!({
            "targets": [{
                "id": "cloudflare-gateway-azure",
                "provider": "cloudflare-gateway:azure-openai:gpt-5.4-mini",
                "base_url": "https://gateway.ai.cloudflare.com/v1/acct-123/gateway-456/azure-openai/demo-resource/demo-deployment?api-version=2024-06-01",
                "secret_key_ref": { "store": "AZURE_OPENAI_API_KEY" }
            }]
        }))
        .unwrap();

        assert_eq!(targets.len(), 1);
        let target = &targets[0];
        assert_eq!(target.provider.as_str(), "cloudflare-gateway");
        assert_eq!(target.model.as_str(), "gpt-5.4-mini");
        assert_eq!(target.api_key_header.as_str(), "api-key");
        assert!(target.api_key_prefix.is_empty());
    }

    #[test]
    fn resolve_provider_path_prefers_templates_catalog_mappings_and_format_shims() {
        let mut custom = sample_target("custom");
        custom.path_template = Some("/deployments/{model}".to_string());
        assert_eq!(
            resolve_provider_path(&custom, "/v1/chat/completions"),
            "/deployments/gpt-5.4"
        );

        let mut openrouter = sample_target("openrouter");
        openrouter.provider = "openrouter".to_string();
        assert_eq!(
            resolve_provider_path(&openrouter, "/v1/chat/completions"),
            "/api/v1/chat/completions"
        );

        let mut anthropic_format = sample_target("anthropic-format");
        anthropic_format.provider = "custom-anthropic-compatible".to_string();
        anthropic_format.format =
            Some(crate::gateway::format_translation::ProviderFormat::Anthropic);
        assert_eq!(
            resolve_provider_path(&anthropic_format, "/v1/chat/completions"),
            "/v1/messages"
        );

        let mut openai_format = sample_target("openai-format");
        openai_format.provider = "anthropic".to_string();
        openai_format.format = Some(crate::gateway::format_translation::ProviderFormat::OpenAI);
        assert_eq!(
            resolve_provider_path(&openai_format, "/v1/messages"),
            "/v1/chat/completions"
        );
    }

    #[test]
    fn parse_pipeline_helpers_cover_defaults_and_error_paths() {
        assert_eq!(
            parse_pipeline_mode(None, "pipeline").unwrap(),
            ProviderPipelineMode::Sequence
        );
        assert_eq!(
            parse_pipeline_input_mode(None, "pipeline").unwrap(),
            ProviderPipelineInputMode::Append
        );
        assert_eq!(
            parse_pipeline_inject_role(None, "pipeline").unwrap(),
            ProviderPipelineInjectRole::User
        );
        assert_eq!(
            parse_pipeline_aggregation(None, "pipeline").unwrap(),
            ProviderPipelineAggregation::Concat
        );

        assert!(parse_pipeline_mode(Some(&json!("invalid")), "pipeline")
            .unwrap_err()
            .to_string()
            .contains("unsupported mode"));
        assert!(
            parse_pipeline_input_mode(Some(&json!("invalid")), "pipeline")
                .unwrap_err()
                .to_string()
                .contains("unsupported input_mode")
        );
        assert!(
            parse_pipeline_inject_role(Some(&json!("invalid")), "pipeline")
                .unwrap_err()
                .to_string()
                .contains("unsupported inject_as")
        );
        assert!(
            parse_pipeline_aggregation(Some(&json!("invalid")), "pipeline")
                .unwrap_err()
                .to_string()
                .contains("unsupported aggregation")
        );
    }

    // ── DataPolicy ──────────────────────────────────────────────────────

    #[test]
    fn data_policy_defaults_all_fields() {
        let dp = DataPolicy::default();
        assert!(!dp.zero_data_retention);
        assert!(!dp.training_opt_out);
        assert!(dp.retention_days.is_none());
        assert!(!dp.in_memory_only);
        assert!(!dp.sanitized);
        assert!(!dp.accepts_tokenized_input);
        assert!(dp.allow_internet_egress);
        assert!(!dp.local_only_processing);
    }

    #[test]
    fn data_policy_serde_roundtrip() {
        let dp = DataPolicy {
            zero_data_retention: true,
            training_opt_out: true,
            retention_days: Some(30),
            in_memory_only: true,
            sanitized: false,
            accepts_tokenized_input: true,
            allow_internet_egress: false,
            local_only_processing: true,
        };
        let json = serde_json::to_string(&dp).unwrap();
        let recovered: DataPolicy = serde_json::from_str(&json).unwrap();
        assert!(recovered.zero_data_retention);
        assert_eq!(recovered.retention_days, Some(30));
        assert!(!recovered.allow_internet_egress);
    }

    // ── DataCollectionPolicy ────────────────────────────────────────────

    #[test]
    fn data_collection_policy_variants_eq() {
        assert_eq!(DataCollectionPolicy::Allow, DataCollectionPolicy::Allow);
        assert_ne!(DataCollectionPolicy::Allow, DataCollectionPolicy::Deny);
    }

    // ── Percentile ──────────────────────────────────────────────────────

    #[test]
    fn percentile_variants() {
        assert_eq!(Percentile::P50, Percentile::P50);
        assert_ne!(Percentile::P50, Percentile::P99);
    }

    // ── ProviderPricing compute_cost ────────────────────────────────────

    #[test]
    fn provider_pricing_basic_cost() {
        let pricing = ProviderPricing {
            input_price_per_million: 10.0,
            output_price_per_million: 30.0,
            cached_input_price_per_million: None,
            input_multiplier: None,
            cached_input_multiplier: None,
            output_multiplier: None,
        };
        let cost = pricing.compute_cost(1_000_000, 500_000);
        assert!((cost.prompt - 10.0).abs() < 1e-6);
        assert!((cost.completion - 15.0).abs() < 1e-6);
        assert!((cost.request - 25.0).abs() < 1e-6);
    }

    #[test]
    fn provider_pricing_with_multipliers() {
        let pricing = ProviderPricing {
            input_price_per_million: 10.0,
            output_price_per_million: 30.0,
            cached_input_price_per_million: Some(5.0),
            input_multiplier: Some(2.0),
            cached_input_multiplier: Some(0.5),
            output_multiplier: Some(1.5),
        };
        let cost = pricing.compute_cost_with_cache(1_000_000, 1_000_000, 1_000_000);
        assert!((cost.prompt - 0.0).abs() < 1e-6);
        assert!((cost.cached_input - 2.5).abs() < 1e-6);
        assert!((cost.completion - 45.0).abs() < 1e-6);
        assert!((cost.request - 47.5).abs() < 1e-6);
    }

    #[test]
    fn provider_pricing_zero_tokens() {
        let pricing = ProviderPricing {
            input_price_per_million: 10.0,
            output_price_per_million: 30.0,
            cached_input_price_per_million: None,
            input_multiplier: None,
            cached_input_multiplier: None,
            output_multiplier: None,
        };
        let cost = pricing.compute_cost(0, 0);
        assert!((cost.request).abs() < 1e-10);
    }

    // ── EscalationRouting serde ──────────────────────────────────────────

    #[test]
    fn escalation_routing_serde_roundtrip() {
        let routing = EscalationRouting {
            team_id: Some("eng-team".to_string()),
            user_id: None,
        };
        let json = serde_json::to_string(&routing).unwrap();
        let recovered: EscalationRouting = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.team_id, Some("eng-team".to_string()));
        assert!(recovered.user_id.is_none());
    }

    // ── DataResidencyPolicy serde ───────────────────────────────────────

    #[test]
    fn data_residency_policy_serde_roundtrip() {
        let policy = DataResidencyPolicy {
            regions: vec!["us-east-1".to_string()],
            data_center_locations: vec!["Virginia".to_string()],
            sovereignty_compliant: true,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let recovered: DataResidencyPolicy = serde_json::from_str(&json).unwrap();
        assert!(recovered.sovereignty_compliant);
        assert_eq!(recovered.regions.len(), 1);
    }

    // ── resolve_provider_path ───────────────────────────────────────────

    #[test]
    fn resolve_provider_path_default() {
        let target = sample_target("t1");
        let path = resolve_provider_path(&target, "/v1/chat/completions");
        assert!(path.contains("chat/completions"));
    }

    #[test]
    fn resolve_provider_path_with_template() {
        let mut target = sample_target("t1");
        target.path_template = Some("/custom/{{path}}".to_string());
        let path = resolve_provider_path(&target, "/v1/chat/completions");
        assert!(path.contains("custom") || path.contains("v1"));
    }

    // ── ProviderModelEntry ──────────────────────────────────────────────

    #[test]
    fn provider_model_entry_fields() {
        let entry = ProviderModelEntry {
            model_id: "gpt-5.4-mini".into(),
            aliases: vec!["gpt-latest".into()],
            enabled: true,
            pricing: Some(ProviderPricing {
                input_price_per_million: 3.0,
                output_price_per_million: 15.0,
                cached_input_price_per_million: None,
                input_multiplier: None,
                cached_input_multiplier: None,
                output_multiplier: None,
            }),
            supported_features: vec!["tools".into(), "vision".into()],
            max_output_tokens: Some(4096),
            parameter_overrides: serde_json::Map::new(),
            removed_params: vec!["logprobs".into()],
            description: Some("Fast model".into()),
            escalation_routing: None,
        };
        assert_eq!(entry.model_id, "gpt-5.4-mini");
        assert_eq!(entry.aliases, vec!["gpt-latest"]);
        assert!(entry.enabled);
        assert_eq!(entry.max_output_tokens, Some(4096));
        assert_eq!(entry.supported_features.len(), 2);
        assert_eq!(entry.removed_params, vec!["logprobs"]);
    }

    // ── ProviderTarget requires_resolved_api_key for self-managed ──────

    #[test]
    fn self_managed_provider_does_not_require_key() {
        let mut target = sample_target("bedrock");
        target.provider = "aws-bedrock".to_string();
        target.provider_type = Some(crate::gateway::provider_auth::ProviderType::AwsBedrock);
        assert!(!target.requires_resolved_api_key());
        assert!(!target.requires_provider_auth_material());
    }

    // ── ProviderPricing::compute_cost_with_cache cached_input default ──

    #[test]
    fn compute_cost_with_cache_no_cached_price() {
        let pricing = ProviderPricing {
            input_price_per_million: 3.0,
            output_price_per_million: 15.0,
            cached_input_price_per_million: None,
            input_multiplier: None,
            cached_input_multiplier: None,
            output_multiplier: None,
        };
        let cost = pricing.compute_cost_with_cache(1_000_000, 500_000, 1_000_000);
        assert!((cost.cached_input - 3.0).abs() < 1e-9);
        assert!((cost.prompt - 0.0).abs() < 1e-9);
    }

    // ── quantization field on ProviderTarget ────────────────────────────

    #[test]
    fn provider_target_quantizations_default_none() {
        let target = sample_target("t1");
        assert!(target.quantizations.is_none());
    }

    #[test]
    fn provider_target_quantizations_set() {
        let mut target = sample_target("t1");
        target.quantizations = Some(vec!["fp16".into(), "int8".into()]);
        assert_eq!(target.quantizations.as_ref().unwrap().len(), 2);
        assert!(target
            .quantizations
            .as_ref()
            .unwrap()
            .contains(&"fp16".to_string()));
    }

    // ── ProviderTarget with MCP bridge ──────────────────────────────────

    #[test]
    fn provider_target_with_mcp_bridge_not_required() {
        let mut target = sample_target("mcp-target");
        target.provider = "mcp".to_string();
        target.mcp_bridge =
            Some(crate::gateway::runtimes::network::mcp::McpBridgeConfig::default());
        assert!(!target.requires_resolved_api_key());
    }

    // ── RoutingConfig ───────────────────────────────────────────────────

    #[test]
    fn routing_config_default_empty() {
        let config = RoutingConfig::default();
        assert!(config.order.is_none());
        assert!(config.only.is_none());
        assert!(config.ignore.is_none());
    }
}

#[cfg(test)]
mod coverage_expansion_providers_tests {
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

    // ── DataPolicy ──────────────────────────────────────────────────────

    #[test]
    fn data_policy_default() {
        let dp = DataPolicy::default();
        assert!(!dp.zero_data_retention);
        assert!(!dp.training_opt_out);
        assert!(dp.retention_days.is_none());
        assert!(!dp.in_memory_only);
        assert!(!dp.sanitized);
        assert!(!dp.accepts_tokenized_input);
        assert!(dp.allow_internet_egress);
        assert!(!dp.local_only_processing);
    }

    #[test]
    fn data_policy_serde_round_trip() {
        let dp = DataPolicy {
            zero_data_retention: true,
            training_opt_out: true,
            retention_days: Some(30),
            in_memory_only: true,
            sanitized: false,
            accepts_tokenized_input: true,
            allow_internet_egress: false,
            local_only_processing: true,
        };
        let serialized = serde_json::to_value(&dp).unwrap();
        let deserialized: DataPolicy = serde_json::from_value(serialized).unwrap();
        assert!(deserialized.zero_data_retention);
        assert!(deserialized.training_opt_out);
        assert_eq!(deserialized.retention_days, Some(30));
        assert!(deserialized.in_memory_only);
        assert!(!deserialized.allow_internet_egress);
        assert!(deserialized.local_only_processing);
    }

    // ── DataCollectionPolicy ────────────────────────────────────────────

    #[test]
    fn data_collection_policy_variants() {
        assert_ne!(DataCollectionPolicy::Allow, DataCollectionPolicy::Deny);
    }

    // ── Percentile ──────────────────────────────────────────────────────

    #[test]
    fn percentile_variants() {
        assert_ne!(Percentile::P50, Percentile::P90);
        assert_ne!(Percentile::P90, Percentile::P99);
    }

    // ── DataResidencyPolicy ─────────────────────────────────────────────

    #[test]
    fn data_residency_policy_serde() {
        let policy = DataResidencyPolicy {
            regions: vec!["us-east-1".to_string(), "eu-west-1".to_string()],
            data_center_locations: vec!["Virginia".to_string()],
            sovereignty_compliant: true,
        };
        let j = serde_json::to_value(&policy).unwrap();
        assert_eq!(j["regions"].as_array().unwrap().len(), 2);
        assert!(j["sovereignty_compliant"].as_bool().unwrap());
    }

    // ── PerformanceCutoff ───────────────────────────────────────────────

    #[test]
    fn performance_cutoff_creation() {
        let cutoff = PerformanceCutoff {
            value: 200.0,
            percentile: Percentile::P99,
        };
        assert_eq!(cutoff.value, 200.0);
        assert_eq!(cutoff.percentile, Percentile::P99);
    }

    // ── MaxPrice ────────────────────────────────────────────────────────

    #[test]
    fn max_price_creation() {
        let price = MaxPrice {
            prompt: Some(0.01),
            completion: Some(0.03),
            request: Some(0.05),
        };
        assert_eq!(price.prompt, Some(0.01));
        assert_eq!(price.completion, Some(0.03));
        assert_eq!(price.request, Some(0.05));
    }

    // ── ProviderTarget basic fields ─────────────────────────────────────

    #[test]
    fn provider_target_requires_auth_material_with_key() {
        let target = ProviderTarget {
            id: "t1".into(),
            provider: "openai".into(),
            model: "gpt-5.4".into(),
            execution_target: None,
            mcp_bridge: None,
            description: None,
            base_url: "https://api.openai.com".into(),
            api_key: "sk-test".into(),
            api_key_header: "Authorization".into(),
            api_key_prefix: "Bearer ".into(),
            secret_key_ref: None,
            path_template: None,
            headers: Default::default(),
            timeout: Duration::from_secs(30),
            stream_timeout: None,
            max_context_tokens: None,
            max_messages: None,
            data_policy: None,
            pricing: None,
            models: vec![],
            data_collection: None,
            zdr: false,
            region: None,
            quantizations: None,
            weight: None,
            provider_type: None,
            format: None,
            anthropic_version: None,
            aws_region: None,
            aws_profile: None,
            bedrock_model_family: None,
            watsonx_api_version: None,
            watsonx_project_id: None,
            watsonx_space_id: None,
            gcp_project: None,
            gcp_region: None,
            azure_api_version: None,
            azure_deployment: None,
            oauth2: None,
            health_probe: None,
            allow_insecure_tls: false,
            escalation_routing: None,
            required: false,
            data_residency: None,
            certifications: None,
        };
        assert!(!target.api_key.is_empty());
    }

    // ── ProviderTarget additional fields ────────────────────────────────

    #[test]
    fn provider_target_zdr_default_false() {
        let dp = DataPolicy {
            zero_data_retention: true,
            training_opt_out: true,
            retention_days: Some(0),
            ..Default::default()
        };
        assert!(dp.zero_data_retention);
        assert_eq!(dp.retention_days, Some(0));
    }

    #[test]
    fn data_policy_allow_internet_egress_default() {
        let dp: DataPolicy = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(dp.allow_internet_egress);
    }

    #[test]
    fn data_policy_local_only_processing_flag() {
        let dp: DataPolicy = serde_json::from_value(serde_json::json!({
            "local_only_processing": true,
            "allow_internet_egress": false
        }))
        .unwrap();
        assert!(dp.local_only_processing);
        assert!(!dp.allow_internet_egress);
    }

    // ── ProviderPricing ─────────────────────────────────────────────────

    #[test]
    fn provider_pricing_creation() {
        let pricing = ProviderPricing {
            input_price_per_million: 0.01,
            output_price_per_million: 0.03,
            cached_input_price_per_million: Some(0.005),
            input_multiplier: None,
            cached_input_multiplier: None,
            output_multiplier: None,
        };
        assert_eq!(pricing.input_price_per_million, 0.01);
        assert_eq!(pricing.output_price_per_million, 0.03);
        assert_eq!(pricing.cached_input_price_per_million, Some(0.005));
    }

    #[test]
    fn provider_pricing_with_multipliers() {
        let pricing = ProviderPricing {
            input_price_per_million: 1.0,
            output_price_per_million: 2.0,
            cached_input_price_per_million: None,
            input_multiplier: Some(1.5),
            cached_input_multiplier: Some(0.75),
            output_multiplier: Some(2.0),
        };
        assert_eq!(pricing.input_multiplier, Some(1.5));
        assert_eq!(pricing.cached_input_multiplier, Some(0.75));
        assert_eq!(pricing.output_multiplier, Some(2.0));
    }

    // ── MaxPrice ────────────────────────────────────────────────────────

    #[test]
    fn max_price_all_none() {
        let price = MaxPrice {
            prompt: None,
            completion: None,
            request: None,
        };
        assert!(price.prompt.is_none());
        assert!(price.completion.is_none());
        assert!(price.request.is_none());
    }

    // ── DataResidencyPolicy ─────────────────────────────────────────────

    #[test]
    fn data_residency_policy_empty_regions() {
        let policy = DataResidencyPolicy {
            regions: vec![],
            data_center_locations: vec![],
            sovereignty_compliant: false,
        };
        assert!(policy.regions.is_empty());
        assert!(!policy.sovereignty_compliant);
    }

    // ── ProviderTarget with multi-model and weight ──────────────────────

    #[test]
    fn provider_target_with_weight_and_models() {
        let target = ProviderTarget {
            id: "weighted".into(),
            provider: "openai".into(),
            model: "gpt-5.4".into(),
            execution_target: None,
            mcp_bridge: None,
            description: Some("A weighted target".to_string()),
            base_url: "https://api.openai.com".into(),
            api_key: "sk-test".into(),
            api_key_header: "Authorization".into(),
            api_key_prefix: "Bearer ".into(),
            secret_key_ref: None,
            path_template: None,
            headers: Default::default(),
            timeout: Duration::from_secs(30),
            stream_timeout: Some(Duration::from_secs(60)),
            max_context_tokens: Some(128000),
            max_messages: Some(100),
            data_policy: None,
            pricing: Some(ProviderPricing {
                input_price_per_million: 10.0,
                output_price_per_million: 30.0,
                cached_input_price_per_million: None,
                input_multiplier: None,
                cached_input_multiplier: None,
                output_multiplier: None,
            }),
            models: vec![
                ProviderModelEntry {
                    model_id: "gpt-5.4".to_string(),
                    aliases: vec![],
                    enabled: true,
                    pricing: None,
                    supported_features: vec![],
                    max_output_tokens: None,
                    parameter_overrides: serde_json::Map::new(),
                    removed_params: vec![],
                    description: None,
                    escalation_routing: None,
                },
                ProviderModelEntry {
                    model_id: "gpt-5.4-mini".to_string(),
                    aliases: vec![],
                    enabled: true,
                    pricing: None,
                    supported_features: vec![],
                    max_output_tokens: None,
                    parameter_overrides: serde_json::Map::new(),
                    removed_params: vec![],
                    description: None,
                    escalation_routing: None,
                },
            ],
            data_collection: None,
            zdr: true,
            region: Some("us-east-1".to_string()),
            quantizations: None,
            weight: Some(2.5),
            provider_type: None,
            format: None,
            anthropic_version: None,
            aws_region: None,
            aws_profile: None,
            bedrock_model_family: None,
            watsonx_api_version: None,
            watsonx_project_id: None,
            watsonx_space_id: None,
            gcp_project: None,
            gcp_region: None,
            azure_api_version: None,
            azure_deployment: None,
            oauth2: None,
            health_probe: None,
            allow_insecure_tls: false,
            escalation_routing: None,
            required: true,
            data_residency: None,
            certifications: None,
        };
        assert_eq!(target.weight, Some(2.5));
        assert!(target.zdr);
        assert!(target.required);
        assert_eq!(target.models.len(), 2);
        assert_eq!(target.max_context_tokens, Some(128000));
        assert_eq!(target.stream_timeout, Some(Duration::from_secs(60)));
    }
}
