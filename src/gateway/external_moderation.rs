// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Phase 25 — External Toxicity & Moderation Service Integration
//!
//! Provides config types and HTTP client implementations for:
//! - OpenAI Moderation API
//! - Azure Content Safety
//!
//! Security: credentials MUST be supplied via `secret_key_ref.env`, never inline
//! in config.
//!
//! Fail-closed behaviour: if the moderation service is unreachable, times out,
//! returns an invalid status, or yields a malformed response, the configured
//! policy blocks with [`EXTERNAL_MODERATION_UNAVAILABLE`]. The legacy
//! `fail_closed` config field is retained for schema compatibility but service
//! failures always block.

use std::collections::HashMap;
use std::fmt::Display;
use std::time::Duration;

use crate::secret_key_ref::parse_env_secret_key_name;

// ═══════════════════════════════════════════════════════════════════════════
// Config types
// ═══════════════════════════════════════════════════════════════════════════

/// Moderation service provider.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModerationProvider {
    /// OpenAI Moderation API (<https://platform.openai.com/docs/api-reference/moderations>).
    #[default]
    OpenaiModeration,
    /// Azure Content Safety (<https://learn.microsoft.com/azure/ai-services/content-safety/>).
    AzureContentSafety,
    /// AWS Bedrock ApplyGuardrail runtime API.
    BedrockApplyGuardrail,
    /// External embedding endpoint for semantic moderation.
    EmbeddingEndpoint,
    /// Presidio Analyzer API for PII detection.
    Presidio,
    /// Guardrails AI guard validation.
    GuardrailsAi,
    /// DynamoAI safety policy enforcement.
    DynamoAi,
    /// Lakera Guard for prompt injection detection.
    Lakera,
}

/// Configuration for the `external-moderation` policy.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ExternalModerationConfig {
    /// Which moderation provider to use.
    pub provider: ModerationProvider,
    /// Environment-variable name that holds the API key.
    /// Required for `openai-moderation` and `azure-content-safety`.
    #[serde(default)]
    pub secret_key_env: String,
    /// Provider endpoint URL.
    /// - `openai-moderation`: defaults to `https://api.openai.com/v1/moderations`.
    /// - `azure-content-safety`: required — your Azure resource endpoint.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Only flag content that matches these categories. Empty = all categories.
    #[serde(default)]
    pub categories: Vec<String>,
    /// Minimum score (per category) to consider the content flagged.
    #[serde(default = "default_threshold")]
    pub threshold: f64,
    /// Request timeout in milliseconds. Default: 3 000.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Legacy fail-closed toggle retained for schema compatibility.
    ///
    /// Service failures (missing credentials, network/timeout, invalid status,
    /// malformed response) always block with
    /// [`EXTERNAL_MODERATION_UNAVAILABLE`] regardless of this value.
    /// Default: `true`.
    #[serde(default = "default_fail_closed")]
    pub fail_closed: bool,
    #[serde(default)]
    pub aws_region: Option<String>,
    #[serde(default)]
    pub aws_access_key_env: Option<String>,
    #[serde(default)]
    pub aws_secret_key_env: Option<String>,
    #[serde(default)]
    pub aws_session_token_env: Option<String>,
    #[serde(default)]
    pub guardrail_id: Option<String>,
    #[serde(default)]
    pub guardrail_version: Option<String>,
    #[serde(default)]
    pub embedding_model: Option<String>,
    #[serde(default)]
    pub reference_texts: Vec<String>,
    /// Presidio: language hint for the analyzer (default: "en").
    #[serde(default)]
    pub presidio_language: Option<String>,
    /// Presidio: entity types to detect (e.g. ["PERSON", "CREDIT_CARD"]).
    #[serde(default)]
    pub presidio_entities: Vec<String>,
    /// Guardrails AI: guard name to invoke.
    #[serde(default)]
    pub guard_name: Option<String>,
    /// DynamoAI: policy ID to enforce.
    #[serde(default)]
    pub policy_id: Option<String>,
    /// Lakera: category filters for prompt injection detection.
    #[serde(default)]
    pub lakera_categories: Vec<String>,
}

impl Default for ExternalModerationConfig {
    fn default() -> Self {
        Self {
            provider: ModerationProvider::OpenaiModeration,
            secret_key_env: String::new(),
            endpoint: None,
            categories: Vec::new(),
            threshold: default_threshold(),
            timeout_ms: default_timeout_ms(),
            fail_closed: default_fail_closed(),
            aws_region: None,
            aws_access_key_env: None,
            aws_secret_key_env: None,
            aws_session_token_env: None,
            guardrail_id: None,
            guardrail_version: None,
            embedding_model: None,
            reference_texts: Vec::new(),
            presidio_language: None,
            presidio_entities: Vec::new(),
            guard_name: None,
            policy_id: None,
            lakera_categories: Vec::new(),
        }
    }
}

fn default_threshold() -> f64 {
    0.5
}

fn default_timeout_ms() -> u64 {
    3_000
}

fn default_fail_closed() -> bool {
    true
}

/// Stable reason code when a configured external moderation policy cannot be
/// evaluated because the provider is unavailable or returned an invalid result.
pub const EXTERNAL_MODERATION_UNAVAILABLE: &str = "policy.external_moderation_unavailable";

// ═══════════════════════════════════════════════════════════════════════════
// Result type
// ═══════════════════════════════════════════════════════════════════════════

/// Outcome returned by every moderation client.
#[derive(Clone, Debug)]
pub struct ModerationResult {
    /// Whether any category exceeded the threshold.
    pub flagged: bool,
    /// Per-category score map (category name → [0.0, 1.0]).
    pub scores: HashMap<String, f64>,
    /// Human-readable reason if flagged or unavailable.
    pub reason: Option<String>,
    /// True when the moderation provider could not complete a valid check.
    pub unavailable: bool,
}

impl ModerationResult {
    /// Build an "allow" result (no violation).
    pub fn allow() -> Self {
        Self {
            flagged: false,
            scores: HashMap::new(),
            reason: None,
            unavailable: false,
        }
    }

    /// Build a "flagged" result with details.
    pub fn flagged(scores: HashMap<String, f64>, reason: impl Into<String>) -> Self {
        Self {
            flagged: true,
            scores,
            reason: Some(reason.into()),
            unavailable: false,
        }
    }

    /// Build an unavailable result that must block configured policies.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            flagged: true,
            scores: HashMap::new(),
            reason: Some(reason.into()),
            unavailable: true,
        }
    }
}

/// Service/config failure path for a configured moderation policy.
///
/// Always blocks; the legacy `fail_closed` toggle is ignored.
fn unavailable_result(reason: impl Into<String>) -> ModerationResult {
    ModerationResult::unavailable(reason)
}

/// Compatibility wrapper used by older call sites / tests.
fn fail_closed_result(
    _config: &ExternalModerationConfig,
    reason: impl Into<String>,
) -> ModerationResult {
    unavailable_result(reason)
}

// ═══════════════════════════════════════════════════════════════════════════
// Helper: resolve env-var API key
// ═══════════════════════════════════════════════════════════════════════════

/// Resolve an API key from the named environment variable.
/// Returns an error if the variable is missing or empty.
fn resolve_api_key(env_var: &str) -> Result<String, String> {
    if env_var.is_empty() {
        return Err("secret_key_ref.env is not configured".to_string());
    }
    // CLI-SEC-006: Validate env var name before lookup.
    if !crate::secret_key_ref::is_valid_env_var_name(env_var) {
        tracing::warn!(
            env_var = env_var,
            "rejected moderation env var lookup with invalid name"
        );
        return Err(format!(
            "environment variable name '{env_var}' contains invalid characters"
        ));
    }
    let key =
        std::env::var(env_var).map_err(|_| format!("environment variable '{env_var}' not set"))?;
    if key.trim().is_empty() {
        return Err(format!("environment variable '{env_var}' is empty"));
    }
    Ok(key.trim().to_string())
}

// ═══════════════════════════════════════════════════════════════════════════
// OpenAI Moderation client
// ═══════════════════════════════════════════════════════════════════════════

/// Check `content` against the OpenAI Moderation API.
///
/// Service failures block with [`EXTERNAL_MODERATION_UNAVAILABLE`].
pub async fn check_openai_moderation(
    content: &str,
    config: &ExternalModerationConfig,
) -> ModerationResult {
    let api_key = match resolve_api_key(&config.secret_key_env) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(error = %e, "openai-moderation: cannot resolve API key");
            return fail_closed_result(config, format!("api key unavailable: {e}"));
        }
    };

    let endpoint = config
        .endpoint
        .as_deref()
        .unwrap_or("https://api.openai.com/v1/moderations");

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "openai-moderation: failed to build HTTP client");
            return fail_closed_result(config, "service unavailable (fail_closed)");
        }
    };

    let body = serde_json::json!({ "input": content });
    let response = client
        .post(endpoint)
        .header("Authorization", format!("Bearer {api_key}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await;

    match response {
        Err(e) => {
            tracing::warn!(error = %e, endpoint, "openai-moderation: request failed");
            fail_closed_result(config, "service unavailable (fail_closed)")
        }
        Ok(resp) => parse_openai_response(resp, config).await,
    }
}

pub async fn parse_openai_response(
    resp: reqwest::Response,
    config: &ExternalModerationConfig,
) -> ModerationResult {
    let status = resp.status();
    parse_openai_response_body(status, resp.text().await, config)
}

fn parse_openai_response_body<E: Display>(
    status: reqwest::StatusCode,
    body: Result<String, E>,
    config: &ExternalModerationConfig,
) -> ModerationResult {
    let text = match body {
        Ok(text) => text,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "openai-moderation: failed to read response body"
            );
            return fail_closed_result(config, "response body unreadable (fail_closed)");
        }
    };

    if !status.is_success() {
        tracing::warn!(status = %status, "openai-moderation: non-200 response");
        return fail_closed_result(config, format!("HTTP {status} (fail_closed)"));
    }

    let parsed: OpenaiModerationResponse = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(e) => {
            tracing::warn!(error = %e, "openai-moderation: failed to parse JSON response");
            return fail_closed_result(config, "response body malformed (fail_closed)");
        }
    };

    let Some(result) = parsed.results.into_iter().next() else {
        tracing::warn!("openai-moderation: response missing results[0]");
        return fail_closed_result(config, "response body malformed (fail_closed)");
    };
    let scores = result.category_scores;

    // Apply category filter and threshold.
    let flagged_categories: HashMap<String, f64> = scores
        .iter()
        .filter(|(cat, &score)| {
            let in_filter = config.categories.is_empty() || config.categories.contains(cat);
            in_filter && score >= config.threshold
        })
        .map(|(k, &v)| (k.clone(), v))
        .collect();

    if flagged_categories.is_empty() {
        ModerationResult::allow()
    } else {
        let top = flagged_categories
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(k, v)| format!("{k} ({v:.3})"))
            .unwrap_or_default();
        ModerationResult::flagged(
            flagged_categories,
            format!("flagged by openai-moderation: {top}"),
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Azure Content Safety client
// ═══════════════════════════════════════════════════════════════════════════

/// Check `content` via Azure Content Safety API.
pub async fn check_azure_content_safety(
    content: &str,
    config: &ExternalModerationConfig,
) -> ModerationResult {
    let api_key = match resolve_api_key(&config.secret_key_env) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(error = %e, "azure-content-safety: cannot resolve API key");
            return fail_closed_result(config, format!("api key unavailable: {e}"));
        }
    };

    let endpoint = match &config.endpoint {
        Some(e) => e.clone(),
        None => {
            tracing::warn!("azure-content-safety: no endpoint configured");
            return fail_closed_result(config, "endpoint unavailable (fail_closed)");
        }
    };

    let url = format!(
        "{}/contentsafety/text:analyze?api-version=2023-10-01",
        endpoint.trim_end_matches('/')
    );

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "azure-content-safety: failed to build HTTP client");
            return fail_closed_result(config, "service unavailable (fail_closed)");
        }
    };

    let body = serde_json::json!({ "text": content });
    let response = client
        .post(&url)
        .header("Ocp-Apim-Subscription-Key", api_key)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await;

    match response {
        Err(e) => {
            tracing::warn!(error = %e, url, "azure-content-safety: request failed");
            fail_closed_result(config, "service unavailable (fail_closed)")
        }
        Ok(resp) => parse_azure_response(resp, config).await,
    }
}

pub async fn parse_azure_response(
    resp: reqwest::Response,
    config: &ExternalModerationConfig,
) -> ModerationResult {
    let status = resp.status();
    parse_azure_response_body(status, resp.text().await, config)
}

fn parse_azure_response_body<E: Display>(
    status: reqwest::StatusCode,
    body: Result<String, E>,
    config: &ExternalModerationConfig,
) -> ModerationResult {
    let text = match body {
        Ok(text) => text,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "azure-content-safety: failed to read response body"
            );
            return fail_closed_result(config, "response body unreadable (fail_closed)");
        }
    };

    if !status.is_success() {
        tracing::warn!(status = %status, "azure-content-safety: non-200 response");
        return fail_closed_result(config, format!("HTTP {status} (fail_closed)"));
    }

    let parsed: AzureContentSafetyResponse = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(e) => {
            tracing::warn!(error = %e, "azure-content-safety: failed to parse JSON");
            return fail_closed_result(config, "response body malformed (fail_closed)");
        }
    };

    // Azure response: `{ "categoriesAnalysis": [ { "category": "Hate", "severity": 2 },... ] }`
    // Severity is 0–6; normalise to 0.0–1.0 (divide by 6).
    let scores: HashMap<String, f64> = parsed
        .categories_analysis
        .into_iter()
        .map(|item| (item.category.to_lowercase(), item.severity / 6.0))
        .collect();

    let flagged_categories: HashMap<String, f64> = scores
        .iter()
        .filter(|(cat, &score)| {
            let in_filter =
                config.categories.is_empty() || config.categories.contains(&cat.to_string());
            in_filter && score >= config.threshold
        })
        .map(|(k, &v)| (k.clone(), v))
        .collect();

    if flagged_categories.is_empty() {
        ModerationResult::allow()
    } else {
        let top = flagged_categories
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(k, v)| format!("{k} ({v:.3})"))
            .unwrap_or_default();
        ModerationResult::flagged(
            flagged_categories,
            format!("flagged by azure-content-safety: {top}"),
        )
    }
}

#[derive(serde::Deserialize)]
struct OpenaiModerationResponse {
    results: Vec<OpenaiModerationResult>,
}

#[derive(serde::Deserialize)]
struct OpenaiModerationResult {
    category_scores: HashMap<String, f64>,
}

#[derive(serde::Deserialize)]
struct AzureContentSafetyResponse {
    #[serde(rename = "categoriesAnalysis")]
    categories_analysis: Vec<AzureContentSafetyCategory>,
}

#[derive(serde::Deserialize)]
struct AzureContentSafetyCategory {
    category: String,
    severity: f64,
}

pub async fn check_bedrock_apply_guardrail(
    content: &str,
    config: &ExternalModerationConfig,
) -> ModerationResult {
    let guardrail_id = match &config.guardrail_id {
        Some(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => return fail_closed_result(config, "bedrock: guardrail_id not configured"),
    };
    let region = match config
        .aws_region
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(region) => region.to_string(),
        None => return fail_closed_result(config, "bedrock: aws_region not configured"),
    };
    let guardrail_version = config
        .guardrail_version
        .clone()
        .unwrap_or_else(|| "DRAFT".to_string());
    let access_key = config
        .aws_access_key_env
        .as_ref()
        .and_then(|env| std::env::var(env).ok())
        .or_else(|| std::env::var("AWS_ACCESS_KEY_ID").ok())
        .unwrap_or_default();
    let secret_key = config
        .aws_secret_key_env
        .as_ref()
        .and_then(|env| std::env::var(env).ok())
        .or_else(|| std::env::var("AWS_SECRET_ACCESS_KEY").ok())
        .unwrap_or_default();
    if access_key.trim().is_empty() || secret_key.trim().is_empty() {
        return fail_closed_result(config, "bedrock credentials unavailable (fail_closed)");
    }

    let path = format!("/guardrail/{guardrail_id}/version/{guardrail_version}/apply");
    let endpoint_base = config
        .endpoint
        .clone()
        .unwrap_or_else(|| format!("https://bedrock-runtime.{region}.amazonaws.com"));
    let parsed_base = reqwest::Url::parse(&endpoint_base).ok();
    let host = parsed_base
        .as_ref()
        .and_then(|url| url.host_str())
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("bedrock-runtime.{region}.amazonaws.com"));
    let body = serde_json::json!({
        "source": "INPUT",
        "content": [{"text": {"text": content}}]
    });
    let body_bytes = serde_json::to_vec(&body).unwrap_or_default();
    let session_token = config
        .aws_session_token_env
        .as_ref()
        .and_then(|env| std::env::var(env).ok());
    let signed_headers = match crate::gateway::provider_auth::sign_bedrock_request(
        access_key.trim(),
        secret_key.trim(),
        session_token.as_deref(),
        &region,
        &host,
        &path,
        &body_bytes,
    ) {
        Ok(headers) => headers,
        Err(error) => {
            tracing::warn!(error = %error, "bedrock-apply-guardrail: request signing failed");
            return fail_closed_result(config, "bedrock request signing failed (fail_closed)");
        }
    };

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms.max(1)))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(error = %error, "bedrock-apply-guardrail: failed to build HTTP client");
            return fail_closed_result(config, "service unavailable (fail_closed)");
        }
    };

    let mut request = client
        .post(format!("{}{}", endpoint_base.trim_end_matches('/'), path))
        .header("Content-Type", "application/json")
        .body(body_bytes);
    for (name, value) in signed_headers {
        request = request.header(name, value);
    }

    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(error = %error, "bedrock-apply-guardrail: request failed");
            return fail_closed_result(config, "service unavailable (fail_closed)");
        }
    };
    let payload: serde_json::Value = match response.json().await {
        Ok(payload) => payload,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "bedrock-apply-guardrail: failed to parse response"
            );
            return fail_closed_result(config, "response body malformed (fail_closed)");
        }
    };

    let action = payload
        .get("action")
        .or_else(|| payload.get("topAction"))
        .and_then(|value| value.as_str())
        .unwrap_or("ALLOW");
    if action.eq_ignore_ascii_case("allow") || action.eq_ignore_ascii_case("none") {
        return ModerationResult::allow();
    }

    let mut scores = HashMap::new();
    let assessment_count = payload
        .get("assessments")
        .and_then(|value| value.as_array())
        .map(|items| items.len() as f64)
        .unwrap_or(1.0);
    scores.insert("bedrock_guardrail".to_string(), assessment_count);
    ModerationResult::flagged(scores, format!("flagged by bedrock guardrail: {action}"))
}

pub async fn check_embedding_moderation(
    content: &str,
    config: &ExternalModerationConfig,
) -> ModerationResult {
    let endpoint = match &config.endpoint {
        Some(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => return fail_closed_result(config, "embedding: endpoint not configured"),
    };
    if config.reference_texts.is_empty() {
        return fail_closed_result(config, "embedding: reference_texts is empty");
    }

    let mut inputs = vec![content.to_string()];
    inputs.extend(config.reference_texts.iter().cloned());

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms.max(1)))
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            tracing::warn!(error = %e, "embedding-moderation: failed to build HTTP client");
            return fail_closed_result(config, "service unavailable (fail_closed)");
        }
    };
    let mut request = client.post(&endpoint).json(&serde_json::json!({
        "model": config.embedding_model.clone().unwrap_or_else(|| "embed".to_string()),
        "input": inputs,
    }));
    if !config.secret_key_env.is_empty() {
        if let Ok(api_key) = std::env::var(&config.secret_key_env) {
            if !api_key.trim().is_empty() {
                request = request.bearer_auth(api_key.trim());
            }
        }
    }
    let resp = match request.send().await.and_then(|r| r.error_for_status()) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "embedding-moderation: request failed");
            return fail_closed_result(config, "service unavailable (fail_closed)");
        }
    };
    let payload: serde_json::Value = match resp.json().await {
        Ok(payload) => payload,
        Err(e) => {
            tracing::warn!(error = %e, "embedding-moderation: failed to parse response");
            return fail_closed_result(config, "response body malformed (fail_closed)");
        }
    };

    let embeddings = payload
        .get("data")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("embedding"))
                .filter_map(|value| value.as_array())
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_f64())
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if embeddings.len() < 2 {
        return fail_closed_result(config, "embedding response has insufficient embeddings");
    }

    let input_embedding = &embeddings[0];
    let mut scores = HashMap::new();
    for (index, reference_embedding) in embeddings.iter().enumerate().skip(1) {
        let score = crate::gateway::cache::cosine_similarity(input_embedding, reference_embedding);
        scores.insert(
            config
                .categories
                .get(index - 1)
                .cloned()
                .unwrap_or_else(|| format!("reference_{index}")),
            score,
        );
    }

    let flagged_scores = scores
        .iter()
        .filter(|(_, score)| **score >= config.threshold)
        .map(|(name, score)| (name.clone(), *score))
        .collect::<HashMap<_, _>>();
    if flagged_scores.is_empty() {
        ModerationResult::allow()
    } else {
        ModerationResult::flagged(flagged_scores, "flagged by embedding moderation")
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Dispatch entry point
// ═══════════════════════════════════════════════════════════════════════════

/// Dispatch to the appropriate moderation provider.
pub async fn check(content: &str, config: &ExternalModerationConfig) -> ModerationResult {
    match config.provider {
        ModerationProvider::OpenaiModeration => check_openai_moderation(content, config).await,
        ModerationProvider::AzureContentSafety => check_azure_content_safety(content, config).await,
        ModerationProvider::BedrockApplyGuardrail => {
            check_bedrock_apply_guardrail(content, config).await
        }
        ModerationProvider::EmbeddingEndpoint => check_embedding_moderation(content, config).await,
        ModerationProvider::Presidio => check_presidio(content, config).await,
        ModerationProvider::GuardrailsAi => check_guardrails_ai(content, config).await,
        ModerationProvider::DynamoAi => check_dynamo_ai(content, config).await,
        ModerationProvider::Lakera => check_lakera(content, config).await,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Parse from JSON config value
// ═══════════════════════════════════════════════════════════════════════════

/// Parse an `ExternalModerationConfig` from a policy config block value.
pub fn parse_config(v: &serde_json::Value) -> ExternalModerationConfig {
    let provider = v
        .get("provider")
        .and_then(|p| p.as_str())
        .and_then(|s| match s {
            "openai-moderation" => Some(ModerationProvider::OpenaiModeration),
            "azure-content-safety" => Some(ModerationProvider::AzureContentSafety),
            "bedrock-apply-guardrail" => Some(ModerationProvider::BedrockApplyGuardrail),
            "embedding-endpoint" => Some(ModerationProvider::EmbeddingEndpoint),
            "presidio" => Some(ModerationProvider::Presidio),
            "guardrails-ai" => Some(ModerationProvider::GuardrailsAi),
            "dynamo-ai" => Some(ModerationProvider::DynamoAi),
            "lakera" => Some(ModerationProvider::Lakera),
            _ => None,
        })
        .unwrap_or_default();

    let secret_key_env = match parse_env_secret_key_name(
        v.get("secret_key_ref"),
        "policy.external-moderation.secret_key_ref",
    ) {
        Ok(value) => value.unwrap_or_default(),
        Err(error) => {
            tracing::warn!(
                error = %error,
                "invalid policy.external-moderation.secret_key_ref; external moderation will run without credentials"
            );
            String::new()
        }
    };

    let endpoint = v
        .get("endpoint")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);

    let categories: Vec<String> = v
        .get("categories")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let threshold = v
        .get("threshold")
        .and_then(|v| v.as_f64())
        .unwrap_or_else(default_threshold);

    let timeout_ms = v
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or_else(default_timeout_ms);

    let fail_closed = v
        .get("fail_closed")
        .and_then(|v| v.as_bool())
        .unwrap_or_else(default_fail_closed);

    let aws_region = v
        .get("aws_region")
        .and_then(|value| value.as_str())
        .map(ToString::to_string);
    let aws_access_key_env = v
        .get("aws_access_key_env")
        .and_then(|value| value.as_str())
        .map(ToString::to_string);
    let aws_secret_key_env = v
        .get("aws_secret_key_env")
        .and_then(|value| value.as_str())
        .map(ToString::to_string);
    let aws_session_token_env = v
        .get("aws_session_token_env")
        .and_then(|value| value.as_str())
        .map(ToString::to_string);
    let guardrail_id = v
        .get("guardrail_id")
        .and_then(|value| value.as_str())
        .map(ToString::to_string);
    let guardrail_version = v
        .get("guardrail_version")
        .and_then(|value| value.as_str())
        .map(ToString::to_string);
    let embedding_model = v
        .get("embedding_model")
        .and_then(|value| value.as_str())
        .map(ToString::to_string);
    let reference_texts = v
        .get("reference_texts")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(ToString::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let presidio_language = v
        .get("presidio_language")
        .and_then(|value| value.as_str())
        .map(ToString::to_string);
    let presidio_entities = v
        .get("presidio_entities")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(ToString::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let guard_name = v
        .get("guard_name")
        .and_then(|value| value.as_str())
        .map(ToString::to_string);
    let policy_id = v
        .get("policy_id")
        .and_then(|value| value.as_str())
        .map(ToString::to_string);
    let lakera_categories = v
        .get("lakera_categories")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(ToString::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    ExternalModerationConfig {
        provider,
        secret_key_env,
        endpoint,
        categories,
        threshold,
        timeout_ms,
        fail_closed,
        aws_region,
        aws_access_key_env,
        aws_secret_key_env,
        aws_session_token_env,
        guardrail_id,
        guardrail_version,
        embedding_model,
        reference_texts,
        presidio_language,
        presidio_entities,
        guard_name,
        policy_id,
        lakera_categories,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Presidio Analyzer client
// ═══════════════════════════════════════════════════════════════════════════

/// Check `content` against a Presidio Analyzer instance.
///
/// POST to `{endpoint}/analyze` with `{ "text":..., "language":..., "entities": [...] }`.
/// Response: `[ { "entity_type": "PERSON", "score": 0.85,... },... ]`.
pub async fn check_presidio(content: &str, config: &ExternalModerationConfig) -> ModerationResult {
    let endpoint = match &config.endpoint {
        Some(ep) => format!("{}/analyze", ep.trim_end_matches('/')),
        None => {
            tracing::warn!("presidio: no endpoint configured");
            return unavailable_result("presidio: no endpoint configured");
        }
    };

    let language = config.presidio_language.as_deref().unwrap_or("en");

    let mut body = serde_json::json!({
        "text": content,
        "language": language,
    });

    if !config.presidio_entities.is_empty() {
        body["entities"] = serde_json::json!(config.presidio_entities);
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms))
        .build()
        .unwrap_or_default();

    let response = match client.post(&endpoint).json(&body).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "presidio: request failed");
            return unavailable_result(format!("presidio: request failed: {e}"));
        }
    };

    let results: Vec<serde_json::Value> = match response.json().await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "presidio: failed to parse response");
            return unavailable_result(format!("presidio: parse error: {e}"));
        }
    };

    let mut scores = HashMap::new();
    let mut flagged = false;

    for entity in &results {
        let entity_type = entity
            .get("entity_type")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN");
        let score = entity.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0);
        scores.insert(entity_type.to_string(), score);
        if score >= config.threshold {
            flagged = true;
        }
    }

    if flagged {
        ModerationResult::flagged(scores, "presidio: PII detected")
    } else {
        ModerationResult {
            flagged: false,
            scores,
            reason: None,
            unavailable: false,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Guardrails AI client
// ═══════════════════════════════════════════════════════════════════════════

/// Check `content` against a Guardrails AI guard endpoint.
///
/// POST to `{endpoint}/guards/{guard_name}/validate` with `{ "llmOutput": content }`.
pub async fn check_guardrails_ai(
    content: &str,
    config: &ExternalModerationConfig,
) -> ModerationResult {
    let base = match &config.endpoint {
        Some(ep) => ep.trim_end_matches('/').to_string(),
        None => {
            tracing::warn!("guardrails-ai: no endpoint configured");
            return unavailable_result("guardrails-ai: no endpoint configured");
        }
    };

    let guard_name = config.guard_name.as_deref().unwrap_or("default");
    let url = format!("{base}/guards/{guard_name}/validate");

    let body = serde_json::json!({ "llmOutput": content });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms))
        .build()
        .unwrap_or_default();

    let mut req = client.post(&url).json(&body);
    if let Ok(key) = resolve_api_key(&config.secret_key_env) {
        req = req.bearer_auth(key);
    }

    let response = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "guardrails-ai: request failed");
            return unavailable_result(format!("guardrails-ai: request failed: {e}"));
        }
    };

    let json: serde_json::Value = match response.json().await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "guardrails-ai: failed to parse response");
            return unavailable_result(format!("guardrails-ai: parse error: {e}"));
        }
    };

    let validation_passed = match json.get("validationPassed").and_then(|v| v.as_bool()) {
        Some(val) => val,
        None => {
            return unavailable_result(
                "guardrails-ai: validationPassed field missing (fail_closed)",
            );
        }
    };

    if !validation_passed {
        let mut scores = HashMap::new();
        scores.insert("validation".to_string(), 1.0);
        ModerationResult::flagged(scores, "guardrails-ai: validation failed")
    } else {
        ModerationResult::allow()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DynamoAI client
// ═══════════════════════════════════════════════════════════════════════════

/// Check `content` against the DynamoAI safety API.
///
/// POST to `{endpoint}/v1/safety/check` with `{ "content":..., "policy_id":... }`.
pub async fn check_dynamo_ai(content: &str, config: &ExternalModerationConfig) -> ModerationResult {
    let endpoint = match &config.endpoint {
        Some(ep) => format!("{}/v1/safety/check", ep.trim_end_matches('/')),
        None => {
            tracing::warn!("dynamo-ai: no endpoint configured");
            return unavailable_result("dynamo-ai: no endpoint configured");
        }
    };

    let mut body = serde_json::json!({ "content": content });
    if let Some(ref pid) = config.policy_id {
        body["policy_id"] = serde_json::json!(pid);
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms))
        .build()
        .unwrap_or_default();

    let mut req = client.post(&endpoint).json(&body);
    if let Ok(key) = resolve_api_key(&config.secret_key_env) {
        req = req.bearer_auth(key);
    }

    let response = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "dynamo-ai: request failed");
            return unavailable_result(format!("dynamo-ai: request failed: {e}"));
        }
    };

    let json: serde_json::Value = match response.json().await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "dynamo-ai: failed to parse response");
            return unavailable_result(format!("dynamo-ai: parse error: {e}"));
        }
    };

    let safe = match json.get("safe").and_then(|v| v.as_bool()) {
        Some(val) => val,
        None => {
            return unavailable_result("dynamo-ai: safe field missing (fail_closed)");
        }
    };

    if !safe {
        let mut scores = HashMap::new();
        if let Some(violations) = json.get("violations").and_then(|v| v.as_array()) {
            for (i, v) in violations.iter().enumerate() {
                let name = v
                    .get("category")
                    .and_then(|c| c.as_str())
                    .unwrap_or("unknown");
                let score = v.get("score").and_then(|s| s.as_f64()).unwrap_or(1.0);
                scores.insert(format!("{}_{}", name, i), score);
            }
        }
        ModerationResult::flagged(scores, "dynamo-ai: safety violation detected")
    } else {
        ModerationResult::allow()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Lakera Guard client
// ═══════════════════════════════════════════════════════════════════════════

/// Check `content` against the Lakera Guard API.
///
/// POST to `{endpoint}/v1/guard` (default: `https://api.lakera.ai/v1/guard`)
/// with `{ "input": content }`.
pub async fn check_lakera(content: &str, config: &ExternalModerationConfig) -> ModerationResult {
    let endpoint = config
        .endpoint
        .as_deref()
        .unwrap_or("https://api.lakera.ai/v1/guard");

    let body = serde_json::json!({ "input": content });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms))
        .build()
        .unwrap_or_default();

    let mut req = client.post(endpoint).json(&body);
    if let Ok(key) = resolve_api_key(&config.secret_key_env) {
        req = req.bearer_auth(key);
    }

    let response = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "lakera: request failed");
            return unavailable_result(format!("lakera: request failed: {e}"));
        }
    };

    let json: serde_json::Value = match response.json().await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "lakera: failed to parse response");
            return unavailable_result(format!("lakera: parse error: {e}"));
        }
    };

    let mut scores = HashMap::new();
    let mut flagged = false;

    if let Some(results) = json.get("results").and_then(|v| v.as_array()) {
        for result in results {
            if let Some(categories) = result.get("categories").and_then(|c| c.as_object()) {
                for (cat, val) in categories {
                    let is_flagged = val.as_bool().unwrap_or(false);
                    scores.insert(cat.clone(), if is_flagged { 1.0 } else { 0.0 });
                    if is_flagged {
                        // filter by configured categories if specified
                        if config.lakera_categories.is_empty()
                            || config.lakera_categories.iter().any(|c| c == cat)
                        {
                            flagged = true;
                        }
                    }
                }
            }
        }
    } else {
        // Lakera v1 simple response: { "flagged": bool }
        flagged = json
            .get("flagged")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
    }

    if flagged {
        ModerationResult::flagged(
            scores,
            "lakera: prompt injection or unsafe content detected",
        )
    } else {
        ModerationResult {
            flagged: false,
            scores,
            reason: None,
            unavailable: false,
        }
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

    fn config_fail_open() -> ExternalModerationConfig {
        ExternalModerationConfig {
            fail_closed: false,
            ..Default::default()
        }
    }

    fn config_fail_closed() -> ExternalModerationConfig {
        ExternalModerationConfig {
            fail_closed: true,
            ..Default::default()
        }
    }

    fn openai_parse(
        status: reqwest::StatusCode,
        body: Result<String, &str>,
        config: &ExternalModerationConfig,
    ) -> ModerationResult {
        parse_openai_response_body(status, body, config)
    }

    fn azure_parse(
        status: reqwest::StatusCode,
        body: Result<String, &str>,
        config: &ExternalModerationConfig,
    ) -> ModerationResult {
        parse_azure_response_body(status, body, config)
    }

    async fn start_json_server(
        path: &'static str,
        body: serde_json::Value,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let (tx, rx) = tokio::sync::oneshot::channel::<u16>();
        let server = tokio::spawn(async move {
            let app = axum::Router::new().route(
                path,
                axum::routing::post(move || {
                    let body = body.clone();
                    async move { axum::Json(body) }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind moderation test server");
            let port = listener.local_addr().expect("moderation test addr").port();
            tx.send(port).expect("send moderation test port");
            axum::serve(listener, app)
                .await
                .expect("serve moderation test server");
        });

        let port = rx.await.expect("receive moderation test port");
        (format!("http://127.0.0.1:{port}{path}"), server)
    }

    // ── fail_closed_result helper ────────────────────────────────────────

    #[test]
    fn fail_closed_result_blocks_when_configured() {
        let result = fail_closed_result(&config_fail_closed(), "test error");
        assert!(result.flagged);
        assert!(result.unavailable);
        assert!(result.reason.as_deref().unwrap().contains("test error"));
    }

    #[test]
    fn fail_closed_result_blocks_when_fail_closed_false() {
        let result = fail_closed_result(&config_fail_open(), "test error");
        assert!(result.flagged);
        assert!(result.unavailable);
        assert!(result.reason.as_deref().unwrap().contains("test error"));
    }

    // ── OpenAI response parsing ──────────────────────────────────────────

    #[test]
    fn openai_allows_content_below_threshold() {
        let body = serde_json::json!({
            "results": [{
                "category_scores": {
                    "hate": 0.01,
                    "violence": 0.02
                }
            }]
        });
        let result = openai_parse(
            reqwest::StatusCode::OK,
            Ok(body.to_string()),
            &config_fail_closed(),
        );
        assert!(!result.flagged);
    }

    #[test]
    fn openai_flags_content_above_threshold() {
        let body = serde_json::json!({
            "results": [{
                "category_scores": {
                    "hate": 0.95,
                    "violence": 0.02
                }
            }]
        });
        let result = openai_parse(
            reqwest::StatusCode::OK,
            Ok(body.to_string()),
            &config_fail_closed(),
        );
        assert!(result.flagged);
        assert!(result.scores.contains_key("hate"));
        assert!(!result.scores.contains_key("violence"));
    }

    #[test]
    fn openai_category_filter_restricts_flagging() {
        let config = ExternalModerationConfig {
            categories: vec!["violence".to_string()],
            ..Default::default()
        };
        let body = serde_json::json!({
            "results": [{
                "category_scores": {
                    "hate": 0.95,
                    "violence": 0.02
                }
            }]
        });
        let result = openai_parse(reqwest::StatusCode::OK, Ok(body.to_string()), &config);
        assert!(
            !result.flagged,
            "hate should be filtered out by category allowlist"
        );
    }

    #[test]
    fn openai_category_filter_allows_matching_category() {
        let config = ExternalModerationConfig {
            categories: vec!["violence".to_string()],
            ..Default::default()
        };
        let body = serde_json::json!({
            "results": [{
                "category_scores": {
                    "hate": 0.95,
                    "violence": 0.91
                }
            }]
        });
        let result = openai_parse(reqwest::StatusCode::OK, Ok(body.to_string()), &config);
        assert!(result.flagged);
        assert_eq!(result.scores.len(), 1);
        assert_eq!(result.scores.get("violence"), Some(&0.91));
        assert!(result.reason.as_deref().unwrap().contains("violence"));
    }

    #[test]
    fn openai_blocks_on_5xx_when_fail_closed() {
        let result = openai_parse(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            Ok("server error".to_string()),
            &config_fail_closed(),
        );
        assert!(result.flagged);
        assert!(result.reason.as_deref().unwrap().contains("500"));
    }

    #[test]
    fn openai_blocks_on_5xx_when_fail_open() {
        let result = openai_parse(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            Ok("server error".to_string()),
            &config_fail_open(),
        );
        assert!(result.flagged);
        assert!(result.unavailable);
    }

    #[test]
    fn openai_blocks_on_malformed_json_when_fail_closed() {
        let result = openai_parse(
            reqwest::StatusCode::OK,
            Ok("not json".to_string()),
            &config_fail_closed(),
        );
        assert!(result.flagged);
        assert!(result.reason.as_deref().unwrap().contains("malformed"));
    }

    #[test]
    fn openai_blocks_on_malformed_json_when_fail_open() {
        let result = openai_parse(
            reqwest::StatusCode::OK,
            Ok("not json".to_string()),
            &config_fail_open(),
        );
        assert!(result.flagged);
        assert!(result.unavailable);
    }

    #[test]
    fn openai_blocks_on_body_read_failure_when_fail_closed() {
        let result = openai_parse(
            reqwest::StatusCode::OK,
            Err("read error"),
            &config_fail_closed(),
        );
        assert!(result.flagged);
        assert!(result.reason.as_deref().unwrap().contains("unreadable"));
    }

    #[test]
    fn openai_blocks_on_body_read_failure_when_fail_open() {
        let result = openai_parse(
            reqwest::StatusCode::OK,
            Err("read error"),
            &config_fail_open(),
        );
        assert!(result.flagged);
        assert!(result.unavailable);
    }

    #[test]
    fn openai_blocks_on_empty_results_when_fail_closed() {
        let body = serde_json::json!({ "results": [] });
        let result = openai_parse(
            reqwest::StatusCode::OK,
            Ok(body.to_string()),
            &config_fail_closed(),
        );
        assert!(result.flagged);
        assert!(result.reason.as_deref().unwrap().contains("malformed"));
    }

    #[test]
    fn openai_blocks_on_empty_results_when_fail_open() {
        let body = serde_json::json!({ "results": [] });
        let result = openai_parse(
            reqwest::StatusCode::OK,
            Ok(body.to_string()),
            &config_fail_open(),
        );
        assert!(result.flagged);
        assert!(result.unavailable);
    }

    // ── Azure response parsing ───────────────────────────────────────────

    #[test]
    fn azure_allows_content_below_threshold() {
        let body = serde_json::json!({
            "categoriesAnalysis": [
                { "category": "Hate", "severity": 0.0 },
                { "category": "Violence", "severity": 1.0 }
            ]
        });
        let result = azure_parse(
            reqwest::StatusCode::OK,
            Ok(body.to_string()),
            &config_fail_closed(),
        );
        assert!(
            !result.flagged,
            "severity 1/6 = 0.167 is below 0.5 threshold"
        );
    }

    #[test]
    fn azure_flags_content_above_threshold() {
        let body = serde_json::json!({
            "categoriesAnalysis": [
                { "category": "Hate", "severity": 4.0 }
            ]
        });
        let result = azure_parse(
            reqwest::StatusCode::OK,
            Ok(body.to_string()),
            &config_fail_closed(),
        );
        assert!(result.flagged, "severity 4/6 = 0.667 exceeds 0.5 threshold");
        assert!(result.scores.contains_key("hate"));
    }

    #[test]
    fn azure_category_filter_restricts_flagging() {
        let config = ExternalModerationConfig {
            categories: vec!["violence".to_string()],
            ..Default::default()
        };
        let body = serde_json::json!({
            "categoriesAnalysis": [
                { "category": "Hate", "severity": 5.0 }
            ]
        });
        let result = azure_parse(reqwest::StatusCode::OK, Ok(body.to_string()), &config);
        assert!(!result.flagged);
    }

    #[test]
    fn azure_category_filter_matches_normalized_category_name() {
        let config = ExternalModerationConfig {
            categories: vec!["hate".to_string()],
            ..Default::default()
        };
        let body = serde_json::json!({
            "categoriesAnalysis": [
                { "category": "Hate", "severity": 5.0 },
                { "category": "Violence", "severity": 1.0 }
            ]
        });
        let result = azure_parse(reqwest::StatusCode::OK, Ok(body.to_string()), &config);
        assert!(result.flagged);
        assert_eq!(result.scores.len(), 1);
        assert_eq!(result.scores.get("hate"), Some(&(5.0 / 6.0)));
        assert!(result.reason.as_deref().unwrap().contains("hate"));
    }

    #[test]
    fn azure_blocks_on_5xx_when_fail_closed() {
        let result = azure_parse(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            Ok("unavailable".to_string()),
            &config_fail_closed(),
        );
        assert!(result.flagged);
    }

    #[test]
    fn azure_blocks_on_5xx_when_fail_open() {
        let result = azure_parse(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            Ok("unavailable".to_string()),
            &config_fail_open(),
        );
        assert!(result.flagged);
        assert!(result.unavailable);
    }

    #[test]
    fn azure_blocks_on_malformed_json_when_fail_closed() {
        let result = azure_parse(
            reqwest::StatusCode::OK,
            Ok("not json".to_string()),
            &config_fail_closed(),
        );
        assert!(result.flagged);
        assert!(result.reason.as_deref().unwrap().contains("malformed"));
    }

    #[test]
    fn azure_blocks_on_malformed_json_when_fail_open() {
        let result = azure_parse(
            reqwest::StatusCode::OK,
            Ok("not json".to_string()),
            &config_fail_open(),
        );
        assert!(result.flagged);
        assert!(result.unavailable);
    }

    #[test]
    fn azure_blocks_on_body_read_failure_when_fail_closed() {
        let result = azure_parse(
            reqwest::StatusCode::OK,
            Err("read error"),
            &config_fail_closed(),
        );
        assert!(result.flagged);
        assert!(result.reason.as_deref().unwrap().contains("unreadable"));
    }

    #[test]
    fn azure_blocks_on_body_read_failure_when_fail_open() {
        let result = azure_parse(
            reqwest::StatusCode::OK,
            Err("read error"),
            &config_fail_open(),
        );
        assert!(result.flagged);
        assert!(result.unavailable);
    }

    // ── Config parsing ───────────────────────────────────────────────────

    #[test]
    fn parse_config_defaults_are_correct() {
        let config = parse_config(&serde_json::json!({}));
        assert_eq!(config.provider, ModerationProvider::OpenaiModeration);
        assert!(config.fail_closed);
        assert!((config.threshold - 0.5).abs() < f64::EPSILON);
        assert_eq!(config.timeout_ms, 3_000);
    }

    #[test]
    fn parse_config_extracts_provider_and_fail_closed() {
        let config = parse_config(&serde_json::json!({
            "provider": "azure-content-safety",
            "fail_closed": true,
            "threshold": 0.8,
            "timeout_ms": 5000
        }));
        assert_eq!(config.provider, ModerationProvider::AzureContentSafety);
        assert!(config.fail_closed);
        assert!((config.threshold - 0.8).abs() < f64::EPSILON);
        assert_eq!(config.timeout_ms, 5_000);
    }

    #[test]
    fn parse_config_recognises_all_providers() {
        let providers = [
            ("openai-moderation", ModerationProvider::OpenaiModeration),
            (
                "azure-content-safety",
                ModerationProvider::AzureContentSafety,
            ),
            (
                "bedrock-apply-guardrail",
                ModerationProvider::BedrockApplyGuardrail,
            ),
            ("embedding-endpoint", ModerationProvider::EmbeddingEndpoint),
            ("presidio", ModerationProvider::Presidio),
            ("guardrails-ai", ModerationProvider::GuardrailsAi),
            ("dynamo-ai", ModerationProvider::DynamoAi),
            ("lakera", ModerationProvider::Lakera),
        ];
        for (name, expected) in providers {
            let config = parse_config(&serde_json::json!({ "provider": name }));
            assert_eq!(config.provider, expected, "provider mismatch for {name}");
        }
    }

    #[test]
    fn parse_config_unknown_provider_defaults_to_openai() {
        let config = parse_config(&serde_json::json!({ "provider": "unknown-provider" }));
        assert_eq!(config.provider, ModerationProvider::OpenaiModeration);
    }

    // ── ModerationResult constructors ────────────────────────────────────

    #[test]
    fn allow_result_is_not_flagged() {
        let result = ModerationResult::allow();
        assert!(!result.flagged);
        assert!(result.scores.is_empty());
        assert!(result.reason.is_none());
    }

    #[test]
    fn flagged_result_carries_scores_and_reason() {
        let mut scores = HashMap::new();
        scores.insert("hate".to_string(), 0.9);
        let result = ModerationResult::flagged(scores.clone(), "test reason");
        assert!(result.flagged);
        assert_eq!(result.scores, scores);
        assert_eq!(result.reason.as_deref(), Some("test reason"));
    }

    #[test]
    fn resolve_api_key_trims_whitespace() {
        let _guard = crate::test_support::env_lock().lock().unwrap();
        let key = "VERDICTAN_EXTMOD_TEST_KEY_TRIM";
        crate::test_support::set_var(key, "  secret-value  ");

        let resolved = resolve_api_key(key).unwrap();
        assert_eq!(resolved, "secret-value");

        crate::test_support::unset_var(key);
    }

    #[test]
    fn resolve_api_key_rejects_empty_secret_key_ref_env_name() {
        let err = resolve_api_key("").unwrap_err();
        assert!(err.contains("not configured"));
    }

    #[test]
    fn resolve_api_key_rejects_unset_env_var() {
        let _guard = crate::test_support::env_lock().lock().unwrap();
        let key = "VERDICTAN_EXTMOD_TEST_KEY_MISSING";
        crate::test_support::unset_var(key);

        let err = resolve_api_key(key).unwrap_err();
        assert!(err.contains("not set"));
    }

    #[test]
    fn resolve_api_key_rejects_empty_env_var_value() {
        let _guard = crate::test_support::env_lock().lock().unwrap();
        let key = "VERDICTAN_EXTMOD_TEST_KEY_EMPTY";
        crate::test_support::set_var(key, "   ");

        let err = resolve_api_key(key).unwrap_err();
        assert!(err.contains("is empty"));

        crate::test_support::unset_var(key);
    }

    #[test]
    fn resolve_api_key_rejects_invalid_env_name() {
        let err = resolve_api_key("invalid-name!").unwrap_err();
        assert!(err.contains("invalid characters"));
    }

    #[test]
    fn parse_config_extracts_secret_and_provider_specific_fields() {
        let config = parse_config(&serde_json::json!({
            "provider": "lakera",
            "secret_key_ref": { "env": "VERDICTAN_EXTMOD_LAKERA_KEY" },
            "endpoint": "https://lakera.example.com",
            "categories": ["prompt_injection"],
            "threshold": 0.75,
            "timeout_ms": 4500,
            "fail_closed": true,
            "presidio_language": "de",
            "presidio_entities": ["PERSON"],
            "guard_name": "strict",
            "policy_id": "policy-1",
            "lakera_categories": ["jailbreak"]
        }));

        assert_eq!(config.provider, ModerationProvider::Lakera);
        assert_eq!(config.secret_key_env, "VERDICTAN_EXTMOD_LAKERA_KEY");
        assert_eq!(
            config.endpoint.as_deref(),
            Some("https://lakera.example.com")
        );
        assert_eq!(config.categories, vec!["prompt_injection".to_string()]);
        assert!((config.threshold - 0.75).abs() < f64::EPSILON);
        assert_eq!(config.timeout_ms, 4_500);
        assert!(config.fail_closed);
        assert_eq!(config.presidio_language.as_deref(), Some("de"));
        assert_eq!(config.presidio_entities, vec!["PERSON".to_string()]);
        assert_eq!(config.guard_name.as_deref(), Some("strict"));
        assert_eq!(config.policy_id.as_deref(), Some("policy-1"));
        assert_eq!(config.lakera_categories, vec!["jailbreak".to_string()]);
    }

    #[test]
    fn parse_config_extracts_bedrock_and_embedding_fields() {
        let config = parse_config(&serde_json::json!({
            "provider": "embedding-endpoint",
            "aws_region": "us-west-2",
            "aws_access_key_env": "VERDICTAN_BEDROCK_ACCESS_KEY",
            "aws_secret_key_env": "VERDICTAN_BEDROCK_SECRET_KEY",
            "aws_session_token_env": "VERDICTAN_BEDROCK_SESSION_TOKEN",
            "guardrail_id": "guardrail-123",
            "guardrail_version": "3",
            "embedding_model": "text-embedding-3-large",
            "reference_texts": ["policy-a", "policy-b"]
        }));

        assert_eq!(config.provider, ModerationProvider::EmbeddingEndpoint);
        assert_eq!(config.aws_region.as_deref(), Some("us-west-2"));
        assert_eq!(
            config.aws_access_key_env.as_deref(),
            Some("VERDICTAN_BEDROCK_ACCESS_KEY")
        );
        assert_eq!(
            config.aws_secret_key_env.as_deref(),
            Some("VERDICTAN_BEDROCK_SECRET_KEY")
        );
        assert_eq!(
            config.aws_session_token_env.as_deref(),
            Some("VERDICTAN_BEDROCK_SESSION_TOKEN")
        );
        assert_eq!(config.guardrail_id.as_deref(), Some("guardrail-123"));
        assert_eq!(config.guardrail_version.as_deref(), Some("3"));
        assert_eq!(
            config.embedding_model.as_deref(),
            Some("text-embedding-3-large")
        );
        assert_eq!(
            config.reference_texts,
            vec!["policy-a".to_string(), "policy-b".to_string()]
        );
    }

    #[test]
    fn parse_config_invalid_secret_ref_falls_back_to_empty_secret_env() {
        let config = parse_config(&serde_json::json!({
            "secret_key_ref": { "store": "shared-secret" }
        }));
        assert!(config.secret_key_env.is_empty());
    }

    #[tokio::test]
    async fn check_dispatch_openai_missing_secret_respects_fail_closed() {
        let blocked = check(
            "unsafe content",
            &ExternalModerationConfig {
                provider: ModerationProvider::OpenaiModeration,
                fail_closed: true,
                ..Default::default()
            },
        )
        .await;
        assert!(blocked.flagged);
        assert!(blocked
            .reason
            .as_deref()
            .unwrap()
            .contains("api key unavailable"));

        let also_blocked = check(
            "unsafe content",
            &ExternalModerationConfig {
                provider: ModerationProvider::OpenaiModeration,
                fail_closed: false,
                ..Default::default()
            },
        )
        .await;
        assert!(also_blocked.flagged);
        assert!(also_blocked.unavailable);
    }

    #[tokio::test]
    async fn check_dispatch_presidio_missing_endpoint_respects_fail_closed() {
        let blocked = check(
            "pii content",
            &ExternalModerationConfig {
                provider: ModerationProvider::Presidio,
                fail_closed: true,
                ..Default::default()
            },
        )
        .await;
        assert!(blocked.flagged);
        assert!(blocked
            .reason
            .as_deref()
            .unwrap()
            .contains("no endpoint configured"));

        let also_blocked = check(
            "pii content",
            &ExternalModerationConfig {
                provider: ModerationProvider::Presidio,
                fail_closed: false,
                ..Default::default()
            },
        )
        .await;
        assert!(also_blocked.flagged);
        assert!(also_blocked.unavailable);
    }

    #[tokio::test]
    async fn check_dispatch_lakera_flags_legacy_flagged_response() {
        let (endpoint, server) =
            start_json_server("/v1/guard", serde_json::json!({ "flagged": true })).await;

        let result = check(
            "prompt injection",
            &ExternalModerationConfig {
                provider: ModerationProvider::Lakera,
                endpoint: Some(endpoint),
                ..Default::default()
            },
        )
        .await;

        assert!(result.flagged);
        assert!(result
            .reason
            .as_deref()
            .unwrap()
            .contains("lakera: prompt injection"));

        server.abort();
    }

    #[tokio::test]
    async fn check_dispatch_lakera_category_filter_can_suppress_flagged_results() {
        let (endpoint, server) = start_json_server(
            "/v1/guard",
            serde_json::json!({
                "results": [{
                    "categories": {
                        "prompt_injection": true,
                        "jailbreak": true
                    }
                }]
            }),
        )
        .await;

        let result = check(
            "prompt injection",
            &ExternalModerationConfig {
                provider: ModerationProvider::Lakera,
                endpoint: Some(endpoint),
                lakera_categories: vec!["phishing".to_string()],
                ..Default::default()
            },
        )
        .await;

        assert!(!result.flagged);
        assert_eq!(result.scores.get("prompt_injection"), Some(&1.0));
        assert_eq!(result.scores.get("jailbreak"), Some(&1.0));

        server.abort();
    }

    // ── F1: Bedrock guardrail_id missing respects fail_closed ────────────

    #[tokio::test]
    async fn bedrock_missing_guardrail_id_blocks_when_fail_closed() {
        let config = ExternalModerationConfig {
            provider: ModerationProvider::BedrockApplyGuardrail,
            fail_closed: true,
            guardrail_id: None,
            ..Default::default()
        };
        let result = check_bedrock_apply_guardrail("test content", &config).await;
        assert!(result.flagged);
        assert!(result.reason.as_deref().unwrap().contains("guardrail_id"));
    }

    #[tokio::test]
    async fn bedrock_missing_guardrail_id_blocks_when_fail_open() {
        let config = ExternalModerationConfig {
            provider: ModerationProvider::BedrockApplyGuardrail,
            fail_closed: false,
            guardrail_id: None,
            ..Default::default()
        };
        let result = check_bedrock_apply_guardrail("test content", &config).await;
        assert!(result.flagged);
        assert!(result.unavailable);
    }

    #[tokio::test]
    async fn bedrock_empty_guardrail_id_blocks_when_fail_closed() {
        let config = ExternalModerationConfig {
            provider: ModerationProvider::BedrockApplyGuardrail,
            fail_closed: true,
            guardrail_id: Some("  ".to_string()),
            ..Default::default()
        };
        let result = check_bedrock_apply_guardrail("test content", &config).await;
        assert!(result.flagged);
        assert!(result.reason.as_deref().unwrap().contains("guardrail_id"));
    }

    #[tokio::test]
    async fn bedrock_missing_aws_region_blocks_when_fail_closed() {
        let config = ExternalModerationConfig {
            provider: ModerationProvider::BedrockApplyGuardrail,
            fail_closed: true,
            guardrail_id: Some("guardrail-123".to_string()),
            ..Default::default()
        };
        let result = check_bedrock_apply_guardrail("test content", &config).await;
        assert!(result.flagged);
        assert!(result.reason.as_deref().unwrap().contains("aws_region"));
    }

    #[tokio::test]
    async fn bedrock_missing_aws_region_blocks_when_fail_open() {
        let config = ExternalModerationConfig {
            provider: ModerationProvider::BedrockApplyGuardrail,
            fail_closed: false,
            guardrail_id: Some("guardrail-123".to_string()),
            ..Default::default()
        };
        let result = check_bedrock_apply_guardrail("test content", &config).await;
        assert!(result.flagged);
        assert!(result.unavailable);
    }

    // ── F2: Embedding precondition checks respect fail_closed ────────────

    #[tokio::test]
    async fn embedding_missing_endpoint_blocks_when_fail_closed() {
        let config = ExternalModerationConfig {
            provider: ModerationProvider::EmbeddingEndpoint,
            fail_closed: true,
            endpoint: None,
            reference_texts: vec!["ref".to_string()],
            ..Default::default()
        };
        let result = check_embedding_moderation("test", &config).await;
        assert!(result.flagged);
        assert!(result.reason.as_deref().unwrap().contains("endpoint"));
    }

    #[tokio::test]
    async fn embedding_missing_endpoint_blocks_when_fail_open() {
        let config = ExternalModerationConfig {
            provider: ModerationProvider::EmbeddingEndpoint,
            fail_closed: false,
            endpoint: None,
            reference_texts: vec!["ref".to_string()],
            ..Default::default()
        };
        let result = check_embedding_moderation("test", &config).await;
        assert!(result.flagged);
        assert!(result.unavailable);
    }

    #[tokio::test]
    async fn embedding_blank_endpoint_blocks_when_fail_closed() {
        let config = ExternalModerationConfig {
            provider: ModerationProvider::EmbeddingEndpoint,
            fail_closed: true,
            endpoint: Some("   ".to_string()),
            reference_texts: vec!["ref".to_string()],
            ..Default::default()
        };
        let result = check_embedding_moderation("test", &config).await;
        assert!(result.flagged);
        assert!(result.reason.as_deref().unwrap().contains("endpoint"));
    }

    #[tokio::test]
    async fn embedding_blank_endpoint_blocks_when_fail_open() {
        let config = ExternalModerationConfig {
            provider: ModerationProvider::EmbeddingEndpoint,
            fail_closed: false,
            endpoint: Some("   ".to_string()),
            reference_texts: vec!["ref".to_string()],
            ..Default::default()
        };
        let result = check_embedding_moderation("test", &config).await;
        assert!(result.flagged);
        assert!(result.unavailable);
    }

    #[tokio::test]
    async fn embedding_empty_reference_texts_blocks_when_fail_closed() {
        let config = ExternalModerationConfig {
            provider: ModerationProvider::EmbeddingEndpoint,
            fail_closed: true,
            endpoint: Some("http://localhost:9999/embed".to_string()),
            reference_texts: vec![],
            ..Default::default()
        };
        let result = check_embedding_moderation("test", &config).await;
        assert!(result.flagged);
        assert!(result
            .reason
            .as_deref()
            .unwrap()
            .contains("reference_texts"));
    }

    #[tokio::test]
    async fn embedding_empty_reference_texts_blocks_when_fail_open() {
        let config = ExternalModerationConfig {
            provider: ModerationProvider::EmbeddingEndpoint,
            fail_closed: false,
            endpoint: Some("http://localhost:9999/embed".to_string()),
            reference_texts: vec![],
            ..Default::default()
        };
        let result = check_embedding_moderation("test", &config).await;
        assert!(result.flagged);
        assert!(result.unavailable);
    }

    // ── F3: GuardrailsAi missing field respects fail_closed ──────────────

    #[tokio::test]
    async fn guardrails_ai_missing_field_blocks_when_fail_closed() {
        let (tx, rx) = tokio::sync::oneshot::channel::<u16>();
        let server = tokio::spawn(async move {
            let app = axum::Router::new().route(
                "/guards/test-guard/validate",
                axum::routing::post(|| async {
                    axum::Json(serde_json::json!({"other_field": "value"}))
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tx.send(port).unwrap();
            axum::serve(listener, app).await.unwrap();
        });

        let port = rx.await.unwrap();
        let config = ExternalModerationConfig {
            provider: ModerationProvider::GuardrailsAi,
            fail_closed: true,
            endpoint: Some(format!("http://127.0.0.1:{port}")),
            guard_name: Some("test-guard".to_string()),
            ..Default::default()
        };
        let result = check_guardrails_ai("test input", &config).await;
        assert!(result.flagged);
        assert!(result
            .reason
            .as_deref()
            .unwrap()
            .contains("validationPassed field missing"));

        server.abort();
    }

    #[tokio::test]
    async fn guardrails_ai_missing_field_blocks_when_fail_open() {
        let (tx, rx) = tokio::sync::oneshot::channel::<u16>();
        let server = tokio::spawn(async move {
            let app = axum::Router::new().route(
                "/guards/test-guard/validate",
                axum::routing::post(|| async {
                    axum::Json(serde_json::json!({"other_field": "value"}))
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tx.send(port).unwrap();
            axum::serve(listener, app).await.unwrap();
        });

        let port = rx.await.unwrap();
        let config = ExternalModerationConfig {
            provider: ModerationProvider::GuardrailsAi,
            fail_closed: false,
            endpoint: Some(format!("http://127.0.0.1:{port}")),
            guard_name: Some("test-guard".to_string()),
            ..Default::default()
        };
        let result = check_guardrails_ai("test input", &config).await;
        assert!(result.flagged);
        assert!(result.unavailable);

        server.abort();
    }

    // ── F3: DynamoAi missing field respects fail_closed ──────────────────

    #[tokio::test]
    async fn dynamo_ai_missing_safe_field_blocks_when_fail_closed() {
        let (tx, rx) = tokio::sync::oneshot::channel::<u16>();
        let server = tokio::spawn(async move {
            let app = axum::Router::new().route(
                "/v1/safety/check",
                axum::routing::post(|| async { axum::Json(serde_json::json!({"status": "ok"})) }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tx.send(port).unwrap();
            axum::serve(listener, app).await.unwrap();
        });

        let port = rx.await.unwrap();
        let config = ExternalModerationConfig {
            provider: ModerationProvider::DynamoAi,
            fail_closed: true,
            endpoint: Some(format!("http://127.0.0.1:{port}")),
            ..Default::default()
        };
        let result = check_dynamo_ai("bad content", &config).await;
        assert!(result.flagged);
        assert!(result
            .reason
            .as_deref()
            .unwrap()
            .contains("safe field missing"));

        server.abort();
    }

    #[tokio::test]
    async fn dynamo_ai_missing_safe_field_blocks_when_fail_open() {
        let (tx, rx) = tokio::sync::oneshot::channel::<u16>();
        let server = tokio::spawn(async move {
            let app = axum::Router::new().route(
                "/v1/safety/check",
                axum::routing::post(|| async { axum::Json(serde_json::json!({"status": "ok"})) }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tx.send(port).unwrap();
            axum::serve(listener, app).await.unwrap();
        });

        let port = rx.await.unwrap();
        let config = ExternalModerationConfig {
            provider: ModerationProvider::DynamoAi,
            fail_closed: false,
            endpoint: Some(format!("http://127.0.0.1:{port}")),
            ..Default::default()
        };
        let result = check_dynamo_ai("content", &config).await;
        assert!(result.flagged);
        assert!(result.unavailable);

        server.abort();
    }

    // ── ModerationProvider serde roundtrip ───────────────────────────────

    #[test]
    fn moderation_provider_serde_roundtrip() {
        for provider in [
            ModerationProvider::OpenaiModeration,
            ModerationProvider::AzureContentSafety,
            ModerationProvider::BedrockApplyGuardrail,
            ModerationProvider::EmbeddingEndpoint,
            ModerationProvider::Presidio,
            ModerationProvider::GuardrailsAi,
            ModerationProvider::DynamoAi,
            ModerationProvider::Lakera,
        ] {
            let json = serde_json::to_string(&provider).unwrap();
            let recovered: ModerationProvider = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, provider);
        }
    }

    #[test]
    fn moderation_provider_default() {
        assert_eq!(
            ModerationProvider::default(),
            ModerationProvider::OpenaiModeration
        );
    }

    // ── ModerationResult constructors ───────────────────────────────────

    #[test]
    fn moderation_result_allow() {
        let result = ModerationResult::allow();
        assert!(!result.flagged);
        assert!(result.scores.is_empty());
        assert!(result.reason.is_none());
    }

    #[test]
    fn moderation_result_flagged() {
        let scores = HashMap::from([("hate".to_string(), 0.9)]);
        let result = ModerationResult::flagged(scores.clone(), "hate speech");
        assert!(result.flagged);
        assert_eq!(result.scores.get("hate"), Some(&0.9));
        assert_eq!(result.reason.as_deref(), Some("hate speech"));
    }

    // ── fail_closed_result ──────────────────────────────────────────────

    #[test]
    fn fail_closed_result_blocks_when_fail_closed() {
        let config = ExternalModerationConfig {
            fail_closed: true,
            ..Default::default()
        };
        let result = fail_closed_result(&config, "service timeout");
        assert!(result.flagged);
    }

    #[test]
    fn fail_closed_result_blocks_when_fail_closed_false_on_timeout() {
        let config = ExternalModerationConfig {
            fail_closed: false,
            ..Default::default()
        };
        let result = fail_closed_result(&config, "service timeout");
        assert!(result.flagged);
        assert!(result.unavailable);
    }

    // ── ExternalModerationConfig defaults ───────────────────────────────

    #[test]
    fn external_moderation_config_defaults() {
        let config = ExternalModerationConfig::default();
        assert_eq!(config.provider, ModerationProvider::OpenaiModeration);
        assert!(config.secret_key_env.is_empty());
        assert!(config.endpoint.is_none());
        assert!(config.categories.is_empty());
        assert!((config.threshold - 0.5).abs() < 1e-9);
        assert_eq!(config.timeout_ms, 3000);
        assert!(config.fail_closed);
    }

    // ── ExternalModerationConfig serde roundtrip ────────────────────────

    #[test]
    fn external_moderation_config_serde_roundtrip() {
        let config = ExternalModerationConfig {
            provider: ModerationProvider::AzureContentSafety,
            secret_key_env: "AZURE_KEY".to_string(),
            endpoint: Some("https://azure.example.com".to_string()),
            categories: vec!["hate".to_string(), "violence".to_string()],
            threshold: 0.7,
            timeout_ms: 5000,
            fail_closed: true,
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let recovered: ExternalModerationConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.provider, ModerationProvider::AzureContentSafety);
        assert_eq!(recovered.categories.len(), 2);
        assert!(recovered.fail_closed);
    }

    // ── resolve_api_key ─────────────────────────────────────────────────

    #[test]
    fn resolve_api_key_empty_env_var() {
        assert!(resolve_api_key("").is_err());
    }

    #[test]
    fn resolve_api_key_invalid_name() {
        assert!(resolve_api_key("invalid-name-with-dashes").is_err());
    }

    // ── default_threshold and default_timeout_ms ────────────────────────

    #[test]
    fn default_threshold_value() {
        assert!((default_threshold() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn default_timeout_ms_value() {
        assert_eq!(default_timeout_ms(), 3000);
    }

    // ── parse_config ───────────────────────────────────────────────────

    #[test]
    fn parse_config_with_threshold() {
        let v = serde_json::json!({"provider": "openai_moderation", "threshold": 0.8});
        let config = parse_config(&v);
        assert!((config.threshold - 0.8).abs() < 1e-9);
    }

    #[test]
    fn parse_config_with_categories() {
        let v = serde_json::json!({
            "provider": "openai_moderation",
            "categories": ["hate", "violence"]
        });
        let config = parse_config(&v);
        assert_eq!(config.categories.len(), 2);
    }

    #[test]
    fn parse_config_empty_object_uses_defaults() {
        let v = serde_json::json!({});
        let config = parse_config(&v);
        assert!((config.threshold - default_threshold()).abs() < 1e-9);
    }
}

#[cfg(test)]
mod coverage_expansion_moderation_tests {
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

    // ── ModerationProvider ──────────────────────────────────────────────

    #[test]
    fn moderation_provider_default_is_openai() {
        let provider = ModerationProvider::default();
        assert_eq!(provider, ModerationProvider::OpenaiModeration);
    }

    #[test]
    fn moderation_provider_serde_round_trip() {
        let providers = vec![
            ModerationProvider::OpenaiModeration,
            ModerationProvider::AzureContentSafety,
            ModerationProvider::BedrockApplyGuardrail,
            ModerationProvider::EmbeddingEndpoint,
            ModerationProvider::Presidio,
            ModerationProvider::GuardrailsAi,
            ModerationProvider::DynamoAi,
            ModerationProvider::Lakera,
        ];
        for p in providers {
            let serialized = serde_json::to_string(&p).unwrap();
            let deserialized: ModerationProvider = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized, p);
        }
    }

    // ── ExternalModerationConfig ────────────────────────────────────────

    #[test]
    fn external_moderation_config_defaults() {
        let config: ExternalModerationConfig = serde_json::from_value(serde_json::json!({
            "provider": "openai-moderation",
            "secret_key_env": "OPENAI_KEY"
        }))
        .unwrap();
        assert_eq!(config.provider, ModerationProvider::OpenaiModeration);
        assert_eq!(config.threshold, default_threshold());
        assert_eq!(config.timeout_ms, default_timeout_ms());
        assert!(config.fail_closed);
        assert!(config.categories.is_empty());
    }

    #[test]
    fn external_moderation_config_custom_values() {
        let config: ExternalModerationConfig = serde_json::from_value(serde_json::json!({
            "provider": "azure-content-safety",
            "secret_key_env": "AZURE_KEY",
            "endpoint": "https://my-resource.cognitiveservices.azure.com",
            "categories": ["hate", "violence"],
            "threshold": 0.8,
            "timeout_ms": 5000,
            "fail_closed": true
        }))
        .unwrap();
        assert_eq!(config.provider, ModerationProvider::AzureContentSafety);
        assert_eq!(
            config.endpoint,
            Some("https://my-resource.cognitiveservices.azure.com".to_string())
        );
        assert_eq!(config.categories, vec!["hate", "violence"]);
        assert_eq!(config.threshold, 0.8);
        assert_eq!(config.timeout_ms, 5000);
        assert!(config.fail_closed);
    }

    #[test]
    fn external_moderation_config_presidio() {
        let config: ExternalModerationConfig = serde_json::from_value(serde_json::json!({
            "provider": "presidio",
            "secret_key_env": "",
            "endpoint": "http://localhost:5002/analyze",
            "presidio_language": "en",
            "presidio_entities": ["PERSON", "CREDIT_CARD"]
        }))
        .unwrap();
        assert_eq!(config.provider, ModerationProvider::Presidio);
        assert_eq!(config.presidio_language, Some("en".to_string()));
        assert_eq!(config.presidio_entities, vec!["PERSON", "CREDIT_CARD"]);
    }

    #[test]
    fn external_moderation_config_bedrock() {
        let config: ExternalModerationConfig = serde_json::from_value(serde_json::json!({
            "provider": "bedrock-apply-guardrail",
            "secret_key_env": "AWS_KEY",
            "aws_region": "us-east-1",
            "guardrail_id": "gr-123",
            "guardrail_version": "DRAFT"
        }))
        .unwrap();
        assert_eq!(config.provider, ModerationProvider::BedrockApplyGuardrail);
        assert_eq!(config.aws_region, Some("us-east-1".to_string()));
        assert_eq!(config.guardrail_id, Some("gr-123".to_string()));
        assert_eq!(config.guardrail_version, Some("DRAFT".to_string()));
    }

    // ── ModerationResult ────────────────────────────────────────────────

    #[test]
    fn moderation_result_allow_is_not_flagged() {
        let result = ModerationResult::allow();
        assert!(!result.flagged);
        assert!(result.scores.is_empty());
        assert!(result.reason.is_none());
    }

    #[test]
    fn moderation_result_flagged_has_reason_and_scores() {
        let scores = HashMap::from([("hate".to_string(), 0.9), ("violence".to_string(), 0.7)]);
        let result = ModerationResult::flagged(scores.clone(), "flagged content");
        assert!(result.flagged);
        assert_eq!(result.scores.len(), 2);
        assert_eq!(result.reason, Some("flagged content".to_string()));
    }

    // ── fail_closed_result ──────────────────────────────────────────────

    #[test]
    fn fail_closed_result_blocks_when_fail_open() {
        let config = ExternalModerationConfig {
            fail_closed: false,
            ..Default::default()
        };
        let result = fail_closed_result(&config, "some error");
        assert!(result.flagged);
        assert!(result.unavailable);
    }

    #[test]
    fn fail_closed_result_flags_when_fail_closed() {
        let config = ExternalModerationConfig {
            fail_closed: true,
            ..Default::default()
        };
        let result = fail_closed_result(&config, "some error");
        assert!(result.flagged);
        assert_eq!(result.reason, Some("some error".to_string()));
    }

    // ── resolve_api_key ─────────────────────────────────────────────────

    #[test]
    fn resolve_api_key_empty_name_returns_error() {
        let result = resolve_api_key("");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("secret_key_ref.env is not configured"));
    }

    #[test]
    fn resolve_api_key_invalid_name_returns_error() {
        let result = resolve_api_key("INVALID/PATH/VAR");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid characters"));
    }

    #[test]
    fn resolve_api_key_missing_env_returns_error() {
        let result = resolve_api_key("VERDICTAN_MODERATION_NONEXISTENT_KEY_12345");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not set"));
    }

    // ── parse_openai_response_body ──────────────────────────────────────

    #[test]
    fn parse_openai_response_body_non_success_status_blocks() {
        let config = ExternalModerationConfig::default();
        let result = parse_openai_response_body(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            Ok::<String, String>("{}".to_string()),
            &config,
        );
        assert!(result.flagged);
        assert!(result.unavailable);
    }

    #[test]
    fn parse_openai_response_body_non_success_status_fail_closed() {
        let config = ExternalModerationConfig {
            fail_closed: true,
            ..Default::default()
        };
        let result = parse_openai_response_body(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            Ok::<String, String>("{}".to_string()),
            &config,
        );
        assert!(result.flagged);
    }

    #[test]
    fn parse_openai_response_body_read_error_blocks() {
        let config = ExternalModerationConfig::default();
        let result = parse_openai_response_body(
            reqwest::StatusCode::OK,
            Err::<String, String>("read failed".to_string()),
            &config,
        );
        assert!(result.flagged);
        assert!(result.unavailable);
    }

    #[test]
    fn parse_openai_response_body_malformed_json_fail_closed() {
        let config = ExternalModerationConfig {
            fail_closed: true,
            ..Default::default()
        };
        let result = parse_openai_response_body(
            reqwest::StatusCode::OK,
            Ok::<String, String>("not json".to_string()),
            &config,
        );
        assert!(result.flagged);
    }

    #[test]
    fn parse_openai_response_body_empty_results_fail_closed() {
        let config = ExternalModerationConfig {
            fail_closed: true,
            ..Default::default()
        };
        let result = parse_openai_response_body(
            reqwest::StatusCode::OK,
            Ok::<String, String>(r#"{"results":[]}"#.to_string()),
            &config,
        );
        assert!(result.flagged);
    }

    #[test]
    fn parse_openai_response_body_below_threshold_allows() {
        let config = ExternalModerationConfig {
            threshold: 0.8,
            ..Default::default()
        };
        let body = serde_json::json!({
            "results": [{
                "category_scores": {"hate": 0.3}
            }]
        });
        let result = parse_openai_response_body(
            reqwest::StatusCode::OK,
            Ok::<String, String>(serde_json::to_string(&body).unwrap()),
            &config,
        );
        assert!(!result.flagged);
    }

    #[test]
    fn parse_openai_response_body_above_threshold_flags() {
        let config = ExternalModerationConfig {
            threshold: 0.5,
            ..Default::default()
        };
        let body = serde_json::json!({
            "results": [{
                "category_scores": {"hate": 0.9, "violence": 0.2}
            }]
        });
        let result = parse_openai_response_body(
            reqwest::StatusCode::OK,
            Ok::<String, String>(serde_json::to_string(&body).unwrap()),
            &config,
        );
        assert!(result.flagged);
        assert!(result.scores.contains_key("hate"));
        assert!(!result.scores.contains_key("violence"));
    }

    #[test]
    fn parse_openai_response_body_category_filter_limits_results() {
        let config = ExternalModerationConfig {
            threshold: 0.5,
            categories: vec!["violence".to_string()],
            ..Default::default()
        };
        let body = serde_json::json!({
            "results": [{
                "category_scores": {"hate": 0.9, "violence": 0.8}
            }]
        });
        let result = parse_openai_response_body(
            reqwest::StatusCode::OK,
            Ok::<String, String>(serde_json::to_string(&body).unwrap()),
            &config,
        );
        assert!(result.flagged);
        assert!(!result.scores.contains_key("hate"));
        assert!(result.scores.contains_key("violence"));
    }

    // ── ModerationProvider serde names ────────────────────────────────

    #[test]
    fn moderation_provider_serializes_to_expected_names() {
        let openai = serde_json::to_string(&ModerationProvider::OpenaiModeration).unwrap();
        assert_eq!(openai, "\"openai-moderation\"");
        let azure = serde_json::to_string(&ModerationProvider::AzureContentSafety).unwrap();
        assert_eq!(azure, "\"azure-content-safety\"");
        let presidio = serde_json::to_string(&ModerationProvider::Presidio).unwrap();
        assert_eq!(presidio, "\"presidio\"");
        let lakera = serde_json::to_string(&ModerationProvider::Lakera).unwrap();
        assert_eq!(lakera, "\"lakera\"");
    }

    // ── ExternalModerationConfig lakera and guardrails_ai ────────────────

    #[test]
    fn external_moderation_config_lakera() {
        let config: ExternalModerationConfig = serde_json::from_value(serde_json::json!({
            "provider": "lakera",
            "secret_key_env": "LAKERA_KEY",
            "endpoint": "https://api.lakera.ai/v1/guard",
            "lakera_categories": ["prompt_injection", "jailbreak"]
        }))
        .unwrap();
        assert_eq!(config.provider, ModerationProvider::Lakera);
        assert_eq!(
            config.lakera_categories,
            vec!["prompt_injection", "jailbreak"]
        );
    }

    #[test]
    fn external_moderation_config_guardrails_ai() {
        let config: ExternalModerationConfig = serde_json::from_value(serde_json::json!({
            "provider": "guardrails-ai",
            "secret_key_env": "GUARD_KEY",
            "guard_name": "my-guard"
        }))
        .unwrap();
        assert_eq!(config.provider, ModerationProvider::GuardrailsAi);
        assert_eq!(config.guard_name, Some("my-guard".to_string()));
    }

    #[test]
    fn external_moderation_config_dynamo_ai() {
        let config: ExternalModerationConfig = serde_json::from_value(serde_json::json!({
            "provider": "dynamo-ai",
            "secret_key_env": "DYNAMO_KEY",
            "policy_id": "pol-123"
        }))
        .unwrap();
        assert_eq!(config.provider, ModerationProvider::DynamoAi);
        assert_eq!(config.policy_id, Some("pol-123".to_string()));
    }

    #[test]
    fn external_moderation_config_embedding_endpoint() {
        let config: ExternalModerationConfig = serde_json::from_value(serde_json::json!({
            "provider": "embedding-endpoint",
            "secret_key_env": "EMB_KEY",
            "endpoint": "http://localhost:8080/embed",
            "embedding_model": "all-MiniLM-L6-v2",
            "reference_texts": ["safe text", "another safe text"]
        }))
        .unwrap();
        assert_eq!(config.provider, ModerationProvider::EmbeddingEndpoint);
        assert_eq!(config.embedding_model, Some("all-MiniLM-L6-v2".to_string()));
        assert_eq!(config.reference_texts.len(), 2);
    }
}
