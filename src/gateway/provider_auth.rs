// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Phase 35 — Provider-specific authentication and endpoint construction.
//!
//! Handles auth header construction for:
//! - OpenAI-compatible endpoints (Bearer token)
//! - Anthropic direct API (x-api-key + anthropic-version)
//! - AWS Bedrock (SigV4 signed requests)
//! - Google Vertex AI (OAuth2 bearer, env-var token, ADC metadata server, or service-account JSON via GoogleAuthResolver)
//! - Azure OpenAI (api-key header + deployment path)
//! - Cloudflare AI (account-scoped OpenAI-compatible endpoints)
//! - Snowflake Cortex (account-scoped inference endpoint)

use crate::{error::CliError, gateway::providers::ProviderTarget};
use aws_credential_types::provider::ProvideCredentials;
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

/// True when the target resolves its provider key from an organization-owned
/// stored secret instead of a local BYOK source.
pub(crate) fn uses_organization_stored_provider_secret(target: &ProviderTarget) -> bool {
    target
        .secret_key_ref
        .as_ref()
        .and_then(|reference| reference.store_name())
        .is_some()
        && target.requires_provider_auth_material()
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuth2GrantType {
    ClientCredentials,
    AuthorizationCode,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct OAuth2Config {
    pub grant_type: OAuth2GrantType,
    pub token_endpoint: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret_env: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub authorization_code: Option<String>,
    #[serde(default)]
    pub authorization_code_env: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub code_verifier_env: Option<String>,
    #[serde(default)]
    pub access_token_env: Option<String>,
    #[serde(default)]
    pub refresh_token_env: Option<String>,
}

// ---------------------------------------------------------------------------
// ProviderType
// ---------------------------------------------------------------------------

/// The type of an upstream provider endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderType {
    #[serde(rename = "openai")]
    OpenAI,
    #[serde(rename = "anthropic")]
    Anthropic,
    #[serde(rename = "cohere")]
    Cohere,
    #[serde(rename = "huggingface")]
    HuggingFace,
    #[serde(rename = "replicate")]
    Replicate,
    #[serde(rename = "databricks")]
    Databricks,
    #[serde(rename = "watsonx")]
    WatsonX,
    #[serde(rename = "aws-bedrock")]
    AwsBedrock,
    #[serde(rename = "google-ai-studio")]
    GoogleAiStudio,
    #[serde(rename = "google-vertex")]
    GoogleVertex,
    #[serde(rename = "sagemaker")]
    SageMaker,
    #[serde(rename = "azure-openai")]
    AzureOpenAI,
    #[serde(rename = "cloudflare-ai")]
    CloudflareAi,
    #[serde(rename = "snowflake-cortex")]
    SnowflakeCortex,
    #[serde(rename = "generic")]
    Generic,
}

impl ProviderType {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "openai" => Some(Self::OpenAI),
            "anthropic" => Some(Self::Anthropic),
            "cohere" => Some(Self::Cohere),
            "huggingface" => Some(Self::HuggingFace),
            "replicate" => Some(Self::Replicate),
            "databricks" => Some(Self::Databricks),
            "watsonx" => Some(Self::WatsonX),
            "aws-bedrock" => Some(Self::AwsBedrock),
            "google-ai-studio" => Some(Self::GoogleAiStudio),
            "google-vertex" => Some(Self::GoogleVertex),
            "sagemaker" => Some(Self::SageMaker),
            "azure-openai" => Some(Self::AzureOpenAI),
            "cloudflare-ai" => Some(Self::CloudflareAi),
            "snowflake-cortex" => Some(Self::SnowflakeCortex),
            "generic" => Some(Self::Generic),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenAI => "openai",
            Self::Anthropic => "anthropic",
            Self::Cohere => "cohere",
            Self::HuggingFace => "huggingface",
            Self::Replicate => "replicate",
            Self::Databricks => "databricks",
            Self::WatsonX => "watsonx",
            Self::AwsBedrock => "aws-bedrock",
            Self::GoogleAiStudio => "google-ai-studio",
            Self::GoogleVertex => "google-vertex",
            Self::SageMaker => "sagemaker",
            Self::AzureOpenAI => "azure-openai",
            Self::CloudflareAi => "cloudflare-ai",
            Self::SnowflakeCortex => "snowflake-cortex",
            Self::Generic => "generic",
        }
    }
}

// ---------------------------------------------------------------------------
// Heuristic provider detection
// ---------------------------------------------------------------------------

/// Detect a `ProviderType` from a base URL heuristically.
pub fn detect_provider_type(base_url: &str) -> ProviderType {
    let lower = base_url.to_ascii_lowercase();
    if lower.contains("models.inference.ai.azure.com")
        || lower.contains("api.ai21.com/studio")
        || lower.contains("dashscope-intl.aliyuncs.com/compatible-mode")
    {
        ProviderType::OpenAI
    } else if lower.contains("anthropic.com") {
        ProviderType::Anthropic
    } else if lower.contains("cohere.ai") {
        ProviderType::Cohere
    } else if lower.contains("huggingface.co") || lower.contains("hf.space") {
        ProviderType::HuggingFace
    } else if lower.contains("replicate.com") {
        ProviderType::Replicate
    } else if lower.contains("databricks.com") {
        ProviderType::Databricks
    } else if lower.contains("watsonx.ai") || lower.contains("ml.cloud.ibm.com") {
        ProviderType::WatsonX
    } else if lower.contains("runtime.sagemaker") {
        ProviderType::SageMaker
    } else if lower.contains("bedrock-runtime") {
        ProviderType::AwsBedrock
    } else if lower.contains("generativelanguage.googleapis.com") {
        ProviderType::GoogleAiStudio
    } else if lower.contains("aiplatform.googleapis.com")
        || lower.contains("vertexai.googleapis.com")
    {
        ProviderType::GoogleVertex
    } else if lower.contains("api.cerebras.ai")
        || lower.contains("api.cometapi.com")
        || lower.contains("api.deepseek.com")
        || lower.contains("api.fireworks.ai")
        || lower.contains("api.hyperbolic.xyz")
        || lower.contains("api.perplexity.ai")
        || lower.contains("api.portkey.ai")
        || lower.contains("api.voyageai.com")
        || lower.contains("llm-gateway.truefoundry.com")
        || lower.contains("models.github.ai")
        || lower.contains("api.llama.com/compat")
        || lower.contains("localhost:12434/engines/v1")
        || lower.contains("localhost:8080/v1")
        || lower.contains("0.0.0.0:4000")
    {
        ProviderType::OpenAI
    } else if lower.contains("api.cloudflare.com/client/v4/accounts") && lower.contains("/ai/v1") {
        ProviderType::CloudflareAi
    } else if lower.contains(".snowflakecomputing.com") {
        ProviderType::SnowflakeCortex
    } else if lower.contains("openai.azure.com") || lower.contains(".azure.com") {
        ProviderType::AzureOpenAI
    } else if lower.contains("api.openai.com") || lower.contains("github") {
        ProviderType::OpenAI
    } else {
        ProviderType::Generic
    }
}

/// Resolve the effective `ProviderType` for a target: explicit field takes precedence
/// over URL-heuristic detection.
pub fn resolve_provider_type(target: &ProviderTarget) -> ProviderType {
    target
        .provider_type
        .unwrap_or_else(|| detect_provider_type(&target.base_url))
}

// ---------------------------------------------------------------------------
// ProviderAuthResult
// ---------------------------------------------------------------------------

/// Auth information and routing overrides produced by `build_provider_auth`.
#[derive(Debug, Default)]
pub struct ProviderAuthResult {
    /// Additional HTTP headers to inject (name, value).
    pub extra_headers: Vec<(String, String)>,
    /// If set, overrides the request path (e.g. Bedrock, Vertex, Azure use non-standard paths).
    pub endpoint_override: Option<String>,
    /// If set, overrides the base URL (e.g. Azure uses a deployment-specific hostname).
    pub base_url_override: Option<String>,
    /// If set, overrides the auth type; caller appends via upstream_auth mechanism instead.
    /// For providers that are fully handled through `extra_headers`, this is None.
    pub primary_auth_header: Option<(String, String)>,
}

// ---------------------------------------------------------------------------
// Main auth builder
// ---------------------------------------------------------------------------

/// Build auth headers, endpoint overrides, and body for the given provider target.
///
/// `body_bytes` is the serialised request body (needed for Bedrock SigV4 body hash).
/// `is_streaming` affects the Vertex AI endpoint suffix.
pub async fn build_provider_auth(
    target: &ProviderTarget,
    model: &str,
    path: &str,
    body_bytes: &[u8],
    is_streaming: bool,
) -> Result<ProviderAuthResult, CliError> {
    let ptype = resolve_provider_type(target);
    match ptype {
        ProviderType::OpenAI | ProviderType::Generic => build_openai_auth(target).await,
        ProviderType::Anthropic => build_anthropic_auth(target).await,
        ProviderType::Cohere => build_cohere_auth(target).await,
        ProviderType::HuggingFace => build_huggingface_auth(target).await,
        ProviderType::Replicate => build_replicate_auth(target).await,
        ProviderType::Databricks => build_databricks_auth(target).await,
        ProviderType::WatsonX => build_watsonx_auth(target, is_streaming).await,
        ProviderType::AwsBedrock => {
            build_bedrock_auth(target, model, path, body_bytes, is_streaming).await
        }
        ProviderType::GoogleAiStudio => {
            build_google_ai_studio_auth(target, model, is_streaming).await
        }
        ProviderType::GoogleVertex => build_vertex_auth(target, model, is_streaming).await,
        ProviderType::SageMaker => build_sagemaker_auth(target, model, body_bytes).await,
        ProviderType::AzureOpenAI => build_azure_auth(target, path).await,
        ProviderType::CloudflareAi => build_cloudflare_ai_auth(target, path).await,
        ProviderType::SnowflakeCortex => build_snowflake_auth(target).await,
    }
}

async fn append_oauth_header(
    target: &ProviderTarget,
    extra_headers: &mut Vec<(String, String)>,
) -> Result<(), CliError> {
    let Some(oauth2) = &target.oauth2 else {
        return Ok(());
    };
    let token = resolve_oauth_token(target, oauth2).await?;
    extra_headers.push(("Authorization".to_string(), token.bearer_value()));
    Ok(())
}

fn require_resolved_api_key(target: &ProviderTarget, provider_name: &str) -> Result<(), CliError> {
    if target.api_key.is_empty() && target.requires_resolved_api_key() {
        return Err(CliError::user(format!(
            "provider '{}': {provider_name} requires an API key via secret_key_ref.env or a control-plane-resolved secret_key_ref.store value",
            target.id
        )));
    }
    Ok(())
}

fn require_explicit_aws_region(
    target: &ProviderTarget,
    provider_name: &str,
) -> Result<String, CliError> {
    target
        .aws_region
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| {
            CliError::user(format!(
                "provider '{}': {provider_name} requires explicit aws_region in provider config",
                target.id
            ))
        })
}

// ---------------------------------------------------------------------------
// OpenAI / Generic
// ---------------------------------------------------------------------------

async fn build_openai_auth(target: &ProviderTarget) -> Result<ProviderAuthResult, CliError> {
    let mut extra = Vec::new();
    // Static extra headers configured in the target (e.g. organisation headers)
    for (name, value) in &target.headers {
        extra.push((name.clone(), value.clone()));
    }
    append_oauth_header(target, &mut extra).await?;
    Ok(ProviderAuthResult {
        extra_headers: extra,
        ..Default::default()
    })
}

async fn build_cohere_auth(target: &ProviderTarget) -> Result<ProviderAuthResult, CliError> {
    let mut extra = Vec::new();
    for (name, value) in &target.headers {
        extra.push((name.clone(), value.clone()));
    }
    append_oauth_header(target, &mut extra).await?;
    Ok(ProviderAuthResult {
        extra_headers: extra,
        endpoint_override: Some(
            target
                .path_template
                .clone()
                .unwrap_or_else(|| "/v2/chat".to_string())
                .replace("{model}", &target.model),
        ),
        ..Default::default()
    })
}

async fn build_huggingface_auth(target: &ProviderTarget) -> Result<ProviderAuthResult, CliError> {
    let mut extra = Vec::new();
    for (name, value) in &target.headers {
        extra.push((name.clone(), value.clone()));
    }
    append_oauth_header(target, &mut extra).await?;
    Ok(ProviderAuthResult {
        extra_headers: extra,
        endpoint_override: Some(
            target
                .path_template
                .clone()
                .unwrap_or_else(|| "/models/{model}".to_string())
                .replace("{model}", &target.model),
        ),
        ..Default::default()
    })
}

async fn build_replicate_auth(target: &ProviderTarget) -> Result<ProviderAuthResult, CliError> {
    let mut extra = vec![("Prefer".to_string(), "wait".to_string())];
    for (name, value) in &target.headers {
        extra.push((name.clone(), value.clone()));
    }
    append_oauth_header(target, &mut extra).await?;
    Ok(ProviderAuthResult {
        extra_headers: extra,
        endpoint_override: Some(
            target
                .path_template
                .clone()
                .unwrap_or_else(|| "/v1/models/{model}/predictions".to_string())
                .replace("{model}", &target.model),
        ),
        ..Default::default()
    })
}

async fn build_databricks_auth(target: &ProviderTarget) -> Result<ProviderAuthResult, CliError> {
    let mut extra = Vec::new();
    for (name, value) in &target.headers {
        extra.push((name.clone(), value.clone()));
    }
    append_oauth_header(target, &mut extra).await?;
    Ok(ProviderAuthResult {
        extra_headers: extra,
        endpoint_override: Some(
            target
                .path_template
                .clone()
                .unwrap_or_else(|| "/serving-endpoints/{model}/invocations".to_string())
                .replace("{model}", &target.model),
        ),
        ..Default::default()
    })
}

#[derive(Clone, Debug)]
struct CachedWatsonxToken {
    access_token: String,
    expires_at_epoch_s: i64,
}

fn watsonx_token_cache() -> &'static Mutex<HashMap<String, CachedWatsonxToken>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CachedWatsonxToken>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lookup_cached_watsonx_token(api_key: &str) -> Option<String> {
    let now = chrono::Utc::now().timestamp();
    watsonx_token_cache()
        .lock()
        .ok()
        .and_then(|cache| cache.get(api_key).cloned())
        .filter(|cached| cached.expires_at_epoch_s.saturating_sub(30) > now)
        .map(|cached| cached.access_token)
}

fn store_cached_watsonx_token(api_key: &str, token: &CachedWatsonxToken) {
    if let Ok(mut cache) = watsonx_token_cache().lock() {
        cache.insert(api_key.to_string(), token.clone());
    }
}

async fn build_watsonx_auth(
    target: &ProviderTarget,
    is_streaming: bool,
) -> Result<ProviderAuthResult, CliError> {
    let api_version = target
        .watsonx_api_version
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::user(format!(
                "provider '{}': watsonx requires watsonx_api_version",
                target.id
            ))
        })?;
    let project_id = target
        .watsonx_project_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let space_id = target
        .watsonx_space_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if project_id.is_some() == space_id.is_some() {
        return Err(CliError::user(format!(
            "provider '{}': watsonx requires exactly one of watsonx_project_id or watsonx_space_id",
            target.id
        )));
    }

    let token = if let Ok(token) = std::env::var("WATSONX_ACCESS_TOKEN") {
        token
    } else if target.api_key.starts_with("eyJ") {
        target.api_key.clone()
    } else if !target.api_key.is_empty() {
        if let Some(cached) = lookup_cached_watsonx_token(&target.api_key) {
            cached
        } else {
            let exchanged = exchange_watsonx_access_token(&target.api_key).await?;
            let token = exchanged.access_token.clone();
            store_cached_watsonx_token(&target.api_key, &exchanged);
            token
        }
    } else {
        return Err(CliError::user(format!(
            "provider '{}': watsonx requires WATSONX_ACCESS_TOKEN or an IBM Cloud API key via secret_key_ref.env",
            target.id
        )));
    };

    let mut extra = vec![("Authorization".to_string(), format!("Bearer {token}"))];
    for (name, value) in &target.headers {
        extra.push((name.clone(), value.clone()));
    }
    let endpoint = if is_streaming {
        format!("/ml/v1/text/chat_stream?version={api_version}")
    } else {
        format!("/ml/v1/text/chat?version={api_version}")
    };

    Ok(ProviderAuthResult {
        extra_headers: extra,
        endpoint_override: Some(endpoint),
        ..Default::default()
    })
}

fn watsonx_iam_token_endpoint() -> String {
    #[cfg(test)]
    {
        std::env::var("VERDICTAN_TEST_WATSONX_IAM_URL")
            .unwrap_or_else(|_| "https://iam.cloud.ibm.com/identity/token".to_string())
    }

    #[cfg(not(test))]
    {
        "https://iam.cloud.ibm.com/identity/token".to_string()
    }
}

async fn exchange_watsonx_access_token(api_key: &str) -> Result<CachedWatsonxToken, CliError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|error| CliError::user(format!("failed to build watsonx auth client: {error}")))?;
    let token_endpoint = watsonx_iam_token_endpoint();

    let response = client
        .post(token_endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=urn:ibm:params:oauth:grant-type:apikey&apikey={}",
            urlencoding::encode(api_key)
        ))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|error| CliError::user(format!("watsonx IAM token exchange failed: {error}")))?;

    let payload: serde_json::Value = response
        .json()
        .await
        .map_err(|error| CliError::user(format!("invalid watsonx IAM token response: {error}")))?;
    let access_token = payload
        .get("access_token")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| CliError::user("watsonx IAM token response did not include access_token"))?;
    let now = chrono::Utc::now().timestamp();
    let expires_at_epoch_s = payload
        .get("expiration")
        .and_then(|value| value.as_i64())
        .or_else(|| {
            payload
                .get("expires_in")
                .and_then(|value| value.as_i64())
                .map(|seconds| now.saturating_add(seconds))
        })
        .unwrap_or_else(|| now.saturating_add(300));
    Ok(CachedWatsonxToken {
        access_token,
        expires_at_epoch_s,
    })
}

// ---------------------------------------------------------------------------
// Anthropic
// ---------------------------------------------------------------------------

async fn build_anthropic_auth(target: &ProviderTarget) -> Result<ProviderAuthResult, CliError> {
    require_resolved_api_key(target, "anthropic")?;
    let api_version = target
        .anthropic_version
        .as_deref()
        .unwrap_or("2023-06-01")
        .to_string();

    let mut extra = vec![
        ("anthropic-version".to_string(), api_version),
        (
            "x-api-key".to_string(),
            format!("{}{}", target.api_key_prefix, target.api_key),
        ),
    ];
    for (name, value) in &target.headers {
        extra.push((name.clone(), value.clone()));
    }
    append_oauth_header(target, &mut extra).await?;

    // Anthropic uses its own header names; disable the generic upstream_auth header
    // by returning the api-key via extra_headers so the caller can skip upstream_auth.
    Ok(ProviderAuthResult {
        extra_headers: extra,
        // Signal to the caller that the standard upstream_auth header should not be set
        primary_auth_header: None,
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------
// Azure OpenAI
// ---------------------------------------------------------------------------

async fn build_azure_auth(
    target: &ProviderTarget,
    path: &str,
) -> Result<ProviderAuthResult, CliError> {
    require_resolved_api_key(target, "azure-openai")?;
    let api_version = target.azure_api_version.as_deref().unwrap_or("2024-02-01");
    let deployment = match target.azure_deployment.as_deref() {
        Some(d) if !d.is_empty() => d.to_string(),
        _ => target.model.clone(),
    };

    // Azure path: /openai/deployments/{deployment}/{operation}?api-version={ver}
    let operation = if path.ends_with("chat/completions") {
        "chat/completions"
    } else {
        path.trim_start_matches('/')
    };
    let endpoint =
        format!("/openai/deployments/{deployment}/{operation}?api-version={api_version}",);

    let mut extra = vec![("api-key".to_string(), target.api_key.clone())];
    for (name, value) in &target.headers {
        extra.push((name.clone(), value.clone()));
    }
    append_oauth_header(target, &mut extra).await?;

    Ok(ProviderAuthResult {
        extra_headers: extra,
        endpoint_override: Some(endpoint),
        ..Default::default()
    })
}

async fn build_cloudflare_ai_auth(
    target: &ProviderTarget,
    path: &str,
) -> Result<ProviderAuthResult, CliError> {
    let mut extra = Vec::new();
    for (name, value) in &target.headers {
        extra.push((name.clone(), value.clone()));
    }
    append_oauth_header(target, &mut extra).await?;

    let endpoint =
        if target.base_url.trim_end_matches('/').ends_with("/v1") && path.starts_with("/v1/") {
            format!("/{}", path.trim_start_matches("/v1/"))
        } else {
            path.to_string()
        };

    Ok(ProviderAuthResult {
        extra_headers: extra,
        endpoint_override: Some(endpoint),
        ..Default::default()
    })
}

async fn build_snowflake_auth(target: &ProviderTarget) -> Result<ProviderAuthResult, CliError> {
    let mut extra = Vec::new();
    for (name, value) in &target.headers {
        extra.push((name.clone(), value.clone()));
    }
    append_oauth_header(target, &mut extra).await?;

    Ok(ProviderAuthResult {
        extra_headers: extra,
        endpoint_override: Some("/api/v2/cortex/inference:complete".to_string()),
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------
// Google AI Studio
// ---------------------------------------------------------------------------

pub fn google_ai_studio_endpoint(model_id: &str, is_streaming: bool) -> String {
    let suffix = if is_streaming {
        "streamGenerateContent?alt=sse"
    } else {
        "generateContent"
    };
    format!("/v1beta/models/{model_id}:{suffix}")
}

async fn build_google_ai_studio_auth(
    target: &ProviderTarget,
    model: &str,
    is_streaming: bool,
) -> Result<ProviderAuthResult, CliError> {
    if target.api_key.is_empty() {
        return Err(CliError::user(format!(
            "provider '{}': google-ai-studio requires an API key via secret_key_ref.env",
            target.id
        )));
    }
    let model_id = if model.is_empty() {
        &target.model
    } else {
        model
    };
    let endpoint = target
        .path_template
        .clone()
        .unwrap_or_else(|| google_ai_studio_endpoint(model_id, is_streaming))
        .replace("{model}", model_id);

    let mut extra = vec![("x-goog-api-key".to_string(), target.api_key.clone())];
    for (name, value) in &target.headers {
        extra.push((name.clone(), value.clone()));
    }
    append_oauth_header(target, &mut extra).await?;

    Ok(ProviderAuthResult {
        extra_headers: extra,
        endpoint_override: Some(endpoint),
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------
// Google Vertex AI
// ---------------------------------------------------------------------------

/// Build the Vertex AI endpoint URL for a model.
pub fn vertex_endpoint(
    project_id: &str,
    region: &str,
    model_id: &str,
    is_streaming: bool,
) -> String {
    let suffix = if is_streaming {
        "streamGenerateContent"
    } else {
        "generateContent"
    };
    format!(
        "/v1/projects/{project_id}/locations/{region}/publishers/google/models/{model_id}:{suffix}"
    )
}

async fn build_vertex_auth(
    target: &ProviderTarget,
    model: &str,
    is_streaming: bool,
) -> Result<ProviderAuthResult, CliError> {
    let project = target.gcp_project.as_deref().unwrap_or("").to_string();
    let region = target
        .gcp_region
        .as_deref()
        .unwrap_or("us-central1")
        .to_string();
    let model_id = if model.is_empty() {
        &target.model
    } else {
        model
    };

    let endpoint = vertex_endpoint(&project, &region, model_id, is_streaming);

    // Priority 1: Explicit OAuth2 config — handled first, before the resolver.
    let token = if let Some(oauth2) = &target.oauth2 {
        resolve_oauth_token(target, oauth2)
            .await
            .map_err(|e| {
                CliError::user(format!(
                    "provider '{}': vertex OAuth2 failed: {e}",
                    target.id
                ))
            })?
            .access_token
    } else {
        // Priorities 2–5: delegate to GoogleAuthResolver (api_key → env var → ADC → service account).
        crate::gateway::google_auth::GoogleAuthResolver::new(
            target.api_key.clone(),
            target.id.clone(),
        )
        .resolve_token()
        .await
        .map_err(|e| CliError::user(e.to_string()))?
    };

    let mut extra = vec![("Authorization".to_string(), format!("Bearer {token}"))];
    for (name, value) in &target.headers {
        extra.push((name.clone(), value.clone()));
    }

    Ok(ProviderAuthResult {
        extra_headers: extra,
        endpoint_override: Some(endpoint),
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------
// Amazon SageMaker Runtime
// ---------------------------------------------------------------------------

async fn build_sagemaker_auth(
    target: &ProviderTarget,
    model: &str,
    body_bytes: &[u8],
) -> Result<ProviderAuthResult, CliError> {
    let aws_region = require_explicit_aws_region(target, "sagemaker")?;

    let access_key = if !target.api_key.is_empty() {
        target.api_key.clone()
    } else {
        std::env::var("AWS_ACCESS_KEY_ID").ok().unwrap_or_default()
    };
    let secret_key = if !target.api_key_prefix.is_empty() {
        target.api_key_prefix.clone()
    } else {
        std::env::var("AWS_SECRET_ACCESS_KEY")
            .ok()
            .unwrap_or_default()
    };
    let session_token = std::env::var("AWS_SESSION_TOKEN").ok();

    if access_key.is_empty() || secret_key.is_empty() {
        return Err(CliError::user(format!(
            "provider '{}': sagemaker requires AWS credentials via api_key/api_key_prefix or AWS_* env vars",
            target.id
        )));
    }

    let endpoint_name = if model.is_empty() {
        &target.model
    } else {
        model
    };
    let endpoint = target
        .path_template
        .clone()
        .unwrap_or_else(|| "/endpoints/{model}/invocations".to_string())
        .replace("{model}", endpoint_name);

    let host = reqwest::Url::parse(&target.base_url)
        .ok()
        .and_then(|url| url.host_str().map(ToString::to_string))
        .unwrap_or_else(|| format!("runtime.sagemaker.{aws_region}.amazonaws.com"));

    let sigv4_headers = sign_aws_request(
        &access_key,
        &secret_key,
        session_token.as_deref(),
        &aws_region,
        "sagemaker",
        &host,
        &endpoint,
        body_bytes,
    )?;

    let mut extra = sigv4_headers;
    for (name, value) in &target.headers {
        extra.push((name.clone(), value.clone()));
    }
    append_oauth_header(target, &mut extra).await?;

    let base_url_override = if target.base_url.is_empty() {
        Some(format!("https://{host}"))
    } else {
        None
    };

    Ok(ProviderAuthResult {
        extra_headers: extra,
        endpoint_override: Some(endpoint),
        base_url_override,
        ..Default::default()
    })
}

async fn resolve_bedrock_credentials(
    target: &ProviderTarget,
    aws_region: &str,
) -> Result<(String, String, Option<String>), CliError> {
    let access_key = if !target.api_key.is_empty() {
        target.api_key.clone()
    } else {
        std::env::var("AWS_ACCESS_KEY_ID").ok().unwrap_or_default()
    };
    let secret_key = if !target.api_key_prefix.is_empty() {
        target.api_key_prefix.clone()
    } else {
        std::env::var("AWS_SECRET_ACCESS_KEY")
            .ok()
            .unwrap_or_default()
    };

    if !access_key.is_empty() && !secret_key.is_empty() {
        let session_token = std::env::var("AWS_SESSION_TOKEN").ok();
        return Ok((access_key, secret_key, session_token));
    }

    let has_explicit_attempt = !target.api_key.is_empty()
        || !target.api_key_prefix.is_empty()
        || std::env::var("AWS_ACCESS_KEY_ID").is_ok()
        || std::env::var("AWS_SECRET_ACCESS_KEY").is_ok();
    if has_explicit_attempt {
        return Err(CliError::user(format!(
            "provider '{}': aws-bedrock requires AWS credentials via api_key/api_key_prefix or AWS_* env vars",
            target.id
        )));
    }

    resolve_aws_credentials(target, aws_region, "aws-bedrock").await
}

async fn resolve_aws_credentials(
    target: &ProviderTarget,
    aws_region: &str,
    provider_name: &str,
) -> Result<(String, String, Option<String>), CliError> {
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(aws_region.to_string()));
    if let Some(profile) = target
        .aws_profile
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        loader = loader.profile_name(profile);
    }
    let sdk_config = loader.load().await;
    let provider = sdk_config.credentials_provider().ok_or_else(|| {
        CliError::user(format!(
            "provider '{}': {provider_name} could not resolve an AWS credentials provider from the default chain",
            target.id
        ))
    })?;
    let credentials = provider.provide_credentials().await.map_err(|error| {
        CliError::user(format!(
            "provider '{}': {provider_name} AWS credential resolution failed: {error}",
            target.id
        ))
    })?;
    Ok((
        credentials.access_key_id().to_string(),
        credentials.secret_access_key().to_string(),
        credentials.session_token().map(ToString::to_string),
    ))
}

// ---------------------------------------------------------------------------
// AWS Bedrock — SigV4
// ---------------------------------------------------------------------------

async fn build_bedrock_auth(
    target: &ProviderTarget,
    model: &str,
    _path: &str,
    body_bytes: &[u8],
    is_streaming: bool,
) -> Result<ProviderAuthResult, CliError> {
    let aws_region = require_explicit_aws_region(target, "aws-bedrock")?;
    let (access_key, secret_key, session_token) =
        resolve_bedrock_credentials(target, &aws_region).await?;

    // Build Bedrock model endpoint path
    let model_id = if model.is_empty() {
        &target.model
    } else {
        model
    };
    let encoded_model_id = urlencoding::encode(model_id);
    let endpoint = if is_streaming {
        format!("/model/{encoded_model_id}/invoke-with-response-stream")
    } else {
        format!("/model/{encoded_model_id}/invoke")
    };

    // Build the Bedrock hostname for the given region
    let host = format!("bedrock-runtime.{aws_region}.amazonaws.com");

    let sigv4_headers = sign_bedrock_request(
        &access_key,
        &secret_key,
        session_token.as_deref(),
        &aws_region,
        &host,
        &endpoint,
        body_bytes,
    )?;

    let mut extra: Vec<(String, String)> = sigv4_headers;
    if is_streaming {
        extra.push((
            "accept".to_string(),
            "application/vnd.amazon.eventstream".to_string(),
        ));
        extra.push((
            "x-amzn-bedrock-accept".to_string(),
            "application/json".to_string(),
        ));
    }
    for (name, value) in &target.headers {
        extra.push((name.clone(), value.clone()));
    }
    append_oauth_header(target, &mut extra).await?;

    let base_url_override = if target.base_url.trim().is_empty() {
        Some(format!("https://{host}"))
    } else if let Ok(url) = reqwest::Url::parse(&target.base_url) {
        match url.host_str() {
            Some(host_value) if host_value == host => None,
            Some("127.0.0.1" | "localhost" | "::1") => None,
            Some(host_value)
                if host_value.starts_with("bedrock-runtime.")
                    && host_value.ends_with(".amazonaws.com")
                    && host_value != host =>
            {
                return Err(CliError::user(format!(
                    "provider '{}': aws-bedrock base_url host must match aws_region '{}'",
                    target.id, aws_region
                )));
            }
            _ => None,
        }
    } else {
        None
    };

    Ok(ProviderAuthResult {
        extra_headers: extra,
        endpoint_override: Some(endpoint),
        base_url_override,
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------
// SigV4 implementation
// ---------------------------------------------------------------------------

/// Sign a Bedrock request and return the auth-related HTTP headers.
#[allow(clippy::too_many_arguments)]
pub fn sign_bedrock_request(
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
    region: &str,
    host: &str,
    path: &str,
    body: &[u8],
) -> Result<Vec<(String, String)>, CliError> {
    sign_aws_request(
        access_key,
        secret_key,
        session_token,
        region,
        "bedrock",
        host,
        path,
        body,
    )
}

#[allow(clippy::too_many_arguments)]
fn sign_aws_request(
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
    region: &str,
    service: &str,
    host: &str,
    path: &str,
    body: &[u8],
) -> Result<Vec<(String, String)>, CliError> {
    use hmac::{Hmac, Mac};
    use sha2::Digest;

    let now = chrono::Utc::now();
    let datetime = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();

    // Body hash
    let body_hash = {
        let mut h = sha2::Sha256::new();
        h.update(body);
        hex::encode(h.finalize())
    };

    // Canonical request
    let mut signed_headers_list = vec!["content-type", "host", "x-amz-date"];
    if session_token.is_some() {
        signed_headers_list.push("x-amz-security-token");
    }
    signed_headers_list.sort_unstable();
    let signed_headers = signed_headers_list.join(";");

    let mut canonical_headers =
        format!("content-type:application/json\nhost:{host}\nx-amz-date:{datetime}\n",);
    if let Some(token) = session_token {
        canonical_headers.push_str(&format!("x-amz-security-token:{token}\n"));
    }

    // Re-sort so our ordered canonical headers match signed_headers_list alphabetically.
    // Since we built them in order "content-type, host, x-amz-date[, x-amz-security-token]"
    // and these are already alphabetically sorted, no further sorting required.

    let canonical_request =
        format!("POST\n{path}\n\n{canonical_headers}\n{signed_headers}\n{body_hash}");

    // String to sign
    let credential_scope = format!("{date}/{region}/{service}/aws4_request");
    let canonical_hash = {
        let mut h = sha2::Sha256::new();
        h.update(canonical_request.as_bytes());
        hex::encode(h.finalize())
    };
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{datetime}\n{credential_scope}\n{canonical_hash}");

    // Signing key
    type HmacSha256 = Hmac<sha2::Sha256>;
    let sign = |key: &[u8], msg: &[u8]| -> Vec<u8> {
        // SAFETY: HMAC accepts keys of any length
        #[allow(clippy::expect_used)]
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key valid");
        mac.update(msg);
        mac.finalize().into_bytes().to_vec()
    };

    let signing_key = {
        let k_date = sign(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
        let k_region = sign(&k_date, region.as_bytes());
        let k_service = sign(&k_region, service.as_bytes());
        sign(&k_service, b"aws4_request")
    };

    // Compute signature
    let signature = {
        // SAFETY: HMAC accepts keys of any length
        #[allow(clippy::expect_used)]
        let mut mac = HmacSha256::new_from_slice(&signing_key).expect("HMAC key valid");
        mac.update(string_to_sign.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    };

    // Authorization header
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );

    let mut headers = vec![
        ("x-amz-date".to_string(), datetime),
        ("x-amz-content-sha256".to_string(), body_hash),
        ("Authorization".to_string(), authorization),
    ];
    if let Some(token) = session_token {
        headers.push(("x-amz-security-token".to_string(), token.to_string()));
    }

    Ok(headers)
}

async fn resolve_oauth_token(
    target: &ProviderTarget,
    oauth2: &OAuth2Config,
) -> Result<crate::gateway::oauth_token_store::CachedOAuthToken, CliError> {
    let cache_key = format!(
        "{}|{}|{}|{}",
        target.id,
        oauth2.token_endpoint,
        oauth2.client_id,
        oauth2.scopes.join(" ")
    );
    let store = crate::gateway::oauth_token_store::OAuthTokenStore::global();

    if let Some(token) = store.get(&cache_key) {
        if token.is_fresh() {
            return Ok(token);
        }

        if let Some(refresh_token) = token.refresh_token.clone() {
            if let Ok(refreshed) = refresh_oauth_token(oauth2, &refresh_token).await {
                store.put(cache_key.clone(), refreshed.clone());
                return Ok(refreshed);
            }
        }
    }

    if let Some(access_token_env) = &oauth2.access_token_env {
        if let Ok(access_token) = std::env::var(access_token_env) {
            if !access_token.trim().is_empty() {
                let token = crate::gateway::oauth_token_store::CachedOAuthToken::from_expires_in(
                    access_token.trim().to_string(),
                    oauth2
                        .refresh_token_env
                        .as_ref()
                        .and_then(|env| std::env::var(env).ok()),
                    "Bearer".to_string(),
                    std::time::Duration::from_secs(300),
                );
                store.put(cache_key, token.clone());
                return Ok(token);
            }
        }
    }

    let exchanged = exchange_oauth_token(oauth2).await?;
    store.put(cache_key, exchanged.clone());
    Ok(exchanged)
}

async fn exchange_oauth_token(
    oauth2: &OAuth2Config,
) -> Result<crate::gateway::oauth_token_store::CachedOAuthToken, CliError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|error| CliError::user(format!("failed to build oauth2 client: {error}")))?;

    let mut params = vec![("client_id", oauth2.client_id.clone())];
    if let Some(secret) = oauth2
        .client_secret_env
        .as_ref()
        .and_then(|env| std::env::var(env).ok())
    {
        if !secret.trim().is_empty() {
            params.push(("client_secret", secret.trim().to_string()));
        }
    }
    if !oauth2.scopes.is_empty() {
        params.push(("scope", oauth2.scopes.join(" ")));
    }
    if let Some(audience) = &oauth2.audience {
        params.push(("audience", audience.clone()));
    }

    match oauth2.grant_type {
        OAuth2GrantType::ClientCredentials => {
            params.push(("grant_type", "client_credentials".to_string()));
        }
        OAuth2GrantType::AuthorizationCode => {
            params.push(("grant_type", "authorization_code".to_string()));
            let code = oauth2
                .authorization_code
                .clone()
                .or_else(|| {
                    oauth2
                        .authorization_code_env
                        .as_ref()
                        .and_then(|env| std::env::var(env).ok())
                })
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| CliError::user("oauth2 authorization_code grant requires authorization_code or authorization_code_env"))?;
            params.push(("code", code));
            if let Some(redirect_uri) = &oauth2.redirect_uri {
                params.push(("redirect_uri", redirect_uri.clone()));
            }
            let verifier = oauth2
                .code_verifier
                .clone()
                .or_else(|| {
                    oauth2
                        .code_verifier_env
                        .as_ref()
                        .and_then(|env| std::env::var(env).ok())
                })
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| CliError::user("oauth2 authorization_code grant requires code_verifier or code_verifier_env"))?;
            params.push(("code_verifier", verifier));
        }
    }

    let response = client
        .post(&oauth2.token_endpoint)
        .form(&params)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|error| CliError::user(format!("oauth2 token exchange failed: {error}")))?;
    parse_oauth_token_response(response).await
}

async fn refresh_oauth_token(
    oauth2: &OAuth2Config,
    refresh_token: &str,
) -> Result<crate::gateway::oauth_token_store::CachedOAuthToken, CliError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|error| {
            CliError::user(format!("failed to build oauth2 refresh client: {error}"))
        })?;

    let mut params = vec![
        ("grant_type", "refresh_token".to_string()),
        ("client_id", oauth2.client_id.clone()),
        ("refresh_token", refresh_token.to_string()),
    ];
    if let Some(secret) = oauth2
        .client_secret_env
        .as_ref()
        .and_then(|env| std::env::var(env).ok())
    {
        if !secret.trim().is_empty() {
            params.push(("client_secret", secret.trim().to_string()));
        }
    }

    let response = client
        .post(&oauth2.token_endpoint)
        .form(&params)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|error| CliError::user(format!("oauth2 token refresh failed: {error}")))?;
    let mut token = parse_oauth_token_response(response).await?;
    if token.refresh_token.is_none() {
        token.refresh_token = Some(refresh_token.to_string());
    }
    Ok(token)
}

async fn parse_oauth_token_response(
    response: reqwest::Response,
) -> Result<crate::gateway::oauth_token_store::CachedOAuthToken, CliError> {
    let payload: serde_json::Value = response
        .json()
        .await
        .map_err(|error| CliError::user(format!("invalid oauth2 token response: {error}")))?;

    let access_token = payload
        .get("access_token")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| CliError::user("oauth2 token response missing access_token"))?
        .to_string();
    let expires_in = payload
        .get("expires_in")
        .and_then(|value| value.as_u64())
        .unwrap_or(3600);
    let token_type = payload
        .get("token_type")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("Bearer")
        .to_string();

    Ok(
        crate::gateway::oauth_token_store::CachedOAuthToken::from_expires_in(
            access_token,
            payload
                .get("refresh_token")
                .and_then(|value| value.as_str())
                .map(ToString::to_string),
            token_type,
            std::time::Duration::from_secs(expires_in.max(1)),
        ),
    )
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
    use crate::secret_key_ref::SecretKeyReference;
    use axum::{
        extract::Form,
        http::StatusCode,
        routing::{get, post},
        Json, Router,
    };
    use serial_test::serial;
    use std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
        time::Duration,
    };

    fn unique_test_id(prefix: &str) -> String {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
        format!("{prefix}-{}", NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }

    fn provider_target(secret_key_ref: Option<SecretKeyReference>) -> ProviderTarget {
        ProviderTarget {
            id: "openai-default".to_string(),
            provider: "openai".to_string(),
            model: "gpt-5.4-mini".to_string(),
            execution_target: None,
            mcp_bridge: None,
            description: None,
            base_url: "https://api.openai.com".to_string(),
            api_key: String::new(),
            api_key_header: "Authorization".to_string(),
            api_key_prefix: "Bearer ".to_string(),
            secret_key_ref,
            path_template: None,
            headers: HashMap::new(),
            timeout: Duration::from_secs(30),
            stream_timeout: None,
            max_context_tokens: None,
            max_messages: None,
            data_policy: None,
            pricing: None,
            models: Vec::new(),
            data_collection: None,
            zdr: false,
            region: None,
            quantizations: None,
            weight: None,
            provider_type: Some(ProviderType::OpenAI),
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

    fn oauth_cache_key(target: &ProviderTarget, oauth2: &OAuth2Config) -> String {
        format!(
            "{}|{}|{}|{}",
            target.id,
            oauth2.token_endpoint,
            oauth2.client_id,
            oauth2.scopes.join(" ")
        )
    }

    #[test]
    fn optional_store_target_uses_organization_stored_provider_secret_resolution() {
        let target = provider_target(Some(SecretKeyReference {
            env: None,
            store: Some("OPENAI_API_KEY".to_string()),
            scope: None,
            keychain: None,
        }));

        assert!(uses_organization_stored_provider_secret(&target));
    }

    #[test]
    fn env_backed_target_does_not_use_an_organization_stored_provider_secret() {
        let target = provider_target(Some(SecretKeyReference::from_env("OPENAI_API_KEY")));

        assert!(!uses_organization_stored_provider_secret(&target));
    }

    #[test]
    fn self_credential_chain_targets_do_not_use_an_organization_stored_provider_secret() {
        let mut target = provider_target(Some(SecretKeyReference {
            env: None,
            store: Some("VERTEX_TOKEN".to_string()),
            scope: None,
            keychain: None,
        }));
        target.provider_type = Some(ProviderType::GoogleVertex);

        assert!(!uses_organization_stored_provider_secret(&target));
    }

    async fn start_json_server(
        payload: serde_json::Value,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new().route(
            "/token",
            get(move || {
                let payload = payload.clone();
                async move { Json(payload) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        (format!("http://{addr}/token"), handle)
    }

    async fn start_form_server(
        status: StatusCode,
        payload: serde_json::Value,
    ) -> (
        String,
        Arc<Mutex<Vec<HashMap<String, String>>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let forms = Arc::new(Mutex::new(Vec::new()));
        let forms_for_handler = Arc::clone(&forms);
        let app = Router::new().route(
            "/token",
            post(move |Form(form): Form<HashMap<String, String>>| {
                let payload = payload.clone();
                let forms_for_handler = Arc::clone(&forms_for_handler);
                async move {
                    forms_for_handler.lock().expect("forms lock").push(form);
                    (status, Json(payload))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        (format!("http://{addr}/token"), forms, handle)
    }

    async fn start_text_server(
        status: StatusCode,
        body: &'static str,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new().route(
            "/token",
            get(move || async move { (status, body) }).post(move || async move { (status, body) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        (format!("http://{addr}/token"), handle)
    }

    #[test]
    fn provider_type_round_trip_covers_all_variants() {
        let variants = [
            ProviderType::OpenAI,
            ProviderType::Anthropic,
            ProviderType::Cohere,
            ProviderType::HuggingFace,
            ProviderType::Replicate,
            ProviderType::Databricks,
            ProviderType::WatsonX,
            ProviderType::AwsBedrock,
            ProviderType::GoogleAiStudio,
            ProviderType::GoogleVertex,
            ProviderType::SageMaker,
            ProviderType::AzureOpenAI,
            ProviderType::CloudflareAi,
            ProviderType::SnowflakeCortex,
            ProviderType::Generic,
        ];

        for variant in variants {
            assert_eq!(ProviderType::from_str(variant.as_str()), Some(variant));
        }

        assert_eq!(ProviderType::from_str("unknown-provider"), None);
    }

    #[test]
    fn provider_detection_helpers_cover_known_hosts_and_explicit_override() {
        assert_eq!(
            detect_provider_type("https://models.inference.ai.azure.com"),
            ProviderType::OpenAI
        );
        assert_eq!(
            detect_provider_type("https://api.cloudflare.com/client/v4/accounts/abc/ai/v1"),
            ProviderType::CloudflareAi
        );
        assert_eq!(
            detect_provider_type("https://myorg.openai.azure.com"),
            ProviderType::AzureOpenAI
        );
        assert_eq!(
            resolve_provider_type(&ProviderTarget {
                provider_type: Some(ProviderType::SnowflakeCortex),
                base_url: "https://api.openai.com".to_string(),
                ..provider_target(None)
            }),
            ProviderType::SnowflakeCortex
        );
    }

    #[test]
    fn provider_detection_helpers_cover_google_github_and_generic_hosts() {
        assert_eq!(
            detect_provider_type("https://generativelanguage.googleapis.com"),
            ProviderType::GoogleAiStudio
        );
        assert_eq!(
            detect_provider_type("https://us-central1-aiplatform.googleapis.com"),
            ProviderType::GoogleVertex
        );
        assert_eq!(
            detect_provider_type("https://models.github.ai/inference"),
            ProviderType::OpenAI
        );
        assert_eq!(
            detect_provider_type("https://custom.internal.example"),
            ProviderType::Generic
        );
    }

    #[test]
    fn google_and_vertex_endpoints_match_expected_paths() {
        assert_eq!(
            google_ai_studio_endpoint("gemini-2.0-flash", true),
            "/v1beta/models/gemini-2.0-flash:streamGenerateContent?alt=sse"
        );
        assert_eq!(
            vertex_endpoint("project-1", "europe-west1", "gemini-2.5-pro", false),
            "/v1/projects/project-1/locations/europe-west1/publishers/google/models/gemini-2.5-pro:generateContent"
        );
    }

    #[tokio::test]
    async fn build_provider_auth_uses_expected_default_paths_for_basic_providers() {
        let cases = [
            (ProviderType::Cohere, "/v2/chat"),
            (ProviderType::HuggingFace, "/models/gpt-5.4-mini"),
            (
                ProviderType::Replicate,
                "/v1/models/gpt-5.4-mini/predictions",
            ),
            (
                ProviderType::Databricks,
                "/serving-endpoints/gpt-5.4-mini/invocations",
            ),
        ];

        for (provider_type, expected_endpoint) in cases {
            let mut target = provider_target(None);
            target.provider_type = Some(provider_type);

            let auth = build_provider_auth(&target, "", "/ignored", b"{}", false)
                .await
                .expect("provider auth");

            assert_eq!(auth.endpoint_override.as_deref(), Some(expected_endpoint));
        }
    }

    #[tokio::test]
    async fn build_provider_auth_adds_replicate_wait_header() {
        let mut target = provider_target(None);
        target.provider_type = Some(ProviderType::Replicate);

        let auth = build_provider_auth(&target, "", "/ignored", b"{}", false)
            .await
            .expect("replicate auth");

        assert!(auth
            .extra_headers
            .contains(&("Prefer".to_string(), "wait".to_string())));
    }

    #[tokio::test]
    async fn anthropic_auth_requires_api_key_for_required_targets() {
        let mut target = provider_target(None);
        target.id = unique_test_id("anthropic-missing");
        target.provider_type = Some(ProviderType::Anthropic);
        target.required = true;

        let error = build_provider_auth(&target, "", "/v1/messages", b"{}", false)
            .await
            .expect_err("missing anthropic key should fail");

        assert!(format!("{error}").contains("anthropic requires an API key"));
    }

    #[tokio::test]
    async fn azure_auth_normalizes_deployment_operation_and_version() {
        let mut target = provider_target(None);
        target.provider_type = Some(ProviderType::AzureOpenAI);
        target.api_key = "azure-key".to_string();
        target.model = "gpt-4.1".to_string();
        target.azure_deployment = Some("deployment-a".to_string());
        target.azure_api_version = Some("2024-10-21".to_string());

        let auth = build_provider_auth(&target, "", "/v1/embeddings", b"{}", false)
            .await
            .expect("azure auth");

        assert_eq!(
            auth.endpoint_override.as_deref(),
            Some("/openai/deployments/deployment-a/v1/embeddings?api-version=2024-10-21")
        );
        assert!(auth
            .extra_headers
            .contains(&("api-key".to_string(), "azure-key".to_string())));
    }

    #[tokio::test]
    async fn azure_auth_requires_api_key_for_required_targets() {
        let mut target = provider_target(None);
        target.id = unique_test_id("azure-missing");
        target.provider_type = Some(ProviderType::AzureOpenAI);
        target.required = true;

        let error = build_provider_auth(&target, "", "/chat/completions", b"{}", false)
            .await
            .expect_err("missing azure key should fail");

        assert!(format!("{error}").contains("azure-openai requires an API key"));
    }

    #[tokio::test]
    async fn cloudflare_and_snowflake_auth_normalize_expected_paths() {
        let mut cloudflare = provider_target(None);
        cloudflare.provider_type = Some(ProviderType::CloudflareAi);
        cloudflare.base_url = "https://api.cloudflare.com/client/v4/accounts/abc/ai/v1".to_string();

        let cloudflare_auth =
            build_provider_auth(&cloudflare, "", "/v1/chat/completions", b"{}", false)
                .await
                .expect("cloudflare auth");
        assert_eq!(
            cloudflare_auth.endpoint_override.as_deref(),
            Some("/chat/completions")
        );

        let mut snowflake = provider_target(None);
        snowflake.provider_type = Some(ProviderType::SnowflakeCortex);

        let snowflake_auth = build_provider_auth(&snowflake, "", "/ignored", b"{}", false)
            .await
            .expect("snowflake auth");
        assert_eq!(
            snowflake_auth.endpoint_override.as_deref(),
            Some("/api/v2/cortex/inference:complete")
        );
    }

    #[tokio::test]
    async fn vertex_auth_uses_resolver_token_and_default_region_without_oauth_config() {
        let mut target = provider_target(None);
        target.provider_type = Some(ProviderType::GoogleVertex);
        target.model = "gemini-2.0-flash".to_string();
        target.gcp_project = Some("project-xyz".to_string());
        target.api_key = "vertex-direct-token".to_string();

        let auth = build_provider_auth(&target, "", "/ignored", b"{}", false)
            .await
            .expect("vertex resolver auth");

        assert_eq!(
            auth.endpoint_override.as_deref(),
            Some(
                "/v1/projects/project-xyz/locations/us-central1/publishers/google/models/gemini-2.0-flash:generateContent"
            )
        );
        assert_eq!(
            auth.extra_headers,
            vec![(
                "Authorization".to_string(),
                "Bearer vertex-direct-token".to_string()
            )]
        );
    }

    #[tokio::test]
    async fn google_ai_studio_auth_requires_api_key() {
        let mut target = provider_target(None);
        target.id = unique_test_id("google-ai-missing");
        target.provider_type = Some(ProviderType::GoogleAiStudio);

        let error = build_provider_auth(&target, "", "/ignored", b"{}", true)
            .await
            .expect_err("missing ai studio key should fail");

        assert!(format!("{error}").contains("google-ai-studio requires an API key"));
    }

    #[tokio::test]
    async fn google_ai_studio_auth_uses_model_argument_for_default_endpoint() {
        let mut target = provider_target(None);
        target.provider_type = Some(ProviderType::GoogleAiStudio);
        target.api_key = "studio-key".to_string();
        target.model = "gemini-1.5-pro".to_string();

        let auth = build_provider_auth(&target, "gemini-2.5-flash", "/ignored", b"{}", false)
            .await
            .expect("google ai studio auth");

        assert_eq!(
            auth.endpoint_override.as_deref(),
            Some("/v1beta/models/gemini-2.5-flash:generateContent")
        );
    }

    #[tokio::test]
    #[serial]
    async fn sagemaker_auth_requires_explicit_aws_region() {
        let mut target = provider_target(None);
        target.id = unique_test_id("sagemaker-region-missing");
        target.provider_type = Some(ProviderType::SageMaker);
        target.api_key = "TARGET_ACCESS_KEY".to_string();
        target.api_key_prefix = "TARGET_SECRET_KEY".to_string();

        let error = build_provider_auth(&target, "", "/ignored", b"{}", false)
            .await
            .expect_err("missing sagemaker region should fail");

        assert!(format!("{error}").contains("sagemaker requires explicit aws_region"));
    }

    #[tokio::test]
    #[serial]
    async fn bedrock_auth_requires_explicit_aws_region() {
        let mut target = provider_target(None);
        target.id = unique_test_id("bedrock-region-missing");
        target.provider_type = Some(ProviderType::AwsBedrock);
        target.api_key = "TARGET_BEDROCK_ACCESS".to_string();
        target.api_key_prefix = "TARGET_BEDROCK_SECRET".to_string();

        let error = build_provider_auth(&target, "", "/ignored", b"{}", false)
            .await
            .expect_err("missing bedrock region should fail");

        assert!(format!("{error}").contains("aws-bedrock requires explicit aws_region"));
    }

    #[test]
    fn sign_bedrock_request_includes_session_token_when_present() {
        let headers = sign_bedrock_request(
            "AKIA_TEST",
            "secret",
            Some("session-token"),
            "us-east-1",
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/test/invoke",
            br#"{"hello":"world"}"#,
        )
        .expect("sign request");

        assert!(headers
            .iter()
            .any(|(name, value)| name == "x-amz-security-token" && value == "session-token"));
        assert!(headers.iter().any(|(name, value)| {
            name == "Authorization" && value.contains("Credential=AKIA_TEST/")
        }));
    }

    #[tokio::test]
    #[serial]
    async fn resolve_oauth_token_prefers_fresh_cached_token() {
        let mut target = provider_target(None);
        target.id = unique_test_id("oauth-cache-fresh");
        let oauth2 = OAuth2Config {
            grant_type: OAuth2GrantType::ClientCredentials,
            token_endpoint: "http://127.0.0.1:9/token".to_string(),
            client_id: "cache-client".to_string(),
            client_secret_env: None,
            scopes: vec!["scope:a".to_string()],
            audience: None,
            redirect_uri: None,
            authorization_code: None,
            authorization_code_env: None,
            code_verifier: None,
            code_verifier_env: None,
            access_token_env: None,
            refresh_token_env: None,
        };
        let cache_key = oauth_cache_key(&target, &oauth2);
        crate::gateway::oauth_token_store::OAuthTokenStore::global().put(
            cache_key,
            crate::gateway::oauth_token_store::CachedOAuthToken::from_expires_in(
                "cached-token".to_string(),
                None,
                "Bearer".to_string(),
                Duration::from_secs(3600),
            ),
        );

        let token = resolve_oauth_token(&target, &oauth2)
            .await
            .expect("fresh cache token");

        assert_eq!(token.access_token, "cached-token");
    }

    #[tokio::test]
    async fn exchange_oauth_token_authorization_code_requires_code() {
        let oauth2 = OAuth2Config {
            grant_type: OAuth2GrantType::AuthorizationCode,
            token_endpoint: "http://127.0.0.1:9/token".to_string(),
            client_id: "authorization-client".to_string(),
            client_secret_env: None,
            scopes: Vec::new(),
            audience: None,
            redirect_uri: None,
            authorization_code: None,
            authorization_code_env: None,
            code_verifier: Some("verifier".to_string()),
            code_verifier_env: None,
            access_token_env: None,
            refresh_token_env: None,
        };

        let error = exchange_oauth_token(&oauth2)
            .await
            .expect_err("missing auth code should fail");

        assert!(format!("{error}").contains("authorization_code grant requires authorization_code"));
    }

    #[tokio::test]
    async fn exchange_oauth_token_authorization_code_requires_verifier() {
        let oauth2 = OAuth2Config {
            grant_type: OAuth2GrantType::AuthorizationCode,
            token_endpoint: "http://127.0.0.1:9/token".to_string(),
            client_id: "authorization-client".to_string(),
            client_secret_env: None,
            scopes: Vec::new(),
            audience: None,
            redirect_uri: None,
            authorization_code: Some("code-1".to_string()),
            authorization_code_env: None,
            code_verifier: None,
            code_verifier_env: None,
            access_token_env: None,
            refresh_token_env: None,
        };

        let error = exchange_oauth_token(&oauth2)
            .await
            .expect_err("missing verifier should fail");

        assert!(format!("{error}").contains("authorization_code grant requires code_verifier"));
    }

    #[tokio::test]
    async fn parse_oauth_token_response_defaults_missing_optional_fields() {
        let (url, handle) = start_json_server(serde_json::json!({
            "access_token": "oauth-access-token"
        }))
        .await;

        let response = reqwest::get(url).await.expect("request");
        let token = parse_oauth_token_response(response)
            .await
            .expect("parse oauth token");

        handle.abort();

        assert_eq!(token.access_token, "oauth-access-token");
        assert_eq!(token.token_type, "Bearer");
        assert!(token.refresh_token.is_none());
        assert!(token.is_fresh());
    }

    #[tokio::test]
    async fn parse_oauth_token_response_requires_access_token() {
        let (url, handle) = start_json_server(serde_json::json!({
            "token_type": "Bearer"
        }))
        .await;

        let response = reqwest::get(url).await.expect("request");
        let error = parse_oauth_token_response(response)
            .await
            .expect_err("missing access token should fail");

        handle.abort();

        assert!(format!("{error}").contains("missing access_token"));
    }

    #[tokio::test]
    async fn parse_oauth_token_response_rejects_invalid_json() {
        let (url, handle) = start_text_server(StatusCode::OK, "not-json").await;

        let response = reqwest::get(url).await.expect("request");
        let error = parse_oauth_token_response(response)
            .await
            .expect_err("invalid json should fail");

        handle.abort();

        assert!(format!("{error}").contains("invalid oauth2 token response"));
    }
}

#[cfg(test)]
mod coverage_expansion_provider_auth_tests {
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

    // ── ProviderType ────────────────────────────────────────────────────

    #[test]
    fn provider_type_from_str_all_variants() {
        assert_eq!(ProviderType::from_str("openai"), Some(ProviderType::OpenAI));
        assert_eq!(
            ProviderType::from_str("anthropic"),
            Some(ProviderType::Anthropic)
        );
        assert_eq!(ProviderType::from_str("cohere"), Some(ProviderType::Cohere));
        assert_eq!(
            ProviderType::from_str("huggingface"),
            Some(ProviderType::HuggingFace)
        );
        assert_eq!(
            ProviderType::from_str("replicate"),
            Some(ProviderType::Replicate)
        );
        assert_eq!(
            ProviderType::from_str("databricks"),
            Some(ProviderType::Databricks)
        );
        assert_eq!(
            ProviderType::from_str("watsonx"),
            Some(ProviderType::WatsonX)
        );
        assert_eq!(
            ProviderType::from_str("aws-bedrock"),
            Some(ProviderType::AwsBedrock)
        );
        assert_eq!(
            ProviderType::from_str("google-ai-studio"),
            Some(ProviderType::GoogleAiStudio)
        );
        assert_eq!(
            ProviderType::from_str("google-vertex"),
            Some(ProviderType::GoogleVertex)
        );
        assert_eq!(
            ProviderType::from_str("sagemaker"),
            Some(ProviderType::SageMaker)
        );
        assert_eq!(
            ProviderType::from_str("azure-openai"),
            Some(ProviderType::AzureOpenAI)
        );
        assert_eq!(
            ProviderType::from_str("cloudflare-ai"),
            Some(ProviderType::CloudflareAi)
        );
        assert_eq!(
            ProviderType::from_str("snowflake-cortex"),
            Some(ProviderType::SnowflakeCortex)
        );
        assert_eq!(
            ProviderType::from_str("generic"),
            Some(ProviderType::Generic)
        );
        assert_eq!(ProviderType::from_str("unknown"), None);
    }

    #[test]
    fn provider_type_serde_round_trip() {
        let types = vec![
            ProviderType::OpenAI,
            ProviderType::Anthropic,
            ProviderType::AwsBedrock,
            ProviderType::AzureOpenAI,
            ProviderType::GoogleVertex,
        ];
        for pt in types {
            let serialized = serde_json::to_string(&pt).unwrap();
            let deserialized: ProviderType = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized, pt);
        }
    }

    // ── OAuth2GrantType ─────────────────────────────────────────────────

    #[test]
    fn oauth2_grant_type_serde() {
        let j = serde_json::to_value(OAuth2GrantType::ClientCredentials).unwrap();
        assert_eq!(j, serde_json::json!("client_credentials"));
        let j = serde_json::to_value(OAuth2GrantType::AuthorizationCode).unwrap();
        assert_eq!(j, serde_json::json!("authorization_code"));
    }

    // ── OAuth2Config ────────────────────────────────────────────────────

    #[test]
    fn oauth2_config_deserialization() {
        let config: OAuth2Config = serde_json::from_value(serde_json::json!({
            "grant_type": "client_credentials",
            "token_endpoint": "https://auth.example.com/token",
            "client_id": "my-client",
            "scopes": ["read", "write"]
        }))
        .unwrap();
        assert_eq!(config.grant_type, OAuth2GrantType::ClientCredentials);
        assert_eq!(config.token_endpoint, "https://auth.example.com/token");
        assert_eq!(config.client_id, "my-client");
        assert_eq!(config.scopes, vec!["read", "write"]);
        assert!(config.client_secret_env.is_none());
        assert!(config.audience.is_none());
    }

    // ── uses_organization_stored_provider_secret ──────────────────────────────────

    #[test]
    fn organization_stored_provider_secret_requires_a_secret_ref() {
        let target = crate::gateway::providers::ProviderTarget {
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
            timeout: std::time::Duration::from_secs(30),
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
        assert!(!uses_organization_stored_provider_secret(&target));
    }
}
