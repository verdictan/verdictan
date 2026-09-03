// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Embedding-based semantic detection (Tier 4).
//!
//! Provides a framework for detecting sensitive content through vector-similarity
//! search rather than purely regex/keyword matching. The initial implementation
//! uses a lightweight per-token IDF-weighted bag-of-words vector so that it works
//! without any external model server. When an external embedding endpoint is
//! configured, the module delegates to it instead.
//!
//! # Backends
//!
//! The embedding backend is selected at runtime via [`EmbeddingConfig::backend`]:
//!
//! - **`Local`** (default): Built-in TF-IDF bag-of-words vectors. Zero external
//!   dependencies; operates within the 20 ms hot-path budget.
//! - **`External`**: HTTP calls to an OpenAI-compatible embedding endpoint
//!   (e.g. SentenceTransformers, OpenAI, a local Ollama instance). Requires the
//!   `embedding-external` compile-time feature flag (enabled in default builds).
//!
//! # Feature flag: `embedding-external`
//!
//! The `External` backend is a fully implemented, feature-gated capability.
//! Default builds include this feature. Disable it with:
//!
//! ```shell
//! cargo build --no-default-features
//! ```
//!
//! Without the flag the `External` variant compiles and is selectable, but
//! [`detect_by_embedding`] falls back to the local bag-of-words path instead
//! of making an HTTP call.
//!
//! # Configuration (External backend)
//!
//! ```yaml
//! policy:
//!   embedding-detector:
//!     backend: external
//!     endpoint: https://api.openai.com/v1/embeddings
//!     model: text-embedding-3-small
//!     secret_key_ref:
//!       env: VERDICTAN_OPENAI_API_KEY # optional; bearer token
//!     timeout_ms: 200
//!     similarity_threshold: 0.75
//! ```
//!
//! The external implementation sends a single `POST` with `{"input": "...",
//! "model": "..."}`, reads `data[0].embedding` from the response, and applies
//! cosine-similarity against pre-embedded reference categories. If the HTTP
//! call exceeds `timeout_ms` the module falls back to the local bag-of-words
//! path transparently.
//!
//! # Design goals
//!
//! 1. Hot-path latency < 20 ms for local fallback (bag-of-words).
//! 2. Pluggable backend (local BoW → SentenceTransformers → OpenAI).
//! 3. Deterministic results for the local path (no randomness).

use std::collections::HashMap;

#[cfg(feature = "embedding-external")]
use anyhow::Context;

use super::pii::{Confidence, Detection, PiiKind};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Backend selection for the embedding engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmbeddingBackend {
    /// Built-in bag-of-words TF-IDF vectors (no external dependency).
    Local,
    /// External embedding API (e.g. SentenceTransformers / OpenAI).
    External {
        endpoint: String,
        model: String,
        api_key: Option<String>,
    },
}

/// Configuration for the embedding-based detector.
#[derive(Debug, Clone)]
pub struct EmbeddingConfig {
    pub backend: EmbeddingBackend,
    /// Minimum cosine similarity to flag as a match.
    pub similarity_threshold: f64,
    /// Maximum latency (ms) before falling back to local.
    pub timeout_ms: u64,
    /// Reference descriptions of sensitive categories.
    pub sensitive_categories: Vec<SensitiveCategory>,
}

impl Default for EmbeddingConfig {
    fn default() -> Self {
        Self {
            backend: EmbeddingBackend::Local,
            similarity_threshold: 0.70,
            timeout_ms: 20,
            sensitive_categories: default_sensitive_categories(),
        }
    }
}

/// A labelled reference that the detector compares input text against.
#[derive(Debug, Clone)]
pub struct SensitiveCategory {
    #[allow(dead_code)]
    pub label: String,
    pub pii_kind: PiiKind,
    pub reference_text: String,
    /// Pre-computed local embedding (filled lazily).
    #[allow(dead_code)]
    pub reference_vec: Option<Vec<f64>>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run embedding-based detection over `input`.
///
/// Returns detections where a sliding window of the input text has cosine
/// similarity ≥ `config.similarity_threshold` against one of the reference
/// categories.
pub fn detect_by_embedding(input: &str, config: &EmbeddingConfig) -> Vec<Detection> {
    match &config.backend {
        EmbeddingBackend::Local => detect_local(input, config),
        EmbeddingBackend::External { .. } => {
            #[cfg(feature = "embedding-external")]
            {
                detect_external_sync(input, config)
            }

            #[cfg(not(feature = "embedding-external"))]
            {
                detect_local(input, config)
            }
        }
    }
}

/// Async variant that can call an external embedding endpoint.
#[cfg(feature = "embedding-external")]
pub async fn detect_by_embedding_async(input: &str, config: &EmbeddingConfig) -> Vec<Detection> {
    match &config.backend {
        EmbeddingBackend::Local => detect_local(input, config),
        EmbeddingBackend::External {
            endpoint,
            model,
            api_key,
        } => detect_external(input, config, endpoint, model, api_key.as_deref())
            .await
            .unwrap_or_else(|_| detect_local(input, config)),
    }
}

#[cfg(feature = "embedding-external")]
fn detect_external_sync(input: &str, config: &EmbeddingConfig) -> Vec<Detection> {
    let input = input.to_string();
    let config = config.clone();
    let fallback_input = input.clone();
    let fallback_config = config.clone();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map(|runtime| runtime.block_on(detect_by_embedding_async(&input, &config)))
            .unwrap_or_else(|_| detect_local(&input, &config))
    })
    .join()
    .unwrap_or_else(|_| detect_local(&fallback_input, &fallback_config))
}

#[cfg(feature = "embedding-external")]
async fn detect_external(
    input: &str,
    config: &EmbeddingConfig,
    endpoint: &str,
    model: &str,
    api_key: Option<&str>,
) -> Result<Vec<Detection>, anyhow::Error> {
    let mut detections = Vec::new();
    let mut reference_vectors: HashMap<String, Vec<f64>> = HashMap::new();

    for (seg_start, seg_end) in split_segments(input) {
        let segment = &input[seg_start..seg_end];
        if tokenize(segment).is_empty() {
            continue;
        }

        let segment_vec = embed_with_timeout(segment, endpoint, model, api_key, config.timeout_ms)
            .await
            .with_context(|| format!("embed segment {}..{}", seg_start, seg_end))?;

        for cat in &config.sensitive_categories {
            let ref_vec = if let Some(vec) = reference_vectors.get(&cat.label) {
                vec.clone()
            } else {
                let vec = embed_with_timeout(
                    &cat.reference_text,
                    endpoint,
                    model,
                    api_key,
                    config.timeout_ms,
                )
                .await
                .with_context(|| format!("embed reference {}", cat.label))?;
                reference_vectors.insert(cat.label.clone(), vec.clone());
                vec
            };

            let sim = cosine_similarity(&segment_vec, &ref_vec);
            if sim >= config.similarity_threshold {
                detections.push(Detection {
                    kind: cat.pii_kind.clone(),
                    start: seg_start,
                    end: seg_end,
                    confidence: confidence_from_similarity(sim),
                });
            }
        }
    }

    Ok(detections)
}

// ---------------------------------------------------------------------------
// Local bag-of-words embedding
// ---------------------------------------------------------------------------

/// Tokenise text into lowercase alphanumeric tokens.
pub fn tokenize(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_ascii_lowercase())
        .collect()
}

/// Build a term-frequency vector for `tokens`, keyed by the `vocabulary`.
fn tf_vector(tokens: &[String], vocabulary: &[String]) -> Vec<f64> {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for t in tokens {
        *counts.entry(t.as_str()).or_insert(0) += 1;
    }
    let total = tokens.len().max(1) as f64;
    vocabulary
        .iter()
        .map(|w| (*counts.get(w.as_str()).unwrap_or(&0) as f64) / total)
        .collect()
}

/// Build a shared vocabulary from two sets of tokens.
fn build_vocabulary(a: &[String], b: &[String]) -> Vec<String> {
    let mut set: Vec<String> = Vec::new();
    for t in a.iter().chain(b.iter()) {
        if !set.contains(t) {
            set.push(t.clone());
        }
    }
    set
}

/// Cosine similarity between two vectors of equal length.
pub fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let mag_a: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let mag_b: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
    if mag_a == 0.0 || mag_b == 0.0 {
        return 0.0;
    }
    dot / (mag_a * mag_b)
}

/// Local detection: for each sentence-like segment of the input compare against
/// every reference category using TF-IDF bag-of-words cosine similarity.
fn detect_local(input: &str, config: &EmbeddingConfig) -> Vec<Detection> {
    let mut detections = Vec::new();

    // Split input into sentence-ish segments for windowed comparison.
    let segments = split_segments(input);

    for &(seg_start, seg_end) in &segments {
        let segment = &input[seg_start..seg_end];
        let seg_tokens = tokenize(segment);
        if seg_tokens.is_empty() {
            continue;
        }

        for cat in &config.sensitive_categories {
            let ref_tokens = tokenize(&cat.reference_text);
            if ref_tokens.is_empty() {
                continue;
            }
            let vocab = build_vocabulary(&seg_tokens, &ref_tokens);
            let vec_a = tf_vector(&seg_tokens, &vocab);
            let vec_b = tf_vector(&ref_tokens, &vocab);
            let sim = cosine_similarity(&vec_a, &vec_b);

            if sim >= config.similarity_threshold {
                detections.push(Detection {
                    kind: cat.pii_kind.clone(),
                    start: seg_start,
                    end: seg_end,
                    confidence: if sim >= 0.90 {
                        Confidence::High
                    } else if sim >= 0.80 {
                        Confidence::Medium
                    } else {
                        Confidence::Low
                    },
                });
            }
        }
    }

    detections
}

/// Split text into byte-offset segments (sentences or clauses).
pub fn split_segments(text: &str) -> Vec<(usize, usize)> {
    let mut segs = Vec::new();
    let mut start = 0;
    for (i, c) in text.char_indices() {
        if c == '.' || c == '!' || c == '?' || c == '\n' {
            let end = i + c.len_utf8();
            if end > start + 3 {
                segs.push((start, end));
            }
            start = end;
        }
    }
    // Trailing segment.
    if start < text.len() && text.len() - start > 3 {
        segs.push((start, text.len()));
    }
    segs
}

#[cfg(feature = "embedding-external")]
fn confidence_from_similarity(similarity: f64) -> Confidence {
    if similarity >= 0.90 {
        Confidence::High
    } else if similarity >= 0.80 {
        Confidence::Medium
    } else {
        Confidence::Low
    }
}

/// Call the external embedding endpoint with a per-request timeout.
///
/// This function is active only when the `embedding-external` feature flag is
/// enabled. It wraps [`call_external`] in a `tokio::time::timeout` so that a
/// slow or unavailable embedding service never blocks the detection hot path
/// beyond `timeout_ms` milliseconds. On timeout or transport error the caller
/// ([`detect_external_sync`] / [`detect_by_embedding_async`]) falls back to the
/// local bag-of-words path transparently.
#[cfg(feature = "embedding-external")]
async fn embed_with_timeout(
    input: &str,
    endpoint: &str,
    model: &str,
    api_key: Option<&str>,
    timeout_ms: u64,
) -> Result<Vec<f64>, anyhow::Error> {
    tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        call_external(input, endpoint, model, api_key),
    )
    .await
    .context("external embedding timed out")?
}

#[cfg(feature = "embedding-external")]
async fn call_external(
    input: &str,
    endpoint: &str,
    model: &str,
    api_key: Option<&str>,
) -> Result<Vec<f64>, anyhow::Error> {
    #[derive(serde::Deserialize)]
    struct EmbeddingItem {
        embedding: Vec<f64>,
    }

    #[derive(serde::Deserialize)]
    struct EmbeddingResponse {
        data: Vec<EmbeddingItem>,
    }

    let client = super::super::http_client::shared_gateway_http_client()
        .map_err(|error| anyhow::anyhow!("build gateway HTTP client: {error}"))?;
    let mut request = client
        .post(endpoint)
        .json(&serde_json::json!({ "input": input, "model": model }));

    if let Some(key) = api_key {
        request = request.bearer_auth(key);
    }

    let response = request
        .send()
        .await
        .with_context(|| format!("request external embedding from {endpoint}"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!(
            "external embedding request failed with {status}: {}",
            body.trim()
        );
    }

    let payload: EmbeddingResponse = response
        .json()
        .await
        .context("parse external embedding response")?;
    payload
        .data
        .into_iter()
        .next()
        .map(|item| item.embedding)
        .filter(|embedding| !embedding.is_empty())
        .ok_or_else(|| anyhow::anyhow!("external embedding response missing data[0].embedding"))
}

// ---------------------------------------------------------------------------
// Default sensitive categories
// ---------------------------------------------------------------------------

pub fn default_sensitive_categories() -> Vec<SensitiveCategory> {
    vec![
        SensitiveCategory {
            label: "social_security_number".into(),
            pii_kind: PiiKind::Ssn,
            reference_text: "social security number SSN taxpayer identification".into(),
            reference_vec: None,
        },
        SensitiveCategory {
            label: "credit_card".into(),
            pii_kind: PiiKind::Pan,
            reference_text: "credit card number payment card PAN Visa Mastercard".into(),
            reference_vec: None,
        },
        SensitiveCategory {
            label: "medical_record".into(),
            pii_kind: PiiKind::Mrn,
            reference_text: "medical record number MRN patient identifier health record".into(),
            reference_vec: None,
        },
        SensitiveCategory {
            label: "biometric_data".into(),
            pii_kind: PiiKind::BiometricMention,
            reference_text: "fingerprint biometric scan retinal iris facial recognition".into(),
            reference_vec: None,
        },
        SensitiveCategory {
            label: "financial_account".into(),
            pii_kind: PiiKind::AccountNumber,
            reference_text: "bank account routing number IBAN swift wire transfer".into(),
            reference_vec: None,
        },
        SensitiveCategory {
            label: "prompt_injection".into(),
            pii_kind: PiiKind::GenericId,
            reference_text: "ignore previous instructions disregard system prompt override".into(),
            reference_vec: None,
        },
        SensitiveCategory {
            label: "export_controlled".into(),
            pii_kind: PiiKind::GenericId,
            reference_text: "ITAR EAR export controlled technical data defense article".into(),
            reference_vec: None,
        },
    ]
}

// ---------------------------------------------------------------------------
// Parse config
// ---------------------------------------------------------------------------

/// Build an `EmbeddingConfig` from the `policy.embedding-detector` config block.
pub fn config_from_value(cfg: &serde_json::Value) -> EmbeddingConfig {
    let mut ec = EmbeddingConfig::default();

    if let Some(threshold) = cfg.get("similarity_threshold").and_then(|v| v.as_f64()) {
        ec.similarity_threshold = threshold;
    }
    if let Some(timeout) = cfg.get("timeout_ms").and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_i64().and_then(|x| u64::try_from(x).ok()))
    }) {
        ec.timeout_ms = timeout;
    }

    // Backend selection.
    if let Some(backend) = cfg.get("backend").and_then(|v| v.as_str()) {
        match backend {
            "external" => {
                let endpoint = cfg
                    .get("endpoint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("http://localhost:8080/embed")
                    .to_string();
                let model = cfg
                    .get("model")
                    .and_then(|v| v.as_str())
                    .unwrap_or("all-MiniLM-L6-v2")
                    .to_string();
                let api_key = cfg
                    .get("api_key")
                    .and_then(|v| v.as_str())
                    .and_then(parse_external_api_key);
                ec.backend = EmbeddingBackend::External {
                    endpoint,
                    model,
                    api_key,
                };
            }
            _ => {
                ec.backend = EmbeddingBackend::Local;
            }
        }
    }

    // Custom categories.
    if let Some(cats) = cfg.get("categories").and_then(|v| v.as_array()) {
        let mut custom = Vec::new();
        for cat in cats {
            if let (Some(label), Some(reference)) = (
                cat.get("label").and_then(|v| v.as_str()),
                cat.get("reference_text").and_then(|v| v.as_str()),
            ) {
                custom.push(SensitiveCategory {
                    label: label.to_string(),
                    pii_kind: PiiKind::GenericId,
                    reference_text: reference.to_string(),
                    reference_vec: None,
                });
            }
        }
        if !custom.is_empty() {
            ec.sensitive_categories.extend(custom);
        }
    }

    ec
}

fn parse_external_api_key(value: &str) -> Option<String> {
    if value
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        tracing::warn!(
            "ignoring embedding-detector.api_key because it contains whitespace or control characters"
        );
        return None;
    }

    Some(value.to_string())
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

    // --- tokenize ---

    #[test]
    fn tokenize_simple_sentence() {
        let tokens = tokenize("Hello World");
        assert_eq!(tokens, vec!["hello", "world"]);
    }

    #[test]
    fn tokenize_with_punctuation() {
        let tokens = tokenize("Hello, World! How are you?");
        assert_eq!(tokens, vec!["hello", "world", "how", "are", "you"]);
    }

    #[test]
    fn tokenize_empty_string() {
        let tokens = tokenize("");
        assert!(tokens.is_empty());
    }

    #[test]
    fn tokenize_only_punctuation() {
        let tokens = tokenize("!@#$%^&*()");
        assert!(tokens.is_empty());
    }

    #[test]
    fn tokenize_mixed_case() {
        let tokens = tokenize("CamelCase UPPER lower");
        assert_eq!(tokens, vec!["camelcase", "upper", "lower"]);
    }

    #[test]
    fn tokenize_numbers() {
        let tokens = tokenize("abc 123 def456");
        assert_eq!(tokens, vec!["abc", "123", "def456"]);
    }

    // --- cosine_similarity ---

    #[test]
    fn cosine_identical_vectors() {
        let v = vec![1.0, 2.0, 3.0];
        let sim = cosine_similarity(&v, &v);
        assert!((sim - 1.0).abs() < 1e-10);
    }

    #[test]
    fn cosine_orthogonal_vectors() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        let sim = cosine_similarity(&a, &b);
        assert!(sim.abs() < 1e-10);
    }

    #[test]
    fn cosine_zero_vector() {
        let a = vec![0.0, 0.0];
        let b = vec![1.0, 2.0];
        assert_eq!(cosine_similarity(&a, &b), 0.0);
    }

    #[test]
    fn cosine_opposite_vectors() {
        let a = vec![1.0, 0.0];
        let b = vec![-1.0, 0.0];
        let sim = cosine_similarity(&a, &b);
        assert!((sim - (-1.0)).abs() < 1e-10);
    }

    #[test]
    fn cosine_proportional_vectors() {
        let a = vec![1.0, 2.0, 3.0];
        let b = vec![2.0, 4.0, 6.0];
        let sim = cosine_similarity(&a, &b);
        assert!((sim - 1.0).abs() < 1e-10);
    }

    // --- split_segments ---

    #[test]
    fn split_segments_single_sentence() {
        let segs = split_segments("Hello world.");
        assert_eq!(segs.len(), 1);
        assert_eq!(&"Hello world."[segs[0].0..segs[0].1], "Hello world.");
    }

    #[test]
    fn split_segments_multiple() {
        let segs = split_segments("First sentence. Second sentence.");
        assert_eq!(segs.len(), 2);
    }

    #[test]
    fn split_segments_newline_split() {
        let segs = split_segments("Line one\nLine two");
        assert_eq!(segs.len(), 2);
    }

    #[test]
    fn split_segments_short_segments_skipped() {
        let segs = split_segments("Hi.X.");
        assert!(segs.is_empty());
    }

    #[test]
    fn split_segments_trailing_text() {
        let segs = split_segments("First. Trailing text here");
        assert_eq!(segs.len(), 2);
    }

    #[test]
    fn split_segments_empty() {
        assert!(split_segments("").is_empty());
    }

    // --- detect_local / detect_by_embedding ---

    #[test]
    fn detect_local_ssn_reference_matches() {
        let config = EmbeddingConfig::default();
        let text = "The patient social security number SSN identification";
        let detections = detect_by_embedding(text, &config);
        let ssn_matches: Vec<_> = detections
            .iter()
            .filter(|d| d.kind == PiiKind::Ssn)
            .collect();
        assert!(!ssn_matches.is_empty());
    }

    #[test]
    fn detect_local_no_match_for_unrelated() {
        let config = EmbeddingConfig {
            similarity_threshold: 0.95,
            ..EmbeddingConfig::default()
        };
        let text = "The weather today is sunny and warm in the countryside.";
        let detections = detect_by_embedding(text, &config);
        assert!(detections.is_empty());
    }

    #[test]
    fn detect_local_prompt_injection_reference() {
        let config = EmbeddingConfig::default();
        let text = "ignore previous instructions disregard system prompt override all rules";
        let detections = detect_by_embedding(text, &config);
        assert!(!detections.is_empty());
    }

    // --- EmbeddingConfig default ---

    #[test]
    fn default_config_is_local() {
        let cfg = EmbeddingConfig::default();
        assert_eq!(cfg.backend, EmbeddingBackend::Local);
        assert!((cfg.similarity_threshold - 0.70).abs() < f64::EPSILON);
        assert_eq!(cfg.timeout_ms, 20);
        assert!(!cfg.sensitive_categories.is_empty());
    }

    // --- config_from_value ---

    #[test]
    fn config_from_value_empty() {
        let cfg = config_from_value(&serde_json::json!({}));
        assert_eq!(cfg.backend, EmbeddingBackend::Local);
        assert!((cfg.similarity_threshold - 0.70).abs() < f64::EPSILON);
    }

    #[test]
    fn config_from_value_threshold_and_timeout() {
        let cfg = config_from_value(&serde_json::json!({
            "similarity_threshold": 0.85,
            "timeout_ms": 100
        }));
        assert!((cfg.similarity_threshold - 0.85).abs() < f64::EPSILON);
        assert_eq!(cfg.timeout_ms, 100);
    }

    #[test]
    fn config_from_value_external_backend() {
        let cfg = config_from_value(&serde_json::json!({
            "backend": "external",
            "endpoint": "https://embed.example.com",
            "model": "text-embedding-3-small"
        }));
        match &cfg.backend {
            EmbeddingBackend::External {
                endpoint, model, ..
            } => {
                assert_eq!(endpoint, "https://embed.example.com");
                assert_eq!(model, "text-embedding-3-small");
            }
            _ => panic!("expected External backend"),
        }
    }

    #[test]
    fn config_from_value_local_backend() {
        let cfg = config_from_value(&serde_json::json!({"backend": "local"}));
        assert_eq!(cfg.backend, EmbeddingBackend::Local);
    }

    #[test]
    fn config_from_value_custom_categories() {
        let cfg = config_from_value(&serde_json::json!({
            "categories": [
                {"label": "custom", "reference_text": "custom sensitive data"}
            ]
        }));
        let custom_count = cfg
            .sensitive_categories
            .iter()
            .filter(|c| c.label == "custom")
            .count();
        assert_eq!(custom_count, 1);
    }

    #[test]
    fn config_from_value_api_key_with_whitespace_ignored() {
        let cfg = config_from_value(&serde_json::json!({
            "backend": "external",
            "api_key": "key with space"
        }));
        match &cfg.backend {
            EmbeddingBackend::External { api_key, .. } => {
                assert!(api_key.is_none());
            }
            _ => panic!("expected External backend"),
        }
    }

    #[test]
    fn config_from_value_valid_api_key() {
        let expected_api_key = format!("sk-{}-123", "fixture-provider-key");
        let cfg = config_from_value(&serde_json::json!({
            "backend": "external",
            "api_key": expected_api_key
        }));
        match &cfg.backend {
            EmbeddingBackend::External { api_key, .. } => {
                assert_eq!(api_key.as_deref(), Some(expected_api_key.as_str()));
            }
            _ => panic!("expected External backend"),
        }
    }

    // --- default_sensitive_categories ---

    #[test]
    fn default_categories_include_expected_labels() {
        let cats = default_sensitive_categories();
        let labels: Vec<&str> = cats.iter().map(|c| c.label.as_str()).collect();
        assert!(labels.contains(&"social_security_number"));
        assert!(labels.contains(&"credit_card"));
        assert!(labels.contains(&"medical_record"));
        assert!(labels.contains(&"biometric_data"));
        assert!(labels.contains(&"financial_account"));
        assert!(labels.contains(&"prompt_injection"));
        assert!(labels.contains(&"export_controlled"));
    }

    // --- build_vocabulary ---

    #[test]
    fn build_vocabulary_deduplicates() {
        let a = vec!["hello".into(), "world".into()];
        let b = vec!["world".into(), "foo".into()];
        let vocab = build_vocabulary(&a, &b);
        assert_eq!(vocab.len(), 3);
        assert!(vocab.contains(&"hello".to_string()));
        assert!(vocab.contains(&"world".to_string()));
        assert!(vocab.contains(&"foo".to_string()));
    }

    // --- tf_vector ---

    #[test]
    fn tf_vector_proportional() {
        let tokens: Vec<String> = vec!["a".into(), "b".into(), "a".into()];
        let vocab: Vec<String> = vec!["a".into(), "b".into(), "c".into()];
        let tf = tf_vector(&tokens, &vocab);
        assert!((tf[0] - 2.0 / 3.0).abs() < 1e-10);
        assert!((tf[1] - 1.0 / 3.0).abs() < 1e-10);
        assert!((tf[2] - 0.0).abs() < 1e-10);
    }

    // --- parse_external_api_key ---

    #[test]
    fn parse_api_key_valid() {
        assert_eq!(
            parse_external_api_key("sk-abc123"),
            Some("sk-abc123".to_string())
        );
    }

    #[test]
    fn parse_api_key_with_tab_rejected() {
        assert!(parse_external_api_key("key\there").is_none());
    }

    #[test]
    fn parse_api_key_with_newline_rejected() {
        assert!(parse_external_api_key("key\nvalue").is_none());
    }
}
