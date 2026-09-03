// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::json;
use std::collections::HashSet;
use std::time::Duration;

use crate::policy::assertions::{assertion_key, AssertionResult, AssertionSpec};
use crate::secret_key_ref::parse_env_secret_key_name;

// ═══════════════════════════════════════════════════════════════════════════
// Phase 6 — LLM-as-a-judge: config, result, and provider execution
// ═══════════════════════════════════════════════════════════════════════════

/// Verdict produced by a judge-backed quality evaluation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum JudgeVerdict {
    Pass,
    Warn,
    Fail,
}

impl JudgeVerdict {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

/// Configuration for a judge provider used by the quality scorer.
#[derive(Debug, Clone)]
pub(crate) struct JudgeConfig {
    /// Chat completions endpoint URL (OpenAI-compatible).
    pub(crate) endpoint: String,
    /// Model identifier (e.g. "gpt-5.4-mini", "claude-3-5-sonnet-20241022").
    pub(crate) model: String,
    /// Environment variable whose value is the API bearer token.
    pub(crate) secret_key_env: Option<String>,
    /// Request timeout in milliseconds (default 5000).
    pub(crate) timeout_ms: u64,
    /// When true, capture the rationale field from the judge response.
    pub(crate) rationale_capture: bool,
    /// Optional custom prompt template. Use `{input}`, `{output}`, `{rubric}` placeholders.
    pub(crate) prompt_template: Option<String>,
    /// Score at or above which the verdict is `pass`.
    pub(crate) threshold: f64,
    /// Score between this and `threshold` produces a `warn` verdict.
    pub(crate) warn_threshold: f64,
    /// Sampling rate [0, 1]: probability that the judge is actually invoked.
    /// Values < 1.0 enable regression-monitoring mode.
    pub(crate) sampling_rate: f64,
    /// Human-readable scorer name persisted in audit records.
    pub(crate) scorer_name: String,
    /// Scorer version persisted in audit records.
    pub(crate) scorer_version: String,
}

impl JudgeConfig {
    /// Parse a judge config block from a `serde_json::Value`.
    ///
    /// Returns `None` when the block is absent or `enabled` is false.
    pub(crate) fn from_json(v: &serde_json::Value) -> Option<Self> {
        let enabled = v.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false);
        if !enabled {
            return None;
        }
        let endpoint = v
            .get("endpoint")
            .and_then(|e| e.as_str())
            .unwrap_or("https://api.openai.com/v1/chat/completions")
            .to_string();
        let model = v
            .get("model")
            .and_then(|m| m.as_str())
            .unwrap_or("gpt-5.4-mini")
            .to_string();
        Some(Self {
            endpoint,
            model,
            secret_key_env: parse_env_secret_key_name(
                v.get("secret_key_ref"),
                "policy.quality.judge.secret_key_ref",
            )
            .map_err(|error| {
                tracing::warn!(
                    error = %error,
                    "invalid policy.quality.judge.secret_key_ref; judge provider will run without credentials"
                );
                error
            })
            .ok()
            .flatten(),
            timeout_ms: v.get("timeout_ms").and_then(|t| t.as_u64()).unwrap_or(5000),
            rationale_capture: v
                .get("rationale_capture")
                .and_then(|r| r.as_bool())
                .unwrap_or(true),
            prompt_template: v
                .get("prompt_template")
                .and_then(|p| p.as_str())
                .map(|s| s.to_string()),
            threshold: v.get("threshold").and_then(|t| t.as_f64()).unwrap_or(0.7),
            warn_threshold: v
                .get("warn_threshold")
                .and_then(|t| t.as_f64())
                .unwrap_or(0.5),
            sampling_rate: v
                .get("sampling_rate")
                .and_then(|s| s.as_f64())
                .unwrap_or(1.0)
                .clamp(0.0, 1.0),
            scorer_name: v
                .get("scorer_name")
                .and_then(|s| s.as_str())
                .unwrap_or("quality-scorer")
                .to_string(),
            scorer_version: v
                .get("scorer_version")
                .and_then(|s| s.as_str())
                .unwrap_or("1")
                .to_string(),
        })
    }
}

/// Structured result from a single judge-backed quality evaluation.
///
/// SEC-004 compliance: only the `rationale` field explicitly requested from
/// the judge model is stored here. Opaque provider-private reasoning chains
/// (e.g. chain-of-thought tokens not in the final message) are never captured.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct JudgeResult {
    /// Scorer identity name persisted in audit records.
    pub(crate) scorer_name: String,
    /// Model identifier used to produce this score (e.g. "gpt-5.4-mini").
    pub(crate) scorer_model: String,
    /// Scorer version string persisted in audit records.
    pub(crate) scorer_version: String,
    /// Numeric quality score in [0, 1].
    pub(crate) score: f64,
    /// Pass threshold applied.
    pub(crate) threshold: f64,
    /// Verdict: pass, warn, or fail.
    pub(crate) verdict: JudgeVerdict,
    /// Explicit chain-of-thought rationale emitted by the judge (may be `None`
    /// when `rationale_capture` is false or the judge omitted the field).
    pub(crate) rationale: Option<String>,
    /// Whether this result was produced by an actual inference call (`true`)
    /// or was skipped due to the sampling policy (`false`).
    pub(crate) sampled: bool,
}

impl JudgeResult {
    pub(crate) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "scorer_name": self.scorer_name,
            "scorer_model": self.scorer_model,
            "scorer_version": self.scorer_version,
            "score": self.score,
            "threshold": self.threshold,
            "verdict": self.verdict.as_str(),
            "rationale": self.rationale,
            "sampled": self.sampled,
        })
    }
}

/// Build the default judge scoring prompt.
fn default_judge_prompt(input_text: &str, output_text: &str, rubric: &str) -> String {
    format!(
        r#"You are a quality evaluator for LLM outputs. Evaluate the assistant response against the rubric below.

Rubric: {rubric}

Input: {input_text}

Assistant Response: {output_text}

Respond ONLY with a JSON object containing these exact fields:
- "score": a number from 0.0 to 1.0 (1.0 = fully satisfies rubric, 0.0 = does not satisfy rubric at all)
- "verdict": exactly "pass", "warn", or "fail"
- "rationale": 1–3 sentences of plain text explaining your score (no markdown, no lists)

Example output: {{"score": 0.85, "verdict": "pass", "rationale": "The response accurately addresses the query and follows the rubric."}}

Do not include any text outside the JSON object."#
    )
}

fn resolve_api_key(secret_key_env: Option<&str>) -> Option<String> {
    match secret_key_env {
        Some(env_var) => match std::env::var(env_var) {
            Ok(key) if !key.is_empty() => Some(key),
            Ok(_) => {
                tracing::warn!(
                    env_var,
                    "judge provider: secret_key_ref.env variable is empty"
                );
                None
            }
            Err(_) => {
                tracing::warn!(
                    env_var,
                    "judge provider: secret_key_ref.env not found in environment"
                );
                None
            }
        },
        None => None,
    }
}

fn parse_structured_json_content(content: &str) -> Option<serde_json::Value> {
    let trimmed = content
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    serde_json::from_str(trimmed).ok()
}

pub(crate) async fn call_structured_provider(
    prompt: &str,
    endpoint: &str,
    model: &str,
    secret_key_env: Option<&str>,
    timeout_ms: u64,
) -> Option<serde_json::Value> {
    let api_key = resolve_api_key(secret_key_env);

    let body = serde_json::json!({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 1024,
    });

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "judge provider: failed to build HTTP client, skipping"
            );
            return None;
        }
    };

    let mut request = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .json(&body);
    if let Some(key) = api_key {
        request = request.header("Authorization", format!("Bearer {key}"));
    }

    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(
                error = %error,
                endpoint,
                model,
                "judge provider: request failed, skipping"
            );
            return None;
        }
    };

    let status = response.status();
    if !status.is_success() {
        tracing::warn!(
            status = status.as_u16(),
            endpoint,
            model,
            "judge provider: non-success HTTP response, skipping"
        );
        return None;
    }

    let response_text = match response.text().await {
        Ok(text) => text,
        Err(error) => {
            tracing::warn!(error = %error, "judge provider: failed to read response body");
            return None;
        }
    };

    let response_json: serde_json::Value = match serde_json::from_str(&response_text) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "judge provider: provider response is not valid JSON"
            );
            return None;
        }
    };

    let content = response_json
        .get("choices")
        .and_then(|choices| choices.get(0))
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(|content| content.as_str())
        .unwrap_or("");

    if content.is_empty() {
        tracing::warn!("judge provider: empty content in response");
        return None;
    }

    let parsed = parse_structured_json_content(content);
    if parsed.is_none() {
        tracing::warn!("judge provider: provider response content is not valid JSON");
    }
    parsed
}

/// Call a judge provider with a scoring prompt and return a structured result.
///
/// Returns `None` when the call is skipped due to the sampling policy, when
/// the API key is unavailable, or when the provider returns an error. The
/// main request path is never blocked by judge failures.
pub(crate) async fn call_judge_provider(
    input_text: &str,
    output_text: &str,
    rubric: &str,
    config: &JudgeConfig,
) -> Option<JudgeResult> {
    // Sampling: deterministically skip based on output text hash.
    if config.sampling_rate < 1.0 {
        let mut h: u64 = 0xcbf29ce484222325;
        for byte in output_text.as_bytes().iter().take(64) {
            h ^= *byte as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        let sample_value = (h % 1000) as f64 / 1000.0;
        if sample_value >= config.sampling_rate {
            tracing::debug!(
                sampling_rate = config.sampling_rate,
                "judge provider skipped by sampling policy"
            );
            return Some(JudgeResult {
                scorer_name: config.scorer_name.clone(),
                scorer_model: config.model.clone(),
                scorer_version: config.scorer_version.clone(),
                score: 0.0,
                threshold: config.threshold,
                verdict: JudgeVerdict::Pass,
                rationale: None,
                sampled: false,
            });
        }
    }

    let api_key = match &config.secret_key_env {
        Some(env_var) => match std::env::var(env_var) {
            Ok(k) if !k.is_empty() => Some(k),
            Ok(_) => {
                tracing::warn!(
                    env_var = env_var.as_str(),
                    "judge provider: secret_key_ref.env variable is empty"
                );
                None
            }
            Err(_) => {
                tracing::warn!(
                    env_var = env_var.as_str(),
                    "judge provider: secret_key_ref.env not found in environment"
                );
                None
            }
        },
        None => None,
    };

    let prompt = match &config.prompt_template {
        Some(template) => template
            .replace("{input}", input_text)
            .replace("{output}", output_text)
            .replace("{rubric}", rubric),
        None => default_judge_prompt(input_text, output_text, rubric),
    };

    let body = serde_json::json!({
        "model": config.model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 512,
    });

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "judge provider: failed to build HTTP client, skipping");
            return None;
        }
    };

    let mut req = client
        .post(&config.endpoint)
        .header("Content-Type", "application/json")
        .json(&body);
    if let Some(key) = api_key {
        req = req.header("Authorization", format!("Bearer {key}"));
    }

    let response = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                error = %e,
                endpoint = config.endpoint.as_str(),
                model = config.model.as_str(),
                "judge provider: request failed, skipping"
            );
            return None;
        }
    };

    let status = response.status();
    if !status.is_success() {
        tracing::warn!(
            status = status.as_u16(),
            endpoint = config.endpoint.as_str(),
            "judge provider: non-success HTTP response, skipping"
        );
        return None;
    }

    let response_text = match response.text().await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "judge provider: failed to read response body");
            return None;
        }
    };

    let response_json: serde_json::Value = match serde_json::from_str(&response_text) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "judge provider: provider response is not valid JSON");
            return None;
        }
    };

    // Extract assistant message content from OpenAI-compatible response.
    let content = response_json
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .unwrap_or("");

    if content.is_empty() {
        tracing::warn!("judge provider: empty content in response");
        return None;
    }

    // Parse the structured JSON the judge was instructed to emit.
    // Only the explicitly emitted fields are captured.
    let parsed: serde_json::Value = {
        match serde_json::from_str(content) {
            Ok(v) => v,
            Err(_) => {
                // Strip markdown fences the model may have added.
                let trimmed = content
                    .trim()
                    .trim_start_matches("```json")
                    .trim_start_matches("```")
                    .trim_end_matches("```")
                    .trim();
                match serde_json::from_str(trimmed) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            content_preview = &content[..content.len().min(120)],
                            "judge provider: cannot parse response as JSON, skipping"
                        );
                        return None;
                    }
                }
            }
        }
    };

    let score = parsed
        .get("score")
        .and_then(|s| s.as_f64())
        .map(|s| s.clamp(0.0, 1.0))
        .unwrap_or(0.0);

    let verdict = match parsed.get("verdict").and_then(|v| v.as_str()) {
        Some("pass") => JudgeVerdict::Pass,
        Some("warn") => JudgeVerdict::Warn,
        Some("fail") => JudgeVerdict::Fail,
        _ => {
            // Derive verdict from score when the model did not emit a valid one.
            if score >= config.threshold {
                JudgeVerdict::Pass
            } else if score >= config.warn_threshold {
                JudgeVerdict::Warn
            } else {
                JudgeVerdict::Fail
            }
        }
    };

    // SEC-004: capture only the `rationale` field explicitly requested from the model.
    let rationale = if config.rationale_capture {
        parsed
            .get("rationale")
            .and_then(|r| r.as_str())
            .filter(|r| !r.is_empty())
            .map(|r| r.to_string())
    } else {
        None
    };

    tracing::debug!(
        scorer_model = config.model.as_str(),
        score,
        verdict = verdict.as_str(),
        has_rationale = rationale.is_some(),
        "judge provider: evaluation complete"
    );

    Some(JudgeResult {
        scorer_name: config.scorer_name.clone(),
        scorer_model: config.model.clone(),
        scorer_version: config.scorer_version.clone(),
        score,
        threshold: config.threshold,
        verdict,
        rationale,
        sampled: true,
    })
}

fn normalized_tokens(text: &str) -> HashSet<String> {
    text.split(|ch: char| !ch.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect()
}

fn token_overlap_score(left: &str, right: &str) -> f64 {
    let left_tokens = normalized_tokens(left);
    let right_tokens = normalized_tokens(right);
    if left_tokens.is_empty() || right_tokens.is_empty() {
        return 0.0;
    }
    let overlap = left_tokens.intersection(&right_tokens).count() as f64;
    overlap / left_tokens.len().min(right_tokens.len()) as f64
}

fn build_result(
    spec: &AssertionSpec,
    score: f64,
    threshold: f64,
    details: serde_json::Value,
) -> AssertionResult {
    let passed = score >= threshold;
    AssertionResult {
        assertion_type: spec.assertion_type.as_str().to_string(),
        name: spec.name.clone(),
        score: Some(score),
        threshold: Some(threshold),
        weight: spec.weight,
        passed: Some(passed),
        reason_code: if passed {
            "ok".to_string()
        } else {
            format!(
                "quality.assertion.{}.below_threshold",
                assertion_key(spec.name.as_deref().unwrap_or(spec.assertion_type.as_str()))
            )
        },
        details,
        mode: spec.mode.clone(),
        severity: spec.severity.clone(),
    }
}

pub fn eval_llm_rubric(output: &str, context: &str, spec: &AssertionSpec) -> AssertionResult {
    let rubric = spec
        .config
        .get("rubric")
        .and_then(|value| value.as_str())
        .or(spec.value.as_deref())
        .unwrap_or("");
    let reference = spec
        .config
        .get("reference")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let required_terms = string_list(spec.config.get("required_terms"));
    let rubric_score = crate::gateway::quality::pub_relevancy_score(output, rubric);
    let reference_score = crate::gateway::quality::pub_similarity_score(output, reference);
    let context_score = if context.trim().is_empty() {
        None
    } else {
        crate::gateway::quality::pub_faithfulness_score(output, context)
    };
    let terms_score = required_terms_score(output, &required_terms);
    let score = average_present(&[rubric_score, reference_score, context_score, terms_score])
        .unwrap_or(0.0);
    let threshold = spec.threshold.unwrap_or(0.7);
    let passed = score >= threshold;
    AssertionResult {
        assertion_type: spec.assertion_type.as_str().to_string(),
        name: spec.name.clone(),
        score: Some(score),
        threshold: Some(threshold),
        weight: spec.weight,
        passed: Some(passed),
        reason_code: if passed {
            "ok".to_string()
        } else {
            format!(
                "quality.assertion.{}.below_threshold",
                assertion_key(spec.name.as_deref().unwrap_or(spec.assertion_type.as_str()))
            )
        },
        details: json!({
            "rubric": rubric,
            "reference": reference,
            "required_terms": required_terms,
            "provider": spec.provider,
            "prompt_template": spec.config.get("prompt_template").and_then(|value| value.as_str()),
            "heuristic_backend": "local_rubric_blend",
            "components": {
                "rubric_relevance": rubric_score,
                "reference_similarity": reference_score,
                "context_faithfulness": context_score,
                "required_terms": terms_score,
            }
        }),
        mode: spec.mode.clone(),
        severity: spec.severity.clone(),
    }
}

pub fn eval_search_rubric(output: &str, spec: &AssertionSpec) -> AssertionResult {
    let rubric = spec
        .config
        .get("rubric")
        .and_then(|value| value.as_str())
        .or(spec.value.as_deref())
        .unwrap_or("");
    let corpus = string_list(spec.config.get("corpus"));
    let rubric_score = crate::gateway::quality::pub_relevancy_score(output, rubric).unwrap_or(0.0);
    let corpus_score = corpus
        .iter()
        .filter_map(|entry| crate::gateway::quality::pub_similarity_score(output, entry))
        .fold(0.0, f64::max);
    let score = if corpus.is_empty() {
        rubric_score
    } else {
        ((rubric_score + corpus_score) / 2.0).clamp(0.0, 1.0)
    };
    build_result(
        spec,
        score,
        spec.threshold.unwrap_or(0.7),
        json!({
            "rubric": rubric,
            "corpus_size": corpus.len(),
            "components": {
                "rubric_relevance": rubric_score,
                "corpus_similarity": corpus_score,
            },
            "heuristic_backend": "rubric_plus_reference_search"
        }),
    )
}

pub(crate) fn eval_select_best(output: &str, spec: &AssertionSpec) -> AssertionResult {
    let candidates = string_list(spec.config.get("candidates"));
    let criteria = spec
        .config
        .get("criteria")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let best_idx = candidates
        .iter()
        .enumerate()
        .max_by(|(_, left), (_, right)| {
            let left_score =
                crate::gateway::quality::pub_relevancy_score(left, criteria).unwrap_or(0.0);
            let right_score =
                crate::gateway::quality::pub_relevancy_score(right, criteria).unwrap_or(0.0);
            left_score
                .partial_cmp(&right_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|(idx, _)| idx);
    let selected = best_idx.and_then(|idx| candidates.get(idx)).cloned();
    let score = if selected.as_deref() == Some(output) {
        1.0
    } else {
        0.0
    };
    build_result(
        spec,
        score,
        spec.threshold.unwrap_or(1.0),
        json!({
            "criteria": criteria,
            "candidate_count": candidates.len(),
            "selected_index": best_idx,
            "selected_candidate": selected,
            "heuristic_backend": "criteria_relevance_ranker"
        }),
    )
}

pub(crate) fn eval_g_eval(output: &str, spec: &AssertionSpec) -> AssertionResult {
    let criteria = spec
        .config
        .get("criteria")
        .and_then(|value| value.as_str())
        .or(spec.value.as_deref())
        .unwrap_or("");
    let score = crate::gateway::quality::pub_relevancy_score(output, criteria).unwrap_or(0.0);
    build_result(
        spec,
        score,
        spec.threshold.unwrap_or(0.6),
        json!({
            "criteria": criteria,
            "heuristic_backend": "criteria_relevance",
        }),
    )
}

pub fn eval_answer_relevance(
    output: &str,
    query_text: &str,
    spec: &AssertionSpec,
) -> AssertionResult {
    let question = spec
        .config
        .get("question")
        .and_then(|value| value.as_str())
        .or(spec.value.as_deref())
        .unwrap_or(query_text);
    let relevancy = crate::gateway::quality::pub_relevancy_score(output, question).unwrap_or(0.0);
    let lexical = crate::gateway::quality::pub_similarity_score(output, question).unwrap_or(0.0);
    let overlap = token_overlap_score(output, question);
    let score = relevancy.max(lexical).max(overlap);
    build_result(
        spec,
        score,
        spec.threshold.unwrap_or(0.7),
        json!({
            "question": question,
            "heuristic_backend": "query_relevance_blend",
            "relevancy_score": relevancy,
            "lexical_similarity": lexical,
            "token_overlap": overlap,
        }),
    )
}

pub(crate) fn eval_factuality(
    output: &str,
    context: &str,
    spec: &AssertionSpec,
) -> AssertionResult {
    let reference = spec
        .config
        .get("reference")
        .and_then(|value| value.as_str())
        .unwrap_or(context);

    if reference.trim().is_empty() {
        return build_result(
            spec,
            1.0,
            spec.threshold.unwrap_or(0.8),
            json!({
                "reference": null,
                "skipped": true,
                "reason": "no reference or context provided; factuality assertion cannot evaluate",
            }),
        );
    }

    let score = crate::gateway::quality::pub_faithfulness_score(output, reference).unwrap_or(0.0);
    build_result(
        spec,
        score,
        spec.threshold.unwrap_or(0.8),
        json!({
            "reference": reference,
            "heuristic_backend": "context_faithfulness",
        }),
    )
}

pub fn eval_closedqa(output: &str, query_text: &str, spec: &AssertionSpec) -> AssertionResult {
    let question = spec
        .config
        .get("question")
        .and_then(|value| value.as_str())
        .unwrap_or(query_text);
    let reference = spec
        .config
        .get("reference")
        .and_then(|value| value.as_str())
        .or(spec.value.as_deref());

    // When no reference is configured, skip the assertion with a passing score.
    // ClosedQA compares model output against a reference answer; without one
    // the similarity check is meaningless and would always fail.
    let reference = match reference {
        Some(r) if !r.is_empty() => r,
        _ => {
            return build_result(
                spec,
                1.0,
                spec.threshold.unwrap_or(0.5),
                json!({
                    "question": question,
                    "reference": null,
                    "heuristic_backend": "reference_similarity",
                    "skipped": true,
                    "reason": "no reference provided; assertion cannot evaluate without a reference answer",
                }),
            );
        }
    };

    let answer_similarity =
        crate::gateway::quality::pub_similarity_score(output, reference).unwrap_or(0.0);
    let question_relevance =
        crate::gateway::quality::pub_relevancy_score(output, question).unwrap_or(0.0);
    let score = ((answer_similarity * 0.8) + (question_relevance * 0.2)).clamp(0.0, 1.0);
    build_result(
        spec,
        score,
        spec.threshold.unwrap_or(0.5),
        json!({
            "question": question,
            "reference": reference,
            "heuristic_backend": "reference_similarity",
            "components": {
                "reference_similarity": answer_similarity,
                "question_relevance": question_relevance,
            }
        }),
    )
}

fn average_present(values: &[Option<f64>]) -> Option<f64> {
    let mut total = 0.0;
    let mut count = 0.0;

    for value in values.iter().flatten() {
        total += *value;
        count += 1.0;
    }

    if count == 0.0 {
        None
    } else {
        Some((total / count).clamp(0.0, 1.0))
    }
}

fn required_terms_score(text: &str, required_terms: &[String]) -> Option<f64> {
    if required_terms.is_empty() {
        return None;
    }

    let lower = text.to_ascii_lowercase();
    let hits = required_terms
        .iter()
        .filter(|term| lower.contains(&term.to_ascii_lowercase()))
        .count();
    Some((hits as f64 / required_terms.len() as f64).clamp(0.0, 1.0))
}

fn string_list(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(|value| value.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
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
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    fn spawn_json_server(
        status_line: &str,
        body: serde_json::Value,
    ) -> (String, mpsc::Receiver<String>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let address = listener.local_addr().expect("server address");
        let (request_tx, request_rx) = mpsc::sync_channel(1);
        let body_text = body.to_string();
        let status_line = status_line.to_string();

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut buffer = [0_u8; 8192];
            let read = stream.read(&mut buffer).expect("read request");
            let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
            let _ = request_tx.send(request);

            let response = format!(
                "HTTP/1.1 {status_line}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body_text.len(),
                body_text
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        });

        (format!("http://{address}"), request_rx, handle)
    }

    fn contains_spec() -> AssertionSpec {
        AssertionSpec::from_json(&json!({
            "type": "contains",
            "threshold": 0.5,
            "config": {"value": "billing"}
        }))
    }

    #[test]
    fn policy_llm_judge_config_defaults_and_sampling_clamp() {
        let config = JudgeConfig::from_json(&json!({
            "enabled": true,
            "secret_key_ref": {"env": "VERDICTAN_POLICY_JUDGE"},
            "sampling_rate": 2.5
        }))
        .expect("enabled config");

        assert_eq!(
            config.endpoint,
            "https://api.openai.com/v1/chat/completions"
        );
        assert_eq!(config.model, "gpt-5.4-mini");
        assert_eq!(
            config.secret_key_env.as_deref(),
            Some("VERDICTAN_POLICY_JUDGE")
        );
        assert_eq!(config.timeout_ms, 5000);
        assert!(config.rationale_capture);
        assert_eq!(config.threshold, 0.7);
        assert_eq!(config.warn_threshold, 0.5);
        assert_eq!(config.sampling_rate, 1.0);
        assert!(JudgeConfig::from_json(&json!({"enabled": false})).is_none());
    }

    #[test]
    fn policy_llm_judge_parse_helpers_cover_fences() {
        let parsed =
            parse_structured_json_content("```json\n{\"score\":0.9}\n```").expect("fenced json");
        assert_eq!(parsed["score"], json!(0.9));
        let prompt = default_judge_prompt("question", "answer", "rubric text");
        assert!(prompt.contains("question"));
        assert!(prompt.contains("answer"));
        assert!(prompt.contains("rubric text"));

        assert!(resolve_api_key(None).is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn policy_llm_judge_call_judge_provider_covers_sampling_and_verdict_derivation() {
        let skipped = call_judge_provider(
            "question",
            "answer",
            "rubric",
            &JudgeConfig {
                endpoint: "http://127.0.0.1:9".to_string(),
                model: "judge-model".to_string(),
                secret_key_env: None,
                timeout_ms: 100,
                rationale_capture: true,
                prompt_template: None,
                threshold: 0.8,
                warn_threshold: 0.4,
                sampling_rate: 0.0,
                scorer_name: "judge".to_string(),
                scorer_version: "1".to_string(),
            },
        )
        .await
        .expect("sampling result");
        assert!(!skipped.sampled);
        assert_eq!(skipped.verdict, JudgeVerdict::Pass);
        assert_eq!(skipped.score, 0.0);

        let response = json!({
            "choices": [{
                "message": {
                    "content": "{\"score\":0.6,\"verdict\":\"mystery\",\"rationale\":\"private chain\"}"
                }
            }]
        });
        let (url, requests, handle) = spawn_json_server("200 OK", response);
        let config = JudgeConfig {
            endpoint: url,
            model: "judge-model".to_string(),
            secret_key_env: None,
            timeout_ms: 2_000,
            rationale_capture: false,
            prompt_template: Some("Input={input}; Output={output}; Rubric={rubric}".to_string()),
            threshold: 0.75,
            warn_threshold: 0.5,
            sampling_rate: 1.0,
            scorer_name: "judge".to_string(),
            scorer_version: "2".to_string(),
        };

        let judged = call_judge_provider("question", "answer", "policy rubric", &config)
            .await
            .expect("judge provider response");
        let request = requests.recv().expect("captured request");
        handle.join().expect("server join");

        assert!(judged.sampled);
        assert_eq!(judged.verdict, JudgeVerdict::Warn);
        assert_eq!(judged.rationale, None);
        assert_eq!(judged.scorer_version, "2");
        assert!(request.contains("Input=question; Output=answer; Rubric=policy rubric"));
    }

    #[test]
    fn policy_llm_judge_eval_helpers_cover_skip_and_selection_paths() {
        let factuality = eval_factuality("answer", "", &contains_spec());
        assert_eq!(factuality.passed, Some(true));
        assert_eq!(factuality.details["skipped"], json!(true));

        let closedqa = eval_closedqa(
            "answer",
            "question",
            &AssertionSpec::from_json(&json!({
                "type": "model-graded-closedqa",
                "threshold": 0.5
            })),
        );
        assert_eq!(closedqa.passed, Some(true));
        assert_eq!(closedqa.details["skipped"], json!(true));

        let select_best = eval_select_best(
            "billing guidance",
            &AssertionSpec::from_json(&json!({
                "type": "select-best",
                "config": {
                    "criteria": "billing guidance",
                    "candidates": ["shipping", "billing guidance"]
                }
            })),
        );
        assert_eq!(select_best.passed, Some(true));
        assert_eq!(select_best.details["selected_index"], json!(1));

        let g_eval = eval_g_eval(
            "helpful billing guidance",
            &AssertionSpec::from_json(&json!({
                "type": "g-eval",
                "threshold": 0.1,
                "config": {"criteria": "billing guidance"}
            })),
        );
        assert_eq!(g_eval.passed, Some(true));

        assert_eq!(average_present(&[Some(0.25), Some(0.75), None]), Some(0.5));
        assert_eq!(average_present(&[None, None]), None);
        assert_eq!(
            required_terms_score(
                "The answer includes billing but not refunds.",
                &["billing".to_string(), "refunds".to_string()]
            ),
            Some(1.0)
        );
        assert_eq!(required_terms_score("text", &[]), None);
        assert_eq!(
            string_list(Some(&json!(["billing", 7, "refunds"]))),
            vec!["billing".to_string(), "refunds".to_string()]
        );
    }

    #[test]
    fn judge_verdict_as_str() {
        assert_eq!(JudgeVerdict::Pass.as_str(), "pass");
        assert_eq!(JudgeVerdict::Warn.as_str(), "warn");
        assert_eq!(JudgeVerdict::Fail.as_str(), "fail");
    }

    #[test]
    fn judge_verdict_serde_round_trip() {
        for (verdict, expected) in [
            (JudgeVerdict::Pass, "\"pass\""),
            (JudgeVerdict::Warn, "\"warn\""),
            (JudgeVerdict::Fail, "\"fail\""),
        ] {
            let json = serde_json::to_string(&verdict).unwrap();
            assert_eq!(json, expected);
            let recovered: JudgeVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, verdict);
        }
    }

    #[test]
    fn judge_verdict_debug_clone() {
        let verdict = JudgeVerdict::Warn;
        let dbg = format!("{verdict:?}");
        assert!(dbg.contains("Warn"));
        let cloned = verdict.clone();
        assert_eq!(cloned, JudgeVerdict::Warn);
    }

    #[test]
    fn judge_result_to_json() {
        let result = JudgeResult {
            scorer_name: "quality-scorer".to_string(),
            scorer_model: "gpt-5.4-mini".to_string(),
            scorer_version: "1".to_string(),
            score: 0.85,
            threshold: 0.7,
            verdict: JudgeVerdict::Pass,
            rationale: Some("Looks good".to_string()),
            sampled: true,
        };
        let json = result.to_json();
        assert_eq!(json["scorer_name"], "quality-scorer");
        assert_eq!(json["scorer_model"], "gpt-5.4-mini");
        assert_eq!(json["scorer_version"], "1");
        assert_eq!(json["score"], 0.85);
        assert_eq!(json["threshold"], 0.7);
        assert_eq!(json["verdict"], "pass");
        assert_eq!(json["rationale"], "Looks good");
        assert_eq!(json["sampled"], true);
    }

    #[test]
    fn judge_result_to_json_without_rationale() {
        let result = JudgeResult {
            scorer_name: "scorer".to_string(),
            scorer_model: "model".to_string(),
            scorer_version: "1".to_string(),
            score: 0.4,
            threshold: 0.7,
            verdict: JudgeVerdict::Fail,
            rationale: None,
            sampled: true,
        };
        let json = result.to_json();
        assert!(json["rationale"].is_null());
        assert_eq!(json["verdict"], "fail");
    }

    #[test]
    fn judge_config_from_json_disabled() {
        assert!(JudgeConfig::from_json(&json!({})).is_none());
        assert!(JudgeConfig::from_json(&json!({"enabled": false})).is_none());
    }

    #[test]
    fn judge_config_from_json_custom_values() {
        let config = JudgeConfig::from_json(&json!({
            "enabled": true,
            "endpoint": "https://custom.api.com/v1/chat",
            "model": "claude-3-5-sonnet",
            "timeout_ms": 10000,
            "rationale_capture": false,
            "prompt_template": "Custom: {input} {output} {rubric}",
            "threshold": 0.9,
            "warn_threshold": 0.6,
            "sampling_rate": 0.5,
            "scorer_name": "custom-scorer",
            "scorer_version": "3"
        }))
        .unwrap();

        assert_eq!(config.endpoint, "https://custom.api.com/v1/chat");
        assert_eq!(config.model, "claude-3-5-sonnet");
        assert_eq!(config.timeout_ms, 10000);
        assert!(!config.rationale_capture);
        assert!(config
            .prompt_template
            .as_deref()
            .unwrap()
            .contains("Custom:"));
        assert_eq!(config.threshold, 0.9);
        assert_eq!(config.warn_threshold, 0.6);
        assert_eq!(config.sampling_rate, 0.5);
        assert_eq!(config.scorer_name, "custom-scorer");
        assert_eq!(config.scorer_version, "3");
    }

    #[test]
    fn parse_structured_json_content_plain_json() {
        let parsed = parse_structured_json_content("{\"score\": 0.5}").unwrap();
        assert_eq!(parsed["score"], 0.5);
    }

    #[test]
    fn parse_structured_json_content_fenced() {
        let parsed = parse_structured_json_content("```json\n{\"key\": \"val\"}\n```").unwrap();
        assert_eq!(parsed["key"], "val");
    }

    #[test]
    fn parse_structured_json_content_invalid() {
        assert!(parse_structured_json_content("not json at all").is_none());
    }

    #[test]
    fn parse_structured_json_content_fenced_no_lang() {
        let parsed = parse_structured_json_content("```\n{\"a\": 1}\n```").unwrap();
        assert_eq!(parsed["a"], 1);
    }

    #[test]
    fn normalized_tokens_splits_and_lowercases() {
        let tokens = normalized_tokens("Hello World! Foo-Bar");
        assert!(tokens.contains("hello"));
        assert!(tokens.contains("world"));
        assert!(tokens.contains("foo"));
        assert!(tokens.contains("bar"));
    }

    #[test]
    fn normalized_tokens_empty() {
        assert!(normalized_tokens("").is_empty());
        assert!(normalized_tokens("!!!").is_empty());
    }

    #[test]
    fn token_overlap_score_identical() {
        let score = token_overlap_score("foo bar baz", "foo bar baz");
        assert!((score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn token_overlap_score_no_common() {
        let score = token_overlap_score("abc def", "xyz uvw");
        assert!((score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn token_overlap_score_empty_strings() {
        assert!((token_overlap_score("", "hello") - 0.0).abs() < f64::EPSILON);
        assert!((token_overlap_score("hello", "") - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn build_result_passing() {
        let spec = AssertionSpec::from_json(&json!({"type": "test", "threshold": 0.5}));
        let result = build_result(&spec, 0.8, 0.5, json!({"key": "val"}));
        assert_eq!(result.passed, Some(true));
        assert_eq!(result.reason_code, "ok");
        assert_eq!(result.score, Some(0.8));
        assert_eq!(result.threshold, Some(0.5));
    }

    #[test]
    fn build_result_failing() {
        let spec = AssertionSpec::from_json(&json!({"type": "test", "threshold": 0.9}));
        let result = build_result(&spec, 0.3, 0.9, json!({}));
        assert_eq!(result.passed, Some(false));
        assert!(result.reason_code.contains("below_threshold"));
    }

    #[test]
    fn average_present_clamps_to_unit() {
        assert_eq!(average_present(&[Some(1.5)]), Some(1.0));
    }

    #[test]
    fn required_terms_score_partial_match() {
        let score = required_terms_score("billing info", &["billing".into(), "refunds".into()]);
        assert_eq!(score, Some(0.5));
    }

    #[test]
    fn required_terms_score_case_insensitive() {
        let score = required_terms_score("BILLING REFUNDS", &["billing".into(), "refunds".into()]);
        assert_eq!(score, Some(1.0));
    }

    #[test]
    fn string_list_none_returns_empty() {
        assert!(string_list(None).is_empty());
    }

    #[test]
    fn string_list_non_array_returns_empty() {
        assert!(string_list(Some(&json!("not_an_array"))).is_empty());
    }

    #[test]
    fn eval_llm_rubric_with_reference_and_required_terms() {
        let spec = AssertionSpec::from_json(&json!({
            "type": "llm-rubric",
            "threshold": 0.0,
            "config": {
                "rubric": "billing guidance",
                "reference": "billing guidance about invoices",
                "required_terms": ["billing"]
            }
        }));
        let result = eval_llm_rubric("billing guidance about invoices", "context", &spec);
        assert_eq!(result.passed, Some(true));
        assert_eq!(result.details["heuristic_backend"], "local_rubric_blend");
    }

    #[test]
    fn eval_llm_rubric_with_empty_context() {
        let spec = AssertionSpec::from_json(&json!({
            "type": "llm-rubric",
            "threshold": 0.0,
            "config": {"rubric": "test rubric"}
        }));
        let result = eval_llm_rubric("output text", "", &spec);
        assert!(result.score.is_some());
    }

    #[test]
    fn eval_search_rubric_without_corpus() {
        let spec = AssertionSpec::from_json(&json!({
            "type": "search-rubric",
            "threshold": 0.0,
            "config": {"rubric": "test query"}
        }));
        let result = eval_search_rubric("test query answer", &spec);
        assert!(result.score.is_some());
        assert_eq!(result.details["corpus_size"], 0);
    }

    #[test]
    fn eval_search_rubric_with_corpus() {
        let spec = AssertionSpec::from_json(&json!({
            "type": "search-rubric",
            "threshold": 0.0,
            "config": {
                "rubric": "test",
                "corpus": ["test reference", "other"]
            }
        }));
        let result = eval_search_rubric("test reference output", &spec);
        assert!(result.score.is_some());
        assert_eq!(result.details["corpus_size"], 2);
    }

    #[test]
    fn eval_answer_relevance_uses_question_override() {
        let spec = AssertionSpec::from_json(&json!({
            "type": "answer-relevance",
            "threshold": 0.0,
            "config": {"question": "custom question"}
        }));
        let result = eval_answer_relevance("custom question answer", "original query", &spec);
        assert!(result.score.is_some());
        assert_eq!(result.details["question"], "custom question");
    }

    #[test]
    fn eval_answer_relevance_uses_query_text_as_default() {
        let spec = AssertionSpec::from_json(&json!({
            "type": "answer-relevance",
            "threshold": 0.0
        }));
        let result = eval_answer_relevance("answer", "query text", &spec);
        assert_eq!(result.details["question"], "query text");
    }

    #[test]
    fn eval_factuality_with_reference_in_config() {
        let spec = AssertionSpec::from_json(&json!({
            "type": "factuality",
            "threshold": 0.0,
            "config": {"reference": "The sky is blue."}
        }));
        let result = eval_factuality("The sky is blue.", "context", &spec);
        assert!(result.score.is_some());
        assert_eq!(result.details["reference"], "The sky is blue.");
    }

    #[test]
    fn eval_factuality_empty_reference_skips() {
        let spec = AssertionSpec::from_json(&json!({
            "type": "factuality",
            "threshold": 0.5,
            "config": {"reference": "   "}
        }));
        let result = eval_factuality("output", "   ", &spec);
        assert_eq!(result.passed, Some(true));
        assert_eq!(result.details["skipped"], true);
    }

    #[test]
    fn eval_closedqa_with_reference() {
        let spec = AssertionSpec::from_json(&json!({
            "type": "model-graded-closedqa",
            "threshold": 0.0,
            "config": {
                "question": "What color is the sky?",
                "reference": "blue"
            }
        }));
        let result = eval_closedqa("The sky is blue", "What color is the sky?", &spec);
        assert!(result.score.is_some());
        assert_eq!(result.details["question"], "What color is the sky?");
        assert_eq!(result.details["reference"], "blue");
    }

    #[test]
    fn eval_select_best_no_candidates() {
        let spec = AssertionSpec::from_json(&json!({
            "type": "select-best",
            "config": {"criteria": "quality", "candidates": []}
        }));
        let result = eval_select_best("anything", &spec);
        assert_eq!(result.score, Some(0.0));
        assert_eq!(result.details["candidate_count"], 0);
    }

    #[test]
    fn eval_g_eval_with_value_fallback() {
        let spec = AssertionSpec::from_json(&json!({
            "type": "g-eval",
            "threshold": 0.0,
            "value": "helpfulness"
        }));
        let result = eval_g_eval("helpful response", &spec);
        assert_eq!(result.details["criteria"], "helpfulness");
    }
}
