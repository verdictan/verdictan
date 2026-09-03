// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Assertion type enum ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssertionType {
    Contains,
    Similar,
    LlmRubric,
    SearchRubric,
    SelectBest,
    GEval,
    AnswerRelevance,
    Factuality,
    ModelGradedClosedQA,
    Rouge,
    Meteor,
    Gleu,
    SemanticSimilarity,
    Perplexity,
    Javascript,
    Python,
    Cost,
    Moderation,
    ContextFaithfulness,
    ConversationRelevance,
    IsRefusal,
    TrajectoryGoalSuccess,
    TrajectoryToolUsed,
    TrajectoryToolSequence,
    TrajectoryStepCount,
    ContextRecall,
    ContextRelevance,
    RagDocumentExfiltration,
    RagPoisoning,
    RagSourceAttribution,
    Threshold,
    SchemaMatch,
    Regex,
    JsonPath,
    /// Pass-through for all other string assertion types already handled by quality.rs
    Other(String),
}

impl AssertionType {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "contains" => Self::Contains,
            "similar" => Self::Similar,
            "llm-rubric" => Self::LlmRubric,
            "search-rubric" => Self::SearchRubric,
            "select-best" => Self::SelectBest,
            "g-eval" => Self::GEval,
            "answer-relevance" => Self::AnswerRelevance,
            "factuality" | "model-graded-factuality" => Self::Factuality,
            "model-graded-closedqa" => Self::ModelGradedClosedQA,
            "rouge" => Self::Rouge,
            "meteor" => Self::Meteor,
            "gleu" => Self::Gleu,
            "semantic-similarity" => Self::SemanticSimilarity,
            "perplexity" | "perplexity-score" => Self::Perplexity,
            "javascript" => Self::Javascript,
            "python" => Self::Python,
            "cost" => Self::Cost,
            "moderation" => Self::Moderation,
            "context-faithfulness" => Self::ContextFaithfulness,
            "conversation-relevance" => Self::ConversationRelevance,
            "is-refusal" => Self::IsRefusal,
            "trajectory:goal-success" => Self::TrajectoryGoalSuccess,
            "trajectory:tool-used" => Self::TrajectoryToolUsed,
            "trajectory:tool-sequence" => Self::TrajectoryToolSequence,
            "trajectory:step-count" => Self::TrajectoryStepCount,
            "context-recall" => Self::ContextRecall,
            "context-relevance" => Self::ContextRelevance,
            "rag-document-exfiltration" => Self::RagDocumentExfiltration,
            "rag-poisoning" => Self::RagPoisoning,
            "rag-source-attribution" => Self::RagSourceAttribution,
            "threshold" => Self::Threshold,
            "schema-match" => Self::SchemaMatch,
            "regex" => Self::Regex,
            "json-path" => Self::JsonPath,
            other => Self::Other(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Contains => "contains",
            Self::Similar => "similar",
            Self::LlmRubric => "llm-rubric",
            Self::SearchRubric => "search-rubric",
            Self::SelectBest => "select-best",
            Self::GEval => "g-eval",
            Self::AnswerRelevance => "answer-relevance",
            Self::Factuality => "factuality",
            Self::ModelGradedClosedQA => "model-graded-closedqa",
            Self::Rouge => "rouge",
            Self::Meteor => "meteor",
            Self::Gleu => "gleu",
            Self::SemanticSimilarity => "semantic-similarity",
            Self::Perplexity => "perplexity",
            Self::Javascript => "javascript",
            Self::Python => "python",
            Self::Cost => "cost",
            Self::Moderation => "moderation",
            Self::ContextFaithfulness => "context-faithfulness",
            Self::ConversationRelevance => "conversation-relevance",
            Self::IsRefusal => "is-refusal",
            Self::TrajectoryGoalSuccess => "trajectory:goal-success",
            Self::TrajectoryToolUsed => "trajectory:tool-used",
            Self::TrajectoryToolSequence => "trajectory:tool-sequence",
            Self::TrajectoryStepCount => "trajectory:step-count",
            Self::ContextRecall => "context-recall",
            Self::ContextRelevance => "context-relevance",
            Self::RagDocumentExfiltration => "rag-document-exfiltration",
            Self::RagPoisoning => "rag-poisoning",
            Self::RagSourceAttribution => "rag-source-attribution",
            Self::Threshold => "threshold",
            Self::SchemaMatch => "schema-match",
            Self::Regex => "regex",
            Self::JsonPath => "json-path",
            Self::Other(s) => s.as_str(),
        }
    }
}

// ── Assertion mode and severity (Phase 11) ────────────────────────────────────

/// Enforcement mode for a single assertion.
///
/// - `Enforce` (default): failure contributes to the quality-scorer verdict and
///   can block the response depending on `severity`.
/// - `Audit`: evaluated and reported in scores/details but never causes a block.
/// - `Shadow`: evaluated in the background; results are logged at debug level
///   only and never affect the verdict or details exposed to the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AssertionMode {
    #[default]
    Enforce,
    Audit,
    Shadow,
}

impl AssertionMode {
    pub fn from_json(v: &Value) -> Self {
        match v.as_str() {
            Some("audit") => Self::Audit,
            Some("shadow") => Self::Shadow,
            _ => Self::Enforce,
        }
    }
}

/// Severity of a failing assertion when `mode == Enforce`.
///
/// - `Critical` (default): any failure triggers the configured failure action.
/// - `Warning`: reported but does not trigger the failure action.
/// - `Info`: reported only, no action taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AssertionSeverity {
    #[default]
    Critical,
    Warning,
    Info,
}

impl AssertionSeverity {
    pub fn from_json(v: &Value) -> Self {
        match v.as_str() {
            Some("warning") => Self::Warning,
            Some("info") => Self::Info,
            _ => Self::Critical,
        }
    }
}

// ── AssertionSpec ─────────────────────────────────────────────────────────────

/// Parsed representation of a single assertion entry in a policy config.
///
/// Fields not used by a particular assertion type are `None` / default.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionSpec {
    pub assertion_type: AssertionType,
    /// Optional human-readable name for the assertion (used in reason codes).
    pub name: Option<String>,
    /// String value argument for assertions like `contains`, `regex`, etc.
    pub value: Option<String>,
    /// Minimum score required for the assertion to pass.
    pub threshold: Option<f64>,
    /// Relative weight when computing the weighted-average pass policy score.
    pub weight: f64,
    /// Provider id reference (for llm-rubric, similar, cost).
    pub provider: Option<String>,
    /// Named metric to compare against threshold (for `threshold` assertion
    /// type which checks a named quality metric).
    pub metric: Option<String>,
    /// Whether to negate the match (e.g., "does not contain").
    pub negate: bool,
    /// Whether string comparisons are case sensitive (for `contains`, `regex`).
    pub case_sensitive: bool,
    /// Whether the assertion is enabled.
    pub enabled: bool,
    /// Enforcement mode.
    pub mode: AssertionMode,
    /// Severity when mode is `Enforce` and the assertion fails.
    pub severity: AssertionSeverity,
    /// Raw config blob for assertion-specific options.
    pub config: Value,
    /// Name of an assertion pack to inline (used during pack resolution).
    pub pack: Option<String>,
}

impl AssertionSpec {
    /// Parse a single assertion JSON object from a policy config.
    pub fn from_json(v: &Value) -> Self {
        let assertion_type_str = v.get("type").and_then(|t| t.as_str()).unwrap_or("unknown");
        let config = v.get("config").cloned().unwrap_or(Value::Null);

        // For `contains` the value may live either in `config.value` or directly
        // as `value` on the assertion object.
        let value = v
            .get("value")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                config
                    .get("value")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
            });

        Self {
            assertion_type: AssertionType::from_str(assertion_type_str),
            name: v
                .get("name")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            value,
            threshold: v.get("threshold").and_then(|t| t.as_f64()),
            weight: v
                .get("weight")
                .and_then(|w| w.as_f64())
                .unwrap_or(1.0)
                .clamp(0.0, 10.0),
            provider: v
                .get("provider")
                .and_then(|p| p.as_str())
                .map(|s| s.to_string()),
            metric: v
                .get("metric")
                .and_then(|m| m.as_str())
                .map(|s| s.to_string())
                .or_else(|| {
                    config
                        .get("metric")
                        .and_then(|m| m.as_str())
                        .map(|s| s.to_string())
                }),
            negate: v
                .get("negate")
                .or_else(|| config.get("negate"))
                .and_then(|n| n.as_bool())
                .unwrap_or(false),
            case_sensitive: v
                .get("case_sensitive")
                .or_else(|| config.get("case_sensitive"))
                .and_then(|c| c.as_bool())
                .unwrap_or(true),
            enabled: v.get("enabled").and_then(|e| e.as_bool()).unwrap_or(true),
            mode: v
                .get("mode")
                .map(AssertionMode::from_json)
                .unwrap_or_default(),
            severity: v
                .get("severity")
                .map(AssertionSeverity::from_json)
                .unwrap_or_default(),
            config,
            pack: v
                .get("pack")
                .and_then(|p| p.as_str())
                .map(|s| s.to_string()),
        }
    }
}

// ── AssertionResult ────────────────────────────────────────────────────────────

/// Result of evaluating a single assertion.
#[derive(Debug, Clone, Serialize)]
pub struct AssertionResult {
    pub assertion_type: String,
    pub name: Option<String>,
    pub score: Option<f64>,
    pub threshold: Option<f64>,
    pub weight: f64,
    pub passed: Option<bool>,
    pub reason_code: String,
    pub details: Value,
    pub mode: AssertionMode,
    pub severity: AssertionSeverity,
}

impl AssertionResult {
    /// Whether this result should contribute to blocking (i.e., will produce a
    /// failure that causes the verdict to change). Returns `false` when mode is
    /// `Audit` or `Shadow`, or when severity is `Warning`/`Info`.
    pub(crate) fn is_blocking_failure(&self) -> bool {
        if self.passed != Some(false) {
            return false;
        }
        if self.mode != AssertionMode::Enforce {
            return false;
        }
        self.severity == AssertionSeverity::Critical
    }

    /// Whether this result should appear in the client-visible details payload.
    pub(crate) fn is_visible(&self) -> bool {
        self.mode != AssertionMode::Shadow
    }
}

// ── AssertionContext ────────────────────────────────────────────────────────────

/// Everything an assertion evaluator may need from the surrounding request /
/// response context.
pub struct AssertionContext<'a> {
    pub output_text: &'a str,
    pub query_text: &'a str,
    pub context_text: &'a str,
    pub request_json: &'a Value,
    pub upstream_json: &'a Value,
    /// Named quality metric scores already computed by the quality-scorer
    /// (faithfulness, relevancy, bleu, nli_entailment, etc.).
    pub quality_scores: &'a BTreeMap<String, f64>,
    /// Optional provider registry used by provider-backed assertions such as
    /// real embedding similarity.
    pub provider_registry: Option<&'a crate::gateway::providers::ProviderRegistry>,
}

// ── Individual assertion evaluators ───────────────────────────────────────────

/// `contains` / `icontains` assertion.
pub fn eval_contains(output: &str, spec: &AssertionSpec) -> AssertionResult {
    let value = spec
        .value
        .as_deref()
        .or_else(|| spec.config.get("value").and_then(|v| v.as_str()))
        .unwrap_or("");
    let (haystack, needle) = if spec.case_sensitive {
        (output.to_string(), value.to_string())
    } else {
        (output.to_lowercase(), value.to_lowercase())
    };
    let found = haystack.contains(needle.as_str());
    let result = if spec.negate { !found } else { found };
    let score = if result { 1.0 } else { 0.0 };
    let threshold = spec.threshold.unwrap_or(1.0);
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
        details: serde_json::json!({ "value": value, "found": found, "negate": spec.negate, "case_sensitive": spec.case_sensitive }),
        mode: spec.mode.clone(),
        severity: spec.severity.clone(),
    }
}

/// `threshold` assertion — checks a named metric from quality_scores.
pub fn eval_threshold(
    quality_scores: &BTreeMap<String, f64>,
    spec: &AssertionSpec,
) -> AssertionResult {
    let metric_name = spec
        .metric
        .as_deref()
        .or_else(|| spec.config.get("metric").and_then(|v| v.as_str()))
        .unwrap_or("");
    let min = spec
        .threshold
        .or_else(|| spec.config.get("min").and_then(|v| v.as_f64()))
        .unwrap_or(0.5);
    let max = spec.config.get("max").and_then(|v| v.as_f64());

    let actual = quality_scores.get(metric_name).copied();
    let passed_min = actual.map(|s| s >= min).unwrap_or(false);
    let passed_max = max
        .map(|mx| actual.map(|s| s <= mx).unwrap_or(true))
        .unwrap_or(true);
    let passed = passed_min && passed_max;

    AssertionResult {
        assertion_type: spec.assertion_type.as_str().to_string(),
        name: spec.name.clone(),
        score: actual,
        threshold: Some(min),
        weight: spec.weight,
        passed: Some(passed),
        reason_code: if passed {
            "ok".to_string()
        } else {
            format!(
                "quality.assertion.{}.threshold_failed",
                assertion_key(spec.name.as_deref().unwrap_or(metric_name))
            )
        },
        details: serde_json::json!({ "metric": metric_name, "actual": actual, "min": min, "max": max }),
        mode: spec.mode.clone(),
        severity: spec.severity.clone(),
    }
}

/// `moderation` assertion — local keyword/category check.
pub fn eval_moderation(output: &str, spec: &AssertionSpec) -> AssertionResult {
    let lower = output.to_lowercase();
    let categories = ["hate", "violence", "sexual", "self-harm", "self_harm"];
    let custom: Vec<&str> = spec
        .config
        .get("categories")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    let effective_categories: Vec<&str> = if custom.is_empty() {
        categories.to_vec()
    } else {
        custom
    };

    let flagged_cats: Vec<&str> = effective_categories
        .iter()
        .filter(|cat| lower.contains(*cat) || lower.contains(&cat.replace('-', "_")))
        .copied()
        .collect();

    let clean = flagged_cats.is_empty();
    let score = if clean { 1.0 } else { 0.0 };
    let threshold = spec.threshold.unwrap_or(1.0);
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
            "quality.assertion.moderation.flagged".to_string()
        },
        details: serde_json::json!({ "flagged_categories": flagged_cats }),
        mode: spec.mode.clone(),
        severity: spec.severity.clone(),
    }
}

/// `context-faithfulness` assertion — reuses TF-IDF cosine from quality.rs.
pub(crate) fn eval_context_faithfulness(
    output: &str,
    context: &str,
    spec: &AssertionSpec,
) -> AssertionResult {
    let threshold = spec.threshold.unwrap_or(0.7);
    let score = if context.is_empty() {
        0.0
    } else {
        crate::gateway::quality::pub_faithfulness_score(output, context).unwrap_or(0.0)
    };
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
            "quality.assertion.context_faithfulness.below_threshold".to_string()
        },
        details: serde_json::json!({ "has_context": !context.is_empty() }),
        mode: spec.mode.clone(),
        severity: spec.severity.clone(),
    }
}

async fn eval_quality_native(spec: &AssertionSpec, ctx: &AssertionContext<'_>) -> AssertionResult {
    let assertion_type = spec.assertion_type.as_str();
    let threshold = spec
        .threshold
        .or_else(|| crate::gateway::quality::pub_default_threshold_for_assertion(assertion_type));
    let (score, details) = crate::gateway::quality::pub_score_native_assertion(
        assertion_type,
        ctx.request_json,
        ctx.upstream_json,
        ctx.output_text,
        ctx.query_text,
        ctx.context_text,
        &spec.config,
    )
    .await;
    let passed = threshold.map(|value| score.unwrap_or(0.0) >= value);

    AssertionResult {
        assertion_type: assertion_type.to_string(),
        name: spec.name.clone(),
        score,
        threshold,
        weight: spec.weight,
        passed,
        reason_code: if passed == Some(false) {
            format!(
                "quality.assertion.{}.below_threshold",
                assertion_key(spec.name.as_deref().unwrap_or(assertion_type))
            )
        } else {
            "ok".to_string()
        },
        details,
        mode: spec.mode.clone(),
        severity: spec.severity.clone(),
    }
}

// ── Assertion orchestrator ────────────────────────────────────────────────────

/// Evaluate a slice of `AssertionSpec` objects and return results.
///
/// Only a focused, local-only subset is natively handled here. All other types
/// still fall through to a stub so results remain visible in the output.
///
/// Per: **all assertions are always evaluated**; mode/severity only
/// affect how results are reported and whether failures trigger actions.
pub async fn evaluate_assertions(
    assertions: &[AssertionSpec],
    ctx: &AssertionContext<'_>,
) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for spec in assertions.iter().filter(|s| s.enabled) {
        let result = match &spec.assertion_type {
            AssertionType::Contains => eval_contains(ctx.output_text, spec),
            AssertionType::LlmRubric => {
                crate::policy::llm_judge::eval_llm_rubric(ctx.output_text, ctx.context_text, spec)
            }
            AssertionType::SearchRubric => {
                crate::policy::llm_judge::eval_search_rubric(ctx.output_text, spec)
            }
            AssertionType::SelectBest => {
                crate::policy::llm_judge::eval_select_best(ctx.output_text, spec)
            }
            AssertionType::GEval => crate::policy::llm_judge::eval_g_eval(ctx.output_text, spec),
            AssertionType::AnswerRelevance => crate::policy::llm_judge::eval_answer_relevance(
                ctx.output_text,
                ctx.query_text,
                spec,
            ),
            AssertionType::Factuality => {
                crate::policy::llm_judge::eval_factuality(ctx.output_text, ctx.context_text, spec)
            }
            AssertionType::ModelGradedClosedQA => {
                crate::policy::llm_judge::eval_closedqa(ctx.output_text, ctx.query_text, spec)
            }
            AssertionType::Rouge => crate::policy::nlp_metrics::eval_rouge(ctx.output_text, spec),
            AssertionType::Meteor => crate::policy::nlp_metrics::eval_meteor(ctx.output_text, spec),
            AssertionType::Gleu => crate::policy::nlp_metrics::eval_gleu(ctx.output_text, spec),
            AssertionType::SemanticSimilarity => {
                crate::policy::nlp_metrics::eval_semantic_similarity(
                    ctx.output_text,
                    spec,
                    ctx.provider_registry,
                )
            }
            AssertionType::Perplexity => {
                crate::policy::nlp_metrics::eval_perplexity(ctx.output_text, spec)
            }
            AssertionType::Moderation => eval_moderation(ctx.output_text, spec),
            AssertionType::ContextFaithfulness => {
                eval_context_faithfulness(ctx.output_text, ctx.context_text, spec)
            }
            AssertionType::ConversationRelevance
            | AssertionType::IsRefusal
            | AssertionType::TrajectoryGoalSuccess
            | AssertionType::TrajectoryToolUsed
            | AssertionType::TrajectoryToolSequence
            | AssertionType::TrajectoryStepCount => eval_quality_native(spec, ctx).await,
            AssertionType::ContextRecall => crate::policy::rag_assertions::eval_context_recall(
                ctx.output_text,
                ctx.context_text,
                ctx.request_json,
                spec,
            ),
            AssertionType::ContextRelevance => {
                crate::policy::rag_assertions::eval_context_relevance(
                    ctx.query_text,
                    ctx.context_text,
                    ctx.request_json,
                    spec,
                )
            }
            AssertionType::RagDocumentExfiltration => {
                crate::policy::rag_assertions::eval_rag_document_exfiltration(
                    ctx.output_text,
                    ctx.context_text,
                    ctx.request_json,
                    spec,
                )
            }
            AssertionType::RagPoisoning => crate::policy::rag_assertions::eval_rag_poisoning(
                ctx.output_text,
                ctx.context_text,
                spec,
            ),
            AssertionType::RagSourceAttribution => {
                crate::policy::rag_assertions::eval_rag_source_attribution(
                    ctx.output_text,
                    ctx.context_text,
                    ctx.request_json,
                    spec,
                )
            }
            AssertionType::Threshold => eval_threshold(ctx.quality_scores, spec),
            _ => AssertionResult {
                assertion_type: spec.assertion_type.as_str().to_string(),
                name: spec.name.clone(),
                score: None,
                threshold: spec.threshold,
                weight: spec.weight,
                passed: None,
                reason_code: "ok".to_string(),
                details: serde_json::json!({
                    "note": "delegated_to_quality_scorer"
                }),
                mode: spec.mode.clone(),
                severity: spec.severity.clone(),
            },
        };
        results.push(result);
    }
    results
}

// ── Pass policy (Phase 12) ────────────────────────────────────────────────────

/// Strategy used to decide if the quality-scorer as a whole passes.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PassStrategy {
    /// Every enforced critical assertion must pass (default).
    #[default]
    All,
    /// At least `quorum` fraction of enforced assertions must pass.
    Quorum,
    /// Weighted-average score of all enforced assertions must meet `threshold`.
    WeightedAverage,
}

/// Configuration for the quality-scorer pass policy.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassPolicy {
    pub strategy: PassStrategy,
    /// Required passing fraction for `Quorum` strategy (0.0–1.0).
    pub quorum: f64,
    /// Required weighted-average score for `WeightedAverage` strategy.
    pub threshold: f64,
}

impl Default for PassPolicy {
    fn default() -> Self {
        Self {
            strategy: PassStrategy::All,
            quorum: 0.5,
            threshold: 0.5,
        }
    }
}

#[allow(dead_code)]
impl PassPolicy {
    pub fn from_json(v: &Value) -> Self {
        let strategy = match v.get("strategy").and_then(|s| s.as_str()) {
            Some("quorum") => PassStrategy::Quorum,
            Some("weighted_average") => PassStrategy::WeightedAverage,
            _ => PassStrategy::All,
        };
        let quorum = v
            .get("quorum")
            .and_then(|q| q.as_f64())
            .unwrap_or(0.5)
            .clamp(0.0, 1.0);
        let threshold = v
            .get("threshold")
            .and_then(|t| t.as_f64())
            .unwrap_or(0.5)
            .clamp(0.0, 1.0);
        Self {
            strategy,
            quorum,
            threshold,
        }
    }
}

/// Evaluate whether the set of assertion results satisfies the pass policy.
///
/// Returns `(passed: bool, reason: String)` where `reason` is empty on pass.
///
/// Per and: only results with `mode == Enforce` contribute.
/// `Shadow` and `Audit` results are excluded from the pass policy calculation.
#[allow(dead_code)]
pub fn evaluate_pass_policy(results: &[AssertionResult], policy: &PassPolicy) -> (bool, String) {
    // Collect only Enforce-mode results.
    let enforce_results: Vec<&AssertionResult> = results
        .iter()
        .filter(|r| r.mode == AssertionMode::Enforce && r.passed.is_some())
        .collect();

    if enforce_results.is_empty() {
        return (true, String::new());
    }

    match policy.strategy {
        PassStrategy::All => {
            let failures: Vec<&AssertionResult> = enforce_results
                .iter()
                .filter(|r| r.is_blocking_failure())
                .copied()
                .collect();
            if failures.is_empty() {
                (true, String::new())
            } else {
                let codes: Vec<String> = failures.iter().map(|r| r.reason_code.clone()).collect();
                (false, codes.join(","))
            }
        }
        PassStrategy::Quorum => {
            let total = enforce_results.len() as f64;
            let passed_count = enforce_results
                .iter()
                .filter(|r| r.passed == Some(true))
                .count() as f64;
            let ratio = passed_count / total;
            if ratio >= policy.quorum {
                (true, String::new())
            } else {
                (
                    false,
                    format!(
                        "quality.pass_policy.quorum_not_met (ratio={ratio:.2}, required={:.2})",
                        policy.quorum
                    ),
                )
            }
        }
        PassStrategy::WeightedAverage => {
            let total_weight: f64 = enforce_results.iter().map(|r| r.weight).sum();
            if total_weight == 0.0 {
                return (true, String::new());
            }
            let weighted_sum: f64 = enforce_results
                .iter()
                .map(|r| r.weight * r.score.unwrap_or(0.0))
                .sum();
            let avg = weighted_sum / total_weight;
            if avg >= policy.threshold {
                (true, String::new())
            } else {
                (
                    false,
                    format!(
                        "quality.pass_policy.weighted_average_below_threshold (avg={avg:.3}, required={:.3})",
                        policy.threshold
                    ),
                )
            }
        }
    }
}

// ── Assertion pack resolution (Phase 13) ──────────────────────────────────────

/// An `AssertionPack` is a named list of assertion specs that can be referenced
/// from within the `assertions` array via `{ pack: "<name>" }`.
pub type AssertionPacks = std::collections::HashMap<String, Vec<AssertionSpec>>;

/// Parse the `assertion_packs` block from a quality-scorer policy config.
///
/// Expected shape:
/// ```yaml
/// assertion_packs:
/// baseline:
/// - type: contains
/// config: { value: "ok" }
/// strict:
/// - type: moderation
/// ```
pub fn parse_assertion_packs(policy_cfg: &Value) -> AssertionPacks {
    let mut packs = AssertionPacks::new();
    let Some(obj) = policy_cfg
        .get("assertion_packs")
        .and_then(|v| v.as_object())
    else {
        return packs;
    };
    for (name, list) in obj {
        if let Some(arr) = list.as_array() {
            let specs: Vec<AssertionSpec> = arr.iter().map(AssertionSpec::from_json).collect();
            packs.insert(name.clone(), specs);
        }
    }
    packs
}

/// Resolve the `assertions` array from a policy config, inlining any
/// `{ pack: "<name>" }` references. Per, packs cannot reference
/// other packs (single-level only).
pub fn resolve_assertions(policy_cfg: &Value, packs: &AssertionPacks) -> Vec<AssertionSpec> {
    let Some(arr) = policy_cfg.get("assertions").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut resolved = Vec::new();
    for item in arr {
        if let Some(pack_name) = item.get("pack").and_then(|v| v.as_str()) {
            if let Some(pack_specs) = packs.get(pack_name) {
                resolved.extend(pack_specs.iter().cloned());
            } else {
                tracing::warn!(%pack_name, "assertion_packs: unknown pack referenced");
            }
        } else {
            resolved.push(AssertionSpec::from_json(item));
        }
    }
    resolved
}

// ── Helpers ────────────────────────────────────────────────────────────────────

pub fn assertion_key(label: &str) -> String {
    label.replace(['-', ' '], "_")
}

// ── Unit tests ────────────────────────────────────────────────────────────────

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
    use std::collections::BTreeMap;

    // ── AssertionType ────────────────────────────────────────────────────

    #[test]
    fn assertion_type_from_str_known_types() {
        assert_eq!(AssertionType::from_str("contains"), AssertionType::Contains);
        assert_eq!(AssertionType::from_str("similar"), AssertionType::Similar);
        assert_eq!(
            AssertionType::from_str("llm-rubric"),
            AssertionType::LlmRubric
        );
        assert_eq!(
            AssertionType::from_str("search-rubric"),
            AssertionType::SearchRubric
        );
        assert_eq!(
            AssertionType::from_str("select-best"),
            AssertionType::SelectBest
        );
        assert_eq!(AssertionType::from_str("g-eval"), AssertionType::GEval);
        assert_eq!(
            AssertionType::from_str("answer-relevance"),
            AssertionType::AnswerRelevance
        );
        assert_eq!(
            AssertionType::from_str("factuality"),
            AssertionType::Factuality
        );
        assert_eq!(
            AssertionType::from_str("model-graded-factuality"),
            AssertionType::Factuality
        );
        assert_eq!(
            AssertionType::from_str("model-graded-closedqa"),
            AssertionType::ModelGradedClosedQA
        );
        assert_eq!(AssertionType::from_str("rouge"), AssertionType::Rouge);
        assert_eq!(AssertionType::from_str("meteor"), AssertionType::Meteor);
        assert_eq!(AssertionType::from_str("gleu"), AssertionType::Gleu);
        assert_eq!(
            AssertionType::from_str("semantic-similarity"),
            AssertionType::SemanticSimilarity
        );
        assert_eq!(
            AssertionType::from_str("perplexity"),
            AssertionType::Perplexity
        );
        assert_eq!(
            AssertionType::from_str("perplexity-score"),
            AssertionType::Perplexity
        );
        assert_eq!(
            AssertionType::from_str("javascript"),
            AssertionType::Javascript
        );
        assert_eq!(AssertionType::from_str("python"), AssertionType::Python);
        assert_eq!(AssertionType::from_str("cost"), AssertionType::Cost);
        assert_eq!(
            AssertionType::from_str("moderation"),
            AssertionType::Moderation
        );
        assert_eq!(
            AssertionType::from_str("context-faithfulness"),
            AssertionType::ContextFaithfulness
        );
        assert_eq!(
            AssertionType::from_str("conversation-relevance"),
            AssertionType::ConversationRelevance
        );
        assert_eq!(
            AssertionType::from_str("is-refusal"),
            AssertionType::IsRefusal
        );
        assert_eq!(
            AssertionType::from_str("trajectory:goal-success"),
            AssertionType::TrajectoryGoalSuccess
        );
        assert_eq!(
            AssertionType::from_str("trajectory:tool-used"),
            AssertionType::TrajectoryToolUsed
        );
        assert_eq!(
            AssertionType::from_str("trajectory:tool-sequence"),
            AssertionType::TrajectoryToolSequence
        );
        assert_eq!(
            AssertionType::from_str("trajectory:step-count"),
            AssertionType::TrajectoryStepCount
        );
        assert_eq!(
            AssertionType::from_str("context-recall"),
            AssertionType::ContextRecall
        );
        assert_eq!(
            AssertionType::from_str("context-relevance"),
            AssertionType::ContextRelevance
        );
        assert_eq!(
            AssertionType::from_str("rag-document-exfiltration"),
            AssertionType::RagDocumentExfiltration
        );
        assert_eq!(
            AssertionType::from_str("rag-poisoning"),
            AssertionType::RagPoisoning
        );
        assert_eq!(
            AssertionType::from_str("rag-source-attribution"),
            AssertionType::RagSourceAttribution
        );
        assert_eq!(
            AssertionType::from_str("threshold"),
            AssertionType::Threshold
        );
        assert_eq!(
            AssertionType::from_str("schema-match"),
            AssertionType::SchemaMatch
        );
        assert_eq!(AssertionType::from_str("regex"), AssertionType::Regex);
        assert_eq!(
            AssertionType::from_str("json-path"),
            AssertionType::JsonPath
        );
    }

    #[test]
    fn assertion_type_unknown_becomes_other() {
        assert_eq!(
            AssertionType::from_str("custom-checker"),
            AssertionType::Other("custom-checker".to_string())
        );
    }

    #[test]
    fn assertion_type_as_str_roundtrip() {
        let cases = [
            "contains",
            "similar",
            "llm-rubric",
            "g-eval",
            "rouge",
            "meteor",
            "gleu",
            "moderation",
            "threshold",
            "regex",
            "json-path",
        ];
        for case in cases {
            assert_eq!(
                AssertionType::from_str(case).as_str(),
                case,
                "roundtrip failed for {case}"
            );
        }
    }

    #[test]
    fn assertion_type_other_preserves_original_string() {
        let t = AssertionType::from_str("my-custom-type");
        assert_eq!(t.as_str(), "my-custom-type");
    }

    // ── AssertionMode ────────────────────────────────────────────────────

    #[test]
    fn assertion_mode_from_json_variants() {
        assert_eq!(
            AssertionMode::from_json(&json!("enforce")),
            AssertionMode::Enforce
        );
        assert_eq!(
            AssertionMode::from_json(&json!("audit")),
            AssertionMode::Audit
        );
        assert_eq!(
            AssertionMode::from_json(&json!("shadow")),
            AssertionMode::Shadow
        );
        assert_eq!(
            AssertionMode::from_json(&json!("unknown")),
            AssertionMode::Enforce
        );
        assert_eq!(
            AssertionMode::from_json(&json!(null)),
            AssertionMode::Enforce
        );
        assert_eq!(AssertionMode::from_json(&json!(42)), AssertionMode::Enforce);
    }

    #[test]
    fn assertion_mode_default_is_enforce() {
        assert_eq!(AssertionMode::default(), AssertionMode::Enforce);
    }

    // ── AssertionSeverity ────────────────────────────────────────────────

    #[test]
    fn assertion_severity_from_json_variants() {
        assert_eq!(
            AssertionSeverity::from_json(&json!("critical")),
            AssertionSeverity::Critical
        );
        assert_eq!(
            AssertionSeverity::from_json(&json!("warning")),
            AssertionSeverity::Warning
        );
        assert_eq!(
            AssertionSeverity::from_json(&json!("info")),
            AssertionSeverity::Info
        );
        assert_eq!(
            AssertionSeverity::from_json(&json!("unknown")),
            AssertionSeverity::Critical
        );
        assert_eq!(
            AssertionSeverity::from_json(&json!(null)),
            AssertionSeverity::Critical
        );
    }

    #[test]
    fn assertion_severity_default_is_critical() {
        assert_eq!(AssertionSeverity::default(), AssertionSeverity::Critical);
    }

    // ── AssertionSpec::from_json ──────────────────────────────────────────

    #[test]
    fn assertion_spec_from_json_minimal() {
        let spec = AssertionSpec::from_json(&json!({}));
        assert_eq!(
            spec.assertion_type,
            AssertionType::Other("unknown".to_string())
        );
        assert!(spec.name.is_none());
        assert!(spec.value.is_none());
        assert!(spec.threshold.is_none());
        assert!((spec.weight - 1.0).abs() < 1e-9);
        assert!(!spec.negate);
        assert!(spec.case_sensitive);
        assert!(spec.enabled);
        assert_eq!(spec.mode, AssertionMode::Enforce);
        assert_eq!(spec.severity, AssertionSeverity::Critical);
        assert!(spec.pack.is_none());
    }

    #[test]
    fn assertion_spec_from_json_full() {
        let spec = AssertionSpec::from_json(&json!({
            "type": "contains",
            "name": "check-greeting",
            "value": "hello",
            "threshold": 0.8,
            "weight": 2.5,
            "provider": "openai",
            "metric": "bleu",
            "negate": true,
            "case_sensitive": false,
            "enabled": false,
            "mode": "audit",
            "severity": "warning",
            "pack": "baseline",
            "config": { "extra": true },
        }));
        assert_eq!(spec.assertion_type, AssertionType::Contains);
        assert_eq!(spec.name.as_deref(), Some("check-greeting"));
        assert_eq!(spec.value.as_deref(), Some("hello"));
        assert!((spec.threshold.unwrap() - 0.8).abs() < 1e-9);
        assert!((spec.weight - 2.5).abs() < 1e-9);
        assert_eq!(spec.provider.as_deref(), Some("openai"));
        assert_eq!(spec.metric.as_deref(), Some("bleu"));
        assert!(spec.negate);
        assert!(!spec.case_sensitive);
        assert!(!spec.enabled);
        assert_eq!(spec.mode, AssertionMode::Audit);
        assert_eq!(spec.severity, AssertionSeverity::Warning);
        assert_eq!(spec.pack.as_deref(), Some("baseline"));
    }

    #[test]
    fn assertion_spec_value_falls_back_to_config() {
        let spec = AssertionSpec::from_json(&json!({
            "type": "contains",
            "config": { "value": "from-config" },
        }));
        assert_eq!(spec.value.as_deref(), Some("from-config"));
    }

    #[test]
    fn assertion_spec_metric_falls_back_to_config() {
        let spec = AssertionSpec::from_json(&json!({
            "type": "threshold",
            "config": { "metric": "bleu" },
        }));
        assert_eq!(spec.metric.as_deref(), Some("bleu"));
    }

    #[test]
    fn assertion_spec_weight_clamps_to_range() {
        let over = AssertionSpec::from_json(&json!({ "weight": 50.0 }));
        assert!((over.weight - 10.0).abs() < 1e-9);

        let under = AssertionSpec::from_json(&json!({ "weight": -5.0 }));
        assert!(under.weight.abs() < 1e-9);
    }

    #[test]
    fn assertion_spec_negate_from_config_block() {
        let spec = AssertionSpec::from_json(&json!({
            "type": "contains",
            "config": { "negate": true },
        }));
        assert!(spec.negate);
    }

    // ── AssertionResult::is_blocking_failure ──────────────────────────────

    fn result_fixture(
        passed: Option<bool>,
        mode: AssertionMode,
        severity: AssertionSeverity,
    ) -> AssertionResult {
        AssertionResult {
            assertion_type: "test".to_string(),
            name: None,
            score: Some(0.0),
            threshold: Some(1.0),
            weight: 1.0,
            passed,
            reason_code: "test".to_string(),
            details: json!({}),
            mode,
            severity,
        }
    }

    #[test]
    fn is_blocking_failure_true_for_enforce_critical_failed() {
        let r = result_fixture(
            Some(false),
            AssertionMode::Enforce,
            AssertionSeverity::Critical,
        );
        assert!(r.is_blocking_failure());
    }

    #[test]
    fn is_blocking_failure_false_for_passed() {
        let r = result_fixture(
            Some(true),
            AssertionMode::Enforce,
            AssertionSeverity::Critical,
        );
        assert!(!r.is_blocking_failure());
    }

    #[test]
    fn is_blocking_failure_false_for_audit_mode() {
        let r = result_fixture(
            Some(false),
            AssertionMode::Audit,
            AssertionSeverity::Critical,
        );
        assert!(!r.is_blocking_failure());
    }

    #[test]
    fn is_blocking_failure_false_for_shadow_mode() {
        let r = result_fixture(
            Some(false),
            AssertionMode::Shadow,
            AssertionSeverity::Critical,
        );
        assert!(!r.is_blocking_failure());
    }

    #[test]
    fn is_blocking_failure_false_for_warning_severity() {
        let r = result_fixture(
            Some(false),
            AssertionMode::Enforce,
            AssertionSeverity::Warning,
        );
        assert!(!r.is_blocking_failure());
    }

    #[test]
    fn is_blocking_failure_false_for_info_severity() {
        let r = result_fixture(Some(false), AssertionMode::Enforce, AssertionSeverity::Info);
        assert!(!r.is_blocking_failure());
    }

    #[test]
    fn is_blocking_failure_false_when_passed_is_none() {
        let r = result_fixture(None, AssertionMode::Enforce, AssertionSeverity::Critical);
        assert!(!r.is_blocking_failure());
    }

    // ── AssertionResult::is_visible ──────────────────────────────────────

    #[test]
    fn is_visible_true_for_enforce() {
        let r = result_fixture(
            Some(true),
            AssertionMode::Enforce,
            AssertionSeverity::Critical,
        );
        assert!(r.is_visible());
    }

    #[test]
    fn is_visible_true_for_audit() {
        let r = result_fixture(
            Some(true),
            AssertionMode::Audit,
            AssertionSeverity::Critical,
        );
        assert!(r.is_visible());
    }

    #[test]
    fn is_visible_false_for_shadow() {
        let r = result_fixture(
            Some(true),
            AssertionMode::Shadow,
            AssertionSeverity::Critical,
        );
        assert!(!r.is_visible());
    }

    // ── eval_contains ────────────────────────────────────────────────────

    fn contains_spec(value: &str, negate: bool, case_sensitive: bool) -> AssertionSpec {
        AssertionSpec::from_json(&json!({
            "type": "contains",
            "value": value,
            "negate": negate,
            "case_sensitive": case_sensitive,
        }))
    }

    #[test]
    fn eval_contains_case_sensitive_found() {
        let r = eval_contains("Hello World", &contains_spec("World", false, true));
        assert_eq!(r.passed, Some(true));
        assert!((r.score.unwrap() - 1.0).abs() < 1e-9);
        assert_eq!(r.reason_code, "ok");
    }

    #[test]
    fn eval_contains_case_sensitive_not_found() {
        let r = eval_contains("Hello World", &contains_spec("world", false, true));
        assert_eq!(r.passed, Some(false));
        assert!(r.score.unwrap().abs() < 1e-9);
    }

    #[test]
    fn eval_contains_case_insensitive_found() {
        let r = eval_contains("Hello World", &contains_spec("world", false, false));
        assert_eq!(r.passed, Some(true));
    }

    #[test]
    fn eval_contains_negate_inverts_result() {
        let r = eval_contains("Hello World", &contains_spec("World", true, true));
        assert_eq!(r.passed, Some(false));

        let r2 = eval_contains("Hello World", &contains_spec("missing", true, true));
        assert_eq!(r2.passed, Some(true));
    }

    #[test]
    fn eval_contains_empty_value_always_found() {
        let r = eval_contains("any output", &contains_spec("", false, true));
        assert_eq!(r.passed, Some(true));
    }

    // ── eval_threshold ───────────────────────────────────────────────────

    #[test]
    fn eval_threshold_passes_when_above_min() {
        let mut scores = BTreeMap::new();
        scores.insert("bleu".to_string(), 0.8);
        let spec = AssertionSpec::from_json(&json!({
            "type": "threshold",
            "metric": "bleu",
            "threshold": 0.5,
        }));
        let r = eval_threshold(&scores, &spec);
        assert_eq!(r.passed, Some(true));
    }

    #[test]
    fn eval_threshold_fails_when_below_min() {
        let mut scores = BTreeMap::new();
        scores.insert("bleu".to_string(), 0.3);
        let spec = AssertionSpec::from_json(&json!({
            "type": "threshold",
            "metric": "bleu",
            "threshold": 0.5,
        }));
        let r = eval_threshold(&scores, &spec);
        assert_eq!(r.passed, Some(false));
        assert!(r.reason_code.contains("threshold_failed"));
    }

    #[test]
    fn eval_threshold_fails_when_metric_missing() {
        let scores = BTreeMap::new();
        let spec = AssertionSpec::from_json(&json!({
            "type": "threshold",
            "metric": "nonexistent",
            "threshold": 0.5,
        }));
        let r = eval_threshold(&scores, &spec);
        assert_eq!(r.passed, Some(false));
        assert!(r.score.is_none());
    }

    #[test]
    fn eval_threshold_checks_max_bound() {
        let mut scores = BTreeMap::new();
        scores.insert("cost".to_string(), 0.9);
        let spec = AssertionSpec::from_json(&json!({
            "type": "threshold",
            "metric": "cost",
            "threshold": 0.1,
            "config": { "max": 0.8 },
        }));
        let r = eval_threshold(&scores, &spec);
        assert_eq!(r.passed, Some(false));
    }

    #[test]
    fn eval_threshold_passes_within_min_max_range() {
        let mut scores = BTreeMap::new();
        scores.insert("cost".to_string(), 0.5);
        let spec = AssertionSpec::from_json(&json!({
            "type": "threshold",
            "metric": "cost",
            "threshold": 0.1,
            "config": { "max": 0.8 },
        }));
        let r = eval_threshold(&scores, &spec);
        assert_eq!(r.passed, Some(true));
    }

    // ── eval_moderation ──────────────────────────────────────────────────

    #[test]
    fn eval_moderation_clean_output_passes() {
        let spec = AssertionSpec::from_json(&json!({ "type": "moderation" }));
        let r = eval_moderation("The weather is nice today.", &spec);
        assert_eq!(r.passed, Some(true));
        assert!((r.score.unwrap() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn eval_moderation_flags_builtin_categories() {
        let spec = AssertionSpec::from_json(&json!({ "type": "moderation" }));
        let r = eval_moderation("This contains hate speech.", &spec);
        assert_eq!(r.passed, Some(false));
        assert!(r.score.unwrap().abs() < 1e-9);
    }

    #[test]
    fn eval_moderation_uses_custom_categories() {
        let spec = AssertionSpec::from_json(&json!({
            "type": "moderation",
            "config": { "categories": ["spam", "phishing"] },
        }));
        let r = eval_moderation("This is a phishing attempt.", &spec);
        assert_eq!(r.passed, Some(false));

        let r2 = eval_moderation("Clean output", &spec);
        assert_eq!(r2.passed, Some(true));
    }

    #[test]
    fn eval_moderation_handles_underscore_variants() {
        let spec = AssertionSpec::from_json(&json!({ "type": "moderation" }));
        let r = eval_moderation("self_harm content", &spec);
        assert_eq!(r.passed, Some(false));
    }

    // ── assertion_key ────────────────────────────────────────────────────

    #[test]
    fn assertion_key_replaces_dashes_and_spaces() {
        assert_eq!(
            assertion_key("context-faithfulness"),
            "context_faithfulness"
        );
        assert_eq!(assertion_key("some assertion"), "some_assertion");
        assert_eq!(assertion_key("no-change-needed"), "no_change_needed");
        assert_eq!(assertion_key("clean"), "clean");
    }

    // ── PassPolicy ───────────────────────────────────────────────────────

    #[test]
    fn pass_policy_default_is_all_strategy() {
        let policy = PassPolicy::default();
        assert_eq!(policy.strategy, PassStrategy::All);
        assert!((policy.quorum - 0.5).abs() < 1e-9);
        assert!((policy.threshold - 0.5).abs() < 1e-9);
    }

    #[test]
    fn pass_policy_from_json_all() {
        let policy = PassPolicy::from_json(&json!({ "strategy": "all" }));
        assert_eq!(policy.strategy, PassStrategy::All);
    }

    #[test]
    fn pass_policy_from_json_quorum() {
        let policy = PassPolicy::from_json(&json!({
            "strategy": "quorum",
            "quorum": 0.75,
        }));
        assert_eq!(policy.strategy, PassStrategy::Quorum);
        assert!((policy.quorum - 0.75).abs() < 1e-9);
    }

    #[test]
    fn pass_policy_from_json_weighted_average() {
        let policy = PassPolicy::from_json(&json!({
            "strategy": "weighted_average",
            "threshold": 0.8,
        }));
        assert_eq!(policy.strategy, PassStrategy::WeightedAverage);
        assert!((policy.threshold - 0.8).abs() < 1e-9);
    }

    #[test]
    fn pass_policy_from_json_clamps_quorum() {
        let policy = PassPolicy::from_json(&json!({
            "strategy": "quorum",
            "quorum": 2.0,
        }));
        assert!((policy.quorum - 1.0).abs() < 1e-9);
    }

    // ── evaluate_pass_policy ─────────────────────────────────────────────

    #[test]
    fn evaluate_pass_policy_all_passes_when_all_pass() {
        let results = vec![
            result_fixture(
                Some(true),
                AssertionMode::Enforce,
                AssertionSeverity::Critical,
            ),
            result_fixture(
                Some(true),
                AssertionMode::Enforce,
                AssertionSeverity::Critical,
            ),
        ];
        let (passed, reason) = evaluate_pass_policy(&results, &PassPolicy::default());
        assert!(passed);
        assert!(reason.is_empty());
    }

    #[test]
    fn evaluate_pass_policy_all_fails_on_blocking_failure() {
        let results = vec![
            result_fixture(
                Some(true),
                AssertionMode::Enforce,
                AssertionSeverity::Critical,
            ),
            result_fixture(
                Some(false),
                AssertionMode::Enforce,
                AssertionSeverity::Critical,
            ),
        ];
        let (passed, reason) = evaluate_pass_policy(&results, &PassPolicy::default());
        assert!(!passed);
        assert!(!reason.is_empty());
    }

    #[test]
    fn evaluate_pass_policy_all_ignores_audit_failures() {
        let results = vec![
            result_fixture(
                Some(true),
                AssertionMode::Enforce,
                AssertionSeverity::Critical,
            ),
            result_fixture(
                Some(false),
                AssertionMode::Audit,
                AssertionSeverity::Critical,
            ),
        ];
        let (passed, _) = evaluate_pass_policy(&results, &PassPolicy::default());
        assert!(passed);
    }

    #[test]
    fn evaluate_pass_policy_all_ignores_warning_severity() {
        let results = vec![result_fixture(
            Some(false),
            AssertionMode::Enforce,
            AssertionSeverity::Warning,
        )];
        let (passed, _) = evaluate_pass_policy(&results, &PassPolicy::default());
        assert!(passed);
    }

    #[test]
    fn evaluate_pass_policy_empty_results_pass() {
        let (passed, _) = evaluate_pass_policy(&[], &PassPolicy::default());
        assert!(passed);
    }

    #[test]
    fn evaluate_pass_policy_quorum_passes_when_met() {
        let results = vec![
            result_fixture(
                Some(true),
                AssertionMode::Enforce,
                AssertionSeverity::Critical,
            ),
            result_fixture(
                Some(true),
                AssertionMode::Enforce,
                AssertionSeverity::Critical,
            ),
            result_fixture(
                Some(false),
                AssertionMode::Enforce,
                AssertionSeverity::Critical,
            ),
        ];
        let policy = PassPolicy {
            strategy: PassStrategy::Quorum,
            quorum: 0.6,
            threshold: 0.5,
        };
        let (passed, _) = evaluate_pass_policy(&results, &policy);
        assert!(passed);
    }

    #[test]
    fn evaluate_pass_policy_quorum_fails_when_not_met() {
        let results = vec![
            result_fixture(
                Some(true),
                AssertionMode::Enforce,
                AssertionSeverity::Critical,
            ),
            result_fixture(
                Some(false),
                AssertionMode::Enforce,
                AssertionSeverity::Critical,
            ),
            result_fixture(
                Some(false),
                AssertionMode::Enforce,
                AssertionSeverity::Critical,
            ),
        ];
        let policy = PassPolicy {
            strategy: PassStrategy::Quorum,
            quorum: 0.5,
            threshold: 0.5,
        };
        let (passed, reason) = evaluate_pass_policy(&results, &policy);
        assert!(!passed);
        assert!(reason.contains("quorum_not_met"));
    }

    #[test]
    fn evaluate_pass_policy_weighted_avg_passes() {
        let mut r1 = result_fixture(
            Some(true),
            AssertionMode::Enforce,
            AssertionSeverity::Critical,
        );
        r1.score = Some(0.9);
        r1.weight = 2.0;
        let mut r2 = result_fixture(
            Some(false),
            AssertionMode::Enforce,
            AssertionSeverity::Critical,
        );
        r2.score = Some(0.3);
        r2.weight = 1.0;
        let results = vec![r1, r2];
        let policy = PassPolicy {
            strategy: PassStrategy::WeightedAverage,
            quorum: 0.5,
            threshold: 0.5,
        };
        let (passed, _) = evaluate_pass_policy(&results, &policy);
        assert!(passed);
    }

    #[test]
    fn evaluate_pass_policy_weighted_avg_fails() {
        let mut r1 = result_fixture(
            Some(false),
            AssertionMode::Enforce,
            AssertionSeverity::Critical,
        );
        r1.score = Some(0.1);
        r1.weight = 1.0;
        let mut r2 = result_fixture(
            Some(false),
            AssertionMode::Enforce,
            AssertionSeverity::Critical,
        );
        r2.score = Some(0.2);
        r2.weight = 1.0;
        let results = vec![r1, r2];
        let policy = PassPolicy {
            strategy: PassStrategy::WeightedAverage,
            quorum: 0.5,
            threshold: 0.5,
        };
        let (passed, reason) = evaluate_pass_policy(&results, &policy);
        assert!(!passed);
        assert!(reason.contains("weighted_average_below_threshold"));
    }

    #[test]
    fn evaluate_pass_policy_weighted_avg_zero_weight_passes() {
        let mut r1 = result_fixture(
            Some(false),
            AssertionMode::Enforce,
            AssertionSeverity::Critical,
        );
        r1.weight = 0.0;
        let results = vec![r1];
        let policy = PassPolicy {
            strategy: PassStrategy::WeightedAverage,
            quorum: 0.5,
            threshold: 0.5,
        };
        let (passed, _) = evaluate_pass_policy(&results, &policy);
        assert!(passed);
    }

    // ── parse_assertion_packs ────────────────────────────────────────────

    #[test]
    fn parse_assertion_packs_empty_config() {
        let packs = parse_assertion_packs(&json!({}));
        assert!(packs.is_empty());
    }

    #[test]
    fn parse_assertion_packs_with_entries() {
        let cfg = json!({
            "assertion_packs": {
                "baseline": [
                    { "type": "contains", "value": "ok" },
                    { "type": "moderation" },
                ],
                "strict": [
                    { "type": "threshold", "metric": "bleu", "threshold": 0.9 },
                ],
            }
        });
        let packs = parse_assertion_packs(&cfg);
        assert_eq!(packs.len(), 2);
        assert_eq!(packs["baseline"].len(), 2);
        assert_eq!(packs["baseline"][0].assertion_type, AssertionType::Contains);
        assert_eq!(packs["strict"].len(), 1);
        assert_eq!(packs["strict"][0].assertion_type, AssertionType::Threshold);
    }

    // ── resolve_assertions ───────────────────────────────────────────────

    #[test]
    fn resolve_assertions_inlines_packs() {
        let packs = {
            let mut p = AssertionPacks::new();
            p.insert(
                "base".to_string(),
                vec![
                    AssertionSpec::from_json(&json!({ "type": "contains", "value": "yes" })),
                    AssertionSpec::from_json(&json!({ "type": "moderation" })),
                ],
            );
            p
        };
        let cfg = json!({
            "assertions": [
                { "pack": "base" },
                { "type": "threshold", "metric": "bleu" },
            ]
        });
        let resolved = resolve_assertions(&cfg, &packs);
        assert_eq!(resolved.len(), 3);
        assert_eq!(resolved[0].assertion_type, AssertionType::Contains);
        assert_eq!(resolved[1].assertion_type, AssertionType::Moderation);
        assert_eq!(resolved[2].assertion_type, AssertionType::Threshold);
    }

    #[test]
    fn resolve_assertions_skips_unknown_pack() {
        let packs = AssertionPacks::new();
        let cfg = json!({
            "assertions": [
                { "pack": "nonexistent" },
                { "type": "contains", "value": "ok" },
            ]
        });
        let resolved = resolve_assertions(&cfg, &packs);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].assertion_type, AssertionType::Contains);
    }

    #[test]
    fn resolve_assertions_empty_when_no_assertions_key() {
        let packs = AssertionPacks::new();
        let resolved = resolve_assertions(&json!({}), &packs);
        assert!(resolved.is_empty());
    }

    // ── AssertionType serde ──────────────────────────────────────────────

    #[test]
    fn assertion_type_serde_roundtrip() {
        let original = AssertionType::Contains;
        let json = serde_json::to_string(&original).unwrap();
        let recovered: AssertionType = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn assertion_mode_serde_roundtrip() {
        for mode in [
            AssertionMode::Enforce,
            AssertionMode::Audit,
            AssertionMode::Shadow,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let recovered: AssertionMode = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, mode);
        }
    }

    #[test]
    fn assertion_severity_serde_roundtrip() {
        for sev in [
            AssertionSeverity::Critical,
            AssertionSeverity::Warning,
            AssertionSeverity::Info,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let recovered: AssertionSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, sev);
        }
    }

    #[test]
    fn pass_strategy_serde_roundtrip() {
        for strategy in [
            PassStrategy::All,
            PassStrategy::Quorum,
            PassStrategy::WeightedAverage,
        ] {
            let json = serde_json::to_string(&strategy).unwrap();
            let recovered: PassStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, strategy);
        }
    }

    /// Unit-test entrypoint for credential-store coverage.
    ///
    /// Table-driven replacement for `cli/tests/policy_test_assertions_e2e.rs` covering
    /// inline testing-section assertion evaluation without invoking the `verdictan policy test`
    /// binary.
    #[tokio::test]
    async fn policy_test_assertions_matrix() {
        let disclaimer_output =
            "Disclaimer: The policy requires a disclaimer and cites the source material.";
        let disclaimer_context = "The policy requires a disclaimer and cites the source material.";
        let disclaimer_request = json!({
            "model": "gpt-5.4-mini",
            "messages": [{ "role": "user", "content": "What is the policy?" }],
            "verdictan": {
                "context_documents": [{ "content": disclaimer_context }],
            },
        });
        let disclaimer_upstream = json!({
            "choices": [{ "message": { "content": disclaimer_output } }],
        });
        let inline_assertions = vec![
            AssertionSpec::from_json(&json!({ "type": "contains", "value": "Disclaimer" })),
            AssertionSpec::from_json(&json!({ "type": "moderation" })),
            AssertionSpec::from_json(&json!({ "type": "context-faithfulness" })),
            AssertionSpec::from_json(&json!({
                "type": "g-eval",
                "threshold": 0.2,
                "config": { "criteria": "disclaimer and source fidelity" },
            })),
            AssertionSpec::from_json(&json!({
                "type": "rouge",
                "config": { "reference": disclaimer_context },
            })),
        ];
        let inline_ctx = AssertionContext {
            output_text: disclaimer_output,
            query_text: "What is the policy?",
            context_text: disclaimer_context,
            request_json: &disclaimer_request,
            upstream_json: &disclaimer_upstream,
            quality_scores: &BTreeMap::new(),
            provider_registry: None,
        };
        let inline_results = evaluate_assertions(&inline_assertions, &inline_ctx).await;
        let inline_types = inline_results
            .iter()
            .map(|result| result.assertion_type.as_str())
            .collect::<Vec<_>>();
        for expected in [
            "contains",
            "moderation",
            "context-faithfulness",
            "g-eval",
            "rouge",
        ] {
            assert!(
                inline_types.contains(&expected),
                "inline matrix missing assertion type {expected}"
            );
        }
        assert!(
            inline_results
                .iter()
                .all(|result| result.passed.unwrap_or(false)),
            "inline matrix assertions should pass: {inline_results:?}"
        );

        let refusal_output =
            "I'm sorry, but I can't assist with executing that refund workflow directly.";
        let refusal_request = json!({
            "messages": [
                { "role": "user", "content": "How do I process a refund?" },
                { "role": "assistant", "content": "I can help with that." },
                { "role": "user", "content": "Summarize the refund workflow." },
            ],
            "verdictan": {
                "trajectory": [
                    { "type": "tool", "tool": "lookup_order", "result": "Order found" },
                    { "type": "tool", "tool": "issue_refund", "result": "Refund complete" },
                ],
            },
        });
        let refusal_upstream = json!({
            "choices": [{
                "finish_reason": "content_filter",
                "message": { "content": refusal_output },
            }],
        });
        let advanced_assertions = vec![
            AssertionSpec::from_json(&json!({
                "type": "conversation-relevance",
                "threshold": 0.1,
            })),
            AssertionSpec::from_json(&json!({ "type": "is-refusal" })),
            AssertionSpec::from_json(&json!({
                "type": "trajectory:tool-used",
                "config": { "tools": ["lookup_order"] },
            })),
            AssertionSpec::from_json(&json!({
                "type": "trajectory:tool-sequence",
                "config": { "tools": ["lookup_order", "issue_refund"] },
            })),
            AssertionSpec::from_json(&json!({
                "type": "trajectory:step-count",
                "config": { "min": 2, "max": 3 },
            })),
        ];
        let advanced_ctx = AssertionContext {
            output_text: refusal_output,
            query_text: "Summarize the refund workflow.",
            context_text: "",
            request_json: &refusal_request,
            upstream_json: &refusal_upstream,
            quality_scores: &BTreeMap::new(),
            provider_registry: None,
        };
        let advanced_results = evaluate_assertions(&advanced_assertions, &advanced_ctx).await;
        let advanced_types = advanced_results
            .iter()
            .map(|result| result.assertion_type.as_str())
            .collect::<Vec<_>>();
        for expected in [
            "conversation-relevance",
            "is-refusal",
            "trajectory:tool-used",
            "trajectory:tool-sequence",
            "trajectory:step-count",
        ] {
            assert!(
                advanced_types.contains(&expected),
                "advanced matrix missing assertion type {expected}"
            );
        }
        assert!(
            advanced_results
                .iter()
                .all(|result| result.passed.unwrap_or(false)),
            "advanced matrix assertions should pass: {advanced_results:?}"
        );

        let pass_case = eval_contains(
            "Disclaimer: follow the policy.",
            &AssertionSpec::from_json(&json!({
                "type": "contains",
                "value": "Disclaimer",
            })),
        );
        let fail_case = eval_contains(
            "No notice was provided.",
            &AssertionSpec::from_json(&json!({
                "type": "contains",
                "value": "Disclaimer",
            })),
        );
        assert_eq!(pass_case.passed, Some(true));
        assert_eq!(fail_case.passed, Some(false));
        assert_ne!(pass_case.reason_code, fail_case.reason_code);
    }
}
