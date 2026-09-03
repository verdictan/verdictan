// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::json;

use crate::gateway::providers::ProviderRegistry;
use crate::policy::assertions::{assertion_key, AssertionResult, AssertionSpec};

pub fn eval_rouge(output: &str, spec: &AssertionSpec) -> AssertionResult {
    let reference = reference_from_spec(spec);
    let variant = spec
        .config
        .get("variant")
        .and_then(|value| value.as_str())
        .unwrap_or("rouge-l");
    let case_sensitive = spec
        .config
        .get("case_sensitive")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let score = match variant {
        "rouge-1" => {
            crate::gateway::quality::pub_rouge_n_score(output, &reference, 1, case_sensitive)
        }
        "rouge-2" => {
            crate::gateway::quality::pub_rouge_n_score(output, &reference, 2, case_sensitive)
        }
        _ => crate::gateway::quality::pub_similarity_score(output, &reference),
    }
    .unwrap_or(0.0);
    result(
        spec,
        score,
        spec.threshold.unwrap_or(0.3),
        json!({
            "reference": reference,
            "variant": variant,
            "heuristic_backend": if variant == "rouge-l" { "similarity_score" } else { "rouge_n" },
        }),
    )
}

pub(crate) fn eval_meteor(output: &str, spec: &AssertionSpec) -> AssertionResult {
    let reference = reference_from_spec(spec);
    let similarity = crate::gateway::quality::pub_similarity_score(output, &reference);
    let rouge_1 = crate::gateway::quality::pub_rouge_n_score(output, &reference, 1, false);
    let score = weighted_average(&[(similarity, 0.6), (rouge_1, 0.4)]).unwrap_or(0.0);
    result(
        spec,
        score,
        spec.threshold.unwrap_or(0.3),
        json!({
            "reference": reference,
            "heuristic_backend": "similarity_plus_rouge1",
            "components": {
                "similarity": similarity,
                "rouge_1": rouge_1,
            }
        }),
    )
}

pub(crate) fn eval_gleu(output: &str, spec: &AssertionSpec) -> AssertionResult {
    let reference = reference_from_spec(spec);
    let bleu = crate::gateway::quality::pub_bleu_score(output, &reference);
    let similarity = crate::gateway::quality::pub_similarity_score(output, &reference);
    let score = weighted_average(&[(bleu, 0.7), (similarity, 0.3)]).unwrap_or(0.0);
    result(
        spec,
        score,
        spec.threshold.unwrap_or(0.2),
        json!({
            "reference": reference,
            "max_n": spec.config.get("max_n").and_then(|value| value.as_u64()).unwrap_or(4),
            "heuristic_backend": "bleu_plus_similarity",
            "components": {
                "bleu": bleu,
                "similarity": similarity,
            }
        }),
    )
}

pub fn eval_semantic_similarity(
    output: &str,
    spec: &AssertionSpec,
    provider_registry: Option<&ProviderRegistry>,
) -> AssertionResult {
    let reference = reference_from_spec(spec);

    if let Some(provider_id) = spec.provider.as_deref() {
        let remote_result = provider_registry
            .ok_or_else(|| {
                format!(
                    "provider '{}' requested but provider registry is unavailable",
                    provider_id
                )
            })
            .and_then(|registry| {
                crate::policy::embeddings::semantic_similarity_with_provider(
                    output,
                    &reference,
                    provider_id,
                    registry,
                )
            });

        match remote_result {
            Ok((score, details)) => {
                let enriched = match details {
                    serde_json::Value::Object(mut object) => {
                        object.insert("reference".to_string(), json!(reference));
                        serde_json::Value::Object(object)
                    }
                    _ => json!({
                        "reference": reference,
                        "provider": spec.provider,
                    }),
                };
                return result(spec, score, spec.threshold.unwrap_or(0.8), enriched);
            }
            Err(err) => {
                return result(
                    spec,
                    0.0,
                    spec.threshold.unwrap_or(0.8),
                    json!({
                        "reference": reference,
                        "provider": provider_id,
                        "error": err,
                        "fail_closed": true,
                    }),
                );
            }
        }
    }

    let score = crate::gateway::quality::pub_similarity_score(output, &reference).unwrap_or(0.0);
    result(
        spec,
        score,
        spec.threshold.unwrap_or(0.8),
        json!({
            "reference": reference,
            "heuristic_backend": "tfidf_cosine",
        }),
    )
}

pub fn eval_perplexity(output: &str, spec: &AssertionSpec) -> AssertionResult {
    let tokens: Vec<&str> = output.split_whitespace().collect();
    let token_count = tokens.len() as f64;
    let unique_count = tokens
        .iter()
        .map(|token| token.to_ascii_lowercase())
        .collect::<std::collections::BTreeSet<_>>()
        .len() as f64;
    let diversity = if token_count == 0.0 {
        0.0
    } else {
        unique_count / token_count
    };
    let repetition_penalty = if token_count > 0.0 {
        1.0 - diversity
    } else {
        1.0
    };
    let punctuation_bonus =
        if output.ends_with('.') || output.ends_with('!') || output.ends_with('?') {
            0.1
        } else {
            0.0
        };
    let score =
        (0.6 + (diversity * 0.3) - (repetition_penalty * 0.2) + punctuation_bonus).clamp(0.0, 1.0);
    result(
        spec,
        score,
        spec.threshold.unwrap_or(0.5),
        json!({
            "heuristic_backend": "lexical_diversity_proxy",
            "token_count": token_count,
            "unique_tokens": unique_count,
            "provider": spec.provider,
        }),
    )
}

fn result(
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

fn reference_from_spec(spec: &AssertionSpec) -> String {
    spec.config
        .get("reference")
        .and_then(|value| value.as_str())
        .or(spec.value.as_deref())
        .unwrap_or("")
        .to_string()
}

fn weighted_average(values: &[(Option<f64>, f64)]) -> Option<f64> {
    let mut total = 0.0;
    let mut weight_sum = 0.0;

    for (value, weight) in values {
        if let Some(value) = value {
            total += value * weight;
            weight_sum += weight;
        }
    }

    if weight_sum == 0.0 {
        None
    } else {
        Some((total / weight_sum).clamp(0.0, 1.0))
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
    use super::{eval_gleu, eval_meteor, weighted_average};
    use crate::policy::assertions::AssertionSpec;
    use serde_json::json;

    #[test]
    fn meteor_uses_similarity_and_rouge_components() {
        let spec = AssertionSpec::from_json(&json!({
            "type": "meteor",
            "threshold": 0.3,
            "config": {"reference": "billing payment guidance"}
        }));

        let result = eval_meteor("billing payment guidance", &spec);

        assert_eq!(result.passed, Some(true));
        assert_eq!(
            result.details["heuristic_backend"],
            "similarity_plus_rouge1"
        );
        assert!(result.details["components"]["similarity"].is_number());
        assert!(result.details["components"]["rouge_1"].is_number());
    }

    #[test]
    fn gleu_uses_bleu_and_similarity_components() {
        let spec = AssertionSpec::from_json(&json!({
            "type": "gleu",
            "threshold": 0.2,
            "config": {"reference": "employees receive 20 days of annual vacation"}
        }));

        let result = eval_gleu("employees receive 20 days of annual vacation", &spec);

        assert_eq!(result.passed, Some(true));
        assert_eq!(result.details["heuristic_backend"], "bleu_plus_similarity");
        assert!(result.details["components"]["bleu"].is_number());
        assert!(result.details["components"]["similarity"].is_number());
    }

    #[test]
    fn weighted_average_returns_none_without_present_values() {
        assert_eq!(weighted_average(&[(None, 0.6), (None, 0.4)]), None);
    }
}
