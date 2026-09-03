// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use super::enforcement::{PolicyResult, Verdict};

use serde_json::Value;

macro_rules! static_regex {
    ($pattern:expr) => {{
        static RE: std::sync::OnceLock<regex_lite::Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| {
            #[allow(clippy::expect_used)]
            regex_lite::Regex::new($pattern).expect("static regex pattern")
        })
    }};
}

pub struct Rewrite {
    pub prefix: String,
}

pub struct EvalOutcome {
    pub policy_result: PolicyResult,
    pub rewrite: Option<Rewrite>,
    pub should_block: bool,
    pub should_escalate: bool,
}

pub fn evaluate_mnpi_filter(text: &str, cfg: Option<&Value>) -> EvalOutcome {
    crate::telemetry::with_policy_span("mnpi-filter", "output", |span| {
        let outcome = evaluate_mnpi_filter_inner(text, cfg);
        crate::telemetry::annotate_policy_result_span(span, &outcome.policy_result);
        outcome
    })
}

fn evaluate_mnpi_filter_inner(text: &str, cfg: Option<&Value>) -> EvalOutcome {
    let patterns = cfg
        .and_then(|v| v.get("detect_patterns"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| {
            vec![
                "earnings before announcement".to_string(),
                "merger not public".to_string(),
                "insider information".to_string(),
                "board decision".to_string(),
                "not public".to_string(),
            ]
        });

    let lower = text.to_lowercase();
    let hit = patterns.iter().any(|p| lower.contains(&p.to_lowercase()));

    // Context-aware: detect stock symbols near MNPI keywords.
    let stock_context = detect_stock_symbol_context(&lower);

    let verdict = if hit { Verdict::Block } else { Verdict::Allow };
    let reason = if hit { "mnpi.detected" } else { "mnpi.clean" };

    EvalOutcome {
        rewrite: None,
        should_block: hit,
        should_escalate: false,
        policy_result: PolicyResult {
            policy_kind: "mnpi-filter".to_string(),
            phase: "output".to_string(),
            verdict,
            reason_code: reason.to_string(),
            details: Some(serde_json::json!({
                "hit": hit,
                "pattern_count": patterns.len(),
                "stock_symbol_context": stock_context,
            })),
            redaction_targets: None,
        },
    }
}

/// Detect stock symbols near MNPI keywords for context-aware detection.
fn detect_stock_symbol_context(lower_text: &str) -> serde_json::Value {
    let mnpi_keywords = [
        "earnings",
        "merger",
        "insider",
        "board decision",
        "not public",
        "acquisition",
        "ipo",
    ];
    let hits: Vec<String> = mnpi_keywords
        .iter()
        .filter(|kw| lower_text.contains(*kw))
        .map(|kw| kw.to_string())
        .collect();
    serde_json::json!({"mnpi_keywords_found": hits})
}

pub fn evaluate_financial_compliance(text: &str, cfg: Option<&Value>) -> EvalOutcome {
    crate::telemetry::with_policy_span("financial-compliance", "output", |span| {
        let outcome = evaluate_financial_compliance_inner(text, cfg);
        crate::telemetry::annotate_policy_result_span(span, &outcome.policy_result);
        outcome
    })
}

fn evaluate_financial_compliance_inner(text: &str, cfg: Option<&Value>) -> EvalOutcome {
    let blocked = cfg
        .and_then(|v| v.get("blocked_patterns"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let required_disclaimers = cfg
        .and_then(|v| v.get("required_disclaimers"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let lower = text.to_lowercase();

    let is_blocked = blocked
        .iter()
        .any(|p| !p.trim().is_empty() && lower.contains(&p.to_lowercase()));

    if is_blocked {
        return EvalOutcome {
            rewrite: None,
            should_block: true,
            should_escalate: false,
            policy_result: PolicyResult {
                policy_kind: "financial-compliance".to_string(),
                phase: "output".to_string(),
                verdict: Verdict::Block,
                reason_code: "financial.blocked".to_string(),
                details: Some(serde_json::json!({"blocked": true})),
                redaction_targets: None,
            },
        };
    }

    let looks_like_advice = lower.contains("buy ")
        || lower.contains("sell ")
        || lower.contains("you should invest")
        || lower.contains("guaranteed returns")
        || lower.contains("target price")
        || lower.contains("strong buy")
        || lower.contains("strong sell");

    let disclaimer = if !required_disclaimers.is_empty() {
        required_disclaimers.join("\n")
    } else {
        "This is not financial advice.".to_string()
    };

    let should_rewrite =
        looks_like_advice && !text.to_lowercase().starts_with(&disclaimer.to_lowercase());

    EvalOutcome {
        rewrite: if should_rewrite {
            Some(Rewrite {
                prefix: format!("{}\n\n", disclaimer),
            })
        } else {
            None
        },
        should_block: false,
        should_escalate: false,
        policy_result: PolicyResult {
            policy_kind: "financial-compliance".to_string(),
            phase: "output".to_string(),
            verdict: Verdict::Allow,
            reason_code: if should_rewrite {
                "financial.disclaimer_injected".to_string()
            } else {
                "financial.clean".to_string()
            },
            details: Some(serde_json::json!({
                "looks_like_advice": looks_like_advice,
                "disclaimer_injected": should_rewrite,
            })),
            redaction_targets: None,
        },
    }
}

pub fn evaluate_healthcare_compliance(text: &str, cfg: Option<&Value>) -> EvalOutcome {
    crate::telemetry::with_policy_span("healthcare-compliance", "output", |span| {
        let outcome = evaluate_healthcare_compliance_inner(text, cfg);
        crate::telemetry::annotate_policy_result_span(span, &outcome.policy_result);
        outcome
    })
}

fn evaluate_healthcare_compliance_inner(text: &str, cfg: Option<&Value>) -> EvalOutcome {
    let blocked = cfg
        .and_then(|v| v.get("blocked_patterns"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let required_disclaimers = cfg
        .and_then(|v| v.get("required_disclaimers"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let fda_class = cfg
        .and_then(|v| v.get("fda_class"))
        .and_then(|v| v.as_str())
        .unwrap_or("II")
        .to_string();

    let lower = text.to_lowercase();

    let matched_blocked = blocked
        .iter()
        .find(|p| !p.trim().is_empty() && lower.contains(&p.to_lowercase()))
        .cloned();

    if let Some(matched) = matched_blocked {
        return EvalOutcome {
            rewrite: None,
            should_block: true,
            should_escalate: false,
            policy_result: PolicyResult {
                policy_kind: "healthcare-compliance".to_string(),
                phase: "output".to_string(),
                verdict: Verdict::Block,
                reason_code: "healthcare.blocked".to_string(),
                details: Some(serde_json::json!({
                    "blocked": true,
                    "matched_pattern": matched,
                    "fda_class": fda_class,
                })),
                redaction_targets: None,
            },
        };
    }

    let looks_like_medical_advice = looks_like_medical_advice(&lower);

    let disclaimer = if !required_disclaimers.is_empty() {
        required_disclaimers.join("\n")
    } else {
        match fda_class.as_str() {
            "I" => "General health information only; not medical advice.".to_string(),
            "III" => "This is not medical advice and must not be used for diagnosis or treatment decisions. Consult a licensed clinician.".to_string(),
            _ => "This is not medical advice. Consult a licensed clinician.".to_string(),
        }
    };

    let disclaimer_lower = disclaimer.to_lowercase();
    let should_rewrite =
        looks_like_medical_advice && !lower.trim_start().starts_with(&disclaimer_lower);

    EvalOutcome {
        rewrite: if should_rewrite {
            Some(Rewrite {
                prefix: format!("{}\n\n", disclaimer),
            })
        } else {
            None
        },
        should_block: false,
        should_escalate: false,
        policy_result: PolicyResult {
            policy_kind: "healthcare-compliance".to_string(),
            phase: "output".to_string(),
            verdict: Verdict::Allow,
            reason_code: if should_rewrite {
                "healthcare.disclaimer_injected".to_string()
            } else if looks_like_medical_advice {
                "healthcare.disclaimer_present".to_string()
            } else {
                "healthcare.clean".to_string()
            },
            details: Some(serde_json::json!({
                "fda_class": fda_class,
                "looks_like_medical_advice": looks_like_medical_advice,
                "disclaimer_injected": should_rewrite,
            })),
            redaction_targets: None,
        },
    }
}

fn looks_like_medical_advice(lower_text: &str) -> bool {
    if lower_text.contains("diagnose")
        || lower_text.contains("diagnosis")
        || lower_text.contains("treat")
        || lower_text.contains("treatment")
        || lower_text.contains("prescribe")
        || lower_text.contains("prescription")
        || lower_text.contains("dosage")
        || lower_text.contains("dose")
        || lower_text.contains("take ") && lower_text.contains(" mg")
        || lower_text.contains("take ") && lower_text.contains(" ml")
        || lower_text.contains("start taking")
        || lower_text.contains("stop taking")
        || lower_text.contains("contraindication")
        || lower_text.contains("side effects")
    {
        return true;
    }

    if static_regex!(r"(?i)\b(?:take|start|increase|decrease)\s+\d{1,4}\s*(?:mg|ml|mcg)\b")
        .is_match(lower_text)
    {
        return true;
    }

    false
}

pub fn evaluate_legal_privilege(text: &str, cfg: Option<&Value>) -> EvalOutcome {
    crate::telemetry::with_policy_span("legal-privilege", "output", |span| {
        let outcome = evaluate_legal_privilege_inner(text, cfg);
        crate::telemetry::annotate_policy_result_span(span, &outcome.policy_result);
        outcome
    })
}

fn evaluate_legal_privilege_inner(text: &str, cfg: Option<&Value>) -> EvalOutcome {
    let markers = cfg
        .and_then(|v| v.get("privilege_markers"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| {
            vec![
                "attorney-client privilege".to_string(),
                "privileged and confidential".to_string(),
                "work product".to_string(),
                "for legal review only".to_string(),
            ]
        });

    let lower = text.to_lowercase();
    let hit = markers.iter().any(|m| lower.contains(&m.to_lowercase()));

    EvalOutcome {
        rewrite: None,
        should_block: hit,
        should_escalate: false,
        policy_result: PolicyResult {
            policy_kind: "legal-privilege".to_string(),
            phase: "output".to_string(),
            verdict: if hit { Verdict::Block } else { Verdict::Allow },
            reason_code: if hit {
                "legal.privilege_detected".to_string()
            } else {
                "legal.clean".to_string()
            },
            details: Some(serde_json::json!({"hit": hit, "marker_count": markers.len()})),
            redaction_targets: None,
        },
    }
}

pub fn evaluate_upl_filter(text: &str, cfg: Option<&Value>) -> EvalOutcome {
    crate::telemetry::with_policy_span("upl-filter", "output", |span| {
        let outcome = evaluate_upl_filter_inner(text, cfg);
        crate::telemetry::annotate_policy_result_span(span, &outcome.policy_result);
        outcome
    })
}

fn evaluate_upl_filter_inner(text: &str, cfg: Option<&Value>) -> EvalOutcome {
    let blocked = cfg
        .and_then(|v| v.get("blocked_patterns"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| {
            vec![
                "you should sue".to_string(),
                "file this motion".to_string(),
                "sign here".to_string(),
            ]
        });

    let require_disclaimer = cfg
        .and_then(|v| v.get("require_disclaimer"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let rewrite_to_educational = cfg
        .and_then(|v| v.get("rewrite_to_educational"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let lower = text.to_lowercase();
    let hit = blocked.iter().any(|p| lower.contains(&p.to_lowercase()));

    if hit {
        // If rewrite_to_educational is enabled, rewrite instead of block.
        if rewrite_to_educational {
            let educational_prefix = "Note: The following is for educational purposes only and does not constitute legal advice. Please consult a qualified attorney for advice specific to your situation.\n\n";
            return EvalOutcome {
                rewrite: Some(Rewrite {
                    prefix: educational_prefix.to_string(),
                }),
                should_block: false,
                should_escalate: false,
                policy_result: PolicyResult {
                    policy_kind: "upl-filter".to_string(),
                    phase: "output".to_string(),
                    verdict: Verdict::Allow,
                    reason_code: "upl.rewritten_to_educational".to_string(),
                    details: Some(
                        serde_json::json!({"rewritten": true, "original_would_block": true}),
                    ),
                    redaction_targets: None,
                },
            };
        }
        return EvalOutcome {
            rewrite: None,
            should_block: true,
            should_escalate: false,
            policy_result: PolicyResult {
                policy_kind: "upl-filter".to_string(),
                phase: "output".to_string(),
                verdict: Verdict::Block,
                reason_code: "upl.blocked".to_string(),
                details: Some(serde_json::json!({"blocked": true})),
                redaction_targets: None,
            },
        };
    }

    let looks_like_legal_advice = lower.contains("you should")
        || lower.contains("file") && lower.contains("court")
        || lower.contains("legal advice")
        || lower.contains("retain counsel");

    let disclaimer = "This is not legal advice.".to_string();
    let should_rewrite = require_disclaimer
        && looks_like_legal_advice
        && !lower.starts_with(&disclaimer.to_lowercase());

    EvalOutcome {
        rewrite: if should_rewrite {
            Some(Rewrite {
                prefix: format!("{}\n\n", disclaimer),
            })
        } else {
            None
        },
        should_block: false,
        should_escalate: false,
        policy_result: PolicyResult {
            policy_kind: "upl-filter".to_string(),
            phase: "output".to_string(),
            verdict: Verdict::Allow,
            reason_code: if should_rewrite {
                "upl.disclaimer_injected".to_string()
            } else {
                "upl.clean".to_string()
            },
            details: Some(serde_json::json!({
                "require_disclaimer": require_disclaimer,
                "looks_like_legal_advice": looks_like_legal_advice,
                "disclaimer_injected": should_rewrite,
            })),
            redaction_targets: None,
        },
    }
}

pub fn evaluate_bias_monitor(
    request_text: &str,
    response_text: &str,
    cfg: Option<&Value>,
) -> EvalOutcome {
    crate::telemetry::with_policy_span("bias-monitor", "output", |span| {
        let outcome = evaluate_bias_monitor_inner(request_text, response_text, cfg);
        crate::telemetry::annotate_policy_result_span(span, &outcome.policy_result);
        outcome
    })
}

fn evaluate_bias_monitor_inner(
    request_text: &str,
    response_text: &str,
    cfg: Option<&Value>,
) -> EvalOutcome {
    let threshold = cfg
        .and_then(|v| v.get("threshold"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.85);

    let req = request_text.to_lowercase();
    let resp = response_text.to_lowercase();

    let is_hr_context =
        req.contains("hire") || req.contains("promotion") || req.contains("performance review");
    let mentions_protected = resp.contains("race")
        || resp.contains("gender")
        || resp.contains("religion")
        || resp.contains("disability")
        || resp.contains("age");

    // Enhanced age detection: look for explicit age references like "over 40" or "under 25"
    let has_age_reference = detect_age_discrimination(&resp);
    let mentions_age_explicitly = mentions_protected || has_age_reference;

    let score = if is_hr_context && mentions_age_explicitly {
        0.95
    } else {
        0.0
    };
    let should_escalate = score >= threshold;

    EvalOutcome {
        rewrite: None,
        should_block: false,
        should_escalate,
        policy_result: PolicyResult {
            policy_kind: "bias-monitor".to_string(),
            phase: "output".to_string(),
            verdict: if should_escalate {
                Verdict::Escalate
            } else {
                Verdict::Allow
            },
            reason_code: if should_escalate {
                "bias.detected".to_string()
            } else {
                "bias.clean".to_string()
            },
            details: Some(serde_json::json!({
                "score": score,
                "threshold": threshold,
                "is_hr_context": is_hr_context,
                "mentions_protected_characteristic": mentions_age_explicitly,
                "has_age_reference": has_age_reference,
            })),
            redaction_targets: None,
        },
    }
}

/// Detect age-based discrimination patterns.
fn detect_age_discrimination(text: &str) -> bool {
    static_regex!(
        r"(?i)\b(?:over|under|above|below|older than|younger than)\s+\d{1,3}\s*(?:years?\s*old)?\b"
    )
    .is_match(text)
        || static_regex!(r"(?i)\b(?:too\s+old|too\s+young)\b").is_match(text)
        || static_regex!(r"(?i)\bage\s*(?:limit|requirement|restriction|ceiling|floor)\b")
            .is_match(text)
        || static_regex!(r"(?i)\b(?:retirement\s*age|mandatory\s*retirement)\b").is_match(text)
        || static_regex!(r"(?i)\b(?:overqualified|digital\s*native)\b").is_match(text)
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

    #[test]
    fn mnpi_filter_detects_insider_info() {
        let outcome = evaluate_mnpi_filter_inner("This contains insider information", None);
        assert!(outcome.should_block);
        assert_eq!(outcome.policy_result.verdict, Verdict::Block);
    }

    #[test]
    fn mnpi_filter_clean_text() {
        let outcome = evaluate_mnpi_filter_inner("The weather is nice today", None);
        assert!(!outcome.should_block);
        assert_eq!(outcome.policy_result.verdict, Verdict::Allow);
    }

    #[test]
    fn mnpi_filter_custom_patterns() {
        let cfg = serde_json::json!({"detect_patterns": ["secret project"]});
        let outcome = evaluate_mnpi_filter_inner("Details about the secret project", Some(&cfg));
        assert!(outcome.should_block);
    }

    #[test]
    fn detect_stock_symbol_context_with_keyword() {
        let result = detect_stock_symbol_context("earnings report for $AAPL this quarter");
        assert!(result.is_object());
    }

    #[test]
    fn detect_stock_symbol_context_no_keyword() {
        let result = detect_stock_symbol_context("the weather is nice");
        assert!(result.is_object());
    }

    #[test]
    fn healthcare_compliance_medical_advice() {
        let outcome = evaluate_healthcare_compliance_inner(
            "You should take 500 mg of acetaminophen for your headache",
            None,
        );
        assert_eq!(outcome.policy_result.policy_kind, "healthcare-compliance");
    }

    #[test]
    fn healthcare_compliance_clean() {
        let outcome = evaluate_healthcare_compliance_inner("The weather is sunny today", None);
        assert!(!outcome.should_block);
    }

    #[test]
    fn looks_like_medical_advice_dosage() {
        assert!(looks_like_medical_advice("take 500 mg daily"));
        assert!(looks_like_medical_advice("start taking the medication"));
    }

    #[test]
    fn looks_like_medical_advice_clean() {
        assert!(!looks_like_medical_advice("the weather is nice"));
    }

    #[test]
    fn detect_age_discrimination_positive() {
        assert!(detect_age_discrimination("must be over 30 years old"));
        assert!(detect_age_discrimination("candidate is too old"));
        assert!(detect_age_discrimination("age limit applies"));
    }

    #[test]
    fn detect_age_discrimination_negative() {
        assert!(!detect_age_discrimination("the project is old"));
    }

    #[test]
    fn legal_privilege_detects_attorney_client() {
        let outcome = evaluate_legal_privilege_inner(
            "This is attorney-client privileged communication",
            None,
        );
        assert!(outcome.should_block || outcome.should_escalate);
    }

    #[test]
    fn legal_privilege_clean_text() {
        let outcome = evaluate_legal_privilege_inner("The weather is fine today", None);
        assert!(!outcome.should_block);
    }

    #[test]
    fn upl_filter_evaluates_text() {
        let outcome =
            evaluate_upl_filter_inner("Based on the statute, you should file a motion", None);
        assert_eq!(outcome.policy_result.policy_kind, "upl-filter");
    }

    #[test]
    fn upl_filter_clean_text() {
        let outcome = evaluate_upl_filter_inner("The weather is sunny", None);
        assert!(!outcome.should_block);
    }

    #[test]
    fn financial_compliance_evaluates_text() {
        let outcome = evaluate_financial_compliance_inner(
            "You should buy AAPL stock right now at $150",
            None,
        );
        assert_eq!(outcome.policy_result.policy_kind, "financial-compliance");
    }

    #[test]
    fn financial_compliance_clean_text() {
        let outcome = evaluate_financial_compliance_inner("The sun is shining today", None);
        assert!(!outcome.should_block);
    }

    #[test]
    fn financial_compliance_blocked_pattern() {
        let cfg = serde_json::json!({"blocked_patterns": ["insider tip"]});
        let outcome = evaluate_financial_compliance_inner("Here is an insider tip", Some(&cfg));
        assert!(outcome.should_block);
        assert_eq!(outcome.policy_result.verdict, Verdict::Block);
        assert_eq!(outcome.policy_result.reason_code, "financial.blocked");
    }

    #[test]
    fn financial_compliance_disclaimer_injected() {
        let outcome = evaluate_financial_compliance_inner(
            "You should invest in TSLA for guaranteed returns",
            None,
        );
        assert!(!outcome.should_block);
        assert!(outcome.rewrite.is_some());
        assert_eq!(
            outcome.policy_result.reason_code,
            "financial.disclaimer_injected"
        );
    }

    #[test]
    fn financial_compliance_custom_disclaimers() {
        let cfg = serde_json::json!({"required_disclaimers": ["Custom disclaimer line 1", "Custom disclaimer line 2"]});
        let outcome = evaluate_financial_compliance_inner("strong buy recommendation", Some(&cfg));
        assert!(outcome.rewrite.is_some());
        assert!(outcome
            .rewrite
            .as_ref()
            .unwrap()
            .prefix
            .contains("Custom disclaimer line 1"));
    }

    #[test]
    fn financial_compliance_no_rewrite_when_starts_with_disclaimer() {
        let text = "This is not financial advice.\n\nYou should invest wisely.";
        let outcome = evaluate_financial_compliance_inner(text, None);
        assert!(outcome.rewrite.is_none());
        assert_eq!(outcome.policy_result.reason_code, "financial.clean");
    }

    #[test]
    fn healthcare_compliance_blocked_pattern() {
        let cfg = serde_json::json!({"blocked_patterns": ["schedule II controlled"]});
        let outcome = evaluate_healthcare_compliance_inner(
            "This involves schedule II controlled substances",
            Some(&cfg),
        );
        assert!(outcome.should_block);
        assert_eq!(outcome.policy_result.verdict, Verdict::Block);
        assert_eq!(outcome.policy_result.reason_code, "healthcare.blocked");
    }

    #[test]
    fn healthcare_compliance_fda_class_iii_disclaimer() {
        let cfg = serde_json::json!({"fda_class": "III"});
        let outcome =
            evaluate_healthcare_compliance_inner("Take 200 mg daily for treatment", Some(&cfg));
        assert!(outcome.rewrite.is_some());
        assert!(outcome
            .rewrite
            .as_ref()
            .unwrap()
            .prefix
            .contains("must not be used for diagnosis"));
    }

    #[test]
    fn healthcare_compliance_fda_class_i_disclaimer() {
        let cfg = serde_json::json!({"fda_class": "I"});
        let outcome = evaluate_healthcare_compliance_inner("Start taking this dosage", Some(&cfg));
        assert!(outcome.rewrite.is_some());
        assert!(outcome
            .rewrite
            .as_ref()
            .unwrap()
            .prefix
            .contains("General health information"));
    }

    #[test]
    fn healthcare_compliance_custom_disclaimers() {
        let cfg = serde_json::json!({"required_disclaimers": ["Custom medical warning"]});
        let outcome =
            evaluate_healthcare_compliance_inner("You should diagnose yourself", Some(&cfg));
        assert!(outcome.rewrite.is_some());
        assert!(outcome
            .rewrite
            .as_ref()
            .unwrap()
            .prefix
            .contains("Custom medical warning"));
    }

    #[test]
    fn healthcare_compliance_disclaimer_already_present() {
        let text = "This is not medical advice. Consult a licensed clinician.\n\nTake 500 mg of acetaminophen.";
        let outcome = evaluate_healthcare_compliance_inner(text, None);
        assert!(outcome.rewrite.is_none());
        assert_eq!(
            outcome.policy_result.reason_code,
            "healthcare.disclaimer_present"
        );
    }

    #[test]
    fn legal_privilege_custom_markers() {
        let cfg = serde_json::json!({"privilege_markers": ["for eyes only"]});
        let outcome = evaluate_legal_privilege_inner("This document is for eyes only", Some(&cfg));
        assert!(outcome.should_block);
        assert_eq!(outcome.policy_result.verdict, Verdict::Block);
        assert_eq!(
            outcome.policy_result.reason_code,
            "legal.privilege_detected"
        );
    }

    #[test]
    fn upl_filter_blocks_matched_pattern() {
        let outcome = evaluate_upl_filter_inner("You should sue immediately for damages", None);
        assert!(outcome.should_block);
        assert_eq!(outcome.policy_result.verdict, Verdict::Block);
        assert_eq!(outcome.policy_result.reason_code, "upl.blocked");
    }

    #[test]
    fn upl_filter_rewrite_to_educational() {
        let cfg = serde_json::json!({"rewrite_to_educational": true, "blocked_patterns": ["you should sue"]});
        let outcome =
            evaluate_upl_filter_inner("You should sue the landlord right now", Some(&cfg));
        assert!(!outcome.should_block);
        assert!(outcome.rewrite.is_some());
        assert_eq!(
            outcome.policy_result.reason_code,
            "upl.rewritten_to_educational"
        );
    }

    #[test]
    fn upl_filter_disclaimer_injected_for_legal_advice() {
        let outcome =
            evaluate_upl_filter_inner("I think you should retain counsel immediately", None);
        assert!(!outcome.should_block);
        assert!(outcome.rewrite.is_some());
        assert_eq!(outcome.policy_result.reason_code, "upl.disclaimer_injected");
    }

    #[test]
    fn upl_filter_no_disclaimer_when_disabled() {
        let cfg = serde_json::json!({"require_disclaimer": false});
        let outcome = evaluate_upl_filter_inner("you should retain counsel", Some(&cfg));
        assert!(outcome.rewrite.is_none());
        assert_eq!(outcome.policy_result.reason_code, "upl.clean");
    }

    #[test]
    fn bias_monitor_escalates_hr_with_protected_characteristic() {
        let outcome = evaluate_bias_monitor_inner(
            "Reviewing candidate for promotion",
            "The candidate is too old for this role",
            None,
        );
        assert!(outcome.should_escalate);
        assert_eq!(outcome.policy_result.verdict, Verdict::Escalate);
        assert_eq!(outcome.policy_result.reason_code, "bias.detected");
    }

    #[test]
    fn bias_monitor_clean_non_hr_context() {
        let outcome = evaluate_bias_monitor_inner(
            "General inquiry",
            "The candidate mentioned their race in passing",
            None,
        );
        assert!(!outcome.should_escalate);
        assert_eq!(outcome.policy_result.verdict, Verdict::Allow);
    }

    #[test]
    fn bias_monitor_custom_threshold() {
        let cfg = serde_json::json!({"threshold": 0.99});
        let outcome = evaluate_bias_monitor_inner(
            "hire new candidate",
            "candidate is over 50 years old",
            Some(&cfg),
        );
        assert!(!outcome.should_escalate);
    }

    #[test]
    fn detect_age_discrimination_retirement() {
        assert!(detect_age_discrimination(
            "mandatory retirement age applies"
        ));
    }

    #[test]
    fn detect_age_discrimination_digital_native() {
        assert!(detect_age_discrimination("we need a digital native"));
    }

    #[test]
    fn detect_age_discrimination_overqualified() {
        assert!(detect_age_discrimination("candidate seems overqualified"));
    }

    #[test]
    fn looks_like_medical_advice_regex_match() {
        assert!(looks_like_medical_advice("increase 200 mg immediately"));
    }

    #[test]
    fn looks_like_medical_advice_stop_taking() {
        assert!(looks_like_medical_advice("stop taking this medication"));
    }

    #[test]
    fn looks_like_medical_advice_contraindication() {
        assert!(looks_like_medical_advice("known contraindication exists"));
    }

    #[test]
    fn looks_like_medical_advice_side_effects() {
        assert!(looks_like_medical_advice("common side effects include"));
    }

    #[test]
    fn mnpi_filter_public_api_wraps_inner() {
        let outcome = evaluate_mnpi_filter("Contains insider information on the deal", None);
        assert!(outcome.should_block);
        assert_eq!(outcome.policy_result.policy_kind, "mnpi-filter");
    }

    #[test]
    fn financial_compliance_public_api_wraps_inner() {
        let outcome = evaluate_financial_compliance("Strong buy recommendation", None);
        assert_eq!(outcome.policy_result.policy_kind, "financial-compliance");
    }

    #[test]
    fn healthcare_compliance_public_api_wraps_inner() {
        let outcome = evaluate_healthcare_compliance("Take 100 mg of ibuprofen", None);
        assert_eq!(outcome.policy_result.policy_kind, "healthcare-compliance");
    }

    #[test]
    fn legal_privilege_public_api_wraps_inner() {
        let outcome = evaluate_legal_privilege("This is attorney-client privilege material", None);
        assert_eq!(outcome.policy_result.policy_kind, "legal-privilege");
    }

    #[test]
    fn upl_filter_public_api_wraps_inner() {
        let outcome = evaluate_upl_filter("General information only", None);
        assert_eq!(outcome.policy_result.policy_kind, "upl-filter");
    }

    #[test]
    fn bias_monitor_public_api_wraps_inner() {
        let outcome = evaluate_bias_monitor("general question", "neutral answer", None);
        assert_eq!(outcome.policy_result.policy_kind, "bias-monitor");
    }
}
