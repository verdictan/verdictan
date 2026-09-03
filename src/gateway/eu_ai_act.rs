// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::declarative_config::LoadedDeclarativeConfig;
use super::enforcement::{PolicyResult, Verdict};

// ---------------------------------------------------------------------------
// EU AI Act compliance evaluator (Art. 9–15 gap detector)
// ---------------------------------------------------------------------------

/// Article-to-policy mapping for EU AI Act high-risk AI systems.
const ARTICLE_MAPPINGS: &[(u32, &str, &[&str])] = &[
    (9, "Risk management", &["quality-scorer"]),
    (10, "Data governance", &["gdpr-compliance", "pii-detector"]),
    (11, "Technical documentation", &[]), // Covered by compliance_report export.
    (12, "Transparency", &["audit-logger"]),
    (13, "Human oversight", &["human-oversight"]),
    (14, "Human oversight mechanisms", &["human-oversight"]),
    (
        15,
        "Accuracy, robustness, cybersecurity",
        &["quality-scorer", "prompt-injection"],
    ),
];

/// Coverage status for a single article.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArticleCoverage {
    pub article: u32,
    pub title: String,
    pub required_policies: Vec<String>,
    pub present_policies: Vec<String>,
    pub covered: bool,
}

/// Full compliance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub risk_class: String,
    pub articles_checked: Vec<ArticleCoverage>,
    pub fully_covered: bool,
    pub gap_count: usize,
    pub timestamp: String,
}

/// EU AI Act policy config.
#[derive(Debug, Clone)]
pub struct EuAiActConfig {
    pub risk_class: String,
    pub articles: Vec<u32>,
}

impl EuAiActConfig {
    pub fn from_json(v: &Value) -> Self {
        let risk_class = v
            .get("risk_class")
            .and_then(|x| x.as_str())
            .unwrap_or("high")
            .to_string();
        let articles = v
            .get("articles")
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_u64().map(|n| n as u32))
                    .collect()
            })
            .unwrap_or_else(|| vec![9, 10, 11, 12, 13, 14, 15]);
        Self {
            risk_class,
            articles,
        }
    }
}

/// Evaluate EU AI Act compliance against the active policy chain.
///
/// This is a **gap detector**: it checks whether the required policy kinds
/// are present in the deployment's policy chain.
fn evaluate_eu_ai_act(policy_chain: &[String], policy_cfg: &Value) -> PolicyResult {
    let config = EuAiActConfig::from_json(policy_cfg);
    let report = check_article_coverage(policy_chain, &config);

    if report.fully_covered {
        PolicyResult {
            policy_kind: "eu-ai-act".to_string(),
            phase: "input".to_string(),
            verdict: Verdict::Allow,
            reason_code: "ok".to_string(),
            details: Some(serde_json::to_value(&report).unwrap_or_default()),
            redaction_targets: None,
        }
    } else {
        let gaps: Vec<String> = report
            .articles_checked
            .iter()
            .filter(|a| !a.covered)
            .map(|a| format!("Art.{}", a.article))
            .collect();
        PolicyResult {
            policy_kind: "eu-ai-act".to_string(),
            phase: "input".to_string(),
            verdict: Verdict::Escalate,
            reason_code: format!("eu-ai-act.gaps:{}", gaps.join(",")),
            details: Some(serde_json::to_value(&report).unwrap_or_default()),
            redaction_targets: None,
        }
    }
}

fn check_article_coverage(policy_chain: &[String], config: &EuAiActConfig) -> ComplianceReport {
    let chain_set: std::collections::HashSet<&str> =
        policy_chain.iter().map(|s| s.as_str()).collect();

    let mut articles_checked = Vec::new();
    let mut gap_count = 0;

    for &(article_num, title, required) in ARTICLE_MAPPINGS {
        if !config.articles.contains(&article_num) {
            continue;
        }

        let required_policies: Vec<String> = required.iter().map(|s| s.to_string()).collect();

        // Art. 11 (technical documentation) is covered by the compliance-report
        // export feature itself — no specific policy required in the chain.
        let covered = if required.is_empty() {
            true
        } else {
            required.iter().all(|p| chain_set.contains(p))
        };

        let present: Vec<String> = required
            .iter()
            .filter(|p| chain_set.contains(*p))
            .map(|s| s.to_string())
            .collect();

        if !covered {
            gap_count += 1;
        }

        articles_checked.push(ArticleCoverage {
            article: article_num,
            title: title.to_string(),
            required_policies,
            present_policies: present,
            covered,
        });
    }

    ComplianceReport {
        risk_class: config.risk_class.clone(),
        articles_checked,
        fully_covered: gap_count == 0,
        gap_count,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }
}

/// Generate a full compliance report from the loaded config. Used by the
/// `/verdictan/compliance/report` HTTP endpoint.
pub fn generate_compliance_report(config: &LoadedDeclarativeConfig) -> ComplianceReport {
    // Find the eu-ai-act policy block, if any — otherwise use defaults.
    let eu_cfg = config
        .policy_blocks
        .get("eu-ai-act")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let parsed = EuAiActConfig::from_json(&eu_cfg);
    let policy_chain: Vec<String> = config
        .chain_entries
        .iter()
        .map(|e| e.kind().to_string())
        .collect();
    check_article_coverage(&policy_chain, &parsed)
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
    use serde_json::json;

    #[test]
    fn eu_ai_act_config_defaults() {
        let v = json!({});
        let config = EuAiActConfig::from_json(&v);
        assert_eq!(config.risk_class, "high");
        assert_eq!(config.articles, vec![9, 10, 11, 12, 13, 14, 15]);
    }

    #[test]
    fn eu_ai_act_config_custom() {
        let v = json!({"risk_class": "limited", "articles": [9, 12]});
        let config = EuAiActConfig::from_json(&v);
        assert_eq!(config.risk_class, "limited");
        assert_eq!(config.articles, vec![9, 12]);
    }

    #[test]
    fn evaluate_fully_covered_allows() {
        let chain = vec![
            "quality-scorer".to_string(),
            "gdpr-compliance".to_string(),
            "pii-detector".to_string(),
            "audit-logger".to_string(),
            "human-oversight".to_string(),
            "prompt-injection".to_string(),
        ];
        let cfg = json!({});
        let result = evaluate_eu_ai_act(&chain, &cfg);
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn evaluate_missing_policies_escalates() {
        let chain = vec!["audit-logger".to_string()];
        let cfg = json!({});
        let result = evaluate_eu_ai_act(&chain, &cfg);
        assert_eq!(result.verdict, Verdict::Escalate);
        assert!(result.reason_code.contains("gaps"));
    }

    #[test]
    fn evaluate_empty_chain_escalates() {
        let chain: Vec<String> = vec![];
        let cfg = json!({});
        let result = evaluate_eu_ai_act(&chain, &cfg);
        assert_eq!(result.verdict, Verdict::Escalate);
    }

    #[test]
    fn evaluate_specific_articles_only() {
        let chain = vec!["audit-logger".to_string()];
        let cfg = json!({"articles": [12]});
        let result = evaluate_eu_ai_act(&chain, &cfg);
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn article_11_covered_without_policy() {
        let chain: Vec<String> = vec![];
        let cfg = json!({"articles": [11]});
        let result = evaluate_eu_ai_act(&chain, &cfg);
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn check_article_coverage_report_fields() {
        let chain = vec!["quality-scorer".to_string()];
        let config = EuAiActConfig {
            risk_class: "high".to_string(),
            articles: vec![9, 10],
        };
        let report = check_article_coverage(&chain, &config);
        assert_eq!(report.risk_class, "high");
        assert_eq!(report.articles_checked.len(), 2);
        assert!(report.articles_checked[0].covered);
        assert!(!report.articles_checked[1].covered);
        assert_eq!(report.gap_count, 1);
        assert!(!report.fully_covered);
    }

    #[test]
    fn article_coverage_partial_not_covered() {
        let chain = vec!["quality-scorer".to_string(), "gdpr-compliance".to_string()];
        let config = EuAiActConfig {
            risk_class: "high".to_string(),
            articles: vec![10],
        };
        let report = check_article_coverage(&chain, &config);
        let art10 = &report.articles_checked[0];
        assert!(
            !art10.covered,
            "Art.10 requires both gdpr-compliance AND pii-detector"
        );
        assert!(art10
            .present_policies
            .contains(&"gdpr-compliance".to_string()));
        assert!(!art10.present_policies.contains(&"pii-detector".to_string()));
    }

    #[test]
    fn article_coverage_all_required_policies_present() {
        let chain = vec!["gdpr-compliance".to_string(), "pii-detector".to_string()];
        let config = EuAiActConfig {
            risk_class: "high".to_string(),
            articles: vec![10],
        };
        let report = check_article_coverage(&chain, &config);
        let art10 = &report.articles_checked[0];
        assert!(art10.covered);
        assert_eq!(art10.present_policies.len(), 2);
    }
}
