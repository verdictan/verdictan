// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use super::enforcement::{PolicyResult, Verdict};

// ---------------------------------------------------------------------------
// GDPR compliance evaluator
// ---------------------------------------------------------------------------

/// Configuration for the `gdpr-compliance` policy kind.
///
/// Fields removed (externally owned, no live gateway contract):
/// - `consent_verification_endpoint` — requires an external consent service
/// - `retention_days` — owned by the API retention settings
/// - erasure webhook — requires an external erasure service
#[derive(Debug, Clone)]
pub struct GdprConfig {
    pub consent_required: bool,
    pub consent_header: String,
    pub data_categories: Vec<String>,
    pub timeout_ms: u64,
}

/// Fields removed from GDPR config.
pub const REMOVED_GDPR_FIELDS: &[&str] = &[
    "consent_verification_endpoint",
    "retention_days",
    "erasure_webhook",
];

impl GdprConfig {
    pub fn from_json(v: &Value) -> Self {
        Self {
            consent_required: v
                .get("consent_required")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
            consent_header: v
                .get("consent_header")
                .and_then(|x| x.as_str())
                .unwrap_or("X-User-Consent-Token")
                .to_string(),
            data_categories: v
                .get("data_categories")
                .and_then(|x| x.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(ToString::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            timeout_ms: v.get("timeout_ms").and_then(|t| t.as_u64()).unwrap_or(5000),
        }
    }
}

/// Evaluate GDPR compliance for an inbound request.
///
/// Checks:
/// 1. If `consent_required`, verify the consent header is present.
/// 2. If a `consent_verification_endpoint` is set, POST the token for validation.
/// 3. If the request contains an `X-Erasure-Request` header, note the erasure request.
pub fn evaluate_gdpr_compliance(
    request_headers: &std::collections::HashMap<String, String>,
    _request_body: &Value,
    policy_cfg: &Value,
) -> PolicyResult {
    let config = GdprConfig::from_json(policy_cfg);
    let mut failures: Vec<String> = Vec::new();

    // 1. Consent header check.
    if config.consent_required {
        let header_name = config.consent_header.to_lowercase();
        let has_consent = request_headers
            .iter()
            .any(|(k, v)| k.to_lowercase() == header_name && !v.is_empty());
        if !has_consent {
            failures.push("gdpr.consent_missing".to_string());
        }
    }

    // 2. Erasure request detection.
    let has_erasure = request_headers
        .iter()
        .any(|(k, _)| k.to_lowercase() == "x-erasure-request");

    // 3. Build result.
    if failures.is_empty() {
        PolicyResult {
            policy_kind: "gdpr-compliance".to_string(),
            phase: "input".to_string(),
            verdict: Verdict::Allow,
            reason_code: "ok".to_string(),
            details: Some(serde_json::json!({
                "consent_required": config.consent_required,
                "erasure_detected": has_erasure,
                "data_categories": config.data_categories,
            })),
            redaction_targets: None,
        }
    } else {
        PolicyResult {
            policy_kind: "gdpr-compliance".to_string(),
            phase: "input".to_string(),
            verdict: Verdict::Block,
            reason_code: failures.join(","),
            details: Some(serde_json::json!({
                "consent_required": config.consent_required,
                "failures": failures,
            })),
            redaction_targets: None,
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
    use std::collections::HashMap;

    #[test]
    fn gdpr_config_defaults() {
        let v = serde_json::json!({});
        let config = GdprConfig::from_json(&v);
        assert!(!config.consent_required);
        assert_eq!(config.consent_header, "X-User-Consent-Token");
        assert!(config.data_categories.is_empty());
        assert_eq!(config.timeout_ms, 5000);
    }

    #[test]
    fn gdpr_config_from_json_full() {
        let v = serde_json::json!({
            "consent_required": true,
            "consent_header": "X-Consent",
            "data_categories": ["personal", "health"],
            "timeout_ms": 3000
        });
        let config = GdprConfig::from_json(&v);
        assert!(config.consent_required);
        assert_eq!(config.consent_header, "X-Consent");
        assert_eq!(config.data_categories, vec!["personal", "health"]);
        assert_eq!(config.timeout_ms, 3000);
    }

    #[test]
    fn evaluate_consent_not_required_allows() {
        let headers = HashMap::new();
        let body = serde_json::json!({});
        let cfg = serde_json::json!({"consent_required": false});
        let result = evaluate_gdpr_compliance(&headers, &body, &cfg);
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn evaluate_consent_required_missing_blocks() {
        let headers = HashMap::new();
        let body = serde_json::json!({});
        let cfg = serde_json::json!({"consent_required": true});
        let result = evaluate_gdpr_compliance(&headers, &body, &cfg);
        assert_eq!(result.verdict, Verdict::Block);
        assert!(result.reason_code.contains("consent_missing"));
    }

    #[test]
    fn evaluate_consent_required_present_allows() {
        let mut headers = HashMap::new();
        headers.insert(
            "x-user-consent-token".to_string(),
            "valid-token".to_string(),
        );
        let body = serde_json::json!({});
        let cfg = serde_json::json!({"consent_required": true});
        let result = evaluate_gdpr_compliance(&headers, &body, &cfg);
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn evaluate_consent_required_empty_value_blocks() {
        let mut headers = HashMap::new();
        headers.insert("x-user-consent-token".to_string(), "".to_string());
        let body = serde_json::json!({});
        let cfg = serde_json::json!({"consent_required": true});
        let result = evaluate_gdpr_compliance(&headers, &body, &cfg);
        assert_eq!(result.verdict, Verdict::Block);
    }

    #[test]
    fn evaluate_erasure_detected_in_details() {
        let mut headers = HashMap::new();
        headers.insert("X-Erasure-Request".to_string(), "true".to_string());
        let body = serde_json::json!({});
        let cfg = serde_json::json!({});
        let result = evaluate_gdpr_compliance(&headers, &body, &cfg);
        assert_eq!(result.verdict, Verdict::Allow);
        let details = result.details.unwrap();
        assert_eq!(details["erasure_detected"], true);
    }

    #[test]
    fn evaluate_custom_consent_header() {
        let mut headers = HashMap::new();
        headers.insert("x-my-consent".to_string(), "token-abc".to_string());
        let body = serde_json::json!({});
        let cfg = serde_json::json!({
            "consent_required": true,
            "consent_header": "X-My-Consent"
        });
        let result = evaluate_gdpr_compliance(&headers, &body, &cfg);
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn evaluate_details_include_data_categories() {
        let headers = HashMap::new();
        let body = serde_json::json!({});
        let cfg = serde_json::json!({"data_categories": ["personal", "financial"]});
        let result = evaluate_gdpr_compliance(&headers, &body, &cfg);
        let details = result.details.unwrap();
        let cats = details["data_categories"].as_array().unwrap();
        assert_eq!(cats.len(), 2);
    }
}
