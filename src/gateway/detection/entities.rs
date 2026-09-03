// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::collections::HashSet;

use regex_lite::Regex;
use serde::Serialize;

use super::{hipaa, pci, pii};

macro_rules! static_regex {
    ($pattern:expr) => {{
        static RE: std::sync::OnceLock<regex_lite::Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| {
            #[allow(clippy::expect_used)]
            regex_lite::Regex::new($pattern).expect("static regex pattern")
        })
    }};
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntityFinding {
    pub entity_type: String,
    pub category: String,
    pub confidence: String,
    pub start: usize,
    pub end: usize,
}

const DEFAULT_BLOCKED_ENTITY_TYPES: &[&str] = &[
    "account_number",
    "aws_access_key",
    "cvv",
    "health_plan_beneficiary",
    "jwt",
    "mrn",
    "pan",
    "private_key",
    "ssn",
];

pub fn detect_entities(text: &str) -> Vec<EntityFinding> {
    let mut findings = Vec::new();
    findings.extend(map_detections(pii::detect_all(text)));
    findings.extend(map_detections(hipaa::detect_hipaa_18_like(text)));
    findings.extend(map_detections(pci::detect_pci_dss(text)));
    findings.extend(detect_named_pattern(
        text,
        "aws_access_key",
        "credential",
        "high",
        static_regex!(r"\bAKIA[0-9A-Z]{16}\b"),
    ));
    findings.extend(detect_named_pattern(
        text,
        "jwt",
        "credential",
        "high",
        static_regex!(r"\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9._-]{4,}\.[a-zA-Z0-9._-]{4,}\b"),
    ));
    findings.extend(detect_named_pattern(
        text,
        "private_key",
        "credential",
        "high",
        static_regex!(r"-----BEGIN(?: RSA| EC| OPENSSH)? PRIVATE KEY-----"),
    ));

    dedupe_findings(findings)
}

pub fn blocked_findings(text: &str, blocked_entity_types: &[String]) -> Vec<EntityFinding> {
    let blocked = if blocked_entity_types.is_empty() {
        DEFAULT_BLOCKED_ENTITY_TYPES
            .iter()
            .map(|value| value.to_string())
            .collect::<HashSet<_>>()
    } else {
        blocked_entity_types
            .iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect::<HashSet<_>>()
    };

    detect_entities(text)
        .into_iter()
        .filter(|finding| blocked.contains(&finding.entity_type))
        .collect()
}

fn map_detections(detections: Vec<pii::Detection>) -> Vec<EntityFinding> {
    detections
        .into_iter()
        .map(|detection| EntityFinding {
            entity_type: detection.kind.marker_key().to_string(),
            category: detection.kind.as_kind_str().to_string(),
            confidence: detection.confidence.as_str().to_string(),
            start: detection.start,
            end: detection.end,
        })
        .collect()
}

fn detect_named_pattern(
    text: &str,
    entity_type: &str,
    category: &str,
    confidence: &str,
    re: &Regex,
) -> Vec<EntityFinding> {
    re.find_iter(text)
        .map(|matched| EntityFinding {
            entity_type: entity_type.to_string(),
            category: category.to_string(),
            confidence: confidence.to_string(),
            start: matched.start(),
            end: matched.end(),
        })
        .collect()
}

fn dedupe_findings(findings: Vec<EntityFinding>) -> Vec<EntityFinding> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();

    for finding in findings {
        let key = (finding.entity_type.clone(), finding.start, finding.end);
        if seen.insert(key) {
            deduped.push(finding);
        }
    }

    deduped.sort_by(|left, right| {
        (left.start, left.end, left.entity_type.as_str()).cmp(&(
            right.start,
            right.end,
            right.entity_type.as_str(),
        ))
    });
    deduped
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
    fn detect_entities_empty_text() {
        let findings = detect_entities("");
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_entities_no_sensitive_data() {
        let findings = detect_entities("Hello world, this is a normal sentence.");
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_entities_aws_access_key() {
        let findings = detect_entities("Key: AKIAIOSFODNN7EXAMPLE");
        assert!(findings.iter().any(|f| f.entity_type == "aws_access_key"));
    }

    #[test]
    fn detect_entities_jwt() {
        let sample_jwt = [
            "eyJhbGciOiJIUzI1NiJ9",
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        ]
        .join(".");
        let findings = detect_entities(&format!("token: {sample_jwt}"));
        assert!(findings.iter().any(|f| f.entity_type == "jwt"));
    }

    #[test]
    fn detect_entities_private_key() {
        let findings = detect_entities("-----BEGIN RSA PRIVATE KEY-----");
        assert!(findings.iter().any(|f| f.entity_type == "private_key"));
    }

    #[test]
    fn detect_entities_deduplicates() {
        let text = "AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE";
        let findings = detect_entities(text);
        let aws_count = findings
            .iter()
            .filter(|f| f.entity_type == "aws_access_key")
            .count();
        assert_eq!(aws_count, 2);
    }

    #[test]
    fn blocked_findings_default_blocks_ssn() {
        let findings = blocked_findings("SSN: 123-45-6789", &[]);
        assert!(findings.iter().any(|f| f.entity_type == "ssn"));
    }

    #[test]
    fn blocked_findings_custom_entity_types() {
        let custom = vec!["aws_access_key".to_string()];
        let findings = blocked_findings("Key: AKIAIOSFODNN7EXAMPLE SSN: 123-45-6789", &custom);
        assert!(findings.iter().any(|f| f.entity_type == "aws_access_key"));
        assert!(!findings.iter().any(|f| f.entity_type == "ssn"));
    }

    #[test]
    fn blocked_findings_empty_custom_uses_defaults() {
        let findings = blocked_findings("Key: AKIAIOSFODNN7EXAMPLE", &[]);
        assert!(findings.iter().any(|f| f.entity_type == "aws_access_key"));
    }

    #[test]
    fn entity_finding_serialization() {
        let finding = EntityFinding {
            entity_type: "ssn".to_string(),
            category: "pii".to_string(),
            confidence: "high".to_string(),
            start: 0,
            end: 11,
        };
        let json = serde_json::to_value(&finding).unwrap();
        assert_eq!(json["entity_type"], "ssn");
        assert_eq!(json["start"], 0);
    }

    #[test]
    fn dedupe_findings_removes_duplicates() {
        let findings = vec![
            EntityFinding {
                entity_type: "ssn".to_string(),
                category: "pii".to_string(),
                confidence: "high".to_string(),
                start: 5,
                end: 16,
            },
            EntityFinding {
                entity_type: "ssn".to_string(),
                category: "pii".to_string(),
                confidence: "medium".to_string(),
                start: 5,
                end: 16,
            },
        ];
        let deduped = dedupe_findings(findings);
        assert_eq!(deduped.len(), 1);
    }
}
