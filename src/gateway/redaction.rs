// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use sha2::Digest;

use crate::gateway::detection;
use crate::gateway::enforcement::RedactionTarget;

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerFormat {
    Label,
    Asterisk,
    Partial,
}

#[derive(Debug, Clone)]
pub struct RedactionConfig {
    pub marker_format: MarkerFormat,
    pub include_metadata: bool,
    pub preserve_length: bool,
    pub custom_markers: BTreeMap<String, String>,

    // Detector toggles (parsed from `[policy.pii-detector]`)
    pub healthcare_mode: bool,
    pub pci_mode: bool,
    pub detect_patterns: Vec<String>,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            marker_format: MarkerFormat::Label,
            include_metadata: true,
            preserve_length: false,
            custom_markers: BTreeMap::new(),
            healthcare_mode: false,
            pci_mode: true,
            detect_patterns: Vec::new(),
        }
    }
}

impl RedactionConfig {
    /// Parse `[policy.pii-detector.redaction]` from a policy block.
    pub fn from_policy_block(policy_block: Option<&Value>) -> Self {
        let mut cfg = RedactionConfig::default();

        let Some(tbl) = policy_block.and_then(|v| v.as_object()) else {
            return cfg;
        };
        cfg.healthcare_mode = tbl
            .get("healthcare_mode")
            .and_then(|v| v.as_bool())
            .unwrap_or(cfg.healthcare_mode);
        cfg.pci_mode = tbl
            .get("pci_mode")
            .and_then(|v| v.as_bool())
            .unwrap_or(cfg.pci_mode);

        if let Some(arr) = tbl.get("detect_patterns").and_then(|v| v.as_array()) {
            cfg.detect_patterns = arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }

        let Some(redaction) = tbl.get("redaction").and_then(|v| v.as_object()) else {
            return cfg;
        };

        if let Some(fmt) = redaction.get("marker_format").and_then(|v| v.as_str()) {
            cfg.marker_format = match fmt {
                "label" => MarkerFormat::Label,
                "asterisk" => MarkerFormat::Asterisk,
                "partial" => MarkerFormat::Partial,
                _ => MarkerFormat::Label,
            };
        }

        cfg.preserve_length = redaction
            .get("preserve_length")
            .and_then(|v| v.as_bool())
            .unwrap_or(cfg.preserve_length);

        cfg.include_metadata = redaction
            .get("include_metadata")
            .and_then(|v| v.as_bool())
            .unwrap_or(cfg.include_metadata);

        if let Some(map) = redaction.get("custom_markers").and_then(|v| v.as_object()) {
            for (k, v) in map {
                if let Some(s) = v.as_str() {
                    cfg.custom_markers.insert(k.to_string(), s.to_string());
                }
            }
        }

        cfg
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerdictanRedaction {
    pub kind: String,
    pub replacement: String,
    pub start: usize,
    pub end: usize,
    pub span_hash: String,
}

/// Redact sensitive values from free text.
///
/// This is deterministic and local-only (no ML). It returns only the redacted
/// text (used for request redaction).
pub fn redact_text(input: &str) -> String {
    redact_with_metadata(input).0
}

pub fn redact_text_with_config(input: &str, cfg: &RedactionConfig) -> String {
    redact_with_metadata_with_config(input, cfg).0
}

/// Redact sensitive values from free text and return Verdictan-compatible metadata.
///
/// `start`/`end` are byte offsets in the original text.
#[allow(dead_code)]
pub fn redact_with_metadata(input: &str) -> (String, Vec<VerdictanRedaction>) {
    redact_with_metadata_with_config(input, &RedactionConfig::default())
}

pub fn redact_with_metadata_with_config(
    input: &str,
    cfg: &RedactionConfig,
) -> (String, Vec<VerdictanRedaction>) {
    let (out, redactions, _targets) = redact_with_metadata_and_targets_with_config(input, cfg, "");
    (out, redactions)
}

pub fn redact_with_metadata_and_targets_with_config(
    input: &str,
    cfg: &RedactionConfig,
    location: &str,
) -> (String, Vec<VerdictanRedaction>, Vec<RedactionTarget>) {
    let mut detections = detection::pii::detect_all(input);
    if cfg.healthcare_mode {
        detections.extend(detection::hipaa::detect_hipaa_18_like(input));
    }
    if cfg.pci_mode {
        detections.extend(detection::pci::detect_pci_dss(input));
    }

    // Custom patterns are treated as generic IDs.
    for pat in &cfg.detect_patterns {
        if let Ok(re) = regex_lite::Regex::new(pat) {
            for m in re.find_iter(input) {
                detections.push(detection::pii::Detection {
                    kind: detection::pii::PiiKind::GenericId,
                    start: m.start(),
                    end: m.end(),
                    confidence: detection::pii::Confidence::Low,
                });
            }
        }
    }

    detections.sort_by(|a, b| {
        (
            a.start,
            a.kind.priority(),
            std::cmp::Reverse(a.end - a.start),
        )
            .cmp(&(
                b.start,
                b.kind.priority(),
                std::cmp::Reverse(b.end - b.start),
            ))
    });
    detections = dedupe_overlaps(detections);
    if detections.is_empty() {
        return (input.to_string(), Vec::new(), Vec::new());
    }

    let mut out = String::with_capacity(input.len());
    let mut redactions = Vec::new();
    let mut targets = Vec::new();

    let mut cursor = 0;
    for d in detections {
        if d.start < cursor || d.end > input.len() {
            continue;
        }

        out.push_str(&input[cursor..d.start]);

        let original_span = &input[d.start..d.end];
        let replacement = replacement_for_detection(cfg, &d.kind, original_span);
        out.push_str(&replacement);

        targets.push(RedactionTarget {
            location: location.to_string(),
            entity_type: d.kind.marker_key().to_string(),
            start: d.start,
            end: d.end,
        });

        if cfg.include_metadata {
            redactions.push(VerdictanRedaction {
                kind: d.kind.as_kind_str().to_string(),
                replacement: replacement.clone(),
                start: d.start,
                end: d.end,
                span_hash: sha256_prefixed(original_span.as_bytes()),
            });
        }

        cursor = d.end;
    }

    out.push_str(&input[cursor..]);
    (out, redactions, targets)
}

fn dedupe_overlaps(detections: Vec<detection::pii::Detection>) -> Vec<detection::pii::Detection> {
    let mut out = Vec::new();

    let mut i = 0;
    while i < detections.len() {
        let mut best = detections[i].clone();
        let mut cluster_end = best.end;

        let mut j = i + 1;
        while j < detections.len() && detections[j].start < cluster_end {
            cluster_end = cluster_end.max(detections[j].end);
            let cand = &detections[j];
            let cand_len = cand.end.saturating_sub(cand.start);
            let best_len = best.end.saturating_sub(best.start);
            let cand_key = (cand.kind.priority(), std::cmp::Reverse(cand_len));
            let best_key = (best.kind.priority(), std::cmp::Reverse(best_len));
            if cand_key < best_key {
                best = cand.clone();
            }
            j += 1;
        }

        out.push(best);
        i = j;
    }

    out.sort_by_key(|d| (d.start, d.end));
    out
}

fn replacement_for_detection(
    cfg: &RedactionConfig,
    kind: &detection::pii::PiiKind,
    original_span: &str,
) -> String {
    if let Some(custom) = cfg.custom_markers.get(kind.marker_key()) {
        return custom.clone();
    }

    match cfg.marker_format {
        MarkerFormat::Label => kind.replacement().to_string(),
        MarkerFormat::Asterisk => {
            if cfg.preserve_length {
                "*".repeat(original_span.chars().count().max(1))
            } else {
                "***".to_string()
            }
        }
        MarkerFormat::Partial => {
            partial_mask(kind, original_span).unwrap_or_else(|| kind.replacement().to_string())
        }
    }
}

fn partial_mask(kind: &detection::pii::PiiKind, original_span: &str) -> Option<String> {
    match kind {
        detection::pii::PiiKind::Ssn => Some(mask_digits_keep_last(original_span, 4)),
        detection::pii::PiiKind::Pan => Some(mask_digits_keep_last(original_span, 4)),
        detection::pii::PiiKind::Email => mask_email(original_span),
        _ => None,
    }
}

fn mask_digits_keep_last(original_span: &str, keep_last: usize) -> String {
    let digits: Vec<char> = original_span
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect();
    let total = digits.len();
    let keep = keep_last.min(total);
    let mut keep_from = total.saturating_sub(keep);

    let mut out = String::with_capacity(original_span.len());
    for c in original_span.chars() {
        if c.is_ascii_digit() {
            if keep_from > 0 {
                out.push('*');
                keep_from -= 1;
            } else {
                out.push(c);
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn mask_email(original_span: &str) -> Option<String> {
    let (local, domain) = original_span.split_once('@')?;
    if local.is_empty() {
        return None;
    }
    let mut masked_local = String::new();
    let mut chars = local.chars();
    if let Some(first) = chars.next() {
        masked_local.push(first);
    }
    masked_local.push_str("***");
    Some(format!("{}@{}", masked_local, domain))
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
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
    use crate::gateway::detection::pii::{Confidence, Detection, PiiKind};

    #[test]
    fn from_policy_block_parses_modes_and_custom_markers() {
        let cfg = RedactionConfig::from_policy_block(Some(&serde_json::json!({
            "healthcare_mode": true,
            "pci_mode": false,
            "detect_patterns": ["EMP-[0-9]+"],
            "redaction": {
                "marker_format": "partial",
                "preserve_length": true,
                "include_metadata": false,
                "custom_markers": {
                    "email": "[CUSTOM:EMAIL]"
                }
            }
        })));

        assert!(cfg.healthcare_mode);
        assert!(!cfg.pci_mode);
        assert_eq!(cfg.detect_patterns, vec!["EMP-[0-9]+".to_string()]);
        assert!(matches!(cfg.marker_format, MarkerFormat::Partial));
        assert!(cfg.preserve_length);
        assert!(!cfg.include_metadata);
        assert_eq!(
            cfg.custom_markers.get("email").map(String::as_str),
            Some("[CUSTOM:EMAIL]")
        );
    }

    #[test]
    fn redact_with_partial_masks_keeps_tail_digits_and_email_domain() {
        let cfg = RedactionConfig {
            marker_format: MarkerFormat::Partial,
            include_metadata: true,
            preserve_length: false,
            custom_markers: BTreeMap::new(),
            healthcare_mode: false,
            pci_mode: false,
            detect_patterns: Vec::new(),
        };

        let output = redact_text_with_config("SSN 123-45-6789 and alice@example.com", &cfg);

        assert!(output.contains("***-**-6789"));
        assert!(output.contains("a***@example.com"));
    }

    #[test]
    fn redact_with_custom_patterns_can_disable_metadata_and_emit_targets() {
        let cfg = RedactionConfig {
            marker_format: MarkerFormat::Label,
            include_metadata: false,
            preserve_length: false,
            custom_markers: BTreeMap::new(),
            healthcare_mode: false,
            pci_mode: false,
            detect_patterns: vec!["EMP-[A-Z]+".to_string()],
        };

        let (output, redactions, targets) = redact_with_metadata_and_targets_with_config(
            "Employee EMP-ALPHA requested access",
            &cfg,
            "request.messages[0].content",
        );

        assert_eq!(output, "Employee [REDACTED:ID] requested access");
        assert!(redactions.is_empty());
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].location, "request.messages[0].content");
        assert_eq!(targets[0].entity_type, "generic_id");
    }

    #[test]
    fn dedupe_overlaps_prefers_higher_priority_detection() {
        let deduped = dedupe_overlaps(vec![
            Detection {
                kind: PiiKind::Email,
                start: 0,
                end: 17,
                confidence: Confidence::Medium,
            },
            Detection {
                kind: PiiKind::Ssn,
                start: 0,
                end: 11,
                confidence: Confidence::High,
            },
            Detection {
                kind: PiiKind::Phone,
                start: 20,
                end: 32,
                confidence: Confidence::Low,
            },
        ]);

        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped[0].kind, PiiKind::Ssn);
        assert_eq!(deduped[1].kind, PiiKind::Phone);
    }

    #[test]
    fn asterisk_preserve_length_masks_entire_span_length() {
        let cfg = RedactionConfig {
            marker_format: MarkerFormat::Asterisk,
            include_metadata: true,
            preserve_length: true,
            custom_markers: BTreeMap::new(),
            healthcare_mode: false,
            pci_mode: false,
            detect_patterns: Vec::new(),
        };

        let output = redact_text_with_config("Contact alice@example.com", &cfg);
        assert_eq!(output, "Contact *****************");
    }
}
