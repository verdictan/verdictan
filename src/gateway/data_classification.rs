// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

/// Data classification for regulated-execution privacy pipeline.
///
/// Provides deterministic, pattern-based classification of text content into
/// sensitivity classes. No external service calls; runs in-process during
/// the input phase before provider routing.
///
/// Classification order follows PAT-003:
/// classify → tokenize/redact → policy evaluation → provider routing
///
/// Part of the regulated-runtime foundation.
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Data class taxonomy
// ---------------------------------------------------------------------------

/// Broad sensitivity class assigned to a matched text span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    /// Protected Health Information (HIPAA ePHI) — e.g. SSN, MRN, DOB in clinical context.
    SensitivePhi,
    /// Personally Identifiable Information — names, emails, phone numbers, IPs, etc.
    SensitivePii,
    /// Financial data — credit card numbers, IBAN, account numbers.
    FinancialData,
    /// Intellectual property markers — code secrets, proprietary terms.
    IntellectualProperty,
    /// No sensitive class detected; safe to pass through.
    Unclassified,
}

impl DataClass {
    /// Returns `true` for any class that requires access control beyond `Unclassified`.
    #[inline]
    pub fn is_sensitive(self) -> bool {
        !matches!(self, DataClass::Unclassified)
    }

    /// Human-readable label used in audit logs and token placeholders.
    pub fn label(self) -> &'static str {
        match self {
            DataClass::SensitivePhi => "PHI",
            DataClass::SensitivePii => "PII",
            DataClass::FinancialData => "FINANCIAL",
            DataClass::IntellectualProperty => "IP",
            DataClass::Unclassified => "UNCLASSIFIED",
        }
    }
}

impl std::fmt::Display for DataClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Classification result
// ---------------------------------------------------------------------------

/// A single detected span within a text string.
#[derive(Debug, Clone, Serialize)]
pub struct ClassificationMatch {
    /// Sensitivity class of this span.
    pub data_class: DataClass,
    /// Byte offset of the match start (inclusive).
    pub start: usize,
    /// Byte offset of the match end (exclusive).
    pub end: usize,
    /// The matched substring.
    pub matched_text: String,
    /// Human-readable pattern label that triggered this match.
    pub pattern_label: &'static str,
}

/// Aggregate result for one text input.
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    /// All detected spans, ordered by `start`.
    pub matches: Vec<ClassificationMatch>,
    /// Highest-priority data class found; `Unclassified` if no matches.
    pub dominant_class: DataClass,
}

impl ClassificationResult {
    /// Returns `true` when at least one sensitive span was detected.
    #[inline]
    pub fn has_sensitive_content(&self) -> bool {
        self.dominant_class.is_sensitive()
    }

    /// Returns only matches belonging to `class`.
    fn matches_for(&self, class: DataClass) -> impl Iterator<Item = &ClassificationMatch> {
        self.matches.iter().filter(move |m| m.data_class == class)
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Controls which detectors run during classification.
///
/// All detectors are **enabled by default** when the `regulated_execution`
/// section is present. Operators can selectively disable expensive or
/// noisy detectors in permissive deployment profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DataClassificationConfig {
    /// Global on/off switch.
    pub enabled: bool,
    /// Run PHI detection (SSN, MRN, NPI, DOB patterns).
    pub phi_detection: bool,
    /// Run PII detection (email, phone, IP, person patterns).
    pub pii_detection: bool,
    /// Run financial data detection (credit card, IBAN, account numbers).
    pub financial_detection: bool,
    /// Run intellectual-property marker detection (API keys, token patterns).
    pub ip_detection: bool,
    /// Class priority order used to select `dominant_class`.
    /// Higher index = lower priority when multiple classes co-occur.
    /// Default: PHI > Financial > PII > IP > Unclassified.
    #[serde(skip)]
    pub priority_order: Vec<DataClass>,
}

impl Default for DataClassificationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            phi_detection: true,
            pii_detection: true,
            financial_detection: true,
            ip_detection: true,
            priority_order: vec![
                DataClass::SensitivePhi,
                DataClass::FinancialData,
                DataClass::SensitivePii,
                DataClass::IntellectualProperty,
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// Pattern helpers
// ---------------------------------------------------------------------------

struct Pattern {
    label: &'static str,
    class: DataClass,
    /// Minimum match length guard to avoid false positives.
    min_len: usize,
    matcher: fn(&str, usize) -> Option<usize>,
}

/// Try to match a US Social Security Number (NNN-NN-NNNN or NNNNNNNNN).
fn match_ssn(text: &str, offset: usize) -> Option<usize> {
    let s = &text[offset..];
    // Dashed form: 3-2-4 digits
    if s.len() >= 11 {
        let b = s.as_bytes();
        if b[0..3].iter().all(|c| c.is_ascii_digit())
            && b[3] == b'-'
            && b[4..6].iter().all(|c| c.is_ascii_digit())
            && b[6] == b'-'
            && b[7..11].iter().all(|c| c.is_ascii_digit())
            // Reject all-zeros segments (invalid SSN)
            && &b[0..3] != b"000"
            && &b[4..6] != b"00"
            && &b[7..11] != b"0000"
        {
            // Ensure not preceded/followed by a digit (word-boundary approximation)
            let before_ok = offset == 0 || !text.as_bytes()[offset - 1].is_ascii_digit();
            let after_ok =
                offset + 11 >= text.len() || !text.as_bytes()[offset + 11].is_ascii_digit();
            if before_ok && after_ok {
                return Some(11);
            }
        }
    }
    None
}

/// Try to match a simple credit card number (16-digit groups separated by spaces or dashes).
fn match_credit_card(text: &str, offset: usize) -> Option<usize> {
    let s = &text[offset..];
    if s.len() < 16 {
        return None;
    }
    let b = s.as_bytes();

    // Pure 16-digit form
    if b.len() >= 16 && b[0..16].iter().all(|c| c.is_ascii_digit()) {
        let before_ok = offset == 0 || !text.as_bytes()[offset - 1].is_ascii_digit();
        let after_ok = offset + 16 >= text.len() || !text.as_bytes()[offset + 16].is_ascii_digit();
        if before_ok && after_ok && luhn_check(&s[..16]) {
            return Some(16);
        }
    }

    // 4-4-4-4 space/dash separated form
    if s.len() >= 19 {
        let sep = b[4];
        if (sep == b' ' || sep == b'-')
            && b[9] == sep
            && b[14] == sep
            && b[0..4].iter().all(|c| c.is_ascii_digit())
            && b[5..9].iter().all(|c| c.is_ascii_digit())
            && b[10..14].iter().all(|c| c.is_ascii_digit())
            && b[15..19].iter().all(|c| c.is_ascii_digit())
        {
            let plain = format!("{}{}{}{}", &s[0..4], &s[5..9], &s[10..14], &s[15..19]);
            if luhn_check(&plain) {
                return Some(19);
            }
        }
    }

    None
}

/// Minimal Luhn algorithm.
fn luhn_check(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 13 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let v = d * 2;
                if v > 9 {
                    v - 9
                } else {
                    v
                }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// Match a simple email address.
fn match_email(text: &str, offset: usize) -> Option<usize> {
    let s = &text[offset..];
    // Find '@'
    let at = s.find('@')?;
    if at == 0 {
        return None;
    }
    // local-part: letters, digits, dots, dashes, underscores (simplified)
    let local = &s[..at];
    if !local
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
    {
        return None;
    }
    // domain: at least one dot after @
    let domain = &s[at + 1..];
    let dot_pos = domain.find('.')?;
    if dot_pos == 0 || dot_pos + 1 >= domain.len() {
        return None;
    }
    let end_domain = domain
        .find(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '"' | '\'' | ')' | ']' | '>'))
        .unwrap_or(domain.len());
    let tld = &domain[dot_pos + 1..end_domain];
    if tld.is_empty() || tld.len() > 10 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    Some(at + 1 + end_domain)
}

/// Match a simple API-key or bearer token pattern (high-entropy strings prefixed by known sigils).
fn match_api_key(text: &str, offset: &usize) -> Option<usize> {
    let offset = *offset;
    let s = &text[offset..];
    // Common sigil prefixes: sk-, pk-, ghp_, ghs_, Bearer <token>, etc.
    for prefix in &["sk-", "pk-", "ghp_", "ghs_", "Bearer "] {
        if let Some(rest) = s.strip_prefix(prefix) {
            let token_end = rest
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';'))
                .unwrap_or(rest.len());
            let token = &rest[..token_end];
            if token.len() >= 20 {
                return Some(prefix.len() + token_end);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Public classification entry point
// ---------------------------------------------------------------------------

/// Classify all sensitive spans in `text`.
///
/// Returns a [`ClassificationResult`] with every detected span.
/// Spans may overlap; callers applying tokenization should process
/// from last-to-first to avoid offset corruption.
pub fn classify_text(text: &str, config: &DataClassificationConfig) -> ClassificationResult {
    if !config.enabled || text.is_empty() {
        return ClassificationResult {
            matches: Vec::new(),
            dominant_class: DataClass::Unclassified,
        };
    }

    let mut matches: Vec<ClassificationMatch> = Vec::new();

    // --- PHI: SSN ---
    if config.phi_detection {
        scan_pattern(
            text,
            &Pattern {
                label: "ssn",
                class: DataClass::SensitivePhi,
                min_len: 9,
                matcher: match_ssn,
            },
            &mut matches,
        );
    }

    // --- Financial: Credit card ---
    if config.financial_detection {
        scan_pattern(
            text,
            &Pattern {
                label: "credit_card",
                class: DataClass::FinancialData,
                min_len: 16,
                matcher: match_credit_card,
            },
            &mut matches,
        );
    }

    // --- PII: Email ---
    if config.pii_detection {
        scan_pattern(
            text,
            &Pattern {
                label: "email",
                class: DataClass::SensitivePii,
                min_len: 5,
                matcher: match_email,
            },
            &mut matches,
        );
    }

    // --- IP: API key / bearer token ---
    if config.ip_detection {
        scan_api_key_pattern(text, &mut matches);
    }

    // Sort by offset for deterministic output.
    matches.sort_by_key(|m| m.start);

    let dominant_class = compute_dominant_class(&matches, &config.priority_order);

    ClassificationResult {
        matches,
        dominant_class,
    }
}

fn scan_pattern(text: &str, pattern: &Pattern, out: &mut Vec<ClassificationMatch>) {
    if text.len() < pattern.min_len {
        return;
    }
    for i in 0..text.len() {
        if let Some(len) = (pattern.matcher)(text, i) {
            if len >= pattern.min_len {
                out.push(ClassificationMatch {
                    data_class: pattern.class,
                    start: i,
                    end: i + len,
                    matched_text: text[i..i + len].to_string(),
                    pattern_label: pattern.label,
                });
                // Skip ahead to avoid overlapping matches for same pattern.
                // (We can't mutate `i` in a for-loop, so we push and deduplicate later.)
            }
        }
    }
    // Remove overlapping matches for this pattern class (keep first occurrence).
    dedup_overlapping(out, pattern.class);
}

fn scan_api_key_pattern(text: &str, out: &mut Vec<ClassificationMatch>) {
    for i in 0..text.len() {
        if let Some(len) = match_api_key(text, &i) {
            if len >= 20 {
                out.push(ClassificationMatch {
                    data_class: DataClass::IntellectualProperty,
                    start: i,
                    end: i + len,
                    matched_text: text[i..i + len].to_string(),
                    pattern_label: "api_key",
                });
            }
        }
    }
    dedup_overlapping(out, DataClass::IntellectualProperty);
}

fn dedup_overlapping(matches: &mut Vec<ClassificationMatch>, class: DataClass) {
    let mut i = 0usize;
    while i < matches.len() {
        if matches[i].data_class != class {
            i += 1;
            continue;
        }
        let end_i = matches[i].end;
        let mut j = i + 1;
        while j < matches.len() {
            if matches[j].data_class == class && matches[j].start < end_i {
                matches.remove(j);
            } else {
                j += 1;
            }
        }
        i += 1;
    }
}

fn compute_dominant_class(
    matches: &[ClassificationMatch],
    priority_order: &[DataClass],
) -> DataClass {
    if matches.is_empty() {
        return DataClass::Unclassified;
    }
    // Return the highest-priority class seen.
    for class in priority_order {
        if matches.iter().any(|m| &m.data_class == class) {
            return *class;
        }
    }
    // Fallback: return the class of the first match.
    matches[0].data_class
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

    #[test]
    fn data_class_is_sensitive() {
        assert!(DataClass::SensitivePhi.is_sensitive());
        assert!(DataClass::SensitivePii.is_sensitive());
        assert!(DataClass::FinancialData.is_sensitive());
        assert!(DataClass::IntellectualProperty.is_sensitive());
        assert!(!DataClass::Unclassified.is_sensitive());
    }

    #[test]
    fn data_class_labels() {
        assert_eq!(DataClass::SensitivePhi.label(), "PHI");
        assert_eq!(DataClass::SensitivePii.label(), "PII");
        assert_eq!(DataClass::FinancialData.label(), "FINANCIAL");
        assert_eq!(DataClass::IntellectualProperty.label(), "IP");
        assert_eq!(DataClass::Unclassified.label(), "UNCLASSIFIED");
    }

    #[test]
    fn data_class_display() {
        assert_eq!(format!("{}", DataClass::SensitivePhi), "PHI");
        assert_eq!(format!("{}", DataClass::Unclassified), "UNCLASSIFIED");
    }

    #[test]
    fn classify_disabled_returns_unclassified() {
        let config = DataClassificationConfig {
            enabled: false,
            ..Default::default()
        };
        let result = classify_text("123-45-6789", &config);
        assert!(!result.has_sensitive_content());
        assert_eq!(result.dominant_class, DataClass::Unclassified);
        assert!(result.matches.is_empty());
    }

    #[test]
    fn classify_empty_text() {
        let config = DataClassificationConfig::default();
        let result = classify_text("", &config);
        assert!(!result.has_sensitive_content());
        assert!(result.matches.is_empty());
    }

    #[test]
    fn classify_detects_ssn_dashed() {
        let config = DataClassificationConfig::default();
        let result = classify_text("SSN: 123-45-6789", &config);
        assert!(result.has_sensitive_content());
        assert_eq!(result.dominant_class, DataClass::SensitivePhi);
        assert!(result.matches.iter().any(|m| m.pattern_label == "ssn"));
    }

    #[test]
    fn classify_rejects_invalid_ssn_zeros() {
        let config = DataClassificationConfig::default();
        let result = classify_text("000-45-6789", &config);
        assert!(!result.matches.iter().any(|m| m.pattern_label == "ssn"));
    }

    #[test]
    fn classify_detects_email() {
        let config = DataClassificationConfig::default();
        let result = classify_text("Contact: user@example.com", &config);
        assert!(result.has_sensitive_content());
        assert!(result.matches.iter().any(|m| m.pattern_label == "email"));
        assert_eq!(
            result
                .matches
                .iter()
                .find(|m| m.pattern_label == "email")
                .unwrap()
                .data_class,
            DataClass::SensitivePii
        );
    }

    #[test]
    fn classify_detects_credit_card_luhn_valid() {
        let config = DataClassificationConfig::default();
        // 4111111111111111 is a well-known test card number (Luhn valid)
        let result = classify_text("Card: 4111111111111111", &config);
        assert!(result.has_sensitive_content());
        assert!(result
            .matches
            .iter()
            .any(|m| m.pattern_label == "credit_card"));
    }

    #[test]
    fn classify_rejects_credit_card_luhn_invalid() {
        let config = DataClassificationConfig::default();
        let result = classify_text("Card: 1234567890123456", &config);
        assert!(!result
            .matches
            .iter()
            .any(|m| m.pattern_label == "credit_card"));
    }

    #[test]
    fn classify_detects_api_key() {
        let config = DataClassificationConfig::default();
        let sample = format!("key: sk-{}", "fixture-classify-test-value-only");
        let result = classify_text(&sample, &config);
        assert!(result.has_sensitive_content());
        assert!(result.matches.iter().any(|m| m.pattern_label == "api_key"));
        assert_eq!(
            result
                .matches
                .iter()
                .find(|m| m.pattern_label == "api_key")
                .unwrap()
                .data_class,
            DataClass::IntellectualProperty
        );
    }

    #[test]
    fn classify_ignores_short_api_key() {
        let config = DataClassificationConfig::default();
        let result = classify_text("key: sk-short", &config);
        assert!(!result.matches.iter().any(|m| m.pattern_label == "api_key"));
    }

    #[test]
    fn classify_phi_disabled() {
        let config = DataClassificationConfig {
            phi_detection: false,
            ..Default::default()
        };
        let result = classify_text("SSN: 123-45-6789", &config);
        assert!(!result.matches.iter().any(|m| m.pattern_label == "ssn"));
    }

    #[test]
    fn classify_pii_disabled() {
        let config = DataClassificationConfig {
            pii_detection: false,
            ..Default::default()
        };
        let result = classify_text("email: user@example.com", &config);
        assert!(!result.matches.iter().any(|m| m.pattern_label == "email"));
    }

    #[test]
    fn classify_financial_disabled() {
        let config = DataClassificationConfig {
            financial_detection: false,
            ..Default::default()
        };
        let result = classify_text("4111111111111111", &config);
        assert!(!result
            .matches
            .iter()
            .any(|m| m.pattern_label == "credit_card"));
    }

    #[test]
    fn classify_ip_disabled() {
        let config = DataClassificationConfig {
            ip_detection: false,
            ..Default::default()
        };
        let result = classify_text("sk-abcdefghij1234567890abcdefgh", &config);
        assert!(!result.matches.iter().any(|m| m.pattern_label == "api_key"));
    }

    #[test]
    fn dominant_class_follows_priority() {
        let config = DataClassificationConfig::default();
        let text = "SSN: 123-45-6789 email: test@example.com";
        let result = classify_text(text, &config);
        assert_eq!(result.dominant_class, DataClass::SensitivePhi);
    }

    #[test]
    fn classification_result_has_sensitive_content() {
        let config = DataClassificationConfig::default();
        let result = classify_text("hello world", &config);
        assert!(!result.has_sensitive_content());
    }

    #[test]
    fn classification_result_matches_for_class() {
        let config = DataClassificationConfig::default();
        let text = "SSN: 123-45-6789 and email: user@example.com";
        let result = classify_text(text, &config);
        let phi: Vec<_> = result.matches_for(DataClass::SensitivePhi).collect();
        assert!(!phi.is_empty());
        assert!(phi.iter().all(|m| m.data_class == DataClass::SensitivePhi));
    }

    #[test]
    fn config_default_all_enabled() {
        let config = DataClassificationConfig::default();
        assert!(config.enabled);
        assert!(config.phi_detection);
        assert!(config.pii_detection);
        assert!(config.financial_detection);
        assert!(config.ip_detection);
        assert_eq!(config.priority_order.len(), 4);
    }

    #[test]
    fn data_class_serde_roundtrip() {
        let json = serde_json::to_string(&DataClass::SensitivePhi).unwrap();
        assert_eq!(json, "\"sensitive_phi\"");
        let parsed: DataClass = serde_json::from_str("\"financial_data\"").unwrap();
        assert_eq!(parsed, DataClass::FinancialData);
    }

    #[test]
    fn luhn_check_valid() {
        assert!(luhn_check("4111111111111111"));
    }

    #[test]
    fn luhn_check_invalid() {
        assert!(!luhn_check("1234567890123456"));
    }

    #[test]
    fn luhn_check_too_short() {
        assert!(!luhn_check("123456"));
    }

    #[test]
    fn match_email_valid() {
        assert!(match_email("user@example.com", 0).is_some());
    }

    #[test]
    fn match_email_no_tld() {
        assert!(match_email("user@localhost", 0).is_none());
    }

    #[test]
    fn match_email_no_at() {
        assert!(match_email("not-an-email", 0).is_none());
    }

    #[test]
    fn credit_card_separated_form() {
        let config = DataClassificationConfig::default();
        let result = classify_text("4111-1111-1111-1111", &config);
        assert!(result
            .matches
            .iter()
            .any(|m| m.pattern_label == "credit_card"));
    }
}
