// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

/// Field-level tokenization for the regulated-execution privacy pipeline.
///
/// Replaces classified sensitive spans in text with opaque token placeholders
/// of the form `[TOKEN:<uuid>:<data_class_label>]`. The original values are
/// stored in a `TokenVault` so they can be restored (detokenized) after the
/// provider response if and only if the runtime execution profile permits it.
///
/// Design constraints:
/// - Tokenization is strictly one-way at the edge.
/// - Detokenization is gated by execution profile; by default it is blocked
///   for regulated workloads.
/// - No external network calls; all logic is in-process.
/// - Tokens are UUID-v4 based to guarantee uniqueness within a request.
///
/// Part of the regulated runtime privacy pipeline.
use crate::gateway::data_classification::{ClassificationMatch, ClassificationResult, DataClass};
use crate::gateway::token_vault::TokenVault;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Controls the tokenization pass applied after classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TokenizationConfig {
    /// Enable the tokenization pass. When `false`, classification still runs
    /// but spans are not replaced — metadata is emitted only.
    pub enabled: bool,
    /// String prefix embedded in placeholder tokens for operator readability.
    /// Default: `TOKEN`.
    pub placeholder_prefix: String,
    /// When `true`, the placeholder length approximates the original value
    /// length (padded to nearest 8 chars) to preserve token-budget estimates.
    pub preserve_approximate_length: bool,
    /// Data classes to tokenize. An empty list means "tokenize all sensitive classes".
    pub target_classes: Vec<DataClass>,
}

impl Default for TokenizationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            placeholder_prefix: "TOKEN".to_string(),
            preserve_approximate_length: false,
            target_classes: Vec::new(), // empty = all sensitive
        }
    }
}

impl TokenizationConfig {
    /// Returns `true` if the given data class should be tokenized under this config.
    pub fn should_tokenize(&self, class: DataClass) -> bool {
        if !class.is_sensitive() {
            return false;
        }
        if self.target_classes.is_empty() {
            return true; // all sensitive classes
        }
        self.target_classes.contains(&class)
    }
}

// ---------------------------------------------------------------------------
// Tokenization result
// ---------------------------------------------------------------------------

/// The result of tokenizing a single text string.
#[derive(Debug, Clone)]
pub struct TokenizedText {
    /// The text with sensitive spans replaced by token placeholders.
    pub text: String,
    /// Tokens introduced in this pass. Each entry is `(token_id, original_value, data_class)`.
    pub tokens: Vec<(String, String, DataClass)>,
    /// Total number of spans that were tokenized.
    pub span_count: usize,
}

impl TokenizedText {
    /// Returns `true` when at least one span was tokenized.
    #[inline]
    fn has_replacements(&self) -> bool {
        self.span_count > 0
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Tokenize sensitive spans in `text` based on a pre-computed `ClassificationResult`.
///
/// Each sensitive span matching `config.target_classes` is replaced with an
/// opaque placeholder and stored in `vault`. Spans are processed back-to-front
/// to preserve byte offsets during in-place replacement.
///
/// Returns a [`TokenizedText`] describing the transformed string and the set of
/// new tokens that were introduced.
fn tokenize_classified(
    text: &str,
    classification: &ClassificationResult,
    config: &TokenizationConfig,
    vault: &mut TokenVault,
) -> TokenizedText {
    if !config.enabled || !classification.has_sensitive_content() {
        return TokenizedText {
            text: text.to_string(),
            tokens: Vec::new(),
            span_count: 0,
        };
    }

    // Filter to spans that should be tokenized.
    let mut spans: Vec<&ClassificationMatch> = classification
        .matches
        .iter()
        .filter(|m| config.should_tokenize(m.data_class))
        .collect();

    if spans.is_empty() {
        return TokenizedText {
            text: text.to_string(),
            tokens: Vec::new(),
            span_count: 0,
        };
    }

    // Sort descending by start so we can replace without offset drift.
    spans.sort_by_key(|span| std::cmp::Reverse(span.start));
    // Deduplicate overlapping spans (keep the first occurring one, which is the
    // highest-priority one after our deduplication in classify_text).
    let mut non_overlapping: Vec<&ClassificationMatch> = Vec::new();
    for span in spans {
        if let Some(last) = non_overlapping.last() {
            // Since we're processing in reverse-start order, if this span's end
            // exceeds the last kept span's start, it overlaps — skip.
            if span.end > last.start {
                continue;
            }
        }
        non_overlapping.push(span);
    }

    let mut result = text.to_string();
    let mut introduced: Vec<(String, String, DataClass)> = Vec::new();

    for span in &non_overlapping {
        let original = &text[span.start..span.end];
        let token_id = vault.store(original.to_string(), span.data_class);
        let placeholder = build_placeholder(&config.placeholder_prefix, &token_id, span.data_class);

        // Validate that byte offsets are still valid UTF-8 boundaries.
        if result.is_char_boundary(span.start) && result.is_char_boundary(span.end) {
            result.replace_range(span.start..span.end, &placeholder);
            introduced.push((token_id, original.to_string(), span.data_class));
        } else {
            tracing::warn!(
                start = span.start,
                end = span.end,
                data_class = %span.data_class,
                "tokenization: span boundary is not a valid UTF-8 char boundary; skipping"
            );
        }
    }

    let span_count = introduced.len();

    TokenizedText {
        text: result,
        tokens: introduced,
        span_count,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_placeholder(prefix: &str, token_id: &str, class: DataClass) -> String {
    format!("[{prefix}:{token_id}:{class}]")
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
    fn tokenization_config_default() {
        let config = TokenizationConfig::default();
        assert!(config.enabled);
        assert_eq!(config.placeholder_prefix, "TOKEN");
        assert!(!config.preserve_approximate_length);
        assert!(config.target_classes.is_empty());
    }

    #[test]
    fn should_tokenize_non_sensitive_returns_false() {
        let config = TokenizationConfig::default();
        assert!(!config.should_tokenize(DataClass::Unclassified));
    }

    #[test]
    fn should_tokenize_empty_target_classes_matches_all_sensitive() {
        let config = TokenizationConfig {
            target_classes: Vec::new(),
            ..Default::default()
        };
        assert!(config.should_tokenize(DataClass::SensitivePii));
        assert!(config.should_tokenize(DataClass::SensitivePhi));
        assert!(config.should_tokenize(DataClass::FinancialData));
        assert!(config.should_tokenize(DataClass::IntellectualProperty));
    }

    #[test]
    fn should_tokenize_specific_target_only_matches_configured() {
        let config = TokenizationConfig {
            target_classes: vec![DataClass::SensitivePii],
            ..Default::default()
        };
        assert!(config.should_tokenize(DataClass::SensitivePii));
        assert!(!config.should_tokenize(DataClass::SensitivePhi));
        assert!(!config.should_tokenize(DataClass::FinancialData));
    }

    #[test]
    fn build_placeholder_format() {
        let result = build_placeholder("TOKEN", "abc-123", DataClass::SensitivePii);
        assert_eq!(result, "[TOKEN:abc-123:PII]");
    }

    #[test]
    fn tokenized_text_has_replacements() {
        let tt = TokenizedText {
            text: "redacted".to_string(),
            tokens: vec![(
                "id".to_string(),
                "original".to_string(),
                DataClass::SensitivePii,
            )],
            span_count: 1,
        };
        assert!(tt.has_replacements());
    }

    #[test]
    fn tokenized_text_no_replacements() {
        let tt = TokenizedText {
            text: "unchanged".to_string(),
            tokens: Vec::new(),
            span_count: 0,
        };
        assert!(!tt.has_replacements());
    }

    #[test]
    fn tokenize_classified_disabled_returns_original() {
        let config = TokenizationConfig {
            enabled: false,
            ..Default::default()
        };
        let classification = ClassificationResult {
            matches: vec![ClassificationMatch {
                data_class: DataClass::SensitivePii,
                start: 0,
                end: 5,
                matched_text: "hello".to_string(),
                pattern_label: "test",
            }],
            dominant_class: DataClass::SensitivePii,
        };
        let mut vault = TokenVault::new();
        let result = tokenize_classified("hello world", &classification, &config, &mut vault);
        assert_eq!(result.text, "hello world");
        assert!(!result.has_replacements());
    }

    #[test]
    fn tokenize_classified_no_sensitive_content() {
        let config = TokenizationConfig::default();
        let classification = ClassificationResult {
            matches: vec![],
            dominant_class: DataClass::Unclassified,
        };
        let mut vault = TokenVault::new();
        let result = tokenize_classified("hello world", &classification, &config, &mut vault);
        assert_eq!(result.text, "hello world");
        assert!(!result.has_replacements());
    }

    #[test]
    fn tokenize_classified_replaces_sensitive_span() {
        let config = TokenizationConfig::default();
        let classification = ClassificationResult {
            matches: vec![ClassificationMatch {
                data_class: DataClass::SensitivePii,
                start: 6,
                end: 11,
                matched_text: "world".to_string(),
                pattern_label: "name",
            }],
            dominant_class: DataClass::SensitivePii,
        };
        let mut vault = TokenVault::new();
        let result = tokenize_classified("hello world", &classification, &config, &mut vault);
        assert!(result.has_replacements());
        assert!(result.text.starts_with("hello "));
        assert!(result.text.contains("[TOKEN:"));
        assert_eq!(result.span_count, 1);
    }

    #[test]
    fn tokenize_classified_skips_non_target_class() {
        let config = TokenizationConfig {
            target_classes: vec![DataClass::FinancialData],
            ..Default::default()
        };
        let classification = ClassificationResult {
            matches: vec![ClassificationMatch {
                data_class: DataClass::SensitivePii,
                start: 0,
                end: 5,
                matched_text: "hello".to_string(),
                pattern_label: "test",
            }],
            dominant_class: DataClass::SensitivePii,
        };
        let mut vault = TokenVault::new();
        let result = tokenize_classified("hello world", &classification, &config, &mut vault);
        assert_eq!(result.text, "hello world");
        assert!(!result.has_replacements());
    }
}
