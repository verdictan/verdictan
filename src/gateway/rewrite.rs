// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Generic response rewrite framework (Tier 4).
//!
//! Provides a configurable pipeline for transforming LLM response text before it
//! is returned to the client. Each rewrite rule is a (pattern, replacement)
//! pair with optional conditions.
//!
//! Config example (YAML):
//! ```yaml
//! policy:
//!   response-rewriter:
//!     preserve_structure: true
//!     rules:
//!       - name: "add-disclaimer"
//!         pattern: "(?i)^" # beginning of text
//!         replacement: "[Disclaimer: AI-generated content. Verify independently.]\n\n"
//!         position: "prepend" # prepend | append | replace
//!       - name: "redact-internal-urls"
//!         pattern: "https?://internal\\.corp\\.[a-z]+/[^ ]*"
//!         replacement: "[INTERNAL_URL_REDACTED]"
//! ```

use super::enforcement::{PolicyResult, Verdict};

/// Outcome of applying the rewrite pipeline.
#[allow(dead_code)]
pub struct RewriteEval {
    pub policy_result: PolicyResult,
    /// The possibly-modified response text.
    pub rewritten_text: Option<String>,
    /// Number of rules that actually changed the text.
    pub rules_applied: usize,
}

/// A single rewrite rule.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RewriteRule {
    pub name: String,
    /// Regex pattern to match in the response text.
    pub pattern: String,
    /// Replacement text (supports capture group back-references like $1).
    pub replacement: String,
    /// How to apply: "replace" (default), "prepend", "append".
    pub position: RewritePosition,
    /// Optional: only apply when the response contains this substring.
    pub condition: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewritePosition {
    /// Replace matched text with replacement.
    Replace,
    /// Prepend replacement to the beginning of text (pattern ignored for match location).
    Prepend,
    /// Append replacement to the end of text (pattern ignored for match location).
    Append,
}

/// Configuration for the rewrite pipeline.
#[derive(Debug, Clone)]
pub struct RewriteConfig {
    pub rules: Vec<RewriteRule>,
    /// If true, preserve JSON structure and only rewrite the text content field.
    pub preserve_structure: bool,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Evaluate the response-rewriter policy.
///
/// Returns a `RewriteEval` with the rewritten text (if any rules matched) and
/// a policy result that is always Allow (rewriting never blocks).
pub fn evaluate_response_rewriter(response_text: &str, cfg: &serde_json::Value) -> RewriteEval {
    crate::telemetry::with_policy_span("response-rewriter", "output", |span| {
        let eval = evaluate_response_rewriter_inner(response_text, cfg);
        crate::telemetry::annotate_policy_result_span(span, &eval.policy_result);
        eval
    })
}

fn evaluate_response_rewriter_inner(response_text: &str, cfg: &serde_json::Value) -> RewriteEval {
    let config = config_from_value(cfg);
    let (rewritten, applied) = apply_rules(response_text, &config.rules);

    let changed = applied > 0;

    RewriteEval {
        policy_result: PolicyResult {
            policy_kind: "response-rewriter".to_string(),
            phase: "output".to_string(),
            verdict: Verdict::Allow,
            reason_code: if changed {
                "rewriter.applied".to_string()
            } else {
                "rewriter.no_match".to_string()
            },
            details: Some(serde_json::json!({
                "rules_evaluated": config.rules.len(),
                "rules_applied": applied,
                "preserve_structure": config.preserve_structure,
            })),
            redaction_targets: None,
        },
        rewritten_text: if changed { Some(rewritten) } else { None },
        rules_applied: applied,
    }
}

/// Apply rewrite rules in order, returning (final_text, count_of_applied_rules).
pub fn apply_rules(text: &str, rules: &[RewriteRule]) -> (String, usize) {
    let mut current = text.to_string();
    let mut count = 0usize;

    for rule in rules {
        // Check optional condition.
        if let Some(cond) = &rule.condition {
            if !current
                .to_ascii_lowercase()
                .contains(&cond.to_ascii_lowercase())
            {
                continue;
            }
        }

        match rule.position {
            RewritePosition::Prepend => {
                // Always prepend, but only once – check it hasn't already been added.
                if !current.starts_with(&rule.replacement) {
                    current = format!("{}{}", rule.replacement, current);
                    count += 1;
                }
            }
            RewritePosition::Append => {
                if !current.ends_with(&rule.replacement) {
                    current = format!("{}{}", current, rule.replacement);
                    count += 1;
                }
            }
            RewritePosition::Replace => {
                if let Ok(re) = regex_lite::Regex::new(&rule.pattern) {
                    let before = current.clone();
                    current = re
                        .replace_all(&current, rule.replacement.as_str())
                        .to_string();
                    if current != before {
                        count += 1;
                    }
                }
            }
        }
    }

    (current, count)
}

/// Rewrite the text content inside a JSON response body, preserving the outer structure.
///
/// Supports OpenAI chat-completion format (`choices[0].message.content`) and
/// the Responses API format (`output[*].content[*].text`).
pub fn rewrite_json_response(
    response_bytes: &[u8],
    rules: &[RewriteRule],
) -> Option<(Vec<u8>, usize)> {
    let mut json: serde_json::Value = serde_json::from_slice(response_bytes).ok()?;
    let mut total_applied = 0usize;

    // Chat completions format.
    if let Some(choices) = json.get_mut("choices").and_then(|v| v.as_array_mut()) {
        for choice in choices {
            if let Some(content) = choice
                .get_mut("message")
                .and_then(|m| m.get_mut("content"))
                .and_then(|c| c.as_str())
                .map(|s| s.to_string())
            {
                let (rewritten, n) = apply_rules(&content, rules);
                if n > 0 {
                    choice["message"]["content"] = serde_json::Value::String(rewritten);
                    total_applied += n;
                }
            }
        }
    }

    // Responses API format.
    if let Some(output) = json.get_mut("output").and_then(|v| v.as_array_mut()) {
        for item in output {
            if let Some(content) = item.get_mut("content").and_then(|v| v.as_array_mut()) {
                for part in content {
                    if let Some(text) = part
                        .get("text")
                        .and_then(|t| t.as_str())
                        .map(|s| s.to_string())
                    {
                        let (rewritten, n) = apply_rules(&text, rules);
                        if n > 0 {
                            part["text"] = serde_json::Value::String(rewritten);
                            total_applied += n;
                        }
                    }
                }
            }
        }
    }

    if total_applied > 0 {
        let bytes = serde_json::to_vec(&json).ok()?;
        Some((bytes, total_applied))
    } else {
        None
    }
}

pub fn rewrite_json_response_with_config(
    response_bytes: &[u8],
    cfg: &serde_json::Value,
) -> Option<(Vec<u8>, usize)> {
    let config = config_from_value(cfg);
    rewrite_json_response(response_bytes, &config.rules)
}

// ---------------------------------------------------------------------------
// Config parsing
// ---------------------------------------------------------------------------

pub fn config_from_value(cfg: &serde_json::Value) -> RewriteConfig {
    let preserve_structure = cfg
        .get("preserve_structure")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let rules = cfg
        .get("rules")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|rule| {
                    let name = rule
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unnamed");
                    let pattern = rule.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
                    let replacement = rule
                        .get("replacement")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let position = match rule.get("position").and_then(|v| v.as_str()) {
                        Some("prepend") => RewritePosition::Prepend,
                        Some("append") => RewritePosition::Append,
                        _ => RewritePosition::Replace,
                    };
                    let condition = rule
                        .get("condition")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    RewriteRule {
                        name: name.to_string(),
                        pattern: pattern.to_string(),
                        replacement: replacement.to_string(),
                        position,
                        condition,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    RewriteConfig {
        rules,
        preserve_structure,
    }
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

    fn rule(
        name: &str,
        pattern: &str,
        replacement: &str,
        position: RewritePosition,
    ) -> RewriteRule {
        RewriteRule {
            name: name.into(),
            pattern: pattern.into(),
            replacement: replacement.into(),
            position,
            condition: None,
        }
    }

    // --- apply_rules: Replace ---

    #[test]
    fn replace_substitutes_matching_text() {
        let rules = vec![rule(
            "r",
            r"secret\d+",
            "[REDACTED]",
            RewritePosition::Replace,
        )];
        let (result, count) = apply_rules("my secret123 is here", &rules);
        assert_eq!(result, "my [REDACTED] is here");
        assert_eq!(count, 1);
    }

    #[test]
    fn replace_no_match_yields_zero_count() {
        let rules = vec![rule("r", r"zzz", "ZZZ", RewritePosition::Replace)];
        let (result, count) = apply_rules("hello world", &rules);
        assert_eq!(result, "hello world");
        assert_eq!(count, 0);
    }

    #[test]
    fn replace_multiple_occurrences() {
        let rules = vec![rule("r", r"foo", "bar", RewritePosition::Replace)];
        let (result, count) = apply_rules("foo and foo", &rules);
        assert_eq!(result, "bar and bar");
        assert_eq!(count, 1);
    }

    #[test]
    fn replace_invalid_regex_skipped() {
        let rules = vec![rule("r", r"[invalid", "x", RewritePosition::Replace)];
        let (result, count) = apply_rules("test", &rules);
        assert_eq!(result, "test");
        assert_eq!(count, 0);
    }

    // --- apply_rules: Prepend ---

    #[test]
    fn prepend_adds_to_front() {
        let rules = vec![rule("r", "", "[DISCLAIMER] ", RewritePosition::Prepend)];
        let (result, count) = apply_rules("Hello", &rules);
        assert_eq!(result, "[DISCLAIMER] Hello");
        assert_eq!(count, 1);
    }

    #[test]
    fn prepend_idempotent() {
        let rules = vec![
            rule("r1", "", "PREFIX:", RewritePosition::Prepend),
            rule("r2", "", "PREFIX:", RewritePosition::Prepend),
        ];
        let (result, count) = apply_rules("data", &rules);
        assert_eq!(result, "PREFIX:data");
        assert_eq!(count, 1);
    }

    // --- apply_rules: Append ---

    #[test]
    fn append_adds_to_end() {
        let rules = vec![rule("r", "", " [END]", RewritePosition::Append)];
        let (result, count) = apply_rules("Hello", &rules);
        assert_eq!(result, "Hello [END]");
        assert_eq!(count, 1);
    }

    #[test]
    fn append_idempotent() {
        let rules = vec![
            rule("r1", "", ":SUFFIX", RewritePosition::Append),
            rule("r2", "", ":SUFFIX", RewritePosition::Append),
        ];
        let (result, count) = apply_rules("data", &rules);
        assert_eq!(result, "data:SUFFIX");
        assert_eq!(count, 1);
    }

    // --- apply_rules: Condition ---

    #[test]
    fn condition_skips_when_not_present() {
        let rules = vec![RewriteRule {
            condition: Some("trigger".into()),
            ..rule("r", "x", "y", RewritePosition::Replace)
        }];
        let (result, count) = apply_rules("no match here", &rules);
        assert_eq!(result, "no match here");
        assert_eq!(count, 0);
    }

    #[test]
    fn condition_applies_when_present_case_insensitive() {
        let rules = vec![RewriteRule {
            condition: Some("TRIGGER".into()),
            ..rule("r", "old", "new", RewritePosition::Replace)
        }];
        let (result, count) = apply_rules("trigger old data", &rules);
        assert_eq!(result, "trigger new data");
        assert_eq!(count, 1);
    }

    // --- apply_rules: Multiple rules pipeline ---

    #[test]
    fn multiple_rules_applied_in_order() {
        let rules = vec![
            rule("prepend", "", "[WARN] ", RewritePosition::Prepend),
            rule("replace", r"bad", "good", RewritePosition::Replace),
            rule("append", "", " [EOF]", RewritePosition::Append),
        ];
        let (result, count) = apply_rules("bad data", &rules);
        assert_eq!(result, "[WARN] good data [EOF]");
        assert_eq!(count, 3);
    }

    // --- config_from_value ---

    #[test]
    fn config_from_value_empty_object() {
        let cfg = config_from_value(&serde_json::json!({}));
        assert!(cfg.rules.is_empty());
        assert!(cfg.preserve_structure);
    }

    #[test]
    fn config_from_value_parses_rules() {
        let cfg_val = serde_json::json!({
            "preserve_structure": false,
            "rules": [
                {
                    "name": "disclaimer",
                    "pattern": "^",
                    "replacement": "[AI] ",
                    "position": "prepend"
                },
                {
                    "name": "redact",
                    "pattern": "internal",
                    "replacement": "[REDACTED]"
                }
            ]
        });
        let cfg = config_from_value(&cfg_val);
        assert!(!cfg.preserve_structure);
        assert_eq!(cfg.rules.len(), 2);
        assert_eq!(cfg.rules[0].position, RewritePosition::Prepend);
        assert_eq!(cfg.rules[1].position, RewritePosition::Replace);
    }

    #[test]
    fn config_from_value_append_position() {
        let cfg_val = serde_json::json!({
            "rules": [{"name": "a", "position": "append", "replacement": "X"}]
        });
        let cfg = config_from_value(&cfg_val);
        assert_eq!(cfg.rules[0].position, RewritePosition::Append);
    }

    #[test]
    fn config_from_value_condition_parsed() {
        let cfg_val = serde_json::json!({
            "rules": [{"name": "c", "pattern": "x", "replacement": "y", "condition": "if_present"}]
        });
        let cfg = config_from_value(&cfg_val);
        assert_eq!(cfg.rules[0].condition.as_deref(), Some("if_present"));
    }

    // --- rewrite_json_response ---

    #[test]
    fn rewrite_json_response_chat_completions() {
        let body = serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "Visit https://internal.corp.dev/secret"}}]
        });
        let rules = vec![rule(
            "redact",
            r"https?://internal\.\S+",
            "[REDACTED_URL]",
            RewritePosition::Replace,
        )];
        let bytes = serde_json::to_vec(&body).unwrap();
        let (rewritten, count) = rewrite_json_response(&bytes, &rules).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
        assert_eq!(
            parsed["choices"][0]["message"]["content"],
            "Visit [REDACTED_URL]"
        );
        assert_eq!(count, 1);
    }

    #[test]
    fn rewrite_json_response_responses_api() {
        let body = serde_json::json!({
            "output": [{"content": [{"text": "secret data"}]}]
        });
        let rules = vec![rule("r", "secret", "redacted", RewritePosition::Replace)];
        let bytes = serde_json::to_vec(&body).unwrap();
        let (rewritten, _) = rewrite_json_response(&bytes, &rules).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
        assert_eq!(parsed["output"][0]["content"][0]["text"], "redacted data");
    }

    #[test]
    fn rewrite_json_response_no_match_returns_none() {
        let body = serde_json::json!({"choices": [{"message": {"content": "safe text"}}]});
        let rules = vec![rule("r", "zzz", "xxx", RewritePosition::Replace)];
        let bytes = serde_json::to_vec(&body).unwrap();
        assert!(rewrite_json_response(&bytes, &rules).is_none());
    }

    #[test]
    fn rewrite_json_response_invalid_json_returns_none() {
        let rules = vec![rule("r", "a", "b", RewritePosition::Replace)];
        assert!(rewrite_json_response(b"not json", &rules).is_none());
    }

    // --- RewritePosition equality ---

    #[test]
    fn rewrite_position_eq() {
        assert_eq!(RewritePosition::Replace, RewritePosition::Replace);
        assert_ne!(RewritePosition::Prepend, RewritePosition::Append);
    }
}
