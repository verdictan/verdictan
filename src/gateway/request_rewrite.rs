// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use super::{
    enforcement::{PolicyResult, Verdict},
    rewrite::{apply_rules, RewritePosition, RewriteRule},
};

pub struct RequestRewriteEval {
    pub policy_result: PolicyResult,
    pub rewritten_request: Option<Value>,
}

pub fn evaluate_request_rewriter(request_json: &Value, cfg: &Value) -> RequestRewriteEval {
    crate::telemetry::with_policy_span("request-rewriter", "input", |span| {
        let eval = evaluate_request_rewriter_inner(request_json, cfg);
        crate::telemetry::annotate_policy_result_span(span, &eval.policy_result);
        eval
    })
}

fn evaluate_request_rewriter_inner(request_json: &Value, cfg: &Value) -> RequestRewriteEval {
    let config = config_from_value(cfg);
    let mut rewritten = request_json.clone();
    let system_message_applied = config
        .system_message
        .as_deref()
        .map(|message| inject_system_message(&mut rewritten, message))
        .unwrap_or(false);
    let rules_applied = rewrite_request_fields(&mut rewritten, &config.rules);
    let changed = system_message_applied || rules_applied > 0;

    RequestRewriteEval {
        policy_result: PolicyResult {
            policy_kind: "request-rewriter".to_string(),
            phase: "input".to_string(),
            verdict: Verdict::Allow,
            reason_code: if changed {
                "request_rewriter.applied".to_string()
            } else {
                "request_rewriter.no_match".to_string()
            },
            details: Some(serde_json::json!({
                "rules_evaluated": config.rules.len(),
                "rules_applied": rules_applied,
                "system_message_applied": system_message_applied,
            })),
            redaction_targets: None,
        },
        rewritten_request: if changed { Some(rewritten) } else { None },
    }
}

#[derive(Debug, Clone)]
struct RequestRewriteConfig {
    rules: Vec<RewriteRule>,
    system_message: Option<String>,
}

fn config_from_value(cfg: &Value) -> RequestRewriteConfig {
    let rules = cfg
        .get("rules")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .map(|rule| RewriteRule {
                    name: rule
                        .get("name")
                        .and_then(|value| value.as_str())
                        .unwrap_or("unnamed")
                        .to_string(),
                    pattern: rule
                        .get("pattern")
                        .and_then(|value| value.as_str())
                        .unwrap_or("")
                        .to_string(),
                    replacement: rule
                        .get("replacement")
                        .and_then(|value| value.as_str())
                        .unwrap_or("")
                        .to_string(),
                    position: match rule.get("position").and_then(|value| value.as_str()) {
                        Some("prepend") => RewritePosition::Prepend,
                        Some("append") => RewritePosition::Append,
                        _ => RewritePosition::Replace,
                    },
                    condition: rule
                        .get("condition")
                        .and_then(|value| value.as_str())
                        .map(ToOwned::to_owned),
                })
                .collect()
        })
        .unwrap_or_default();

    let system_message = cfg
        .get("system_message")
        .and_then(|value| match value {
            Value::String(text) => Some(text.clone()),
            Value::Object(map) => map
                .get("content")
                .and_then(|candidate| candidate.as_str())
                .map(ToOwned::to_owned),
            _ => None,
        })
        .filter(|value| !value.trim().is_empty());

    RequestRewriteConfig {
        rules,
        system_message,
    }
}

fn rewrite_request_fields(request_json: &mut Value, rules: &[RewriteRule]) -> usize {
    let mut applied = 0usize;
    applied += rewrite_message_array(request_json.get_mut("messages"), rules);
    applied += rewrite_responses_input(request_json.get_mut("input"), rules);
    applied
}

fn rewrite_message_array(messages: Option<&mut Value>, rules: &[RewriteRule]) -> usize {
    let Some(messages) = messages.and_then(|value| value.as_array_mut()) else {
        return 0;
    };

    let mut applied = 0usize;
    for message in messages {
        let Some(content) = message.get_mut("content") else {
            continue;
        };
        let Some(text) = content.as_str() else {
            continue;
        };
        let (rewritten, count) = apply_rules(text, rules);
        if count > 0 {
            *content = Value::String(rewritten);
            applied += count;
        }
    }

    applied
}

fn rewrite_responses_input(input: Option<&mut Value>, rules: &[RewriteRule]) -> usize {
    let Some(input) = input else {
        return 0;
    };

    if let Some(text) = input.as_str() {
        let (rewritten, count) = apply_rules(text, rules);
        if count > 0 {
            *input = Value::String(rewritten);
        }
        return count;
    }

    let Some(items) = input.as_array_mut() else {
        return 0;
    };

    let mut applied = 0usize;
    for item in items {
        if let Some(text) = item.as_str() {
            let (rewritten, count) = apply_rules(text, rules);
            if count > 0 {
                *item = Value::String(rewritten);
                applied += count;
            }
            continue;
        }

        let Some(content) = item.get_mut("content") else {
            continue;
        };
        let Some(text) = content.as_str() else {
            continue;
        };
        let (rewritten, count) = apply_rules(text, rules);
        if count > 0 {
            *content = Value::String(rewritten);
            applied += count;
        }
    }

    applied
}

fn inject_system_message(request_json: &mut Value, content: &str) -> bool {
    if inject_chat_system_message(request_json, content) {
        return true;
    }

    inject_responses_system_message(request_json, content)
}

fn inject_chat_system_message(request_json: &mut Value, content: &str) -> bool {
    let Some(messages) = request_json
        .get_mut("messages")
        .and_then(|value| value.as_array_mut())
    else {
        return false;
    };

    for message in messages.iter_mut() {
        let role = message
            .get("role")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if role != "system" {
            continue;
        }
        if let Some(existing) = message.get_mut("content") {
            if let Some(text) = existing.as_str() {
                if text.contains(content) {
                    return false;
                }
                *existing = Value::String(format!("{text}\n\n{content}"));
                return true;
            }
        }
    }

    messages.insert(
        0,
        serde_json::json!({
            "role": "system",
            "content": content,
        }),
    );
    true
}

fn inject_responses_system_message(request_json: &mut Value, content: &str) -> bool {
    let Some(input) = request_json.get_mut("input") else {
        return false;
    };

    if let Some(text) = input.as_str() {
        *input = serde_json::json!([
            { "role": "system", "content": content },
            { "role": "user", "content": text }
        ]);
        return true;
    }

    let Some(items) = input.as_array_mut() else {
        return false;
    };

    for item in items.iter_mut() {
        let role = item
            .get("role")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if role != "system" {
            continue;
        }
        if let Some(existing) = item.get_mut("content") {
            if let Some(text) = existing.as_str() {
                if text.contains(content) {
                    return false;
                }
                *existing = Value::String(format!("{text}\n\n{content}"));
                return true;
            }
        }
    }

    items.insert(
        0,
        serde_json::json!({ "role": "system", "content": content }),
    );
    true
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
    fn config_from_value_parses_positions_and_object_system_message() {
        let cfg = serde_json::json!({
            "system_message": { "content": "Follow company policy." },
            "rules": [
                {
                    "name": "prepend-note",
                    "pattern": "^",
                    "replacement": "NOTICE: ",
                    "position": "prepend",
                    "condition": "user"
                },
                {
                    "name": "append-note",
                    "pattern": "$",
                    "replacement": " [checked]",
                    "position": "append"
                },
                {
                    "name": "replace-secret",
                    "pattern": "secret",
                    "replacement": "public"
                }
            ]
        });

        let parsed = config_from_value(&cfg);
        assert_eq!(
            parsed.system_message.as_deref(),
            Some("Follow company policy.")
        );
        assert_eq!(parsed.rules.len(), 3);
        assert!(matches!(parsed.rules[0].position, RewritePosition::Prepend));
        assert!(matches!(parsed.rules[1].position, RewritePosition::Append));
        assert!(matches!(parsed.rules[2].position, RewritePosition::Replace));
        assert_eq!(parsed.rules[0].condition.as_deref(), Some("user"));
    }

    #[test]
    fn evaluate_request_rewriter_returns_no_match_when_no_changes_apply() {
        let request = serde_json::json!({
            "messages": [{ "role": "user", "content": "hello world" }]
        });
        let cfg = serde_json::json!({
            "system_message": "   ",
            "rules": [{
                "name": "unused",
                "pattern": "goodbye",
                "replacement": "hello"
            }]
        });

        let eval = evaluate_request_rewriter_inner(&request, &cfg);
        assert_eq!(eval.policy_result.reason_code, "request_rewriter.no_match");
        assert!(eval.rewritten_request.is_none());
        assert_eq!(
            eval.policy_result.details,
            Some(serde_json::json!({
                "rules_evaluated": 1,
                "rules_applied": 0,
                "system_message_applied": false,
            }))
        );
    }

    #[test]
    fn inject_chat_system_message_appends_once_to_existing_system_prompt() {
        let mut request = serde_json::json!({
            "messages": [
                { "role": "system", "content": "Existing system guidance." },
                { "role": "user", "content": "question" }
            ]
        });

        assert!(inject_chat_system_message(
            &mut request,
            "Follow company policy."
        ));
        assert!(!inject_chat_system_message(
            &mut request,
            "Follow company policy."
        ));
        assert_eq!(
            request["messages"][0]["content"],
            "Existing system guidance.\n\nFollow company policy."
        );
    }

    #[test]
    fn inject_responses_system_message_wraps_string_input_and_deduplicates_existing_system_item() {
        let mut string_request = serde_json::json!({
            "input": "original user input"
        });

        assert!(inject_responses_system_message(
            &mut string_request,
            "System guardrail"
        ));
        assert_eq!(
            string_request["input"],
            serde_json::json!([
                { "role": "system", "content": "System guardrail" },
                { "role": "user", "content": "original user input" }
            ])
        );

        let mut array_request = serde_json::json!({
            "input": [
                { "role": "system", "content": "Existing policy" },
                { "role": "user", "content": "question" }
            ]
        });
        assert!(inject_responses_system_message(
            &mut array_request,
            "Additional policy"
        ));
        assert!(!inject_responses_system_message(
            &mut array_request,
            "Additional policy"
        ));
        assert_eq!(
            array_request["input"][0]["content"],
            "Existing policy\n\nAdditional policy"
        );
    }

    #[test]
    fn rewrite_request_fields_updates_strings_and_content_objects_only() {
        let mut request = serde_json::json!({
            "messages": [
                { "role": "user", "content": "remove secret" },
                { "role": "assistant", "content": ["not a string"] },
                { "role": "assistant" }
            ],
            "input": [
                "remove secret again",
                { "role": "user", "content": "secret appears here too" },
                { "role": "tool", "content": { "nested": "ignored" } }
            ]
        });
        let rules = vec![RewriteRule {
            name: "replace-secret".to_string(),
            pattern: "secret".to_string(),
            replacement: "public".to_string(),
            position: RewritePosition::Replace,
            condition: None,
        }];

        let applied = rewrite_request_fields(&mut request, &rules);

        assert_eq!(applied, 3);
        assert_eq!(request["messages"][0]["content"], "remove public");
        assert_eq!(request["input"][0], "remove public again");
        assert_eq!(request["input"][1]["content"], "public appears here too");
        assert_eq!(
            request["messages"][1]["content"],
            serde_json::json!(["not a string"])
        );
        assert_eq!(
            request["input"][2]["content"],
            serde_json::json!({ "nested": "ignored" })
        );
    }
}
