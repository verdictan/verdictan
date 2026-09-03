// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

/// Strategy for reducing context when it exceeds a provider's limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Remove the middle messages, keeping system + first user + last N.
    MiddleOut,
    /// Remove the oldest non-system messages first.
    OldestFirst,
}

/// Rough character-to-token estimation: ceil(chars / 4).
pub fn estimate_tokens(text: &str) -> usize {
    text.len().div_ceil(4)
}

/// Estimate total tokens for a messages array.
pub fn estimate_messages_tokens(messages: &[Value]) -> usize {
    messages
        .iter()
        .map(|m| {
            let content = m
                .get("content")
                .and_then(|c| c.as_str())
                .unwrap_or_default();
            let role = m.get("role").and_then(|r| r.as_str()).unwrap_or_default();
            // Role + content + overhead per message (~4 tokens).
            estimate_tokens(role) + estimate_tokens(content) + 4
        })
        .sum()
}

/// Compress a messages array to fit within `max_tokens` using the given strategy.
/// Returns `None` if already within limit.
pub fn compress_messages(
    messages: &[Value],
    max_tokens: usize,
    strategy: Strategy,
) -> Option<Vec<Value>> {
    let current = estimate_messages_tokens(messages);
    if current <= max_tokens {
        return None; // No compression needed.
    }

    Some(match strategy {
        Strategy::MiddleOut => middle_out(messages, max_tokens),
        Strategy::OldestFirst => oldest_first(messages, max_tokens),
    })
}

/// Middle-out: keep system messages + first user message + last N messages.
/// Drops from the middle until under budget.
fn middle_out(messages: &[Value], max_tokens: usize) -> Vec<Value> {
    if messages.is_empty() {
        return vec![];
    }

    // Separate system messages (at the beginning).
    let system_count = messages
        .iter()
        .take_while(|m| m.get("role").and_then(|r| r.as_str()) == Some("system"))
        .count();

    let system_messages = &messages[..system_count];
    let non_system = &messages[system_count..];

    if non_system.is_empty() {
        // Only system messages — just return them all.
        return messages.to_vec();
    }

    // Keep first non-system message (usually first user prompt).
    let first_msg = &non_system[0];
    let rest = &non_system[1..];

    // Build from the tail: add messages from the end until we'd exceed budget.
    let system_tokens: usize = system_messages.iter().map(message_tokens).sum();
    let first_tokens = message_tokens(first_msg);
    let base_budget = system_tokens + first_tokens;

    if base_budget >= max_tokens {
        // Can't even fit system + first — return just system + first.
        let mut result = system_messages.to_vec();
        result.push(first_msg.clone());
        return result;
    }

    let remaining_budget = max_tokens - base_budget;
    let mut tail_messages: Vec<Value> = Vec::new();
    let mut tail_tokens = 0usize;

    for m in rest.iter().rev() {
        let t = message_tokens(m);
        if tail_tokens + t > remaining_budget {
            break;
        }
        tail_tokens += t;
        tail_messages.push(m.clone());
    }
    tail_messages.reverse();

    let mut result = system_messages.to_vec();
    result.push(first_msg.clone());
    result.extend(tail_messages);
    result
}

/// Oldest-first: remove non-system messages from the front until under budget.
fn oldest_first(messages: &[Value], max_tokens: usize) -> Vec<Value> {
    if messages.is_empty() {
        return vec![];
    }

    let system_count = messages
        .iter()
        .take_while(|m| m.get("role").and_then(|r| r.as_str()) == Some("system"))
        .count();

    let system_messages = &messages[..system_count];
    let non_system = &messages[system_count..];

    let system_tokens: usize = system_messages.iter().map(message_tokens).sum();

    if system_tokens >= max_tokens {
        return system_messages.to_vec();
    }

    let remaining_budget = max_tokens - system_tokens;

    // Walk non-system from the end, accumulating until budget is reached.
    let mut kept: Vec<Value> = Vec::new();
    let mut kept_tokens = 0usize;

    for m in non_system.iter().rev() {
        let t = message_tokens(m);
        if kept_tokens + t > remaining_budget {
            break;
        }
        kept_tokens += t;
        kept.push(m.clone());
    }
    kept.reverse();

    let mut result = system_messages.to_vec();
    result.extend(kept);
    result
}

fn message_tokens(m: &Value) -> usize {
    let content = m
        .get("content")
        .and_then(|c| c.as_str())
        .unwrap_or_default();
    let role = m.get("role").and_then(|r| r.as_str()).unwrap_or_default();
    estimate_tokens(role) + estimate_tokens(content) + 4
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

    fn msg(role: &str, content: &str) -> Value {
        json!({"role": role, "content": content})
    }

    #[test]
    fn estimate_tokens_empty_string() {
        assert_eq!(estimate_tokens(""), 0);
    }

    #[test]
    fn estimate_tokens_short_string() {
        assert_eq!(estimate_tokens("hi"), 1);
        assert_eq!(estimate_tokens("helo"), 1);
        assert_eq!(estimate_tokens("hello"), 2);
    }

    #[test]
    fn estimate_tokens_longer_string() {
        let text = "a".repeat(100);
        assert_eq!(estimate_tokens(&text), 25);
    }

    #[test]
    fn estimate_messages_tokens_empty() {
        assert_eq!(estimate_messages_tokens(&[]), 0);
    }

    #[test]
    fn estimate_messages_tokens_single_message() {
        let messages = vec![msg("user", "hello world")];
        let tokens = estimate_messages_tokens(&messages);
        let expected = estimate_tokens("user") + estimate_tokens("hello world") + 4;
        assert_eq!(tokens, expected);
    }

    #[test]
    fn estimate_messages_tokens_multiple() {
        let messages = vec![msg("system", "you are helpful"), msg("user", "hi")];
        let tokens = estimate_messages_tokens(&messages);
        let m1 = estimate_tokens("system") + estimate_tokens("you are helpful") + 4;
        let m2 = estimate_tokens("user") + estimate_tokens("hi") + 4;
        assert_eq!(tokens, m1 + m2);
    }

    #[test]
    fn compress_messages_returns_none_when_within_limit() {
        let messages = vec![msg("user", "hi")];
        assert!(compress_messages(&messages, 1000, Strategy::MiddleOut).is_none());
    }

    #[test]
    fn compress_messages_middle_out_empty() {
        let result = compress_messages(&[], 0, Strategy::MiddleOut);
        assert!(result.is_none() || result.unwrap().is_empty());
    }

    #[test]
    fn compress_messages_middle_out_keeps_system_and_first() {
        let messages = vec![
            msg("system", "sys"),
            msg("user", "first"),
            msg("assistant", "a".repeat(200).as_str()),
            msg("user", "second"),
            msg("assistant", "last"),
        ];
        let budget = estimate_messages_tokens(&messages[..2]) + 20;
        let result = compress_messages(&messages, budget, Strategy::MiddleOut).unwrap();
        assert_eq!(result[0]["role"], "system");
        assert_eq!(result[1]["role"], "user");
        assert_eq!(result[1]["content"], "first");
    }

    #[test]
    fn compress_messages_middle_out_keeps_tail() {
        let messages = vec![
            msg("system", "sys"),
            msg("user", "first"),
            msg("assistant", "middle1"),
            msg("user", "middle2"),
            msg("assistant", "tail"),
        ];
        let total = estimate_messages_tokens(&messages);
        let budget = total - 5;
        let result = compress_messages(&messages, budget, Strategy::MiddleOut).unwrap();
        assert_eq!(result.first().unwrap()["role"], "system");
        assert_eq!(result.last().unwrap()["content"], "tail");
    }

    #[test]
    fn compress_messages_middle_out_system_only() {
        let messages = vec![msg("system", "sys")];
        let result = compress_messages(&messages, 0, Strategy::MiddleOut).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "system");
    }

    #[test]
    fn compress_messages_oldest_first_removes_old_non_system() {
        let messages = vec![
            msg("system", "sys"),
            msg("user", "old"),
            msg("assistant", "old_reply"),
            msg("user", "new"),
            msg("assistant", "new_reply"),
        ];
        let budget =
            estimate_messages_tokens(&messages[..1]) + estimate_messages_tokens(&messages[3..]);
        let result = compress_messages(&messages, budget, Strategy::OldestFirst).unwrap();
        assert_eq!(result[0]["role"], "system");
        assert!(result.iter().all(|m| m["content"] != "old"));
    }

    #[test]
    fn compress_messages_oldest_first_keeps_system_when_budget_tight() {
        let messages = vec![msg("system", "s"), msg("user", "a".repeat(1000).as_str())];
        let sys_tokens = estimate_messages_tokens(&messages[..1]);
        let result = compress_messages(&messages, sys_tokens, Strategy::OldestFirst).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "system");
    }

    #[test]
    fn compress_messages_oldest_first_empty_input() {
        let result = compress_messages(&[], 0, Strategy::OldestFirst);
        assert!(result.is_none() || result.unwrap().is_empty());
    }

    #[test]
    fn strategy_enum_equality() {
        assert_eq!(Strategy::MiddleOut, Strategy::MiddleOut);
        assert_ne!(Strategy::MiddleOut, Strategy::OldestFirst);
    }
}
