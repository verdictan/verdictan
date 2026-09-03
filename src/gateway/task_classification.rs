// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use axum::http::HeaderMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskClass {
    ReadOnly,
    CodeChange,
    ToolExecution,
    Destructive,
    SecuritySensitive,
    Unknown,
}

pub fn classify_request(value: &serde_json::Value, headers: &HeaderMap) -> TaskClass {
    if let Some(header_class) = headers
        .get("x-verdictan-task-class")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_task_class)
    {
        return header_class;
    }

    let text = request_text(value).to_ascii_lowercase();
    if text.trim().is_empty() {
        return TaskClass::Unknown;
    }

    if contains_any(
        &text,
        &[
            "delete file",
            "remove file",
            "drop table",
            "truncate table",
            "rm -rf",
            "reset --hard",
            "revoke",
            "rotate secret",
            "destroy",
        ],
    ) {
        return TaskClass::Destructive;
    }

    if contains_any(
        &text,
        &[
            "secret",
            "credential",
            "private key",
            "token",
            "vulnerability",
            "exploit",
            "permission",
            "auth bypass",
        ],
    ) {
        return TaskClass::SecuritySensitive;
    }

    if contains_any(
        &text,
        &[
            "apply patch",
            "apply a patch",
            "patch ",
            "edit ",
            "edits ",
            "modify ",
            "write ",
            "create file",
            "migration",
            "refactor",
            "fix ",
            "implement ",
            "generate code",
        ],
    ) {
        return TaskClass::CodeChange;
    }

    if value.get("tools").is_some()
        || value.get("tool_choice").is_some()
        || text.contains("run command")
        || text.contains("execute")
    {
        return TaskClass::ToolExecution;
    }

    if contains_any(
        &text,
        &[
            "explain",
            "summarize",
            "where is",
            "what is",
            "how does",
            "find",
            "show me",
            "list",
            "describe",
        ],
    ) {
        return TaskClass::ReadOnly;
    }

    // Benign prompts that did not match a more specific class are treated as
    // read-only so provider response caching and org-shared tiering can apply.
    TaskClass::ReadOnly
}

fn parse_task_class(value: &str) -> Option<TaskClass> {
    match value.trim().to_ascii_lowercase().as_str() {
        "read_only" | "readonly" => Some(TaskClass::ReadOnly),
        "code_change" | "code-change" => Some(TaskClass::CodeChange),
        "tool_execution" | "tool-execution" => Some(TaskClass::ToolExecution),
        "destructive" => Some(TaskClass::Destructive),
        "security_sensitive" | "security-sensitive" => Some(TaskClass::SecuritySensitive),
        "unknown" => Some(TaskClass::Unknown),
        _ => None,
    }
}

fn request_text(value: &serde_json::Value) -> String {
    let mut parts = Vec::new();
    collect_text(value, &mut parts);
    parts.join("\n")
}

fn collect_text(value: &serde_json::Value, parts: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) => parts.push(text.clone()),
        serde_json::Value::Array(items) => {
            for item in items {
                collect_text(item, parts);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if matches!(
                    key.as_str(),
                    "content" | "prompt" | "input" | "description" | "name"
                ) || value.is_array()
                    || value.is_object()
                {
                    collect_text(value, parts);
                }
            }
        }
        _ => {}
    }
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
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
    use axum::http::HeaderMap;
    use serde_json::json;

    #[test]
    fn classify_request_header_override_readonly() {
        let mut headers = HeaderMap::new();
        headers.insert("x-verdictan-task-class", "read_only".parse().unwrap());
        let value = json!({"messages": [{"content": "rm -rf /"}]});
        assert_eq!(classify_request(&value, &headers), TaskClass::ReadOnly);
    }

    #[test]
    fn classify_request_header_override_destructive() {
        let mut headers = HeaderMap::new();
        headers.insert("x-verdictan-task-class", "destructive".parse().unwrap());
        let value = json!({"messages": [{"content": "explain this"}]});
        assert_eq!(classify_request(&value, &headers), TaskClass::Destructive);
    }

    #[test]
    fn classify_request_header_code_change_variants() {
        let mut headers = HeaderMap::new();
        headers.insert("x-verdictan-task-class", "code_change".parse().unwrap());
        assert_eq!(
            classify_request(&json!({}), &headers),
            TaskClass::CodeChange
        );

        headers.insert("x-verdictan-task-class", "code-change".parse().unwrap());
        assert_eq!(
            classify_request(&json!({}), &headers),
            TaskClass::CodeChange
        );
    }

    #[test]
    fn classify_request_header_tool_execution() {
        let mut headers = HeaderMap::new();
        headers.insert("x-verdictan-task-class", "tool_execution".parse().unwrap());
        assert_eq!(
            classify_request(&json!({}), &headers),
            TaskClass::ToolExecution
        );
    }

    #[test]
    fn classify_request_header_security_sensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-verdictan-task-class",
            "security_sensitive".parse().unwrap(),
        );
        assert_eq!(
            classify_request(&json!({}), &headers),
            TaskClass::SecuritySensitive
        );
    }

    #[test]
    fn classify_request_header_unknown() {
        let mut headers = HeaderMap::new();
        headers.insert("x-verdictan-task-class", "unknown".parse().unwrap());
        assert_eq!(classify_request(&json!({}), &headers), TaskClass::Unknown);
    }

    #[test]
    fn classify_request_invalid_header_falls_through() {
        let mut headers = HeaderMap::new();
        headers.insert("x-verdictan-task-class", "bogus".parse().unwrap());
        let value = json!({"messages": [{"content": "explain this code"}]});
        assert_eq!(classify_request(&value, &headers), TaskClass::ReadOnly);
    }

    #[test]
    fn classify_request_destructive_patterns() {
        let headers = HeaderMap::new();
        for phrase in [
            "delete file x.txt",
            "remove file y.rs",
            "drop table users",
            "truncate table sessions",
            "rm -rf /tmp",
            "reset --hard HEAD",
            "revoke all tokens",
            "rotate secret key",
            "destroy the cluster",
        ] {
            let value = json!({"messages": [{"content": phrase}]});
            assert_eq!(
                classify_request(&value, &headers),
                TaskClass::Destructive,
                "expected Destructive for: {phrase}"
            );
        }
    }

    #[test]
    fn classify_request_security_sensitive_patterns() {
        let headers = HeaderMap::new();
        for phrase in [
            "show me the secret",
            "find credential leak",
            "expose private key",
            "list token values",
            "assess vulnerability",
            "demonstrate exploit",
            "check permission bypass",
            "describe auth bypass",
        ] {
            let value = json!({"messages": [{"content": phrase}]});
            assert_eq!(
                classify_request(&value, &headers),
                TaskClass::SecuritySensitive,
                "expected SecuritySensitive for: {phrase}"
            );
        }
    }

    #[test]
    fn classify_request_code_change_patterns() {
        let headers = HeaderMap::new();
        for phrase in [
            "apply patch to file",
            "edit the function",
            "modify the config",
            "write the implementation",
            "create file main.rs",
            "run migration",
            "refactor the module",
            "fix the bug",
            "implement the feature",
            "generate code for the handler",
        ] {
            let value = json!({"messages": [{"content": phrase}]});
            assert_eq!(
                classify_request(&value, &headers),
                TaskClass::CodeChange,
                "expected CodeChange for: {phrase}"
            );
        }
    }

    #[test]
    fn classify_request_tool_execution_from_tools_field() {
        let headers = HeaderMap::new();
        let value = json!({
            "tools": [{"function": {"name": "search"}}],
            "messages": [{"content": "find the result"}]
        });
        assert_eq!(classify_request(&value, &headers), TaskClass::ToolExecution);
    }

    #[test]
    fn classify_request_tool_execution_from_tool_choice() {
        let headers = HeaderMap::new();
        let value = json!({
            "tool_choice": "auto",
            "messages": [{"content": "do something"}]
        });
        assert_eq!(classify_request(&value, &headers), TaskClass::ToolExecution);
    }

    #[test]
    fn classify_request_tool_execution_text_hint() {
        let headers = HeaderMap::new();
        let value = json!({"messages": [{"content": "run command ls"}]});
        assert_eq!(classify_request(&value, &headers), TaskClass::ToolExecution);
    }

    #[test]
    fn classify_request_read_only_patterns() {
        let headers = HeaderMap::new();
        for phrase in [
            "explain how this works",
            "summarize the document",
            "where is the config",
            "what is the purpose",
            "how does auth work",
            "find the definition",
            "show me the code",
            "list all files",
            "describe the architecture",
        ] {
            let value = json!({"messages": [{"content": phrase}]});
            assert_eq!(
                classify_request(&value, &headers),
                TaskClass::ReadOnly,
                "expected ReadOnly for: {phrase}"
            );
        }
    }

    #[test]
    fn classify_request_empty_text_is_unknown() {
        let headers = HeaderMap::new();
        let value = json!({"messages": [{"content": ""}]});
        assert_eq!(classify_request(&value, &headers), TaskClass::Unknown);
    }

    #[test]
    fn classify_request_no_messages_is_unknown() {
        let headers = HeaderMap::new();
        let value = json!({"model": "gpt-4"});
        assert_eq!(classify_request(&value, &headers), TaskClass::Unknown);
    }

    #[test]
    fn parse_task_class_all_variants() {
        assert_eq!(parse_task_class("read_only"), Some(TaskClass::ReadOnly));
        assert_eq!(parse_task_class("readonly"), Some(TaskClass::ReadOnly));
        assert_eq!(parse_task_class("code_change"), Some(TaskClass::CodeChange));
        assert_eq!(parse_task_class("code-change"), Some(TaskClass::CodeChange));
        assert_eq!(
            parse_task_class("tool_execution"),
            Some(TaskClass::ToolExecution)
        );
        assert_eq!(
            parse_task_class("tool-execution"),
            Some(TaskClass::ToolExecution)
        );
        assert_eq!(
            parse_task_class("destructive"),
            Some(TaskClass::Destructive)
        );
        assert_eq!(
            parse_task_class("security_sensitive"),
            Some(TaskClass::SecuritySensitive)
        );
        assert_eq!(
            parse_task_class("security-sensitive"),
            Some(TaskClass::SecuritySensitive)
        );
        assert_eq!(parse_task_class("unknown"), Some(TaskClass::Unknown));
        assert_eq!(parse_task_class("invalid"), None);
        assert_eq!(parse_task_class(""), None);
    }

    #[test]
    fn parse_task_class_case_insensitive() {
        assert_eq!(parse_task_class("READ_ONLY"), Some(TaskClass::ReadOnly));
        assert_eq!(
            parse_task_class("Destructive"),
            Some(TaskClass::Destructive)
        );
    }

    #[test]
    fn parse_task_class_trims_whitespace() {
        assert_eq!(parse_task_class("  read_only  "), Some(TaskClass::ReadOnly));
    }

    #[test]
    fn request_text_extracts_content_fields() {
        let value = json!({
            "messages": [
                {"role": "user", "content": "first"},
                {"role": "assistant", "content": "second"}
            ]
        });
        let text = request_text(&value);
        assert!(text.contains("first"));
        assert!(text.contains("second"));
    }

    #[test]
    fn request_text_extracts_prompt_field() {
        let value = json!({"prompt": "hello world"});
        let text = request_text(&value);
        assert!(text.contains("hello world"));
    }

    #[test]
    fn request_text_extracts_input_field() {
        let value = json!({"input": "test input"});
        let text = request_text(&value);
        assert!(text.contains("test input"));
    }

    #[test]
    fn contains_any_matches() {
        assert!(contains_any("hello world", &["world", "foo"]));
        assert!(!contains_any("hello world", &["bar", "baz"]));
        assert!(!contains_any("hello world", &[]));
    }
}
