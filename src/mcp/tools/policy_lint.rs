// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP tool: policy_lint

use serde_json::{json, Value};

use super::ToolContext;
use crate::error::CliError;

pub(crate) const MAX_INLINE_YAML_BYTES: usize = 1_048_576;

pub(crate) fn definition() -> Value {
    json!({
        "name": "policy_lint",
        "description": "Lint bounded inline declarative gateway policy YAML and return structured diagnostics.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "yaml": {
                    "type": "string",
                    "description": "Inline policy config YAML (maximum 1 MiB).",
                    "minLength": 1,
                    "maxLength": MAX_INLINE_YAML_BYTES,
                }
            },
            "required": ["yaml"],
            "additionalProperties": false,
        }
    })
}

pub(crate) async fn execute(_ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let yaml = resolve_inline_yaml(arguments)?;
    let result = crate::policy::lint::lint_yaml(yaml);

    Ok(match result {
        Ok(result) => lint_result_json(result.errors),
        Err(error) => lint_failure_json(&error.to_string()),
    })
}

fn resolve_inline_yaml(arguments: &Value) -> Result<&str, CliError> {
    let object = arguments
        .as_object()
        .ok_or_else(|| CliError::user("policy_lint arguments must be an object"))?;
    if object.keys().any(|key| key != "yaml") {
        return Err(CliError::user(
            "remote policy_lint accepts only inline 'yaml'; filesystem paths are not permitted",
        ));
    }

    let yaml = object
        .get("yaml")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| CliError::user("policy_lint requires a non-empty inline 'yaml' input"))?;
    let byte_len = yaml.len();
    if byte_len > MAX_INLINE_YAML_BYTES {
        return Err(CliError::user(format!(
            "policy_lint inline 'yaml' exceeds the 1 MiB limit ({byte_len} bytes)"
        )));
    }

    Ok(yaml)
}

fn lint_result_json(diagnostics: Vec<String>) -> Value {
    let rendered = diagnostics
        .iter()
        .map(|diagnostic| render_diagnostic(diagnostic))
        .collect::<Vec<_>>();

    json!({
        "ok": rendered.is_empty(),
        "source": source_json(),
        "summary": {
            "error_count": rendered.len(),
        },
        "diagnostics": rendered,
    })
}

fn lint_failure_json(message: &str) -> Value {
    json!({
        "ok": false,
        "source": source_json(),
        "summary": {
            "error_count": 1,
        },
        "diagnostics": [render_diagnostic(message)],
    })
}

fn source_json() -> Value {
    json!({
        "kind": "inline_yaml",
    })
}

fn render_diagnostic(message: &str) -> Value {
    let (location, detail) = split_location(message);
    let (rule_id, remediation) = classify_diagnostic(detail);

    json!({
        "rule_id": rule_id,
        "severity": "error",
        "location": location,
        "message": detail,
        "remediation": remediation,
    })
}

fn split_location(message: &str) -> (Option<String>, &str) {
    if let Some((location, detail)) = message.split_once(": ") {
        let looks_structured = location.contains('.')
            || location.contains('[')
            || location.contains('/')
            || location.starts_with("providers")
            || location.starts_with("tool_servers")
            || location.starts_with("history")
            || location.starts_with("routes");
        if looks_structured {
            return (Some(location.to_string()), detail);
        }
    }

    (None, message)
}

fn classify_diagnostic(message: &str) -> (&'static str, &'static str) {
    if message.contains("failed to parse YAML") {
        return (
            "policy_lint.yaml_parse",
            "Fix the YAML syntax first so schema and cross-policy validation can run on the normalized document.",
        );
    }
    if message.contains("is no longer accepted; use 'secret_key_ref' instead") {
        return (
            "policy_lint.deprecated_secret_key",
            "Replace deprecated secret-key fields with the supported 'secret_key_ref' block everywhere in the policy config.",
        );
    }
    if message.contains("tool server declarations belong in the top-level 'tool_servers' block")
        || message.contains("matching tool_servers[] entry")
    {
        return (
            "policy_lint.tool_server_boundary",
            "Keep durable tool servers in top-level tool_servers[] and keep runtime MCP bridge targets under providers.targets[].mcp.",
        );
    }
    if message.contains("no providers have 'pricing'") {
        return (
            "policy_lint.pricing_missing",
            "Declare pricing for the providers you expect cost filters to act on, or remove the cost filter if pricing is intentionally absent.",
        );
    }
    if message.contains("allowed_languages and denied_languages are mutually exclusive") {
        return (
            "policy_lint.language_conflict",
            "Choose either allowed_languages or denied_languages so the language policy has one unambiguous enforcement mode.",
        );
    }

    (
        "policy_lint.validation",
        "Fix the reported policy validation error and rerun policy_lint before publishing the updated gateway configuration.",
    )
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
    fn definition_requires_bounded_inline_yaml_only() {
        let schema = definition()["inputSchema"].clone();

        assert_eq!(schema["required"], json!(["yaml"]));
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["yaml"]["minLength"], 1);
        assert_eq!(
            schema["properties"]["yaml"]["maxLength"],
            MAX_INLINE_YAML_BYTES
        );
        assert!(schema["properties"].get("file_path").is_none());
        assert!(schema["properties"].get("file").is_none());
        assert!(schema["properties"].get("path").is_none());

        let compiled = jsonschema::JSONSchema::compile(&schema).expect("compile input schema");
        assert!(compiled.is_valid(&json!({"yaml": "pack:\n  name: demo"})));
        assert!(!compiled.is_valid(&json!({"file_path": "/etc/passwd"})));
        assert!(!compiled.is_valid(&json!({
            "yaml": "a".repeat(MAX_INLINE_YAML_BYTES + 1)
        })));
    }

    #[test]
    fn resolve_inline_yaml_rejects_path_shaped_input_before_access() {
        let arguments = json!({"file_path": "/definitely-not-readable/policy-config.yaml"});

        let error = resolve_inline_yaml(&arguments).expect_err("path input must fail");

        assert!(error
            .to_string()
            .contains("filesystem paths are not permitted"));
    }

    #[test]
    fn resolve_inline_yaml_rejects_more_than_one_mib() {
        let yaml = "a".repeat(MAX_INLINE_YAML_BYTES + 1);
        let arguments = json!({"yaml": yaml});

        let error = resolve_inline_yaml(&arguments).expect_err("oversized input must fail");

        assert!(error.to_string().contains("exceeds the 1 MiB limit"));
    }

    #[test]
    fn resolve_inline_yaml_uses_utf8_byte_limit() {
        let yaml = "é".repeat((MAX_INLINE_YAML_BYTES / 2) + 1);
        let arguments = json!({"yaml": yaml});

        let error = resolve_inline_yaml(&arguments).expect_err("oversized UTF-8 input must fail");

        assert!(error.to_string().contains("1048578 bytes"));
    }

    #[test]
    fn split_location_extracts_structured_prefixes() {
        let (location, detail) = split_location("tool_servers[0].id: duplicated");

        assert_eq!(location.as_deref(), Some("tool_servers[0].id"));
        assert_eq!(detail, "duplicated");
    }

    #[test]
    fn classify_diagnostic_detects_tool_server_boundary_errors() {
        let (rule_id, remediation) = classify_diagnostic(
            "tool server declarations belong in the top-level 'tool_servers' block",
        );

        assert_eq!(rule_id, "policy_lint.tool_server_boundary");
        assert!(remediation.contains("top-level tool_servers[]"));
    }

    #[tokio::test]
    async fn execute_returns_structured_failure_for_invalid_inline_yaml() {
        let client =
            crate::api::AsyncApiClient::new("http://127.0.0.1:9", "token").expect("client");
        let ctx = ToolContext {
            client: &client,
            session_id: "session-1",
        };

        let result = execute(
            &ctx,
            &json!({
                "yaml": "pack:\n  name: demo\nproviders:\n  targets:\n    - id: openai\n      model: ["
            }),
        )
        .await
        .expect("lint result");

        assert_eq!(result["ok"], false);
        assert_eq!(
            result["diagnostics"][0]["rule_id"],
            "policy_lint.yaml_parse"
        );
    }

    #[tokio::test]
    async fn execute_accepts_valid_inline_yaml() {
        let client =
            crate::api::AsyncApiClient::new("http://127.0.0.1:9", "token").expect("client");
        let ctx = ToolContext {
            client: &client,
            session_id: "session-1",
        };

        let result = execute(
            &ctx,
            &json!({
                "yaml": r#"
pack:
  name: demo
  version: "1.0.0"
  enabled: true
policies:
  chain:
    - prompt-injection
"#
            }),
        )
        .await
        .expect("lint result");

        assert_eq!(result["ok"], true);
        assert_eq!(result["summary"]["error_count"], 0);
    }
}
