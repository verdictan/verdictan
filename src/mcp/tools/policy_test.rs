// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP tool: policy_test

use std::path::PathBuf;

use serde_json::{json, Value};

use super::ToolContext;
use crate::error::CliError;
use crate::policy::test_runner::{TestCaseResult, TestRunOutput};

enum PolicyTestSource {
    PackDir(PathBuf),
    InlineYaml,
}

pub(crate) async fn execute(_ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let source = resolve_source(arguments)?;
    let result = match &source {
        PolicyTestSource::PackDir(pack_dir) => {
            crate::policy::test_runner::run_pack_tests(pack_dir).await
        }
        PolicyTestSource::InlineYaml => run_inline_pack(arguments).await,
    };

    Ok(match result {
        Ok(result) => success_json(&source, result),
        Err(error) => failure_json(&source, &error.to_string()),
    })
}

fn resolve_source(arguments: &Value) -> Result<PolicyTestSource, CliError> {
    let yaml = arguments
        .get("yaml")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let pack_dir = arguments
        .get("pack_dir")
        .or_else(|| arguments.get("path"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if yaml.is_some() && pack_dir.is_some() {
        return Err(CliError::user(
            "policy_test accepts either 'yaml' or 'pack_dir', but not both",
        ));
    }

    if yaml.is_some() {
        return Ok(PolicyTestSource::InlineYaml);
    }

    if let Some(pack_dir) = pack_dir {
        return Ok(PolicyTestSource::PackDir(PathBuf::from(pack_dir)));
    }

    let current_dir = std::env::current_dir().map_err(|error| {
        CliError::user(format!("failed to determine current directory: {error}"))
    })?;
    Ok(PolicyTestSource::PackDir(current_dir))
}

async fn run_inline_pack(arguments: &Value) -> Result<TestRunOutput, CliError> {
    let yaml = arguments
        .get("yaml")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::user("policy_test requires a non-empty 'yaml' input"))?;
    let temp_dir =
        std::env::temp_dir().join(format!("verdictan-policy-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir)
        .map_err(|error| CliError::internal(format!("failed to create temp dir: {error}")))?;
    std::fs::write(temp_dir.join("policy-config.yaml"), yaml).map_err(|error| {
        CliError::internal(format!("failed to stage inline policy config: {error}"))
    })?;
    std::fs::create_dir(temp_dir.join("tests")).map_err(|error| {
        CliError::internal(format!("failed to create inline tests directory: {error}"))
    })?;

    let result = crate::policy::test_runner::run_pack_tests(&temp_dir).await;
    if let Err(error) = std::fs::remove_dir_all(&temp_dir) {
        tracing::debug!(
            path = %temp_dir.display(),
            %error,
            "failed to clean up inline policy test temp dir"
        );
    }

    result
}

fn success_json(source: &PolicyTestSource, result: TestRunOutput) -> Value {
    let total = result.results.len();
    let passed = result.results.iter().filter(|test| test.passed).count();
    let failed = total.saturating_sub(passed);

    json!({
        "ok": result.ok,
        "source": source_json(source),
        "summary": {
            "total": total,
            "passed": passed,
            "failed": failed,
        },
        "results": result.results.iter().map(render_test_case).collect::<Vec<_>>(),
    })
}

fn failure_json(source: &PolicyTestSource, message: &str) -> Value {
    let (rule_id, remediation) = classify_failure(message);

    json!({
        "ok": false,
        "source": source_json(source),
        "summary": {
            "total": 0,
            "passed": 0,
            "failed": 0,
        },
        "results": [],
        "error": {
            "rule_id": rule_id,
            "message": message,
            "remediation": remediation,
        }
    })
}

fn source_json(source: &PolicyTestSource) -> Value {
    match source {
        PolicyTestSource::PackDir(pack_dir) => json!({
            "kind": "pack_dir",
            "pack_dir": pack_dir.display().to_string(),
        }),
        PolicyTestSource::InlineYaml => json!({
            "kind": "inline_yaml",
        }),
    }
}

fn render_test_case(result: &TestCaseResult) -> Value {
    let remediation = (!result.passed).then(|| remediation_for_reason_code(&result.reason_code));
    let failing_assertions = if result.passed {
        Vec::new()
    } else {
        vec![json!({
            "reason_code": &result.reason_code,
            "details": &result.details,
        })]
    };

    json!({
        "name": &result.name,
        "verdict": &result.verdict,
        "reason_code": &result.reason_code,
        "passed": result.passed,
        "details": &result.details,
        "failing_assertions": failing_assertions,
        "remediation": remediation,
    })
}

fn remediation_for_reason_code(reason_code: &str) -> &'static str {
    if reason_code.starts_with("quality.assertion.") {
        return "Inspect the assertion details, then align the golden expectation or the quality-scorer policy so the expected verdict and reason code match the observed behavior.";
    }
    if reason_code.contains("prompt_injection") || reason_code.contains("prompt-injection") {
        return "Review the request fixture and the prompt-injection policy thresholds to confirm the expected allow/block decision is still the intended contract.";
    }
    if reason_code == "ok" {
        return "The test runner reported an unexpected mismatch even though the case reason_code is 'ok'; inspect the rendered details for a contract drift between the test input and the policy pack.";
    }

    "Inspect the failing case details and update either the test expectation or the underlying policy so the intended contract is explicit."
}

fn classify_failure(message: &str) -> (&'static str, &'static str) {
    if message.contains("missing tests/ directory") {
        return (
            "policy_test.missing_tests_dir",
            "Create a tests/ directory in the pack, or provide inline YAML that includes a testing.suites section so the policy pack has executable assertions.",
        );
    }
    if message.contains("failed to determine current directory") {
        return (
            "policy_test.cwd_unavailable",
            "Run the tool from a readable working directory or pass an explicit 'pack_dir' argument.",
        );
    }
    if message.contains("failed to read tests directory") {
        return (
            "policy_test.tests_dir_unreadable",
            "Check that the pack directory exists and that the MCP process can read its tests/ directory contents.",
        );
    }
    if message.contains("invalid test JSON") {
        return (
            "policy_test.invalid_test_json",
            "Fix the malformed tests/*.json fixture so the pack test runner can deserialize the golden case.",
        );
    }

    (
        "policy_test.execution",
        "Fix the reported policy-test failure and rerun the MCP tool once the pack inputs and fixtures are consistent.",
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
    fn resolve_source_defaults_to_current_directory() {
        match resolve_source(&json!({})).expect("default source") {
            PolicyTestSource::PackDir(path) => {
                assert_eq!(path, std::env::current_dir().expect("cwd"));
            }
            PolicyTestSource::InlineYaml => panic!("expected pack dir"),
        }
    }

    #[test]
    fn remediation_for_reason_code_handles_quality_assertions() {
        let remediation =
            remediation_for_reason_code("quality.assertion.trace_span_count.below_threshold");

        assert!(remediation.contains("quality-scorer policy"));
    }

    #[tokio::test]
    async fn execute_runs_inline_testing_suite() {
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
  name: inline-pack
  version: "1.0.0"
providers:
  targets:
    - id: openai
      provider: openai
      model: gpt-5.4-mini
      base_url: https://api.openai.com/v1
      secret_key_ref:
        store: OPENAI_API_KEY
policies:
  chain:
    - prompt-injection
testing:
  suites:
    - name: inline
      cases:
        - name: allows_normal_prompt
          input:
            messages:
              - role: user
                content: "hello"
          expected:
            verdict: allow
            reason_code: ok
"#
            }),
        )
        .await
        .expect("policy test result");

        assert_eq!(result["summary"]["total"], 1);
        assert_eq!(result["summary"]["passed"], 1);
    }

    #[tokio::test]
    async fn execute_returns_structured_runner_failures() {
        let client =
            crate::api::AsyncApiClient::new("http://127.0.0.1:9", "token").expect("client");
        let ctx = ToolContext {
            client: &client,
            session_id: "session-1",
        };

        let result = execute(
            &ctx,
            &json!({
                "yaml": "pack:\n  name: inline-pack\n  version: [\n"
            }),
        )
        .await
        .expect("policy test result");

        assert_eq!(result["ok"], false);
        assert_eq!(result["error"]["rule_id"], "policy_test.execution");
    }
}
