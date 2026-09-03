// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;

use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct PolicyTestArgs {
    /// Print machine-readable JSON.
    #[arg(long)]
    pub(crate) json: bool,

    /// Policy config directory (default: current directory)
    #[arg(long)]
    pub(crate) pack_dir: Option<std::path::PathBuf>,
}
pub(crate) async fn run_async(args: PolicyTestArgs) -> Result<(), CliError> {
    let pack_dir = match args.pack_dir {
        Some(pack_dir) => pack_dir,
        None => std::env::current_dir().map_err(|error| {
            CliError::user(format!("failed to determine current directory: {error}"))
        })?,
    };

    let out = crate::policy::test_runner::run_pack_tests(&pack_dir).await?;

    if args.json {
        print_json(&out)?;
    } else {
        print_human_summary(&out);
    }

    if out.ok {
        Ok(())
    } else {
        Err(CliError::user("policy tests failed"))
    }
}

fn print_human_summary(out: &crate::policy::test_runner::TestRunOutput) {
    let total = out.results.len();
    let passed = out.results.iter().filter(|r| r.passed).count();
    let failed = total - passed;

    for result in &out.results {
        let icon = if result.passed { "PASS" } else { "FAIL" };
        println!(
            "  [{}] {} — {} ({})",
            icon, result.name, result.verdict, result.reason_code
        );
    }

    println!();
    if out.ok {
        println!("  {} passed, {} total", passed, total);
    } else {
        println!("  {} passed, {} failed, {} total", passed, failed, total);
    }
}

#[cfg(test)]
fn format_human_summary(out: &crate::policy::test_runner::TestRunOutput) -> String {
    let mut output = Vec::new();
    {
        let total = out.results.len();
        let passed = out.results.iter().filter(|r| r.passed).count();
        let failed = total - passed;

        for result in &out.results {
            let icon = if result.passed { "PASS" } else { "FAIL" };
            output.push(format!(
                "  [{}] {} — {} ({})",
                icon, result.name, result.verdict, result.reason_code
            ));
        }

        output.push(String::new());
        if out.ok {
            output.push(format!("  {} passed, {} total", passed, total));
        } else {
            output.push(format!(
                "  {} passed, {} failed, {} total",
                passed, failed, total
            ));
        }
    }
    output.join("\n")
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
    use crate::policy::test_runner::{TestCaseResult, TestRunOutput};

    #[cfg(test)]
    pub(crate) fn format_human_summary(out: &TestRunOutput) -> String {
        let total = out.results.len();
        let passed = out.results.iter().filter(|r| r.passed).count();
        let failed = total - passed;
        let mut lines = Vec::new();

        for result in &out.results {
            let icon = if result.passed { "PASS" } else { "FAIL" };
            lines.push(format!(
                "  [{}] {} — {} ({})",
                icon, result.name, result.verdict, result.reason_code
            ));
        }
        lines.push(String::new());
        if out.ok {
            lines.push(format!("  {passed} passed, {total} total"));
        } else {
            lines.push(format!("  {passed} passed, {failed} failed, {total} total"));
        }
        lines.join("\n")
    }

    #[tokio::test]
    async fn policy_test_prints_human_readable_pass_fail_summary_for_assertion_mismatches() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("tests")).expect("create tests dir");
        std::fs::write(
            dir.path().join("policy-config.yaml"),
            r#"pack:
  name: human-output
  version: "0.1.0"
  enabled: true

policies:
  chain: []

testing:
  suites:
    - name: human
      cases:
        - name: pass-case
          input:
            messages:
              - role: user
                content: Summarize the policy.
            upstream_response:
              choices:
                - message:
                    content: "Disclaimer: follow the policy."
          expected:
            verdict: allow
            reason_code: ok
          assertions:
            - type: contains
              value: Disclaimer
        - name: fail-case
          input:
            messages:
              - role: user
                content: Summarize the policy.
            upstream_response:
              choices:
                - message:
                    content: No notice was provided.
          expected:
            verdict: allow
            reason_code: ok
          assertions:
            - type: contains
              value: Disclaimer
"#,
        )
        .expect("write config");

        let out = crate::policy::test_runner::run_pack_tests(dir.path())
            .await
            .expect("run pack tests");
        assert!(!out.ok);

        let stdout = format_human_summary(&out);
        assert!(stdout.contains("[PASS] human/pass-case"));
        assert!(stdout.contains("[FAIL] human/fail-case"));
        assert!(stdout.contains("1 passed, 1 failed, 2 total"));
    }

    #[test]
    fn count_passed_and_failed() {
        let results = vec![
            TestCaseResult {
                name: "t1".into(),
                verdict: "allow".into(),
                reason_code: "ok".into(),
                passed: true,
                details: None,
            },
            TestCaseResult {
                name: "t2".into(),
                verdict: "deny".into(),
                reason_code: "blocked".into(),
                passed: false,
                details: None,
            },
            TestCaseResult {
                name: "t3".into(),
                verdict: "allow".into(),
                reason_code: "ok".into(),
                passed: true,
                details: None,
            },
        ];
        let total = results.len();
        let passed = results.iter().filter(|r| r.passed).count();
        let failed = total - passed;
        assert_eq!(total, 3);
        assert_eq!(passed, 2);
        assert_eq!(failed, 1);
    }

    #[test]
    fn all_passed() {
        let out = TestRunOutput {
            ok: true,
            results: vec![TestCaseResult {
                name: "t1".into(),
                verdict: "allow".into(),
                reason_code: "ok".into(),
                passed: true,
                details: None,
            }],
        };
        assert!(out.ok);
        assert_eq!(out.results.iter().filter(|r| r.passed).count(), 1);
    }

    #[test]
    fn test_run_output_serializes() {
        let out = TestRunOutput {
            ok: false,
            results: vec![TestCaseResult {
                name: "test_deny".into(),
                verdict: "deny".into(),
                reason_code: "pii".into(),
                passed: false,
                details: None,
            }],
        };
        let json = serde_json::to_value(&out).unwrap();
        assert_eq!(json["ok"], false);
        assert_eq!(json["results"][0]["name"], "test_deny");
    }

    #[test]
    fn test_case_icon_mapping() {
        let passed = true;
        let icon = if passed { "PASS" } else { "FAIL" };
        assert_eq!(icon, "PASS");

        let failed = false;
        let icon = if failed { "PASS" } else { "FAIL" };
        assert_eq!(icon, "FAIL");
    }

    #[test]
    fn mixed_pass_and_fail_counts() {
        let out = TestRunOutput {
            ok: false,
            results: vec![
                TestCaseResult {
                    name: "pass1".into(),
                    verdict: "allow".into(),
                    reason_code: "ok".into(),
                    passed: true,
                    details: None,
                },
                TestCaseResult {
                    name: "fail1".into(),
                    verdict: "deny".into(),
                    reason_code: "pii".into(),
                    passed: false,
                    details: Some("mismatch".into()),
                },
                TestCaseResult {
                    name: "pass2".into(),
                    verdict: "allow".into(),
                    reason_code: "ok".into(),
                    passed: true,
                    details: None,
                },
            ],
        };

        let total = out.results.len();
        let passed = out.results.iter().filter(|r| r.passed).count();
        let failed = total - passed;

        assert_eq!(total, 3);
        assert_eq!(passed, 2);
        assert_eq!(failed, 1);
        assert!(!out.ok);
    }

    #[test]
    fn test_case_result_with_details() {
        let result = TestCaseResult {
            name: "detailed_test".into(),
            verdict: "block".into(),
            reason_code: "injection".into(),
            passed: false,
            details: Some("expected allow but got block".into()),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["details"], "expected allow but got block");
        assert_eq!(json["passed"], false);
    }

    #[test]
    fn test_run_output_all_failed() {
        let out = TestRunOutput {
            ok: false,
            results: vec![
                TestCaseResult {
                    name: "f1".into(),
                    verdict: "block".into(),
                    reason_code: "invalid".into(),
                    passed: false,
                    details: None,
                },
                TestCaseResult {
                    name: "f2".into(),
                    verdict: "deny".into(),
                    reason_code: "rate_limit".into(),
                    passed: false,
                    details: None,
                },
            ],
        };
        assert_eq!(out.results.iter().filter(|r| r.passed).count(), 0);
        assert!(!out.ok);
    }

    #[test]
    fn human_summary_includes_pass_fail_lines_and_totals() {
        let out = TestRunOutput {
            ok: false,
            results: vec![
                TestCaseResult {
                    name: "human/pass-case".into(),
                    verdict: "allow".into(),
                    reason_code: "ok".into(),
                    passed: true,
                    details: None,
                },
                TestCaseResult {
                    name: "human/fail-case".into(),
                    verdict: "allow".into(),
                    reason_code: "ok".into(),
                    passed: false,
                    details: None,
                },
            ],
        };

        let summary = super::format_human_summary(&out);
        assert!(summary.contains("[PASS] human/pass-case"));
        assert!(summary.contains("[FAIL] human/fail-case"));
        assert!(summary.contains("1 passed, 1 failed, 2 total"));
    }
}
