// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;

use crate::commands::policy_common::{lint_policy_specs, load_policy_specs_from_path};
use crate::error::CliError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyLintMode {
    Auto,
    Runtime,
    Abac,
}

#[derive(Debug, Args)]
pub(crate) struct PolicyLintArgs {
    /// Policy config file to lint.
    #[arg(long, default_value = "policy-config.yaml")]
    pub(crate) file: std::path::PathBuf,

    /// Lint mode: `runtime`, `abac`, or `auto`.
    #[arg(long, default_value = "auto", value_parser = ["auto", "runtime", "abac"])]
    pub(crate) mode: String,
}

pub(crate) fn run(args: PolicyLintArgs) -> Result<(), CliError> {
    match parse_mode(&args.mode)? {
        PolicyLintMode::Runtime => lint_runtime_config(&args.file),
        PolicyLintMode::Abac => lint_abac_policies(&args.file),
        PolicyLintMode::Auto => match detect_mode(&args.file)? {
            PolicyLintMode::Runtime => lint_runtime_config(&args.file),
            PolicyLintMode::Abac => lint_abac_policies(&args.file),
            PolicyLintMode::Auto => unreachable!("auto mode must resolve to a concrete lint mode"),
        },
    }
}

fn parse_mode(value: &str) -> Result<PolicyLintMode, CliError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(PolicyLintMode::Auto),
        "runtime" => Ok(PolicyLintMode::Runtime),
        "abac" => Ok(PolicyLintMode::Abac),
        other => Err(CliError::user(format!(
            "unsupported policy lint mode {other:?}; expected auto, runtime, or abac"
        ))),
    }
}

fn lint_runtime_config(path: &std::path::Path) -> Result<(), CliError> {
    let result = crate::policy::lint::lint_config_file(path)?;

    if result.is_valid {
        return Ok(());
    }

    let error_count = result.errors.len();
    for err in result.errors {
        eprintln!("{err}");
    }

    // Return a user error (exit code 2) while preserving deterministic ordering.
    Err(CliError::user(format!(
        "policy lint failed ({error_count} error(s))"
    )))
}

fn lint_abac_policies(path: &std::path::Path) -> Result<(), CliError> {
    let policies = load_policy_specs_from_path(path)?;
    let errors = lint_policy_specs(&policies);
    if errors.is_empty() {
        return Ok(());
    }

    let error_count = errors.len();
    for error in errors {
        eprintln!("{error}");
    }
    Err(CliError::user(format!(
        "policy lint failed ({error_count} error(s))"
    )))
}

fn detect_mode(path: &std::path::Path) -> Result<PolicyLintMode, CliError> {
    let bytes = std::fs::read(path)
        .map_err(|error| CliError::user(format!("failed to read {}: {error}", path.display())))?;
    let raw = String::from_utf8(bytes)
        .map_err(|error| CliError::user(format!("file is not valid UTF-8: {error}")))?;
    let value = if matches!(
        path.extension().and_then(|value| value.to_str()),
        Some("json")
    ) {
        serde_json::from_str::<serde_json::Value>(&raw).map_err(|error| {
            CliError::user(format!(
                "failed to parse {} as JSON: {error}",
                path.display()
            ))
        })?
    } else {
        let yaml: serde_yaml::Value = serde_yaml::from_str(&raw)
            .map_err(|error| CliError::user(format!("failed to parse YAML: {error}")))?;
        serde_json::to_value(yaml)
            .map_err(|error| CliError::internal(format!("failed to normalize YAML: {error}")))?
    };

    detect_value_mode(&value)
}

fn detect_value_mode(value: &serde_json::Value) -> Result<PolicyLintMode, CliError> {
    let Some(object) = value.as_object() else {
        return Ok(PolicyLintMode::Runtime);
    };

    if object
        .get("policies")
        .is_some_and(serde_json::Value::is_array)
        || object.contains_key("statements")
        || object.contains_key("Statement")
    {
        return Ok(PolicyLintMode::Abac);
    }

    Ok(PolicyLintMode::Runtime)
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
    fn command_helper_coverage_run_succeeds_for_valid_policy_config() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/policy-config/prompt-injection-detection.yaml");
        run(PolicyLintArgs {
            file: path,
            mode: "auto".to_string(),
        })
        .expect("fixture policy config should lint cleanly");
    }

    #[test]
    fn command_helper_coverage_run_reports_schema_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy-config.yaml");
        std::fs::write(
            &path,
            r#"pack:
  name: smoke
  version: "1.0.0"
providers:
  targets:
    - id: openai
      provider: openai
      model: 42
"#,
        )
        .expect("write invalid schema config");

        let error = run(PolicyLintArgs {
            file: path,
            mode: "auto".to_string(),
        })
        .expect_err("invalid schema should fail");
        assert!(error.to_string().contains("policy lint failed"));
    }

    #[test]
    fn command_helper_coverage_run_reports_missing_file() {
        let path = std::path::PathBuf::from("/nonexistent/path/policy-config.yaml");
        let error = run(PolicyLintArgs {
            file: path,
            mode: "auto".to_string(),
        })
        .expect_err("missing file should fail");
        assert!(!error.to_string().is_empty());
    }

    #[test]
    fn command_helper_coverage_lints_abac_bundle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policies.yaml");
        std::fs::write(
            &path,
            r#"policies:
  - name: Gateway Reader
    description: Read gateway events
    statements:
      - effect: allow
        actions: ["events:read"]
        resources: ["*"]
        conditions: {}
"#,
        )
        .expect("write policy bundle");

        run(PolicyLintArgs {
            file: path,
            mode: "auto".to_string(),
        })
        .expect("abac bundle should lint cleanly");
    }

    #[test]
    fn command_helper_coverage_detects_runtime_policy_chain_config() {
        let value = serde_json::json!({
            "pack": {
                "name": "test-pack",
                "version": "0.1.0",
                "enabled": true
            },
            "policies": {
                "chain": ["prompt-injection"]
            }
        });

        assert_eq!(
            detect_value_mode(&value).expect("detect mode"),
            PolicyLintMode::Runtime
        );
    }

    #[test]
    fn command_helper_coverage_detects_json_abac_policy_bundle() {
        let value = serde_json::json!({
            "policies": [{
                "name": "Gateway Reader",
                "description": "Read gateway events",
                "statements": [{
                    "effect": "allow",
                    "actions": ["events:read"],
                    "resources": ["*"],
                    "conditions": {}
                }]
            }]
        });

        assert_eq!(
            detect_value_mode(&value).expect("detect mode"),
            PolicyLintMode::Abac
        );
    }
}
