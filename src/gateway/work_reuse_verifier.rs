// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::path::PathBuf;

use serde::Serialize;

use super::{
    declarative_config::HostedGatewayLocalAccessConfig,
    local_access::{self, LocalAccessRequest, LocalShellExecution},
    shell_actions::ShellRiskLevel,
};

#[derive(Clone, Debug, Default, Serialize)]
pub struct ReuseVerifierAttempt {
    pub command: String,
    pub risk_level: String,
    pub executed: bool,
    pub succeeded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timed_out: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr_preview: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ReuseVerifierSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
    pub attempted: usize,
    pub executed: usize,
    pub succeeded: bool,
    pub attempts: Vec<ReuseVerifierAttempt>,
}

pub async fn execute_reuse_verifier(
    config: &HostedGatewayLocalAccessConfig,
    working_directory_hint: Option<&str>,
    git_repo: &str,
    commands: &[String],
) -> anyhow::Result<ReuseVerifierSummary> {
    let Some(working_directory) =
        resolve_working_directory(config, working_directory_hint, git_repo)
    else {
        return Ok(ReuseVerifierSummary {
            attempted: commands.len().min(3),
            executed: 0,
            succeeded: false,
            attempts: commands
                .iter()
                .take(3)
                .map(|command| ReuseVerifierAttempt {
                    command: command.clone(),
                    risk_level: "critical".to_string(),
                    executed: false,
                    succeeded: false,
                    skipped_reason: Some(
                        "no safe working directory was available for verifier execution"
                            .to_string(),
                    ),
                    ..ReuseVerifierAttempt::default()
                })
                .collect(),
            ..ReuseVerifierSummary::default()
        });
    };
    let request = LocalAccessRequest {
        path: working_directory.clone(),
    };
    let mut attempts = Vec::new();
    let mut executed = 0usize;
    let mut succeeded = true;

    for command in commands.iter().take(3) {
        let risk_level =
            super::shell_actions::classify_shell_command(command, &working_directory, config).await;
        let risk_label = shell_risk_label(risk_level).to_string();
        if risk_level != ShellRiskLevel::Safe {
            attempts.push(ReuseVerifierAttempt {
                command: command.clone(),
                risk_level: risk_label,
                executed: false,
                succeeded: false,
                skipped_reason: Some("verifier command must classify as safe".to_string()),
                ..ReuseVerifierAttempt::default()
            });
            succeeded = false;
            break;
        }

        let argv = command
            .split_whitespace()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        match local_access::execute_command(config, &request, &argv, &working_directory).await {
            Ok(result) => {
                executed = executed.saturating_add(1);
                let attempt = attempt_from_execution(result);
                if !attempt.succeeded {
                    succeeded = false;
                    attempts.push(attempt);
                    break;
                }
                attempts.push(attempt);
            }
            Err(error) => {
                // PERF-014: capacity rejection must not spawn; surface the HTTP
                // 429 contract so callers and audits can distinguish overload
                // from policy/execution failures.
                let skipped_reason =
                    if matches!(error, local_access::LocalCommandError::CapacityExceeded) {
                        format!("HTTP {}: {error}", error.status_code())
                    } else {
                        error.to_string()
                    };
                attempts.push(ReuseVerifierAttempt {
                    command: command.clone(),
                    risk_level: risk_label,
                    executed: false,
                    succeeded: false,
                    skipped_reason: Some(skipped_reason),
                    ..ReuseVerifierAttempt::default()
                });
                succeeded = false;
                break;
            }
        }
    }

    Ok(ReuseVerifierSummary {
        working_directory: Some(working_directory.display().to_string()),
        attempted: commands.len().min(3),
        executed,
        succeeded: executed > 0 && succeeded,
        attempts,
    })
}

pub(crate) fn resolve_working_directory(
    config: &HostedGatewayLocalAccessConfig,
    working_directory_hint: Option<&str>,
    git_repo: &str,
) -> Option<PathBuf> {
    if let Some(path) = working_directory_hint
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(PathBuf::from(path));
    }
    if git_repo.starts_with('/') {
        return Some(PathBuf::from(git_repo));
    }
    if config.allowed_roots.len() == 1 {
        return config.allowed_roots.first().map(PathBuf::from);
    }
    None
}

fn attempt_from_execution(result: LocalShellExecution) -> ReuseVerifierAttempt {
    let stdout_preview =
        (!result.stdout.trim().is_empty()).then(|| truncate_preview(&result.stdout));
    let stderr_preview =
        (!result.stderr.trim().is_empty()).then(|| truncate_preview(&result.stderr));
    ReuseVerifierAttempt {
        command: result.command,
        risk_level: result.risk_level,
        executed: true,
        succeeded: !result.timed_out && result.exit_code == Some(0),
        exit_code: result.exit_code,
        timed_out: Some(result.timed_out),
        skipped_reason: None,
        stdout_preview,
        stderr_preview,
    }
}

fn truncate_preview(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() > 240 {
        format!("{}...", &trimmed[..240])
    } else {
        trimmed.to_string()
    }
}

fn shell_risk_label(level: ShellRiskLevel) -> &'static str {
    match level {
        ShellRiskLevel::Safe => "safe",
        ShellRiskLevel::Moderate => "moderate",
        ShellRiskLevel::Destructive => "destructive",
        ShellRiskLevel::Critical => "critical",
    }
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
    use crate::gateway::local_access::LocalShellExecution;

    #[test]
    fn resolve_working_directory_prefers_hint() {
        let config = HostedGatewayLocalAccessConfig {
            enabled: true,
            allowed_roots: vec!["/tmp/root".to_string()],
            ..Default::default()
        };

        let resolved =
            resolve_working_directory(&config, Some("/tmp/project"), "verdictan/verdictan")
                .expect("working directory");

        assert_eq!(resolved, PathBuf::from("/tmp/project"));
    }

    #[test]
    fn attempt_from_execution_marks_failures() {
        let attempt = attempt_from_execution(LocalShellExecution {
            command: "cargo nextest run --test gateway_features_unit".to_string(),
            argv: vec!["cargo".to_string(), "nextest".to_string()],
            working_directory: "/tmp/project".to_string(),
            exit_code: Some(1),
            stdout: "out".to_string(),
            stderr: "err".to_string(),
            timed_out: false,
            stdout_truncated: false,
            stderr_truncated: false,
            risk_level: "safe".to_string(),
            audit: serde_json::json!({}),
        });

        assert!(attempt.executed);
        assert!(!attempt.succeeded);
        assert_eq!(attempt.exit_code, Some(1));
    }
}
