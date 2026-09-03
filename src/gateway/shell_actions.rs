// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::path::Path;

use super::{declarative_config::HostedGatewayLocalAccessConfig, local_access};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) enum ShellRiskLevel {
    Safe,
    Moderate,
    Destructive,
    Critical,
}

pub(crate) async fn classify_shell_command(
    command: &str,
    working_directory: &Path,
    config: &HostedGatewayLocalAccessConfig,
) -> ShellRiskLevel {
    if local_access::validate_path(config, working_directory)
        .await
        .is_err()
    {
        return ShellRiskLevel::Critical;
    }
    let command = command.to_ascii_lowercase();
    if command.contains("rm -rf")
        || command.contains("drop table")
        || command.contains("truncate table")
        || command.contains("reset --hard")
        || command.contains("chmod 777")
    {
        return ShellRiskLevel::Critical;
    }
    if command.contains(" rm ")
        || command.contains("delete")
        || command.contains("overwrite")
        || command.contains("npm install")
        || command.contains("cargo install")
        || command.contains("curl ")
        || command.contains("psql ")
        || command.contains("kill ")
    {
        return ShellRiskLevel::Destructive;
    }
    if command.contains("secret") || command.contains("token") || command.contains("credential") {
        return ShellRiskLevel::Destructive;
    }
    if command.contains("git status")
        || command.contains("cargo test")
        || command.contains("npm test")
    {
        ShellRiskLevel::Safe
    } else {
        ShellRiskLevel::Moderate
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
    use std::path::PathBuf;

    fn disabled_config() -> HostedGatewayLocalAccessConfig {
        HostedGatewayLocalAccessConfig {
            enabled: false,
            ..Default::default()
        }
    }

    fn enabled_config_with_root(root: &str) -> HostedGatewayLocalAccessConfig {
        HostedGatewayLocalAccessConfig {
            enabled: true,
            allowed_roots: vec![root.to_string()],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn disabled_config_returns_critical() {
        let config = disabled_config();
        let level = classify_shell_command("ls", &PathBuf::from("/tmp"), &config).await;
        assert_eq!(level, ShellRiskLevel::Critical);
    }

    #[tokio::test]
    async fn rm_rf_is_critical() {
        let config = enabled_config_with_root("/tmp");
        let level = classify_shell_command("rm -rf /", &PathBuf::from("/tmp"), &config).await;
        assert_eq!(level, ShellRiskLevel::Critical);
    }

    #[tokio::test]
    async fn drop_table_is_critical() {
        let config = enabled_config_with_root("/tmp");
        let level =
            classify_shell_command("DROP TABLE users", &PathBuf::from("/tmp"), &config).await;
        assert_eq!(level, ShellRiskLevel::Critical);
    }

    #[tokio::test]
    async fn truncate_table_is_critical() {
        let config = enabled_config_with_root("/tmp");
        let level =
            classify_shell_command("TRUNCATE TABLE events", &PathBuf::from("/tmp"), &config).await;
        assert_eq!(level, ShellRiskLevel::Critical);
    }

    #[tokio::test]
    async fn reset_hard_is_critical() {
        let config = enabled_config_with_root("/tmp");
        let level =
            classify_shell_command("git reset --hard HEAD~1", &PathBuf::from("/tmp"), &config)
                .await;
        assert_eq!(level, ShellRiskLevel::Critical);
    }

    #[tokio::test]
    async fn chmod_777_is_critical() {
        let config = enabled_config_with_root("/tmp");
        let level =
            classify_shell_command("chmod 777 /etc/passwd", &PathBuf::from("/tmp"), &config).await;
        assert_eq!(level, ShellRiskLevel::Critical);
    }

    #[tokio::test]
    async fn rm_command_is_destructive() {
        let config = enabled_config_with_root("/tmp");
        let level =
            classify_shell_command("sudo rm file.txt", &PathBuf::from("/tmp"), &config).await;
        assert_eq!(level, ShellRiskLevel::Destructive);
    }

    #[tokio::test]
    async fn delete_keyword_is_destructive() {
        let config = enabled_config_with_root("/tmp");
        let level =
            classify_shell_command("delete from table", &PathBuf::from("/tmp"), &config).await;
        assert_eq!(level, ShellRiskLevel::Destructive);
    }

    #[tokio::test]
    async fn npm_install_is_destructive() {
        let config = enabled_config_with_root("/tmp");
        let level =
            classify_shell_command("npm install lodash", &PathBuf::from("/tmp"), &config).await;
        assert_eq!(level, ShellRiskLevel::Destructive);
    }

    #[tokio::test]
    async fn curl_is_destructive() {
        let config = enabled_config_with_root("/tmp");
        let level =
            classify_shell_command("curl http://example.com", &PathBuf::from("/tmp"), &config)
                .await;
        assert_eq!(level, ShellRiskLevel::Destructive);
    }

    #[tokio::test]
    async fn secret_keyword_is_destructive() {
        let config = enabled_config_with_root("/tmp");
        let level =
            classify_shell_command("echo secret value", &PathBuf::from("/tmp"), &config).await;
        assert_eq!(level, ShellRiskLevel::Destructive);
    }

    #[tokio::test]
    async fn token_keyword_is_destructive() {
        let config = enabled_config_with_root("/tmp");
        let level =
            classify_shell_command("print token here", &PathBuf::from("/tmp"), &config).await;
        assert_eq!(level, ShellRiskLevel::Destructive);
    }

    #[tokio::test]
    async fn git_status_is_safe() {
        let config = enabled_config_with_root("/tmp");
        let level = classify_shell_command("git status", &PathBuf::from("/tmp"), &config).await;
        assert_eq!(level, ShellRiskLevel::Safe);
    }

    #[tokio::test]
    async fn cargo_test_is_safe() {
        let config = enabled_config_with_root("/tmp");
        let level = classify_shell_command("cargo test", &PathBuf::from("/tmp"), &config).await;
        assert_eq!(level, ShellRiskLevel::Safe);
    }

    #[tokio::test]
    async fn npm_test_is_safe() {
        let config = enabled_config_with_root("/tmp");
        let level = classify_shell_command("npm test", &PathBuf::from("/tmp"), &config).await;
        assert_eq!(level, ShellRiskLevel::Safe);
    }

    #[tokio::test]
    async fn generic_command_is_moderate() {
        let config = enabled_config_with_root("/tmp");
        let level = classify_shell_command("echo hello", &PathBuf::from("/tmp"), &config).await;
        assert_eq!(level, ShellRiskLevel::Moderate);
    }

    #[tokio::test]
    async fn kill_is_destructive() {
        let config = enabled_config_with_root("/tmp");
        let level = classify_shell_command("kill -9 12345", &PathBuf::from("/tmp"), &config).await;
        assert_eq!(level, ShellRiskLevel::Destructive);
    }

    #[tokio::test]
    async fn psql_is_destructive() {
        let config = enabled_config_with_root("/tmp");
        let level =
            classify_shell_command("psql -c 'SELECT 1'", &PathBuf::from("/tmp"), &config).await;
        assert_eq!(level, ShellRiskLevel::Destructive);
    }

    #[test]
    fn shell_risk_level_equality() {
        assert_eq!(ShellRiskLevel::Safe, ShellRiskLevel::Safe);
        assert_ne!(ShellRiskLevel::Safe, ShellRiskLevel::Critical);
    }
}
