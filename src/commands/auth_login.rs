// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::io::{self, IsTerminal};

use clap::Args;

use crate::{
    auth::{
        browser_callback::{self, DEFAULT_CONSOLE_URL},
        credential_store::{self, StoredCredentials},
        login::{self, LoginRequest},
    },
    config::{Config, ConfigInputs},
    error::CliError,
    i18n,
    output::json::print_json,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginMode {
    Browser,
    Password { email: String, password: String },
}

#[derive(Debug, Args)]
#[command(after_help = crate::i18n::AUTH_LOGIN_AFTER_HELP_EN)]
pub struct AuthLoginArgs {
    #[arg(long)]
    pub email: Option<String>,

    #[arg(long)]
    pub password: Option<String>,

    /// Open the browser-based login flow.
    #[arg(long)]
    pub browser: bool,

    /// Console base URL for browser login (self-hosted or different origin).
    #[arg(long, default_value = DEFAULT_CONSOLE_URL)]
    pub console_url: String,

    #[arg(long)]
    pub json: bool,

    #[arg(long)]
    pub config: Option<std::path::PathBuf>,

    #[arg(long)]
    pub api_url: Option<String>,

    #[arg(long, default_value = "default")]
    pub profile: String,
}

pub fn run(args: AuthLoginArgs) -> Result<(), CliError> {
    tokio::runtime::Runtime::new()
        .map_err(|e| CliError::internal(format!("failed to create async runtime: {e}")))?
        .block_on(run_async(args))
}

pub fn resolve_login_mode(
    args: &AuthLoginArgs,
    stdin_is_terminal: bool,
) -> Result<LoginMode, CliError> {
    let locale = i18n::global();

    if args.browser {
        if args.email.is_some() || args.password.is_some() {
            return Err(CliError::user(i18n::t(locale, "auth.login_choose_method")));
        }
        if !stdin_is_terminal {
            return Err(CliError::auth(i18n::t(locale, "auth.not_a_terminal")));
        }
        return Ok(LoginMode::Browser);
    }

    match (args.email.as_deref(), args.password.as_deref()) {
        (Some(email), Some(password)) => Ok(LoginMode::Password {
            email: email.to_string(),
            password: password.to_string(),
        }),
        (Some(_), None) | (None, Some(_)) => Err(CliError::user(i18n::t(
            locale,
            "auth.login_password_requires_both",
        ))),
        (None, None) if stdin_is_terminal => Ok(LoginMode::Browser),
        (None, None) => Err(CliError::auth(i18n::t(locale, "auth.not_a_terminal"))),
    }
}

fn persist_credentials(
    profile: &str,
    api_url: &str,
    response: &login::LoginResponse,
) -> Result<(), CliError> {
    credential_store::save(
        Some(profile),
        StoredCredentials {
            api_url: api_url.to_string(),
            api_token: response.token.clone(),
            expires_at: Some(response.expires_at.clone()),
            org_id: response.org_id.clone(),
            org_name: response.org_name.clone(),
            org_slug: response.org_slug.clone(),
            project_id: response.project_id.clone(),
            role: response.role.clone(),
            user_id: response.user_id.clone(),
            email: response.email.clone(),
            display_name: response.display_name.clone(),
            team_ids: response.team_ids.clone(),
            capabilities: response.capabilities.clone(),
        },
    )
}

fn success_lines(profile: &str, response: &login::LoginResponse) -> Vec<String> {
    let mut lines = vec![
        format!("authenticated profile {profile}"),
        format!("org: {} ({})", response.org_name, response.org_id),
        format!("role: {}", response.role),
    ];
    if !response.team_ids.is_empty() {
        lines.push(format!("teams: {}", response.team_ids.join(", ")));
    }
    lines
}

pub(crate) async fn run_async(args: AuthLoginArgs) -> Result<(), CliError> {
    let login_mode = resolve_login_mode(&args, io::stdin().is_terminal())?;
    let config = Config::resolve(ConfigInputs {
        api_url_flag: args.api_url,
        api_token_flag: None,
        config_path: args.config,
        profile_flag: Some(args.profile.clone()),
        region_flag: None,
    })?;

    let browser_login = matches!(login_mode, LoginMode::Browser);
    let response = match login_mode {
        LoginMode::Browser => {
            browser_callback::run_browser_auth(&config.api_url, &args.console_url).await?
        }
        LoginMode::Password { email, password } => {
            login::login_async(&config.api_url, &LoginRequest { email, password }).await?
        }
    };

    persist_credentials(&args.profile, &config.api_url, &response)?;

    if args.json {
        return print_json(&serde_json::json!({
            "authenticated": true,
            "profile": args.profile,
            "org_id": response.org_id,
            "org_name": response.org_name,
            "project_id": response.project_id,
            "role": response.role,
            "team_ids": response.team_ids,
            "capabilities": response.capabilities,
            "expires_at": response.expires_at,
        }));
    }

    if browser_login {
        eprintln!("{}", i18n::t(i18n::global(), "auth.browser_success"));
    }

    for line in success_lines(&args.profile, &response) {
        println!("{line}");
    }
    Ok(())
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
    use tempfile::tempdir;

    struct EnvGuard {
        verdictan_test_home: Option<std::ffi::OsString>,
        home: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn capture() -> Self {
            Self {
                verdictan_test_home: std::env::var_os("VERDICTAN_TEST_HOME"),
                home: std::env::var_os("HOME"),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.verdictan_test_home {
                Some(value) => std::env::set_var("VERDICTAN_TEST_HOME", value),
                None => std::env::remove_var("VERDICTAN_TEST_HOME"),
            }
            match &self.home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    fn sample_args() -> AuthLoginArgs {
        AuthLoginArgs {
            email: None,
            password: None,
            browser: false,
            console_url: DEFAULT_CONSOLE_URL.to_string(),
            json: false,
            config: None,
            api_url: None,
            profile: "workspace".to_string(),
        }
    }

    fn sample_response() -> login::LoginResponse {
        login::LoginResponse {
            token: "vdt_secret".to_string(),
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            org_id: "org_123".to_string(),
            org_name: "Verdictan".to_string(),
            org_slug: Some("verdictan".to_string()),
            project_id: "proj_123".to_string(),
            role: "owner".to_string(),
            authz_version: 7,
            user_id: Some("user_123".to_string()),
            email: Some("owner@example.com".to_string()),
            display_name: Some("Owner".to_string()),
            team_ids: vec!["team_a".to_string(), "team_b".to_string()],
            capabilities: vec!["gateway:write".to_string()],
        }
    }

    #[test]
    fn resolve_login_mode_rejects_mixed_browser_and_password_inputs() {
        let mut args = sample_args();
        args.browser = true;
        args.email = Some("user@example.com".to_string());

        let err = resolve_login_mode(&args, true).expect_err("mixed auth mode must fail");
        assert_eq!(err.error_code(), "cli.config_invalid");
    }

    #[test]
    fn resolve_login_mode_requires_both_password_fields() {
        let mut args = sample_args();
        args.email = Some("user@example.com".to_string());

        let err = resolve_login_mode(&args, true).expect_err("partial password input must fail");
        assert_eq!(err.error_code(), "cli.config_invalid");
    }

    #[test]
    fn resolve_login_mode_covers_browser_password_and_non_terminal_paths() {
        let mut args = sample_args();
        args.browser = true;
        assert_eq!(
            resolve_login_mode(&args, true).expect("browser mode"),
            LoginMode::Browser
        );

        let mut password_args = sample_args();
        password_args.email = Some("user@example.com".to_string());
        password_args.password = Some("secret".to_string());
        assert_eq!(
            resolve_login_mode(&password_args, true).expect("password mode"),
            LoginMode::Password {
                email: "user@example.com".to_string(),
                password: "secret".to_string(),
            }
        );

        let tty_default = resolve_login_mode(&sample_args(), true).expect("tty defaults browser");
        assert_eq!(tty_default, LoginMode::Browser);

        let err =
            resolve_login_mode(&sample_args(), false).expect_err("non-terminal browser must fail");
        assert_eq!(err.error_code(), "cli.auth_failed");
    }

    #[test]
    fn success_lines_include_teams_only_when_present() {
        assert_eq!(
            success_lines("workspace", &sample_response()),
            vec![
                "authenticated profile workspace".to_string(),
                "org: Verdictan (org_123)".to_string(),
                "role: owner".to_string(),
                "teams: team_a, team_b".to_string(),
            ]
        );

        let mut response = sample_response();
        response.team_ids.clear();
        assert_eq!(
            success_lines("workspace", &response),
            vec![
                "authenticated profile workspace".to_string(),
                "org: Verdictan (org_123)".to_string(),
                "role: owner".to_string(),
            ]
        );
    }

    #[test]
    fn persist_credentials_writes_selected_profile() {
        let _lock = crate::config::test_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _guard = EnvGuard::capture();
        let temp = tempdir().expect("tempdir");
        std::env::set_var("VERDICTAN_TEST_HOME", temp.path());
        std::env::set_var("HOME", temp.path());

        let response = sample_response();
        persist_credentials("workspace", "https://api.example.com", &response)
            .expect("persist credentials");

        let stored = credential_store::load(Some("workspace"))
            .expect("load stored credentials")
            .expect("stored credentials");
        assert_eq!(stored.api_url, "https://api.example.com");
        assert_eq!(stored.api_token, "vdt_secret");
        assert_eq!(
            stored.team_ids,
            vec!["team_a".to_string(), "team_b".to_string()]
        );
        assert_eq!(stored.email.as_deref(), Some("owner@example.com"));
    }

    #[test]
    fn login_mode_eq_impl() {
        assert_eq!(LoginMode::Browser, LoginMode::Browser);
        assert_eq!(
            LoginMode::Password {
                email: "a@b.com".to_string(),
                password: "pass".to_string(),
            },
            LoginMode::Password {
                email: "a@b.com".to_string(),
                password: "pass".to_string(),
            }
        );
        assert_ne!(
            LoginMode::Browser,
            LoginMode::Password {
                email: "a@b.com".to_string(),
                password: "pass".to_string(),
            }
        );
    }

    #[test]
    fn login_mode_debug_impl() {
        let browser = LoginMode::Browser;
        let debug = format!("{:?}", browser);
        assert!(debug.contains("Browser"));

        let password = LoginMode::Password {
            email: "user@test.com".to_string(),
            password: "secret".to_string(),
        };
        let debug = format!("{:?}", password);
        assert!(debug.contains("Password"));
        assert!(debug.contains("user@test.com"));
    }

    #[test]
    fn resolve_login_mode_browser_non_terminal_fails() {
        let mut args = sample_args();
        args.browser = true;
        let err = resolve_login_mode(&args, false).expect_err("browser needs terminal");
        assert_eq!(err.error_code(), "cli.auth_failed");
    }

    #[test]
    fn resolve_login_mode_password_only_fails() {
        let mut args = sample_args();
        args.password = Some("secret".to_string());
        let err = resolve_login_mode(&args, true).expect_err("needs email too");
        assert_eq!(err.error_code(), "cli.config_invalid");
    }

    #[test]
    fn success_lines_format_with_empty_teams() {
        let mut response = sample_response();
        response.team_ids = vec![];
        let lines = success_lines("default", &response);
        assert_eq!(lines.len(), 3);
        assert!(!lines.iter().any(|l| l.contains("teams:")));
    }

    #[test]
    fn args_debug_impl() {
        let args = sample_args();
        let debug = format!("{:?}", args);
        assert!(debug.contains("AuthLoginArgs"));
        assert!(debug.contains("workspace"));
    }
}
