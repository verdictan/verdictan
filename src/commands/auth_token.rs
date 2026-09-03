// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;

use crate::{
    auth::{
        credential_store,
        token::{
            create_token_async, list_tokens_async, resolve_api_token, revoke_token_async,
            CreateTokenRequest,
        },
    },
    config::{Config, ConfigInputs},
    error::CliError,
    output::json::print_json,
};

#[derive(Debug, Args)]
pub(crate) struct AuthTokenCreateArgs {
    #[arg(long)]
    pub(crate) name: String,

    #[arg(long, default_value = "team")]
    pub(crate) scope: String,

    #[arg(long)]
    pub(crate) team_id: Option<String>,

    #[arg(long)]
    pub(crate) subject_user_id: Option<String>,

    #[arg(long)]
    pub(crate) expires_at: Option<String>,

    #[arg(long = "role-id", required = true)]
    pub(crate) role_ids: Vec<String>,

    #[arg(long)]
    pub(crate) json: bool,

    #[arg(long)]
    pub(crate) config: Option<std::path::PathBuf>,

    #[arg(long)]
    pub(crate) api_url: Option<String>,

    #[arg(long)]
    pub(crate) api_token: Option<String>,

    #[arg(long, default_value = "default")]
    pub(crate) profile: String,
}

#[derive(Debug, Args)]
pub(crate) struct AuthTokenListArgs {
    #[arg(long)]
    pub(crate) json: bool,

    #[arg(long)]
    pub(crate) config: Option<std::path::PathBuf>,

    #[arg(long)]
    pub(crate) api_url: Option<String>,

    #[arg(long)]
    pub(crate) api_token: Option<String>,

    #[arg(long, default_value = "default")]
    pub(crate) profile: String,
}

#[derive(Debug, Args)]
pub(crate) struct AuthTokenRevokeArgs {
    #[arg(long)]
    pub(crate) token_id: String,

    #[arg(long)]
    pub(crate) json: bool,

    #[arg(long)]
    pub(crate) config: Option<std::path::PathBuf>,

    #[arg(long)]
    pub(crate) api_url: Option<String>,

    #[arg(long)]
    pub(crate) api_token: Option<String>,

    #[arg(long, default_value = "default")]
    pub(crate) profile: String,
}
pub(crate) async fn run_create_async(args: AuthTokenCreateArgs) -> Result<(), CliError> {
    let (config, bearer_token) =
        resolve_config(args.config, args.api_url, args.api_token, args.profile)?;
    let response = create_token_async(
        &config.api_url,
        &bearer_token,
        &CreateTokenRequest {
            name: args.name,
            principal_type: args.scope,
            team_id: args.team_id,
            subject_user_id: args.subject_user_id,
            expires_at: args.expires_at,
            role_ids: args.role_ids,
        },
    )
    .await?;

    if args.json {
        return print_json(&serde_json::json!({
            "token": response.token,
            "token_value": response.token_value,
        }));
    }

    for line in create_success_lines(&response) {
        println!("{line}");
    }
    Ok(())
}
pub(crate) async fn run_list_async(args: AuthTokenListArgs) -> Result<(), CliError> {
    let (config, bearer_token) =
        resolve_config(args.config, args.api_url, args.api_token, args.profile)?;
    let response = list_tokens_async(&config.api_url, &bearer_token).await?;

    if args.json {
        return print_json(&serde_json::json!({ "tokens": response.tokens }));
    }

    for token in response.tokens {
        println!("{}", token_record_line(&token));
    }
    Ok(())
}
pub(crate) async fn run_revoke_async(args: AuthTokenRevokeArgs) -> Result<(), CliError> {
    let (config, bearer_token) =
        resolve_config(args.config, args.api_url, args.api_token, args.profile)?;
    let response = revoke_token_async(&config.api_url, &bearer_token, &args.token_id).await?;

    if args.json {
        return print_json(
            &serde_json::json!({ "revoked": response.revoked, "token_id": args.token_id }),
        );
    }

    if let Some(line) = revoke_success_line(response.revoked, &args.token_id) {
        println!("{line}");
    }
    Ok(())
}

fn resolve_config(
    config_path: Option<std::path::PathBuf>,
    api_url: Option<String>,
    api_token: Option<String>,
    profile: String,
) -> Result<(Config, String), CliError> {
    let config = Config::resolve(ConfigInputs {
        api_url_flag: api_url,
        api_token_flag: None,
        config_path,
        profile_flag: Some(profile.clone()),
        region_flag: None,
    })?;
    let stored = credential_store::load(Some(&profile))?;
    let bearer_token = resolve_api_token(api_token, stored.as_ref())?;

    let config = if config.api_url == crate::config::DEFAULT_API_URL {
        if let Some(stored) = stored {
            Config {
                api_url: stored.api_url,
                api_token: None,
                profile: config.profile,
                region: config.region,
            }
        } else {
            config
        }
    } else {
        config
    };

    Ok((config, bearer_token))
}

fn create_success_lines(response: &crate::auth::token::CreateTokenResponse) -> Vec<String> {
    vec![
        format!("created token {}", response.token.token_id),
        format!("principal_type: {}", response.token.principal_type),
        format!("secret: {}", response.token_value),
    ]
}

fn token_record_line(token: &crate::auth::token::TokenRecord) -> String {
    let status = if token.revoked_at.is_some() {
        "revoked"
    } else {
        "active"
    };
    format!(
        "{}\t{}\t{}\t{}",
        token.token_id, token.principal_type, token.token_prefix, status
    )
}

fn revoke_success_line(revoked: bool, token_id: &str) -> Option<String> {
    revoked.then(|| format!("revoked token {token_id}"))
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
    use crate::auth::credential_store::{self, StoredCredentials};
    use crate::auth::token::{CreateTokenResponse, TokenRecord, TokenRoleSummary};
    use tempfile::tempdir;

    struct EnvGuard {
        verdictan_test_home: Option<std::ffi::OsString>,
        home: Option<std::ffi::OsString>,
        api_url: Option<std::ffi::OsString>,
        api_token: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn capture() -> Self {
            Self {
                verdictan_test_home: std::env::var_os("VERDICTAN_TEST_HOME"),
                home: std::env::var_os("HOME"),
                api_url: std::env::var_os("VERDICTAN_API_URL"),
                api_token: std::env::var_os(crate::auth::token::API_TOKEN_ENV),
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
            match &self.api_url {
                Some(value) => std::env::set_var("VERDICTAN_API_URL", value),
                None => std::env::remove_var("VERDICTAN_API_URL"),
            }
            match &self.api_token {
                Some(value) => std::env::set_var(crate::auth::token::API_TOKEN_ENV, value),
                None => std::env::remove_var(crate::auth::token::API_TOKEN_ENV),
            }
        }
    }

    fn sample_stored_credentials(api_url: &str, token: &str) -> StoredCredentials {
        StoredCredentials {
            api_url: api_url.to_string(),
            api_token: token.to_string(),
            expires_at: Some("2030-01-01T00:00:00Z".to_string()),
            org_id: "org_123".to_string(),
            org_name: "Verdictan".to_string(),
            org_slug: Some("verdictan".to_string()),
            project_id: "proj_123".to_string(),
            role: "owner".to_string(),
            user_id: Some("user_123".to_string()),
            email: Some("owner@example.com".to_string()),
            display_name: Some("Owner".to_string()),
            team_ids: vec!["team_1".to_string()],
            capabilities: vec!["gateway:write".to_string()],
        }
    }

    fn sample_token_record() -> TokenRecord {
        TokenRecord {
            token_id: "tok_123".to_string(),
            name: "Build Token".to_string(),
            token_prefix: "vdt_abc".to_string(),
            principal_type: "team".to_string(),
            team_id: Some("team_1".to_string()),
            subject_user_id: None,
            created_by: Some("user_123".to_string()),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: Some("2030-01-01T00:00:00Z".to_string()),
            last_used_at: None,
            revoked_at: None,
            roles: vec![TokenRoleSummary {
                role_id: "role_owner".to_string(),
                name: "owner".to_string(),
                identifier: Some("owner".to_string()),
                display_name: Some("Owner".to_string()),
                is_system: false,
            }],
        }
    }

    #[test]
    fn create_success_lines_and_revoke_success_line_format_expected_output() {
        let response = CreateTokenResponse {
            token: sample_token_record(),
            token_value: "secret_value".to_string(),
        };

        assert_eq!(
            create_success_lines(&response),
            vec![
                "created token tok_123".to_string(),
                "principal_type: team".to_string(),
                "secret: secret_value".to_string(),
            ]
        );
        assert_eq!(
            revoke_success_line(true, "tok_123"),
            Some("revoked token tok_123".to_string())
        );
        assert_eq!(revoke_success_line(false, "tok_123"), None);
    }

    #[test]
    fn token_record_line_marks_active_and_revoked_tokens() {
        let active = sample_token_record();
        assert_eq!(token_record_line(&active), "tok_123\tteam\tvdt_abc\tactive");

        let mut revoked = sample_token_record();
        revoked.revoked_at = Some("2026-02-01T00:00:00Z".to_string());
        assert_eq!(
            token_record_line(&revoked),
            "tok_123\tteam\tvdt_abc\trevoked"
        );
    }

    #[test]
    fn resolve_config_prefers_stored_profile_defaults_and_allows_overrides() {
        let _lock = crate::config::test_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _guard = EnvGuard::capture();
        let temp = tempdir().expect("tempdir");
        std::env::set_var("VERDICTAN_TEST_HOME", temp.path());
        std::env::set_var("HOME", temp.path());
        std::env::remove_var("VERDICTAN_API_URL");
        std::env::remove_var(crate::auth::token::API_TOKEN_ENV);

        credential_store::save(
            Some("workspace"),
            sample_stored_credentials("https://stored.example.com", "stored_token"),
        )
        .expect("save credentials");

        let (config, bearer) = resolve_config(None, None, None, "workspace".to_string())
            .expect("resolve stored config");
        assert_eq!(config.api_url, "https://stored.example.com");
        assert_eq!(bearer, "stored_token");

        let (config, bearer) = resolve_config(
            None,
            Some("https://explicit.example.com".to_string()),
            Some("explicit_token".to_string()),
            "workspace".to_string(),
        )
        .expect("resolve explicit config");
        assert_eq!(config.api_url, "https://explicit.example.com");
        assert_eq!(bearer, "explicit_token");
    }

    #[test]
    fn revoke_success_line_true_includes_token_id() {
        let line = revoke_success_line(true, "tok_abc");
        assert_eq!(line, Some("revoked token tok_abc".to_string()));
    }

    #[test]
    fn revoke_success_line_false_returns_none() {
        let line = revoke_success_line(false, "tok_abc");
        assert_eq!(line, None);
    }

    #[test]
    fn token_record_line_active_format() {
        let mut record = sample_token_record();
        record.token_id = "tok_x".to_string();
        record.principal_type = "org".to_string();
        record.token_prefix = "vdt_xyz".to_string();
        record.revoked_at = None;
        let line = token_record_line(&record);
        assert_eq!(line, "tok_x\torg\tvdt_xyz\tactive");
    }

    #[test]
    fn create_success_lines_format() {
        let response = CreateTokenResponse {
            token: sample_token_record(),
            token_value: "vdt_full_secret_value".to_string(),
        };
        let lines = create_success_lines(&response);
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("created token"));
        assert!(lines[1].starts_with("principal_type:"));
        assert!(lines[2].starts_with("secret:"));
        assert!(lines[2].contains("vdt_full_secret_value"));
    }

    #[test]
    fn args_debug_impl_create() {
        let args = AuthTokenCreateArgs {
            name: "build-token".to_string(),
            scope: "team".to_string(),
            team_id: Some("team-1".to_string()),
            subject_user_id: None,
            expires_at: None,
            role_ids: vec!["role_a".to_string()],
            json: false,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("build-token"));
    }

    #[test]
    fn args_debug_impl_list() {
        let args = AuthTokenListArgs {
            json: true,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("AuthTokenListArgs"));
    }

    #[test]
    fn args_debug_impl_revoke() {
        let args = AuthTokenRevokeArgs {
            token_id: "tok_123".to_string(),
            json: false,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("tok_123"));
    }
}
