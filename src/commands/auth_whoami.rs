// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;

use crate::auth::{credential_store, token};
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct AuthWhoamiArgs {
    #[arg(long)]
    pub(crate) json: bool,

    /// Optional config file path (YAML).
    #[arg(long)]
    pub(crate) config: Option<std::path::PathBuf>,

    /// Override API URL.
    #[arg(long)]
    pub(crate) api_url: Option<String>,

    #[arg(long)]
    pub(crate) api_token: Option<String>,

    /// Profile name (default: "default").
    #[arg(long, default_value = "default")]
    pub(crate) profile: String,
}
pub(crate) async fn run_async(args: AuthWhoamiArgs) -> Result<(), CliError> {
    let inputs = ConfigInputs {
        api_url_flag: args.api_url,
        api_token_flag: None,
        config_path: args.config,
        profile_flag: Some(args.profile.clone()),
        region_flag: None,
    };

    let config = Config::resolve(inputs)?;
    let stored = credential_store::load(Some(&args.profile))?;
    let api_token = token::resolve_api_token(args.api_token, stored.as_ref())?;
    let api_url = resolved_api_url(config.api_url, stored.as_ref());

    let value = serde_json::to_value(token::whoami_async(&api_url, &api_token).await?).map_err(
        |error| CliError::internal(format!("failed to serialize whoami response: {error}")),
    )?;

    if args.json {
        print_json(&value)?;
        return Ok(());
    }

    let response: token::WhoamiResponse = serde_json::from_value(value).map_err(|error| {
        CliError::internal(format!("failed to decode whoami response: {error}"))
    })?;

    for line in whoami_lines(&response) {
        println!("{line}");
    }
    Ok(())
}

fn resolved_api_url(
    config_api_url: String,
    stored: Option<&credential_store::StoredCredentials>,
) -> String {
    match stored {
        Some(credentials) if config_api_url == crate::config::DEFAULT_API_URL => {
            credentials.api_url.clone()
        }
        _ => config_api_url,
    }
}

fn whoami_lines(response: &token::WhoamiResponse) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(email) = response.email.as_deref() {
        lines.push(format!("user: {email}"));
    }
    lines.push(format!("org: {} ({})", response.org_name, response.org_id));
    lines.push(format!("project: {}", response.project_id));
    lines.push(format!("role: {}", response.role));
    lines.push(format!("auth_method: {}", response.auth_method));
    if !response.team_ids.is_empty() {
        lines.push(format!("teams: {}", response.team_ids.join(", ")));
    }
    if !response.capabilities.is_empty() {
        lines.push(format!(
            "capabilities: {}",
            response.capabilities.join(", ")
        ));
    }
    if !response.resolved_roles.is_empty() {
        let roles = response
            .resolved_roles
            .iter()
            .map(|role| {
                let label = role.role_display_name.as_deref().unwrap_or(&role.role_name);
                let level = role
                    .assignment_level
                    .as_deref()
                    .or(role.binding_kind.as_deref())
                    .unwrap_or("unknown");
                let target = role.assignment_target_id.as_deref().unwrap_or("*");
                format!("{label}:{level}:{target}")
            })
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!("resolved_roles: {roles}"));
    }
    lines
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
    use crate::auth::credential_store::StoredCredentials;

    fn sample_stored_credentials(api_url: &str) -> StoredCredentials {
        StoredCredentials {
            api_url: api_url.to_string(),
            api_token: "vdt_secret".to_string(),
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

    fn sample_whoami_response() -> token::WhoamiResponse {
        token::WhoamiResponse {
            user_id: Some("user_123".to_string()),
            email: Some("owner@example.com".to_string()),
            display_name: Some("Owner".to_string()),
            org_id: "org_123".to_string(),
            org_name: "Verdictan".to_string(),
            project_id: "proj_123".to_string(),
            role: "owner".to_string(),
            auth_method: "token".to_string(),
            team_ids: vec!["team_a".to_string(), "team_b".to_string()],
            capabilities: vec!["gateway:write".to_string(), "events:read".to_string()],
            resolved_roles: vec![
                token::WhoamiResolvedRole {
                    role_id: "role_admin".to_string(),
                    role_name: "admin".to_string(),
                    role_display_name: Some("Administrator".to_string()),
                    assignment_level: Some("team".to_string()),
                    assignment_target_id: Some("team_a".to_string()),
                    binding_kind: None,
                },
                token::WhoamiResolvedRole {
                    role_id: "role_reader".to_string(),
                    role_name: "reader".to_string(),
                    role_display_name: None,
                    assignment_level: None,
                    assignment_target_id: None,
                    binding_kind: Some("org".to_string()),
                },
            ],
            token_scope: None,
        }
    }

    #[test]
    fn resolved_api_url_prefers_stored_url_only_for_default_config_url() {
        let stored = sample_stored_credentials("https://stored.example.com");

        assert_eq!(
            resolved_api_url(crate::config::DEFAULT_API_URL.to_string(), Some(&stored)),
            "https://stored.example.com"
        );
        assert_eq!(
            resolved_api_url("https://explicit.example.com".to_string(), Some(&stored)),
            "https://explicit.example.com"
        );
        assert_eq!(
            resolved_api_url(crate::config::DEFAULT_API_URL.to_string(), None),
            crate::config::DEFAULT_API_URL
        );
    }

    #[test]
    fn whoami_lines_include_optional_sections_when_present() {
        assert_eq!(
            whoami_lines(&sample_whoami_response()),
            vec![
                "user: owner@example.com".to_string(),
                "org: Verdictan (org_123)".to_string(),
                "project: proj_123".to_string(),
                "role: owner".to_string(),
                "auth_method: token".to_string(),
                "teams: team_a, team_b".to_string(),
                "capabilities: gateway:write, events:read".to_string(),
                "resolved_roles: Administrator:team:team_a, reader:org:*".to_string(),
            ]
        );
    }

    #[test]
    fn whoami_lines_omit_optional_sections_when_absent() {
        let mut response = sample_whoami_response();
        response.email = None;
        response.team_ids.clear();
        response.capabilities.clear();
        response.resolved_roles.clear();

        assert_eq!(
            whoami_lines(&response),
            vec![
                "org: Verdictan (org_123)".to_string(),
                "project: proj_123".to_string(),
                "role: owner".to_string(),
                "auth_method: token".to_string(),
            ]
        );
    }

    #[test]
    fn resolved_api_url_with_explicit_non_default_url_and_no_stored() {
        assert_eq!(
            resolved_api_url("https://custom.example.com".to_string(), None),
            "https://custom.example.com"
        );
    }

    #[test]
    fn whoami_lines_single_team_and_capability() {
        let mut response = sample_whoami_response();
        response.team_ids = vec!["solo-team".to_string()];
        response.capabilities = vec!["read-only".to_string()];
        response.resolved_roles.clear();

        let lines = whoami_lines(&response);
        assert!(lines.contains(&"teams: solo-team".to_string()));
        assert!(lines.contains(&"capabilities: read-only".to_string()));
    }

    #[test]
    fn whoami_lines_role_with_no_display_name_uses_role_name() {
        let mut response = sample_whoami_response();
        response.resolved_roles = vec![token::WhoamiResolvedRole {
            role_id: "role_x".to_string(),
            role_name: "auditor".to_string(),
            role_display_name: None,
            assignment_level: None,
            assignment_target_id: None,
            binding_kind: None,
        }];

        let lines = whoami_lines(&response);
        assert!(lines.contains(&"resolved_roles: auditor:unknown:*".to_string()));
    }

    #[test]
    fn args_debug_impl() {
        let args = AuthWhoamiArgs {
            json: true,
            config: None,
            api_url: Some("https://api.test".to_string()),
            api_token: Some("tok".to_string()),
            profile: "default".to_string(),
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("AuthWhoamiArgs"));
    }
}
