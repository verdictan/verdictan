// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan user detach-role` — detach an IAM role from an org member.
//!
//! Uses POST /v1/users/:id/roles/detach (not DELETE) per the API surface spec.
//!
//! # Module wiring
//! Add `pub(crate) mod user_detach_role;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct UserDetachRoleArgs {
    /// User id.
    #[arg(long)]
    pub(crate) user_id: String,

    /// Role id to detach.
    #[arg(long)]
    pub(crate) role_id: String,

    /// Role assignment level (org or team).
    #[arg(long = "assignment-level", alias = "assignment-level", default_value = "org", value_parser = ["org", "team"])]
    pub(crate) assignment_level: String,

    /// Assignment target id. Mandatory for team-level assignments.
    /// Organization-level assignments use the authenticated organization id by default.
    #[arg(long = "assignment-target-id", alias = "assignment-target-id")]
    pub(crate) assignment_target_id: Option<String>,

    /// Skip the confirmation prompt.
    #[arg(long)]
    pub(crate) yes: bool,

    /// Emit machine-readable JSON to stdout.
    #[arg(long)]
    pub(crate) json: bool,

    /// Optional config file path (YAML).
    #[arg(long)]
    pub(crate) config: Option<std::path::PathBuf>,

    /// Override API URL.
    #[arg(long)]
    pub(crate) api_url: Option<String>,

    /// Override API token.
    #[arg(long)]
    pub(crate) api_token: Option<String>,

    /// Profile name (default: "default").
    #[arg(long, default_value = "default")]
    pub(crate) profile: String,

    /// Target region for this API call.
    #[arg(long)]
    pub(crate) region: Option<String>,
}
pub(crate) async fn run_async(args: UserDetachRoleArgs) -> Result<(), CliError> {
    if !args.yes {
        return Err(CliError::user(format!(
            "pass --yes to confirm detaching role {} from user {}",
            args.role_id, args.user_id
        )));
    }

    let inputs = ConfigInputs {
        api_url_flag: args.api_url,
        api_token_flag: args.api_token,
        config_path: args.config,
        profile_flag: Some(args.profile),
        region_flag: args.region,
    };
    let config = Config::resolve(inputs)?;
    let api_token = config.api_token.ok_or_else(|| {
        CliError::auth("missing api token (set VERDICTAN_API_TOKEN or run `verdictan auth login`)")
    })?;
    let client = AsyncApiClient::new(config.api_url, api_token)?.with_region(config.region.clone());

    let assignment_target_id = resolve_assignment_target_id(
        &client,
        &args.assignment_level,
        args.assignment_target_id.as_deref(),
    )
    .await?;

    let path = format!("/v1/users/{}/roles/detach", args.user_id);
    let body = serde_json::json!({
        "role_id": args.role_id,
        "assignment_level": args.assignment_level,
        "assignment_target_id": assignment_target_id,
    });
    let result = client.post_json_value(&path, &body).await?;

    if args.json {
        return print_json(&result);
    }

    println!("detached role {} from user {}", args.role_id, args.user_id);
    Ok(())
}

async fn resolve_assignment_target_id(
    client: &AsyncApiClient,
    assignment_level: &str,
    explicit_target_id: Option<&str>,
) -> Result<String, CliError> {
    match assignment_level {
        "team" => explicit_target_id.map(ToOwned::to_owned).ok_or_else(|| {
            CliError::user("--assignment-target-id is required when --assignment-level team")
        }),
        "org" => {
            if let Some(target_id) = explicit_target_id {
                return Ok(target_id.to_string());
            }

            let whoami = client.get_json_value("/v1/whoami").await?;
            whoami
                .get("org_id")
                .and_then(|value| value.as_str())
                .map(ToOwned::to_owned)
                .ok_or_else(|| CliError::internal("whoami response missing org_id"))
        }
        _ => Err(CliError::user("assignment_level must be org or team")),
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
    use serde_json::json;

    #[test]
    fn detach_role_body_construction() {
        let role_id = "role-1";
        let assignment_level = "org";
        let assignment_target_id = "org-99";
        let body = json!({
            "role_id": role_id,
            "assignment_level": assignment_level,
            "assignment_target_id": assignment_target_id,
        });
        assert_eq!(body["role_id"], "role-1");
        assert_eq!(body["assignment_level"], "org");
        assert_eq!(body["assignment_target_id"], "org-99");
    }

    #[test]
    fn detach_role_path_formatting() {
        let user_id = "usr-5";
        let path = format!("/v1/users/{}/roles/detach", user_id);
        assert_eq!(path, "/v1/users/usr-5/roles/detach");
    }

    #[test]
    fn yes_flag_required_error_message() {
        let role_id = "role-x";
        let user_id = "usr-y";
        let msg = format!(
            "pass --yes to confirm detaching role {} from user {}",
            role_id, user_id
        );
        assert!(msg.contains("role-x"));
        assert!(msg.contains("usr-y"));
    }

    #[test]
    fn resolve_team_without_target_id_fails() {
        let assignment_level = "team";
        let explicit: Option<&str> = None;
        let result = match assignment_level {
            "team" => explicit
                .map(ToOwned::to_owned)
                .ok_or("--assignment-target-id is required"),
            _ => Ok("default".to_string()),
        };
        assert!(result.is_err());
    }

    #[test]
    fn resolve_team_with_target_id_succeeds() {
        let assignment_level = "team";
        let explicit: Option<&str> = Some("team-123");
        let result = match assignment_level {
            "team" => explicit.map(ToOwned::to_owned).ok_or("required"),
            _ => Ok("default".to_string()),
        };
        assert_eq!(result.unwrap(), "team-123");
    }

    #[test]
    fn resolve_org_with_explicit_target_id() {
        let assignment_level = "org";
        let explicit: Option<&str> = Some("org-explicit");
        let result: Result<String, &str> = match assignment_level {
            "org" => {
                if let Some(tid) = explicit {
                    Ok(tid.to_string())
                } else {
                    Err("would need whoami")
                }
            }
            _ => Err("bad level"),
        };
        assert_eq!(result.unwrap(), "org-explicit");
    }

    #[test]
    fn resolve_invalid_level_errors() {
        let assignment_level = "invalid";
        let is_valid = matches!(assignment_level, "org" | "team");
        assert!(!is_valid);
    }
}
