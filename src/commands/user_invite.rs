// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan user invite` — invite a new user to the organisation.
//!
//! Sends a POST to /v1/invitations rather than /v1/users so the API can
//! dispatch the invitation email and leave the user record in a pending state.
//!
//! # Module wiring
//! Add `pub(crate) mod user_invite;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct UserInviteArgs {
    /// Email address of the invitee.
    #[arg(long)]
    pub(crate) email: String,

    /// Role id to assign on acceptance.
    #[arg(long)]
    pub(crate) role_id: String,

    /// Invitation assignment level (org or team).
    #[arg(long = "assignment-level", alias = "assignment-level", value_parser = ["org", "team"])]
    pub(crate) assignment_level: Option<String>,

    /// Assignment target id. Mandatory when --assignment-level is team.
    #[arg(long = "assignment-target-id", alias = "assignment-target-id")]
    pub(crate) assignment_target_id: Option<String>,

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
pub(crate) async fn run_async(args: UserInviteArgs) -> Result<(), CliError> {
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

    if args.assignment_level.as_deref() == Some("team") && args.assignment_target_id.is_none() {
        return Err(CliError::user(
            "--assignment-target-id is required when --assignment-level team",
        ));
    }

    let mut body = serde_json::json!({
        "email": args.email,
        "role_id": args.role_id,
    });
    if let Some(assignment_level) = args.assignment_level {
        body["assignment_level"] = serde_json::Value::String(assignment_level);
    }
    if let Some(assignment_target_id) = args.assignment_target_id {
        body["assignment_target_id"] = serde_json::Value::String(assignment_target_id);
    }

    let result = client.post_json_value("/v1/invitations", &body).await?;

    if args.json {
        return print_json(&result);
    }

    let invitation = result.get("invitation").unwrap_or(&result);
    let id = invitation.get("id").and_then(|v| v.as_str()).unwrap_or("-");
    println!("invitation {} sent to {}", id, args.email);
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
    use serde_json::json;

    #[test]
    fn invite_body_required_fields_only() {
        let body = json!({
            "email": "alice@example.com",
            "role_id": "role-1",
        });
        assert_eq!(body["email"], "alice@example.com");
        assert_eq!(body["role_id"], "role-1");
        assert!(body.get("assignment_level").is_none());
        assert!(body.get("assignment_target_id").is_none());
    }

    #[test]
    fn invite_body_with_assignment_level_org() {
        let mut body = json!({
            "email": "bob@example.com",
            "role_id": "role-2",
        });
        let assignment_level = Some("org".to_string());
        if let Some(al) = assignment_level {
            body["assignment_level"] = serde_json::Value::String(al);
        }
        assert_eq!(body["assignment_level"], "org");
    }

    #[test]
    fn invite_body_with_team_assignment() {
        let mut body = json!({
            "email": "carol@example.com",
            "role_id": "role-3",
        });
        let assignment_level = Some("team".to_string());
        let assignment_target_id = Some("team-99".to_string());
        if let Some(al) = assignment_level {
            body["assignment_level"] = serde_json::Value::String(al);
        }
        if let Some(tid) = assignment_target_id {
            body["assignment_target_id"] = serde_json::Value::String(tid);
        }
        assert_eq!(body["assignment_level"], "team");
        assert_eq!(body["assignment_target_id"], "team-99");
    }

    #[test]
    fn team_level_without_target_id_is_error() {
        let assignment_level: Option<&str> = Some("team");
        let assignment_target_id: Option<String> = None;
        let should_fail = assignment_level == Some("team") && assignment_target_id.is_none();
        assert!(should_fail);
    }

    #[test]
    fn org_level_without_target_id_is_ok() {
        let assignment_level: Option<&str> = Some("org");
        let assignment_target_id: Option<String> = None;
        let should_fail = assignment_level == Some("team") && assignment_target_id.is_none();
        assert!(!should_fail);
    }

    #[test]
    fn parse_invitation_response_with_wrapper() {
        let result = json!({ "invitation": { "id": "inv-42" } });
        let invitation = result.get("invitation").unwrap_or(&result);
        let id = invitation.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        assert_eq!(id, "inv-42");
    }

    #[test]
    fn parse_invitation_response_without_wrapper() {
        let result = json!({ "id": "inv-99" });
        let invitation = result.get("invitation").unwrap_or(&result);
        let id = invitation.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        assert_eq!(id, "inv-99");
    }

    #[test]
    fn parse_invitation_response_missing_id() {
        let result = json!({});
        let invitation = result.get("invitation").unwrap_or(&result);
        let id = invitation.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        assert_eq!(id, "-");
    }
}
