// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan history share <session_id> --with <user_id|email>` — share a history
//! session with another user by adding them as a member.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct HistoryShareArgs {
    /// Session id to share.
    pub(crate) session_id: String,

    /// User id or email to share with.
    #[arg(long = "with")]
    pub(crate) with_user: String,

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
pub(crate) async fn run_async(args: HistoryShareArgs) -> Result<(), CliError> {
    let client = build_client(args.api_url, args.api_token, args.config, args.profile)?;

    let sid = urlencoding::encode(&args.session_id);
    let path = format!("/v1/history/sessions/{sid}/members");
    let body = serde_json::json!({ "user": args.with_user });
    let response = client.post_json_value(&path, &body).await?;

    if args.json {
        return print_json(&response);
    }

    println!("shared session {} with {}", args.session_id, args.with_user);

    let members = response
        .get("members")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if !members.is_empty() {
        println!("members:");
        for member in &members {
            let id = member
                .get("user_id")
                .or_else(|| member.get("email"))
                .and_then(|v| v.as_str())
                .unwrap_or("-");
            let role = member
                .get("role")
                .and_then(|v| v.as_str())
                .unwrap_or("member");
            println!("  {id} ({role})");
        }
    }

    Ok(())
}

fn build_client(
    api_url: Option<String>,
    api_token: Option<String>,
    config_path: Option<std::path::PathBuf>,
    profile: String,
) -> Result<AsyncApiClient, CliError> {
    let inputs = ConfigInputs {
        api_url_flag: api_url,
        api_token_flag: api_token,
        config_path,
        profile_flag: Some(profile),
        region_flag: None,
    };
    let config = Config::resolve(inputs)?;
    let token = config.api_token.ok_or_else(|| {
        CliError::auth("missing api token (set VERDICTAN_API_TOKEN or run `verdictan auth login`)")
    })?;
    AsyncApiClient::new(config.api_url, token)
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
    fn share_path_encoding() {
        let session_id = "sess 123";
        let sid = urlencoding::encode(session_id);
        let path = format!("/v1/history/sessions/{sid}/members");
        assert_eq!(path, "/v1/history/sessions/sess%20123/members");
    }

    #[test]
    fn share_path_no_encoding_needed() {
        let session_id = "sess-abc";
        let sid = urlencoding::encode(session_id);
        let path = format!("/v1/history/sessions/{sid}/members");
        assert_eq!(path, "/v1/history/sessions/sess-abc/members");
    }

    #[test]
    fn share_body_construction() {
        let with_user = "user@example.com";
        let body = json!({ "user": with_user });
        assert_eq!(body["user"], "user@example.com");
    }

    #[test]
    fn parse_members_response() {
        let response = json!({"members": [
            {"user_id": "u-1", "role": "owner"},
            {"email": "a@b.com", "role": "member"}
        ]});
        let members = response
            .get("members")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert_eq!(members.len(), 2);
    }

    #[test]
    fn member_id_prefers_user_id() {
        let member = json!({"user_id": "u-1", "email": "a@b.com"});
        let id = member
            .get("user_id")
            .or_else(|| member.get("email"))
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        assert_eq!(id, "u-1");
    }

    #[test]
    fn member_id_falls_back_to_email() {
        let member = json!({"email": "a@b.com"});
        let id = member
            .get("user_id")
            .or_else(|| member.get("email"))
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        assert_eq!(id, "a@b.com");
    }

    #[test]
    fn member_role_default() {
        let member = json!({});
        let role = member
            .get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("member");
        assert_eq!(role, "member");
    }
}
