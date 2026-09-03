// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan user update` — update an org member's profile fields.
//!
//! # Module wiring
//! Add `pub(crate) mod user_update;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct UserUpdateArgs {
    /// User id.
    #[arg(long)]
    pub(crate) user_id: String,

    /// New display name.
    #[arg(long)]
    pub(crate) name: Option<String>,

    /// New organization role.
    #[arg(long)]
    pub(crate) org_role: Option<String>,

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
pub(crate) async fn run_async(args: UserUpdateArgs) -> Result<(), CliError> {
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

    let mut body = serde_json::json!({});
    if let Some(name) = args.name {
        body["display_name"] = serde_json::Value::String(name);
    }
    if let Some(org_role) = args.org_role {
        body["org_role"] = serde_json::Value::String(org_role);
    }

    if body.as_object().map(|o| o.is_empty()).unwrap_or(true) {
        return Err(CliError::user(
            "nothing to update: provide --name or --org-role",
        ));
    }

    let path = format!("/v1/users/{}", args.user_id);
    let result = client.put_json_value(&path, &body).await?;

    if args.json {
        return print_json(&result);
    }

    let id = result
        .get("user")
        .and_then(|user| user.get("user_id"))
        .and_then(|v| v.as_str())
        .unwrap_or(&args.user_id);
    println!("updated user {id}");
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
    fn update_body_with_name_only() {
        let mut body = json!({});
        let name = Some("Alice".to_string());
        if let Some(n) = name {
            body["display_name"] = serde_json::Value::String(n);
        }
        assert_eq!(body["display_name"], "Alice");
        assert!(body.get("org_role").is_none());
    }

    #[test]
    fn update_body_with_org_role_only() {
        let mut body = json!({});
        let org_role = Some("admin".to_string());
        if let Some(r) = org_role {
            body["org_role"] = serde_json::Value::String(r);
        }
        assert_eq!(body["org_role"], "admin");
        assert!(body.get("display_name").is_none());
    }

    #[test]
    fn update_body_with_both_fields() {
        let mut body = json!({});
        body["display_name"] = serde_json::Value::String("Bob".into());
        body["org_role"] = serde_json::Value::String("member".into());
        assert_eq!(body["display_name"], "Bob");
        assert_eq!(body["org_role"], "member");
    }

    #[test]
    fn empty_body_detected() {
        let body = json!({});
        let is_empty = body.as_object().map(|o| o.is_empty()).unwrap_or(true);
        assert!(is_empty);
    }

    #[test]
    fn non_empty_body_not_detected_as_empty() {
        let mut body = json!({});
        body["display_name"] = serde_json::Value::String("X".into());
        let is_empty = body.as_object().map(|o| o.is_empty()).unwrap_or(true);
        assert!(!is_empty);
    }

    #[test]
    fn parse_update_response_with_wrapper() {
        let result = json!({ "user": { "user_id": "u-1" } });
        let id = result
            .get("user")
            .and_then(|user| user.get("user_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("fallback");
        assert_eq!(id, "u-1");
    }

    #[test]
    fn parse_update_response_without_wrapper() {
        let result = json!({});
        let fallback = "u-fallback".to_string();
        let id = result
            .get("user")
            .and_then(|user| user.get("user_id"))
            .and_then(|v| v.as_str())
            .unwrap_or(&fallback);
        assert_eq!(id, "u-fallback");
    }
}
