// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan role update` — update an existing IAM role.
//!
//! # Module wiring
//! Add `pub(crate) mod role_update;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct RoleUpdateArgs {
    /// Role id.
    #[arg(long)]
    pub(crate) role_id: String,

    /// New name.
    #[arg(long)]
    pub(crate) name: Option<String>,

    /// New description.
    #[arg(long)]
    pub(crate) description: Option<String>,

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
pub(crate) async fn run_async(args: RoleUpdateArgs) -> Result<(), CliError> {
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
        body["name"] = serde_json::Value::String(name);
    }
    if let Some(desc) = args.description {
        body["description"] = serde_json::Value::String(desc);
    }

    if body.as_object().map(|o| o.is_empty()).unwrap_or(true) {
        return Err(CliError::user(
            "nothing to update: provide --name or --description",
        ));
    }

    let path = format!("/v1/roles/{}", args.role_id);
    let result = client.put_json_value(&path, &body).await?;

    if args.json {
        return print_json(&result);
    }

    let updated = result
        .get("updated")
        .and_then(|value| value.as_bool())
        .unwrap_or(true);
    if updated {
        println!("updated role {}", args.role_id);
    } else {
        println!("no changes applied to role {}", args.role_id);
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
    use serde_json::json;

    #[test]
    fn update_path_formatting() {
        let role_id = "r-42";
        let path = format!("/v1/roles/{}", role_id);
        assert_eq!(path, "/v1/roles/r-42");
    }

    #[test]
    fn body_with_name_only() {
        let mut body = json!({});
        body["name"] = serde_json::Value::String("new-name".into());
        assert_eq!(body["name"], "new-name");
        assert!(body.get("description").is_none());
    }

    #[test]
    fn body_with_description_only() {
        let mut body = json!({});
        body["description"] = serde_json::Value::String("new-desc".into());
        assert_eq!(body["description"], "new-desc");
        assert!(body.get("name").is_none());
    }

    #[test]
    fn body_with_both_fields() {
        let mut body = json!({});
        body["name"] = serde_json::Value::String("n".into());
        body["description"] = serde_json::Value::String("d".into());
        assert!(!body.as_object().unwrap().is_empty());
    }

    #[test]
    fn empty_body_validation() {
        let body = json!({});
        let is_empty = body.as_object().map(|o| o.is_empty()).unwrap_or(true);
        assert!(is_empty);
    }

    #[test]
    fn parse_updated_response() {
        let result = json!({"updated": true});
        let updated = result
            .get("updated")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        assert!(updated);
    }

    #[test]
    fn parse_not_updated_response() {
        let result = json!({"updated": false});
        let updated = result
            .get("updated")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        assert!(!updated);
    }
}
