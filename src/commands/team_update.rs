// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan team update` — update an existing team.
//!
//! # Module wiring
//! Add `pub(crate) mod team_update;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct TeamUpdateArgs {
    /// Team id.
    #[arg(long)]
    pub(crate) team_id: String,

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
pub(crate) async fn run_async(args: TeamUpdateArgs) -> Result<(), CliError> {
    if args.name.is_none() && args.description.is_none() {
        return Err(CliError::user(
            "nothing to update: provide --name or --description",
        ));
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

    let current_team = if args.name.is_none() {
        let path = format!("/v1/teams/{}", args.team_id);
        Some(client.get_json_value(&path).await?)
    } else {
        None
    };

    let mut body = serde_json::json!({});
    if let Some(name) = args.name {
        body["name"] = serde_json::Value::String(name);
    } else if let Some(current_team) = &current_team {
        let current_name = current_team
            .get("team")
            .or(Some(current_team))
            .and_then(|team| team.get("name"))
            .and_then(|value| value.as_str())
            .ok_or_else(|| CliError::internal("team response missing name"))?;
        body["name"] = serde_json::Value::String(current_name.to_string());
    }
    if let Some(desc) = args.description {
        body["description"] = serde_json::Value::String(desc);
    }

    if body.as_object().map(|o| o.is_empty()).unwrap_or(true) {
        return Err(CliError::user(
            "nothing to update: provide --name or --description",
        ));
    }

    let path = format!("/v1/teams/{}", args.team_id);
    let result = client.put_json_value(&path, &body).await?;

    if args.json {
        return print_json(&result);
    }

    let id = result
        .get("team")
        .and_then(|team| team.get("team_id"))
        .and_then(|v| v.as_str())
        .unwrap_or(&args.team_id);
    println!("updated team {id}");
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
    fn update_body_with_name() {
        let mut body = json!({});
        body["name"] = serde_json::Value::String("new-name".into());
        assert_eq!(body["name"], "new-name");
    }

    #[test]
    fn update_body_with_description() {
        let mut body = json!({});
        body["description"] = serde_json::Value::String("updated desc".into());
        assert_eq!(body["description"], "updated desc");
    }

    #[test]
    fn empty_update_body_detected() {
        let body = json!({});
        let is_empty = body.as_object().map(|o| o.is_empty()).unwrap_or(true);
        assert!(is_empty);
    }

    #[test]
    fn non_empty_update_body() {
        let mut body = json!({});
        body["name"] = serde_json::Value::String("x".into());
        let is_empty = body.as_object().map(|o| o.is_empty()).unwrap_or(true);
        assert!(!is_empty);
    }

    #[test]
    fn extract_current_name_from_team_response() {
        let current_team = json!({"team": {"name": "old-name"}});
        let name = current_team
            .get("team")
            .or(Some(&current_team))
            .and_then(|t| t.get("name"))
            .and_then(|v| v.as_str());
        assert_eq!(name, Some("old-name"));
    }

    #[test]
    fn extract_current_name_fallback_to_root() {
        let current_team = json!({"name": "root-name"});
        let name = current_team
            .get("team")
            .or(Some(&current_team))
            .and_then(|t| t.get("name"))
            .and_then(|v| v.as_str());
        assert_eq!(name, Some("root-name"));
    }

    #[test]
    fn parse_update_response() {
        let result = json!({"team": {"team_id": "t-5"}});
        let id = result
            .get("team")
            .and_then(|t| t.get("team_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("fallback");
        assert_eq!(id, "t-5");
    }
}
