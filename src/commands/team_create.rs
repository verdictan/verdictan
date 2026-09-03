// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan team create` — create a new team.
//!
//! # Module wiring
//! Add `pub(crate) mod team_create;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct TeamCreateArgs {
    /// Team name (unique in the organization).
    #[arg(long)]
    pub(crate) name: String,

    /// Optional description.
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
pub(crate) async fn run_async(args: TeamCreateArgs) -> Result<(), CliError> {
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

    let mut body = serde_json::json!({ "name": args.name });
    if let Some(desc) = args.description {
        body["description"] = serde_json::Value::String(desc);
    }

    let result = client.post_json_value("/v1/teams", &body).await?;

    if args.json {
        return print_json(&result);
    }

    let id = result
        .get("team")
        .and_then(|team| team.get("team_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    println!("created team {id}");
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
    fn create_body_name_only() {
        let body = json!({ "name": "engineering" });
        assert_eq!(body["name"], "engineering");
        assert!(body.get("description").is_none());
    }

    #[test]
    fn create_body_with_description() {
        let mut body = json!({ "name": "platform" });
        let desc = Some("Platform team".to_string());
        if let Some(d) = desc {
            body["description"] = serde_json::Value::String(d);
        }
        assert_eq!(body["description"], "Platform team");
    }

    #[test]
    fn parse_create_response() {
        let result = json!({ "team": { "team_id": "t-1" } });
        let id = result
            .get("team")
            .and_then(|t| t.get("team_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        assert_eq!(id, "t-1");
    }

    #[test]
    fn parse_create_response_missing() {
        let result = json!({});
        let id = result
            .get("team")
            .and_then(|t| t.get("team_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        assert_eq!(id, "-");
    }
}
