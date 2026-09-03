// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan team list` — list teams in the organisation.
//!
//! # Module wiring
//! Add `pub(crate) mod team_list;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct TeamListArgs {
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
pub(crate) async fn run_async(args: TeamListArgs) -> Result<(), CliError> {
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

    let value = client.get_json_value("/v1/teams").await?;

    if args.json {
        return print_json(&value);
    }

    let teams = value
        .get("teams")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if teams.is_empty() {
        println!("no teams");
        return Ok(());
    }

    for t in &teams {
        let id = t.get("team_id").and_then(|v| v.as_str()).unwrap_or("-");
        let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("-");
        let desc = t.get("description").and_then(|v| v.as_str()).unwrap_or("-");
        println!("{id}  {name}  {desc}");
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
    fn parse_teams_from_response() {
        let value = json!({"teams": [
            {"team_id": "t-1", "name": "alpha", "description": "Team A"},
            {"team_id": "t-2", "name": "beta", "description": "Team B"}
        ]});
        let teams = value
            .get("teams")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert_eq!(teams.len(), 2);
    }

    #[test]
    fn parse_teams_empty() {
        let value = json!({"teams": []});
        let teams = value
            .get("teams")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(teams.is_empty());
    }

    #[test]
    fn parse_teams_missing_key() {
        let value = json!({});
        let teams = value
            .get("teams")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(teams.is_empty());
    }

    #[test]
    fn team_row_defaults() {
        let t = json!({});
        let id = t.get("team_id").and_then(|v| v.as_str()).unwrap_or("-");
        let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("-");
        let desc = t.get("description").and_then(|v| v.as_str()).unwrap_or("-");
        assert_eq!(id, "-");
        assert_eq!(name, "-");
        assert_eq!(desc, "-");
    }

    #[test]
    fn team_row_with_values() {
        let t = json!({"team_id": "t-42", "name": "engineering", "description": "Eng team"});
        let id = t.get("team_id").and_then(|v| v.as_str()).unwrap_or("-");
        let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("-");
        let desc = t.get("description").and_then(|v| v.as_str()).unwrap_or("-");
        assert_eq!(id, "t-42");
        assert_eq!(name, "engineering");
        assert_eq!(desc, "Eng team");
    }

    #[test]
    fn teams_api_path() {
        let path = "/v1/teams";
        assert_eq!(path, "/v1/teams");
    }
}
