// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan agent get` — fetch a single agent by id.
//!
//! # Module wiring
//! Add `pub(crate) mod agent_get;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct AgentGetArgs {
    /// Agent id.
    #[arg(long)]
    pub(crate) agent_id: String,

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
pub(crate) async fn run_async(args: AgentGetArgs) -> Result<(), CliError> {
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

    let path = format!("/v1/agents/{}", args.agent_id);
    let value = client.get_json_value(&path).await?;

    if args.json {
        return print_json(&value);
    }

    let a = &value;
    let id = a.get("id").and_then(|v| v.as_str()).unwrap_or("-");
    let name = a.get("name").and_then(|v| v.as_str()).unwrap_or("-");
    let desc = a.get("description").and_then(|v| v.as_str()).unwrap_or("-");
    let status = a.get("status").and_then(|v| v.as_str()).unwrap_or("-");
    let created = a.get("created_at").and_then(|v| v.as_str()).unwrap_or("-");
    let updated = a.get("updated_at").and_then(|v| v.as_str()).unwrap_or("-");

    println!("id:          {id}");
    println!("name:        {name}");
    println!("description: {desc}");
    println!("status:      {status}");
    println!("created_at:  {created}");
    println!("updated_at:  {updated}");

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
    fn get_path_formatting() {
        let agent_id = "ag-42";
        let path = format!("/v1/agents/{}", agent_id);
        assert_eq!(path, "/v1/agents/ag-42");
    }

    #[test]
    fn parse_agent_fields() {
        let a = json!({
            "id": "ag-1",
            "name": "my-agent",
            "description": "Test agent",
            "status": "active",
            "created_at": "2025-01-01",
            "updated_at": "2025-06-01"
        });
        assert_eq!(a.get("id").and_then(|v| v.as_str()).unwrap(), "ag-1");
        assert_eq!(a.get("name").and_then(|v| v.as_str()).unwrap(), "my-agent");
        assert_eq!(a.get("status").and_then(|v| v.as_str()).unwrap(), "active");
    }

    #[test]
    fn parse_agent_field_defaults() {
        let a = json!({});
        assert_eq!(a.get("id").and_then(|v| v.as_str()).unwrap_or("-"), "-");
        assert_eq!(a.get("name").and_then(|v| v.as_str()).unwrap_or("-"), "-");
        assert_eq!(
            a.get("description").and_then(|v| v.as_str()).unwrap_or("-"),
            "-"
        );
        assert_eq!(a.get("status").and_then(|v| v.as_str()).unwrap_or("-"), "-");
        assert_eq!(
            a.get("created_at").and_then(|v| v.as_str()).unwrap_or("-"),
            "-"
        );
        assert_eq!(
            a.get("updated_at").and_then(|v| v.as_str()).unwrap_or("-"),
            "-"
        );
    }

    #[test]
    fn parse_agent_numeric_id_falls_to_default() {
        let a = json!({"id": 123});
        assert_eq!(a.get("id").and_then(|v| v.as_str()).unwrap_or("-"), "-");
    }

    #[test]
    fn parse_agent_null_field() {
        let a = json!({"name": null});
        assert_eq!(a.get("name").and_then(|v| v.as_str()).unwrap_or("-"), "-");
    }

    #[test]
    fn parse_agent_with_optional_fields() {
        let a = json!({
            "id": "ag-1",
            "name": "bot",
            "description": null,
            "status": "active",
            "created_at": "2025-01-01",
            "updated_at": null
        });
        assert_eq!(a.get("id").and_then(|v| v.as_str()).unwrap(), "ag-1");
        assert_eq!(
            a.get("description").and_then(|v| v.as_str()).unwrap_or("-"),
            "-"
        );
        assert_eq!(
            a.get("updated_at").and_then(|v| v.as_str()).unwrap_or("-"),
            "-"
        );
    }

    #[test]
    fn args_debug_impl() {
        let args = super::AgentGetArgs {
            agent_id: "ag-test".to_string(),
            json: true,
            config: None,
            api_url: Some("https://api.test".to_string()),
            api_token: Some("tok".to_string()),
            profile: "default".to_string(),
            region: Some("us-east-1".to_string()),
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("ag-test"));
        assert!(debug.contains("us-east-1"));
    }

    #[test]
    fn get_path_with_uuid() {
        let agent_id = "550e8400-e29b-41d4-a716-446655440000";
        let path = format!("/v1/agents/{}", agent_id);
        assert!(path.starts_with("/v1/agents/550e8400"));
    }

    #[test]
    fn parse_agent_boolean_field_falls_to_default() {
        let a = json!({"status": true});
        assert_eq!(a.get("status").and_then(|v| v.as_str()).unwrap_or("-"), "-");
    }

    #[test]
    fn parse_agent_array_field_falls_to_default() {
        let a = json!({"name": ["not", "a", "string"]});
        assert_eq!(a.get("name").and_then(|v| v.as_str()).unwrap_or("-"), "-");
    }
}
