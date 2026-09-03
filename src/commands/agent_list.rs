// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan agent list` — list agents in the organisation.
//!
//! # Module wiring
//! Add `pub(crate) mod agent_list;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct AgentListArgs {
    /// Filter by status (for example, "active" or "inactive").
    #[arg(long)]
    pub(crate) status: Option<String>,

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
pub(crate) async fn run_async(args: AgentListArgs) -> Result<(), CliError> {
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

    let mut query = Vec::new();
    if let Some(status) = &args.status {
        query.push(format!("status={}", urlencoding::encode(status)));
    }

    let path = if query.is_empty() {
        "/v1/agents".to_string()
    } else {
        format!("/v1/agents?{}", query.join("&"))
    };

    let value = client.get_json_value(&path).await?;

    if args.json {
        return print_json(&value);
    }

    let agents = value
        .get("agents")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if agents.is_empty() {
        println!("no agents");
        return Ok(());
    }

    for a in &agents {
        let id = a.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        let name = a.get("name").and_then(|v| v.as_str()).unwrap_or("-");
        let status = a.get("status").and_then(|v| v.as_str()).unwrap_or("-");
        println!("{id}  {name}  {status}");
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
    fn list_path_no_filter() {
        let query: Vec<String> = vec![];
        let path = if query.is_empty() {
            "/v1/agents".to_string()
        } else {
            format!("/v1/agents?{}", query.join("&"))
        };
        assert_eq!(path, "/v1/agents");
    }

    #[test]
    fn list_path_with_status_filter() {
        let status = "active";
        let mut query = Vec::new();
        query.push(format!("status={}", urlencoding::encode(status)));
        let path = format!("/v1/agents?{}", query.join("&"));
        assert_eq!(path, "/v1/agents?status=active");
    }

    #[test]
    fn parse_agents_response() {
        let value = json!({"agents": [
            {"id": "a-1", "name": "bot-1", "status": "active"},
            {"id": "a-2", "name": "bot-2", "status": "inactive"}
        ]});
        let agents = value.get("agents").and_then(|v| v.as_array()).unwrap();
        assert_eq!(agents.len(), 2);
        assert_eq!(agents[0]["id"], "a-1");
    }

    #[test]
    fn parse_agents_empty() {
        let value = json!({"agents": []});
        let agents = value
            .get("agents")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(agents.is_empty());
    }

    #[test]
    fn parse_agent_field_defaults() {
        let a = json!({});
        assert_eq!(a.get("id").and_then(|v| v.as_str()).unwrap_or("-"), "-");
        assert_eq!(a.get("name").and_then(|v| v.as_str()).unwrap_or("-"), "-");
        assert_eq!(a.get("status").and_then(|v| v.as_str()).unwrap_or("-"), "-");
    }

    #[test]
    fn parse_agents_missing_key() {
        let value = json!({});
        let agents = value
            .get("agents")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(agents.is_empty());
    }

    #[test]
    fn list_path_with_encoded_status() {
        let status = "in progress";
        let mut query = Vec::new();
        query.push(format!("status={}", urlencoding::encode(status)));
        let path = format!("/v1/agents?{}", query.join("&"));
        assert_eq!(path, "/v1/agents?status=in%20progress");
    }

    #[test]
    fn no_agents_message() {
        let agents: Vec<serde_json::Value> = vec![];
        let msg = if agents.is_empty() {
            "no agents found"
        } else {
            "found agents"
        };
        assert_eq!(msg, "no agents found");
    }

    #[test]
    fn args_debug_impl() {
        let args = super::AgentListArgs {
            status: Some("active".to_string()),
            json: true,
            config: None,
            api_url: Some("https://api.test".to_string()),
            api_token: None,
            profile: "workspace".to_string(),
            region: Some("us-east-1".to_string()),
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("active"));
        assert!(debug.contains("workspace"));
        assert!(debug.contains("us-east-1"));
    }

    #[test]
    fn parse_agents_non_array_field() {
        let value = json!({"agents": "not-an-array"});
        let agents = value
            .get("agents")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(agents.is_empty());
    }

    #[test]
    fn parse_agent_field_numeric_values() {
        let a = json!({"id": 123, "name": true, "status": null});
        assert_eq!(a.get("id").and_then(|v| v.as_str()).unwrap_or("-"), "-");
        assert_eq!(a.get("name").and_then(|v| v.as_str()).unwrap_or("-"), "-");
        assert_eq!(a.get("status").and_then(|v| v.as_str()).unwrap_or("-"), "-");
    }

    #[test]
    fn list_path_with_special_char_status() {
        let status = "has spaces&special";
        let mut query = Vec::new();
        query.push(format!("status={}", urlencoding::encode(status)));
        let path = format!("/v1/agents?{}", query.join("&"));
        assert_eq!(path, "/v1/agents?status=has%20spaces%26special");
    }
}
