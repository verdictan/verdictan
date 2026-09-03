// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan agent update` — update an existing agent.
//!
//! # Module wiring
//! Add `pub(crate) mod agent_update;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct AgentUpdateArgs {
    /// Agent id.
    #[arg(long)]
    pub(crate) agent_id: String,

    /// New name.
    #[arg(long)]
    pub(crate) name: Option<String>,

    /// New description.
    #[arg(long)]
    pub(crate) description: Option<String>,

    /// New status (for example, "active" or "inactive").
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
pub(crate) async fn run_async(args: AgentUpdateArgs) -> Result<(), CliError> {
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
    if let Some(status) = args.status {
        body["status"] = serde_json::Value::String(status);
    }

    if body.as_object().map(|o| o.is_empty()).unwrap_or(true) {
        return Err(CliError::user(
            "nothing to update: provide --name, --description, or --status",
        ));
    }

    let path = format!("/v1/agents/{}", args.agent_id);
    let result = client.put_json_value(&path, &body).await?;

    if args.json {
        return print_json(&result);
    }

    let id = result
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or(&args.agent_id);
    println!("updated agent {id}");
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
        body["description"] = serde_json::Value::String("new desc".into());
        assert_eq!(body["description"], "new desc");
    }

    #[test]
    fn update_body_with_status() {
        let mut body = json!({});
        body["status"] = serde_json::Value::String("inactive".into());
        assert_eq!(body["status"], "inactive");
    }

    #[test]
    fn empty_body_detected() {
        let body = json!({});
        let is_empty = body.as_object().map(|o| o.is_empty()).unwrap_or(true);
        assert!(is_empty);
    }

    #[test]
    fn non_empty_body() {
        let mut body = json!({});
        body["name"] = serde_json::Value::String("x".into());
        let is_empty = body.as_object().map(|o| o.is_empty()).unwrap_or(true);
        assert!(!is_empty);
    }

    #[test]
    fn update_path_formatting() {
        let agent_id = "ag-42";
        let path = format!("/v1/agents/{}", agent_id);
        assert_eq!(path, "/v1/agents/ag-42");
    }

    #[test]
    fn parse_update_response_id() {
        let result = json!({"id": "ag-1"});
        let fallback = "ag-fallback".to_string();
        let id = result
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or(&fallback);
        assert_eq!(id, "ag-1");
    }

    #[test]
    fn parse_update_response_missing_id_uses_fallback() {
        let result = json!({});
        let fallback = "ag-fallback".to_string();
        let id = result
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or(&fallback);
        assert_eq!(id, "ag-fallback");
    }

    #[test]
    fn update_body_all_fields() {
        let mut body = json!({});
        body["name"] = serde_json::Value::String("new-name".into());
        body["description"] = serde_json::Value::String("new-desc".into());
        body["status"] = serde_json::Value::String("inactive".into());
        let is_empty = body.as_object().map(|o| o.is_empty()).unwrap_or(true);
        assert!(!is_empty);
        assert_eq!(body.as_object().unwrap().len(), 3);
    }

    #[test]
    fn empty_body_non_object_treated_as_empty() {
        let body = json!(null);
        let is_empty = body.as_object().map(|o| o.is_empty()).unwrap_or(true);
        assert!(is_empty);
    }

    #[test]
    fn args_debug_impl() {
        let args = super::AgentUpdateArgs {
            agent_id: "ag-42".to_string(),
            name: Some("updated-name".to_string()),
            description: None,
            status: Some("inactive".to_string()),
            json: false,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("ag-42"));
        assert!(debug.contains("updated-name"));
        assert!(debug.contains("inactive"));
    }

    #[test]
    fn empty_body_array_treated_as_empty() {
        let body = json!([]);
        let is_empty = body.as_object().map(|o| o.is_empty()).unwrap_or(true);
        assert!(is_empty);
    }

    #[test]
    fn empty_body_string_treated_as_empty() {
        let body = json!("string");
        let is_empty = body.as_object().map(|o| o.is_empty()).unwrap_or(true);
        assert!(is_empty);
    }

    #[test]
    fn parse_update_response_null_id() {
        let result = json!({"id": null});
        let fallback = "ag-fallback".to_string();
        let id = result
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or(&fallback);
        assert_eq!(id, "ag-fallback");
    }

    #[test]
    fn update_body_single_description() {
        let mut body = json!({});
        body["description"] = serde_json::Value::String("only desc".into());
        let is_empty = body.as_object().map(|o| o.is_empty()).unwrap_or(true);
        assert!(!is_empty);
        assert_eq!(body.as_object().unwrap().len(), 1);
    }
}
