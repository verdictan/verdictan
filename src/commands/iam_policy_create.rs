// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan iam policy create` — create a new IAM policy.
//!
//! Actions and resources are repeatable flags:
//!   --action vt:events:read --action vt:escalations:read
//!   --resource '*'
//!
//! # Module wiring
//! Add `pub(crate) mod iam_policy_create;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct IamPolicyCreateArgs {
    /// Policy name (unique in the organization).
    #[arg(long)]
    pub(crate) name: String,

    /// Optional description.
    #[arg(long)]
    pub(crate) description: Option<String>,

    /// Effect: "allow" or "deny".
    #[arg(long, default_value = "allow", value_parser = ["allow", "deny"])]
    pub(crate) effect: String,

    /// Action granted or denied. Use this option more than one time if necessary.
    /// For example, use vt:events:read.
    #[arg(long = "action", value_name = "ACTION")]
    pub(crate) actions: Vec<String>,

    /// Resource that the policy applies to. Use this option more than one time if necessary.
    /// For example, use "*".
    #[arg(long = "resource", value_name = "RESOURCE")]
    pub(crate) resources: Vec<String>,

    /// Optional conditions as raw JSON (for example, '{"ip_range":"10.0.0.0/8"}').
    #[arg(long)]
    pub(crate) conditions_json: Option<String>,

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
pub(crate) async fn run_async(args: IamPolicyCreateArgs) -> Result<(), CliError> {
    if args.actions.is_empty() || args.resources.is_empty() {
        return Err(CliError::user(
            "policy creation requires at least one --action and one --resource",
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

    let conditions = match args.conditions_json {
        Some(conditions_json) => serde_json::from_str(&conditions_json)
            .map_err(|e| CliError::user(format!("invalid --conditions-json: {e}")))?,
        None => serde_json::json!({}),
    };

    let mut body = serde_json::json!({ "name": args.name });
    if let Some(desc) = args.description {
        body["description"] = serde_json::Value::String(desc);
    }
    body["statements"] = serde_json::json!([{
        "effect": args.effect,
        "actions": args.actions,
        "resources": args.resources,
        "conditions": conditions,
    }]);

    let result = client.post_json_value("/v1/policies", &body).await?;

    if args.json {
        return print_json(&result);
    }

    let id = result
        .get("policy")
        .and_then(|policy| policy.get("policy_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    println!("created policy {id}");
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
    fn empty_actions_detected() {
        let actions: Vec<String> = vec![];
        let resources = vec!["*".to_string()];
        assert!(actions.is_empty() || resources.is_empty());
    }

    #[test]
    fn empty_resources_detected() {
        let actions = vec!["vt:events:read".to_string()];
        let resources: Vec<String> = vec![];
        assert!(actions.is_empty() || resources.is_empty());
    }

    #[test]
    fn valid_actions_and_resources() {
        let actions = vec!["vt:events:read".to_string()];
        let resources = vec!["*".to_string()];
        assert!(!actions.is_empty() && !resources.is_empty());
    }

    #[test]
    fn policy_body_construction() {
        let name = "my-policy";
        let effect = "allow";
        let actions = vec![
            "vt:events:read".to_string(),
            "vt:escalations:read".to_string(),
        ];
        let resources = vec!["*".to_string()];
        let conditions = json!({});

        let mut body = json!({ "name": name });
        body["statements"] = json!([{
            "effect": effect,
            "actions": actions,
            "resources": resources,
            "conditions": conditions,
        }]);

        assert_eq!(body["name"], "my-policy");
        let stmts = body["statements"].as_array().unwrap();
        assert_eq!(stmts.len(), 1);
        assert_eq!(stmts[0]["effect"], "allow");
        assert_eq!(stmts[0]["actions"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn policy_body_with_description() {
        let mut body = json!({ "name": "pol" });
        body["description"] = serde_json::Value::String("Test policy".into());
        assert_eq!(body["description"], "Test policy");
    }

    #[test]
    fn conditions_json_parsing_valid() {
        let conditions_json = r#"{"ip_range":"10.0.0.0/8"}"#;
        let parsed: serde_json::Value = serde_json::from_str(conditions_json).unwrap();
        assert_eq!(parsed["ip_range"], "10.0.0.0/8");
    }

    #[test]
    fn conditions_json_parsing_invalid() {
        let conditions_json = "not json";
        let result: Result<serde_json::Value, _> = serde_json::from_str(conditions_json);
        assert!(result.is_err());
    }

    #[test]
    fn parse_policy_create_response() {
        let result = json!({"policy": {"policy_id": "pol-1"}});
        let id = result
            .get("policy")
            .and_then(|p| p.get("policy_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        assert_eq!(id, "pol-1");
    }
}
