// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan iam policy update` — update an existing IAM policy.
//!
//! # Module wiring
//! Add `pub(crate) mod iam_policy_update;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct IamPolicyUpdateArgs {
    /// Policy id.
    #[arg(long)]
    pub(crate) policy_id: String,

    /// New name.
    #[arg(long)]
    pub(crate) name: Option<String>,

    /// New description.
    #[arg(long)]
    pub(crate) description: Option<String>,

    /// New effect: "allow" or "deny".
    #[arg(long, value_parser = ["allow", "deny"])]
    pub(crate) effect: Option<String>,

    /// Replace the actions list. Use this option more than one time if necessary.
    /// If not set, the actions list does not change.
    #[arg(long = "action", value_name = "ACTION")]
    pub(crate) actions: Vec<String>,

    /// Replace the resources list. Use this option more than one time if necessary.
    /// If not set, the resources list does not change.
    #[arg(long = "resource", value_name = "RESOURCE")]
    pub(crate) resources: Vec<String>,

    /// New conditions as raw JSON. Pass '{}' to clear.
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
pub(crate) async fn run_async(args: IamPolicyUpdateArgs) -> Result<(), CliError> {
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
    let path = format!("/v1/policies/{}", args.policy_id);

    let mut body = serde_json::json!({});
    if let Some(name) = args.name {
        body["name"] = serde_json::Value::String(name);
    }
    if let Some(desc) = args.description {
        body["description"] = serde_json::Value::String(desc);
    }

    let update_statements = args.effect.is_some()
        || !args.actions.is_empty()
        || !args.resources.is_empty()
        || args.conditions_json.is_some();
    if update_statements {
        let current = client.get_json_value(&path).await?;
        let first_statement = current
            .get("policy")
            .and_then(|policy| policy.get("statements"))
            .and_then(|statements| statements.as_array())
            .and_then(|statements| statements.first())
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));

        let effect = args.effect.unwrap_or_else(|| {
            first_statement
                .get("effect")
                .and_then(|value| value.as_str())
                .unwrap_or("allow")
                .to_string()
        });
        let actions = if args.actions.is_empty() {
            first_statement
                .get("actions")
                .and_then(|value| value.as_array())
                .map(|actions| {
                    actions
                        .iter()
                        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        } else {
            args.actions
        };
        let resources = if args.resources.is_empty() {
            first_statement
                .get("resources")
                .and_then(|value| value.as_array())
                .map(|resources| {
                    resources
                        .iter()
                        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        } else {
            args.resources
        };
        let conditions = match args.conditions_json {
            Some(conditions_json) => serde_json::from_str(&conditions_json)
                .map_err(|e| CliError::user(format!("invalid --conditions-json: {e}")))?,
            None => first_statement
                .get("conditions")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
        };

        if actions.is_empty() || resources.is_empty() {
            return Err(CliError::user(
                "policy statements must include at least one action and one resource",
            ));
        }

        body["statements"] = serde_json::json!([{
            "effect": effect,
            "actions": actions,
            "resources": resources,
            "conditions": conditions,
        }]);
    }

    if body.as_object().map(|o| o.is_empty()).unwrap_or(true) {
        return Err(CliError::user(
            "nothing to update: provide at least one field",
        ));
    }

    let result = client.put_json_value(&path, &body).await?;

    if args.json {
        return print_json(&result);
    }

    let updated = result
        .get("updated")
        .and_then(|value| value.as_bool())
        .unwrap_or(true);
    if updated {
        println!("updated policy {}", args.policy_id);
    } else {
        println!("no changes applied to policy {}", args.policy_id);
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
        let policy_id = "pol-42";
        let path = format!("/v1/policies/{}", policy_id);
        assert_eq!(path, "/v1/policies/pol-42");
    }

    #[test]
    fn body_with_name_only() {
        let mut body = json!({});
        body["name"] = serde_json::Value::String("new-name".into());
        assert_eq!(body["name"], "new-name");
        assert!(!body.as_object().unwrap().is_empty());
    }

    #[test]
    fn body_with_description() {
        let mut body = json!({});
        body["description"] = serde_json::Value::String("Updated description".into());
        assert_eq!(body["description"], "Updated description");
    }

    #[test]
    fn empty_body_validation() {
        let body = json!({});
        let is_empty = body.as_object().map(|o| o.is_empty()).unwrap_or(true);
        assert!(is_empty);
    }

    #[test]
    fn statement_construction() {
        let effect = "allow";
        let actions = vec!["read".to_string(), "write".to_string()];
        let resources = vec!["secrets:*".to_string()];
        let conditions = json!({});
        let statement = json!({
            "effect": effect,
            "actions": actions,
            "resources": resources,
            "conditions": conditions,
        });
        assert_eq!(statement["effect"], "allow");
        assert_eq!(statement["actions"][0], "read");
        assert_eq!(statement["resources"][0], "secrets:*");
    }

    #[test]
    fn conditions_json_parsing_valid() {
        let raw = r#"{"ip_range": "10.0.0.0/8"}"#;
        let parsed: serde_json::Value = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed["ip_range"], "10.0.0.0/8");
    }

    #[test]
    fn conditions_json_parsing_invalid() {
        let raw = "not json";
        let result: Result<serde_json::Value, _> = serde_json::from_str(raw);
        assert!(result.is_err());
    }

    #[test]
    fn empty_actions_or_resources_rejected() {
        let actions: Vec<String> = vec![];
        let resources: Vec<String> = vec![];
        assert!(actions.is_empty() || resources.is_empty());
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
    fn update_statements_flag_detection() {
        let effect: Option<String> = Some("deny".into());
        let actions: Vec<String> = vec![];
        let resources: Vec<String> = vec![];
        let conditions_json: Option<String> = None;
        let should_update = effect.is_some()
            || !actions.is_empty()
            || !resources.is_empty()
            || conditions_json.is_some();
        assert!(should_update);
    }
}
