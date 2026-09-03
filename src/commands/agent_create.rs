// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan agent create` — create a new agent record.
//!
//! # Module wiring
//! Add `pub(crate) mod agent_create;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct AgentCreateArgs {
    /// Agent name.
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
pub(crate) async fn run_async(args: AgentCreateArgs) -> Result<(), CliError> {
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

    let result = client.post_json_value("/v1/agents", &body).await?;

    if args.json {
        return print_json(&result);
    }

    let id = result.get("id").and_then(|v| v.as_str()).unwrap_or("-");
    println!("created agent {id}");
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
        let body = json!({ "name": "my-agent" });
        assert_eq!(body["name"], "my-agent");
        assert!(body.get("description").is_none());
    }

    #[test]
    fn create_body_with_description() {
        let mut body = json!({ "name": "my-agent" });
        body["description"] = serde_json::Value::String("A test agent".into());
        assert_eq!(body["name"], "my-agent");
        assert_eq!(body["description"], "A test agent");
    }

    #[test]
    fn parse_create_response() {
        let result = json!({"id": "a-new"});
        let id = result.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        assert_eq!(id, "a-new");
    }

    #[test]
    fn parse_create_response_missing_id() {
        let result = json!({});
        let id = result.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        assert_eq!(id, "-");
    }

    #[test]
    fn parse_create_response_non_string_id() {
        let result = json!({"id": 42});
        let id = result.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        assert_eq!(id, "-");
    }

    #[test]
    fn config_inputs_construction() {
        let inputs = crate::config::ConfigInputs {
            api_url_flag: Some("https://api.example.com".to_string()),
            api_token_flag: Some("tok".to_string()),
            config_path: None,
            profile_flag: Some("default".to_string()),
            region_flag: Some("us-east-1".to_string()),
        };
        assert_eq!(
            inputs.api_url_flag.as_deref(),
            Some("https://api.example.com")
        );
        assert_eq!(inputs.region_flag.as_deref(), Some("us-east-1"));
    }

    #[test]
    fn args_debug_impl() {
        let args = super::AgentCreateArgs {
            name: "test".to_string(),
            description: Some("desc".to_string()),
            json: true,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("test"));
        assert!(debug.contains("desc"));
    }

    #[test]
    fn args_with_all_fields() {
        let args = super::AgentCreateArgs {
            name: "production-agent".to_string(),
            description: None,
            json: false,
            config: Some(std::path::PathBuf::from("/etc/verdictan/config.yaml")),
            api_url: Some("https://api.prod.example.com".to_string()),
            api_token: Some("vdt_secret_token".to_string()),
            profile: "production".to_string(),
            region: Some("ap-southeast-1".to_string()),
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("production-agent"));
        assert!(debug.contains("production"));
        assert!(debug.contains("ap-southeast-1"));
    }

    #[test]
    fn create_body_empty_name() {
        let body = json!({ "name": "" });
        assert_eq!(body["name"], "");
        assert!(body.get("description").is_none());
    }

    #[test]
    fn create_body_unicode_name() {
        let body = json!({ "name": "日本語エージェント" });
        assert_eq!(body["name"], "日本語エージェント");
    }

    #[test]
    fn parse_create_response_null_id() {
        let result = json!({"id": null});
        let id = result.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        assert_eq!(id, "-");
    }
}
