// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan escalation unclaim` — release a claimed escalation back to the queue.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct EscalationUnclaimArgs {
    /// Escalation id.
    #[arg(long)]
    pub(crate) escalation_id: String,

    #[arg(long)]
    pub(crate) json: bool,

    #[arg(long)]
    pub(crate) config: Option<std::path::PathBuf>,

    #[arg(long)]
    pub(crate) api_url: Option<String>,

    #[arg(long)]
    pub(crate) api_token: Option<String>,

    #[arg(long, default_value = "default")]
    pub(crate) profile: String,

    /// Target region for this API call.
    #[arg(long)]
    pub(crate) region: Option<String>,
}
pub(crate) async fn run_async(args: EscalationUnclaimArgs) -> Result<(), CliError> {
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

    let path = format!("/v1/escalations/{}/unclaim", args.escalation_id);
    let value = client
        .post_json_value(&path, &serde_json::json!({}))
        .await?;

    if args.json {
        return print_json(&value);
    }

    println!("unclaimed escalation {}", args.escalation_id);
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
    fn unclaim_path_formatting() {
        let esc_id = "esc-7";
        let path = format!("/v1/escalations/{}/unclaim", esc_id);
        assert_eq!(path, "/v1/escalations/esc-7/unclaim");
    }

    #[test]
    fn unclaim_empty_body_serializes() {
        let body = json!({});
        let s = serde_json::to_string(&body).unwrap();
        assert_eq!(s, "{}");
    }

    #[test]
    fn output_message() {
        let esc_id = "esc-unclaimed";
        let msg = format!("unclaimed escalation {}", esc_id);
        assert!(msg.contains("unclaimed escalation"));
        assert!(msg.contains("esc-unclaimed"));
    }

    #[test]
    fn unclaim_path_with_uuid() {
        let esc_id = "550e8400-e29b-41d4-a716-446655440000";
        let path = format!("/v1/escalations/{}/unclaim", esc_id);
        assert!(path.starts_with("/v1/escalations/"));
        assert!(path.ends_with("/unclaim"));
        assert!(path.contains("550e8400"));
    }

    #[test]
    fn unclaim_path_with_empty_id() {
        let esc_id = "";
        let path = format!("/v1/escalations/{}/unclaim", esc_id);
        assert_eq!(path, "/v1/escalations//unclaim");
    }

    #[test]
    fn args_debug_impl() {
        let args = super::EscalationUnclaimArgs {
            escalation_id: "esc-7".to_string(),
            json: false,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let debug_str = format!("{:?}", args);
        assert!(debug_str.contains("esc-7"));
        assert!(debug_str.contains("default"));
    }

    #[test]
    fn args_with_all_options() {
        let args = super::EscalationUnclaimArgs {
            escalation_id: "esc-full".to_string(),
            json: true,
            config: Some(std::path::PathBuf::from("/tmp/config.yaml")),
            api_url: Some("http://api.example.com".to_string()),
            api_token: Some("token-123".to_string()),
            profile: "staging".to_string(),
            region: Some("ap-southeast-1".to_string()),
        };
        assert!(args.json);
        assert_eq!(args.escalation_id, "esc-full");
        assert_eq!(args.profile, "staging");
        assert_eq!(args.region.as_deref(), Some("ap-southeast-1"));
    }
}
