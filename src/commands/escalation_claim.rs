// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan escalation claim` — claim a queued escalation.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct EscalationClaimArgs {
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
pub(crate) async fn run_async(args: EscalationClaimArgs) -> Result<(), CliError> {
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

    let path = format!("/v1/escalations/{}/claim", args.escalation_id);
    let value = client
        .post_json_value(&path, &serde_json::json!({}))
        .await?;

    if args.json {
        return print_json(&value);
    }

    println!("claimed escalation {}", args.escalation_id);
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
    fn claim_path_formatting() {
        let esc_id = "esc-42";
        let path = format!("/v1/escalations/{}/claim", esc_id);
        assert_eq!(path, "/v1/escalations/esc-42/claim");
    }

    #[test]
    fn claim_empty_body_serializes() {
        let body = json!({});
        let s = serde_json::to_string(&body).unwrap();
        assert_eq!(s, "{}");
    }

    #[test]
    fn output_message() {
        let esc_id = "esc-claimed";
        let msg = format!("claimed escalation {}", esc_id);
        assert!(msg.contains("claimed escalation"));
        assert!(msg.contains("esc-claimed"));
    }

    #[test]
    fn claim_path_with_special_characters() {
        let esc_id = "esc-with-special/chars";
        let path = format!("/v1/escalations/{}/claim", esc_id);
        assert_eq!(path, "/v1/escalations/esc-with-special/chars/claim");
    }

    #[test]
    fn claim_path_with_uuid() {
        let esc_id = "550e8400-e29b-41d4-a716-446655440000";
        let path = format!("/v1/escalations/{}/claim", esc_id);
        assert!(path.contains("550e8400-e29b-41d4-a716-446655440000"));
        assert!(path.ends_with("/claim"));
    }

    #[test]
    fn args_debug_impl() {
        let args = super::EscalationClaimArgs {
            escalation_id: "esc-1".to_string(),
            json: true,
            config: None,
            api_url: Some("http://localhost".to_string()),
            api_token: Some("tok".to_string()),
            profile: "default".to_string(),
            region: Some("us-east-1".to_string()),
        };
        let debug_str = format!("{:?}", args);
        assert!(debug_str.contains("esc-1"));
        assert!(debug_str.contains("us-east-1"));
    }

    #[test]
    fn args_default_profile() {
        let args = super::EscalationClaimArgs {
            escalation_id: "e1".to_string(),
            json: false,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        assert_eq!(args.profile, "default");
        assert!(!args.json);
        assert!(args.config.is_none());
    }

    #[test]
    fn config_inputs_construction() {
        use crate::config::ConfigInputs;
        let inputs = ConfigInputs {
            api_url_flag: Some("http://api".to_string()),
            api_token_flag: Some("token".to_string()),
            config_path: None,
            profile_flag: Some("prod".to_string()),
            region_flag: Some("eu-west".to_string()),
        };
        assert_eq!(inputs.api_url_flag.as_deref(), Some("http://api"));
        assert_eq!(inputs.region_flag.as_deref(), Some("eu-west"));
    }
}
