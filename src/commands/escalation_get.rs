// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan escalation get` — fetch a single escalation by id.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct EscalationGetArgs {
    /// Escalation id.
    #[arg(long)]
    pub(crate) escalation_id: String,

    /// Include triggering event context (`?include=context`).
    #[arg(long)]
    pub(crate) include_context: bool,

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
pub(crate) async fn run_async(args: EscalationGetArgs) -> Result<(), CliError> {
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

    let suffix = if args.include_context {
        "?include=context"
    } else {
        ""
    };
    let path = format!("/v1/escalations/{}{suffix}", args.escalation_id);
    let value = client.get_json_value(&path).await?;

    if args.json {
        return print_json(&value);
    }

    let e = value.get("escalation").unwrap_or(&value);
    println!(
        "id:       {}",
        e.get("escalation_id")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
    );
    println!(
        "status:   {}",
        e.get("status").and_then(|v| v.as_str()).unwrap_or("-")
    );
    println!(
        "reason:   {}",
        e.get("reason_code").and_then(|v| v.as_str()).unwrap_or("-")
    );
    println!(
        "created:  {}",
        e.get("created_at").and_then(|v| v.as_str()).unwrap_or("-")
    );
    if let Some(claimed_by) = e.get("claimed_by").and_then(|v| v.as_str()) {
        println!("claimed_by: {claimed_by}");
    }
    if let Some(resolution) = e.get("resolution").and_then(|v| v.as_str()) {
        println!("resolution: {resolution}");
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
    fn get_path_without_context() {
        let esc_id = "esc-1";
        let include_context = false;
        let suffix = if include_context {
            "?include=context"
        } else {
            ""
        };
        let path = format!("/v1/escalations/{}{suffix}", esc_id);
        assert_eq!(path, "/v1/escalations/esc-1");
    }

    #[test]
    fn get_path_with_context() {
        let esc_id = "esc-2";
        let include_context = true;
        let suffix = if include_context {
            "?include=context"
        } else {
            ""
        };
        let path = format!("/v1/escalations/{}{suffix}", esc_id);
        assert_eq!(path, "/v1/escalations/esc-2?include=context");
    }

    #[test]
    fn parse_escalation_with_wrapper() {
        let value = json!({"escalation": {
            "escalation_id": "esc-1",
            "status": "queued",
            "reason_code": "pii_detected",
            "created_at": "2025-01-01"
        }});
        let e = value.get("escalation").unwrap_or(&value);
        assert_eq!(
            e.get("escalation_id").and_then(|v| v.as_str()).unwrap(),
            "esc-1"
        );
        assert_eq!(e.get("status").and_then(|v| v.as_str()).unwrap(), "queued");
    }

    #[test]
    fn parse_escalation_without_wrapper() {
        let value = json!({
            "escalation_id": "esc-3",
            "status": "claimed",
            "reason_code": "budget_exceeded"
        });
        let e = value.get("escalation").unwrap_or(&value);
        assert_eq!(
            e.get("escalation_id").and_then(|v| v.as_str()).unwrap(),
            "esc-3"
        );
    }

    #[test]
    fn parse_escalation_field_defaults() {
        let e = json!({});
        assert_eq!(
            e.get("escalation_id")
                .and_then(|v| v.as_str())
                .unwrap_or("-"),
            "-"
        );
        assert_eq!(e.get("status").and_then(|v| v.as_str()).unwrap_or("-"), "-");
    }

    #[test]
    fn optional_claimed_by_present() {
        let e = json!({"claimed_by": "user-1"});
        let claimed = e.get("claimed_by").and_then(|v| v.as_str());
        assert_eq!(claimed, Some("user-1"));
    }

    #[test]
    fn optional_claimed_by_absent() {
        let e = json!({});
        let claimed = e.get("claimed_by").and_then(|v| v.as_str());
        assert!(claimed.is_none());
    }

    #[test]
    fn optional_resolution_present() {
        let e = json!({"resolution": "allow"});
        let res = e.get("resolution").and_then(|v| v.as_str());
        assert_eq!(res, Some("allow"));
    }

    #[test]
    fn optional_resolution_absent() {
        let e = json!({});
        let res = e.get("resolution").and_then(|v| v.as_str());
        assert!(res.is_none());
    }

    #[test]
    fn parse_escalation_full_fields() {
        let e = json!({
            "escalation_id": "esc-full",
            "status": "resolved",
            "reason_code": "budget_exceeded",
            "created_at": "2025-01-01T00:00:00Z",
            "claimed_by": "user-5",
            "resolution": "block",
            "resolution_note": "Exceeds policy limits"
        });
        assert_eq!(
            e.get("escalation_id").and_then(|v| v.as_str()).unwrap(),
            "esc-full"
        );
        assert_eq!(
            e.get("resolution_note").and_then(|v| v.as_str()).unwrap(),
            "Exceeds policy limits"
        );
    }

    #[test]
    fn parse_escalation_null_fields_fall_to_default() {
        let e = json!({"escalation_id": null, "status": null});
        assert_eq!(
            e.get("escalation_id")
                .and_then(|v| v.as_str())
                .unwrap_or("-"),
            "-"
        );
        assert_eq!(e.get("status").and_then(|v| v.as_str()).unwrap_or("-"), "-");
    }

    #[test]
    fn get_path_with_uuid_id() {
        let id = "550e8400-e29b-41d4-a716-446655440000";
        let path = format!("/v1/escalations/{}", id);
        assert_eq!(path, "/v1/escalations/550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn get_path_with_context_appends_query() {
        let id = "esc-123";
        let include_context = true;
        let path = if include_context {
            format!("/v1/escalations/{}?include=context", id)
        } else {
            format!("/v1/escalations/{}", id)
        };
        assert!(path.contains("include=context"));
    }

    #[test]
    fn get_path_without_context_no_query() {
        let id = "esc-456";
        let include_context = false;
        let path = if include_context {
            format!("/v1/escalations/{}?include=context", id)
        } else {
            format!("/v1/escalations/{}", id)
        };
        assert!(!path.contains("include="));
    }

    #[test]
    fn parse_escalation_all_statuses() {
        for status in ["queued", "claimed", "resolved"] {
            let e = json!({"status": status});
            assert_eq!(e.get("status").and_then(|v| v.as_str()).unwrap(), status);
        }
    }

    #[test]
    fn args_debug_impl() {
        let args = super::EscalationGetArgs {
            escalation_id: "esc-test".to_string(),
            include_context: true,
            json: false,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("esc-test"));
        assert!(debug.contains("true"));
    }

    #[test]
    fn parse_escalation_with_all_optional_fields() {
        let e = json!({
            "escalation_id": "esc-99",
            "status": "resolved",
            "reason_code": "policy_violation",
            "created_at": "2026-01-15T12:00:00Z",
            "claimed_by": "admin@example.com",
            "claimed_at": "2026-01-15T12:05:00Z",
            "resolution": "allow",
            "resolution_note": "Exception granted",
            "resolution_category": "false_positive",
            "event_context": {"prompt_hash": "sha256:example"}
        });
        assert_eq!(
            e.get("claimed_at").and_then(|v| v.as_str()).unwrap(),
            "2026-01-15T12:05:00Z"
        );
        assert_eq!(
            e.get("resolution_category")
                .and_then(|v| v.as_str())
                .unwrap(),
            "false_positive"
        );
        assert!(e.get("event_context").is_some());
    }
}
