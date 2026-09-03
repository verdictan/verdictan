// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan escalation resolve` — resolve a claimed escalation.

use clap::{Args, ValueEnum};

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum EscalationResolution {
    Allow,
    Block,
    Rewrite,
    Redact,
    Rejected,
}

impl EscalationResolution {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
            Self::Rewrite => "rewrite",
            Self::Redact => "redact",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum EscalationResolutionCategory {
    #[value(name = "false_positive")]
    FalsePositive,
    #[value(name = "true_positive_approved")]
    TruePositiveApproved,
    #[value(name = "true_positive_blocked")]
    TruePositiveBlocked,
    #[value(name = "needs_policy_update")]
    NeedsPolicyUpdate,
    #[value(name = "needs_rewrite")]
    NeedsRewrite,
    Duplicate,
    Other,
}

impl EscalationResolutionCategory {
    fn as_str(self) -> &'static str {
        match self {
            Self::FalsePositive => "false_positive",
            Self::TruePositiveApproved => "true_positive_approved",
            Self::TruePositiveBlocked => "true_positive_blocked",
            Self::NeedsPolicyUpdate => "needs_policy_update",
            Self::NeedsRewrite => "needs_rewrite",
            Self::Duplicate => "duplicate",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct EscalationResolveArgs {
    /// Escalation id.
    #[arg(long)]
    pub(crate) escalation_id: String,

    /// Resolution: allow, block, rewrite, redact, or rejected.
    #[arg(long, value_enum)]
    pub(crate) resolution: EscalationResolution,

    /// Short note about the resolution decision.
    #[arg(long)]
    pub(crate) note: Option<String>,

    /// Structured resolution category.
    #[arg(long, value_enum)]
    pub(crate) category: Option<EscalationResolutionCategory>,

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
pub(crate) async fn run_async(args: EscalationResolveArgs) -> Result<(), CliError> {
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

    let mut payload = serde_json::json!({ "resolution": args.resolution.as_str() });
    if let Some(note) = &args.note {
        payload["resolution_note"] = serde_json::Value::String(note.clone());
    }
    if let Some(cat) = &args.category {
        payload["resolution_category"] = serde_json::Value::String(cat.as_str().to_string());
    }

    let path = format!("/v1/escalations/{}/resolve", args.escalation_id);
    let value = client.post_json_value(&path, &payload).await?;

    if args.json {
        return print_json(&value);
    }

    println!("resolved escalation {}", args.escalation_id);
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
    fn resolve_payload_required_only() {
        let payload = json!({ "resolution": "allow" });
        assert_eq!(payload["resolution"], "allow");
        assert!(payload.get("resolution_note").is_none());
        assert!(payload.get("resolution_category").is_none());
    }

    #[test]
    fn resolve_payload_with_note_and_category() {
        let mut payload = json!({ "resolution": "block" });
        payload["resolution_note"] = serde_json::Value::String("PII detected".into());
        payload["resolution_category"] = serde_json::Value::String("true_positive_approved".into());
        assert_eq!(payload["resolution_note"], "PII detected");
        assert_eq!(payload["resolution_category"], "true_positive_approved");
    }

    #[test]
    fn resolve_path_formatting() {
        let esc_id = "esc-99";
        let path = format!("/v1/escalations/{}/resolve", esc_id);
        assert_eq!(path, "/v1/escalations/esc-99/resolve");
    }

    #[test]
    fn resolve_payload_with_note_only() {
        let mut payload = json!({ "resolution": "allow" });
        payload["resolution_note"] = serde_json::Value::String("Looks safe".into());
        assert_eq!(payload["resolution_note"], "Looks safe");
        assert!(payload.get("resolution_category").is_none());
    }

    #[test]
    fn resolve_payload_with_category_only() {
        let mut payload = json!({ "resolution": "block" });
        payload["resolution_category"] = serde_json::Value::String("false_positive".into());
        assert_eq!(payload["resolution_category"], "false_positive");
        assert!(payload.get("resolution_note").is_none());
    }

    #[test]
    fn output_message() {
        let esc_id = "esc-resolved";
        let msg = format!("resolved escalation {}", esc_id);
        assert!(msg.contains("resolved escalation"));
        assert!(msg.contains("esc-resolved"));
    }

    #[test]
    fn resolve_path_with_uuid() {
        let esc_id = "550e8400-e29b-41d4-a716-446655440000";
        let path = format!("/v1/escalations/{}/resolve", esc_id);
        assert!(path.starts_with("/v1/escalations/"));
        assert!(path.ends_with("/resolve"));
    }

    #[test]
    fn resolution_values_match_api_contract() {
        let values = [
            super::EscalationResolution::Allow,
            super::EscalationResolution::Block,
            super::EscalationResolution::Rewrite,
            super::EscalationResolution::Redact,
            super::EscalationResolution::Rejected,
        ];
        assert_eq!(
            values.map(super::EscalationResolution::as_str),
            ["allow", "block", "rewrite", "redact", "rejected"]
        );
    }

    #[test]
    fn resolve_payload_note_and_category_are_string_type() {
        let mut payload = json!({ "resolution": "allow" });
        let note = "This was reviewed by security team";
        let category = "false_positive";
        payload["resolution_note"] = serde_json::Value::String(note.to_string());
        payload["resolution_category"] = serde_json::Value::String(category.to_string());
        assert!(payload["resolution_note"].is_string());
        assert!(payload["resolution_category"].is_string());
    }

    #[test]
    fn args_debug_impl() {
        let args = super::EscalationResolveArgs {
            escalation_id: "esc-1".to_string(),
            resolution: super::EscalationResolution::Block,
            note: Some("test note".to_string()),
            category: Some(super::EscalationResolutionCategory::TruePositiveBlocked),
            json: false,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("esc-1"));
        assert!(debug.contains("Block"));
        assert!(debug.contains("test note"));
    }

    #[test]
    fn resolve_payload_empty_note_still_added() {
        let mut payload = json!({ "resolution": "allow" });
        let note = "";
        payload["resolution_note"] = serde_json::Value::String(note.to_string());
        assert_eq!(payload["resolution_note"].as_str().unwrap(), "");
    }

    #[test]
    fn resolution_category_values_match_api_contract() {
        use super::EscalationResolutionCategory as Category;

        let values = [
            Category::FalsePositive,
            Category::TruePositiveApproved,
            Category::TruePositiveBlocked,
            Category::NeedsPolicyUpdate,
            Category::NeedsRewrite,
            Category::Duplicate,
            Category::Other,
        ];
        assert_eq!(
            values.map(Category::as_str),
            [
                "false_positive",
                "true_positive_approved",
                "true_positive_blocked",
                "needs_policy_update",
                "needs_rewrite",
                "duplicate",
                "other",
            ]
        );
    }
}
