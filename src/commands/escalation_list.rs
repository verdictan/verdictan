// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan escalation list` — list escalations.

use clap::{Args, ValueEnum};

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum EscalationStatus {
    Queued,
    Claimed,
    Resolved,
}

impl EscalationStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Claimed => "claimed",
            Self::Resolved => "resolved",
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct EscalationListArgs {
    /// Since (RFC3339 UTC or relative duration like 10m, 2h, 7d).
    #[arg(long)]
    pub(crate) since: String,

    /// Filter by status: queued, claimed, or resolved.
    #[arg(long, value_enum)]
    pub(crate) status: Option<EscalationStatus>,

    /// Filter by agent id.
    #[arg(long)]
    pub(crate) agent_id: Option<String>,

    /// Pagination cursor from previous response.
    #[arg(long)]
    pub(crate) cursor: Option<String>,

    /// Maximum results to return (1..=100).
    #[arg(
        long,
        default_value_t = 25,
        value_parser = clap::value_parser!(u32).range(1..=100)
    )]
    pub(crate) limit: u32,

    /// Emit machine-readable JSON to stdout.
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
pub(crate) async fn run_async(args: EscalationListArgs) -> Result<(), CliError> {
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

    let mut query = vec![format!("since={}", urlencoding::encode(&args.since))];
    if let Some(status) = &args.status {
        query.push(format!("status={}", urlencoding::encode(status.as_str())));
    }
    if let Some(agent_id) = &args.agent_id {
        query.push(format!("agent_id={}", urlencoding::encode(agent_id)));
    }
    if let Some(cursor) = &args.cursor {
        query.push(format!("cursor={}", urlencoding::encode(cursor)));
    }
    query.push(format!("limit={}", args.limit));

    let path = format!("/v1/escalations?{}", query.join("&"));
    let value = client.get_json_value(&path).await?;

    if args.json {
        return print_json(&value);
    }

    let items = value
        .get("escalations")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if items.is_empty() {
        println!("no escalations");
        return Ok(());
    }

    for e in &items {
        let id = e
            .get("escalation_id")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let status = e.get("status").and_then(|v| v.as_str()).unwrap_or("-");
        let reason = e.get("reason_code").and_then(|v| v.as_str()).unwrap_or("-");
        let created = e.get("created_at").and_then(|v| v.as_str()).unwrap_or("-");
        println!("{id}  {status}  {reason}  {created}");
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
    fn query_construction_all_params() {
        let mut query = Vec::new();
        query.push(format!(
            "since={}",
            urlencoding::encode("2025-01-01T00:00:00Z")
        ));
        query.push(format!("status={}", urlencoding::encode("queued")));
        query.push(format!("agent_id={}", urlencoding::encode("a-1")));
        query.push(format!("cursor={}", urlencoding::encode("abc123")));
        query.push(format!("limit={}", 25));
        let path = format!("/v1/escalations?{}", query.join("&"));
        assert!(path.contains("since="));
        assert!(path.contains("status=queued"));
        assert!(path.contains("agent_id=a-1"));
        assert!(path.contains("cursor=abc123"));
        assert!(path.contains("limit=25"));
    }

    #[test]
    fn query_construction_minimal() {
        let query = vec!["since=24h".to_string(), format!("limit={}", 25)];
        let path = format!("/v1/escalations?{}", query.join("&"));
        assert_eq!(path, "/v1/escalations?since=24h&limit=25");
    }

    #[test]
    fn parse_escalations_response() {
        let value = json!({"escalations": [
            {"escalation_id": "esc-1", "status": "queued", "reason_code": "policy_violation", "created_at": "2025-01-01"}
        ]});
        let items = value.get("escalations").and_then(|v| v.as_array()).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["escalation_id"], "esc-1");
        assert_eq!(items[0]["status"], "queued");
    }

    #[test]
    fn parse_escalations_empty() {
        let value = json!({"escalations": []});
        let items = value
            .get("escalations")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(items.is_empty());
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
        assert_eq!(
            e.get("reason_code").and_then(|v| v.as_str()).unwrap_or("-"),
            "-"
        );
    }

    #[test]
    fn parse_escalations_missing_key() {
        let value = json!({});
        let items = value
            .get("escalations")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(items.is_empty());
    }

    #[test]
    fn query_construction_status_filter() {
        let mut query = vec!["since=24h".to_string()];
        query.push(format!("status={}", urlencoding::encode("claimed")));
        let path = format!("/v1/escalations?{}", query.join("&"));
        assert_eq!(path, "/v1/escalations?since=24h&status=claimed");
    }

    #[test]
    fn query_construction_special_chars() {
        let since = "2025-01-01T00:00:00+05:30";
        let encoded = urlencoding::encode(since);
        let path = format!("/v1/escalations?since={}", encoded);
        assert!(path.contains("2025-01-01T00%3A00%3A00%2B05%3A30"));
    }

    #[test]
    fn query_construction_limit_boundaries() {
        let query = vec!["since=24h".to_string(), format!("limit={}", 1)];
        let path = format!("/v1/escalations?{}", query.join("&"));
        assert!(path.contains("limit=1"));

        let query = vec!["since=24h".to_string(), format!("limit={}", 100)];
        let path = format!("/v1/escalations?{}", query.join("&"));
        assert!(path.contains("limit=100"));
    }

    #[test]
    fn parse_escalations_multiple_items() {
        let value = json!({"escalations": [
            {"escalation_id": "e1", "status": "queued", "reason_code": "pii", "created_at": "2025-01-01"},
            {"escalation_id": "e2", "status": "claimed", "reason_code": "budget", "created_at": "2025-01-02"},
            {"escalation_id": "e3", "status": "resolved", "reason_code": "policy", "created_at": "2025-01-03"},
        ]});
        let items = value.get("escalations").and_then(|v| v.as_array()).unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[2]["status"], "resolved");
    }

    #[test]
    fn parse_escalation_row_formatting() {
        let e = json!({"escalation_id": "esc-1", "status": "queued", "reason_code": "pii_detected", "created_at": "2025-06-01T10:00:00Z"});
        let id = e
            .get("escalation_id")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let status = e.get("status").and_then(|v| v.as_str()).unwrap_or("-");
        let reason = e.get("reason_code").and_then(|v| v.as_str()).unwrap_or("-");
        let created = e.get("created_at").and_then(|v| v.as_str()).unwrap_or("-");
        let row = format!("{id}  {status}  {reason}  {created}");
        assert!(row.contains("esc-1"));
        assert!(row.contains("queued"));
        assert!(row.contains("pii_detected"));
    }

    #[test]
    fn query_construction_agent_id_with_spaces() {
        let agent_id = "agent with spaces";
        let encoded = urlencoding::encode(agent_id);
        assert_eq!(encoded, "agent%20with%20spaces");
    }

    #[test]
    fn args_debug_impl() {
        let args = super::EscalationListArgs {
            since: "1h".to_string(),
            status: Some(super::EscalationStatus::Queued),
            agent_id: Some("a-1".to_string()),
            cursor: None,
            limit: 25,
            json: false,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("EscalationListArgs"));
    }
}
