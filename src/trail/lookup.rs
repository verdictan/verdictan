// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan trail lookup` — query trail events.

use clap::Args;
use serde::Deserialize;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;
use crate::trail::{assert_authenticated_org, validate_bounded_query_window};

#[derive(Debug, Args)]
pub(crate) struct LookupArgs {
    /// Look up events by request ID (correlates a single HTTP request)
    #[arg(long)]
    pub(crate) request_id: Option<String>,

    /// Assert that the authenticated token belongs to this organization (UUID)
    #[arg(long)]
    pub(crate) org_id: Option<String>,

    /// Filter by event source (for example, "identity_access" or "governance")
    #[arg(long)]
    pub(crate) event_source: Option<String>,

    /// Filter by event name (for example, "CreateUser" or "DeleteToken")
    #[arg(long)]
    pub(crate) event_name: Option<String>,

    /// Filter by resource type (for example, "User" or "Team")
    #[arg(long)]
    pub(crate) resource_type: Option<String>,

    /// Filter by resource ID (UUID)
    #[arg(long)]
    pub(crate) resource_id: Option<String>,

    /// Filter by actor ARN.
    #[arg(long)]
    pub(crate) actor_arn: Option<String>,

    /// Limit results (default: 100, max: 1000)
    #[arg(
        long,
        default_value = "100",
        value_parser = clap::value_parser!(u32).range(1..=1000)
    )]
    pub(crate) limit: u32,

    /// Start time (RFC3339)
    #[arg(long)]
    pub(crate) start_time: Option<String>,

    /// End time (RFC3339)
    #[arg(long)]
    pub(crate) end_time: Option<String>,

    /// Emit machine-readable JSON to stdout.
    #[arg(long)]
    pub(crate) json: bool,

    /// Optional config file path (YAML)
    #[arg(long)]
    pub(crate) config: Option<std::path::PathBuf>,

    /// Override API URL.
    #[arg(long)]
    pub(crate) api_url: Option<String>,

    /// Override API token.
    #[arg(long)]
    pub(crate) api_token: Option<String>,

    /// Profile name (default: "default")
    #[arg(long, default_value = "default")]
    pub(crate) profile: String,

    /// Target region for this API call.
    #[arg(long)]
    pub(crate) region: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EventsResponse {
    events: Vec<TrailEvent>,
    #[allow(dead_code)]
    next_cursor: Option<String>,
    #[allow(dead_code)]
    result_count: u32,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct TrailEvent {
    event_id: String,
    event_time: String,
    event_name: String,
    event_source: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    actor_email: Option<String>,
    actor_arn: Option<String>,
    source_ip: Option<String>,
    request_method: Option<String>,
    request_path: Option<String>,
}
pub(crate) async fn run_async(args: LookupArgs) -> Result<(), CliError> {
    let inputs = ConfigInputs {
        api_url_flag: args.api_url.clone(),
        api_token_flag: args.api_token.clone(),
        config_path: args.config.clone(),
        profile_flag: Some(args.profile.clone()),
        region_flag: args.region.clone(),
    };

    let config = Config::resolve(inputs)?;
    let api_token = config.api_token.ok_or_else(|| {
        CliError::auth("missing api token (set VERDICTAN_API_TOKEN or run `verdictan auth login`)")
    })?;

    let client = AsyncApiClient::new(config.api_url, api_token)?.with_region(config.region.clone());
    assert_authenticated_org(&client, args.org_id.as_deref()).await?;

    // If --request-id is provided, use the dedicated lookup endpoint
    if let Some(request_id) = &args.request_id {
        let path = build_request_id_lookup_path(request_id);
        let value = client.get_json_value(&path).await?;

        if args.json {
            return print_json(&value);
        }

        let response: EventsResponse = serde_json::from_value(value)
            .map_err(|e| CliError::internal(format!("failed to parse lookup response: {e}")))?;

        if response.events.is_empty() {
            println!("No trail events found for request_id={}", request_id);
            return Ok(());
        }

        print_events_table(&response.events);
        return Ok(());
    }

    validate_bounded_query_window(args.start_time.as_deref(), args.end_time.as_deref(), 7)?;
    let path = build_events_lookup_path(
        args.limit,
        args.event_source.as_deref(),
        args.event_name.as_deref(),
        args.resource_type.as_deref(),
        args.resource_id.as_deref(),
        args.actor_arn.as_deref(),
        args.start_time.as_deref(),
        args.end_time.as_deref(),
    );
    let value = client.get_json_value(&path).await?;

    if args.json {
        return print_json(&value);
    }

    // Parse and display as table
    let response: EventsResponse = serde_json::from_value(value)
        .map_err(|e| CliError::internal(format!("failed to parse events response: {e}")))?;

    if response.events.is_empty() {
        println!("No trail events found");
        return Ok(());
    }

    print_events_table(&response.events);
    Ok(())
}

fn print_events_table(events: &[TrailEvent]) {
    println!(
        "{:<20} {:<30} {:<15} {:<25} {:<15}",
        "EVENT_TIME", "EVENT_NAME", "RESOURCE_TYPE", "ACTOR", "SOURCE_IP"
    );
    println!("{}", "-".repeat(105));

    for event in events {
        let event_time = format_event_time(&event.event_time);
        let resource_type = event.resource_type.as_deref().unwrap_or("-");
        let actor = event
            .actor_email
            .as_deref()
            .or(event.actor_arn.as_deref())
            .unwrap_or("-");
        let source_ip = event.source_ip.as_deref().unwrap_or("-");

        println!(
            "{:<20} {:<30} {:<15} {:<25} {:<15}",
            event_time,
            truncate(&event.event_name, 30),
            truncate(resource_type, 15),
            truncate(actor, 25),
            source_ip
        );
    }

    println!("\nTotal: {} event(s)", events.len());
}

fn format_event_time(timestamp: &str) -> String {
    // Try to parse and format ISO8601 timestamp
    // For now, just truncate to reasonable length
    if timestamp.len() > 19 {
        timestamp[..19].replace('T', " ")
    } else {
        timestamp.to_string()
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

fn build_request_id_lookup_path(request_id: &str) -> String {
    format!(
        "/v1/trail/events/lookup?request_id={}",
        urlencoding::encode(request_id)
    )
}

#[allow(clippy::too_many_arguments)]
fn build_events_lookup_path(
    limit: u32,
    event_source: Option<&str>,
    event_name: Option<&str>,
    resource_type: Option<&str>,
    resource_id: Option<&str>,
    actor_arn: Option<&str>,
    start_time: Option<&str>,
    end_time: Option<&str>,
) -> String {
    let mut query_params = vec![format!("limit={limit}")];

    if let Some(event_source) = event_source {
        query_params.push(format!(
            "event_source={}",
            urlencoding::encode(event_source)
        ));
    }

    if let Some(event_name) = event_name {
        query_params.push(format!("event_name={}", urlencoding::encode(event_name)));
    }

    if let Some(resource_type) = resource_type {
        query_params.push(format!(
            "resource_type={}",
            urlencoding::encode(resource_type)
        ));
    }

    if let Some(resource_id) = resource_id {
        query_params.push(format!("resource_id={}", urlencoding::encode(resource_id)));
    }

    if let Some(actor_arn) = actor_arn {
        query_params.push(format!("actor_arn={}", urlencoding::encode(actor_arn)));
    }

    if let Some(start_time) = start_time {
        query_params.push(format!("start_time={}", urlencoding::encode(start_time)));
    }

    if let Some(end_time) = end_time {
        query_params.push(format!("end_time={}", urlencoding::encode(end_time)));
    }

    format!("/v1/trail/events?{}", query_params.join("&"))
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
    use super::*;

    fn sample_event() -> TrailEvent {
        TrailEvent {
            event_id: "evt-1".to_string(),
            event_time: "2026-06-23T10:15:30Z".to_string(),
            event_name: "CreateUserWithAVeryLongEventNameThatShouldTruncate".to_string(),
            event_source: Some("identity_access".to_string()),
            resource_type: Some("User".to_string()),
            resource_id: Some("user-1".to_string()),
            actor_email: Some("admin@example.com".to_string()),
            actor_arn: None,
            source_ip: Some("203.0.113.10".to_string()),
            request_method: Some("POST".to_string()),
            request_path: Some("/v1/users".to_string()),
        }
    }

    #[test]
    fn command_helper_coverage_build_request_id_lookup_path_encodes_request_id() {
        assert_eq!(
            build_request_id_lookup_path("req/123"),
            "/v1/trail/events/lookup?request_id=req%2F123"
        );
    }

    #[test]
    fn command_helper_coverage_build_events_lookup_path_includes_all_filters() {
        assert_eq!(
            build_events_lookup_path(100, None, None, None, None, None, None, None),
            "/v1/trail/events?limit=100"
        );
        assert_eq!(
            build_events_lookup_path(
                50,
                Some("identity access"),
                Some("Delete/Token"),
                Some("User"),
                Some("user-1"),
                Some("arn:verdictan:iam::user/admin"),
                Some("2026-01-01T00:00:00Z"),
                Some("2026-01-02T00:00:00Z"),
            ),
            "/v1/trail/events?limit=50&event_source=identity%20access&event_name=Delete%2FToken&resource_type=User&resource_id=user-1&actor_arn=arn%3Averdictan%3Aiam%3A%3Auser%2Fadmin&start_time=2026-01-01T00%3A00%3A00Z&end_time=2026-01-02T00%3A00%3A00Z"
        );
    }

    #[test]
    fn command_helper_coverage_format_event_time_replaces_t_and_truncates() {
        assert_eq!(
            format_event_time("2026-06-23T10:15:30.123Z"),
            "2026-06-23 10:15:30"
        );
        assert_eq!(format_event_time("short"), "short");
    }

    #[test]
    fn command_helper_coverage_truncate_preserves_short_strings() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("0123456789abcdef", 10), "0123456...");
    }

    #[test]
    fn command_helper_coverage_print_events_table_renders_rows_and_empty_set() {
        print_events_table(&[sample_event()]);
        print_events_table(&[]);
    }
}
