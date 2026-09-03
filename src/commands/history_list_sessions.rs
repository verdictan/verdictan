// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan history list-sessions` — list History sessions at user, team, org, or
//! agent scope with optional client-side since/until filtering.
//!
//! The API does not expose `since`/`until` query parameters on the sessions
//! list endpoint, so those filters are applied client-side after fetching the
//! full result set.
//!
//! # Module wiring
//! Add `pub(crate) mod history_list_sessions;` to `cli/src/commands/mod.rs` to
//! activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct HistoryListSessionsArgs {
    /// Scope filter.
    #[arg(long, value_parser = ["user", "team", "org"])]
    pub(crate) scope: Option<String>,

    /// Team id filter.
    #[arg(long)]
    pub(crate) team_id: Option<String>,

    /// Agent id filter.
    #[arg(long)]
    pub(crate) agent_id: Option<String>,

    /// Filter by tag name (server-side if supported).
    #[arg(long)]
    pub(crate) tag: Option<String>,

    /// Include only sessions with last_activity_at after this RFC3339
    /// timestamp (client-side filter).
    #[arg(long)]
    pub(crate) since: Option<String>,

    /// Include only sessions with last_activity_at before this RFC3339
    /// timestamp (client-side filter).
    #[arg(long)]
    pub(crate) until: Option<String>,

    /// Maximum number of sessions to display.
    #[arg(long, default_value_t = 50)]
    pub(crate) limit: usize,

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
pub(crate) async fn run_async(args: HistoryListSessionsArgs) -> Result<(), CliError> {
    // Parse since/until into chrono for client-side filtering.
    let since_dt = args
        .since
        .as_deref()
        .map(parse_rfc3339)
        .transpose()
        .map_err(|e| CliError::user(format!("invalid --since value: {e}")))?;
    let until_dt = args
        .until
        .as_deref()
        .map(parse_rfc3339)
        .transpose()
        .map_err(|e| CliError::user(format!("invalid --until value: {e}")))?;

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
    let path = build_sessions_path(
        args.scope.as_deref(),
        args.team_id.as_deref(),
        args.agent_id.as_deref(),
        args.tag.as_deref(),
    );

    let value = client.get_json_value(&path).await?;

    // Apply client-side since/until and limit.
    let sessions = value
        .get("sessions")
        .and_then(|s| s.as_array())
        .cloned()
        .unwrap_or_default();
    let filtered =
        filter_sessions_by_activity(sessions, since_dt.as_ref(), until_dt.as_ref(), args.limit);

    if args.json {
        return print_json(&serde_json::json!({ "sessions": filtered }));
    }

    if filtered.is_empty() {
        println!("no sessions");
        return Ok(());
    }

    for session in &filtered {
        let id = session
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let scope = session.get("scope").and_then(|v| v.as_str()).unwrap_or("-");
        let entries = session
            .get("entry_count")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let activity = session
            .get("last_activity_at")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        println!("{id}\t{scope}\tentries={entries}\tlast_activity={activity}");
    }

    Ok(())
}

fn build_sessions_path(
    scope: Option<&str>,
    team_id: Option<&str>,
    agent_id: Option<&str>,
    tag: Option<&str>,
) -> String {
    let mut query_parts = Vec::new();
    if let Some(scope) = scope {
        query_parts.push(format!("scope={}", urlencoding::encode(scope)));
    }
    if let Some(team_id) = team_id {
        query_parts.push(format!("team_id={}", urlencoding::encode(team_id)));
    }
    if let Some(agent_id) = agent_id {
        query_parts.push(format!("agent_id={}", urlencoding::encode(agent_id)));
    }
    if let Some(tag) = tag {
        query_parts.push(format!("tag={}", urlencoding::encode(tag)));
    }

    if query_parts.is_empty() {
        "/v1/history/sessions".to_string()
    } else {
        format!("/v1/history/sessions?{}", query_parts.join("&"))
    }
}

fn filter_sessions_by_activity(
    sessions: Vec<serde_json::Value>,
    since: Option<&chrono::DateTime<chrono::Utc>>,
    until: Option<&chrono::DateTime<chrono::Utc>>,
    limit: usize,
) -> Vec<serde_json::Value> {
    sessions
        .into_iter()
        .filter(|session| {
            let activity = session
                .get("last_activity_at")
                .and_then(|v| v.as_str())
                .and_then(|s| parse_rfc3339(s).ok());

            if let (Some(since), Some(act)) = (since, &activity) {
                if act < since {
                    return false;
                }
            }
            if let (Some(until), Some(act)) = (until, &activity) {
                if act > until {
                    return false;
                }
            }
            true
        })
        .take(limit)
        .collect()
}

fn parse_rfc3339(s: &str) -> Result<chrono::DateTime<chrono::Utc>, String> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| e.to_string())
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
    use serde_json::json;

    #[test]
    fn command_helper_coverage_parse_rfc3339_accepts_valid_timestamp() {
        let parsed = parse_rfc3339("2026-06-23T10:15:30Z").unwrap();
        assert_eq!(parsed.to_rfc3339(), "2026-06-23T10:15:30+00:00");
    }

    #[test]
    fn command_helper_coverage_parse_rfc3339_rejects_invalid_timestamp() {
        assert!(parse_rfc3339("2026-06-23").is_err());
    }

    #[test]
    fn command_helper_coverage_build_sessions_path_includes_all_server_filters() {
        let path = build_sessions_path(
            Some("team"),
            Some("team alpha"),
            Some("agent/beta"),
            Some("incident review"),
        );

        assert_eq!(
            path,
            "/v1/history/sessions?scope=team&team_id=team%20alpha&agent_id=agent%2Fbeta&tag=incident%20review"
        );
    }

    #[test]
    fn command_helper_coverage_build_sessions_path_omits_query_without_filters() {
        assert_eq!(
            build_sessions_path(None, None, None, None),
            "/v1/history/sessions"
        );
    }

    #[test]
    fn command_helper_coverage_filter_sessions_by_activity_applies_window_and_limit() {
        let since = parse_rfc3339("2025-01-10T00:00:00Z").unwrap();
        let until = parse_rfc3339("2025-01-20T00:00:00Z").unwrap();
        let sessions = vec![
            json!({"session_id": "sess-before", "last_activity_at": "2025-01-09T00:00:00Z"}),
            json!({"session_id": "sess-one", "last_activity_at": "2025-01-11T00:00:00Z"}),
            json!({"session_id": "sess-two", "last_activity_at": "2025-01-12T00:00:00Z"}),
        ];

        let filtered = filter_sessions_by_activity(sessions, Some(&since), Some(&until), 1);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0]["session_id"], "sess-one");
    }

    #[test]
    fn command_helper_coverage_filter_sessions_by_activity_keeps_missing_timestamp_entries() {
        let since = parse_rfc3339("2025-01-10T00:00:00Z").unwrap();
        let filtered = filter_sessions_by_activity(
            vec![json!({"session_id": "sess-missing"})],
            Some(&since),
            None,
            10,
        );

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0]["session_id"], "sess-missing");
    }

    #[test]
    fn command_helper_coverage_filter_sessions_no_filters_returns_all() {
        let sessions = vec![
            json!({"session_id": "s1", "last_activity_at": "2025-01-01T00:00:00Z"}),
            json!({"session_id": "s2", "last_activity_at": "2025-06-01T00:00:00Z"}),
            json!({"session_id": "s3", "last_activity_at": "2025-12-01T00:00:00Z"}),
        ];
        let filtered = filter_sessions_by_activity(sessions, None, None, 100);
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn command_helper_coverage_filter_sessions_excludes_after_until() {
        let until = parse_rfc3339("2025-01-15T00:00:00Z").unwrap();
        let sessions = vec![
            json!({"session_id": "before", "last_activity_at": "2025-01-10T00:00:00Z"}),
            json!({"session_id": "after", "last_activity_at": "2025-01-20T00:00:00Z"}),
        ];
        let filtered = filter_sessions_by_activity(sessions, None, Some(&until), 10);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0]["session_id"], "before");
    }

    #[test]
    fn command_helper_coverage_filter_sessions_limit_zero_returns_empty() {
        let sessions =
            vec![json!({"session_id": "s1", "last_activity_at": "2025-01-15T00:00:00Z"})];
        let filtered = filter_sessions_by_activity(sessions, None, None, 0);
        assert!(filtered.is_empty());
    }

    #[test]
    fn command_helper_coverage_build_sessions_path_single_filter() {
        assert_eq!(
            build_sessions_path(Some("org"), None, None, None),
            "/v1/history/sessions?scope=org"
        );
        assert_eq!(
            build_sessions_path(None, Some("t-1"), None, None),
            "/v1/history/sessions?team_id=t-1"
        );
        assert_eq!(
            build_sessions_path(None, None, Some("a-1"), None),
            "/v1/history/sessions?agent_id=a-1"
        );
        assert_eq!(
            build_sessions_path(None, None, None, Some("tag1")),
            "/v1/history/sessions?tag=tag1"
        );
    }

    #[test]
    fn command_helper_coverage_parse_rfc3339_with_offset() {
        let parsed = parse_rfc3339("2025-06-01T12:30:00+05:30").unwrap();
        let expected = parse_rfc3339("2025-06-01T07:00:00Z").unwrap();
        assert_eq!(parsed, expected);
    }
}
