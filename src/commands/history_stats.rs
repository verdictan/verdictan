// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan history stats` — display aggregate statistics for history sessions.
//!
//! Calls the aggregate stats endpoint or computes client-side from the sessions
//! list when the endpoint is unavailable.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct HistoryStatsArgs {
    /// Scope filter (user, team, org).
    #[arg(long, value_parser = ["user", "team", "org"])]
    pub(crate) scope: Option<String>,

    /// Filter by team id.
    #[arg(long)]
    pub(crate) team_id: Option<String>,

    /// Filter by agent id.
    #[arg(long)]
    pub(crate) agent_id: Option<String>,

    /// Only include sessions after this timestamp (RFC3339).
    #[arg(long)]
    pub(crate) since: Option<String>,

    /// Only include sessions before this timestamp (RFC3339).
    #[arg(long)]
    pub(crate) until: Option<String>,

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
pub(crate) async fn run_async(args: HistoryStatsArgs) -> Result<(), CliError> {
    let client = build_client(
        args.api_url.clone(),
        args.api_token.clone(),
        args.config.clone(),
        args.profile.clone(),
    )?;

    // Try dedicated stats endpoint first.
    let stats_path = build_stats_path(&args);

    // Try aggregate endpoint; fall back to client-side computation.
    let stats_value = match client.get_bytes(&stats_path).await {
        Ok((status, bytes)) if status.is_success() => {
            serde_json::from_slice::<serde_json::Value>(&bytes).ok()
        }
        _ => None,
    };

    let stats = match stats_value {
        Some(v) => v,
        None => compute_stats_client_side(&client, &args).await?,
    };

    if args.json {
        return print_json(&stats);
    }

    render_stats(&stats);
    Ok(())
}

async fn compute_stats_client_side(
    client: &AsyncApiClient,
    args: &HistoryStatsArgs,
) -> Result<serde_json::Value, CliError> {
    let sessions_path = build_sessions_path(
        args.scope.as_deref(),
        args.team_id.as_deref(),
        args.agent_id.as_deref(),
    );

    let value = client.get_json_value(&sessions_path).await?;
    let sessions = value
        .get("sessions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    // Parse since/until for client-side filtering.
    let since_dt = args.since.as_deref().and_then(|s| parse_rfc3339(s).ok());
    let until_dt = args.until.as_deref().and_then(|s| parse_rfc3339(s).ok());
    Ok(compute_stats_from_sessions(
        &sessions,
        since_dt.as_ref(),
        until_dt.as_ref(),
    ))
}

fn top_n(map: &std::collections::HashMap<String, u64>, n: usize) -> Vec<serde_json::Value> {
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    entries
        .into_iter()
        .take(n)
        .map(|(k, v)| serde_json::json!({"name": k, "count": v}))
        .collect()
}

fn render_stats(stats: &serde_json::Value) {
    let total_sessions = stats
        .get("total_sessions")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let total_messages = stats
        .get("total_messages")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let total_tokens = stats
        .get("total_tokens")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let total_cost = stats
        .get("total_cost")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let avg_len = stats
        .get("avg_session_length")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    println!("═══ history stats ═══");
    println!("total sessions:     {total_sessions}");
    println!("total messages:     {total_messages}");
    println!("total tokens:       {total_tokens}");
    println!("total cost:         ${total_cost:.4}");
    println!("avg session length: {avg_len:.1} messages");

    if let Some(agents) = stats.get("top_agents").and_then(|v| v.as_array()) {
        if !agents.is_empty() {
            println!("\ntop agents:");
            for a in agents {
                let name = a.get("name").and_then(|v| v.as_str()).unwrap_or("-");
                let count = a.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
                println!("  {name}: {count} sessions");
            }
        }
    }

    if let Some(models) = stats.get("top_models").and_then(|v| v.as_array()) {
        if !models.is_empty() {
            println!("\ntop models:");
            for m in models {
                let name = m.get("name").and_then(|v| v.as_str()).unwrap_or("-");
                let count = m.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
                println!("  {name}: {count} sessions");
            }
        }
    }
}

fn parse_rfc3339(s: &str) -> Result<chrono::DateTime<chrono::Utc>, String> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| e.to_string())
}

fn build_stats_path(args: &HistoryStatsArgs) -> String {
    let mut params = Vec::new();
    if let Some(scope) = args.scope.as_deref() {
        params.push(format!("scope={}", urlencoding::encode(scope)));
    }
    if let Some(team_id) = args.team_id.as_deref() {
        params.push(format!("team_id={}", urlencoding::encode(team_id)));
    }
    if let Some(agent_id) = args.agent_id.as_deref() {
        params.push(format!("agent_id={}", urlencoding::encode(agent_id)));
    }
    if let Some(since) = args.since.as_deref() {
        params.push(format!("since={}", urlencoding::encode(since)));
    }
    if let Some(until) = args.until.as_deref() {
        params.push(format!("until={}", urlencoding::encode(until)));
    }

    if params.is_empty() {
        "/v1/history/stats".to_string()
    } else {
        format!("/v1/history/stats?{}", params.join("&"))
    }
}

fn build_sessions_path(
    scope: Option<&str>,
    team_id: Option<&str>,
    agent_id: Option<&str>,
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

    if query_parts.is_empty() {
        "/v1/history/sessions".to_string()
    } else {
        format!("/v1/history/sessions?{}", query_parts.join("&"))
    }
}

fn session_within_window(
    session: &serde_json::Value,
    since: Option<&chrono::DateTime<chrono::Utc>>,
    until: Option<&chrono::DateTime<chrono::Utc>>,
) -> bool {
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
}

fn compute_stats_from_sessions(
    sessions: &[serde_json::Value],
    since: Option<&chrono::DateTime<chrono::Utc>>,
    until: Option<&chrono::DateTime<chrono::Utc>>,
) -> serde_json::Value {
    let mut total_sessions: u64 = 0;
    let mut total_messages: i64 = 0;
    let mut total_tokens: i64 = 0;
    let mut total_cost: f64 = 0.0;
    let mut by_agent: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut by_model: std::collections::HashMap<String, u64> = std::collections::HashMap::new();

    for session in sessions {
        if !session_within_window(session, since, until) {
            continue;
        }

        total_sessions += 1;
        let entries = session
            .get("entry_count")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        total_messages += entries;

        let tokens = session
            .get("total_tokens")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        total_tokens += tokens;

        let cost = session
            .get("total_cost")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        total_cost += cost;

        if let Some(agent) = session.get("agent_id").and_then(|v| v.as_str()) {
            *by_agent.entry(agent.to_string()).or_default() += 1;
        }
        if let Some(model) = session.get("model").and_then(|v| v.as_str()) {
            *by_model.entry(model.to_string()).or_default() += 1;
        }
    }

    let avg_length = if total_sessions > 0 {
        total_messages as f64 / total_sessions as f64
    } else {
        0.0
    };

    serde_json::json!({
        "total_sessions": total_sessions,
        "total_messages": total_messages,
        "total_tokens": total_tokens,
        "total_cost": total_cost,
        "avg_session_length": avg_length,
        "top_agents": top_n(&by_agent, 5),
        "top_models": top_n(&by_model, 5),
    })
}

fn build_client(
    api_url: Option<String>,
    api_token: Option<String>,
    config_path: Option<std::path::PathBuf>,
    profile: String,
) -> Result<AsyncApiClient, CliError> {
    let inputs = ConfigInputs {
        api_url_flag: api_url,
        api_token_flag: api_token,
        config_path,
        profile_flag: Some(profile),
        region_flag: None,
    };
    let config = Config::resolve(inputs)?;
    let token = config.api_token.ok_or_else(|| {
        CliError::auth("missing api token (set VERDICTAN_API_TOKEN or run `verdictan auth login`)")
    })?;
    AsyncApiClient::new(config.api_url, token)
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

    fn stats_args() -> HistoryStatsArgs {
        HistoryStatsArgs {
            scope: None,
            team_id: None,
            agent_id: None,
            since: None,
            until: None,
            json: false,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        }
    }

    #[test]
    fn build_stats_path_includes_all_filters() {
        let mut args = stats_args();
        args.scope = Some("team".to_string());
        args.team_id = Some("team alpha".to_string());
        args.agent_id = Some("agent/beta".to_string());
        args.since = Some("2025-01-10T00:00:00Z".to_string());
        args.until = Some("2025-01-20T00:00:00Z".to_string());

        assert_eq!(
            build_stats_path(&args),
            "/v1/history/stats?scope=team&team_id=team%20alpha&agent_id=agent%2Fbeta&since=2025-01-10T00%3A00%3A00Z&until=2025-01-20T00%3A00%3A00Z"
        );
    }

    #[test]
    fn build_sessions_path_omits_query_without_filters() {
        assert_eq!(
            build_sessions_path(None, None, None),
            "/v1/history/sessions"
        );
    }

    #[test]
    fn session_within_window_keeps_missing_timestamps() {
        let since = parse_rfc3339("2025-01-10T00:00:00Z").unwrap();
        assert!(session_within_window(
            &json!({"session_id": "sess-missing"}),
            Some(&since),
            None
        ));
    }

    #[test]
    fn compute_stats_from_sessions_aggregates_and_filters() {
        let since = parse_rfc3339("2025-01-10T00:00:00Z").unwrap();
        let until = parse_rfc3339("2025-01-20T00:00:00Z").unwrap();
        let sessions = vec![
            json!({
                "session_id": "sess-before",
                "last_activity_at": "2025-01-09T23:00:00Z",
                "entry_count": 10,
                "total_tokens": 500,
                "total_cost": 2.5,
                "agent_id": "agent-z",
                "model": "gpt-5"
            }),
            json!({
                "session_id": "sess-one",
                "last_activity_at": "2025-01-11T12:00:00Z",
                "entry_count": 3,
                "total_tokens": 120,
                "total_cost": 0.25,
                "agent_id": "agent-a",
                "model": "gpt-4o-mini"
            }),
            json!({
                "session_id": "sess-two",
                "last_activity_at": "2025-01-12T12:00:00Z",
                "entry_count": 1,
                "total_tokens": 30,
                "total_cost": 0.05,
                "agent_id": "agent-b",
                "model": "gpt-4o"
            }),
        ];

        let stats = compute_stats_from_sessions(&sessions, Some(&since), Some(&until));

        assert_eq!(stats["total_sessions"], 2);
        assert_eq!(stats["total_messages"], 4);
        assert_eq!(stats["total_tokens"], 150);
        let total_cost = stats["total_cost"].as_f64().expect("total_cost as f64");
        assert!((total_cost - 0.3).abs() < f64::EPSILON);
        assert_eq!(stats["avg_session_length"], 2.0);
        assert_eq!(
            stats["top_agents"],
            json!([
                {"name": "agent-a", "count": 1},
                {"name": "agent-b", "count": 1}
            ])
        );
        assert_eq!(
            stats["top_models"],
            json!([
                {"name": "gpt-4o", "count": 1},
                {"name": "gpt-4o-mini", "count": 1}
            ])
        );
    }

    #[test]
    fn build_stats_path_omits_query_without_filters() {
        assert_eq!(build_stats_path(&stats_args()), "/v1/history/stats");
    }

    #[test]
    fn parse_rfc3339_rejects_invalid_timestamp() {
        assert!(parse_rfc3339("not-a-timestamp").is_err());
    }

    #[test]
    fn session_within_window_excludes_sessions_after_until() {
        let until = parse_rfc3339("2025-01-15T00:00:00Z").unwrap();
        assert!(!session_within_window(
            &json!({"last_activity_at": "2025-01-16T00:00:00Z"}),
            None,
            Some(&until)
        ));
    }

    #[test]
    fn render_stats_prints_summary_and_top_lists() {
        let stats = json!({
            "total_sessions": 2,
            "total_messages": 5,
            "total_tokens": 120,
            "total_cost": 1.25,
            "avg_session_length": 2.5,
            "top_agents": [{"name": "agent-a", "count": 2}],
            "top_models": [{"name": "gpt-4o", "count": 1}]
        });

        render_stats(&stats);
    }

    #[test]
    fn top_n_breaks_ties_by_name() {
        let map = std::collections::HashMap::from([
            ("beta".to_string(), 2_u64),
            ("alpha".to_string(), 2_u64),
            ("gamma".to_string(), 1_u64),
        ]);

        assert_eq!(
            top_n(&map, 2),
            vec![
                json!({"name": "alpha", "count": 2}),
                json!({"name": "beta", "count": 2}),
            ]
        );
    }

    #[test]
    fn top_n_empty_map() {
        let map: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        assert_eq!(top_n(&map, 5), Vec::<serde_json::Value>::new());
    }

    #[test]
    fn top_n_limit_larger_than_entries() {
        let map = std::collections::HashMap::from([("only".to_string(), 1_u64)]);
        assert_eq!(top_n(&map, 10), vec![json!({"name": "only", "count": 1})]);
    }

    #[test]
    fn compute_stats_from_sessions_empty_input() {
        let sessions: Vec<serde_json::Value> = vec![];
        let stats = compute_stats_from_sessions(&sessions, None, None);
        assert_eq!(stats["total_sessions"], 0);
        assert_eq!(stats["total_messages"], 0);
        assert_eq!(stats["total_tokens"], 0);
    }

    #[test]
    fn session_within_window_no_filters() {
        let s = json!({"last_activity_at": "2025-01-15T00:00:00Z"});
        assert!(session_within_window(&s, None, None));
    }

    #[test]
    fn session_within_window_missing_timestamp_always_included() {
        let s = json!({"session_id": "s-1"});
        let since = parse_rfc3339("2025-01-10T00:00:00Z").unwrap();
        assert!(session_within_window(&s, Some(&since), None));
    }

    #[test]
    fn render_stats_with_empty_top_lists() {
        let stats = json!({
            "total_sessions": 0,
            "total_messages": 0,
            "total_tokens": 0,
            "total_cost": 0.0,
            "avg_session_length": 0.0,
            "top_agents": [],
            "top_models": []
        });
        render_stats(&stats);
    }

    #[test]
    fn build_stats_path_with_scope_and_since() {
        let mut args = stats_args();
        args.scope = Some("team".to_string());
        args.since = Some("2025-01-01T00:00:00Z".to_string());
        let path = build_stats_path(&args);
        assert!(path.contains("scope=team"));
        assert!(path.contains("since="));
    }
}
