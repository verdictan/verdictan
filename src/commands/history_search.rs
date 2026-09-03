// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan history search --query "..."` — full-text search across history entries
//! via the OpenSearch endpoint (`GET /v1/history/search`).
//!
//! Falls back to client-side filtering from session list if search returns 503.

use chrono::{DateTime, FixedOffset};
use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

const FALLBACK_SESSION_PAGE_SIZE: usize = 200;
const FALLBACK_ENTRY_PAGE_SIZE: usize = 500;

#[derive(Debug, Args)]
pub(crate) struct HistorySearchArgs {
    /// Search query string.
    #[arg(long)]
    pub(crate) query: String,

    /// Filter by entry type (for example, "user" or "assistant").
    #[arg(long)]
    pub(crate) entry_kind: Option<String>,

    /// Filter by agent id.
    #[arg(long)]
    pub(crate) agent_id: Option<String>,

    /// Filter by team id.
    #[arg(long)]
    pub(crate) team_id: Option<String>,

    /// Only include results after this timestamp (RFC3339).
    #[arg(long)]
    pub(crate) since: Option<String>,

    /// Only include results before this timestamp (RFC3339).
    #[arg(long)]
    pub(crate) until: Option<String>,

    /// Maximum number of results.
    #[arg(long, default_value_t = 20)]
    pub(crate) limit: u32,

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
pub(crate) async fn run_async(args: HistorySearchArgs) -> Result<(), CliError> {
    let filters = FallbackSearchFilters::from_args(&args)?;
    let path = build_search_path(&args);
    let client = build_client(
        args.api_url,
        args.api_token,
        args.config,
        args.profile,
        args.region,
    )?;

    // Try the search endpoint; fall back on 503.
    let result = client.get_bytes(&path).await;
    let value = match result {
        Ok((status, _bytes)) if status.as_u16() == 503 => {
            eprintln!("search service unavailable, falling back to client-side filter");
            return fallback_search(&client, &filters, args.json).await;
        }
        Ok((status, bytes)) if status.is_success() => {
            serde_json::from_slice::<serde_json::Value>(&bytes)
                .map_err(|e| CliError::internal(format!("failed to parse search response: {e}")))?
        }
        Ok((status, _)) => {
            return Err(crate::api::client::map_http_status(status));
        }
        Err(e) => return Err(e),
    };

    if args.json {
        return print_json(&value);
    }

    render_results(&value)
}

async fn fallback_search(
    client: &AsyncApiClient,
    filters: &FallbackSearchFilters,
    json_mode: bool,
) -> Result<(), CliError> {
    let mut results: Vec<serde_json::Value> = Vec::new();

    let mut session_cursor: Option<String> = None;
    loop {
        let sessions_path = build_fallback_sessions_path(filters, session_cursor.as_deref());
        let sessions_value = client.get_json_value(&sessions_path).await?;
        let sessions = sessions_value
            .get("sessions")
            .and_then(|v| v.as_array())
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        for session in sessions {
            if !filters.matches_session(session) {
                continue;
            }
            let sid = match session.get("session_id").and_then(|v| v.as_str()) {
                Some(id) => id,
                None => continue,
            };

            let mut entry_offset = 0usize;
            loop {
                let entries_path = build_fallback_entries_path(sid, filters, entry_offset);
                let entries_value = match client.get_json_value(&entries_path).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let entries = entries_value
                    .get("entries")
                    .and_then(|v| v.as_array())
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);

                for entry in entries {
                    if let Some(content) = filters.matching_content(session, entry) {
                        results.push(serde_json::json!({
                            "session_id": sid,
                            "session_title": session_title(session).unwrap_or("-"),
                            "entry_kind": entry.get("entry_kind").and_then(|v| v.as_str()).unwrap_or("-"),
                            "content": truncate_content(&content, 120),
                            "timestamp": entry_timestamp(entry).unwrap_or("-"),
                        }));
                    }
                }

                if entries.len() < FALLBACK_ENTRY_PAGE_SIZE {
                    break;
                }
                entry_offset += FALLBACK_ENTRY_PAGE_SIZE;
            }
        }

        if !sessions_has_more(&sessions_value) {
            break;
        }
        let Some(next_cursor) = next_sessions_cursor(&sessions_value) else {
            break;
        };
        if session_cursor.as_deref() == Some(next_cursor.as_str()) {
            break;
        }
        session_cursor = Some(next_cursor);
    }

    if results.len() > filters.limit {
        results.truncate(filters.limit);
    }

    let value = serde_json::json!({ "results": results });
    if json_mode {
        return print_json(&value);
    }
    render_results(&value)
}

fn render_results(value: &serde_json::Value) -> Result<(), CliError> {
    let results = value
        .get("results")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if results.is_empty() {
        println!("no results");
        return Ok(());
    }

    for item in &results {
        let title = item
            .get("session_title")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let kind = item
            .get("entry_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let content = item.get("content").and_then(|v| v.as_str()).unwrap_or("-");
        let ts = item
            .get("timestamp")
            .and_then(|v| v.as_str())
            .unwrap_or("-");

        // ANSI bold for kind badge.
        println!("\x1b[1m[{kind}]\x1b[0m {title}");
        println!("  {content}");
        println!("  \x1b[2m{ts}\x1b[0m");
        println!();
    }

    Ok(())
}

fn entry_content_text(entry: &serde_json::Value) -> String {
    let request_text = entry
        .get("request_payload")
        .map(request_payload_text)
        .filter(|text| !text.is_empty());
    let response_text = entry
        .get("response_payload")
        .map(response_payload_text)
        .filter(|text| !text.is_empty());
    let content_text = entry
        .get("content")
        .and_then(|v| v.as_str())
        .filter(|text| !text.is_empty())
        .map(str::to_owned);

    let mut parts = Vec::new();
    if let Some(text) = request_text {
        parts.push(text);
    }
    if let Some(text) = response_text {
        parts.push(text);
    }
    if let Some(text) = content_text {
        parts.push(text);
    }

    parts.join("\n")
}

fn request_payload_text(payload: &serde_json::Value) -> String {
    let mut parts = Vec::new();
    let message_text = payload
        .get("messages")
        .map(message_list_text)
        .filter(|text| !text.is_empty());
    if let Some(text) = message_text {
        parts.push(text);
    }
    if let Some(prompt) = payload
        .get("prompt")
        .and_then(|value| value.as_str())
        .filter(|text| !text.is_empty())
    {
        parts.push(prompt.to_string());
    }
    parts.join("\n")
}

fn response_payload_text(payload: &serde_json::Value) -> String {
    let mut parts = Vec::new();
    let choice_text = payload
        .get("choices")
        .map(choice_list_text)
        .filter(|text| !text.is_empty());
    if let Some(text) = choice_text {
        parts.push(text);
    }
    if let Some(content) = payload
        .get("content")
        .and_then(|value| value.as_str())
        .filter(|text| !text.is_empty())
    {
        parts.push(content.to_string());
    }
    parts.join("\n")
}

fn message_list_text(messages: &serde_json::Value) -> String {
    messages
        .as_array()
        .map(|items| {
            let mut parts = Vec::new();
            for message in items {
                if let Some(content) = message.get("content").and_then(|value| value.as_str()) {
                    parts.push(content.to_string());
                }
                if let Some(content_items) =
                    message.get("content").and_then(|value| value.as_array())
                {
                    parts.extend(
                        content_items
                            .iter()
                            .filter_map(|part| part.get("text").and_then(|value| value.as_str()))
                            .map(str::to_owned),
                    );
                }
            }
            parts.join("\n")
        })
        .unwrap_or_default()
}

fn choice_list_text(choices: &serde_json::Value) -> String {
    choices
        .as_array()
        .map(|items| {
            let mut parts = Vec::new();
            for choice in items {
                if let Some(content) = choice
                    .get("message")
                    .and_then(|message| message.get("content"))
                    .and_then(|value| value.as_str())
                {
                    parts.push(content.to_string());
                }
                if let Some(text) = choice.get("text").and_then(|value| value.as_str()) {
                    parts.push(text.to_string());
                }
            }
            parts.join("\n")
        })
        .unwrap_or_default()
}

fn truncate_content(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let cutoff = s
            .char_indices()
            .nth(max_chars)
            .map(|(index, _)| index)
            .unwrap_or(s.len());
        format!("{}…", &s[..cutoff])
    }
}

fn build_client(
    api_url: Option<String>,
    api_token: Option<String>,
    config_path: Option<std::path::PathBuf>,
    profile: String,
    region: Option<String>,
) -> Result<AsyncApiClient, CliError> {
    let inputs = ConfigInputs {
        api_url_flag: api_url,
        api_token_flag: api_token,
        config_path,
        profile_flag: Some(profile),
        region_flag: region,
    };
    let config = Config::resolve(inputs)?;
    let token = config.api_token.ok_or_else(|| {
        CliError::auth("missing api token (set VERDICTAN_API_TOKEN or run `verdictan auth login`)")
    })?;
    AsyncApiClient::new(config.api_url, token).map(|client| client.with_region(config.region))
}

fn build_search_path(args: &HistorySearchArgs) -> String {
    let mut params = vec![
        format!("q={}", urlencoding::encode(&args.query)),
        format!("limit={}", args.limit),
    ];
    if let Some(ref kind) = args.entry_kind {
        params.push(format!("entry_kind={}", urlencoding::encode(kind)));
    }
    if let Some(ref agent_id) = args.agent_id {
        params.push(format!("agent_id={}", urlencoding::encode(agent_id)));
    }
    if let Some(ref team_id) = args.team_id {
        params.push(format!("team_id={}", urlencoding::encode(team_id)));
    }
    if let Some(ref since) = args.since {
        params.push(format!("since={}", urlencoding::encode(since)));
    }
    if let Some(ref until) = args.until {
        params.push(format!("until={}", urlencoding::encode(until)));
    }
    format!("/v1/history/search?{}", params.join("&"))
}

fn build_fallback_sessions_path(filters: &FallbackSearchFilters, cursor: Option<&str>) -> String {
    let mut params = vec![format!("limit={FALLBACK_SESSION_PAGE_SIZE}")];
    if let Some(cursor) = cursor {
        params.push(format!("cursor={}", urlencoding::encode(cursor)));
    }
    if let Some(agent_id) = filters.agent_id.as_deref() {
        params.push(format!("agent_id={}", urlencoding::encode(agent_id)));
    }
    if let Some(team_id) = filters.team_id.as_deref() {
        params.push(format!("team_id={}", urlencoding::encode(team_id)));
    }
    format!("/v1/history/sessions?{}", params.join("&"))
}

fn build_fallback_entries_path(
    session_id: &str,
    filters: &FallbackSearchFilters,
    offset: usize,
) -> String {
    let mut params = vec![
        format!("limit={FALLBACK_ENTRY_PAGE_SIZE}"),
        format!("offset={offset}"),
    ];
    if let Some(entry_kind) = filters.entry_kind.as_deref() {
        params.push(format!("entry_kind={}", urlencoding::encode(entry_kind)));
    }
    format!(
        "/v1/history/sessions/{}/entries?{}",
        urlencoding::encode(session_id),
        params.join("&")
    )
}

fn normalize_filter_arg(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn session_title(session: &serde_json::Value) -> Option<&str> {
    session
        .get("title")
        .or_else(|| session.get("session_title"))
        .and_then(|value| value.as_str())
}

fn entry_timestamp(entry: &serde_json::Value) -> Option<&str> {
    entry
        .get("captured_at")
        .or_else(|| entry.get("created_at"))
        .and_then(|value| value.as_str())
}

fn sessions_has_more(value: &serde_json::Value) -> bool {
    value
        .get("has_more")
        .and_then(|flag| flag.as_bool())
        .unwrap_or(false)
}

fn next_sessions_cursor(value: &serde_json::Value) -> Option<String> {
    normalize_filter_arg(value.get("next_cursor").and_then(|cursor| cursor.as_str()))
}

struct FallbackSearchFilters {
    query_lower: String,
    entry_kind: Option<String>,
    agent_id: Option<String>,
    team_id: Option<String>,
    since: Option<DateTime<FixedOffset>>,
    until: Option<DateTime<FixedOffset>>,
    limit: usize,
}

impl FallbackSearchFilters {
    fn from_args(args: &HistorySearchArgs) -> Result<Self, CliError> {
        Ok(Self {
            query_lower: args.query.to_lowercase(),
            entry_kind: normalize_filter_arg(args.entry_kind.as_deref())
                .map(|value| value.to_lowercase()),
            agent_id: normalize_filter_arg(args.agent_id.as_deref()),
            team_id: normalize_filter_arg(args.team_id.as_deref()),
            since: parse_rfc3339_filter("--since", args.since.as_deref())?,
            until: parse_rfc3339_filter("--until", args.until.as_deref())?,
            limit: args.limit as usize,
        })
    }

    fn matches_session(&self, session: &serde_json::Value) -> bool {
        let agent_matches = self.agent_id.as_ref().is_none_or(|expected| {
            session
                .get("agent_id")
                .and_then(|value| value.as_str())
                .is_some_and(|actual| actual == expected)
        });
        let team_matches = self.team_id.as_ref().is_none_or(|expected| {
            session
                .get("actor_team_id")
                .or_else(|| session.get("team_id"))
                .and_then(|value| value.as_str())
                .is_some_and(|actual| actual == expected)
        });
        agent_matches && team_matches
    }

    fn matching_content(
        &self,
        session: &serde_json::Value,
        entry: &serde_json::Value,
    ) -> Option<String> {
        if let Some(expected_kind) = &self.entry_kind {
            let actual_kind = entry
                .get("entry_kind")
                .and_then(|value| value.as_str())
                .map(str::to_lowercase)
                .unwrap_or_default();
            if &actual_kind != expected_kind {
                return None;
            }
        }

        if !timestamp_matches(
            entry_timestamp(entry),
            self.since.as_ref(),
            self.until.as_ref(),
        ) {
            return None;
        }

        let content = entry_content_text(entry);
        if content.to_lowercase().contains(&self.query_lower) {
            return Some(content);
        }

        let title_matches = session_title(session)
            .map(|value| value.to_lowercase().contains(&self.query_lower))
            .unwrap_or(false);
        if !title_matches {
            return None;
        }

        if content.is_empty() {
            session_title(session).map(str::to_owned)
        } else {
            Some(content)
        }
    }
}

fn parse_rfc3339_filter(
    flag_name: &str,
    value: Option<&str>,
) -> Result<Option<DateTime<FixedOffset>>, CliError> {
    value
        .map(|timestamp| {
            DateTime::parse_from_rfc3339(timestamp).map_err(|error| {
                CliError::user(format!(
                    "invalid {flag_name} timestamp '{timestamp}': {error}"
                ))
            })
        })
        .transpose()
}

fn timestamp_matches(
    timestamp: Option<&str>,
    since: Option<&DateTime<FixedOffset>>,
    until: Option<&DateTime<FixedOffset>>,
) -> bool {
    let Some(timestamp) = timestamp else {
        return since.is_none() && until.is_none();
    };
    let Ok(parsed) = DateTime::parse_from_rfc3339(timestamp) else {
        return since.is_none() && until.is_none();
    };
    let after_since = since.is_none_or(|lower_bound| parsed >= *lower_bound);
    let before_until = until.is_none_or(|upper_bound| parsed <= *upper_bound);
    after_since && before_until
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
    fn truncate_content_preserves_unicode_boundaries() {
        assert_eq!(truncate_content("hola🙂mundo", 5), "hola🙂…");
    }

    #[test]
    fn truncate_content_no_op_for_short_strings() {
        assert_eq!(truncate_content("short", 10), "short");
    }

    #[test]
    fn matching_content_checks_request_response_and_content_together() {
        let filters = FallbackSearchFilters {
            query_lower: "assistant keyword".to_string(),
            entry_kind: None,
            agent_id: None,
            team_id: None,
            since: None,
            until: None,
            limit: 20,
        };
        let session = json!({
            "title": "Session without the query"
        });
        let entry = json!({
            "entry_kind": "assistant",
            "request_payload": {
                "messages": [{"role": "user", "content": "request body"}]
            },
            "response_payload": {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "assistant keyword response"
                    }
                }]
            },
            "content": "stored transcript body"
        });

        let matched = filters
            .matching_content(&session, &entry)
            .expect("response text should be searchable");
        assert!(matched.contains("request body"));
        assert!(matched.contains("assistant keyword response"));
        assert!(matched.contains("stored transcript body"));
    }

    #[test]
    fn build_search_path_includes_all_filters() {
        let args = HistorySearchArgs {
            query: "hello world".to_string(),
            entry_kind: Some("user".to_string()),
            agent_id: Some("agent-1".to_string()),
            team_id: Some("team-2".to_string()),
            since: Some("2024-01-01T00:00:00Z".to_string()),
            until: Some("2024-12-31T23:59:59Z".to_string()),
            limit: 50,
            json: false,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let path = build_search_path(&args);
        assert!(path.starts_with("/v1/history/search?"));
        assert!(path.contains("q=hello%20world"));
        assert!(path.contains("limit=50"));
        assert!(path.contains("entry_kind=user"));
        assert!(path.contains("agent_id=agent-1"));
        assert!(path.contains("team_id=team-2"));
        assert!(path.contains("since="));
        assert!(path.contains("until="));
    }

    #[test]
    fn build_search_path_minimal_filters() {
        let args = HistorySearchArgs {
            query: "test".to_string(),
            entry_kind: None,
            agent_id: None,
            team_id: None,
            since: None,
            until: None,
            limit: 20,
            json: false,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let path = build_search_path(&args);
        assert_eq!(path, "/v1/history/search?q=test&limit=20");
    }

    #[test]
    fn build_fallback_sessions_path_with_cursor_and_filters() {
        let filters = FallbackSearchFilters {
            query_lower: "x".to_string(),
            entry_kind: None,
            agent_id: Some("agent-a".to_string()),
            team_id: Some("team-b".to_string()),
            since: None,
            until: None,
            limit: 20,
        };
        let path = build_fallback_sessions_path(&filters, Some("cursor-abc"));
        assert!(path.starts_with("/v1/history/sessions?"));
        assert!(path.contains("cursor=cursor-abc"));
        assert!(path.contains("agent_id=agent-a"));
        assert!(path.contains("team_id=team-b"));
    }

    #[test]
    fn build_fallback_entries_path_with_offset_and_kind() {
        let filters = FallbackSearchFilters {
            query_lower: "x".to_string(),
            entry_kind: Some("assistant".to_string()),
            agent_id: None,
            team_id: None,
            since: None,
            until: None,
            limit: 20,
        };
        let path = build_fallback_entries_path("session-123", &filters, 500);
        assert!(path.contains("/v1/history/sessions/session-123/entries?"));
        assert!(path.contains("offset=500"));
        assert!(path.contains("entry_kind=assistant"));
    }

    #[test]
    fn normalize_filter_arg_trims_and_filters_empty() {
        assert_eq!(
            normalize_filter_arg(Some("  hello  ")),
            Some("hello".to_string())
        );
        assert_eq!(normalize_filter_arg(Some("")), None);
        assert_eq!(normalize_filter_arg(Some("  ")), None);
        assert_eq!(normalize_filter_arg(None), None);
    }

    #[test]
    fn timestamp_matches_within_range() {
        let since = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap();
        let until = chrono::DateTime::parse_from_rfc3339("2024-12-31T23:59:59Z").unwrap();

        assert!(timestamp_matches(
            Some("2024-06-15T12:00:00Z"),
            Some(&since),
            Some(&until)
        ));
        assert!(!timestamp_matches(
            Some("2023-06-15T12:00:00Z"),
            Some(&since),
            Some(&until)
        ));
        assert!(!timestamp_matches(
            Some("2025-06-15T12:00:00Z"),
            Some(&since),
            Some(&until)
        ));
    }

    #[test]
    fn timestamp_matches_open_bounds() {
        let since = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap();
        assert!(timestamp_matches(
            Some("2024-06-15T12:00:00Z"),
            Some(&since),
            None
        ));
        assert!(!timestamp_matches(
            Some("2023-06-15T12:00:00Z"),
            Some(&since),
            None
        ));
        assert!(timestamp_matches(Some("2024-06-15T12:00:00Z"), None, None));
    }

    #[test]
    fn timestamp_matches_missing_timestamp_allowed_only_without_bounds() {
        let since = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap();
        assert!(timestamp_matches(None, None, None));
        assert!(!timestamp_matches(None, Some(&since), None));
    }

    #[test]
    fn fallback_filters_matches_session_agent_and_team() {
        let filters = FallbackSearchFilters {
            query_lower: "x".to_string(),
            entry_kind: None,
            agent_id: Some("agent-1".to_string()),
            team_id: Some("team-2".to_string()),
            since: None,
            until: None,
            limit: 20,
        };
        let matching = json!({"agent_id": "agent-1", "actor_team_id": "team-2"});
        let wrong_agent = json!({"agent_id": "agent-other", "actor_team_id": "team-2"});
        let wrong_team = json!({"agent_id": "agent-1", "actor_team_id": "team-other"});

        assert!(filters.matches_session(&matching));
        assert!(!filters.matches_session(&wrong_agent));
        assert!(!filters.matches_session(&wrong_team));
    }

    #[test]
    fn fallback_filters_matches_session_with_no_agent_or_team_filter() {
        let filters = FallbackSearchFilters {
            query_lower: "x".to_string(),
            entry_kind: None,
            agent_id: None,
            team_id: None,
            since: None,
            until: None,
            limit: 20,
        };
        let session = json!({"agent_id": "anything", "actor_team_id": "anything"});
        assert!(filters.matches_session(&session));
    }

    #[test]
    fn matching_content_filters_by_entry_kind() {
        let filters = FallbackSearchFilters {
            query_lower: "hello".to_string(),
            entry_kind: Some("user".to_string()),
            agent_id: None,
            team_id: None,
            since: None,
            until: None,
            limit: 20,
        };
        let session = json!({"title": "test"});
        let user_entry = json!({"entry_kind": "user", "content": "hello there"});
        let assistant_entry = json!({"entry_kind": "assistant", "content": "hello there"});

        assert!(filters.matching_content(&session, &user_entry).is_some());
        assert!(filters
            .matching_content(&session, &assistant_entry)
            .is_none());
    }

    #[test]
    fn session_title_falls_back_to_session_title_field() {
        assert_eq!(session_title(&json!({"title": "A"})), Some("A"));
        assert_eq!(session_title(&json!({"session_title": "B"})), Some("B"));
        assert_eq!(session_title(&json!({})), None);
    }

    #[test]
    fn entry_timestamp_falls_back_to_created_at() {
        assert_eq!(
            entry_timestamp(&json!({"captured_at": "2024-01-01T00:00:00Z"})),
            Some("2024-01-01T00:00:00Z")
        );
        assert_eq!(
            entry_timestamp(&json!({"created_at": "2024-02-01T00:00:00Z"})),
            Some("2024-02-01T00:00:00Z")
        );
        assert_eq!(entry_timestamp(&json!({})), None);
    }

    #[test]
    fn sessions_has_more_and_next_cursor() {
        let with_more = json!({"has_more": true, "next_cursor": "abc"});
        let without_more = json!({"has_more": false});
        let empty = json!({});

        assert!(sessions_has_more(&with_more));
        assert!(!sessions_has_more(&without_more));
        assert!(!sessions_has_more(&empty));
        assert_eq!(next_sessions_cursor(&with_more), Some("abc".to_string()));
        assert_eq!(next_sessions_cursor(&without_more), None);
    }

    #[test]
    fn parse_rfc3339_filter_valid_and_invalid() {
        let valid = parse_rfc3339_filter("--since", Some("2024-01-01T00:00:00Z"));
        assert!(valid.is_ok());
        assert!(valid.unwrap().is_some());

        let invalid = parse_rfc3339_filter("--since", Some("not-a-date"));
        assert!(invalid.is_err());
        assert!(invalid.unwrap_err().to_string().contains("--since"));

        let none = parse_rfc3339_filter("--since", None);
        assert!(none.unwrap().is_none());
    }

    #[test]
    fn entry_content_text_merges_request_response_and_content() {
        let entry = json!({
            "request_payload": {
                "messages": [{"content": "request msg"}]
            },
            "response_payload": {
                "choices": [{"message": {"content": "response msg"}}]
            },
            "content": "direct content"
        });
        let text = entry_content_text(&entry);
        assert!(text.contains("request msg"));
        assert!(text.contains("response msg"));
        assert!(text.contains("direct content"));
    }

    #[test]
    fn entry_content_text_handles_prompt_and_text_fields() {
        let entry = json!({
            "request_payload": {"prompt": "a prompt"},
            "response_payload": {"choices": [{"text": "completion text"}]}
        });
        let text = entry_content_text(&entry);
        assert!(text.contains("a prompt"));
        assert!(text.contains("completion text"));
    }

    #[test]
    fn message_list_text_aggregates_string_content() {
        let messages = json!([
            {"content": "Hello"},
            {"content": "World"}
        ]);
        let text = message_list_text(&messages);
        assert!(text.contains("Hello"));
        assert!(text.contains("World"));
    }

    #[test]
    fn message_list_text_aggregates_array_content() {
        let messages = json!([
            {"content": [{"type": "text", "text": "part 1"}, {"type": "text", "text": "part 2"}]},
            {"content": "simple string"}
        ]);
        let text = message_list_text(&messages);
        assert!(text.contains("part 1"));
        assert!(text.contains("part 2"));
        assert!(text.contains("simple string"));
    }

    #[test]
    fn message_list_text_returns_empty_for_non_array() {
        let messages = json!("not an array");
        assert_eq!(message_list_text(&messages), "");
    }

    #[test]
    fn message_list_text_skips_missing_content() {
        let messages = json!([
            {"role": "user"},
            {"content": "found"}
        ]);
        let text = message_list_text(&messages);
        assert!(text.contains("found"));
        assert!(!text.contains("user"));
    }

    #[test]
    fn render_results_empty_results() {
        let value = json!({"results": []});
        let result = render_results(&value);
        assert!(result.is_ok());
    }

    #[test]
    fn render_results_missing_results_key() {
        let value = json!({"data": "something"});
        let result = render_results(&value);
        assert!(result.is_ok());
    }

    #[test]
    fn render_results_with_entries() {
        let value = json!({"results": [
            {
                "session_title": "Test Session",
                "entry_kind": "user",
                "content": "hello world",
                "timestamp": "2025-01-01T00:00:00Z"
            }
        ]});
        let result = render_results(&value);
        assert!(result.is_ok());
    }

    #[test]
    fn render_results_with_missing_fields() {
        let value = json!({"results": [
            {
                "session_title": null,
                "entry_kind": null,
                "content": null,
                "timestamp": null
            }
        ]});
        let result = render_results(&value);
        assert!(result.is_ok());
    }

    #[test]
    fn choice_list_text_extracts_message_content() {
        let choices = json!([
            {"message": {"content": "choice 1"}},
            {"message": {"content": "choice 2"}}
        ]);
        let text = choice_list_text(&choices);
        assert!(text.contains("choice 1"));
        assert!(text.contains("choice 2"));
    }

    #[test]
    fn choice_list_text_extracts_text_field() {
        let choices = json!([
            {"text": "completion text"},
            {"message": {"content": "msg content"}}
        ]);
        let text = choice_list_text(&choices);
        assert!(text.contains("completion text"));
        assert!(text.contains("msg content"));
    }

    #[test]
    fn choice_list_text_returns_empty_for_non_array() {
        let choices = json!("not an array");
        assert_eq!(choice_list_text(&choices), "");
    }

    #[test]
    fn request_payload_text_with_messages() {
        let payload = json!({"messages": [{"content": "hello"}]});
        let text = request_payload_text(&payload);
        assert!(text.contains("hello"));
    }

    #[test]
    fn request_payload_text_with_prompt() {
        let payload = json!({"prompt": "a test prompt"});
        let text = request_payload_text(&payload);
        assert!(text.contains("a test prompt"));
    }

    #[test]
    fn request_payload_text_empty_payload() {
        let payload = json!({});
        let text = request_payload_text(&payload);
        assert!(text.is_empty());
    }

    #[test]
    fn response_payload_text_with_choices() {
        let payload = json!({"choices": [{"message": {"content": "response"}}]});
        let text = response_payload_text(&payload);
        assert!(text.contains("response"));
    }

    #[test]
    fn response_payload_text_empty_payload() {
        let payload = json!({});
        let text = response_payload_text(&payload);
        assert!(text.is_empty());
    }

    #[test]
    fn entry_content_text_content_only() {
        let entry = json!({"content": "just direct content"});
        let text = entry_content_text(&entry);
        assert_eq!(text, "just direct content");
    }

    #[test]
    fn entry_content_text_empty_entry() {
        let entry = json!({});
        let text = entry_content_text(&entry);
        assert!(text.is_empty());
    }
}
