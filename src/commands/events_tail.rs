// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct EventsTailArgs {
    /// Print machine-readable JSON.
    #[arg(long)]
    pub(crate) json: bool,

    /// Since (RFC3339 UTC or a relative duration, for example 10m, 2h, or 7d).
    #[arg(long)]
    pub(crate) since: Option<String>,

    /// Resume from a cursor returned by a previous call.
    #[arg(long)]
    pub(crate) cursor: Option<String>,

    /// Limit (1..=100).
    #[arg(long, default_value_t = 100)]
    pub(crate) limit: u32,

    /// Filter by event type (for example, "decision").
    #[arg(long)]
    pub(crate) event_type: Option<String>,

    /// Filter by gateway id.
    #[arg(long)]
    pub(crate) gateway_id: Option<String>,

    /// Filter by verdict (for example, "allowed", "blocked", "redacted", or "escalated").
    #[arg(long)]
    pub(crate) verdict: Option<String>,

    /// Poll for new events at N-second intervals (follow mode). Implies --json.
    #[arg(long)]
    pub(crate) follow: bool,

    /// Poll interval in seconds when --follow is active (default 5).
    #[arg(long, default_value_t = 5)]
    pub(crate) follow_interval_secs: u64,

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
fn build_query(
    since: Option<&str>,
    cursor: Option<&str>,
    limit: u32,
    event_type: Option<&str>,
    gateway_id: Option<&str>,
    verdict: Option<&str>,
) -> String {
    let mut params = Vec::new();
    if let Some(s) = since {
        params.push(format!("since={}", urlencoding::encode(s)));
    }
    if let Some(c) = cursor {
        params.push(format!("cursor={}", urlencoding::encode(c)));
    }
    params.push(format!("limit={limit}"));
    if let Some(et) = event_type {
        params.push(format!("event_type={}", urlencoding::encode(et)));
    }
    if let Some(gw) = gateway_id {
        params.push(format!("gateway_id={}", urlencoding::encode(gw)));
    }
    if let Some(v) = verdict {
        params.push(format!("verdict={}", urlencoding::encode(v)));
    }
    format!("/v1/events?{}", params.join("&"))
}

pub(crate) async fn run_async(args: EventsTailArgs) -> Result<(), CliError> {
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

    if args.follow {
        // Follow mode: poll indefinitely, advancing cursor after each page.
        let mut cursor: Option<String> = args.cursor.clone();
        let since_initial = args.since.clone();
        let mut first = true;

        loop {
            let since_ref = if first {
                since_initial.as_deref()
            } else {
                None
            };
            let path = build_query(
                since_ref,
                cursor.as_deref(),
                args.limit,
                args.event_type.as_deref(),
                args.gateway_id.as_deref(),
                args.verdict.as_deref(),
            );

            let value = client.get_json_value(&path).await?;
            let next_cursor = value
                .get("next_cursor")
                .and_then(|v| v.as_str())
                .map(String::from);

            if let Some(events) = value.get("events").and_then(|v| v.as_array()) {
                for event in events {
                    if args.json {
                        print_json(event)?;
                    } else {
                        print_event_line(event);
                    }
                }
            }

            cursor = next_cursor;
            first = false;

            tokio::time::sleep(std::time::Duration::from_secs(args.follow_interval_secs)).await;
        }
    } else {
        let path = build_query(
            args.since.as_deref(),
            args.cursor.as_deref(),
            args.limit,
            args.event_type.as_deref(),
            args.gateway_id.as_deref(),
            args.verdict.as_deref(),
        );

        let value = client.get_json_value(&path).await?;

        if args.json {
            print_json(&value)?;
        } else if let Some(events) = value.get("events").and_then(|v| v.as_array()) {
            if events.is_empty() {
                println!("No events found.");
            } else {
                for event in events {
                    print_event_line(event);
                }
            }
        }
        Ok(())
    }
}

fn print_event_line(event: &serde_json::Value) {
    let line = format_event_line(event);
    println!("{line}");
}

fn format_event_line(event: &serde_json::Value) -> String {
    let time = event
        .get("event_time")
        .or_else(|| event.get("created_at"))
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    let etype = event
        .get("event_type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let verdict = event.get("verdict").and_then(|v| v.as_str()).unwrap_or("-");
    let model = event.get("model").and_then(|v| v.as_str()).unwrap_or("-");
    let policy = event
        .get("policy_name")
        .and_then(|v| v.as_str())
        .unwrap_or("-");

    let time_short = if time.len() > 19 { &time[..19] } else { time };
    format!(
        "  {} {:10} {:10} model={} policy={}",
        time_short, etype, verdict, model, policy
    )
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
    fn build_query_with_all_params() {
        let q = build_query(
            Some("2024-01-01T00:00:00Z"),
            Some("cursor-abc"),
            50,
            Some("decision"),
            Some("gw-1"),
            Some("blocked"),
        );
        assert!(q.starts_with("/v1/events?"));
        assert!(q.contains("since=2024-01-01T00%3A00%3A00Z"));
        assert!(q.contains("cursor=cursor-abc"));
        assert!(q.contains("limit=50"));
        assert!(q.contains("event_type=decision"));
        assert!(q.contains("gateway_id=gw-1"));
        assert!(q.contains("verdict=blocked"));
    }

    #[test]
    fn build_query_minimal() {
        let q = build_query(None, None, 100, None, None, None);
        assert_eq!(q, "/v1/events?limit=100");
    }

    #[test]
    fn build_query_only_since() {
        let q = build_query(Some("10m"), None, 20, None, None, None);
        assert!(q.contains("since=10m"));
        assert!(q.contains("limit=20"));
        assert!(!q.contains("cursor="));
    }

    #[test]
    fn build_query_encodes_special_characters() {
        let q = build_query(None, None, 10, Some("type with spaces"), None, None);
        assert!(q.contains("event_type=type%20with%20spaces"));
    }

    #[test]
    fn format_event_line_full_event() {
        let event = json!({
            "event_time": "2024-06-15T12:30:45.123Z",
            "event_type": "decision",
            "verdict": "allowed",
            "model": "gpt-4o",
            "policy_name": "default"
        });
        let line = format_event_line(&event);
        assert!(line.contains("2024-06-15T12:30:45"));
        assert!(line.contains("decision"));
        assert!(line.contains("allowed"));
        assert!(line.contains("gpt-4o"));
        assert!(line.contains("default"));
    }

    #[test]
    fn format_event_line_missing_fields_uses_defaults() {
        let event = json!({});
        let line = format_event_line(&event);
        assert!(line.contains("-"));
        assert!(line.contains("unknown"));
    }

    #[test]
    fn format_event_line_falls_back_to_created_at() {
        let event = json!({
            "created_at": "2024-03-01T08:00:00Z",
            "event_type": "audit"
        });
        let line = format_event_line(&event);
        assert!(line.contains("2024-03-01T08:00:00"));
    }

    #[test]
    fn format_event_line_short_time_not_truncated() {
        let event = json!({
            "event_time": "short",
            "event_type": "x"
        });
        let line = format_event_line(&event);
        assert!(line.contains("short"));
    }

    #[test]
    fn format_event_line_exact_19_char_time() {
        let event = json!({
            "event_time": "2024-06-15T12:30:45",
            "event_type": "decision"
        });
        let line = format_event_line(&event);
        assert!(line.contains("2024-06-15T12:30:45"));
    }

    #[test]
    fn build_query_cursor_only() {
        let q = build_query(None, Some("next-page-token"), 100, None, None, None);
        assert!(q.contains("cursor=next-page-token"));
        assert!(!q.contains("since="));
    }

    #[test]
    fn build_query_verdict_only() {
        let q = build_query(None, None, 50, None, None, Some("blocked"));
        assert!(q.contains("verdict=blocked"));
        assert!(q.contains("limit=50"));
    }

    #[test]
    fn format_event_line_with_policy_name_fallback() {
        let event = json!({
            "event_time": "2024-06-15T12:30:45.123Z",
            "event_type": "decision",
            "verdict": "blocked"
        });
        let line = format_event_line(&event);
        assert!(line.contains("policy=-"));
    }

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use axum::{
        extract::{Query, State},
        routing::get,
        Json, Router,
    };
    use serde::Deserialize;
    use tokio::net::TcpListener;

    use std::time::Duration;

    #[derive(Clone)]
    struct EventsTailCapture {
        requests: Arc<AtomicUsize>,
        follow_cursor_seen: Arc<std::sync::Mutex<bool>>,
    }

    impl Default for EventsTailCapture {
        fn default() -> Self {
            Self {
                requests: Arc::new(AtomicUsize::new(0)),
                follow_cursor_seen: Arc::new(std::sync::Mutex::new(false)),
            }
        }
    }

    #[derive(Debug, Deserialize)]
    struct TailQuery {
        #[allow(dead_code)]
        since: Option<String>,
        cursor: Option<String>,
        #[allow(dead_code)]
        limit: Option<u32>,
        #[allow(dead_code)]
        event_type: Option<String>,
        #[allow(dead_code)]
        gateway_id: Option<String>,
        #[allow(dead_code)]
        verdict: Option<String>,
    }

    async fn events_tail_handler(
        State(capture): State<EventsTailCapture>,
        Query(query): Query<TailQuery>,
    ) -> Json<serde_json::Value> {
        capture.requests.fetch_add(1, Ordering::SeqCst);
        if query.cursor.as_deref() == Some("cursor-1") {
            *capture.follow_cursor_seen.lock().expect("cursor lock") = true;
            return Json(json!({ "events": [], "next_cursor": null }));
        }

        Json(json!({
            "events": [{
                "event_time": "2024-06-15T12:30:45Z",
                "event_type": "decision",
                "verdict": "allowed",
                "model": "gpt-4o",
                "policy_name": "default"
            }],
            "next_cursor": if query.cursor.is_none() {
                serde_json::Value::String("cursor-1".to_string())
            } else {
                serde_json::Value::Null
            }
        }))
    }

    async fn empty_events_handler(
        State(capture): State<EventsTailCapture>,
    ) -> Json<serde_json::Value> {
        capture.requests.fetch_add(1, Ordering::SeqCst);
        Json(json!({ "events": [], "next_cursor": null }))
    }

    async fn spawn_events_server(capture: EventsTailCapture, empty_only: bool) -> String {
        let app = if empty_only {
            Router::new()
                .route("/v1/events", get(empty_events_handler))
                .with_state(capture)
        } else {
            Router::new()
                .route("/v1/events", get(events_tail_handler))
                .with_state(capture)
        };
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let base_url = format!("http://{}", listener.local_addr().expect("local addr"));
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve events stub");
        });
        base_url
    }

    fn tail_args(api_url: String, mut args: EventsTailArgs) -> EventsTailArgs {
        args.api_url = Some(api_url);
        args.api_token = Some("test-token".to_string());
        args
    }

    #[tokio::test]
    async fn run_async_prints_human_event_rows() {
        let capture = EventsTailCapture::default();
        let api_url = spawn_events_server(capture.clone(), false).await;
        let args = tail_args(
            api_url,
            EventsTailArgs {
                json: false,
                since: Some("10m".to_string()),
                cursor: None,
                limit: 5,
                event_type: None,
                gateway_id: None,
                verdict: None,
                follow: false,
                follow_interval_secs: 5,
                config: None,
                api_url: None,
                api_token: None,
                profile: "default".to_string(),
                region: None,
            },
        );

        run_async(args).await.expect("human tail succeeds");
        assert_eq!(capture.requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn run_async_reports_empty_human_output() {
        let capture = EventsTailCapture::default();
        let api_url = spawn_events_server(capture.clone(), true).await;
        let args = tail_args(
            api_url,
            EventsTailArgs {
                json: false,
                since: Some("10m".to_string()),
                cursor: None,
                limit: 5,
                event_type: None,
                gateway_id: None,
                verdict: None,
                follow: false,
                follow_interval_secs: 5,
                config: None,
                api_url: None,
                api_token: None,
                profile: "default".to_string(),
                region: None,
            },
        );

        run_async(args).await.expect("empty human tail succeeds");
        assert_eq!(capture.requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn run_async_requires_api_token() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        crate::test_support::set_var("HOME", dir.path());
        crate::test_support::set_var(
            "VERDICTAN_TEST_HOME",
            dir.path().to_string_lossy().to_string(),
        );
        std::env::remove_var("VERDICTAN_API_TOKEN");
        std::env::remove_var("VERDICTAN_CONFIG");

        let args = EventsTailArgs {
            json: true,
            since: None,
            cursor: None,
            limit: 100,
            event_type: None,
            gateway_id: None,
            verdict: None,
            follow: false,
            follow_interval_secs: 5,
            config: None,
            api_url: Some("http://127.0.0.1:9".to_string()),
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };

        let err = run_async(args)
            .await
            .expect_err("missing token should fail");
        assert!(err.to_string().contains("missing api token"));
    }

    #[test]
    fn build_query_all_params_present() {
        let q = build_query(
            Some("10m"),
            Some("cursor-abc"),
            50,
            Some("decision"),
            Some("gw-1"),
            Some("blocked"),
        );
        assert!(q.contains("since=10m"));
        assert!(q.contains("cursor=cursor-abc"));
        assert!(q.contains("limit=50"));
        assert!(q.contains("event_type=decision"));
        assert!(q.contains("gateway_id=gw-1"));
        assert!(q.contains("verdict=blocked"));
    }

    #[test]
    fn build_query_limit_zero() {
        let q = build_query(None, None, 0, None, None, None);
        assert!(q.contains("limit=0"));
        assert!(!q.contains("since="));
        assert!(!q.contains("cursor="));
    }

    #[test]
    fn build_query_limit_max() {
        let q = build_query(None, None, 100, None, None, None);
        assert!(q.contains("limit=100"));
    }

    #[test]
    fn build_query_encodes_verdict_with_spaces() {
        let q = build_query(None, None, 10, None, None, Some("partially blocked"));
        assert!(q.contains("verdict=partially%20blocked"));
    }

    #[test]
    fn format_event_line_empty_object() {
        let event = serde_json::json!({});
        let line = format_event_line(&event);
        assert!(!line.is_empty());
    }

    #[test]
    fn args_debug_impl() {
        let args = EventsTailArgs {
            json: true,
            since: Some("5m".to_string()),
            cursor: None,
            limit: 25,
            event_type: None,
            gateway_id: None,
            verdict: None,
            follow: false,
            follow_interval_secs: 5,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("25"));
        assert!(debug.contains("5m"));
    }
}
