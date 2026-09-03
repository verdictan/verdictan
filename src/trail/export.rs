// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan trail export` — export trail events to file.

use clap::{Args, ValueEnum};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs::File;
use std::io::Write;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::trail::{assert_authenticated_org, validate_bounded_query_window};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum ExportFormat {
    Json,
    Jsonl,
    Csv,
}

#[derive(Debug, Args)]
pub(crate) struct ExportArgs {
    /// Assert that the authenticated token belongs to this organization (UUID)
    #[arg(long)]
    pub(crate) org_id: Option<String>,

    /// Output file path.
    #[arg(long)]
    pub(crate) output: std::path::PathBuf,

    /// Export format: json, jsonl, or csv.
    #[arg(long, value_enum, default_value = "jsonl")]
    pub(crate) format: ExportFormat,

    /// Start time (RFC3339)
    #[arg(long)]
    pub(crate) start_time: Option<String>,

    /// End time (RFC3339)
    #[arg(long)]
    pub(crate) end_time: Option<String>,

    /// Filter by event source.
    #[arg(long)]
    pub(crate) event_source: Option<String>,

    /// Filter by event name.
    #[arg(long)]
    pub(crate) event_name: Option<String>,

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
    events: Vec<serde_json::Value>,
    next_cursor: Option<String>,
    #[allow(dead_code)]
    result_count: u32,
}
pub(crate) async fn run_async(args: ExportArgs) -> Result<(), CliError> {
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
    validate_bounded_query_window(args.start_time.as_deref(), args.end_time.as_deref(), 7)?;

    // Collect all events with pagination
    let mut all_events = Vec::new();
    let mut next_cursor: Option<String> = None;
    let mut seen_cursors = HashSet::new();
    let mut page_count = 0;

    println!("Exporting events...");

    loop {
        let path = build_export_events_path(
            next_cursor.as_deref(),
            args.start_time.as_deref(),
            args.end_time.as_deref(),
            args.event_source.as_deref(),
            args.event_name.as_deref(),
        );
        let value = client.get_json_value(&path).await?;

        let response: EventsResponse = serde_json::from_value(value)
            .map_err(|e| CliError::internal(format!("failed to parse events response: {e}")))?;

        page_count += 1;
        let event_count = response.events.len();
        all_events.extend(response.events);

        eprint!(
            "\rExported {:>7} events (page {})...",
            format_count(all_events.len()),
            page_count
        );
        std::io::stderr()
            .flush()
            .map_err(|e| CliError::internal(format!("failed to flush stderr: {e}")))?;

        let Some(cursor) = response.next_cursor else {
            break;
        };
        if event_count == 0 {
            return Err(CliError::internal(
                "trail export pagination returned an empty page with a continuation cursor",
            ));
        }
        if !seen_cursors.insert(cursor.clone()) {
            return Err(CliError::internal(
                "trail export pagination repeated a continuation cursor",
            ));
        }
        next_cursor = Some(cursor);
    }

    eprintln!(); // New line after progress

    if all_events.is_empty() {
        return Err(CliError::user(
            "no trail events matched the requested export window",
        ));
    }

    // Do not create or truncate the destination until every page has been
    // fetched successfully and the result is known to be nonempty.
    let mut file = File::create(&args.output)
        .map_err(|e| CliError::user(format!("failed to create output file: {}", e)))?;
    let use_gzip = output_uses_gzip(&args.output);

    if use_gzip {
        let gz_encoder = GzEncoder::new(&file, Compression::default());
        let mut writer = std::io::BufWriter::new(gz_encoder);
        write_to_output(&mut writer, args.format, &all_events)?;
        writer
            .into_inner()
            .map_err(|e| CliError::internal(format!("failed to flush gzip buffer: {e}")))?
            .finish()
            .map_err(|e| CliError::internal(format!("failed to finalize gzip: {e}")))?;
    } else {
        write_to_output(&mut file, args.format, &all_events)?;
    }

    println!(
        "Exported {} events to {}{}",
        all_events.len(),
        args.output.display(),
        if use_gzip { " (gzip compressed)" } else { "" }
    );

    Ok(())
}

fn write_to_output(
    writer: &mut dyn Write,
    format: ExportFormat,
    events: &[serde_json::Value],
) -> Result<(), CliError> {
    match format {
        ExportFormat::Json => write_json(writer, events),
        ExportFormat::Jsonl => write_jsonl(writer, events),
        ExportFormat::Csv => write_csv(writer, events),
    }
}

fn write_json(w: &mut dyn Write, events: &[serde_json::Value]) -> Result<(), CliError> {
    let json = serde_json::to_string_pretty(events)
        .map_err(|e| CliError::internal(format!("failed to serialize JSON: {e}")))?;

    w.write_all(json.as_bytes())
        .map_err(|e| CliError::user(format!("failed to write file: {e}")))?;

    Ok(())
}

fn write_jsonl(w: &mut dyn Write, events: &[serde_json::Value]) -> Result<(), CliError> {
    for event in events {
        let line = serde_json::to_string(event)
            .map_err(|e| CliError::internal(format!("failed to serialize JSON: {e}")))?;

        writeln!(w, "{}", line)
            .map_err(|e| CliError::user(format!("failed to write file: {e}")))?;
    }

    Ok(())
}

fn write_csv(w: &mut dyn Write, events: &[serde_json::Value]) -> Result<(), CliError> {
    if events.is_empty() {
        return Ok(());
    }

    let header = "event_id,event_time,event_name,event_source,resource_type,resource_id,actor_email,actor_arn,source_ip,request_method,request_path\n";
    w.write_all(header.as_bytes())
        .map_err(|e| CliError::user(format!("failed to write CSV header: {e}")))?;

    for event in events {
        let event_id = event["event_id"].as_str().unwrap_or("");
        let event_time = event["event_time"].as_str().unwrap_or("");
        let event_name = event["event_name"].as_str().unwrap_or("");
        let event_source = event["event_source"].as_str().unwrap_or("");
        let resource_type = event["resource_type"].as_str().unwrap_or("");
        let resource_id = event["resource_id"].as_str().unwrap_or("");
        let actor_email = event["actor_email"].as_str().unwrap_or("");
        let actor_arn = event["actor_arn"].as_str().unwrap_or("");
        let source_ip = event["source_ip"].as_str().unwrap_or("");
        let request_method = event["request_method"].as_str().unwrap_or("");
        let request_path = event["request_path"].as_str().unwrap_or("");

        let row = format!(
            "{},{},{},{},{},{},{},{},{},{},{}\n",
            csv_escape(event_id),
            csv_escape(event_time),
            csv_escape(event_name),
            csv_escape(event_source),
            csv_escape(resource_type),
            csv_escape(resource_id),
            csv_escape(actor_email),
            csv_escape(actor_arn),
            csv_escape(source_ip),
            csv_escape(request_method),
            csv_escape(request_path)
        );

        w.write_all(row.as_bytes())
            .map_err(|e| CliError::user(format!("failed to write CSV row: {e}")))?;
    }

    Ok(())
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn format_count(n: usize) -> String {
    n.to_string()
        .as_bytes()
        .rchunks(3)
        .rev()
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .unwrap_or_default()
        .join(",")
}

fn build_export_events_path(
    cursor: Option<&str>,
    start_time: Option<&str>,
    end_time: Option<&str>,
    event_source: Option<&str>,
    event_name: Option<&str>,
) -> String {
    let mut query_params = vec!["limit=1000".to_string()];

    if let Some(cursor) = cursor {
        query_params.push(format!("cursor={}", urlencoding::encode(cursor)));
    }

    if let Some(start_time) = start_time {
        query_params.push(format!("start_time={}", urlencoding::encode(start_time)));
    }

    if let Some(end_time) = end_time {
        query_params.push(format!("end_time={}", urlencoding::encode(end_time)));
    }

    if let Some(event_source) = event_source {
        query_params.push(format!(
            "event_source={}",
            urlencoding::encode(event_source)
        ));
    }

    if let Some(event_name) = event_name {
        query_params.push(format!("event_name={}", urlencoding::encode(event_name)));
    }

    format!("/v1/trail/events?{}", query_params.join("&"))
}

fn output_uses_gzip(path: &std::path::Path) -> bool {
    path.to_string_lossy().ends_with(".gz")
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
    use std::io::Cursor;

    fn sample_event() -> serde_json::Value {
        json!({
            "event_id": "evt-1",
            "event_time": "2026-01-01T00:00:00Z",
            "event_name": "CreateUser",
            "event_source": "identity_access",
            "resource_type": "User",
            "resource_id": "user-1",
            "actor_email": "admin@example.com",
            "actor_arn": "arn:verdictan:iam::user/admin",
            "source_ip": "203.0.113.10",
            "request_method": "POST",
            "request_path": "/v1/users"
        })
    }

    #[test]
    fn command_helper_coverage_build_export_events_path_encodes_filters() {
        assert_eq!(
            build_export_events_path(None, None, None, None, None),
            "/v1/trail/events?limit=1000"
        );
        assert_eq!(
            build_export_events_path(
                Some("cursor/next"),
                Some("2026-01-01T00:00:00Z"),
                Some("2026-01-02T00:00:00Z"),
                Some("identity access"),
                Some("Delete/Token"),
            ),
            "/v1/trail/events?limit=1000&cursor=cursor%2Fnext&start_time=2026-01-01T00%3A00%3A00Z&end_time=2026-01-02T00%3A00%3A00Z&event_source=identity%20access&event_name=Delete%2FToken"
        );
    }

    #[test]
    fn command_helper_coverage_csv_escape_quotes_commas_and_newlines() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_escape("line\nbreak"), "\"line\nbreak\"");
    }

    #[test]
    fn command_helper_coverage_format_count_groups_thousands() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(999), "999");
        assert_eq!(format_count(1_000), "1,000");
        assert_eq!(format_count(1_234_567), "1,234,567");
    }

    #[test]
    fn command_helper_coverage_write_json_serializes_pretty_array() {
        let mut buf = Vec::new();
        write_json(&mut buf, &[sample_event()]).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("\"event_id\": \"evt-1\""));
        assert!(output.starts_with('['));
    }

    #[test]
    fn command_helper_coverage_write_jsonl_emits_one_line_per_event() {
        let mut buf = Vec::new();
        write_jsonl(&mut buf, &[sample_event(), sample_event()]).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output.matches('\n').count(), 2);
        assert!(output.contains("\"event_id\":\"evt-1\""));
    }

    #[test]
    fn command_helper_coverage_write_csv_includes_header_and_escaped_fields() {
        let mut buf = Vec::new();
        let event = json!({
            "event_id": "evt-2",
            "event_time": "2026-01-02T00:00:00Z",
            "event_name": "Update,Policy",
            "event_source": "governance",
            "resource_type": "Policy",
            "resource_id": "pol-1",
            "actor_email": "ops@example.com",
            "actor_arn": "arn:verdictan:iam::user/ops",
            "source_ip": "198.51.100.4",
            "request_method": "PATCH",
            "request_path": "/v1/policies"
        });
        write_csv(&mut buf, &[event]).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.starts_with("event_id,event_time,event_name"));
        assert!(output.contains("\"Update,Policy\""));
    }

    #[test]
    fn command_helper_coverage_write_to_output_dispatches_by_format() {
        let events = vec![sample_event()];
        let mut json_buf = Cursor::new(Vec::new());
        write_to_output(&mut json_buf, ExportFormat::Json, &events).unwrap();
        assert!(String::from_utf8(json_buf.into_inner())
            .unwrap()
            .starts_with('['));

        let mut jsonl_buf = Cursor::new(Vec::new());
        write_to_output(&mut jsonl_buf, ExportFormat::Jsonl, &events).unwrap();
        assert!(String::from_utf8(jsonl_buf.into_inner())
            .unwrap()
            .contains("\"event_id\""));

        let mut csv_buf = Cursor::new(Vec::new());
        write_to_output(&mut csv_buf, ExportFormat::Csv, &events).unwrap();
        assert!(String::from_utf8(csv_buf.into_inner())
            .unwrap()
            .starts_with("event_id,"));
    }

    #[test]
    fn command_helper_coverage_output_uses_gzip_detects_suffix() {
        assert!(output_uses_gzip(std::path::Path::new(
            "/tmp/events.json.gz"
        )));
        assert!(!output_uses_gzip(std::path::Path::new("/tmp/events.jsonl")));
    }
}
