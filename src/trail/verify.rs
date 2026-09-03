// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan trail verify` — hash chain verification command.

use chrono::Utc;
use clap::Args;
use serde::Deserialize;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;
use crate::trail::anchor_verify::{verify_anchor_receipt_file, AnchorVerifyResult};
use crate::trail::{assert_authenticated_org, resolve_verify_window};

#[derive(Debug, Args)]
pub(crate) struct VerifyArgs {
    /// Assert that the authenticated token belongs to this organization (UUID)
    #[arg(long)]
    pub(crate) org_id: Option<String>,

    /// Start time (RFC3339 or relative like "7d")
    #[arg(long)]
    pub(crate) start_time: Option<String>,

    /// End time (RFC3339)
    #[arg(long)]
    pub(crate) end_time: Option<String>,

    /// Event ID to verify (single event verification)
    #[arg(long)]
    pub(crate) event_id: Option<String>,

    /// Recompute event hashes, inbound links, sequence, and previous-hash continuity
    /// across the requested interval. Archive segments for the range are mandatory.
    #[arg(long)]
    pub(crate) deep: bool,

    /// Local DSSE Trail anchor receipt to verify (s3_object_lock / filesystem_worm export)
    #[arg(long)]
    pub(crate) anchor_receipt: Option<std::path::PathBuf>,

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
#[allow(dead_code)]
struct VerifyResponse {
    status: String,
    digests_verified: Option<u64>,
    events_verified: Option<u64>,
    chain_integrity: Option<String>,
    first_sequence: Option<u64>,
    last_sequence: Option<u64>,
    #[serde(default)]
    gaps: Vec<SequenceGap>,
    verification_time_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SequenceGap {
    expected: i64,
    actual: i64,
}
pub(crate) async fn run_async(args: VerifyArgs) -> Result<(), CliError> {
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

    // Single-event verification via GET endpoint
    if let Some(event_id) = &args.event_id {
        if args.start_time.is_some()
            || args.end_time.is_some()
            || args.deep
            || args.anchor_receipt.is_some()
        {
            return Err(CliError::user(
                "--event-id cannot be combined with --start-time, --end-time, --deep, or --anchor-receipt",
            ));
        }
        assert_authenticated_org(&client, args.org_id.as_deref()).await?;
        return run_single_event_verify(&client, event_id, args.json).await;
    }

    let authenticated_org_id = assert_authenticated_org(&client, args.org_id.as_deref()).await?;
    let anchor_result = if let Some(path) = &args.anchor_receipt {
        let public_key = fetch_trail_public_key(&client).await?;
        Some(verify_anchor_receipt_file(path, &public_key)?)
    } else {
        None
    };

    // Anchor-only verification: when --anchor-receipt is set without a time window,
    // skip the API hash-chain verify and report the local receipt result.
    if args.anchor_receipt.is_some() && args.start_time.is_none() && args.end_time.is_none() {
        let Some(anchor) = anchor_result else {
            return Err(CliError::internal(
                "anchor receipt verification missing after successful verification",
            ));
        };
        if let Some(org_id) = authenticated_org_id.as_deref() {
            if anchor.receipt.org_id != org_id {
                return Err(CliError::user(format!(
                    "anchor receipt org_id {} does not match authenticated organization {org_id}",
                    anchor.receipt.org_id
                )));
            }
        }
        return emit_anchor_only_result(anchor, args.json);
    }

    let now = Utc::now();
    let (start_time, end_time) =
        resolve_verify_window(args.start_time.as_deref(), args.end_time.as_deref(), now)?;

    if let Some(anchor) = &anchor_result {
        if let Some(org_id) = authenticated_org_id.as_deref() {
            if anchor.receipt.org_id != org_id {
                return Err(CliError::user(format!(
                    "anchor receipt org_id {} does not match authenticated organization {org_id}",
                    anchor.receipt.org_id
                )));
            }
        }
        if anchor.receipt.window_start > end_time || anchor.receipt.window_end < start_time {
            return Err(CliError::user(format!(
                "anchor receipt window [{}, {}] does not overlap verification window [{start_time}, {end_time}]",
                anchor.receipt.window_start, anchor.receipt.window_end
            )));
        }
    }

    let request_body = build_verify_request_body(&start_time, &end_time, args.deep);
    let response = client
        .post_json_value("/v1/trail/verify", &request_body)
        .await?;
    let verify_response: VerifyResponse = serde_json::from_value(response.clone())
        .map_err(|e| CliError::internal(format!("failed to parse verification response: {e}")))?;

    let status_lower = verify_response.status.to_lowercase();
    let verification_succeeded = is_verification_success(&status_lower);
    let has_results = if args.deep {
        verify_response.events_verified.unwrap_or(0) > 0
    } else {
        verify_response.digests_verified.unwrap_or(0) > 0
    };

    if args.json {
        let mut combined = response;
        if let Some(anchor) = &anchor_result {
            if let Some(obj) = combined.as_object_mut() {
                obj.insert(
                    "anchor".to_string(),
                    serde_json::json!({
                        "status": "pass",
                        "merkle_root": anchor.merkle_root,
                        "backend": anchor.receipt.backend,
                        "storage_key": anchor.receipt.storage_key,
                        "window_start": anchor.receipt.window_start,
                        "window_end": anchor.receipt.window_end,
                        "leaf_count": anchor.receipt.leaf_hashes.len(),
                        "key_id": anchor.key_id,
                    }),
                );
            }
        }
        print_json(&combined)?;
        if !verification_succeeded {
            return Err(CliError::user("verification failed"));
        }
        if !has_results {
            return Err(CliError::user(
                "verification window contains no verifiable trail records",
            ));
        }
        return Ok(());
    }

    if verification_succeeded && has_results {
        println!("✓ Hash chain verified");
        if let Some(org_id) = authenticated_org_id {
            println!("  Org ID: {}", org_id);
        }
        if let Some(events_verified) = verify_response.events_verified {
            println!("  Events verified: {}", format_number(events_verified));
        }
        if let Some(digests_verified) = verify_response.digests_verified {
            println!("  Digest records checked: {}", digests_verified);
        }
        if let Some(first) = verify_response.first_sequence {
            if let Some(last) = verify_response.last_sequence {
                println!("  Sequence range: {} to {}", first, last);
            }
        }
        println!("  Status: {}", verify_response.status);
        if let Some(anchor) = &anchor_result {
            print_anchor_success(anchor);
        }
    } else if !verification_succeeded {
        println!("✗ Hash chain verification FAILED");
        println!("  Status: {}", verify_response.status);

        if !verify_response.gaps.is_empty() {
            println!("\n  Gaps detected:");
            for gap in &verify_response.gaps {
                println!(
                    "    Expected sequence {}, actual {}",
                    gap.expected, gap.actual
                );
            }
        }

        return Err(CliError::user("verification failed"));
    } else {
        println!("✗ Verification window contains no verifiable trail records");
        return Err(CliError::user(
            "verification window contains no verifiable trail records",
        ));
    }

    Ok(())
}

async fn fetch_trail_public_key(client: &AsyncApiClient) -> Result<String, CliError> {
    let response = client.get_json_value("/v1/trail/public-key").await?;
    response
        .get("public_key")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| CliError::internal("trail public-key response missing public_key"))
}

fn emit_anchor_only_result(anchor: AnchorVerifyResult, json_output: bool) -> Result<(), CliError> {
    if json_output {
        print_json(&serde_json::json!({
            "status": "pass",
            "anchor": {
                "status": "pass",
                "merkle_root": anchor.merkle_root,
                "backend": anchor.receipt.backend,
                "storage_key": anchor.receipt.storage_key,
                "window_start": anchor.receipt.window_start,
                "window_end": anchor.receipt.window_end,
                "leaf_count": anchor.receipt.leaf_hashes.len(),
                "leaf_kind": anchor.receipt.leaf_kind,
                "key_id": anchor.key_id,
                "org_id": anchor.receipt.org_id,
            }
        }))?;
        return Ok(());
    }
    println!("✓ Anchor receipt verified");
    print_anchor_success(&anchor);
    Ok(())
}

fn print_anchor_success(anchor: &AnchorVerifyResult) {
    println!("✓ External Merkle-root anchor verified");
    println!("  Backend: {}", anchor.receipt.backend);
    println!("  Storage key: {}", anchor.receipt.storage_key);
    println!(
        "  Window: {} → {}",
        anchor.receipt.window_start, anchor.receipt.window_end
    );
    println!("  Merkle root: {}", anchor.merkle_root);
    println!("  Leaves: {}", anchor.receipt.leaf_hashes.len());
    println!("  Signing key: {}", anchor.key_id);
}

async fn run_single_event_verify(
    client: &AsyncApiClient,
    event_id: &str,
    json_output: bool,
) -> Result<(), CliError> {
    let path = format!("/v1/trail/events/{}", urlencoding::encode(event_id));
    let response = client.get_json_value(&path).await?;
    let has_record_hash = single_event_has_record_hash(&response);

    if json_output {
        print_json(&build_single_event_verify_result(event_id, &response))?;
        if !has_record_hash {
            return Err(CliError::user(
                "event verification failed — missing record hash",
            ));
        }
        return Ok(());
    }

    let record_hash = response
        .get("record_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let sequence_number = response.get("sequence_number").and_then(|v| v.as_i64());

    if !has_record_hash {
        println!("✗ Event {} has no record hash", event_id);
        return Err(CliError::user(
            "event verification failed — missing record hash",
        ));
    }

    println!("✓ Event record hash present");
    println!("  Event ID: {}", event_id);
    if let Some(sequence_number) = sequence_number {
        println!("  Sequence: {}", sequence_number);
    }
    println!("  Record hash: {}...", record_hash_preview(record_hash));
    println!("  Status: hash_present");
    Ok(())
}

fn format_number(n: u64) -> String {
    n.to_string()
        .as_bytes()
        .rchunks(3)
        .rev()
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .unwrap_or_default()
        .join(",")
}

fn is_verification_success(status_lower: &str) -> bool {
    status_lower == "pass" || status_lower == "valid"
}

fn build_verify_request_body(start_time: &str, end_time: &str, deep: bool) -> serde_json::Value {
    let mut body = serde_json::Map::new();
    body.insert(
        "start_time".to_string(),
        serde_json::Value::String(start_time.to_string()),
    );
    body.insert(
        "end_time".to_string(),
        serde_json::Value::String(end_time.to_string()),
    );

    if deep {
        body.insert("deep_verify".to_string(), serde_json::Value::Bool(true));
    }

    serde_json::Value::Object(body)
}

fn single_event_has_record_hash(response: &serde_json::Value) -> bool {
    response
        .get("record_hash")
        .and_then(|v| v.as_str())
        .is_some_and(|hash| !hash.is_empty())
}

fn build_single_event_verify_result(
    event_id: &str,
    response: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "status": if single_event_has_record_hash(response) { "hash_present" } else { "fail" },
        "event_id": event_id,
        "record_hash_present": single_event_has_record_hash(response),
        "event": response,
    })
}

fn record_hash_preview(record_hash: &str) -> String {
    record_hash[..32.min(record_hash.len())].to_string()
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
    fn command_helper_coverage_format_number_groups_thousands() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(999), "999");
        assert_eq!(format_number(12_345), "12,345");
        assert_eq!(format_number(1_234_567), "1,234,567");
    }

    #[test]
    fn command_helper_coverage_is_verification_success_accepts_pass_and_valid() {
        assert!(is_verification_success("pass"));
        assert!(is_verification_success("valid"));
        assert!(!is_verification_success("fail"));
        assert!(!is_verification_success("invalid"));
    }

    #[test]
    fn command_helper_coverage_build_verify_request_body_includes_deep_flag() {
        let shallow =
            build_verify_request_body("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", false);
        assert_eq!(shallow["start_time"], "2026-01-01T00:00:00Z");
        assert_eq!(shallow["end_time"], "2026-01-02T00:00:00Z");
        assert!(shallow.get("deep_verify").is_none());

        let deep = build_verify_request_body("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", true);
        assert_eq!(deep["deep_verify"], true);

        // CLI no longer enforces a 90-day deep-verify ceiling; the API rejects
        // ranges that are not backed by loaded archive segments instead.
        let year_deep =
            build_verify_request_body("2025-01-01T00:00:00Z", "2026-01-01T00:00:00Z", true);
        assert_eq!(year_deep["deep_verify"], true);
        assert_eq!(year_deep["start_time"], "2025-01-01T00:00:00Z");
        assert_eq!(year_deep["end_time"], "2026-01-01T00:00:00Z");
    }

    #[test]
    fn command_helper_coverage_single_event_has_record_hash_requires_non_empty_value() {
        assert!(single_event_has_record_hash(
            &json!({"record_hash": "abc123"})
        ));
        assert!(!single_event_has_record_hash(&json!({"record_hash": ""})));
        assert!(!single_event_has_record_hash(&json!({})));
    }

    #[test]
    fn command_helper_coverage_build_single_event_verify_result_includes_event_payload() {
        let event = json!({
            "event_id": "evt-1",
            "record_hash": "hash-value",
            "sequence_number": 42
        });
        let result = build_single_event_verify_result("evt-1", &event);

        assert_eq!(result["status"], "hash_present");
        assert_eq!(result["event_id"], "evt-1");
        assert_eq!(result["record_hash_present"], true);
        assert_eq!(result["event"], event);
    }

    #[test]
    fn command_helper_coverage_single_event_missing_hash_is_failure() {
        let result = build_single_event_verify_result("evt-1", &json!({}));
        assert_eq!(result["status"], "fail");
        assert_eq!(result["record_hash_present"], false);
    }

    #[test]
    fn command_helper_coverage_record_hash_preview_truncates_to_32_chars() {
        let hash = "abcdefghijklmnopqrstuvwxyz0123456789";
        assert_eq!(
            record_hash_preview(hash),
            "abcdefghijklmnopqrstuvwxyz012345"
        );
        assert_eq!(record_hash_preview("short"), "short");
    }
}
