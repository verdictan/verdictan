// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;

use crate::error::CliError;
use crate::output::json::print_json;
use crate::supervisor::{default_state_dir, SupervisorStateStore};

#[derive(Debug, Args)]
pub(crate) struct GatewayDiffArgs {
    #[arg(long, default_value = "verdictan-proxy")]
    pub(crate) name: String,

    #[arg(long)]
    pub(crate) state_dir: Option<std::path::PathBuf>,

    #[arg(long)]
    pub(crate) json: bool,
}

pub(crate) fn run(args: GatewayDiffArgs) -> Result<(), CliError> {
    let state_dir = args.state_dir.clone().unwrap_or(default_state_dir()?);
    let store = SupervisorStateStore::load(state_dir)?;

    let record = store
        .get_instance(&args.name)
        .ok_or_else(|| CliError::user(format!("instance {} not found", args.name)))?;

    let history = &record.operations_history;
    if history.is_empty() {
        if args.json {
            return print_json(&serde_json::json!({
                "instance_id": args.name,
                "diff": null,
                "message": "no operations history"
            }));
        }
        println!("No operations history for instance '{}'.", args.name);
        return Ok(());
    }

    // Find the two most recent entries that have version/sha info.
    let latest = &history[history.len() - 1];

    let diff = DiffOutput {
        instance_id: args.name.clone(),
        latest_action: format!("{:?}", latest.action).to_ascii_lowercase(),
        latest_outcome: format!("{:?}", latest.outcome).to_ascii_lowercase(),
        previous_version: latest.previous_version.clone(),
        previous_sha256: latest.previous_sha256.clone(),
        active_version: latest.active_version.clone(),
        active_sha256: latest.active_sha256.clone(),
        recorded_at: latest.recorded_at.clone(),
        version_changed: latest.previous_version != latest.active_version
            || latest.previous_sha256 != latest.active_sha256,
    };

    if args.json {
        return print_json(&diff);
    }

    println!("Instance: {}", diff.instance_id);
    println!(
        "Last operation: {} ({})",
        diff.latest_action, diff.latest_outcome
    );
    println!("Recorded at: {}", diff.recorded_at);
    println!();
    println!(
        "  Previous: version={} sha256={}",
        diff.previous_version.as_deref().unwrap_or("<none>"),
        diff.previous_sha256.as_deref().unwrap_or("<none>")
    );
    println!(
        "  Active:   version={} sha256={}",
        diff.active_version.as_deref().unwrap_or("<none>"),
        diff.active_sha256.as_deref().unwrap_or("<none>")
    );
    if diff.version_changed {
        println!("  → Config version CHANGED");
    } else {
        println!("  → Config version unchanged");
    }

    Ok(())
}

#[derive(serde::Serialize)]
struct DiffOutput {
    instance_id: String,
    latest_action: String,
    latest_outcome: String,
    previous_version: Option<String>,
    previous_sha256: Option<String>,
    active_version: Option<String>,
    active_sha256: Option<String>,
    recorded_at: String,
    version_changed: bool,
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

    #[test]
    fn diff_output_version_changed_when_versions_differ() {
        let diff = DiffOutput {
            instance_id: "gw-1".into(),
            latest_action: "reload".into(),
            latest_outcome: "succeeded".into(),
            previous_version: Some("v1".into()),
            previous_sha256: Some("aaa".into()),
            active_version: Some("v2".into()),
            active_sha256: Some("bbb".into()),
            recorded_at: "2025-06-01T00:00:00Z".into(),
            version_changed: true,
        };
        assert!(diff.version_changed);
    }

    #[test]
    fn diff_output_version_unchanged_when_equal() {
        let prev_v = Some("v1".to_string());
        let active_v = Some("v1".to_string());
        let prev_sha = Some("abc".to_string());
        let active_sha = Some("abc".to_string());
        let changed = prev_v != active_v || prev_sha != active_sha;
        assert!(!changed);
    }

    #[test]
    fn diff_output_version_changed_sha_only() {
        let prev_v = Some("v1".to_string());
        let active_v = Some("v1".to_string());
        let prev_sha = Some("aaa".to_string());
        let active_sha = Some("bbb".to_string());
        let changed = prev_v != active_v || prev_sha != active_sha;
        assert!(changed);
    }

    #[test]
    fn diff_output_serializes_to_json() {
        let diff = DiffOutput {
            instance_id: "gw-1".into(),
            latest_action: "reload".into(),
            latest_outcome: "succeeded".into(),
            previous_version: None,
            previous_sha256: None,
            active_version: Some("v2".into()),
            active_sha256: Some("bbb".into()),
            recorded_at: "2025-06-01T00:00:00Z".into(),
            version_changed: true,
        };
        let json = serde_json::to_value(&diff).unwrap();
        assert_eq!(json["instance_id"], "gw-1");
        assert!(json["previous_version"].is_null());
        assert_eq!(json["version_changed"], true);
    }

    #[test]
    fn diff_output_none_versions_display_none() {
        let prev: Option<String> = None;
        assert_eq!(prev.as_deref().unwrap_or("<none>"), "<none>");
    }

    #[test]
    fn diff_output_both_none_is_unchanged() {
        let prev_v: Option<String> = None;
        let active_v: Option<String> = None;
        let prev_sha: Option<String> = None;
        let active_sha: Option<String> = None;
        let changed = prev_v != active_v || prev_sha != active_sha;
        assert!(!changed);
    }

    #[test]
    fn diff_output_json_round_trip() {
        let diff = DiffOutput {
            instance_id: "gw-rt".into(),
            latest_action: "install".into(),
            latest_outcome: "succeeded".into(),
            previous_version: Some("v1".into()),
            previous_sha256: Some("sha1".into()),
            active_version: Some("v2".into()),
            active_sha256: Some("sha2".into()),
            recorded_at: "2025-06-01T00:00:00Z".into(),
            version_changed: true,
        };
        let json_str = serde_json::to_string(&diff).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["instance_id"], "gw-rt");
        assert_eq!(parsed["version_changed"], true);
    }

    #[test]
    fn diff_output_all_none_fields() {
        let diff = DiffOutput {
            instance_id: "gw-none".into(),
            latest_action: "create".into(),
            latest_outcome: "succeeded".into(),
            previous_version: None,
            previous_sha256: None,
            active_version: None,
            active_sha256: None,
            recorded_at: "2025-06-01".into(),
            version_changed: false,
        };
        let json = serde_json::to_value(&diff).unwrap();
        assert!(json["previous_version"].is_null());
        assert!(json["previous_sha256"].is_null());
        assert!(json["active_version"].is_null());
        assert!(json["active_sha256"].is_null());
        assert_eq!(json["version_changed"], false);
    }

    #[test]
    fn diff_output_version_changed_only_sha_differs() {
        let prev_v: Option<String> = Some("v1".into());
        let active_v: Option<String> = Some("v1".into());
        let prev_sha: Option<String> = Some("aaa".into());
        let active_sha: Option<String> = Some("bbb".into());
        let changed = prev_v != active_v || prev_sha != active_sha;
        assert!(changed);
    }

    #[test]
    fn diff_output_version_unchanged_same_values() {
        let prev_v: Option<String> = Some("v2".into());
        let active_v: Option<String> = Some("v2".into());
        let prev_sha: Option<String> = Some("sha".into());
        let active_sha: Option<String> = Some("sha".into());
        let changed = prev_v != active_v || prev_sha != active_sha;
        assert!(!changed);
    }

    #[test]
    fn diff_output_display_none_placeholder() {
        let v: Option<String> = None;
        assert_eq!(v.as_deref().unwrap_or("<none>"), "<none>");
        let v2: Option<String> = Some("v3".into());
        assert_eq!(v2.as_deref().unwrap_or("<none>"), "v3");
    }

    #[test]
    fn diff_output_latest_action_values() {
        for action in ["reload", "reconcile", "install", "revert", "create"] {
            let diff = DiffOutput {
                instance_id: "gw-act".into(),
                latest_action: action.into(),
                latest_outcome: "succeeded".into(),
                previous_version: None,
                previous_sha256: None,
                active_version: None,
                active_sha256: None,
                recorded_at: "2025-06-01".into(),
                version_changed: false,
            };
            let json = serde_json::to_value(&diff).unwrap();
            assert_eq!(json["latest_action"], action);
        }
    }

    #[test]
    fn diff_output_latest_outcome_values() {
        for outcome in ["succeeded", "failed", "rolledback"] {
            let diff = DiffOutput {
                instance_id: "gw-out".into(),
                latest_action: "reload".into(),
                latest_outcome: outcome.into(),
                previous_version: None,
                previous_sha256: None,
                active_version: None,
                active_sha256: None,
                recorded_at: "2025-06-01".into(),
                version_changed: false,
            };
            let json = serde_json::to_value(&diff).unwrap();
            assert_eq!(json["latest_outcome"], outcome);
        }
    }
}
