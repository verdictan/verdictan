// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan control apply` — reconcile a control-plane manifest to the API.
//!
//! Reads a manifest file, computes the diff, optionally shows the plan for
//! confirmation, and then applies all pending operations in dependency order.
//!
//! # Usage
//!
//! ```text
//! verdictan control apply --file control-manifest.yaml [--prune] [--yes] [--json]
//! ```
//!
//! # Safety
//!
//! - `--prune` is **required** to schedule any delete operations. Remote
//!   resources absent from the manifest are left untouched otherwise.
//! - Without `--yes` the command prints the plan and prompts before applying.
//!   Pass `--yes` to skip the prompt in CI or scripted contexts.
//!
//! # Module wiring
//! Add `pub(crate) mod control_apply;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::managed::control_manifest;
use crate::managed::control_reconcile::{
    ReconcileAction, ReconcileOp, ReconcilePlan, ReconcileResult,
};
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct ControlApplyArgs {
    /// Path to the control-plane manifest (YAML or JSON).
    #[arg(long, default_value = "control-manifest.yaml")]
    pub(crate) file: std::path::PathBuf,

    /// Delete remote resources that are not in the manifest.
    /// RISK-008: This is a destructive operation — always review the plan first.
    #[arg(long)]
    pub(crate) prune: bool,

    /// Skip the interactive confirmation prompt.
    #[arg(long)]
    pub(crate) yes: bool,

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
pub(crate) async fn run_async(args: ControlApplyArgs) -> Result<(), CliError> {
    let manifest = control_manifest::load_from_path(&args.file)?;

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

    let plan =
        crate::managed::control_reconcile::compute_plan(&client, &manifest, args.prune).await?;

    if !plan.has_changes() {
        if args.json {
            let empty_result = ReconcileResult::default();
            return print_json(&build_apply_json_summary(&plan, &empty_result, args.prune));
        }
        println!("no changes — control-plane is up to date");
        return Ok(());
    }

    // Print the plan summary.
    if !args.json {
        print!("{}", render_apply_preview(&plan));

        if !args.yes && !confirm_apply(args.prune)? {
            println!("aborted — no changes applied");
            return Ok(());
        }
    }

    let result = crate::managed::control_reconcile::execute_plan(&client, &plan, &manifest).await?;

    if args.json {
        return print_json(&build_apply_json_summary(&plan, &result, args.prune));
    }

    // Human-readable summary.
    let applied = count_applied_ops(&result);
    println!("applied {applied} operation(s)");

    if result.has_failures() {
        for failure in &result.failed {
            eprintln!(
                "  error: {} {} — {}",
                failure.op.resource_type, failure.op.name, failure.error
            );
        }
        return Err(CliError::network(format!(
            "{} operation(s) failed",
            result.failed.len()
        )));
    }

    println!("control-plane reconciled successfully");
    Ok(())
}

/// Prompt the user to approve the apply operation. Returns `true` after user approval.
fn confirm_apply(prune: bool) -> Result<bool, CliError> {
    let stdout = std::io::stdout();
    let stdin = std::io::stdin();
    let mut stdout = stdout.lock();
    let mut stdin = stdin.lock();
    confirm_apply_with_io(prune, &mut stdin, &mut stdout)
}

fn build_apply_json_summary(
    plan: &ReconcilePlan,
    result: &ReconcileResult,
    prune: bool,
) -> serde_json::Value {
    serde_json::json!({
        "applied": !result.has_failures(),
        "prune": prune,
        "summary": {
            "creates": plan.creates(),
            "updates": plan.updates(),
            "deletes": plan.deletions(),
            "no_ops": plan.no_ops(),
        },
        "successful": &result.successful,
        "failed": &result.failed,
    })
}

fn render_apply_preview(plan: &ReconcilePlan) -> String {
    let mut rendered = format!(
        "plan: {} create(s)  {} update(s)  {} delete(s)  {} no-op(s)\n\n",
        plan.creates(),
        plan.updates(),
        plan.deletions(),
        plan.no_ops(),
    );

    for line in plan.ops.iter().filter_map(format_apply_op_line) {
        rendered.push_str(&line);
        rendered.push('\n');
    }

    rendered.push('\n');
    rendered
}

fn format_apply_op_line(op: &ReconcileOp) -> Option<String> {
    if op.action == ReconcileAction::NoOp {
        return None;
    }

    let marker = match op.action {
        ReconcileAction::Create => "+",
        ReconcileAction::Update => "~",
        ReconcileAction::Delete => "-",
        ReconcileAction::NoOp => " ",
    };
    let mut rendered = format!("{marker} {}  {}", op.resource_type, op.name);
    if let Some(detail) = op.detail.as_deref() {
        if is_structured_diff_detail(detail) {
            for line in detail.lines().filter(|line| !line.trim().is_empty()) {
                rendered.push('\n');
                rendered.push_str("    ");
                rendered.push_str(line);
            }
        } else {
            rendered.push_str(&format!("  ({detail})"));
        }
    }
    Some(rendered)
}

fn is_structured_diff_detail(detail: &str) -> bool {
    !detail.is_empty() && detail.lines().all(is_structured_diff_detail_line)
}

fn is_structured_diff_detail_line(line: &str) -> bool {
    line.strip_prefix("+ ")
        .or_else(|| line.strip_prefix("- "))
        .or_else(|| line.strip_prefix("~ "))
        .is_some()
}

fn count_applied_ops(result: &ReconcileResult) -> usize {
    result
        .successful
        .iter()
        .filter(|op| op.action != ReconcileAction::NoOp)
        .count()
}

fn confirm_apply_with_io<R, W>(prune: bool, input: &mut R, output: &mut W) -> Result<bool, CliError>
where
    R: std::io::BufRead,
    W: std::io::Write,
{
    let prompt = if prune {
        "This will create, update, AND DELETE resources listed above.\nType 'yes' to continue: "
    } else {
        "This will create and update resources listed above.\nType 'yes' to continue: "
    };

    output
        .write_all(prompt.as_bytes())
        .map_err(|e| CliError::internal(format!("prompt write failed: {e}")))?;
    output
        .flush()
        .map_err(|e| CliError::internal(format!("flush failed: {e}")))?;

    let mut line = String::new();
    input
        .read_line(&mut line)
        .map_err(|e| CliError::internal(format!("read failed: {e}")))?;

    Ok(line.trim() == "yes")
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
    use crate::managed::control_reconcile::ReconcileOpError;
    use std::io::{self, Cursor, Write};

    fn sample_plan() -> ReconcilePlan {
        ReconcilePlan {
            ops: vec![
                ReconcileOp {
                    resource_type: "agent".to_string(),
                    name: "nightly-bot".to_string(),
                    action: ReconcileAction::NoOp,
                    remote_id: Some("agent-1".to_string()),
                    detail: None,
                },
                ReconcileOp {
                    resource_type: "team".to_string(),
                    name: "platform".to_string(),
                    action: ReconcileAction::Create,
                    remote_id: None,
                    detail: None,
                },
                ReconcileOp {
                    resource_type: "billing_budget".to_string(),
                    name: "monthly-cap".to_string(),
                    action: ReconcileAction::Update,
                    remote_id: Some("budget-1".to_string()),
                    detail: Some("amount=200.00".to_string()),
                },
                ReconcileOp {
                    resource_type: "user".to_string(),
                    name: "alice@example.com".to_string(),
                    action: ReconcileAction::Delete,
                    remote_id: Some("user-1".to_string()),
                    detail: None,
                },
            ],
        }
    }

    #[derive(Default)]
    struct BrokenWriter {
        flush_failed: bool,
    }

    impl Write for BrokenWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flush_failed = true;
            Err(io::Error::other("flush broke"))
        }
    }

    struct BrokenReader;

    impl io::Read for BrokenReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("read broke"))
        }
    }

    impl io::BufRead for BrokenReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Err(io::Error::other("read broke"))
        }

        fn consume(&mut self, _amt: usize) {}
    }

    #[test]
    fn build_apply_json_summary_tracks_failures_and_prune_flag() {
        let plan = sample_plan();
        let result = ReconcileResult {
            successful: vec![
                plan.ops[0].clone(),
                plan.ops[1].clone(),
                plan.ops[2].clone(),
            ],
            failed: vec![ReconcileOpError {
                op: plan.ops[3].clone(),
                error: "delete failed".to_string(),
            }],
        };

        let payload = build_apply_json_summary(&plan, &result, true);

        assert_eq!(payload["applied"], serde_json::json!(false));
        assert_eq!(payload["prune"], serde_json::json!(true));
        assert_eq!(payload["summary"]["creates"], serde_json::json!(1));
        assert_eq!(payload["summary"]["updates"], serde_json::json!(1));
        assert_eq!(payload["summary"]["deletes"], serde_json::json!(1));
        assert_eq!(payload["summary"]["no_ops"], serde_json::json!(1));
        assert_eq!(payload["successful"].as_array().map(Vec::len), Some(3));
        assert_eq!(payload["failed"].as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn render_apply_preview_skips_noops_and_formats_details() {
        let rendered = render_apply_preview(&sample_plan());

        assert!(rendered.starts_with("plan: 1 create(s)  1 update(s)  1 delete(s)  1 no-op(s)"));
        assert!(rendered.contains("+ team  platform"));
        assert!(rendered.contains("~ billing_budget  monthly-cap  (amount=200.00)"));
        assert!(rendered.contains("- user  alice@example.com"));
        assert!(!rendered.contains("nightly-bot"));
    }

    #[test]
    fn count_applied_ops_excludes_noops() {
        let plan = sample_plan();
        let result = ReconcileResult {
            successful: plan.ops.clone(),
            failed: vec![],
        };

        assert_eq!(count_applied_ops(&result), 3);
    }

    #[test]
    fn confirm_apply_with_io_accepts_trimmed_yes() {
        let mut input = Cursor::new(" yes \n");
        let mut output = Vec::new();

        let confirmed = confirm_apply_with_io(false, &mut input, &mut output).unwrap();

        assert!(confirmed);
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "This will create and update resources listed above.\nType 'yes' to continue: "
        );
    }

    #[test]
    fn confirm_apply_with_io_rejects_non_yes_and_uses_prune_prompt() {
        let mut input = Cursor::new("nope\n");
        let mut output = Vec::new();

        let confirmed = confirm_apply_with_io(true, &mut input, &mut output).unwrap();

        assert!(!confirmed);
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "This will create, update, AND DELETE resources listed above.\nType 'yes' to continue: "
        );
    }

    #[test]
    fn confirm_apply_with_io_maps_flush_failures() {
        let mut input = Cursor::new("yes\n");
        let mut output = BrokenWriter::default();

        let error = confirm_apply_with_io(false, &mut input, &mut output).unwrap_err();

        assert!(error.to_string().contains("flush failed"));
        assert!(output.flush_failed);
    }

    #[test]
    fn confirm_apply_with_io_maps_read_failures() {
        let mut input = BrokenReader;
        let mut output = Vec::new();

        let error = confirm_apply_with_io(false, &mut input, &mut output).unwrap_err();

        assert!(error.to_string().contains("read failed"));
    }

    #[test]
    fn format_apply_op_line_noop_returns_none() {
        let op = ReconcileOp {
            resource_type: "agent".to_string(),
            name: "bot".to_string(),
            action: ReconcileAction::NoOp,
            remote_id: Some("a-1".to_string()),
            detail: Some("unchanged".to_string()),
        };
        assert!(format_apply_op_line(&op).is_none());
    }

    #[test]
    fn format_apply_op_line_create_without_detail() {
        let op = ReconcileOp {
            resource_type: "team".to_string(),
            name: "new-team".to_string(),
            action: ReconcileAction::Create,
            remote_id: None,
            detail: None,
        };
        assert_eq!(
            format_apply_op_line(&op),
            Some("+ team  new-team".to_string())
        );
    }

    #[test]
    fn format_apply_op_line_update_with_detail() {
        let op = ReconcileOp {
            resource_type: "budget".to_string(),
            name: "monthly".to_string(),
            action: ReconcileAction::Update,
            remote_id: Some("b-1".to_string()),
            detail: Some("amount=100".to_string()),
        };
        assert_eq!(
            format_apply_op_line(&op),
            Some("~ budget  monthly  (amount=100)".to_string())
        );
    }

    #[test]
    fn format_apply_op_line_renders_structured_agent_diff_details() {
        let op = ReconcileOp {
            resource_type: "agent".to_string(),
            name: "test-agent".to_string(),
            action: ReconcileAction::Update,
            remote_id: Some("agent-1".to_string()),
            detail: Some(
                "~ context_fabric.capture_mode: \"off\" -> \"auto\"\n+ mcp.allowed_tools: [\"context_search\"]"
                    .to_string(),
            ),
        };

        assert_eq!(
            format_apply_op_line(&op),
            Some(
                "~ agent  test-agent\n    ~ context_fabric.capture_mode: \"off\" -> \"auto\"\n    + mcp.allowed_tools: [\"context_search\"]"
                    .to_string(),
            )
        );
    }

    #[test]
    fn format_apply_op_line_delete() {
        let op = ReconcileOp {
            resource_type: "user".to_string(),
            name: "removed@example.com".to_string(),
            action: ReconcileAction::Delete,
            remote_id: Some("u-1".to_string()),
            detail: None,
        };
        assert_eq!(
            format_apply_op_line(&op),
            Some("- user  removed@example.com".to_string())
        );
    }

    #[test]
    fn count_applied_ops_empty_result() {
        let result = ReconcileResult {
            successful: vec![],
            failed: vec![],
        };
        assert_eq!(count_applied_ops(&result), 0);
    }

    #[test]
    fn count_applied_ops_only_noops() {
        let result = ReconcileResult {
            successful: vec![ReconcileOp {
                resource_type: "agent".to_string(),
                name: "bot".to_string(),
                action: ReconcileAction::NoOp,
                remote_id: Some("a-1".to_string()),
                detail: None,
            }],
            failed: vec![],
        };
        assert_eq!(count_applied_ops(&result), 0);
    }

    #[test]
    fn confirm_apply_with_io_empty_input() {
        let mut input = Cursor::new("\n");
        let mut output = Vec::new();
        let confirmed = confirm_apply_with_io(false, &mut input, &mut output).unwrap();
        assert!(!confirmed);
    }

    #[test]
    fn build_apply_json_summary_no_failures() {
        let plan = sample_plan();
        let result = ReconcileResult {
            successful: plan.ops.clone(),
            failed: vec![],
        };
        let payload = build_apply_json_summary(&plan, &result, false);
        assert_eq!(payload["applied"], serde_json::json!(true));
        assert_eq!(payload["prune"], serde_json::json!(false));
    }

    #[test]
    fn args_debug_impl() {
        let args = ControlApplyArgs {
            file: std::path::PathBuf::from("manifest.yaml"),
            prune: true,
            yes: false,
            json: true,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("manifest.yaml"));
        assert!(debug.contains("ControlApplyArgs"));
    }
}
