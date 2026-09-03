// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan control plan` — show a dry-run diff of a control-plane manifest.
//!
//! Reads a manifest file, computes the reconcile plan against the current
//! remote state, and prints the expected operations **without mutating anything**.
//!
//! # Usage
//!
//! ```text
//! verdictan control plan --file control-manifest.yaml [--prune] [--json]
//! ```
//!
//! # Module wiring
//! Add `pub(crate) mod control_plan;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::managed::control_manifest;
use crate::managed::control_reconcile::{ReconcileAction, ReconcileOp, ReconcilePlan};
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct ControlPlanArgs {
    /// Path to the control-plane manifest (YAML or JSON).
    #[arg(long, default_value = "control-manifest.yaml")]
    pub(crate) file: std::path::PathBuf,

    /// Include delete operations for remote resources that are not in the manifest.
    #[arg(long)]
    pub(crate) prune: bool,

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
pub(crate) async fn run_async(args: ControlPlanArgs) -> Result<(), CliError> {
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

    if args.json {
        return print_json(&build_plan_json(&plan, args.prune));
    }

    print!("{}", render_plan_text(&plan));
    Ok(())
}

fn build_plan_json(plan: &ReconcilePlan, prune: bool) -> serde_json::Value {
    serde_json::json!({
        "dry_run": true,
        "prune": prune,
        "summary": {
            "creates": plan.creates(),
            "updates": plan.updates(),
            "deletes": plan.deletions(),
            "no_ops": plan.no_ops(),
        },
        "ops": &plan.ops,
    })
}

fn render_plan_text(plan: &ReconcilePlan) -> String {
    if !plan.has_changes() {
        return "no changes — control-plane is up to date\n".to_string();
    }

    let mut rendered = format!(
        "plan: {} create(s)  {} update(s)  {} delete(s)  {} no-op(s)\n\n",
        plan.creates(),
        plan.updates(),
        plan.deletions(),
        plan.no_ops(),
    );

    for line in plan.ops.iter().filter_map(format_plan_op_line) {
        rendered.push_str(&line);
        rendered.push('\n');
    }

    rendered.push('\n');
    rendered
        .push_str("(dry-run — no changes applied; run `verdictan control apply` to reconcile)\n");
    rendered
}

fn format_plan_op_line(op: &ReconcileOp) -> Option<String> {
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

    fn sample_plan() -> ReconcilePlan {
        ReconcilePlan {
            ops: vec![
                ReconcileOp {
                    resource_type: "agent".to_string(),
                    name: "nightly-bot".to_string(),
                    action: ReconcileAction::NoOp,
                    remote_id: Some("agent-1".to_string()),
                    detail: Some("unchanged".to_string()),
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

    #[test]
    fn build_plan_json_counts_actions_and_preserves_ops() {
        let plan = sample_plan();

        let payload = build_plan_json(&plan, true);

        assert_eq!(payload["dry_run"], serde_json::json!(true));
        assert_eq!(payload["prune"], serde_json::json!(true));
        assert_eq!(payload["summary"]["creates"], serde_json::json!(1));
        assert_eq!(payload["summary"]["updates"], serde_json::json!(1));
        assert_eq!(payload["summary"]["deletes"], serde_json::json!(1));
        assert_eq!(payload["summary"]["no_ops"], serde_json::json!(1));
        assert_eq!(payload["ops"].as_array().map(Vec::len), Some(4));
    }

    #[test]
    fn render_plan_text_skips_noops_and_formats_markers() {
        let rendered = render_plan_text(&sample_plan());

        assert!(rendered.starts_with("plan: 1 create(s)  1 update(s)  1 delete(s)  1 no-op(s)"));
        assert!(rendered.contains("+ team  platform"));
        assert!(rendered.contains("~ billing_budget  monthly-cap  (amount=200.00)"));
        assert!(rendered.contains("- user  alice@example.com"));
        assert!(!rendered.contains("nightly-bot"));
        assert!(rendered.contains(
            "(dry-run — no changes applied; run `verdictan control apply` to reconcile)"
        ));
    }

    #[test]
    fn render_plan_text_reports_up_to_date_when_only_noops_exist() {
        let rendered = render_plan_text(&ReconcilePlan {
            ops: vec![ReconcileOp {
                resource_type: "agent".to_string(),
                name: "nightly-bot".to_string(),
                action: ReconcileAction::NoOp,
                remote_id: Some("agent-1".to_string()),
                detail: None,
            }],
        });

        assert_eq!(rendered, "no changes — control-plane is up to date\n");
    }

    #[test]
    fn render_plan_text_empty_ops() {
        let rendered = render_plan_text(&ReconcilePlan { ops: vec![] });
        assert_eq!(rendered, "no changes — control-plane is up to date\n");
    }

    #[test]
    fn build_plan_json_prune_false() {
        let plan = ReconcilePlan { ops: vec![] };
        let payload = build_plan_json(&plan, false);
        assert_eq!(payload["dry_run"], serde_json::json!(true));
        assert_eq!(payload["prune"], serde_json::json!(false));
        assert_eq!(payload["summary"]["creates"], serde_json::json!(0));
    }

    #[test]
    fn format_plan_op_line_noop_returns_none() {
        let op = ReconcileOp {
            resource_type: "agent".to_string(),
            name: "bot".to_string(),
            action: ReconcileAction::NoOp,
            remote_id: None,
            detail: Some("ignored".to_string()),
        };
        assert!(format_plan_op_line(&op).is_none());
    }

    #[test]
    fn format_plan_op_line_create_without_detail() {
        let op = ReconcileOp {
            resource_type: "team".to_string(),
            name: "new-team".to_string(),
            action: ReconcileAction::Create,
            remote_id: None,
            detail: None,
        };
        assert_eq!(
            format_plan_op_line(&op),
            Some("+ team  new-team".to_string())
        );
    }

    #[test]
    fn format_plan_op_line_delete_with_detail() {
        let op = ReconcileOp {
            resource_type: "user".to_string(),
            name: "old@example.com".to_string(),
            action: ReconcileAction::Delete,
            remote_id: Some("user-1".to_string()),
            detail: Some("stale".to_string()),
        };
        assert_eq!(
            format_plan_op_line(&op),
            Some("- user  old@example.com  (stale)".to_string())
        );
    }

    #[test]
    fn format_plan_op_line_renders_structured_agent_diff_details() {
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
            format_plan_op_line(&op),
            Some(
                "~ agent  test-agent\n    ~ context_fabric.capture_mode: \"off\" -> \"auto\"\n    + mcp.allowed_tools: [\"context_search\"]"
                    .to_string(),
            )
        );
    }

    #[test]
    fn args_debug_impl() {
        let args = ControlPlanArgs {
            file: std::path::PathBuf::from("manifest.yaml"),
            prune: true,
            json: false,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("manifest.yaml"));
        assert!(debug.contains("true"));
    }
}
