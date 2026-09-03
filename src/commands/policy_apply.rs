// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;

use crate::commands::policy_common::{
    build_apply_json_summary, build_policy_manifest, confirm_apply, count_applied_ops,
    filter_policy_plan, load_policy_specs_from_path, render_apply_preview, resolve_client,
    PolicyApiArgs,
};
use crate::error::CliError;
use crate::managed::control_reconcile::ReconcileResult;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct PolicyApplyArgs {
    /// Path to a policy document or policy bundle (YAML or JSON).
    #[arg(long)]
    pub(crate) file: std::path::PathBuf,

    /// Delete remote policies that are not in the file.
    #[arg(long)]
    pub(crate) prune: bool,

    /// Skip the interactive confirmation prompt.
    #[arg(long)]
    pub(crate) yes: bool,

    /// Emit machine-readable JSON to stdout.
    #[arg(long)]
    pub(crate) json: bool,

    #[command(flatten)]
    pub(crate) api: PolicyApiArgs,
}

pub(crate) async fn run_async(args: PolicyApplyArgs) -> Result<(), CliError> {
    let policies = load_policy_specs_from_path(&args.file)?;
    let manifest = build_policy_manifest(&policies);
    let client = resolve_client(&args.api)?;
    let plan =
        crate::managed::control_reconcile::compute_iam_policy_plan(&client, &policies, args.prune)
            .await?;
    let plan = filter_policy_plan(&plan);

    if !plan.has_changes() {
        if args.json {
            return print_json(&build_apply_json_summary(
                &plan,
                &ReconcileResult::default(),
                args.prune,
            ));
        }
        println!("no changes — policies are up to date");
        return Ok(());
    }

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

    println!("policies reconciled successfully");
    Ok(())
}
