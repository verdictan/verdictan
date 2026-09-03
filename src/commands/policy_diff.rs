// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;

use crate::commands::policy_common::{
    build_plan_json, filter_policy_plan, load_policy_specs_from_path, render_plan_text,
    resolve_client, PolicyApiArgs,
};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct PolicyDiffArgs {
    /// Path to a policy document or policy bundle (YAML or JSON).
    #[arg(long)]
    pub(crate) file: std::path::PathBuf,

    /// Include delete operations for remote policies that are not in the file.
    #[arg(long)]
    pub(crate) prune: bool,

    /// Emit machine-readable JSON to stdout.
    #[arg(long)]
    pub(crate) json: bool,

    #[command(flatten)]
    pub(crate) api: PolicyApiArgs,
}

pub(crate) async fn run_async(args: PolicyDiffArgs) -> Result<(), CliError> {
    let policies = load_policy_specs_from_path(&args.file)?;
    let client = resolve_client(&args.api)?;
    let plan =
        crate::managed::control_reconcile::compute_iam_policy_plan(&client, &policies, args.prune)
            .await?;
    let plan = filter_policy_plan(&plan);

    if args.json {
        return print_json(&build_plan_json(&plan, args.prune));
    }

    print!(
        "{}",
        render_plan_text(
            &plan,
            "(dry-run — no changes applied; run `verdictan policy apply` to reconcile)",
        )
    );
    Ok(())
}
