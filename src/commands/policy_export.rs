// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;

use crate::commands::policy_common::{
    fetch_remote_policies, remote_policies_to_specs, resolve_client, write_policy_specs_to_path,
    PolicyApiArgs, PolicyFileFormat, PolicyRemoteSelectorArgs,
};
use crate::error::CliError;

#[derive(Debug, Args)]
pub(crate) struct PolicyExportArgs {
    /// Destination path for the exported policy document(s).
    #[arg(long)]
    pub(crate) file: std::path::PathBuf,

    /// Override the output format (`json` or `yaml`).
    #[arg(long)]
    pub(crate) format: Option<String>,

    #[command(flatten)]
    pub(crate) selectors: PolicyRemoteSelectorArgs,

    #[command(flatten)]
    pub(crate) api: PolicyApiArgs,
}

pub(crate) async fn run_async(args: PolicyExportArgs) -> Result<(), CliError> {
    let client = resolve_client(&args.api)?;
    let remote = fetch_remote_policies(&client).await?;
    let policies = remote_policies_to_specs(&remote, &args.selectors)?;
    if policies.is_empty() {
        return Err(CliError::user(
            "no policies matched the export selection; pass --policy-id, --name, or omit selectors to export all",
        ));
    }

    let format = args
        .format
        .as_deref()
        .map(PolicyFileFormat::parse)
        .transpose()?;
    write_policy_specs_to_path(&args.file, &policies, format)?;
    println!(
        "exported {} policy document(s) to {}",
        policies.len(),
        args.file.display()
    );
    Ok(())
}
