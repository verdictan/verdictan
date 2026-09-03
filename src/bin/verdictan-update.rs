// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Companion updater for shell and PowerShell installs.
//!
//! Runs axoupdater after refusing service-managed installs tracked in supervisor state.

use axoupdater::AxoUpdater;

fn main() {
    if let Err(err) = verdictan::self_update::guard_supervisor_managed_install() {
        eprintln!("{err}");
        std::process::exit(err.exit_code());
    }

    if let Some(manifest_url) = std::env::var("VERDICTAN_UPDATE_MANIFEST_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        if let Err(err) = run_signed_update(manifest_url) {
            eprintln!("update failed: {err}");
            std::process::exit(2);
        }
        return;
    }

    let mut updater = match AxoUpdater::new_for_updater_executable() {
        Ok(updater) => updater,
        Err(err) => {
            eprintln!("failed to initialize updater: {err}");
            std::process::exit(2);
        }
    };

    if let Err(err) = updater.load_receipt() {
        eprintln!("failed to load install receipt: {err}");
        std::process::exit(2);
    }

    match updater.run_sync() {
        Ok(Some(_)) => {
            eprintln!("Update installed.");
        }
        Ok(None) => {
            eprintln!("verdictan is already up to date.");
        }
        Err(err) => {
            eprintln!("update failed: {err}");
            std::process::exit(2);
        }
    }
}

fn run_signed_update(manifest_url: String) -> Result<(), Box<dyn std::error::Error>> {
    use verdictan::self_update::{apply_signed_update, SignedUpdateOptions, SignedUpdateOutcome};

    let public_key_base64 = std::env::var("VERDICTAN_UPDATE_PUBLIC_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "VERDICTAN_UPDATE_PUBLIC_KEY is required for signed updates",
            )
        })?;
    #[cfg(verdictan_cli_e2e)]
    let current_version = std::env::var("VERDICTAN_TEST_UPDATE_CURRENT_VERSION")
        .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string());
    #[cfg(not(verdictan_cli_e2e))]
    let current_version = env!("CARGO_PKG_VERSION").to_string();
    #[cfg(verdictan_cli_e2e)]
    let target_path = std::env::var_os("VERDICTAN_TEST_UPDATE_TARGET")
        .map(std::path::PathBuf::from)
        .unwrap_or(signed_update_target_path()?);
    #[cfg(not(verdictan_cli_e2e))]
    let target_path = signed_update_target_path()?;
    let allow_downgrade = std::env::var("VERDICTAN_UPDATE_ALLOW_DOWNGRADE")
        .ok()
        .is_some_and(|value| matches!(value.trim(), "1" | "true" | "yes"));
    let options = SignedUpdateOptions {
        manifest_url,
        public_key_base64,
        current_version,
        target_path,
        allow_downgrade,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| std::io::Error::other(format!("failed to initialize signed updater: {e}")))?;
    match runtime.block_on(apply_signed_update(&options))? {
        SignedUpdateOutcome::AlreadyCurrent => eprintln!("verdictan is already up to date."),
        SignedUpdateOutcome::Updated { version } => {
            eprintln!("Update {version} installed.");
        }
    }
    Ok(())
}

fn signed_update_target_path() -> Result<std::path::PathBuf, std::io::Error> {
    let updater = std::env::current_exe()?;
    let parent = updater
        .parent()
        .ok_or_else(|| std::io::Error::other("updater executable has no parent directory"))?;
    let executable = if cfg!(windows) {
        "verdictan.exe"
    } else {
        "verdictan"
    };
    Ok(parent.join(executable))
}
