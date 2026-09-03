// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan secrets status` — report credential resolution status.
//!
//! Loads the policy config and checks whether each provider target's
//! secret_key_ref can be resolved. Prints a summary table.
//! Secret values are NEVER printed.

use clap::Args;

use crate::error::CliError;
use crate::gateway::declarative_config::LoadedDeclarativeConfig;

#[derive(Debug, Args)]
pub(crate) struct SecretsStatusArgs {
    /// Path to the policy config file.
    #[arg(long, default_value = "policy-config.yaml")]
    pub config: String,
}

pub(crate) fn run(args: SecretsStatusArgs) -> Result<(), CliError> {
    let config_path = std::path::Path::new(&args.config);
    if !config_path.exists() {
        return Err(CliError::user(format!(
            "config file not found: {}",
            args.config
        )));
    }

    let loaded = LoadedDeclarativeConfig::from_path(config_path)?;

    let registry = match &loaded.provider_registry {
        Some(r) => r,
        None => {
            println!("No providers section found in config.");
            return Ok(());
        }
    };

    if registry.targets.is_empty() {
        println!("No provider targets defined.");
        return Ok(());
    }

    // Print header.
    println!(
        "{:<24} {:<24} {:<10} Status",
        "Provider ID", "Secret Ref", "Type"
    );
    println!("{}", "-".repeat(72));

    let mut has_missing = false;
    for target in &registry.targets {
        let (ref_name, ref_type, status) = match &target.secret_key_ref {
            Some(skr) => resolve_status(skr),
            None => {
                if target.api_key.is_empty() && target.requires_resolved_api_key() {
                    has_missing = true;
                    (
                        "(none)".to_string(),
                        "-".to_string(),
                        "\u{2717} missing".to_string(),
                    )
                } else {
                    (
                        "(inline)".to_string(),
                        "-".to_string(),
                        "\u{2713} configured".to_string(),
                    )
                }
            }
        };

        if status.contains('\u{2717}') {
            has_missing = true;
        }

        println!(
            "{:<24} {:<24} {:<10} {}",
            truncate(&target.id, 23),
            truncate(&ref_name, 23),
            ref_type,
            status,
        );
    }

    if has_missing {
        return Err(CliError::user(
            "one or more provider secrets are missing or unresolved",
        ));
    }
    Ok(())
}

/// Resolve the status of a SecretKeyReference without displaying the secret value.
fn resolve_status(skr: &crate::secret_key_ref::SecretKeyReference) -> (String, String, String) {
    if let Some(env_name) = &skr.env {
        let status = if std::env::var(env_name).is_ok() {
            "\u{2713} configured".to_string()
        } else {
            "\u{2717} missing".to_string()
        };
        (env_name.clone(), "env".to_string(), status)
    } else if let Some(store_name) = &skr.store {
        // Store resolution requires API connectivity — report as "store" type.
        (
            store_name.clone(),
            "store".to_string(),
            "? (store)".to_string(),
        )
    } else if let Some(keychain_ref) = &skr.keychain {
        let status = check_keychain_entry(keychain_ref);
        (keychain_ref.clone(), "keychain".to_string(), status)
    } else {
        (
            "(empty)".to_string(),
            "-".to_string(),
            "\u{2717} unconfigured".to_string(),
        )
    }
}

/// Verify that a keychain entry is available (macOS only).
///
/// Uses Security.framework. Process argv and diagnostics do not contain secret
/// material. The result reports only availability.
fn check_keychain_entry(name: &str) -> String {
    #[cfg(target_os = "macos")]
    {
        match security_framework::passwords::get_generic_password(name, "verdictan") {
            Ok(_) => "\u{2713} configured".to_string(),
            Err(_) => "\u{2717} missing".to_string(),
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = name;
        "? (keychain unsupported)".to_string()
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
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
    use crate::secret_key_ref::SecretKeyReference;

    #[test]
    fn command_helper_coverage_resolve_status_reports_store_and_keychain() {
        let store = resolve_status(&SecretKeyReference {
            env: None,
            store: Some("vault/prod".to_string()),
            scope: None,
            keychain: None,
        });
        assert_eq!(store.1, "store");
        assert_eq!(store.2, "? (store)");

        let keychain = resolve_status(&SecretKeyReference {
            env: None,
            store: None,
            scope: None,
            keychain: Some("OPENAI_API_KEY".to_string()),
        });
        assert_eq!(keychain.1, "keychain");
        #[cfg(not(target_os = "macos"))]
        assert_eq!(keychain.2, "? (keychain unsupported)");
    }

    #[test]
    fn command_helper_coverage_resolve_status_marks_empty_reference_unconfigured() {
        let status = resolve_status(&SecretKeyReference {
            env: None,
            store: None,
            scope: None,
            keychain: None,
        });
        assert_eq!(status.0, "(empty)");
        assert!(status.2.contains("unconfigured"));
    }

    #[test]
    fn command_helper_coverage_truncate_preserves_short_strings() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("0123456789abcdef", 10), "012345678…");
    }

    #[test]
    fn command_helper_coverage_run_reports_missing_config_file() {
        let error = run(SecretsStatusArgs {
            config: "missing-policy-config.yaml".to_string(),
        })
        .expect_err("missing config should fail");
        assert!(error.to_string().contains("config file not found"));
    }

    #[test]
    fn native_keychain_status_path_has_no_argv_environment_or_log_channels() {
        let source = include_str!("secrets_status.rs");
        let start = source
            .find("fn check_keychain_entry(name: &str)")
            .expect("check_keychain_entry");
        let end = source[start..]
            .find("fn truncate(")
            .map(|offset| start + offset)
            .expect("end of check_keychain_entry");
        let path = &source[start..end];

        let forbidden_cli = format!("/usr/bin/{}", "security");
        for forbidden in [
            forbidden_cli.as_str(),
            "std::process",
            "Command::new",
            ".arg(",
            ".args(",
            ".env(",
            "tracing::",
            "println!",
            "eprintln!",
            "dbg!",
        ] {
            assert!(
                !path.contains(forbidden),
                "native keychain status path must not contain side channel {forbidden}"
            );
        }
        assert!(path.contains("security_framework::passwords::get_generic_password"));
    }
}
