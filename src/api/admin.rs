// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Phase 6 admin helper utilities: secure secret-source parsing shared across
//! secret create/update commands.
//!
//! # Module wiring
//! Add `#[doc(hidden)] pub mod admin;` to `cli/src/api/mod.rs` to activate.

use std::io::Read;

use crate::error::CliError;
use crate::instances::secrets::SecretReference;

/// A secure source for secret material. Never accepts raw plaintext from a
/// plain CLI flag — only indirect references or an explicit stdin opt-in.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub enum SecretSource {
    /// Read the value from the named environment variable at resolution time.
    EnvVar(String),
    /// Read the value from the macOS keychain entry `service:account`.
    Keychain { service: String, account: String },
    /// Read the value from stdin (user passed `--stdin`).
    Stdin,
}

/// Parse exactly one of `--env-var VAR`, `--keychain service:account`, or
/// `--stdin` into a [`SecretSource`].
///
/// Returns a user-facing error when zero or more than one source is supplied.
#[doc(hidden)]
pub fn parse_secret_source(
    env_var: Option<String>,
    keychain: Option<String>,
    stdin: bool,
) -> Result<SecretSource, CliError> {
    let count = env_var.is_some() as u8 + keychain.is_some() as u8 + stdin as u8;

    if count == 0 {
        return Err(CliError::user(
            "specify exactly one of --env-var, --keychain, or --stdin as the secret source",
        ));
    }
    if count > 1 {
        return Err(CliError::user(
            "only one secret source may be specified (--env-var, --keychain, or --stdin)",
        ));
    }

    if let Some(name) = env_var {
        let valid = !name.trim().is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
        if !valid {
            return Err(CliError::user(format!(
                "invalid env var name '{}': must contain only uppercase ASCII letters, \
                 digits, and underscores",
                name
            )));
        }
        return Ok(SecretSource::EnvVar(name));
    }

    if let Some(kc) = keychain {
        let (service, account) = kc.split_once(':').ok_or_else(|| {
            CliError::user("--keychain value must be in the format 'service:account'")
        })?;
        if service.is_empty() || account.is_empty() {
            return Err(CliError::user(
                "--keychain service and account must both be non-empty",
            ));
        }
        return Ok(SecretSource::Keychain {
            service: service.to_string(),
            account: account.to_string(),
        });
    }

    Ok(SecretSource::Stdin)
}

/// Resolve a [`SecretSource`] to the actual string value.
///
/// For `EnvVar` and `Keychain` sources the value is never echoed back to the
/// user; callers should send it directly to the API over TLS.
#[doc(hidden)]
pub fn resolve_secret_value(source: &SecretSource) -> Result<String, CliError> {
    match source {
        SecretSource::EnvVar(name) => {
            std::env::var(name).map_err(|_| CliError::user(format!("env var {} is not set", name)))
        }

        SecretSource::Keychain { service, account } => {
            let sr = SecretReference::keychain(service, account);
            sr.resolve().ok_or_else(|| {
                CliError::user(format!(
                    "keychain entry '{}/{}' not found or inaccessible",
                    service, account
                ))
            })
        }

        SecretSource::Stdin => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| CliError::internal(format!("failed to read stdin: {e}")))?;
            let value = buf
                .trim_end_matches('\n')
                .trim_end_matches('\r')
                .to_string();
            if value.is_empty() {
                return Err(CliError::user("secret value from stdin must not be empty"));
            }
            Ok(value)
        }
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

    // ── SecretSource Debug ─────────────────────────────────────────────

    #[test]
    fn secret_source_debug_env_var() {
        let src = SecretSource::EnvVar("MY_VAR".to_string());
        let dbg = format!("{src:?}");
        assert!(dbg.contains("EnvVar"));
        assert!(dbg.contains("MY_VAR"));
    }

    #[test]
    fn secret_source_debug_keychain() {
        let src = SecretSource::Keychain {
            service: "svc".to_string(),
            account: "acct".to_string(),
        };
        let dbg = format!("{src:?}");
        assert!(dbg.contains("Keychain"));
    }

    #[test]
    fn secret_source_debug_stdin() {
        let src = SecretSource::Stdin;
        let dbg = format!("{src:?}");
        assert!(dbg.contains("Stdin"));
    }

    #[test]
    fn secret_source_clone() {
        let src = SecretSource::EnvVar("X".to_string());
        let cloned = src.clone();
        assert!(format!("{cloned:?}").contains("EnvVar"));
    }

    // ── parse_secret_source: zero sources ──────────────────────────────

    #[test]
    fn parse_no_sources_returns_error() {
        let result = parse_secret_source(None, None, false);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("exactly one"));
    }

    // ── parse_secret_source: multiple sources ──────────────────────────

    #[test]
    fn parse_env_and_stdin_returns_error() {
        let result = parse_secret_source(Some("VAR".to_string()), None, true);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("only one"));
    }

    #[test]
    fn parse_env_and_keychain_returns_error() {
        let result =
            parse_secret_source(Some("VAR".to_string()), Some("svc:acct".to_string()), false);
        assert!(result.is_err());
    }

    #[test]
    fn parse_keychain_and_stdin_returns_error() {
        let result = parse_secret_source(None, Some("svc:acct".to_string()), true);
        assert!(result.is_err());
    }

    #[test]
    fn parse_all_three_returns_error() {
        let result =
            parse_secret_source(Some("VAR".to_string()), Some("svc:acct".to_string()), true);
        assert!(result.is_err());
    }

    // ── parse_secret_source: valid env var ─────────────────────────────

    #[test]
    fn parse_valid_env_var() {
        let result = parse_secret_source(Some("MY_SECRET_KEY".to_string()), None, false);
        let src = result.unwrap();
        assert!(matches!(src, SecretSource::EnvVar(ref name) if name == "MY_SECRET_KEY"));
    }

    #[test]
    fn parse_env_var_with_digits() {
        let result = parse_secret_source(Some("VAR_123".to_string()), None, false);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_env_var_single_char() {
        let result = parse_secret_source(Some("X".to_string()), None, false);
        assert!(result.is_ok());
    }

    // ── parse_secret_source: invalid env var ───────────────────────────

    #[test]
    fn parse_env_var_empty_string_returns_error() {
        let result = parse_secret_source(Some("".to_string()), None, false);
        assert!(result.is_err());
    }

    #[test]
    fn parse_env_var_whitespace_only_returns_error() {
        let result = parse_secret_source(Some("  ".to_string()), None, false);
        assert!(result.is_err());
    }

    #[test]
    fn parse_env_var_lowercase_returns_error() {
        let result = parse_secret_source(Some("my_var".to_string()), None, false);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("uppercase"));
    }

    #[test]
    fn parse_env_var_with_dash_returns_error() {
        let result = parse_secret_source(Some("MY-VAR".to_string()), None, false);
        assert!(result.is_err());
    }

    #[test]
    fn parse_env_var_with_space_returns_error() {
        let result = parse_secret_source(Some("MY VAR".to_string()), None, false);
        assert!(result.is_err());
    }

    // ── parse_secret_source: valid keychain ────────────────────────────

    #[test]
    fn parse_valid_keychain() {
        let result = parse_secret_source(None, Some("myservice:myaccount".to_string()), false);
        let src = result.unwrap();
        match src {
            SecretSource::Keychain { service, account } => {
                assert_eq!(service, "myservice");
                assert_eq!(account, "myaccount");
            }
            _ => panic!("expected Keychain variant"),
        }
    }

    #[test]
    fn parse_keychain_with_multiple_colons() {
        let result = parse_secret_source(None, Some("svc:acct:extra".to_string()), false);
        let src = result.unwrap();
        match src {
            SecretSource::Keychain { service, account } => {
                assert_eq!(service, "svc");
                assert_eq!(account, "acct:extra");
            }
            _ => panic!("expected Keychain variant"),
        }
    }

    // ── parse_secret_source: invalid keychain ──────────────────────────

    #[test]
    fn parse_keychain_no_colon_returns_error() {
        let result = parse_secret_source(None, Some("nocolon".to_string()), false);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("service:account"));
    }

    #[test]
    fn parse_keychain_empty_service_returns_error() {
        let result = parse_secret_source(None, Some(":account".to_string()), false);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("non-empty"));
    }

    #[test]
    fn parse_keychain_empty_account_returns_error() {
        let result = parse_secret_source(None, Some("service:".to_string()), false);
        assert!(result.is_err());
    }

    #[test]
    fn parse_keychain_both_empty_returns_error() {
        let result = parse_secret_source(None, Some(":".to_string()), false);
        assert!(result.is_err());
    }

    // ── parse_secret_source: stdin ─────────────────────────────────────

    #[test]
    fn parse_stdin_returns_stdin_variant() {
        let result = parse_secret_source(None, None, true);
        let src = result.unwrap();
        assert!(matches!(src, SecretSource::Stdin));
    }

    // ── resolve_secret_value: env var path ─────────────────────────────

    #[test]
    fn resolve_env_var_reads_from_environment() {
        let _guard = crate::config::test_env_lock().lock().unwrap();
        let var_name = "VERDICTAN_TEST_SECRET_RESOLVE_ADMIN";
        std::env::set_var(var_name, "s3cret!");
        let src = SecretSource::EnvVar(var_name.to_string());
        let val = resolve_secret_value(&src).unwrap();
        assert_eq!(val, "s3cret!");
        std::env::remove_var(var_name);
    }

    #[test]
    fn resolve_env_var_missing_returns_error() {
        let _guard = crate::config::test_env_lock().lock().unwrap();
        let var_name = "VERDICTAN_TEST_SECRET_RESOLVE_MISSING_8374";
        std::env::remove_var(var_name);
        let src = SecretSource::EnvVar(var_name.to_string());
        let result = resolve_secret_value(&src);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains(var_name));
    }
}
