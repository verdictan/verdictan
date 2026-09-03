// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan secrets add` — add a secret to the local keychain.
//!
//! Stores credentials in the local platform keychain (macOS keychain on macOS).
//! Secret values are read interactively from stdin with echo disabled.

use clap::Args;

use crate::error::CliError;

const KEYCHAIN_ACCOUNT: &str = "verdictan";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeychainStorageError {
    UnsupportedPlatform,
    /// The macOS Security.framework write path and test storage doubles return
    /// this error. Non-macOS production builds do not use it.
    #[allow(dead_code)]
    WriteFailed,
}

trait KeychainStorage {
    fn set_generic_password(
        &self,
        service: &str,
        account: &str,
        password: &[u8],
    ) -> Result<(), KeychainStorageError>;
}

struct NativeKeychainStorage;

impl KeychainStorage for NativeKeychainStorage {
    fn set_generic_password(
        &self,
        service: &str,
        account: &str,
        password: &[u8],
    ) -> Result<(), KeychainStorageError> {
        #[cfg(target_os = "macos")]
        {
            security_framework::passwords::set_generic_password(service, account, password)
                .map_err(|_| KeychainStorageError::WriteFailed)
        }

        #[cfg(not(target_os = "macos"))]
        {
            let _ = (service, account, password);
            Err(KeychainStorageError::UnsupportedPlatform)
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct SecretsAddArgs {
    /// Secret name (for example, OPENAI_API_KEY)
    pub name: String,

    /// Select the keychain backend. At this time, it is the only backend.
    /// This option supports forward compatibility.
    #[arg(long)]
    pub keychain: bool,
}

pub(crate) fn run(args: SecretsAddArgs) -> Result<(), CliError> {
    let _ = args.keychain;

    // Validate name format: alphanumeric + underscores, starting with letter or underscore.
    if !is_valid_secret_name(&args.name) {
        return Err(CliError::user(format!(
            "invalid secret name '{}': must contain only A-Z, a-z, 0-9, _ and start with a letter or underscore",
            args.name
        )));
    }

    // Read secret value interactively (no echo).
    let value = read_secret_value(&args.name)?;

    store_in_keychain(&args.name, &value)?;
    println!("Secret '{}' stored successfully in keychain", args.name);

    Ok(())
}

/// Validate that a secret name contains only safe characters (A-Z, a-z, 0-9, _)
/// and starts with a letter or underscore.
fn is_valid_secret_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let first = name.as_bytes()[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Read a secret value from stdin with echo disabled.
fn read_secret_value(name: &str) -> Result<String, CliError> {
    use std::io::{self, BufRead, IsTerminal};

    if io::stdin().is_terminal() {
        eprint!("Enter value for {}: ", name);

        // Disable echo for secure input using raw terminal manipulation.
        let value = read_password_from_terminal()?;
        eprintln!(); // newline after hidden input
        if value.is_empty() {
            return Err(CliError::user("secret value cannot be empty"));
        }
        Ok(value)
    } else {
        // Non-interactive: read a single line from piped stdin.
        let mut line = String::new();
        io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| CliError::internal(format!("failed to read from stdin: {e}")))?;
        let value = line
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_string();
        if value.is_empty() {
            return Err(CliError::user("secret value cannot be empty"));
        }
        Ok(value)
    }
}

/// Read a password from the terminal with echo disabled (Unix).
fn read_password_from_terminal() -> Result<String, CliError> {
    #[cfg(unix)]
    {
        use std::io::{self, BufRead};

        // Disable echo via stty.
        let stty_off = std::process::Command::new("stty")
            .arg("-echo")
            .stdin(std::process::Stdio::inherit())
            .status();

        if let Err(e) = stty_off {
            return Err(CliError::internal(format!("failed to disable echo: {e}")));
        }

        // Read input.
        let mut buf = String::new();
        let result = io::stdin().lock().read_line(&mut buf);

        // Restore echo (always, even on read error).
        let _ = std::process::Command::new("stty")
            .arg("echo")
            .stdin(std::process::Stdio::inherit())
            .status();

        result.map_err(|e| CliError::internal(format!("failed to read from stdin: {e}")))?;
        Ok(buf
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_string())
    }

    #[cfg(not(unix))]
    {
        use std::io::{self, BufRead};
        let mut line = String::new();
        io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| CliError::internal(format!("failed to read from stdin: {e}")))?;
        Ok(line
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_string())
    }
}

/// Store a secret in the macOS keychain through Security.framework.
fn store_in_keychain(name: &str, value: &str) -> Result<(), CliError> {
    store_in_keychain_with(&NativeKeychainStorage, name, value)
}

fn store_in_keychain_with(
    storage: &dyn KeychainStorage,
    name: &str,
    value: &str,
) -> Result<(), CliError> {
    match storage.set_generic_password(name, KEYCHAIN_ACCOUNT, value.as_bytes()) {
        Ok(()) => Ok(()),
        Err(KeychainStorageError::UnsupportedPlatform) => Err(CliError::user(
            "keychain storage is only available on macOS",
        )),
        Err(KeychainStorageError::WriteFailed) => Err(CliError::internal(
            "failed to store secret in macOS keychain",
        )),
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
    use std::cell::RefCell;

    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    struct RecordedKeychainWrite {
        service: String,
        account: String,
        password: Vec<u8>,
    }

    #[derive(Debug)]
    struct RecordingKeychainStorage {
        result: Result<(), KeychainStorageError>,
        writes: RefCell<Vec<RecordedKeychainWrite>>,
    }

    impl RecordingKeychainStorage {
        fn succeeding() -> Self {
            Self {
                result: Ok(()),
                writes: RefCell::new(Vec::new()),
            }
        }

        fn failing() -> Self {
            Self {
                result: Err(KeychainStorageError::WriteFailed),
                writes: RefCell::new(Vec::new()),
            }
        }
    }

    impl KeychainStorage for RecordingKeychainStorage {
        fn set_generic_password(
            &self,
            service: &str,
            account: &str,
            password: &[u8],
        ) -> Result<(), KeychainStorageError> {
            self.writes.borrow_mut().push(RecordedKeychainWrite {
                service: service.to_string(),
                account: account.to_string(),
                password: password.to_vec(),
            });
            self.result
        }
    }

    #[test]
    fn injected_native_storage_receives_secret_only_as_password_data() {
        let storage = RecordingKeychainStorage::succeeding();
        let secret = "lane-042-secret-sentinel";

        store_in_keychain_with(&storage, "OPENAI_API_KEY", secret)
            .expect("injected keychain write should succeed");

        assert_eq!(
            storage.writes.into_inner(),
            vec![RecordedKeychainWrite {
                service: "OPENAI_API_KEY".to_string(),
                account: KEYCHAIN_ACCOUNT.to_string(),
                password: secret.as_bytes().to_vec(),
            }]
        );
    }

    #[test]
    fn injected_storage_failure_diagnostic_does_not_leak_secret() {
        let storage = RecordingKeychainStorage::failing();
        let secret = "lane-042-diagnostic-value-fixture";

        let diagnostic = store_in_keychain_with(&storage, "OPENAI_API_KEY", secret)
            .expect_err("injected keychain failure should be reported")
            .to_string();

        assert_eq!(
            diagnostic,
            "Internal error: failed to store secret in macOS keychain"
        );
        assert!(!diagnostic.contains(secret));
    }

    #[test]
    fn native_keychain_path_has_no_argv_environment_or_log_channels() {
        let source = include_str!("secrets_add.rs");
        let implementation_start = source
            .find("impl KeychainStorage for NativeKeychainStorage")
            .expect("native keychain implementation");
        let implementation_end = source[implementation_start..]
            .find("#[derive(Debug, Args)]")
            .map(|offset| implementation_start + offset)
            .expect("end of native keychain implementation");
        let implementation = &source[implementation_start..implementation_end];
        let storage_path_start = source
            .find("fn store_in_keychain(name:")
            .expect("keychain storage path");
        let storage_path_end = source[storage_path_start..]
            .find("#[cfg(test)]")
            .map(|offset| storage_path_start + offset)
            .expect("end of keychain storage path");
        let storage_path = &source[storage_path_start..storage_path_end];

        for path in [implementation, storage_path] {
            for forbidden in [
                "std::process",
                "Command::new",
                ".arg(",
                ".args(",
                ".env(",
                "tracing::",
                "println!",
                "eprintln!",
                "dbg!",
                "format!",
            ] {
                assert!(
                    !path.contains(forbidden),
                    "native keychain storage path must not contain side channel {forbidden}"
                );
            }
        }
        assert!(implementation.contains(
            "security_framework::passwords::set_generic_password(service, account, password)"
        ));
    }

    #[test]
    fn command_helper_coverage_is_valid_secret_name_enforces_charset() {
        assert!(is_valid_secret_name("OPENAI_API_KEY"));
        assert!(is_valid_secret_name("_PRIVATE_KEY"));
        assert!(is_valid_secret_name("Key123"));

        assert!(!is_valid_secret_name(""));
        assert!(!is_valid_secret_name("1starts_with_digit"));
        assert!(!is_valid_secret_name("has-dash"));
        assert!(!is_valid_secret_name("has space"));
    }

    #[test]
    fn command_helper_coverage_run_rejects_invalid_secret_names() {
        let error = run(SecretsAddArgs {
            name: "bad-name".to_string(),
            keychain: false,
        })
        .expect_err("invalid name should fail");
        assert!(error.to_string().contains("invalid secret name"));
    }

    #[test]
    fn is_valid_secret_name_boundary_cases() {
        assert!(is_valid_secret_name("A"));
        assert!(is_valid_secret_name("_"));
        assert!(is_valid_secret_name("ABC_DEF_123"));
        assert!(!is_valid_secret_name("123ABC"));
        assert!(!is_valid_secret_name(".dotted"));
        assert!(!is_valid_secret_name("with.dot"));
        assert!(!is_valid_secret_name("slash/name"));
    }

    #[test]
    fn run_rejects_empty_secret_name() {
        let error = run(SecretsAddArgs {
            name: "".to_string(),
            keychain: false,
        })
        .expect_err("empty name should fail");
        assert!(error.to_string().contains("invalid secret name"));
    }
}
