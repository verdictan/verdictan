// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

#![allow(clippy::items_after_test_module)]

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecretReference {
    EnvVar { name: String },
    Keychain { service: String, account: String },
}

impl SecretReference {
    pub fn env_var(name: impl Into<String>) -> Self {
        Self::EnvVar { name: name.into() }
    }

    pub fn keychain(service: impl Into<String>, account: impl Into<String>) -> Self {
        Self::Keychain {
            service: service.into(),
            account: account.into(),
        }
    }

    pub fn validate(&self) -> Result<(), crate::error::CliError> {
        match self {
            SecretReference::EnvVar { name } => {
                let trimmed = name.trim();
                let valid = !trimmed.is_empty()
                    && trimmed
                        .chars()
                        .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_');
                if valid {
                    Ok(())
                } else {
                    Err(crate::error::CliError::user(format!(
                        "secret env var reference {} is invalid",
                        name
                    )))
                }
            }
            SecretReference::Keychain { service, account } => {
                let valid = !service.trim().is_empty() && !account.trim().is_empty();
                if valid {
                    Ok(())
                } else {
                    Err(crate::error::CliError::user(
                        "keychain secret references require non-empty service and account",
                    ))
                }
            }
        }
    }

    #[allow(dead_code)]
    pub fn resolve(&self) -> Option<String> {
        match self {
            SecretReference::EnvVar { name } => std::env::var(name).ok(),
            SecretReference::Keychain { service, account } => {
                resolve_keychain_secret(service, account)
            }
        }
    }

    #[allow(dead_code)]
    fn display_value(&self) -> String {
        match self {
            SecretReference::EnvVar { name } => format!("env:{}", name),
            SecretReference::Keychain { service, account } => {
                format!("keychain:{}:{}", service, account)
            }
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

    #[test]
    fn env_var_constructor() {
        let secret = SecretReference::env_var("MY_KEY");
        assert!(matches!(secret, SecretReference::EnvVar { name } if name == "MY_KEY"));
    }

    #[test]
    fn keychain_constructor() {
        let secret = SecretReference::keychain("svc", "acct");
        assert!(
            matches!(secret, SecretReference::Keychain { service, account } if service == "svc" && account == "acct")
        );
    }

    #[test]
    fn validate_env_var_valid() {
        assert!(SecretReference::env_var("MY_API_KEY").validate().is_ok());
    }

    #[test]
    fn validate_env_var_with_numbers() {
        assert!(SecretReference::env_var("KEY_123").validate().is_ok());
    }

    #[test]
    fn validate_env_var_empty_rejected() {
        let secret = SecretReference::EnvVar {
            name: "".to_string(),
        };
        assert!(secret.validate().is_err());
    }

    #[test]
    fn validate_env_var_whitespace_only_rejected() {
        let secret = SecretReference::EnvVar {
            name: "  ".to_string(),
        };
        assert!(secret.validate().is_err());
    }

    #[test]
    fn validate_env_var_lowercase_rejected() {
        let secret = SecretReference::EnvVar {
            name: "my_key".to_string(),
        };
        let err = secret.validate().unwrap_err();
        assert!(err.to_string().contains("secret env var reference"));
    }

    #[test]
    fn validate_env_var_with_special_chars_rejected() {
        let secret = SecretReference::EnvVar {
            name: "MY-KEY".to_string(),
        };
        assert!(secret.validate().is_err());
    }

    #[test]
    fn validate_keychain_valid() {
        assert!(SecretReference::keychain("my-service", "my-account")
            .validate()
            .is_ok());
    }

    #[test]
    fn validate_keychain_empty_service_rejected() {
        let secret = SecretReference::Keychain {
            service: " ".to_string(),
            account: "acct".to_string(),
        };
        let err = secret.validate().unwrap_err();
        assert!(err.to_string().contains("non-empty service and account"));
    }

    #[test]
    fn validate_keychain_empty_account_rejected() {
        let secret = SecretReference::Keychain {
            service: "svc".to_string(),
            account: "  ".to_string(),
        };
        assert!(secret.validate().is_err());
    }

    #[test]
    fn display_value_env_var() {
        let secret = SecretReference::env_var("MY_KEY");
        assert_eq!(secret.display_value(), "env:MY_KEY");
    }

    #[test]
    fn display_value_keychain() {
        let secret = SecretReference::keychain("svc", "acct");
        assert_eq!(secret.display_value(), "keychain:svc:acct");
    }

    #[test]
    fn serde_roundtrip_env_var() {
        let secret = SecretReference::env_var("MY_KEY");
        let json = serde_json::to_string(&secret).unwrap();
        let recovered: SecretReference = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn serde_roundtrip_keychain() {
        let secret = SecretReference::keychain("svc", "acct");
        let json = serde_json::to_string(&secret).unwrap();
        let recovered: SecretReference = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn resolve_env_var_missing() {
        let secret = SecretReference::env_var("VERDICTAN_TEST_NONEXISTENT_SECRET_12345");
        assert!(secret.resolve().is_none());
    }
}

fn resolve_keychain_secret(service: &str, account: &str) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        // Native Security.framework lookup — secret bytes never appear on argv
        // or in process environment.
        let password =
            security_framework::passwords::get_generic_password(service, account).ok()?;
        let value = String::from_utf8(password).ok()?;
        let trimmed = value.trim().to_string();
        (!trimmed.is_empty()).then_some(trimmed)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (service, account);
        None
    }
}

#[cfg(test)]
mod sec022_native_keychain_tests {
    use super::*;

    #[test]
    fn resolve_keychain_path_has_no_argv_environment_or_log_channels() {
        let source = include_str!("secrets.rs");
        let start = source
            .find("fn resolve_keychain_secret(")
            .expect("resolve_keychain_secret");
        let end = source[start..]
            .find("#[cfg(test)]")
            .map(|offset| start + offset)
            .unwrap_or(source.len());
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
                "native keychain resolve path must not contain side channel {forbidden}"
            );
        }
        assert!(path.contains("security_framework::passwords::get_generic_password"));
    }

    #[test]
    fn resolve_keychain_secret_returns_none_on_non_macos() {
        #[cfg(not(target_os = "macos"))]
        {
            assert!(resolve_keychain_secret("svc", "acct").is_none());
        }
        #[cfg(target_os = "macos")]
        {
            // Missing entry should fail closed without panicking.
            let _ = resolve_keychain_secret(
                "verdictan-sec022-missing-service",
                "verdictan-sec022-missing-account",
            );
        }
    }
}
