// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::error::CliError;

/// CLI-SEC-006: Validate that an environment variable name contains only safe
/// characters (`A-Z`, `0-9`, `_`) starting with a letter or underscore.
/// This prevents injection of crafted names into `std::env::var` lookups.
pub fn is_valid_env_var_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let first = name.as_bytes()[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretKeyReference {
    #[serde(default)]
    pub env: Option<String>,
    #[serde(default)]
    pub store: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub keychain: Option<String>,
}

/// Parsed keychain reference for macOS Keychain Access lookups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeychainRef {
    pub service: String,
    pub account: Option<String>,
}

impl KeychainRef {
    #[allow(dead_code)]
    pub(crate) fn parse(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }
        if let Some((service, account)) = trimmed.split_once('/') {
            let service = service.trim();
            let account = account.trim();
            if service.is_empty() {
                return None;
            }
            Some(Self {
                service: service.to_string(),
                account: if account.is_empty() {
                    None
                } else {
                    Some(account.to_string())
                },
            })
        } else {
            Some(Self {
                service: trimmed.to_string(),
                account: None,
            })
        }
    }
}

impl SecretKeyReference {
    pub fn from_env(env: impl Into<String>) -> Self {
        Self {
            env: Some(env.into()),
            store: None,
            scope: None,
            keychain: None,
        }
    }

    pub fn env_name(&self) -> Option<&str> {
        self.env
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn store_name(&self) -> Option<&str> {
        self.store
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn scope_name(&self) -> Option<&str> {
        self.scope
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn keychain_name(&self) -> Option<&str> {
        self.keychain
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn is_keychain_ref(&self) -> bool {
        self.keychain_name().is_some()
    }

    pub fn is_store_ref(&self) -> bool {
        self.store_name().is_some()
    }

    pub fn validate(&self, field_name: &str) -> Result<(), CliError> {
        let has_env = self.env_name().is_some();
        let has_store = self.store_name().is_some();
        let has_keychain = self.keychain_name().is_some();

        let set_count = [has_env, has_store, has_keychain]
            .iter()
            .filter(|&&v| v)
            .count();

        if set_count > 1 {
            return Err(CliError::user(format!(
                "{field_name} could not be resolved. Expected format: secret_key_ref: {{ env: \"ENV_VAR\" }} \
                 for environment-backed secrets, secret_key_ref: {{ store: \"SECRET_NAME\" }} for stored secrets, \
                 or secret_key_ref: {{ keychain: \"SERVICE/ACCOUNT\" }} for macOS Keychain secrets. \
                 The reference must include exactly one of 'env', 'store', or 'keychain', but multiple were provided. \
                 See: docs.verdictan.com/docs/configurations#secret-references"
            )));
        }
        if set_count == 0 {
            return Err(CliError::user(format!(
                "{field_name} could not be resolved. Expected format: secret_key_ref: {{ env: \"ENV_VAR\" }} \
                 for environment-backed secrets, secret_key_ref: {{ store: \"SECRET_NAME\" }} for stored secrets, \
                 or secret_key_ref: {{ keychain: \"SERVICE/ACCOUNT\" }} for macOS Keychain secrets. \
                 The reference must include exactly one of 'env', 'store', or 'keychain', but none was provided. \
                 See: docs.verdictan.com/docs/configurations#secret-references"
            )));
        }

        if has_env && self.scope_name().is_some() {
            return Err(CliError::user(format!(
                "{field_name}.scope is only supported when '{field_name}.store' is set"
            )));
        }

        if has_keychain && self.scope_name().is_some() {
            return Err(CliError::user(format!(
                "{field_name}.scope is only supported when '{field_name}.store' is set"
            )));
        }

        Ok(())
    }

    pub fn resolve_from_environment(&self, field_name: &str) -> Result<Option<String>, CliError> {
        self.resolve_env_with(field_name, |name| std::env::var(name).ok())
    }

    /// Resolve an env-backed secret using a caller-supplied lookup function.
    ///
    /// Production callers use [`resolve_from_environment`] which delegates here
    /// with `std::env::var`. Tests can pass a custom closure to avoid touching
    /// the real process environment.
    pub(crate) fn resolve_env_with(
        &self,
        field_name: &str,
        env_lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<String>, CliError> {
        let Some(env_name) = self.env_name() else {
            if self.is_store_ref() {
                return Err(CliError::user(format!(
                    "{field_name}.store is not supported in this config surface"
                )));
            }
            return Ok(None);
        };

        // CLI-SEC-006: Reject env var names with invalid characters.
        if !is_valid_env_var_name(env_name) {
            tracing::warn!(
                env_name = env_name,
                field_name = field_name,
                "rejected env var lookup with invalid name"
            );
            return Err(CliError::user(format!(
                "{field_name}.env contains invalid environment variable name '{env_name}'"
            )));
        }

        let value = env_lookup(env_name).ok_or_else(|| {
            CliError::user(format!(
                "{field_name}.env references environment variable '{env_name}', but it is not set"
            ))
        })?;
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(CliError::user(format!(
                "{field_name}.env references environment variable '{env_name}', but it is empty"
            )));
        }

        Ok(Some(trimmed.to_string()))
    }

    /// Resolve a secret from the macOS Keychain via Security.framework.
    /// Only available on macOS; returns an error on other platforms.
    ///
    /// Secret bytes are read through the native Keychain API and never placed
    /// on process argv, environment, or diagnostic channels.
    #[cfg(target_os = "macos")]
    pub fn resolve_from_keychain(&self, field_name: &str) -> Result<Option<String>, CliError> {
        let Some(keychain_value) = self.keychain_name() else {
            return Ok(None);
        };
        let keychain_ref = KeychainRef::parse(keychain_value).ok_or_else(|| {
            CliError::user(format!(
                "{field_name}.keychain: invalid keychain reference '{keychain_value}'"
            ))
        })?;

        // `verdictan secrets add` stores under account "verdictan"; use that when the
        // reference omits an account segment.
        let account = keychain_ref.account.as_deref().unwrap_or("verdictan");

        let password =
            security_framework::passwords::get_generic_password(&keychain_ref.service, account)
                .map_err(|_| {
                    CliError::user(format!(
                        "{field_name}.keychain: keychain lookup failed for service '{}'",
                        keychain_ref.service
                    ))
                })?;

        let value = String::from_utf8(password)
            .map_err(|_| {
                CliError::user(format!(
                    "{field_name}.keychain: keychain entry for service '{}' is not valid UTF-8",
                    keychain_ref.service
                ))
            })?
            .trim()
            .to_string();
        if value.is_empty() {
            return Err(CliError::user(format!(
                "{field_name}.keychain: keychain entry for service '{}' is empty",
                keychain_ref.service
            )));
        }
        Ok(Some(value))
    }

    /// Resolve a secret from the macOS Keychain — stub for non-macOS platforms.
    #[cfg(not(target_os = "macos"))]
    pub fn resolve_from_keychain(&self, field_name: &str) -> Result<Option<String>, CliError> {
        if self.keychain_name().is_some() {
            return Err(CliError::user(format!(
                "{field_name}.keychain: keychain references are only supported on macOS"
            )));
        }
        Ok(None)
    }
}

pub fn parse_secret_key_ref_value(
    value: Option<&Value>,
    field_name: &str,
) -> Result<Option<SecretKeyReference>, CliError> {
    let Some(value) = value else {
        return Ok(None);
    };

    let reference: SecretKeyReference = serde_json::from_value(value.clone()).map_err(|error| {
        CliError::user(format!(
            "{field_name} could not be resolved. Expected format: secret_key_ref: {{ env: \"ENV_VAR\" }} \
             for environment-backed secrets or secret_key_ref: {{ store: \"SECRET_NAME\" }} for stored secrets. \
             The reference must include exactly one of 'env' or 'store'. \
             Parse error: {error}. See: docs.verdictan.com/docs/configurations#secret-references"
        ))
    })?;
    reference.validate(field_name)?;
    Ok(Some(reference))
}

pub fn parse_env_secret_key_name(
    value: Option<&Value>,
    field_name: &str,
) -> Result<Option<String>, CliError> {
    let Some(reference) = parse_secret_key_ref_value(value, field_name)? else {
        return Ok(None);
    };
    let Some(env_name) = reference.env_name() else {
        return Err(CliError::user(format!(
            "{field_name}.store is not supported in this config surface"
        )));
    };
    Ok(Some(env_name.to_string()))
}

pub fn deserialize_optional_env_secret_key_name<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    parse_env_secret_key_name(value.as_ref(), "secret_key_ref")
        .map_err(|error| D::Error::custom(error.to_string()))
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
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Debug, Deserialize)]
    struct EnvNameField {
        #[serde(deserialize_with = "deserialize_optional_env_secret_key_name")]
        secret_key_ref: Option<String>,
    }

    #[test]
    fn valid_env_var_names() {
        assert!(is_valid_env_var_name("OPENAI_KEY"));
        assert!(is_valid_env_var_name("_PRIVATE"));
        assert!(is_valid_env_var_name("A"));
        assert!(is_valid_env_var_name("FOO_BAR_123"));
    }

    #[test]
    fn invalid_env_var_names() {
        assert!(!is_valid_env_var_name(""));
        assert!(!is_valid_env_var_name("1_STARTS_WITH_DIGIT"));
        assert!(!is_valid_env_var_name("HAS SPACE"));
        assert!(!is_valid_env_var_name("HAS-DASH"));
    }

    #[test]
    fn secret_key_ref_env_roundtrip() {
        let skr: SecretKeyReference = serde_json::from_value(json!({"env": "MY_SECRET"})).unwrap();
        assert_eq!(skr.env, Some("MY_SECRET".to_string()));
        assert!(skr.store.is_none());
    }

    #[test]
    fn secret_key_ref_store_roundtrip() {
        let skr: SecretKeyReference =
            serde_json::from_value(json!({"store": "my-secret"})).unwrap();
        assert!(skr.env.is_none());
        assert_eq!(skr.store, Some("my-secret".to_string()));
    }

    #[test]
    fn keychain_ref_parse_service_only() {
        let kr = KeychainRef::parse("my-service").unwrap();
        assert_eq!(kr.service, "my-service");
        assert!(kr.account.is_none());
    }

    #[test]
    fn keychain_ref_parse_with_account() {
        let kr = KeychainRef::parse("my-service/my-account").unwrap();
        assert_eq!(kr.service, "my-service");
        assert_eq!(kr.account, Some("my-account".to_string()));
    }

    #[test]
    fn keychain_ref_parse_empty_is_none() {
        assert!(KeychainRef::parse("").is_none());
        assert!(KeychainRef::parse("  ").is_none());
    }

    #[test]
    fn parse_secret_key_ref_value_none() {
        let result = parse_secret_key_ref_value(None, "test");
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn parse_secret_key_ref_value_env() {
        let val = json!({"env": "MY_KEY"});
        let result = parse_secret_key_ref_value(Some(&val), "test").unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().env, Some("MY_KEY".to_string()));
    }

    #[test]
    fn parse_env_secret_key_name_success() {
        let val = json!({"env": "MY_KEY"});
        let name = parse_env_secret_key_name(Some(&val), "test").unwrap();
        assert_eq!(name, Some("MY_KEY".to_string()));
    }

    #[test]
    fn parse_env_secret_key_name_none() {
        let name = parse_env_secret_key_name(None, "test").unwrap();
        assert!(name.is_none());
    }

    #[test]
    fn from_env_and_name_helpers_trim_whitespace() {
        let env_ref = SecretKeyReference::from_env("  VERDICTAN_OPENAI_API_KEY  ");
        assert_eq!(env_ref.env_name(), Some("VERDICTAN_OPENAI_API_KEY"));
        assert!(!env_ref.is_store_ref());
        assert!(!env_ref.is_keychain_ref());

        let store_ref = SecretKeyReference {
            env: None,
            store: Some("  stored-secret  ".to_string()),
            scope: Some("  org  ".to_string()),
            keychain: Some("   ".to_string()),
        };
        assert_eq!(store_ref.store_name(), Some("stored-secret"));
        assert_eq!(store_ref.scope_name(), Some("org"));
        assert_eq!(store_ref.keychain_name(), None);
        assert!(store_ref.is_store_ref());
    }

    #[test]
    fn keychain_ref_parse_rejects_empty_service_and_allows_blank_account() {
        assert!(KeychainRef::parse("/missing-service").is_none());

        let keychain_ref = KeychainRef::parse("service/").expect("keychain ref");
        assert_eq!(keychain_ref.service, "service");
        assert_eq!(keychain_ref.account, None);
    }

    #[test]
    fn validate_rejects_multiple_sources() {
        let reference = SecretKeyReference {
            env: Some("ENV_ONE".to_string()),
            store: Some("store-one".to_string()),
            scope: None,
            keychain: None,
        };
        let err = reference
            .validate("provider.secret")
            .expect_err("must fail");
        assert!(err.to_string().contains("multiple were provided"));
    }

    #[test]
    fn validate_rejects_missing_sources() {
        let err = SecretKeyReference {
            env: None,
            store: None,
            scope: None,
            keychain: None,
        }
        .validate("provider.secret")
        .expect_err("must fail");
        assert!(err.to_string().contains("none was provided"));
    }

    #[test]
    fn validate_enforces_scope_only_for_store_refs() {
        let env_scope = SecretKeyReference {
            env: Some("ENV_ONE".to_string()),
            store: None,
            scope: Some("org".to_string()),
            keychain: None,
        }
        .validate("provider.secret")
        .expect_err("env scope must fail");
        assert!(env_scope
            .to_string()
            .contains("scope is only supported when 'provider.secret.store' is set"));

        let keychain_scope = SecretKeyReference {
            env: None,
            store: None,
            scope: Some("org".to_string()),
            keychain: Some("svc/acct".to_string()),
        }
        .validate("provider.secret")
        .expect_err("keychain scope must fail");
        assert!(keychain_scope
            .to_string()
            .contains("scope is only supported when 'provider.secret.store' is set"));

        SecretKeyReference {
            env: None,
            store: Some("stored-secret".to_string()),
            scope: Some("org".to_string()),
            keychain: None,
        }
        .validate("provider.secret")
        .expect("store scope should be valid");
    }

    #[test]
    fn resolve_env_with_handles_missing_store_invalid_and_trimmed_values() {
        let no_source = SecretKeyReference {
            env: None,
            store: None,
            scope: None,
            keychain: None,
        };
        assert_eq!(
            no_source
                .resolve_env_with("provider.secret", |_| Some("ignored".to_string()))
                .expect("no source"),
            None
        );

        let store_ref = SecretKeyReference {
            env: None,
            store: Some("shared".to_string()),
            scope: None,
            keychain: None,
        };
        let store_err = store_ref
            .resolve_env_with("provider.secret", |_| None)
            .expect_err("store refs unsupported");
        assert!(store_err
            .to_string()
            .contains("provider.secret.store is not supported"));

        let invalid_name = SecretKeyReference::from_env("BAD-NAME");
        let invalid_err = invalid_name
            .resolve_env_with("provider.secret", |_| Some("value".to_string()))
            .expect_err("invalid env name");
        assert!(invalid_err
            .to_string()
            .contains("contains invalid environment variable name 'BAD-NAME'"));

        let missing_err = SecretKeyReference::from_env("MISSING_KEY")
            .resolve_env_with("provider.secret", |_| None)
            .expect_err("missing env");
        assert!(missing_err
            .to_string()
            .contains("references environment variable 'MISSING_KEY', but it is not set"));

        let empty_err = SecretKeyReference::from_env("EMPTY_KEY")
            .resolve_env_with("provider.secret", |_| Some("   ".to_string()))
            .expect_err("empty env");
        assert!(empty_err
            .to_string()
            .contains("references environment variable 'EMPTY_KEY', but it is empty"));

        let resolved = SecretKeyReference::from_env("TRIMMED_KEY")
            .resolve_env_with("provider.secret", |_| Some("  token-value  ".to_string()))
            .expect("resolve env");
        assert_eq!(resolved, Some("token-value".to_string()));
    }

    #[test]
    fn parse_secret_key_ref_value_rejects_unknown_fields() {
        let err =
            parse_secret_key_ref_value(Some(&json!({"env": "MY_KEY", "extra": true})), "test")
                .expect_err("unknown field");
        assert!(err.to_string().contains("unknown field `extra`"));
    }

    #[test]
    fn parse_env_secret_key_name_rejects_store_refs() {
        let err =
            parse_env_secret_key_name(Some(&json!({"store": "shared-secret"})), "provider.secret")
                .expect_err("store ref unsupported");
        assert!(err
            .to_string()
            .contains("provider.secret.store is not supported"));
    }

    #[test]
    fn deserialize_optional_env_secret_key_name_supports_env_only() {
        let parsed: EnvNameField =
            serde_json::from_value(json!({"secret_key_ref": {"env": "ENV_NAME"}}))
                .expect("deserialize");
        assert_eq!(parsed.secret_key_ref, Some("ENV_NAME".to_string()));

        let err = serde_json::from_value::<EnvNameField>(
            json!({"secret_key_ref": {"store": "shared-secret"}}),
        )
        .expect_err("store refs unsupported");
        assert!(err
            .to_string()
            .contains("secret_key_ref.store is not supported"));
    }

    #[test]
    fn resolve_from_keychain_without_ref_returns_none() {
        let resolved = SecretKeyReference {
            env: None,
            store: None,
            scope: None,
            keychain: None,
        }
        .resolve_from_keychain("provider.secret")
        .expect("no keychain ref");
        assert_eq!(resolved, None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn resolve_from_keychain_rejects_invalid_reference_before_lookup() {
        let err = SecretKeyReference {
            env: None,
            store: None,
            scope: None,
            keychain: Some("/missing-service".to_string()),
        }
        .resolve_from_keychain("provider.secret")
        .expect_err("invalid keychain ref");
        assert!(err
            .to_string()
            .contains("invalid keychain reference '/missing-service'"));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn resolve_from_keychain_rejects_refs_on_non_macos() {
        let err = SecretKeyReference {
            env: None,
            store: None,
            scope: None,
            keychain: Some("service/account".to_string()),
        }
        .resolve_from_keychain("provider.secret")
        .expect_err("keychain unsupported");
        assert!(err.to_string().contains("only supported on macOS"));
    }

    #[test]
    fn native_keychain_resolve_path_has_no_argv_environment_or_log_channels() {
        let source = include_str!("secret_key_ref.rs");
        let start = source
            .find("pub fn resolve_from_keychain(&self, field_name: &str)")
            .expect("resolve_from_keychain");
        // Cover both the macOS and non-macOS impls through the next public fn.
        let end = source[start..]
            .find("pub fn parse_secret_key_ref_value(")
            .map(|offset| start + offset)
            .expect("end of resolve_from_keychain impls");
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
    fn keychain_lookup_failure_diagnostic_does_not_embed_secret_bytes() {
        // Error strings must stay metadata-only even when a secret-looking
        // service name is supplied (no argv/-w password channel remains).
        let secret_like = "lane-c039-secret-sentinel-value";
        let reference = SecretKeyReference {
            env: None,
            store: None,
            scope: None,
            keychain: Some(format!("missing-service/{secret_like}")),
        };
        let diagnostic = match reference.resolve_from_keychain("provider.secret") {
            Ok(value) => format!("unexpected success: {value:?}"),
            Err(err) => err.to_string(),
        };
        assert!(
            !diagnostic.contains(secret_like),
            "diagnostic must not echo account/secret-like material: {diagnostic}"
        );
    }
}
