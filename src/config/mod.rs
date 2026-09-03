// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

pub mod sources;

use std::sync::OnceLock;

use serde::Serialize;

use crate::auth::credential_store;
use crate::error::CliError;

pub const DEFAULT_API_URL: &str = "https://api.verdictan.com";

/// CLI-FIND-LOW-002: Documented config resolution precedence (highest priority first).
///
/// 1. CLI flags (`--api-url`, `--profile`)
/// 2. Environment variables (`VERDICTAN_API_URL`, `VERDICTAN_API_TOKEN`)
/// 3. Config file (`~/.verdictan/config.yaml` or `--config` path)
/// 4. Stored credentials (profile-scoped from `verdictan login`)
/// 5. Built-in defaults (`DEFAULT_API_URL`, profile "default")
///
/// Each field is resolved independently at the first level that provides a value.
const CONFIG_PRECEDENCE: [&str; 5] = ["flag", "env", "file", "stored_credentials", "default"];

#[doc(hidden)]
pub fn test_env_lock() -> &'static std::sync::Mutex<()> {
    crate::test_support::env_lock()
}

#[derive(Debug, Clone)]
pub struct ConfigInputs {
    pub api_url_flag: Option<String>,
    pub api_token_flag: Option<String>,
    pub config_path: Option<std::path::PathBuf>,
    pub profile_flag: Option<String>,
    /// Phase 40: explicit `--region` flag value.
    pub region_flag: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ConfigFile {
    pub api_url: Option<String>,
    pub api_token: Option<String>,
    pub profile: Option<String>,
    /// Default region for API calls.
    pub default_region: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub api_url: String,
    pub api_token: Option<String>,
    pub profile: String,
    pub region: Option<String>,
}

impl Config {
    pub fn resolve(inputs: ConfigInputs) -> Result<Self, CliError> {
        let file = sources::load_config_file(inputs.config_path.as_deref())?;

        // profile: flag > file > default
        let profile = inputs
            .profile_flag
            .or(file.profile)
            .unwrap_or_else(|| "default".to_string());
        let profiled_region =
            sources::load_profile_region_config(inputs.config_path.as_deref(), &profile)?;
        let region = inputs
            .region_flag
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .or(profiled_region.profile_default_region)
            .or(profiled_region.legacy_default_region);
        let stored = match credential_store::load(Some(&profile)) {
            Ok(value) => value,
            Err(error)
                if error
                    .to_string()
                    .contains("unable to determine HOME directory") =>
            {
                None
            }
            Err(error) => return Err(error),
        };

        // api_url: flag > env > file > default
        let api_url = match inputs
            .api_url_flag
            .or_else(sources::load_api_url_from_env)
            .or(file.api_url)
        {
            Some(value) => value,
            None => stored
                .as_ref()
                .map(|credentials| credentials.api_url.clone())
                .unwrap_or_else(|| DEFAULT_API_URL.to_string()),
        };
        let env_api_token = sources::load_api_token_from_env()?;

        // api_token: flag > env > file > stored credentials > default(None)
        let api_token = inputs
            .api_token_flag
            .or(env_api_token)
            .or(file.api_token)
            .or_else(|| {
                stored
                    .as_ref()
                    .map(|credentials| credentials.api_token.clone())
            });

        Ok(Self {
            api_url,
            api_token,
            profile,
            region,
        })
    }

    fn into_public_json(self) -> PublicConfigJson {
        PublicConfigJson {
            api_url: self.api_url,
            has_api_token: self.api_token.is_some(),
            profile: self.profile,
            // CLI-FIND-LOW-002: Document full precedence including stored credentials.
            // Resolution order: CLI flag > environment variable > config file > stored credentials > default.
            source_precedence: ["flag", "env", "file", "stored_credentials", "default"],
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PublicConfigJson {
    pub api_url: String,
    pub has_api_token: bool,
    pub profile: String,
    /// Deterministic config resolution order (highest priority first).
    /// CLI args > env vars > config file > stored credentials > built-in defaults.
    pub source_precedence: [&'static str; 5],
}

/// Deferred config resolution that only reads the config file on first access.
///
/// Commands that never call [`get`](LazyConfig::get) (e.g. `policy lint --local`,
/// `version`, `completions`) skip the file-system read entirely.
pub struct LazyConfig {
    inputs: ConfigInputs,
    resolved: OnceLock<Result<Config, String>>,
}

impl LazyConfig {
    pub fn new(inputs: ConfigInputs) -> Self {
        Self {
            inputs,
            resolved: OnceLock::new(),
        }
    }

    /// Resolve and return the config, reading the config file on first call.
    pub fn get(&self) -> Result<&Config, CliError> {
        self.resolved
            .get_or_init(|| Config::resolve(self.inputs.clone()).map_err(|e| e.to_string()))
            .as_ref()
            .map_err(|message| CliError::internal(message.clone()))
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

    // ── DEFAULT_API_URL ────────────────────────────────────────────────

    #[test]
    fn default_api_url_is_https() {
        assert!(DEFAULT_API_URL.starts_with("https://"));
    }

    #[test]
    fn default_api_url_is_verdictan_domain() {
        assert!(DEFAULT_API_URL.contains("verdictan.com"));
    }

    // ── CONFIG_PRECEDENCE ──────────────────────────────────────────────

    #[test]
    fn config_precedence_has_five_levels() {
        assert_eq!(CONFIG_PRECEDENCE.len(), 5);
    }

    #[test]
    fn config_precedence_flag_is_highest() {
        assert_eq!(CONFIG_PRECEDENCE[0], "flag");
    }

    #[test]
    fn config_precedence_default_is_lowest() {
        assert_eq!(CONFIG_PRECEDENCE[4], "default");
    }

    #[test]
    fn config_precedence_all_entries_non_empty() {
        for entry in &CONFIG_PRECEDENCE {
            assert!(!entry.is_empty());
        }
    }

    // ── ConfigFile::default ────────────────────────────────────────────

    #[test]
    fn config_file_default_all_none() {
        let cf = ConfigFile::default();
        assert!(cf.api_url.is_none());
        assert!(cf.api_token.is_none());
        assert!(cf.profile.is_none());
        assert!(cf.default_region.is_none());
    }

    // ── Config::into_public_json ──────────────────────────────────────

    #[test]
    fn into_public_json_preserves_api_url() {
        let config = Config {
            api_url: "https://api.test.com".to_string(),
            api_token: Some("tok_secret".to_string()),
            profile: "work".to_string(),
            region: None,
        };
        let json = config.into_public_json();
        assert_eq!(json.api_url, "https://api.test.com");
    }

    #[test]
    fn into_public_json_redacts_token_to_boolean() {
        let config = Config {
            api_url: DEFAULT_API_URL.to_string(),
            api_token: Some("tok_abc".to_string()),
            profile: "default".to_string(),
            region: None,
        };
        let json = config.into_public_json();
        assert!(json.has_api_token);
    }

    #[test]
    fn into_public_json_no_token() {
        let config = Config {
            api_url: DEFAULT_API_URL.to_string(),
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let json = config.into_public_json();
        assert!(!json.has_api_token);
    }

    #[test]
    fn into_public_json_preserves_profile() {
        let config = Config {
            api_url: DEFAULT_API_URL.to_string(),
            api_token: None,
            profile: "staging".to_string(),
            region: None,
        };
        let json = config.into_public_json();
        assert_eq!(json.profile, "staging");
    }

    #[test]
    fn into_public_json_source_precedence_matches_constant() {
        let config = Config {
            api_url: DEFAULT_API_URL.to_string(),
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let json = config.into_public_json();
        assert_eq!(json.source_precedence, CONFIG_PRECEDENCE);
    }

    #[test]
    fn into_public_json_serializes() {
        let config = Config {
            api_url: "https://api.test.com".to_string(),
            api_token: Some("sk-secret-value-xyz".to_string()),
            profile: "default".to_string(),
            region: None,
        };
        let json = config.into_public_json();
        let serialized = serde_json::to_string(&json).expect("should serialize");
        assert!(serialized.contains("api_url"));
        assert!(serialized.contains("has_api_token"));
        assert!(serialized.contains("source_precedence"));
        assert!(!serialized.contains("sk-secret-value-xyz"));
    }

    // ── ConfigInputs ──────────────────────────────────────────────────

    #[test]
    fn config_inputs_debug() {
        let inputs = ConfigInputs {
            api_url_flag: Some("https://api.test.com".to_string()),
            api_token_flag: None,
            config_path: None,
            profile_flag: None,
            region_flag: None,
        };
        let dbg = format!("{inputs:?}");
        assert!(dbg.contains("api_url_flag"));
    }

    #[test]
    fn config_inputs_clone() {
        let inputs = ConfigInputs {
            api_url_flag: Some("https://api.test.com".to_string()),
            api_token_flag: Some("tok".to_string()),
            config_path: None,
            profile_flag: Some("dev".to_string()),
            region_flag: Some("eu-west-1".to_string()),
        };
        let cloned = inputs.clone();
        assert_eq!(cloned.api_url_flag, inputs.api_url_flag);
        assert_eq!(cloned.profile_flag, inputs.profile_flag);
        assert_eq!(cloned.region_flag, inputs.region_flag);
    }

    // ── LazyConfig ────────────────────────────────────────────────────

    #[test]
    fn lazy_config_new_does_not_resolve_eagerly() {
        let inputs = ConfigInputs {
            api_url_flag: None,
            api_token_flag: None,
            config_path: Some("/nonexistent/path/config.toml".into()),
            profile_flag: None,
            region_flag: None,
        };
        let _lazy = LazyConfig::new(inputs);
    }

    // ── test_env_lock ─────────────────────────────────────────────────

    #[test]
    fn test_env_lock_is_lockable() {
        let guard = test_env_lock().lock();
        assert!(guard.is_ok());
    }
}
