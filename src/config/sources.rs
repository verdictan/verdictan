// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use crate::config::ConfigFile;
use crate::error::CliError;
use std::collections::BTreeMap;

const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileRegionConfig {
    pub legacy_default_region: Option<String>,
    pub profile_default_region: Option<String>,
}

#[derive(serde::Deserialize)]
struct RawProfileConfig {
    default_region: Option<String>,
}

#[derive(serde::Deserialize)]
struct RawConfig {
    api_url: Option<String>,
    api_token: Option<String>,
    api_key: Option<String>,
    profile: Option<String>,
    default_region: Option<String>,
    #[serde(default)]
    profiles: BTreeMap<String, RawProfileConfig>,
}

pub fn load_api_url_from_env() -> Option<String> {
    std::env::var("VERDICTAN_API_URL").ok()
}

pub fn load_api_token_from_env() -> Result<Option<String>, CliError> {
    Ok(std::env::var("VERDICTAN_API_TOKEN")
        .ok()
        .and_then(|value| normalize_optional_string(Some(value.as_str()))))
}

/// Load the config file from the given path or the default location.
///
/// # Validation boundary
///
/// All external input is parsed through [`ConfigFile`] (a typed struct) before
/// use. The raw YAML bytes are decoded as UTF-8, then deserialized into the
/// struct; unknown fields are silently ignored. The path is resolved at the
/// caller's discretion — callers must ensure it does not traverse outside
/// expected directories (no `..` components in untrusted paths).
pub fn load_config_file(path: Option<&std::path::Path>) -> Result<ConfigFile, CliError> {
    let Some((_path, raw)) = load_raw_config(path)? else {
        return Ok(ConfigFile::default());
    };

    Ok(ConfigFile {
        api_url: normalize_optional_string(raw.api_url.as_deref()),
        api_token: normalize_optional_string(raw.api_token.as_deref()),
        profile: normalize_optional_string(raw.profile.as_deref()),
        default_region: normalize_optional_string(raw.default_region.as_deref()),
    })
}

pub fn load_profile_region_config(
    path: Option<&std::path::Path>,
    profile: &str,
) -> Result<ProfileRegionConfig, CliError> {
    let Some((_path, raw)) = load_raw_config(path)? else {
        return Ok(ProfileRegionConfig::default());
    };

    let profile_default_region = raw
        .profiles
        .get(profile.trim())
        .and_then(|entry| normalize_optional_string(entry.default_region.as_deref()));

    Ok(ProfileRegionConfig {
        legacy_default_region: normalize_optional_string(raw.default_region.as_deref()),
        profile_default_region,
    })
}

pub fn list_config_profiles(path: Option<&std::path::Path>) -> Result<Vec<String>, CliError> {
    let Some((_path, raw)) = load_raw_config(path)? else {
        return Ok(Vec::new());
    };

    let mut profiles = std::collections::BTreeSet::new();
    if let Some(profile) = normalize_optional_string(raw.profile.as_deref()) {
        profiles.insert(profile);
    }
    for profile in raw.profiles.keys() {
        if let Some(profile) = normalize_optional_string(Some(profile.as_str())) {
            profiles.insert(profile);
        }
    }

    Ok(profiles.into_iter().collect())
}

pub fn resolve_config_path(path: Option<&std::path::Path>) -> Option<std::path::PathBuf> {
    path.map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("VERDICTAN_CONFIG").map(std::path::PathBuf::from))
        .or_else(default_config_path)
}

fn load_raw_config(
    path: Option<&std::path::Path>,
) -> Result<Option<(std::path::PathBuf, RawConfig)>, CliError> {
    let Some(path) = resolve_config_path(path) else {
        return Ok(None);
    };

    let metadata = std::fs::metadata(&path).map_err(|e| {
        CliError::user(format!(
            "failed to read config file {}: {e}",
            path.display()
        ))
    })?;
    if metadata.len() > MAX_CONFIG_FILE_BYTES {
        return Err(CliError::user(format!(
            "config file {} exceeds the {} byte limit",
            path.display(),
            MAX_CONFIG_FILE_BYTES
        )));
    }

    let bytes = std::fs::read(&path).map_err(|e| {
        CliError::user(format!(
            "failed to read config file {}: {e}",
            path.display()
        ))
    })?;
    if bytes.len() as u64 > MAX_CONFIG_FILE_BYTES {
        return Err(CliError::user(format!(
            "config file {} exceeds the {} byte limit",
            path.display(),
            MAX_CONFIG_FILE_BYTES
        )));
    }

    let text = String::from_utf8(bytes).map_err(|e| {
        CliError::user(format!(
            "config file {} is not valid UTF-8: {e}",
            path.display()
        ))
    })?;

    let raw: RawConfig = serde_yaml::from_str(&text).map_err(|e| {
        CliError::user(format!(
            "config file {} is not valid YAML: {e}",
            path.display()
        ))
    })?;

    if normalize_optional_string(raw.api_key.as_deref()).is_some() {
        return Err(CliError::user(
            "config file api_key has been removed; use api_token or `verdictan auth login`. For provider configs, use secret_key_ref with a config-variable name",
        ));
    }

    Ok(Some((path, raw)))
}

fn normalize_optional_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub fn default_config_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    let path = std::path::PathBuf::from(home).join(".verdictan/config.yaml");
    path.exists().then_some(path)
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
    use std::io::Write;

    #[test]
    fn load_config_file_from_explicit_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "api_url: https://api.example.com\napi_token: tok-123").unwrap();

        let cfg = load_config_file(Some(path.as_path())).unwrap();
        assert_eq!(cfg.api_url.as_deref(), Some("https://api.example.com"));
        assert_eq!(cfg.api_token.as_deref(), Some("tok-123"));
    }

    #[test]
    fn load_config_file_with_profile_and_region() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "profile: staging\ndefault_region: eu-west-1").unwrap();

        let cfg = load_config_file(Some(path.as_path())).unwrap();
        assert_eq!(cfg.profile.as_deref(), Some("staging"));
        assert_eq!(cfg.default_region.as_deref(), Some("eu-west-1"));
    }

    #[test]
    fn load_config_file_rejects_api_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "api_key: my-old-key").unwrap();

        let err = load_config_file(Some(path.as_path())).unwrap_err();
        assert!(err.to_string().contains("api_key has been removed"));
    }

    #[test]
    fn load_config_file_ignores_empty_api_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "api_key: \"  \"").unwrap();

        let cfg = load_config_file(Some(path.as_path()));
        assert!(cfg.is_ok());
    }

    #[test]
    fn load_config_file_missing_file() {
        let path = std::path::Path::new("/tmp/verdictan-test-nonexistent-987654321.yaml");
        let err = load_config_file(Some(path)).unwrap_err();
        assert!(err.to_string().contains("failed to read config file"));
    }

    #[test]
    fn load_config_file_invalid_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, "{{{{invalid yaml").unwrap();

        let err = load_config_file(Some(path.as_path())).unwrap_err();
        assert!(err.to_string().contains("not valid YAML"));
    }

    #[test]
    fn load_config_file_ignores_unknown_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            "api_url: https://api.example.com\nunknown_field: ignored_value"
        )
        .unwrap();

        let cfg = load_config_file(Some(path.as_path())).unwrap();
        assert_eq!(cfg.api_url.as_deref(), Some("https://api.example.com"));
    }
}
