// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::CliError;
use crate::persistence::{atomic_write_private, PrivateFileMode};

const DEFAULT_PROFILE: &str = "default";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredentials {
    pub api_url: String,
    pub api_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub org_id: String,
    pub org_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_slug: Option<String>,
    pub project_id: String,
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub team_ids: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CredentialStoreFile {
    #[serde(default)]
    profiles: BTreeMap<String, StoredCredentials>,
}

pub fn load(profile: Option<&str>) -> Result<Option<StoredCredentials>, CliError> {
    let path = credentials_path()?;
    load_from_path(&path, profile)
}

pub fn save(profile: Option<&str>, credentials: StoredCredentials) -> Result<(), CliError> {
    let path = credentials_path()?;
    save_to_path(&path, profile, credentials)
}

pub fn delete(profile: Option<&str>) -> Result<bool, CliError> {
    let path = credentials_path()?;
    delete_from_path(&path, profile)
}

pub fn list_profiles() -> Result<Vec<String>, CliError> {
    let path = credentials_path()?;
    list_profiles_from_path(&path)
}

#[doc(hidden)]
pub fn load_from_path(
    path: &PathBuf,
    profile: Option<&str>,
) -> Result<Option<StoredCredentials>, CliError> {
    // CLI-SEC-011: Removed path.exists pre-check to eliminate TOCTOU race.
    // Directly attempt to open and handle NotFound gracefully.
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(CliError::user(format!(
                "failed to read credential store {}: {err}",
                path.display()
            )));
        }
    };
    let store: CredentialStoreFile = serde_json::from_str(&contents).map_err(|error| {
        CliError::user(format!(
            "credential store {} is not valid JSON: {error}",
            path.display()
        ))
    })?;

    Ok(store.profiles.get(profile_name(profile)).cloned())
}

#[doc(hidden)]
pub fn save_to_path(
    path: &PathBuf,
    profile: Option<&str>,
    credentials: StoredCredentials,
) -> Result<(), CliError> {
    let mut store = match std::fs::read_to_string(path) {
        Ok(contents) => {
            serde_json::from_str::<CredentialStoreFile>(&contents).map_err(|error| {
                CliError::user(format!(
                    "credential store {} is not valid JSON: {error}",
                    path.display()
                ))
            })?
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => CredentialStoreFile::default(),
        Err(error) => {
            return Err(CliError::user(format!(
                "failed to read credential store {}: {error}",
                path.display()
            )));
        }
    };

    store
        .profiles
        .insert(profile_name(profile).to_string(), credentials);

    write_store(path, &store)
}

#[doc(hidden)]
pub fn delete_from_path(path: &PathBuf, profile: Option<&str>) -> Result<bool, CliError> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(CliError::user(format!(
                "failed to read credential store {}: {error}",
                path.display()
            )));
        }
    };
    let mut store: CredentialStoreFile = serde_json::from_str(&contents).map_err(|error| {
        CliError::user(format!(
            "credential store {} is not valid JSON: {error}",
            path.display()
        ))
    })?;

    let removed = store.profiles.remove(profile_name(profile)).is_some();
    if removed {
        write_store(path, &store)?;
    }

    Ok(removed)
}

#[doc(hidden)]
pub fn list_profiles_from_path(path: &PathBuf) -> Result<Vec<String>, CliError> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(CliError::user(format!(
                "failed to read credential store {}: {err}",
                path.display()
            )));
        }
    };

    let store: CredentialStoreFile = serde_json::from_str(&contents).map_err(|error| {
        CliError::user(format!(
            "credential store {} is not valid JSON: {error}",
            path.display()
        ))
    })?;

    Ok(store.profiles.keys().cloned().collect())
}

fn write_store(path: &Path, store: &CredentialStoreFile) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            CliError::user(format!(
                "failed to create credential directory {}: {error}",
                parent.display()
            ))
        })?;
        ensure_private_dir(parent)?;
    }

    let contents = serde_json::to_string_pretty(store)
        .map_err(|error| CliError::internal(format!("failed to serialize credentials: {error}")))?;
    let protection = atomic_write_private(path, contents.as_bytes()).map_err(|error| {
        CliError::user(format!(
            "failed to write credential store {}: {error}",
            path.display()
        ))
    })?;

    if protection == PrivateFileMode::Unsupported {
        report_unrestricted_credential_file(path);
    }

    Ok(())
}

fn report_unrestricted_credential_file(path: &Path) {
    let target = std::env::consts::OS;
    tracing::warn!(
        path = %path.display(),
        target_os = target,
        "wrote the credential store without an owner-only file mode"
    );
    eprintln!(
        "warning: {} holds CLI credentials and could not receive an owner-only \
         file mode on {target}. Restrict access to this file before you leave the host.",
        path.display()
    );
}

fn home_dir() -> Result<PathBuf, CliError> {
    // Test seam. The override is compiled only into the crate's own test
    // harness, so a shipped binary cannot redirect credential persistence.
    #[cfg(test)]
    if let Some(path) = std::env::var_os("VERDICTAN_TEST_HOME") {
        return Ok(PathBuf::from(path));
    }

    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| CliError::internal("unable to determine HOME directory"))
}

fn credentials_path() -> Result<PathBuf, CliError> {
    Ok(home_dir()?.join(".verdictan").join("credentials.json"))
}

fn profile_name(profile: Option<&str>) -> &str {
    profile
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_PROFILE)
}

/// Returns an org-scoped state directory under `~/.verdictan/orgs/<org_id>/`.
/// Creates the directory if it does not exist.
pub fn org_state_dir(org_id: &str) -> Result<PathBuf, CliError> {
    let dir = home_dir()?.join(".verdictan").join("orgs").join(org_id);
    std::fs::create_dir_all(&dir).map_err(|error| {
        CliError::user(format!(
            "failed to create org state directory {}: {error}",
            dir.display()
        ))
    })?;
    ensure_private_dir(&dir)?;
    Ok(dir)
}

#[cfg(unix)]
fn ensure_private_dir(path: &std::path::Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|error| {
        CliError::user(format!(
            "failed to secure credential directory {}: {error}",
            path.display()
        ))
    })
}

#[cfg(not(unix))]
fn ensure_private_dir(path: &std::path::Path) -> Result<(), CliError> {
    #[cfg(windows)]
    {
        if crate::windows_private_acl::restrict_path_to_owner(path) {
            return Ok(());
        }
        return Err(CliError::user(format!(
            "failed to secure credential directory {}",
            path.display()
        )));
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(())
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
    use std::ffi::OsString;
    use tempfile::tempdir;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    struct EnvGuard {
        verdictan_test_home: Option<OsString>,
        home: Option<OsString>,
    }

    impl EnvGuard {
        fn capture() -> Self {
            Self {
                verdictan_test_home: std::env::var_os("VERDICTAN_TEST_HOME"),
                home: std::env::var_os("HOME"),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.verdictan_test_home {
                Some(value) => std::env::set_var("VERDICTAN_TEST_HOME", value),
                None => std::env::remove_var("VERDICTAN_TEST_HOME"),
            }
            match &self.home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    fn assert_credentials_eq(actual: Option<StoredCredentials>, expected: &StoredCredentials) {
        let actual = actual.expect("stored credentials");
        assert_eq!(
            serde_json::to_value(actual).expect("actual json"),
            serde_json::to_value(expected).expect("expected json")
        );
    }

    fn sample_credentials(token: &str, api_url: &str) -> StoredCredentials {
        StoredCredentials {
            api_url: api_url.to_string(),
            api_token: token.to_string(),
            expires_at: Some("2030-01-01T00:00:00Z".to_string()),
            org_id: "org_123".to_string(),
            org_name: "Verdictan".to_string(),
            org_slug: Some("verdictan".to_string()),
            project_id: "proj_123".to_string(),
            role: "owner".to_string(),
            user_id: Some("user_123".to_string()),
            email: Some("owner@example.com".to_string()),
            display_name: Some("Owner".to_string()),
            team_ids: vec!["team_1".to_string()],
            capabilities: vec!["gateway:write".to_string()],
        }
    }

    #[test]
    fn load_from_missing_path_returns_none() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("credentials.json");
        let loaded = load_from_path(&path, None).expect("load");
        assert!(loaded.is_none());
    }

    #[test]
    fn delete_from_missing_path_returns_false() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("credentials.json");
        assert!(!delete_from_path(&path, None).expect("delete missing path"));
    }

    #[test]
    fn load_save_and_delete_round_trip_uses_test_home() {
        let _lock = crate::config::test_env_lock().lock().expect("env lock");
        let _guard = EnvGuard::capture();
        let temp = tempdir().expect("tempdir");
        std::env::set_var("VERDICTAN_TEST_HOME", temp.path());
        std::env::remove_var("HOME");

        let credentials = sample_credentials("vdt_primary", "https://api.example.com");
        save(Some("  "), credentials.clone()).expect("save default profile");

        let stored_path = temp.path().join(".verdictan").join("credentials.json");
        assert!(
            stored_path.exists(),
            "expected credential store at {stored_path:?}"
        );
        assert_credentials_eq(load(None).expect("load"), &credentials);
        assert!(delete(None).expect("delete default profile"));
        assert!(!delete(None).expect("delete missing profile"));

        #[cfg(unix)]
        {
            let dir_mode = std::fs::metadata(stored_path.parent().expect("parent"))
                .expect("dir metadata")
                .permissions()
                .mode()
                & 0o777;
            let file_mode = std::fs::metadata(&stored_path)
                .expect("file metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }
    }

    #[test]
    fn public_helpers_use_home_when_test_home_is_missing_and_trim_profile_names() {
        let _lock = crate::config::test_env_lock().lock().expect("env lock");
        let _guard = EnvGuard::capture();
        let temp = tempdir().expect("tempdir");
        let home = temp.path().join("fallback-home");
        std::env::remove_var("VERDICTAN_TEST_HOME");
        std::env::set_var("HOME", &home);

        let default_credentials = sample_credentials("vdt_default", "https://api.default.example");
        let workspace_credentials =
            sample_credentials("vdt_workspace", "https://api.workspace.example");

        save(Some("   "), default_credentials.clone()).expect("save default profile");
        save(Some(" \tworkspace\n "), workspace_credentials.clone())
            .expect("save workspace profile");

        let stored_path = home.join(".verdictan").join("credentials.json");
        assert!(
            stored_path.exists(),
            "expected credential store at {stored_path:?}"
        );
        assert_credentials_eq(
            load(Some("")).expect("load blank profile"),
            &default_credentials,
        );
        assert_credentials_eq(
            load(Some(" workspace ")).expect("load trimmed workspace profile"),
            &workspace_credentials,
        );

        assert!(delete(Some(" \tworkspace\n ")).expect("delete trimmed workspace profile"));
        assert!(!delete(Some("workspace")).expect("delete missing workspace profile"));
        assert!(load(Some("workspace"))
            .expect("load deleted workspace profile")
            .is_none());
        assert_credentials_eq(
            load(None).expect("load default profile"),
            &default_credentials,
        );
    }

    #[test]
    fn public_helpers_prefer_verdictan_test_home_over_home() {
        let _lock = crate::config::test_env_lock().lock().expect("env lock");
        let _guard = EnvGuard::capture();
        let temp = tempdir().expect("tempdir");
        let preferred_home = temp.path().join("preferred-home");
        let fallback_home = temp.path().join("fallback-home");
        std::env::set_var("VERDICTAN_TEST_HOME", &preferred_home);
        std::env::set_var("HOME", &fallback_home);

        let credentials = sample_credentials("vdt_preferred", "https://api.preferred.example");
        save(None, credentials.clone()).expect("save preferred credentials");

        assert_credentials_eq(
            load(None).expect("load preferred credentials"),
            &credentials,
        );
        assert!(preferred_home
            .join(".verdictan")
            .join("credentials.json")
            .exists());
        assert!(!fallback_home
            .join(".verdictan")
            .join("credentials.json")
            .exists());
    }

    #[test]
    fn save_to_path_preserves_other_profiles_and_trims_profile_names() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("credentials.json");
        let first = sample_credentials("vdt_alpha", "https://api.alpha.example");
        let second = sample_credentials("vdt_beta", "https://api.beta.example");

        save_to_path(&path, None, first.clone()).expect("save default");
        save_to_path(&path, Some("  workspace  "), second.clone()).expect("save workspace");

        assert_credentials_eq(load_from_path(&path, None).expect("load default"), &first);
        assert_credentials_eq(
            load_from_path(&path, Some("workspace")).expect("load workspace"),
            &second,
        );

        let file: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read path"))
                .expect("parse store");
        assert!(file["profiles"].get("default").is_some());
        assert!(file["profiles"].get("workspace").is_some());
    }

    #[test]
    fn invalid_store_json_surfaces_user_errors() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("credentials.json");
        std::fs::write(&path, "{not-json").expect("write invalid json");

        let load_error = load_from_path(&path, None).expect_err("invalid load must fail");
        assert!(load_error.to_string().contains("not valid JSON"));

        let save_error = save_to_path(
            &path,
            None,
            sample_credentials("verdictan", "https://api.example"),
        )
        .expect_err("invalid save must fail");
        assert!(save_error.to_string().contains("not valid JSON"));

        let delete_error = delete_from_path(&path, None).expect_err("invalid delete must fail");
        assert!(delete_error.to_string().contains("not valid JSON"));
    }

    #[test]
    fn non_file_paths_surface_read_errors() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("credentials-dir");
        std::fs::create_dir(&path).expect("create dir");

        let load_error = load_from_path(&path, None).expect_err("directory load must fail");
        assert!(load_error
            .to_string()
            .contains("failed to read credential store"));

        let save_error = save_to_path(
            &path,
            None,
            sample_credentials("verdictan", "https://api.example"),
        )
        .expect_err("directory save must fail");
        assert!(save_error
            .to_string()
            .contains("failed to read credential store"));

        let delete_error = delete_from_path(&path, None).expect_err("directory delete must fail");
        assert!(delete_error
            .to_string()
            .contains("failed to read credential store"));
    }

    #[test]
    fn write_store_surfaces_parent_directory_creation_errors() {
        let temp = tempdir().expect("tempdir");
        let parent = temp.path().join("not-a-directory");
        std::fs::write(&parent, "occupied").expect("write parent file");

        let path = parent.join("credentials.json");
        let error = write_store(&path, &CredentialStoreFile::default())
            .expect_err("write with file parent must fail");
        assert!(error
            .to_string()
            .contains("failed to create credential directory"));
    }

    #[test]
    fn delete_from_path_only_removes_selected_profile() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("credentials.json");
        let first = sample_credentials("vdt_alpha", "https://api.alpha.example");
        let second = sample_credentials("vdt_beta", "https://api.beta.example");

        save_to_path(&path, None, first.clone()).expect("save default");
        save_to_path(&path, Some("workspace"), second.clone()).expect("save workspace");

        assert!(delete_from_path(&path, Some("workspace")).expect("delete workspace"));
        assert_credentials_eq(load_from_path(&path, None).expect("load default"), &first);
        assert!(load_from_path(&path, Some("workspace"))
            .expect("load workspace after delete")
            .is_none());
    }

    #[test]
    fn delete_keeps_other_profiles_when_target_profile_is_absent() {
        let _lock = crate::config::test_env_lock().lock().expect("env lock");
        let _guard = EnvGuard::capture();
        let temp = tempdir().expect("tempdir");
        std::env::set_var("VERDICTAN_TEST_HOME", temp.path());
        std::env::remove_var("HOME");

        let default_credentials = sample_credentials("vdt_default", "https://api.default.example");
        let workspace_credentials =
            sample_credentials("vdt_workspace", "https://api.workspace.example");

        save(None, default_credentials.clone()).expect("save default profile");
        save(Some("workspace"), workspace_credentials.clone()).expect("save workspace profile");

        let stored_path = temp.path().join(".verdictan").join("credentials.json");
        let before_delete = std::fs::read_to_string(&stored_path).expect("read before delete");

        assert!(!delete(Some("missing")).expect("delete missing profile"));
        assert_eq!(
            std::fs::read_to_string(&stored_path).expect("read after delete"),
            before_delete
        );
        assert_credentials_eq(
            load(None).expect("load default after missing delete"),
            &default_credentials,
        );
        assert_credentials_eq(
            load(Some("workspace")).expect("load workspace after missing delete"),
            &workspace_credentials,
        );
    }

    #[test]
    fn credentials_path_prefers_verdictan_test_home_then_home_and_profile_name_defaults() {
        let _lock = crate::config::test_env_lock().lock().expect("env lock");
        let _guard = EnvGuard::capture();
        let temp = tempdir().expect("tempdir");

        std::env::set_var("VERDICTAN_TEST_HOME", temp.path().join("preferred-home"));
        std::env::set_var("HOME", temp.path().join("fallback-home"));
        assert_eq!(
            credentials_path().expect("credentials path"),
            temp.path()
                .join("preferred-home")
                .join(".verdictan")
                .join("credentials.json")
        );

        std::env::remove_var("VERDICTAN_TEST_HOME");
        assert_eq!(
            credentials_path().expect("fallback credentials path"),
            temp.path()
                .join("fallback-home")
                .join(".verdictan")
                .join("credentials.json")
        );

        assert_eq!(profile_name(None), "default");
        assert_eq!(profile_name(Some("   ")), "default");
        assert_eq!(profile_name(Some(" \tworkspace\n ")), "workspace");
        assert_eq!(profile_name(Some("workspace")), "workspace");
    }

    #[test]
    fn org_state_dir_uses_test_home_and_secures_directory() {
        let _lock = crate::config::test_env_lock().lock().expect("env lock");
        let _guard = EnvGuard::capture();
        let temp = tempdir().expect("tempdir");
        std::env::set_var("VERDICTAN_TEST_HOME", temp.path());
        std::env::remove_var("HOME");

        let dir = org_state_dir("org_abc").expect("org state dir");
        assert_eq!(
            dir,
            temp.path().join(".verdictan").join("orgs").join("org_abc")
        );
        assert!(dir.exists());

        #[cfg(unix)]
        {
            let mode = std::fs::metadata(&dir)
                .expect("dir metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700);
        }
    }

    #[test]
    fn org_state_dir_surfaces_creation_errors_when_home_path_is_a_file() {
        let _lock = crate::config::test_env_lock().lock().expect("env lock");
        let _guard = EnvGuard::capture();
        let temp = tempdir().expect("tempdir");
        let blocked_home = temp.path().join("blocked-home");
        std::fs::write(&blocked_home, "occupied").expect("write blocked home file");
        std::env::set_var("VERDICTAN_TEST_HOME", &blocked_home);
        std::env::remove_var("HOME");

        let error =
            org_state_dir("org_abc").expect_err("org state dir with blocked home must fail");
        assert!(error
            .to_string()
            .contains("failed to create org state directory"));
    }

    #[test]
    fn public_helpers_surface_path_errors_when_test_home_is_a_file() {
        let _lock = crate::config::test_env_lock().lock().expect("env lock");
        let _guard = EnvGuard::capture();
        let temp = tempdir().expect("tempdir");
        let blocked_home = temp.path().join("blocked-home");
        std::fs::write(&blocked_home, "occupied").expect("write blocked home file");
        std::env::set_var("VERDICTAN_TEST_HOME", &blocked_home);
        std::env::remove_var("HOME");

        let load_error = load(None).expect_err("load with blocked home must fail");
        assert!(load_error
            .to_string()
            .contains("failed to read credential store"));

        let save_error = save(None, sample_credentials("verdictan", "https://api.example"))
            .expect_err("save with blocked home must fail");
        assert!(save_error
            .to_string()
            .contains("failed to read credential store"));

        let delete_error = delete(None).expect_err("delete with blocked home must fail");
        assert!(delete_error
            .to_string()
            .contains("failed to read credential store"));
    }

    #[test]
    fn public_helpers_error_when_home_is_unavailable() {
        let _lock = crate::config::test_env_lock().lock().expect("env lock");
        let _guard = EnvGuard::capture();
        std::env::remove_var("VERDICTAN_TEST_HOME");
        std::env::remove_var("HOME");

        let load_error = load(None).expect_err("missing home load must fail");
        assert!(load_error
            .to_string()
            .contains("unable to determine HOME directory"));

        let save_error = save(None, sample_credentials("verdictan", "https://api.example"))
            .expect_err("missing home save must fail");
        assert!(save_error
            .to_string()
            .contains("unable to determine HOME directory"));

        let delete_error = delete(None).expect_err("missing home delete must fail");
        assert!(delete_error
            .to_string()
            .contains("unable to determine HOME directory"));

        let org_dir_error = org_state_dir("org_123").expect_err("missing home org dir must fail");
        assert!(org_dir_error
            .to_string()
            .contains("unable to determine HOME directory"));
    }

    /// Unit-test entrypoint for credential-store coverage.
    ///
    /// Table-driven replacement for `cli/tests/oauth_token_persistence.rs` covering
    /// control-plane OAuth token persistence contract scenarios.
    mod oauth_token_persistence_cases {
        use super::*;
        use crate::gateway::oauth_token_store::{CachedOAuthToken, OAuthTokenStore};
        use crate::testing::oauth_mock_api::{start_mock_oauth_api, start_override_get_oauth_api};
        use axum::http::StatusCode;
        use std::time::Duration;

        fn fresh_token(expires_in_secs: u64) -> CachedOAuthToken {
            CachedOAuthToken::from_expires_in(
                "test-access-token".to_string(),
                Some("test-refresh-token".to_string()),
                "Bearer".to_string(),
                Duration::from_secs(expires_in_secs),
            )
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum OAuthPersistenceScenario {
            PutSendsToApi,
            ColdCacheFetchesFromApi,
            WarmCacheSkipsApi,
            ExpiredInMemoryFetchesFromApi,
            StaleCacheReturnsTokenOnNotFound,
            ColdCacheReturnsNoneOnInvalidJson,
            StaleCacheReturnsTokenOnApiError,
        }

        pub(super) async fn run_matrix() {
            let scenarios = [
                OAuthPersistenceScenario::PutSendsToApi,
                OAuthPersistenceScenario::ColdCacheFetchesFromApi,
                OAuthPersistenceScenario::WarmCacheSkipsApi,
                OAuthPersistenceScenario::ExpiredInMemoryFetchesFromApi,
                OAuthPersistenceScenario::StaleCacheReturnsTokenOnNotFound,
                OAuthPersistenceScenario::ColdCacheReturnsNoneOnInvalidJson,
                OAuthPersistenceScenario::StaleCacheReturnsTokenOnApiError,
            ];

            for scenario in scenarios {
                match scenario {
                    OAuthPersistenceScenario::PutSendsToApi => {
                        let (base_url, mock_state, _shutdown) = start_mock_oauth_api().await;
                        let store = OAuthTokenStore::new_isolated();
                        store.configure_api_persistence(base_url, "test-token".to_string());

                        store.put("provider:test".to_string(), fresh_token(3600));
                        mock_state.wait_for_puts(1).await;

                        let calls = mock_state.put_calls_snapshot();
                        assert_eq!(calls.len(), 1, "{scenario:?}");
                        assert_eq!(calls[0].0, "provider:test");
                    }
                    OAuthPersistenceScenario::ColdCacheFetchesFromApi => {
                        let (base_url, mock_state, _shutdown) = start_mock_oauth_api().await;
                        {
                            let token = fresh_token(3600);
                            let serialized = serde_json::to_value(&token).expect("serialise token");
                            mock_state
                                .store
                                .lock()
                                .expect("store lock")
                                .insert("provider:cold".to_string(), serialized);
                        }

                        let store = OAuthTokenStore::new_isolated();
                        store.configure_api_persistence(base_url, "test-token".to_string());

                        let result = store.get("provider:cold");
                        assert!(result.is_some(), "{scenario:?}");
                        assert_eq!(result.unwrap().access_token, "test-access-token");
                        assert_eq!(mock_state.get_call_count(), 1);
                    }
                    OAuthPersistenceScenario::WarmCacheSkipsApi => {
                        let (base_url, mock_state, _shutdown) = start_mock_oauth_api().await;
                        let store = OAuthTokenStore::new_isolated();
                        store.configure_api_persistence(base_url, "test-token".to_string());

                        store.put("provider:warm".to_string(), fresh_token(3600));
                        mock_state.wait_for_puts(1).await;
                        mock_state.get_calls.lock().expect("get_calls lock").clear();

                        let result = store.get("provider:warm");
                        assert!(result.is_some(), "{scenario:?}");
                        assert_eq!(mock_state.get_call_count(), 0);
                    }
                    OAuthPersistenceScenario::ExpiredInMemoryFetchesFromApi => {
                        let (base_url, mock_state, _shutdown) = start_mock_oauth_api().await;
                        let store = OAuthTokenStore::new_isolated();
                        store.configure_api_persistence(base_url, "test-token".to_string());

                        store.put("provider:expired".to_string(), fresh_token(0));
                        mock_state.wait_for_puts(1).await;

                        {
                            let token = CachedOAuthToken::from_expires_in(
                                "fresh-from-api".to_string(),
                                Some("fresh-refresh-token".to_string()),
                                "Bearer".to_string(),
                                Duration::from_secs(7200),
                            );
                            let serialized = serde_json::to_value(&token).expect("serialise token");
                            mock_state
                                .store
                                .lock()
                                .expect("store lock")
                                .insert("provider:expired".to_string(), serialized);
                        }
                        mock_state.get_calls.lock().expect("get_calls lock").clear();

                        let result = store
                            .get("provider:expired")
                            .expect("{scenario:?}: expected fresh token from API");
                        assert_eq!(result.access_token, "fresh-from-api");
                        assert_eq!(mock_state.get_call_count(), 1);
                    }
                    OAuthPersistenceScenario::StaleCacheReturnsTokenOnNotFound => {
                        let (base_url, mock_state, _shutdown) = start_mock_oauth_api().await;
                        let store = OAuthTokenStore::new_isolated();
                        store.put("provider:stale-miss".to_string(), fresh_token(0));
                        store.configure_api_persistence(base_url, "test-token".to_string());

                        let result = store
                            .get("provider:stale-miss")
                            .expect("{scenario:?}: stale token should be returned");
                        assert_eq!(result.access_token, "test-access-token");
                        assert!(!result.is_fresh());
                        assert_eq!(mock_state.get_call_count(), 1);
                    }
                    OAuthPersistenceScenario::ColdCacheReturnsNoneOnInvalidJson => {
                        let (base_url, get_calls, _shutdown) =
                            start_override_get_oauth_api(StatusCode::OK, "not-json").await;
                        let store = OAuthTokenStore::new_isolated();
                        store.configure_api_persistence(base_url, "test-token".to_string());

                        let result = store.get("provider:invalid-json");
                        assert!(result.is_none(), "{scenario:?}");
                        assert_eq!(get_calls.lock().expect("get_calls lock").len(), 1);
                    }
                    OAuthPersistenceScenario::StaleCacheReturnsTokenOnApiError => {
                        let (base_url, get_calls, _shutdown) = start_override_get_oauth_api(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "{\"error\":\"boom\"}",
                        )
                        .await;
                        let store = OAuthTokenStore::new_isolated();
                        store.put("provider:stale-error".to_string(), fresh_token(0));
                        store.configure_api_persistence(base_url, "test-token".to_string());

                        let result = store
                            .get("provider:stale-error")
                            .expect("{scenario:?}: stale token should be returned");
                        assert_eq!(result.access_token, "test-access-token");
                        assert!(!result.is_fresh());
                        assert_eq!(get_calls.lock().expect("get_calls lock").len(), 1);
                    }
                }
            }
        }
    }

    /// Destination test symbol for credential-store coverage.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn oauth_token_persistence_matrix() {
        oauth_token_persistence_cases::run_matrix().await;
    }
}
