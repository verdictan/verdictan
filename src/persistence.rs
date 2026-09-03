// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::Digest;
use uuid::Uuid;

use crate::error::CliError;

/// Owner-only file mode for a file that holds secret material.
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;

/// Result of a private write, which tells the caller whether the target
/// platform actually restricted the file mode.
///
/// A caller must branch on this value. A target without Unix file modes gives
/// no restriction at all, and the caller has to report that outcome instead of
/// treating the write as protected.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrivateFileMode {
    /// The file had owner-only permissions from the moment of creation.
    Restricted,
    /// The target platform has no Unix file mode. The file keeps the
    /// permissions that it inherits from its parent directory.
    Unsupported,
}

/// Returns the protection that a private write can give on this target.
const fn private_file_mode_support() -> PrivateFileMode {
    #[cfg(any(unix, windows))]
    {
        PrivateFileMode::Restricted
    }
    #[cfg(not(any(unix, windows)))]
    {
        PrivateFileMode::Unsupported
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    write_atomically(path, bytes, false)
}

/// Writes `bytes` to `path` atomically with owner-only permissions.
///
/// The temporary file gets mode 0600 before the first byte lands, so the
/// secret never exists on disk with a wider mode. The returned value states
/// whether the target platform applied that restriction. The caller must
/// report an `Unsupported` result to the operator.
pub(crate) fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<PrivateFileMode, CliError> {
    write_atomically(path, bytes, true)?;
    Ok(apply_private_protection(path))
}

fn apply_private_protection(path: &Path) -> PrivateFileMode {
    #[cfg(unix)]
    {
        let _ = path;
        PrivateFileMode::Restricted
    }
    #[cfg(windows)]
    {
        if crate::windows_private_acl::restrict_path_to_owner(path) {
            PrivateFileMode::Restricted
        } else {
            PrivateFileMode::Unsupported
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        PrivateFileMode::Unsupported
    }
}

#[cfg(unix)]
fn open_temporary_file(path: &Path, private: bool) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    if private {
        options.mode(PRIVATE_FILE_MODE);
    }
    options.open(path)
}

#[cfg(not(unix))]
fn open_temporary_file(path: &Path, _private: bool) -> std::io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

fn write_atomically(path: &Path, bytes: &[u8], private: bool) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            CliError::internal(format!(
                "failed to create parent directory {}: {error}",
                parent.display()
            ))
        })?;
    }

    let tmp_path = temporary_path(path);
    let mut file = open_temporary_file(&tmp_path, private).map_err(|error| {
        CliError::internal(format!(
            "failed to create temporary file {}: {error}",
            tmp_path.display()
        ))
    })?;

    if let Err(error) = file.write_all(bytes) {
        drop(file);
        cleanup_temporary_file(&tmp_path);
        return Err(CliError::internal(format!(
            "failed to write temporary file {}: {error}",
            tmp_path.display()
        )));
    }
    if let Err(error) = file.sync_all() {
        drop(file);
        cleanup_temporary_file(&tmp_path);
        return Err(CliError::internal(format!(
            "failed to sync temporary file {}: {error}",
            tmp_path.display()
        )));
    }
    drop(file);

    #[cfg(windows)]
    if private {
        let _ = crate::windows_private_acl::restrict_path_to_owner(&tmp_path);
    }

    fs::rename(&tmp_path, path).map_err(|error| {
        cleanup_temporary_file(&tmp_path);
        CliError::internal(format!(
            "failed to replace file {}: {error}",
            path.display()
        ))
    })?;

    if let Some(parent) = path.parent() {
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
    }

    Ok(())
}

fn cleanup_temporary_file(path: &Path) {
    let _ = fs::remove_file(path);
}

pub(crate) fn atomic_write_json<T: serde::Serialize>(
    path: &Path,
    value: &T,
    context: &str,
) -> Result<(), CliError> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| CliError::internal(format!("failed to serialize {context}: {error}")))?;
    atomic_write(path, &bytes)
}

fn temporary_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("tmp");
    path.with_file_name(format!("{}.{}.tmp", file_name, Uuid::new_v4()))
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
    use serde::ser::Error as _;
    use serde::{Serialize, Serializer};
    use tempfile::tempdir;

    #[derive(Serialize)]
    struct ExamplePayload<'a> {
        message: &'a str,
        count: u32,
    }

    struct FailingPayload;

    impl Serialize for FailingPayload {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Err(S::Error::custom("payload boom"))
        }
    }

    #[test]
    fn sha256_hex_matches_known_value() {
        assert_eq!(
            sha256_hex(b"verdictan"),
            "1bdf7f03eb5bae9a941f5e4c2427325fe5f70de5c211df075d35dba20ee78f9e"
        );
    }

    #[test]
    fn atomic_write_creates_parent_dirs_and_replaces_contents() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("nested").join("state.txt");

        atomic_write(&path, b"first").expect("initial write");
        atomic_write(&path, b"second").expect("replace write");

        assert_eq!(std::fs::read(&path).expect("read file"), b"second");

        let tmp_leftovers: Vec<_> = std::fs::read_dir(path.parent().expect("parent"))
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(
            tmp_leftovers.is_empty(),
            "unexpected temporary files left behind: {tmp_leftovers:?}"
        );
    }

    #[cfg(unix)]
    fn file_mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;

        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_private_creates_owner_only_file() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("nested").join("token.env");

        let protection =
            atomic_write_private(&path, b"VERDICTAN_API_TOKEN=secret\n").expect("private write");

        assert_eq!(protection, PrivateFileMode::Restricted);
        assert_eq!(file_mode(&path), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_private_narrows_an_existing_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("token.env");
        std::fs::write(&path, b"stale").expect("seed file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("widen mode");
        assert_eq!(file_mode(&path), 0o644);

        let _ = atomic_write_private(&path, b"fresh").expect("private write");

        assert_eq!(file_mode(&path), 0o600);
        assert_eq!(std::fs::read(&path).expect("read file"), b"fresh");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_leaves_the_umask_mode_for_a_non_secret_file() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("unit.service");

        atomic_write(&path, b"[Service]\n").expect("plain write");

        assert_ne!(file_mode(&path), 0o600);
    }

    #[test]
    fn private_file_mode_support_matches_the_target_family() {
        if cfg!(unix) || cfg!(windows) {
            assert_eq!(private_file_mode_support(), PrivateFileMode::Restricted);
        } else {
            assert_eq!(private_file_mode_support(), PrivateFileMode::Unsupported);
        }
    }

    #[test]
    fn atomic_write_json_serializes_pretty_json() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("config").join("payload.json");

        atomic_write_json(
            &path,
            &ExamplePayload {
                message: "ok",
                count: 2,
            },
            "example payload",
        )
        .expect("write json");

        let contents = std::fs::read_to_string(&path).expect("read json");
        assert!(contents.contains("\n  \"message\": \"ok\","));
        assert!(contents.contains("\n  \"count\": 2\n"));
    }

    #[test]
    fn atomic_write_errors_when_parent_path_is_a_file() {
        let temp = tempdir().expect("tempdir");
        let parent_file = temp.path().join("not-a-directory");
        std::fs::write(&parent_file, b"occupied").expect("seed parent file");

        let err = atomic_write(&parent_file.join("child.txt"), b"payload")
            .expect_err("write should fail");
        assert!(err
            .to_string()
            .contains("failed to create parent directory"));
    }

    #[test]
    fn atomic_write_errors_when_target_path_is_a_directory_and_cleans_up_tmp_file() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("existing-dir");
        std::fs::create_dir(&path).expect("create target directory");

        let err = atomic_write(&path, b"payload").expect_err("write should fail");
        assert!(err.to_string().contains("failed to replace file"));

        let tmp_leftovers: Vec<_> = std::fs::read_dir(temp.path())
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(
            tmp_leftovers.is_empty(),
            "unexpected temporary files left behind: {tmp_leftovers:?}"
        );
    }

    #[test]
    fn atomic_write_json_surfaces_serialization_context() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("config").join("payload.json");

        let err = atomic_write_json(&path, &FailingPayload, "failing payload")
            .expect_err("serialization should fail");
        assert!(err
            .to_string()
            .contains("failed to serialize failing payload: payload boom"));
        assert!(!path.exists(), "json file should not be created on failure");
    }

    #[test]
    fn cleanup_temporary_file_removes_existing_file_and_ignores_missing_paths() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("stale.tmp");
        std::fs::write(&path, b"stale").expect("write tmp file");

        cleanup_temporary_file(&path);
        assert!(
            !path.exists(),
            "cleanup should remove existing temporary file"
        );

        cleanup_temporary_file(&path);
        assert!(
            !path.exists(),
            "cleanup should ignore missing temporary file"
        );
    }
}
