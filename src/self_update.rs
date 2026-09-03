// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Self-update guardrails for the `verdictan-update` companion binary.

use std::path::{Path, PathBuf};

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::CliError;
use crate::supervisor::{default_state_dir, SupervisorStateStore};

const SUPERVISOR_UPGRADE_HINT: &str =
    "Use `verdictan gateway upgrade` for service-managed gateway upgrades.";

const MAX_SIGNED_MANIFEST_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SignedUpdateManifest {
    pub version: String,
    pub artifact_url: String,
    pub sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct SignedUpdateOptions {
    pub manifest_url: String,
    pub public_key_base64: String,
    pub current_version: String,
    pub target_path: PathBuf,
    pub allow_downgrade: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedUpdateOutcome {
    AlreadyCurrent,
    Updated { version: String },
}

pub fn manifest_signed_bytes(manifest: &SignedUpdateManifest) -> Vec<u8> {
    format!(
        "verdictan-signed-update-v1\n{}\n{}\n{}\n",
        manifest.version, manifest.artifact_url, manifest.sha256
    )
    .into_bytes()
}

fn verify_manifest_signature(
    manifest: &SignedUpdateManifest,
    public_key_base64: &str,
) -> Result<(), CliError> {
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(public_key_base64.trim())
        .map_err(|_| CliError::user("update public key is not valid base64"))?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| CliError::user("update public key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| CliError::user("update public key is invalid"))?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(manifest.signature.trim())
        .map_err(|_| CliError::user("update manifest signature is not valid base64"))?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| CliError::user("update manifest signature must be 64 bytes"))?;
    verifying_key
        .verify(
            &manifest_signed_bytes(manifest),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| CliError::user("update manifest signature verification failed"))
}

fn update_is_required(
    current: &str,
    target: &str,
    allow_downgrade: bool,
) -> Result<bool, CliError> {
    let current = semver::Version::parse(current)
        .map_err(|e| CliError::user(format!("current update version is invalid: {e}")))?;
    let target = semver::Version::parse(target)
        .map_err(|e| CliError::user(format!("target update version is invalid: {e}")))?;
    if target == current {
        return Ok(false);
    }
    if target < current && !allow_downgrade {
        return Err(CliError::user(format!(
            "refusing update downgrade from {current} to {target}"
        )));
    }
    Ok(true)
}

pub async fn apply_signed_update(
    options: &SignedUpdateOptions,
) -> Result<SignedUpdateOutcome, CliError> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .map_err(|e| CliError::internal(format!("failed to initialize update client: {e}")))?;
    let manifest_response = client
        .get(&options.manifest_url)
        .send()
        .await
        .map_err(|e| CliError::user(format!("failed to download update manifest: {e}")))?
        .error_for_status()
        .map_err(|e| CliError::user(format!("failed to download update manifest: {e}")))?;
    let manifest_bytes = manifest_response
        .bytes()
        .await
        .map_err(|e| CliError::user(format!("failed to read update manifest: {e}")))?;
    if manifest_bytes.len() > MAX_SIGNED_MANIFEST_BYTES {
        return Err(CliError::user(
            "update manifest exceeds the 65536 byte limit",
        ));
    }
    let manifest: SignedUpdateManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| CliError::user(format!("update manifest is invalid JSON: {e}")))?;
    verify_manifest_signature(&manifest, &options.public_key_base64)?;
    if !update_is_required(
        &options.current_version,
        &manifest.version,
        options.allow_downgrade,
    )? {
        return Ok(SignedUpdateOutcome::AlreadyCurrent);
    }

    let artifact = client
        .get(&manifest.artifact_url)
        .send()
        .await
        .map_err(|e| CliError::user(format!("failed to download update artifact: {e}")))?
        .error_for_status()
        .map_err(|e| CliError::user(format!("failed to download update artifact: {e}")))?
        .bytes()
        .await
        .map_err(|e| CliError::user(format!("failed to read update artifact: {e}")))?;
    let actual_sha256 = hex::encode(Sha256::digest(&artifact));
    if actual_sha256 != manifest.sha256.to_ascii_lowercase() {
        return Err(CliError::user(format!(
            "update artifact checksum mismatch: expected {}, got {actual_sha256}",
            manifest.sha256
        )));
    }
    atomic_replace_and_validate(&options.target_path, &artifact)?;
    Ok(SignedUpdateOutcome::Updated {
        version: manifest.version,
    })
}

fn atomic_replace_and_validate(target: &Path, artifact: &[u8]) -> Result<(), CliError> {
    let parent = target.parent().ok_or_else(|| {
        CliError::user(format!("update target {} has no parent", target.display()))
    })?;
    let file_name = target
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            CliError::user(format!(
                "update target {} has an invalid name",
                target.display()
            ))
        })?;
    let temporary = parent.join(format!(".{file_name}.verdictan-update-new"));
    let backup = parent.join(format!(".{file_name}.verdictan-update-backup"));
    let metadata = std::fs::metadata(target).map_err(|e| {
        CliError::user(format!(
            "update target {} is not readable: {e}",
            target.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(CliError::user(format!(
            "update target {} must be a file",
            target.display()
        )));
    }
    let _ = std::fs::remove_file(&temporary);
    let _ = std::fs::remove_file(&backup);
    let result = (|| -> Result<(), CliError> {
        use std::io::Write;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|e| CliError::user(format!("failed to create update file: {e}")))?;
        output
            .write_all(artifact)
            .and_then(|_| output.sync_all())
            .map_err(|e| CliError::user(format!("failed to write update file: {e}")))?;
        std::fs::set_permissions(&temporary, metadata.permissions())
            .map_err(|e| CliError::user(format!("failed to set update permissions: {e}")))?;
        std::fs::rename(target, &backup)
            .map_err(|e| CliError::user(format!("failed to checkpoint current binary: {e}")))?;
        if let Err(error) = std::fs::rename(&temporary, target) {
            let _ = std::fs::rename(&backup, target);
            return Err(CliError::user(format!(
                "failed to install update atomically: {error}"
            )));
        }
        let validation = std::process::Command::new(target).arg("--version").output();
        match validation {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                let _ = std::fs::remove_file(target);
                let _ = std::fs::rename(&backup, target);
                return Err(CliError::user(format!(
                    "updated binary validation failed with status {} and was rolled back",
                    output.status
                )));
            }
            Err(error) => {
                let _ = std::fs::remove_file(target);
                let _ = std::fs::rename(&backup, target);
                return Err(CliError::user(format!(
                    "updated binary validation failed: {error}; update was rolled back"
                )));
            }
        }
        std::fs::remove_file(&backup)
            .map_err(|e| CliError::user(format!("failed to remove update checkpoint: {e}")))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// Refuse in-place self-update when supervisor state lists a managed gateway instance.
pub fn guard_supervisor_managed_install() -> Result<(), CliError> {
    let state_dir = default_state_dir()?;
    guard_supervisor_managed_install_at(state_dir)
}

pub fn guard_supervisor_managed_install_at(state_dir: impl Into<PathBuf>) -> Result<(), CliError> {
    let store = SupervisorStateStore::load(state_dir)?;
    let instances = store.list_instances();
    if instances.is_empty() {
        return Ok(());
    }

    let ids: Vec<String> = instances.into_iter().map(|item| item.instance_id).collect();
    Err(CliError::user(format!(
        "verdictan-update cannot replace the binary while supervisor manages gateway instance(s): {}. {}",
        ids.join(", "),
        SUPERVISOR_UPGRADE_HINT
    )))
}

#[cfg(test)]
mod tests {
    use super::{guard_supervisor_managed_install_at, SUPERVISOR_UPGRADE_HINT};
    use crate::instances::{GatewayInstanceId, GatewayInstanceSpec, PolicyConfigSource};
    use crate::supervisor::SupervisorStateStore;

    fn sample_spec(instance_id: &str) -> GatewayInstanceSpec {
        GatewayInstanceSpec::new(
            GatewayInstanceId::new(instance_id).unwrap(),
            instance_id,
            instance_id,
            "127.0.0.1:41001",
            "https://api.openai.com",
            None,
            None,
            None,
            "block",
            PolicyConfigSource::path("/tmp/policy.yaml"),
            16,
            None,
            true,
        )
        .unwrap()
    }

    #[test]
    fn guard_allows_update_when_supervisor_state_is_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        guard_supervisor_managed_install_at(dir.path().to_path_buf())
            .expect("empty supervisor state");
    }

    #[test]
    fn guard_refuses_update_when_supervisor_lists_managed_instance() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = SupervisorStateStore::load(dir.path()).expect("load store");
        store
            .create_instance(sample_spec("prod-gw"))
            .expect("create instance");

        let error = guard_supervisor_managed_install_at(dir.path().to_path_buf())
            .expect_err("managed instance guard");
        let message = error.to_string();
        assert!(message.contains("prod-gw"), "message: {message}");
        assert!(
            message.contains(SUPERVISOR_UPGRADE_HINT),
            "message: {message}"
        );
    }
}
