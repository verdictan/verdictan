// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Customer-side verification of Trail Merkle-root anchor receipts.
//!
//! Anchor receipts are DSSE envelopes with payload type
//! `application/vnd.verdictan.trail-anchor.v1+json`. Customers verify them
//! offline (or alongside `verdictan trail verify`) against a published Ed25519 public
//! key from `GET /v1/trail/public-key`.

use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::CliError;

pub(crate) const PAYLOAD_TYPE_TRAIL_ANCHOR: &str = "application/vnd.verdictan.trail-anchor.v1+json";
pub(crate) const BACKEND_S3_OBJECT_LOCK: &str = "s3_object_lock";
pub(crate) const BACKEND_FILESYSTEM_WORM: &str = "filesystem_worm";

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    pub(crate) payload_type: String,
    pub(crate) payload: String,
    pub(crate) signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DsseSignature {
    pub(crate) keyid: String,
    pub(crate) sig: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub(crate) struct AnchorReceipt {
    pub(crate) receipt_version: String,
    pub(crate) org_id: String,
    pub(crate) trail_arn: String,
    pub(crate) window_start: String,
    pub(crate) window_end: String,
    pub(crate) merkle_algorithm: String,
    pub(crate) merkle_root: String,
    pub(crate) leaf_hashes: Vec<String>,
    pub(crate) leaf_kind: String,
    #[serde(default)]
    pub(crate) previous_anchor_merkle_root: Option<String>,
    pub(crate) backend: String,
    pub(crate) storage_key: String,
    pub(crate) published_at: String,
}

#[derive(Debug, Clone)]
pub(crate) struct AnchorVerifyResult {
    pub(crate) receipt: AnchorReceipt,
    pub(crate) key_id: String,
    pub(crate) merkle_root: String,
}

pub(crate) fn verify_anchor_receipt_file(
    path: &Path,
    public_key_b64: &str,
) -> Result<AnchorVerifyResult, CliError> {
    let bytes = std::fs::read(path).map_err(|err| {
        CliError::user(format!(
            "failed to read --anchor-receipt '{}': {err}",
            path.display()
        ))
    })?;
    verify_anchor_receipt_bytes(&bytes, public_key_b64)
}

pub(crate) fn verify_anchor_receipt_bytes(
    envelope_bytes: &[u8],
    public_key_b64: &str,
) -> Result<AnchorVerifyResult, CliError> {
    let envelope: DsseEnvelope = serde_json::from_slice(envelope_bytes).map_err(|err| {
        CliError::user(format!(
            "anchor receipt is not a valid DSSE envelope JSON: {err}"
        ))
    })?;
    verify_anchor_envelope(&envelope, public_key_b64)
}

pub(crate) fn verify_anchor_envelope(
    envelope: &DsseEnvelope,
    public_key_b64: &str,
) -> Result<AnchorVerifyResult, CliError> {
    if envelope.payload_type != PAYLOAD_TYPE_TRAIL_ANCHOR {
        return Err(CliError::user(format!(
            "anchor receipt payloadType must be {PAYLOAD_TYPE_TRAIL_ANCHOR}, got '{}'",
            envelope.payload_type
        )));
    }

    let verifying_key = decode_verifying_key(public_key_b64)?;
    let payload_bytes = B64
        .decode(&envelope.payload)
        .map_err(|_| CliError::user("anchor receipt payload is not valid base64"))?;
    let signature_entry = envelope
        .signatures
        .first()
        .ok_or_else(|| CliError::user("anchor receipt DSSE envelope has no signatures"))?;
    let sig_bytes = B64
        .decode(&signature_entry.sig)
        .map_err(|_| CliError::user("anchor receipt signature is not valid base64"))?;
    if sig_bytes.len() != 64 {
        return Err(CliError::user(
            "anchor receipt signature must be 64 bytes (Ed25519)",
        ));
    }
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_array);
    let pae_bytes = dsse_pae(&envelope.payload_type, &payload_bytes);
    verifying_key
        .verify(&pae_bytes, &signature)
        .map_err(|_| CliError::user("anchor receipt DSSE signature verification failed"))?;

    let receipt: AnchorReceipt = serde_json::from_slice(&payload_bytes)
        .map_err(|err| CliError::user(format!("anchor receipt payload JSON is invalid: {err}")))?;

    if receipt.merkle_algorithm != "SHA-256" {
        return Err(CliError::user(format!(
            "unsupported merkle_algorithm '{}'",
            receipt.merkle_algorithm
        )));
    }
    if receipt.backend != BACKEND_S3_OBJECT_LOCK && receipt.backend != BACKEND_FILESYSTEM_WORM {
        return Err(CliError::user(format!(
            "unsupported anchor backend '{}'; expected {BACKEND_S3_OBJECT_LOCK} or {BACKEND_FILESYSTEM_WORM}",
            receipt.backend
        )));
    }

    let recomputed = compute_merkle_root(&receipt.leaf_hashes)?;
    if recomputed != receipt.merkle_root {
        return Err(CliError::user(format!(
            "anchor merkle_root mismatch: receipt has {}, recomputed {recomputed}",
            receipt.merkle_root
        )));
    }

    Ok(AnchorVerifyResult {
        merkle_root: receipt.merkle_root.clone(),
        key_id: signature_entry.keyid.clone(),
        receipt,
    })
}

pub(crate) fn compute_merkle_root(leaf_hashes_hex: &[String]) -> Result<String, CliError> {
    if leaf_hashes_hex.is_empty() {
        return Ok(hex::encode(Sha256::digest(b"")));
    }

    let mut level: Vec<[u8; 32]> = Vec::with_capacity(leaf_hashes_hex.len());
    for hex_hash in leaf_hashes_hex {
        let bytes = hex::decode(hex_hash)
            .map_err(|_| CliError::user(format!("invalid leaf hash hex '{hex_hash}'")))?;
        let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            CliError::user(format!(
                "leaf hash must be 32 bytes; '{hex_hash}' is {} bytes",
                bytes.len()
            ))
        })?;
        level.push(array);
    }

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut index = 0;
        while index < level.len() {
            if index + 1 < level.len() {
                let mut hasher = Sha256::new();
                hasher.update(level[index]);
                hasher.update(level[index + 1]);
                next.push(hasher.finalize().into());
                index += 2;
            } else {
                next.push(level[index]);
                index += 1;
            }
        }
        level = next;
    }

    Ok(hex::encode(level[0]))
}

fn decode_verifying_key(public_key_b64: &str) -> Result<VerifyingKey, CliError> {
    let bytes = B64.decode(public_key_b64.trim()).map_err(|_| {
        CliError::user("trail public key must be standard-base64-encoded Ed25519 public key bytes")
    })?;
    let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        CliError::user(format!(
            "trail public key must be 32 bytes; got {}",
            bytes.len()
        ))
    })?;
    VerifyingKey::from_bytes(&array)
        .map_err(|_| CliError::user("trail public key material is not a valid Ed25519 key"))
}

fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"DSSEv1 ");
    buf.extend_from_slice(payload_type.len().to_string().as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(payload_type.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(payload.len().to_string().as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(payload);
    buf
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const DEV_SEED: [u8; 32] = [
        0x42, 0x84, 0x21, 0x09, 0x18, 0x37, 0x56, 0x75, 0x94, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54,
        0x76, 0x98, 0xba, 0xdc, 0xfe, 0x11, 0x22, 0x33, 0x44, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd,
    ];

    fn sign_receipt(receipt: &serde_json::Value) -> (DsseEnvelope, String) {
        let signing = SigningKey::from_bytes(&DEV_SEED);
        let payload = serde_json::to_vec(receipt).unwrap();
        let pae = dsse_pae(PAYLOAD_TYPE_TRAIL_ANCHOR, &payload);
        let sig = signing.sign(&pae);
        let envelope = DsseEnvelope {
            payload_type: PAYLOAD_TYPE_TRAIL_ANCHOR.to_string(),
            payload: B64.encode(&payload),
            signatures: vec![DsseSignature {
                keyid: "trail-test".to_string(),
                sig: B64.encode(sig.to_bytes()),
            }],
        };
        let pubkey = B64.encode(signing.verifying_key().as_bytes());
        (envelope, pubkey)
    }

    #[test]
    fn verifies_signed_anchor_receipt_and_merkle_root() {
        let left = hex::encode(Sha256::digest(b"left"));
        let right = hex::encode(Sha256::digest(b"right"));
        let root = compute_merkle_root(&[left.clone(), right.clone()]).unwrap();
        let receipt = serde_json::json!({
            "receipt_version": "1.0",
            "org_id": "550e8400-e29b-41d4-a716-446655440000",
            "trail_arn": "vdt:550e8400-e29b-41d4-a716-446655440000:trail::default",
            "window_start": "2026-08-01T14:00:00Z",
            "window_end": "2026-08-01T15:00:00Z",
            "merkle_algorithm": "SHA-256",
            "merkle_root": root,
            "leaf_hashes": [left, right],
            "leaf_kind": "digest_value",
            "backend": "filesystem_worm",
            "storage_key": "550e8400-e29b-41d4-a716-446655440000/2026/08/01/14.json.dsse",
            "published_at": "2026-08-01T15:00:01.000Z"
        });
        let (envelope, pubkey) = sign_receipt(&receipt);
        let verified = verify_anchor_envelope(&envelope, &pubkey).unwrap();
        assert_eq!(verified.merkle_root, root);
        assert_eq!(verified.receipt.backend, BACKEND_FILESYSTEM_WORM);
    }

    #[test]
    fn rejects_tampered_merkle_root() {
        let leaf = hex::encode(Sha256::digest(b"leaf"));
        let root = compute_merkle_root(&[leaf.clone()]).unwrap();
        let receipt = serde_json::json!({
            "receipt_version": "1.0",
            "org_id": "550e8400-e29b-41d4-a716-446655440000",
            "trail_arn": "vdt:550e8400-e29b-41d4-a716-446655440000:trail::default",
            "window_start": "2026-08-01T14:00:00Z",
            "window_end": "2026-08-01T15:00:00Z",
            "merkle_algorithm": "SHA-256",
            "merkle_root": root,
            "leaf_hashes": [leaf],
            "leaf_kind": "record_hash",
            "backend": "s3_object_lock",
            "storage_key": "org/2026/08/01/14.json.dsse",
            "published_at": "2026-08-01T15:00:01.000Z"
        });
        let (mut envelope, pubkey) = sign_receipt(&receipt);
        let mut payload: serde_json::Value =
            serde_json::from_slice(&B64.decode(&envelope.payload).unwrap()).unwrap();
        payload["merkle_root"] = serde_json::Value::String(hex::encode(Sha256::digest(b"x")));
        envelope.payload = B64.encode(serde_json::to_vec(&payload).unwrap());
        assert!(verify_anchor_envelope(&envelope, &pubkey).is_err());
    }
}
