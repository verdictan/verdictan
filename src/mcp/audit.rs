// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Checkpointed sealed HPKE Trail-intent outbox for connected MCP tool calls.
//!
//! Before any external MCP effect the connected CLI obtains a one-use RFC-9180
//! HPKE recipient bound to the authenticated subject/region/append-identity via
//! `POST /v1/trail/intents`, records a `prepared` then `dispatched` entry in a
//! bounded, checksummed, checkpoint-indexed local WAL through one durability
//! worker, executes the
//! effect, HPKE-seals the post-effect payload
//! (`DHKEM(X25519,HKDF-SHA256)` / `HKDF-SHA256` / `ChaCha20Poly1305`), durably
//! appends the ciphertext, and acknowledges via
//! `POST /v1/trail/intents/{intent_id}/acknowledge`. On a clean acknowledgement
//! the record becomes `completed`; on an ambiguous/failed acknowledgement it
//! becomes `indeterminate` and is retained for idempotent re-acknowledgement
//! (never re-dispatch).
//!
//! The WAL never stores plaintext PII, an unwrapped subject key, or any
//! decrypt-capable private key. It stores only random registry/intent/append
//! UUIDs, the (public) recipient key, the opaque HPKE AAD, an HMAC-SHA256
//! subject pseudonym, and the sealed ciphertext. Logical erasure deletes the
//! API-side recipient private key so retained local ciphertext becomes
//! unreadable through the supported live service.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    mpsc::{sync_channel, SyncSender, TrySendError},
    Mutex, OnceLock,
};

use base64::Engine;
use chrono::Utc;
use fs2::FileExt;
use hmac::{Hmac, Mac};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, single_shot_seal,
    Deserializable, Kem as KemTrait, OpModeS, Serializable,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::api::AsyncApiClient;
use crate::error::CliError;
use crate::gateway::request_id::control_plane_request_id;

// ── HPKE ciphersuite (must match the API control-plane implementation) ───────

type OutboxKem = X25519HkdfSha256;
type OutboxAead = ChaCha20Poly1305;
type OutboxKdf = HkdfSha256;

/// Fixed product/version/purpose HPKE `info` domain separator.
const TRAIL_INTENT_INFO: &[u8] = b"verdictan-trail-hpke/v1";
const EVENT_KIND_MCP_TOOL_CALL: &str = "mcp.tool_call";
const EXPECTED_KEM: &str = "DHKEM(X25519,HKDF-SHA256)";
const EXPECTED_KDF: &str = "HKDF-SHA256";
const EXPECTED_AEAD: &str = "ChaCha20Poly1305";
const RECIPIENT_PUBLIC_KEY_LEN: usize = 32;
const MIN_CIPHERTEXT_LEN: usize = 16;
const MAX_CIPHERTEXT_LEN: usize = 1_048_592;

// ── Subject pseudonymization ─────────────────────────────

type HmacSha256 = Hmac<Sha256>;

/// Environment variable holding the dedicated 32-byte regional pseudonymization
/// key. Accepted encodings: base64 (standard, padded), base64url (unpadded), or
/// 64-char hex; the decoded key must be exactly 32 bytes.
const PSEUDONYMIZATION_KEY_ENV: &str = "VERDICTAN_ERASURE_PSEUDONYMIZATION_KEY";

/// CLI-local domain separator. Distinct from the API subject-registry lookup
/// HMAC so the outbox never reproduces the server-side lookup key, while still
/// deriving the pseudonym as HMAC-SHA256 under the regional key.
const SUBJECT_PSEUDONYM_DOMAIN: &str = "verdictan:cli-mcp-subject-pseudonym:v1:";

// ── Local WAL layout ─────────────────────────────────────────────────────────

/// Sealed-outbox directory name under `VERDICTAN_DATA_DIR`.
pub const SEALED_OUTBOX_DIR_NAME: &str = "mcp-sealed-outbox";

/// Instance-scoped sealed MCP outbox location. Resolves once at construction so
/// parallel integration tests do not race on process-global env vars.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpOutboxHandle {
    dir: PathBuf,
}

impl McpOutboxHandle {
    /// Resolve the outbox directory from the current process environment.
    pub fn from_env() -> Self {
        Self {
            dir: resolve_sealed_outbox_dir(None, None),
        }
    }

    /// Resolve the outbox directory from an explicit data root and optional slot.
    pub fn from_data_dir(data_dir: impl AsRef<Path>, slot: Option<&str>) -> Self {
        Self {
            dir: resolve_sealed_outbox_dir(Some(data_dir.as_ref()), slot),
        }
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }
}
/// Append-only WAL file name.
pub const SEALED_OUTBOX_WAL_FILE: &str = "outbox.wal";
const SEALED_OUTBOX_LOCK_FILE: &str = "outbox.lock";
/// Atomic current-state checkpoint file name.
pub const SEALED_OUTBOX_CHECKPOINT_FILE: &str = "outbox.checkpoint";
const SEALED_OUTBOX_CHECKPOINT_TEMP_FILE: &str = "outbox.checkpoint.tmp";
const SEALED_OUTBOX_COMPACTION_TEMP_FILE: &str = "outbox.wal.compacting";
const OUTBOX_ENTRY_SCHEMA: &str = "verdictan-mcp-sealed-outbox/v1";
const OUTBOX_CHECKPOINT_SCHEMA: &str = "verdictan-mcp-sealed-outbox-checkpoint/v1";
#[cfg(unix)]
const OUTBOX_DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const OUTBOX_FILE_MODE: u32 = 0o600;
/// Bound on total WAL size. No eviction is permitted; when the bound is reached
/// dispatch is blocked (fail closed) rather than dropping durable records.
const MAX_WAL_BYTES: u64 = 64 * 1024 * 1024;
const DURABILITY_QUEUE_CAPACITY: usize = 64;
/// Summaries are sanitized then truncated before sealing to bound ciphertext.
const SEALED_SUMMARY_MAX_BYTES: usize = 512;

const STATE_PREPARED: &str = "prepared";
const STATE_DISPATCHED: &str = "dispatched";
const STATE_COMPLETED: &str = "completed";
const STATE_INDETERMINATE: &str = "indeterminate";

// ─────────────────────────────────────────────────────────────────────────────
// Retained audit-text sanitization (consumed by the gateway trace-preview path
// in `gateway/server.rs` and by MCP summary building here). Redacts obvious
// secrets/PII patterns before the value is truncated and sealed.
// ─────────────────────────────────────────────────────────────────────────────

/// Strip sensitive patterns from text before it enters audit payloads.
pub fn sanitize_for_audit(text: &str) -> String {
    let mut result = text.to_string();

    for prefix in &["Bearer ", "bearer "] {
        while let Some(start) = result.find(prefix) {
            let value_start = start + prefix.len();
            let value_end = result[value_start..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == ',' || c == '}')
                .map(|pos| value_start + pos)
                .unwrap_or(result.len());
            result.replace_range(start..value_end, "[REDACTED]");
        }
    }

    for prefix in &[
        "sk-", "sk_live_", "sk_test_", "ghp_", "gho_", "glpat-", "xoxb-", "xoxp-", "AKIA",
    ] {
        while let Some(start) = result.find(prefix) {
            let value_end = result[start..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == ',' || c == '}')
                .map(|pos| start + pos)
                .unwrap_or(result.len());
            if value_end > start + prefix.len() {
                result.replace_range(start..value_end, "[REDACTED]");
            } else {
                break;
            }
        }
    }

    result = redact_email_addresses(&result);
    result = redact_path_uuids(&result);
    result = redact_credit_card_patterns(&result);
    redact_sensitive_key_values(&mut result);

    result
}

fn redact_email_addresses(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut last = 0;

    for (i, &b) in bytes.iter().enumerate() {
        if b != b'@' {
            continue;
        }
        let mut start = i;
        while start > last
            && (bytes[start - 1].is_ascii_alphanumeric() || b".+-_".contains(&bytes[start - 1]))
        {
            start -= 1;
        }
        let mut end = i + 1;
        let mut has_dot = false;
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'.' || bytes[end] == b'-')
        {
            if bytes[end] == b'.' {
                has_dot = true;
            }
            end += 1;
        }
        if start < i && end > i + 1 && has_dot {
            out.extend_from_slice(&bytes[last..start]);
            out.extend_from_slice(b"[REDACTED]");
            last = end;
        }
    }
    out.extend_from_slice(&bytes[last..]);
    String::from_utf8(out).unwrap_or_else(|_| text.to_string())
}

fn redact_path_uuids(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut last = 0;
    let mut i = 0;

    while i + 36 <= bytes.len() {
        let preceded_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        let followed_ok = i + 36 >= bytes.len() || !bytes[i + 36].is_ascii_alphanumeric();
        if preceded_ok && followed_ok && is_uuid_at(bytes, i) {
            out.extend_from_slice(&bytes[last..i]);
            out.extend_from_slice(b"[REDACTED]");
            last = i + 36;
            i = last;
        } else {
            i += 1;
        }
    }
    out.extend_from_slice(&bytes[last..]);
    String::from_utf8(out).unwrap_or_else(|_| text.to_string())
}

fn is_uuid_at(bytes: &[u8], start: usize) -> bool {
    if start + 36 > bytes.len() {
        return false;
    }
    for offset in 0..36 {
        let b = bytes[start + offset];
        match offset {
            8 | 13 | 18 | 23 => {
                if b != b'-' {
                    return false;
                }
            }
            _ => {
                if !b.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

fn redact_credit_card_patterns(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut last = 0;
    let mut i = 0;

    while i + 19 <= bytes.len() {
        if is_cc_at(bytes, i, b'-') || is_cc_at(bytes, i, b' ') {
            out.extend_from_slice(&bytes[last..i]);
            out.extend_from_slice(b"[REDACTED]");
            last = i + 19;
            i = last;
        } else {
            i += 1;
        }
    }
    out.extend_from_slice(&bytes[last..]);
    String::from_utf8(out).unwrap_or_else(|_| text.to_string())
}

fn is_cc_at(bytes: &[u8], start: usize, sep: u8) -> bool {
    if start + 19 > bytes.len() {
        return false;
    }
    for group in 0u8..4 {
        let base = start + group as usize * 5;
        for d in 0..4 {
            if !bytes[base + d].is_ascii_digit() {
                return false;
            }
        }
        if group < 3 && bytes[base + 4] != sep {
            return false;
        }
    }
    true
}

const SENSITIVE_KEY_NAMES: &[&str] = &["password", "secret", "token", "key", "credential"];

fn redact_sensitive_key_values(result: &mut String) {
    for key_name in SENSITIVE_KEY_NAMES {
        let pattern = format!("\"{}\"", key_name);
        let mut search_from = 0;
        while let Some(rel_pos) = result[search_from..].find(&pattern) {
            let key_pos = search_from + rel_pos;
            let after_key = key_pos + pattern.len();
            let rest = &result[after_key..];
            let colon_offset = match rest.find(':') {
                Some(pos) if result[after_key..after_key + pos].trim().is_empty() => pos,
                _ => {
                    search_from = after_key;
                    continue;
                }
            };
            let after_colon = after_key + colon_offset + 1;
            let ws_offset = result[after_colon..]
                .find(|c: char| !c.is_whitespace())
                .unwrap_or(0);
            let value_start = after_colon + ws_offset;
            if value_start >= result.len() {
                break;
            }
            if result.as_bytes()[value_start] == b'"' {
                let mut end = value_start + 1;
                let bytes = result.as_bytes();
                while end < bytes.len() {
                    if bytes[end] == b'\\' {
                        end += 2;
                    } else if bytes[end] == b'"' {
                        end += 1;
                        break;
                    } else {
                        end += 1;
                    }
                }
                result.replace_range(value_start..end, "\"[REDACTED]\"");
                search_from = value_start + "\"[REDACTED]\"".len();
            } else {
                let value_end = result[value_start..]
                    .find(|c: char| c == ',' || c == '}' || c == ']' || c.is_whitespace())
                    .map(|p| value_start + p)
                    .unwrap_or(result.len());
                result.replace_range(value_start..value_end, "[REDACTED]");
                search_from = value_start + "[REDACTED]".len();
            }
        }
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Build a bounded summary string from a JSON value (compact JSON, capped).
pub fn summarize_json(v: &Value) -> String {
    let s = v.to_string();
    if s.len() > 256 {
        format!("{}...", truncate(&s, 256))
    } else {
        s
    }
}

/// Sanitize then bound a summary before it is sealed into the Trail payload.
fn sealed_summary(text: &str) -> String {
    let sanitized = sanitize_for_audit(text);
    truncate(&sanitized, SEALED_SUMMARY_MAX_BYTES).to_string()
}

// ── Base64url / UUID helpers (match the API DTO bounds) ──────────────────────

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_decode(field: &str, value: &str) -> Result<Vec<u8>, CliError> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| {
            CliError::internal(format!("{field} is not valid unpadded base64url: {error}"))
        })?;
    if b64url(&decoded) != value {
        return Err(CliError::internal(format!(
            "{field} is not canonical unpadded base64url"
        )));
    }
    Ok(decoded)
}

fn is_canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value)
        .map(|parsed| parsed.to_string() == value)
        .unwrap_or(false)
}

fn payload_sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

// ── Subject pseudonymization ─────────────────────────────────────────────────

fn load_pseudonymization_key() -> Result<[u8; 32], CliError> {
    let raw = std::env::var(PSEUDONYMIZATION_KEY_ENV).map_err(|_| {
        CliError::internal(format!(
            "{PSEUDONYMIZATION_KEY_ENV} is required for sealed MCP audit; connected MCP execution fails closed without it"
        ))
    })?;
    let raw = raw.trim();
    let decoded = decode_key_material(raw).ok_or_else(|| {
        CliError::internal(format!(
            "{PSEUDONYMIZATION_KEY_ENV} must decode (base64, base64url, or hex) to exactly 32 bytes"
        ))
    })?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

fn decode_key_material(raw: &str) -> Option<Vec<u8>> {
    let candidates = [
        base64::engine::general_purpose::STANDARD.decode(raw).ok(),
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(raw)
            .ok(),
        hex::decode(raw).ok(),
    ];
    candidates
        .into_iter()
        .flatten()
        .find(|decoded| decoded.len() == 32)
}

/// Compute the CLI-local subject pseudonym as
/// `hmac-sha256:<hex>` over a domain-separated message under the regional key.
fn subject_pseudonym(key: &[u8; 32], subject_ref: &str) -> Result<String, CliError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).map_err(|error| {
        CliError::internal(format!("invalid pseudonymization key length: {error}"))
    })?;
    mac.update(SUBJECT_PSEUDONYM_DOMAIN.as_bytes());
    mac.update(subject_ref.as_bytes());
    let digest = mac.finalize().into_bytes();
    Ok(format!("hmac-sha256:{:x}", digest))
}

// ── HPKE sender path ─────────────────────────────────────────────────────────

/// Seal `plaintext` to `recipient_public_key` with the fixed HPKE ciphersuite,
/// returning `(encapsulated_key, ciphertext)`.
fn hpke_seal(
    recipient_public_key: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CliError> {
    let recipient =
        <OutboxKem as KemTrait>::PublicKey::from_bytes(recipient_public_key).map_err(|error| {
            CliError::internal(format!("invalid HPKE recipient public key: {error}"))
        })?;
    let (encapped_key, ciphertext) = single_shot_seal::<OutboxAead, OutboxKdf, OutboxKem>(
        &OpModeS::Base,
        &recipient,
        TRAIL_INTENT_INFO,
        plaintext,
        aad,
    )
    .map_err(|error| CliError::internal(format!("HPKE seal failed: {error}")))?;
    Ok((encapped_key.to_bytes().to_vec(), ciphertext))
}

// ── Region resolution (slug/group-key → region registry UUID) ────────────────

/// Resolve the region UUID the connected CLI must send to `POST /v1/trail/intents`.
///
/// The connected gateway runtime only holds a region slug/group-key, while the
/// intent contract requires a canonical region UUID. This resolves the
/// configured region against `GET /v1/regions`. Resolution failure fails closed
/// (no dispatch); no plaintext/redacted fallback is added.
pub async fn resolve_trail_intent_region_id(client: &AsyncApiClient) -> Result<String, CliError> {
    let configured = client
        .region()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::internal(
                "sealed MCP audit requires a configured region; connected gateway region is unset",
            )
        })?
        .to_string();

    if is_canonical_uuid(&configured) {
        return Ok(configured);
    }

    let catalog = client.get_json_value("/v1/regions").await?;
    let entries = catalog
        .get("regions")
        .or_else(|| catalog.get("cells"))
        .or_else(|| catalog.get("items"))
        .and_then(Value::as_array)
        .ok_or_else(|| CliError::internal("region discovery returned no region catalog"))?;

    for entry in entries {
        let matches_slug = ["region_key", "n", "slug", "name"].iter().any(|field| {
            entry.get(*field).and_then(Value::as_str).map(str::trim) == Some(configured.as_str())
        });
        if !matches_slug {
            continue;
        }
        for id_field in ["id", "region_id", "region_registry_id"] {
            if let Some(candidate) = entry.get(id_field).and_then(Value::as_str) {
                let candidate = candidate.trim();
                if is_canonical_uuid(candidate) {
                    return Ok(candidate.to_string());
                }
            }
        }
    }

    Err(CliError::internal(format!(
        "region '{configured}' could not be resolved to a canonical region id via /v1/regions"
    )))
}

// ── Local WAL entry + single-process lock ────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OutboxEntry {
    schema: String,
    record_id: Uuid,
    execution_idempotency_key: Uuid,
    intent_id: Uuid,
    region_registry_id: Uuid,
    append_identity: Uuid,
    event_kind: String,
    recipient_generation: u64,
    /// `hmac-sha256:<hex>` pseudonym; never a raw user/token identifier.
    subject_pseudonym: String,
    state: String,
    /// Public recipient key (safe to persist). Base64url, unpadded.
    recipient_public_key_base64url: String,
    /// Opaque HPKE AAD bytes (UUIDs + constants; no PII). Base64url, unpadded.
    aad_base64url: String,
    expires_at: String,
    encapsulated_key_base64url: Option<String>,
    ciphertext_base64url: Option<String>,
    payload_sha256: Option<String>,
    created_at: String,
    checksum: u32,
}

impl OutboxEntry {
    fn compute_checksum(&self) -> u32 {
        let mut zeroed = self.clone();
        zeroed.checksum = 0;
        let bytes = serde_json::to_vec(&zeroed).unwrap_or_default();
        crc32fast::hash(&bytes)
    }

    fn verify_checksum(&self) -> bool {
        self.compute_checksum() == self.checksum
    }
}

/// Exclusive single-process lock over the WAL directory.
struct OutboxGuard {
    _file: File,
}

impl Drop for OutboxGuard {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self._file);
    }
}

struct SealedOutbox {
    dir: PathBuf,
    wal_path: PathBuf,
    lock_path: PathBuf,
    checkpoint_path: PathBuf,
}

impl SealedOutbox {
    fn open(outbox: &McpOutboxHandle) -> Result<Self, CliError> {
        let dir = outbox.dir().to_path_buf();
        std::fs::create_dir_all(&dir).map_err(|error| {
            CliError::internal(format!(
                "failed to create sealed MCP outbox directory {}: {error}",
                dir.display()
            ))
        })?;
        set_mode(&dir, true)?;
        let wal_path = dir.join(SEALED_OUTBOX_WAL_FILE);
        let lock_path = dir.join(SEALED_OUTBOX_LOCK_FILE);
        let checkpoint_path = dir.join(SEALED_OUTBOX_CHECKPOINT_FILE);
        ensure_secure_file(&wal_path)?;
        ensure_secure_file(&lock_path)?;
        Ok(Self {
            dir,
            wal_path,
            lock_path,
            checkpoint_path,
        })
    }

    /// Acquire the exclusive process lock. A second concurrent holder fails
    /// closed rather than corrupting the WAL.
    fn lock(&self) -> Result<OutboxGuard, CliError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.lock_path)
            .map_err(|error| {
                CliError::internal(format!("failed to open sealed MCP outbox lock: {error}"))
            })?;
        FileExt::try_lock_exclusive(&file).map_err(|error| {
            CliError::internal(format!(
                "sealed MCP outbox is locked by another owner; refusing to dispatch: {error}"
            ))
        })?;
        Ok(OutboxGuard { _file: file })
    }

    fn load_state(&self) -> Result<OutboxState, CliError> {
        let wal_len = std::fs::metadata(&self.wal_path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        let mut state = self
            .read_checkpoint(wal_len)?
            .unwrap_or_else(OutboxState::default);
        let folded = self.fold_wal_tail(state.wal_bytes, &mut state)?;
        state.wal_bytes = wal_len;
        state.wal_records = state.wal_records.saturating_add(folded);
        Ok(state)
    }

    fn load_state_for_durability(&self) -> Result<OutboxState, CliError> {
        let state = self.load_state()?;
        self.persist_checkpoint(&state)?;
        Ok(state)
    }

    fn read_checkpoint(&self, wal_len: u64) -> Result<Option<OutboxState>, CliError> {
        let bytes = match std::fs::read(&self.checkpoint_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(CliError::internal(format!(
                    "failed to read sealed MCP outbox checkpoint: {error}"
                )))
            }
        };
        let checkpoint: OutboxCheckpoint = serde_json::from_slice(&bytes).map_err(|error| {
            CliError::internal(format!(
                "sealed MCP outbox checkpoint is corrupt and requires operator repair: {error}"
            ))
        })?;
        if checkpoint.schema != OUTBOX_CHECKPOINT_SCHEMA || !checkpoint.verify_checksum() {
            return Err(CliError::internal(
                "sealed MCP outbox checkpoint failed schema/checksum validation",
            ));
        }
        if checkpoint.wal_bytes > wal_len {
            return Ok(None);
        }
        if checkpoint.wal_prefix_sha256 != self.wal_prefix_sha256(checkpoint.wal_bytes)? {
            return Ok(None);
        }
        let mut current = HashMap::with_capacity(checkpoint.entries.len());
        let mut order = Vec::with_capacity(checkpoint.entries.len());
        for entry in checkpoint.entries {
            if !entry.verify_checksum() {
                return Err(CliError::internal(
                    "sealed MCP outbox checkpoint contains an invalid record checksum",
                ));
            }
            order.push(entry.record_id);
            current.insert(entry.record_id, entry);
        }
        Ok(Some(OutboxState {
            current,
            order,
            wal_bytes: checkpoint.wal_bytes,
            wal_records: checkpoint.wal_records,
        }))
    }

    fn fold_wal_tail(&self, offset: u64, state: &mut OutboxState) -> Result<u64, CliError> {
        let mut file = File::open(&self.wal_path).map_err(|error| {
            CliError::internal(format!("failed to open sealed MCP WAL: {error}"))
        })?;
        file.seek(SeekFrom::Start(offset)).map_err(|error| {
            CliError::internal(format!("failed to seek sealed MCP WAL checkpoint: {error}"))
        })?;
        let mut tail = Vec::new();
        file.read_to_end(&mut tail).map_err(|error| {
            CliError::internal(format!("failed to read sealed MCP WAL tail: {error}"))
        })?;
        if tail.is_empty() {
            return Ok(0);
        }
        if tail.last() != Some(&b'\n') {
            return Err(CliError::internal(
                "sealed MCP WAL has a partial trailing record; unresolved effects require operator repair",
            ));
        }
        let mut folded = 0u64;
        for line in tail
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let entry: OutboxEntry = serde_json::from_slice(line).map_err(|error| {
                CliError::internal(format!(
                    "sealed MCP WAL contains a corrupt record; unresolved effects require operator repair: {error}"
                ))
            })?;
            if !entry.verify_checksum() {
                return Err(CliError::internal(
                    "sealed MCP WAL record checksum mismatch; unresolved effects require operator repair",
                ));
            }
            state.apply(entry);
            folded = folded.saturating_add(1);
        }
        Ok(folded)
    }

    /// Append one checksummed WAL line and fsync. The caller receives success
    /// only after both the WAL and its current-state checkpoint are durable.
    fn append(&self, state: &mut OutboxState, mut entry: OutboxEntry) -> Result<(), CliError> {
        entry.checksum = entry.compute_checksum();
        let mut line = serde_json::to_string(&entry).map_err(|error| {
            CliError::internal(format!(
                "failed to serialize sealed MCP outbox record: {error}"
            ))
        })?;
        line.push('\n');

        let mut existing = std::fs::metadata(&self.wal_path)
            .map(|m| m.len())
            .unwrap_or(0);
        if existing.saturating_add(line.len() as u64) > MAX_WAL_BYTES {
            self.compact(state)?;
            existing = std::fs::metadata(&self.wal_path)
                .map(|metadata| metadata.len())
                .unwrap_or(0);
            if existing.saturating_add(line.len() as u64) > MAX_WAL_BYTES {
                return Err(CliError::internal(
                    "sealed MCP outbox WAL remains at bounded capacity after compaction; refusing to dispatch",
                ));
            }
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.wal_path)
            .map_err(|error| {
                CliError::internal(format!("failed to open sealed MCP outbox WAL: {error}"))
            })?;
        set_mode(&self.wal_path, false)?;
        file.write_all(line.as_bytes()).map_err(|error| {
            CliError::internal(format!(
                "failed to append sealed MCP outbox record: {error}"
            ))
        })?;
        file.sync_all().map_err(|error| {
            CliError::internal(format!("failed to fsync sealed MCP outbox record: {error}"))
        })?;
        state.wal_bytes = existing.saturating_add(line.len() as u64);
        state.wal_records = state.wal_records.saturating_add(1);
        state.apply(entry);
        self.persist_checkpoint(state)?;
        if let Err(error) = self.compact_if_needed(state) {
            tracing::warn!(
                error = %error,
                "sealed MCP WAL compaction deferred after durable checkpoint"
            );
        }
        Ok(())
    }

    fn compact_if_needed(&self, state: &mut OutboxState) -> Result<bool, CliError> {
        if !state.should_compact() {
            return Ok(false);
        }
        self.compact(state)?;
        Ok(true)
    }

    fn compact(&self, state: &mut OutboxState) -> Result<(), CliError> {
        let temporary = self.dir.join(SEALED_OUTBOX_COMPACTION_TEMP_FILE);
        let mut file = secure_truncated_file(&temporary)?;
        let mut wal_bytes = 0u64;
        for entry in state
            .entries()
            .into_iter()
            .filter(|entry| entry.state != STATE_COMPLETED)
        {
            let mut line = serde_json::to_vec(entry).map_err(|error| {
                CliError::internal(format!("failed to serialize compacted MCP WAL: {error}"))
            })?;
            line.push(b'\n');
            file.write_all(&line).map_err(|error| {
                CliError::internal(format!("failed to write compacted MCP WAL: {error}"))
            })?;
            wal_bytes = wal_bytes.saturating_add(line.len() as u64);
        }
        file.sync_all().map_err(|error| {
            CliError::internal(format!("failed to fsync compacted MCP WAL: {error}"))
        })?;
        std::fs::rename(&temporary, &self.wal_path).map_err(|error| {
            CliError::internal(format!("failed to install compacted MCP WAL: {error}"))
        })?;
        set_mode(&self.wal_path, false)?;
        self.sync_dir()?;
        state
            .current
            .retain(|_, entry| entry.state != STATE_COMPLETED);
        state
            .order
            .retain(|record_id| state.current.contains_key(record_id));
        state.wal_bytes = wal_bytes;
        state.wal_records = state.current.len() as u64;
        self.persist_checkpoint(state)?;
        Ok(())
    }

    fn persist_checkpoint(&self, state: &OutboxState) -> Result<(), CliError> {
        let mut checkpoint = OutboxCheckpoint {
            schema: OUTBOX_CHECKPOINT_SCHEMA.to_string(),
            wal_bytes: state.wal_bytes,
            wal_records: state.wal_records,
            wal_prefix_sha256: self.wal_prefix_sha256(state.wal_bytes)?,
            entries: state.entries().into_iter().cloned().collect(),
            checksum: 0,
        };
        checkpoint.checksum = checkpoint.compute_checksum();
        let bytes = serde_json::to_vec(&checkpoint).map_err(|error| {
            CliError::internal(format!(
                "failed to serialize sealed MCP checkpoint: {error}"
            ))
        })?;
        let temporary = self.dir.join(SEALED_OUTBOX_CHECKPOINT_TEMP_FILE);
        let mut file = secure_truncated_file(&temporary)?;
        file.write_all(&bytes).map_err(|error| {
            CliError::internal(format!("failed to write sealed MCP checkpoint: {error}"))
        })?;
        file.sync_all().map_err(|error| {
            CliError::internal(format!("failed to fsync sealed MCP checkpoint: {error}"))
        })?;
        std::fs::rename(&temporary, &self.checkpoint_path).map_err(|error| {
            CliError::internal(format!("failed to install sealed MCP checkpoint: {error}"))
        })?;
        set_mode(&self.checkpoint_path, false)?;
        self.sync_dir()
    }

    fn wal_prefix_sha256(&self, through: u64) -> Result<String, CliError> {
        let mut file = File::open(&self.wal_path).map_err(|error| {
            CliError::internal(format!("failed to hash sealed MCP WAL: {error}"))
        })?;
        let mut prefix = vec![0u8; usize::try_from(through.min(4096)).unwrap_or(4096)];
        if !prefix.is_empty() {
            file.read_exact(&mut prefix).map_err(|error| {
                CliError::internal(format!("failed to read sealed MCP WAL prefix: {error}"))
            })?;
        }
        Ok(payload_sha256_hex(&prefix))
    }

    fn sync_dir(&self) -> Result<(), CliError> {
        let dir = File::open(&self.dir).map_err(|error| {
            CliError::internal(format!(
                "failed to open sealed MCP outbox directory: {error}"
            ))
        })?;
        dir.sync_all().map_err(|error| {
            CliError::internal(format!(
                "failed to fsync sealed MCP outbox directory: {error}"
            ))
        })
    }
}

#[derive(Debug, Default)]
struct OutboxState {
    current: HashMap<Uuid, OutboxEntry>,
    order: Vec<Uuid>,
    wal_bytes: u64,
    wal_records: u64,
}

impl OutboxState {
    fn apply(&mut self, entry: OutboxEntry) {
        if !self.current.contains_key(&entry.record_id) {
            self.order.push(entry.record_id);
        }
        self.current.insert(entry.record_id, entry);
    }

    fn entries(&self) -> Vec<&OutboxEntry> {
        self.order
            .iter()
            .filter_map(|record_id| self.current.get(record_id))
            .collect()
    }

    fn should_compact(&self) -> bool {
        let tombstones = self
            .current
            .values()
            .filter(|entry| entry.state == STATE_COMPLETED)
            .count();
        self.wal_bytes >= MAX_WAL_BYTES
            || (tombstones > 0 && tombstones.saturating_mul(2) >= self.current.len().max(1))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OutboxCheckpoint {
    schema: String,
    wal_bytes: u64,
    wal_records: u64,
    wal_prefix_sha256: String,
    entries: Vec<OutboxEntry>,
    checksum: u32,
}

impl OutboxCheckpoint {
    fn compute_checksum(&self) -> u32 {
        let mut zeroed = self.clone();
        zeroed.checksum = 0;
        crc32fast::hash(&serde_json::to_vec(&zeroed).unwrap_or_default())
    }

    fn verify_checksum(&self) -> bool {
        self.compute_checksum() == self.checksum
    }
}

enum DurabilityCommand {
    Append {
        entry: Box<OutboxEntry>,
        reply: tokio::sync::oneshot::Sender<Result<(), CliError>>,
    },
    Current {
        record_id: Uuid,
        reply: tokio::sync::oneshot::Sender<Result<Option<OutboxEntry>, CliError>>,
    },
    Snapshot {
        reply: tokio::sync::oneshot::Sender<Result<Vec<OutboxEntry>, CliError>>,
    },
}

fn durability_workers() -> &'static Mutex<HashMap<PathBuf, SyncSender<DurabilityCommand>>> {
    static WORKERS: OnceLock<Mutex<HashMap<PathBuf, SyncSender<DurabilityCommand>>>> =
        OnceLock::new();
    WORKERS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn durability_worker(outbox: &McpOutboxHandle) -> Result<SyncSender<DurabilityCommand>, CliError> {
    let dir = outbox.dir().to_path_buf();
    let mut workers = durability_workers()
        .lock()
        .map_err(|_| CliError::internal("sealed MCP durability worker registry is poisoned"))?;
    if let Some(sender) = workers.get(&dir) {
        return Ok(sender.clone());
    }
    let (sender, receiver) = sync_channel(DURABILITY_QUEUE_CAPACITY);
    workers.insert(dir.clone(), sender.clone());
    let thread_dir = dir.clone();
    let worker_outbox = outbox.clone();
    std::thread::Builder::new()
        .name("mcp-outbox-durability".to_string())
        .spawn(move || {
            let mut store: Option<(SealedOutbox, OutboxState)> = None;
            while let Ok(command) = receiver.recv() {
                if store.is_none() {
                    match SealedOutbox::open(&worker_outbox).and_then(|outbox| {
                        let _guard = outbox.lock()?;
                        let state = outbox.load_state_for_durability()?;
                        drop(_guard);
                        Ok((outbox, state))
                    }) {
                        Ok(initialized) => store = Some(initialized),
                        Err(error) => {
                            reply_with_initialization_error(command, error);
                            continue;
                        }
                    }
                }
                match command {
                    DurabilityCommand::Append { entry, reply } => {
                        let result = match store.as_mut() {
                            Some((outbox, state)) => outbox
                                .lock()
                                .and_then(|_guard| outbox.append(state, *entry)),
                            None => Err(CliError::internal(
                                "sealed MCP durability worker could not initialize the outbox",
                            )),
                        };
                        let _ = reply.send(result);
                    }
                    DurabilityCommand::Current { record_id, reply } => {
                        let result = store
                            .as_ref()
                            .map(|(_, state)| state.current.get(&record_id).cloned())
                            .ok_or_else(|| {
                                CliError::internal(
                                    "sealed MCP durability worker could not initialize the outbox",
                                )
                            });
                        let _ = reply.send(result);
                    }
                    DurabilityCommand::Snapshot { reply } => {
                        let result = store
                            .as_ref()
                            .map(|(_, state)| state.entries().into_iter().cloned().collect())
                            .ok_or_else(|| {
                                CliError::internal(
                                    "sealed MCP durability worker could not initialize the outbox",
                                )
                            });
                        let _ = reply.send(result);
                    }
                }
            }
            tracing::debug!(path = %thread_dir.display(), "sealed MCP durability worker stopped");
        })
        .map_err(|error| {
            CliError::internal(format!(
                "failed to start sealed MCP durability worker: {error}"
            ))
        })?;
    Ok(sender)
}

fn reply_with_initialization_error(command: DurabilityCommand, error: CliError) {
    match command {
        DurabilityCommand::Append { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        DurabilityCommand::Current { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        DurabilityCommand::Snapshot { reply } => {
            let _ = reply.send(Err(error));
        }
    }
}

fn enqueue(outbox: &McpOutboxHandle, command: DurabilityCommand) -> Result<(), CliError> {
    durability_worker(outbox)?
        .try_send(command)
        .map_err(|error| match error {
            TrySendError::Full(_) => {
                CliError::internal("sealed MCP durability queue is full; refusing effect dispatch")
            }
            TrySendError::Disconnected(_) => {
                CliError::internal("sealed MCP durability worker is unavailable")
            }
        })
}

async fn durable_append(outbox: &McpOutboxHandle, entry: OutboxEntry) -> Result<(), CliError> {
    let (reply, response) = tokio::sync::oneshot::channel();
    enqueue(
        outbox,
        DurabilityCommand::Append {
            entry: Box::new(entry),
            reply,
        },
    )?;
    response
        .await
        .map_err(|_| CliError::internal("sealed MCP durability worker stopped before fsync"))?
}

async fn durable_current(
    outbox: &McpOutboxHandle,
    record_id: Uuid,
) -> Result<Option<OutboxEntry>, CliError> {
    let (reply, response) = tokio::sync::oneshot::channel();
    enqueue(outbox, DurabilityCommand::Current { record_id, reply })?;
    response
        .await
        .map_err(|_| CliError::internal("sealed MCP durability worker stopped during lookup"))?
}

async fn durable_snapshot(outbox: &McpOutboxHandle) -> Result<Vec<OutboxEntry>, CliError> {
    let (reply, response) = tokio::sync::oneshot::channel();
    enqueue(outbox, DurabilityCommand::Snapshot { reply })?;
    response
        .await
        .map_err(|_| CliError::internal("sealed MCP durability worker stopped during recovery"))?
}

fn secure_truncated_file(path: &Path) -> Result<File, CliError> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(OUTBOX_FILE_MODE);
    }
    let file = options.open(path).map_err(|error| {
        CliError::internal(format!(
            "failed to create secure sealed MCP outbox file {}: {error}",
            path.display()
        ))
    })?;
    set_mode(path, false)?;
    Ok(file)
}

fn resolve_sealed_outbox_dir(data_dir: Option<&Path>, slot: Option<&str>) -> PathBuf {
    let base = data_dir
        .map(PathBuf::from)
        .or_else(|| std::env::var("VERDICTAN_DATA_DIR").ok().map(PathBuf::from))
        .unwrap_or_else(|| std::env::temp_dir().join("verdictan"));
    let resolved_slot = slot
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            std::env::var("VERDICTAN_MCP_OUTBOX_SLOT")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        });
    match resolved_slot {
        Some(slot) => base.join(slot).join(SEALED_OUTBOX_DIR_NAME),
        None => base.join(SEALED_OUTBOX_DIR_NAME),
    }
}

fn ensure_secure_file(path: &Path) -> Result<(), CliError> {
    if !path.exists() {
        let mut options = OpenOptions::new();
        options.create(true).append(true).read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(OUTBOX_FILE_MODE);
        }
        options.open(path).map_err(|error| {
            CliError::internal(format!(
                "failed to create sealed MCP outbox file {}: {error}",
                path.display()
            ))
        })?;
    }
    set_mode(path, false)
}

#[allow(unused_variables)]
fn set_mode(path: &Path, is_dir: bool) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if is_dir {
            OUTBOX_DIR_MODE
        } else {
            OUTBOX_FILE_MODE
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|error| {
            CliError::internal(format!(
                "failed to set secure permissions on {}: {error}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

// ── Trail intent wire types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CreateIntentResponse {
    intent_id: String,
    region_registry_id: String,
    append_identity: String,
    event_kind: String,
    recipient_generation: u64,
    kem: String,
    kdf: String,
    aead: String,
    recipient_public_key_base64url: String,
    aad_base64url: String,
    expires_at: String,
}

#[derive(Debug, Serialize)]
struct SealedPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    session_id: String,
    tool_name: String,
    input_summary: String,
    output_summary: String,
    success: bool,
    duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
}

/// In-memory handle carrying the issued intent + recipient between the
/// pre-effect (`prepare`) and post-effect (`complete`) phases. Never persisted
/// as plaintext; the payload inputs live only in memory until sealed.
#[derive(Debug, Clone)]
pub struct SealedToolCallHandle {
    record_id: Uuid,
    execution_idempotency_key: Uuid,
    intent_id: Uuid,
    append_identity: Uuid,
    event_kind: String,
    recipient_generation: u64,
    recipient_public_key: Vec<u8>,
    aad: Vec<u8>,
    request_id: Option<String>,
    session_id: String,
    tool_name: String,
    input_summary: String,
}

impl SealedToolCallHandle {
    /// Durable key that identifies this effect across dispatch and recovery.
    pub fn execution_idempotency_key(&self) -> Uuid {
        self.execution_idempotency_key
    }
}

/// Outcome of a sealed acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedCompletion {
    /// The Trail intent was cleanly acknowledged; the record is `completed`.
    Completed,
    /// The acknowledgement was ambiguous or failed; the record is retained as
    /// `indeterminate` for idempotent re-acknowledgement (never re-dispatch).
    Indeterminate,
}

/// Phase 1: obtain the one-use HPKE recipient and durably record
/// `prepared` then `dispatched` BEFORE the external MCP effect runs.
///
/// Returns `Err` (fail closed) if intent/recipient creation fails, the region
/// is unresolvable, the pseudonymization key is missing, or the durable WAL
/// append fails. On `Err` the caller MUST NOT execute the external effect.
#[allow(clippy::too_many_arguments)]
pub async fn prepare_sealed_tool_call(
    outbox: &McpOutboxHandle,
    client: &AsyncApiClient,
    region_id: &str,
    subject_ref: &str,
    request_id: Option<&str>,
    session_id: &str,
    tool_name: &str,
    input_summary: &str,
) -> Result<SealedToolCallHandle, CliError> {
    let key = load_pseudonymization_key()?;
    let subject_pseudonym = subject_pseudonym(&key, subject_ref)?;

    let append_identity = Uuid::new_v4();
    let create_body = serde_json::json!({
        "region_id": region_id,
        "append_identity": append_identity.to_string(),
        "event_kind": EVENT_KIND_MCP_TOOL_CALL,
    });
    let response = client
        .post_json_value("/v1/trail/intents", &create_body)
        .await
        .map_err(|error| {
            CliError::internal(format!(
                "Trail intent creation failed; MCP effect blocked: {error}"
            ))
        })?;
    let intent: CreateIntentResponse = serde_json::from_value(response).map_err(|error| {
        CliError::internal(format!("Trail intent response was malformed: {error}"))
    })?;

    if intent.kem != EXPECTED_KEM || intent.kdf != EXPECTED_KDF || intent.aead != EXPECTED_AEAD {
        return Err(CliError::internal(
            "Trail intent advertised an unexpected HPKE ciphersuite; refusing to dispatch",
        ));
    }
    if intent.event_kind != EVENT_KIND_MCP_TOOL_CALL {
        return Err(CliError::internal(
            "Trail intent event_kind mismatch; refusing to dispatch",
        ));
    }
    if intent.append_identity != append_identity.to_string() {
        return Err(CliError::internal(
            "Trail intent append_identity mismatch; refusing to dispatch",
        ));
    }
    let intent_id = Uuid::parse_str(&intent.intent_id)
        .map_err(|_| CliError::internal("Trail intent id was not a canonical UUID"))?;
    let region_registry_id = Uuid::parse_str(&intent.region_registry_id).map_err(|_| {
        CliError::internal("Trail intent region registry id was not a canonical UUID")
    })?;
    if intent.recipient_generation == 0 {
        return Err(CliError::internal(
            "Trail intent recipient_generation must be positive",
        ));
    }
    let recipient_public_key = b64url_decode(
        "recipient_public_key_base64url",
        &intent.recipient_public_key_base64url,
    )?;
    if recipient_public_key.len() != RECIPIENT_PUBLIC_KEY_LEN {
        return Err(CliError::internal(
            "Trail intent recipient public key was not 32 bytes",
        ));
    }
    let aad = b64url_decode("aad_base64url", &intent.aad_base64url)?;

    let record_id = Uuid::new_v4();
    let execution_idempotency_key = Uuid::new_v4();
    let now = Utc::now().to_rfc3339();
    let prepared = OutboxEntry {
        schema: OUTBOX_ENTRY_SCHEMA.to_string(),
        record_id,
        execution_idempotency_key,
        intent_id,
        region_registry_id,
        append_identity,
        event_kind: EVENT_KIND_MCP_TOOL_CALL.to_string(),
        recipient_generation: intent.recipient_generation,
        subject_pseudonym: subject_pseudonym.clone(),
        state: STATE_PREPARED.to_string(),
        recipient_public_key_base64url: intent.recipient_public_key_base64url.clone(),
        aad_base64url: intent.aad_base64url.clone(),
        expires_at: intent.expires_at.clone(),
        encapsulated_key_base64url: None,
        ciphertext_base64url: None,
        payload_sha256: None,
        created_at: now,
        checksum: 0,
    };
    // Persist `prepared` before dispatch, then CAS+fsync `dispatched`
    // immediately before returning control for the external effect.
    durable_append(outbox, prepared.clone()).await?;
    let mut dispatched = prepared;
    dispatched.state = STATE_DISPATCHED.to_string();
    durable_append(outbox, dispatched).await?;

    Ok(SealedToolCallHandle {
        record_id,
        execution_idempotency_key,
        intent_id,
        append_identity,
        event_kind: EVENT_KIND_MCP_TOOL_CALL.to_string(),
        recipient_generation: intent.recipient_generation,
        recipient_public_key,
        aad,
        request_id: request_id
            .map(control_plane_request_id)
            .and_then(|hex| Uuid::parse_str(&hex).ok())
            .map(|value| value.to_string()),
        session_id: session_id.to_string(),
        tool_name: tool_name.to_string(),
        input_summary: sealed_summary(input_summary),
    })
}

/// Phase 2: HPKE-seal the post-effect payload, durably append the ciphertext,
/// and acknowledge the Trail intent. Returns the resulting completion state.
pub async fn complete_sealed_tool_call(
    outbox: &McpOutboxHandle,
    client: &AsyncApiClient,
    handle: SealedToolCallHandle,
    output_summary: &str,
    success: bool,
    duration_ms: u64,
    error_code: Option<&str>,
) -> Result<SealedCompletion, CliError> {
    let payload = SealedPayload {
        request_id: handle.request_id.clone(),
        session_id: handle.session_id.clone(),
        tool_name: handle.tool_name.clone(),
        input_summary: handle.input_summary.clone(),
        output_summary: sealed_summary(output_summary),
        success,
        duration_ms,
        error_code: error_code.map(str::to_string),
    };
    let plaintext = serde_json::to_vec(&payload).map_err(|error| {
        CliError::internal(format!("failed to serialize sealed MCP payload: {error}"))
    })?;
    let payload_sha256 = payload_sha256_hex(&plaintext);
    let (encapped, ciphertext) = hpke_seal(&handle.recipient_public_key, &handle.aad, &plaintext)?;
    if !(MIN_CIPHERTEXT_LEN..=MAX_CIPHERTEXT_LEN).contains(&ciphertext.len()) {
        return Err(CliError::internal(
            "sealed MCP ciphertext length is out of bounds",
        ));
    }
    let encapsulated_key_base64url = b64url(&encapped);
    let ciphertext_base64url = b64url(&ciphertext);

    // Durably persist the sealed ciphertext before acknowledging so an ambiguous
    // acknowledgement can be idempotently retried without re-running the effect.
    {
        let mut entry = require_state(outbox, handle.record_id, STATE_DISPATCHED).await?;
        entry.state = STATE_DISPATCHED.to_string();
        entry.encapsulated_key_base64url = Some(encapsulated_key_base64url.clone());
        entry.ciphertext_base64url = Some(ciphertext_base64url.clone());
        entry.payload_sha256 = Some(payload_sha256.clone());
        entry.checksum = 0;
        durable_append(outbox, entry).await?;
    }

    let ack_body = serde_json::json!({
        "append_identity": handle.append_identity.to_string(),
        "recipient_generation": handle.recipient_generation,
        "event_kind": handle.event_kind,
        "encapsulated_key_base64url": encapsulated_key_base64url,
        "ciphertext_base64url": ciphertext_base64url,
        "payload_sha256": payload_sha256,
    });
    let ack_path = format!("/v1/trail/intents/{}/acknowledge", handle.intent_id);
    let acknowledged = client.post_json_value(&ack_path, &ack_body).await;

    let mut entry = require_state(outbox, handle.record_id, STATE_DISPATCHED).await?;
    let completion = match acknowledged {
        Ok(_) => {
            entry.state = STATE_COMPLETED.to_string();
            SealedCompletion::Completed
        }
        Err(error) => {
            tracing::warn!(
                intent_id = %handle.intent_id,
                error = %error,
                "sealed MCP acknowledgement was ambiguous; retaining indeterminate outbox record"
            );
            entry.state = STATE_INDETERMINATE.to_string();
            SealedCompletion::Indeterminate
        }
    };
    entry.checksum = 0;
    durable_append(outbox, entry).await?;
    Ok(completion)
}

async fn require_state(
    outbox: &McpOutboxHandle,
    record_id: Uuid,
    expected: &str,
) -> Result<OutboxEntry, CliError> {
    let entry = durable_current(outbox, record_id)
        .await?
        .ok_or_else(|| CliError::internal("sealed MCP outbox record vanished"))?;
    if entry.state != expected {
        return Err(CliError::internal(format!(
            "sealed MCP outbox record is in state '{}', expected '{}'",
            entry.state, expected
        )));
    }
    Ok(entry)
}

/// Operator-visible recovery outcome for effects that cannot be safely replayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedEffect {
    pub record_id: Uuid,
    pub execution_idempotency_key: Uuid,
    pub intent_id: Uuid,
    pub state: String,
    pub missing_ciphertext: bool,
}

/// One-pass startup recovery report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    pub completed: u64,
    pub unresolved: Vec<UnresolvedEffect>,
}

/// Recover every unacknowledged record after restart. Sealed records are
/// idempotently re-acknowledged; dispatched records missing ciphertext are
/// surfaced as unresolved and are never re-dispatched.
pub async fn recover_sealed_outbox(
    outbox: &McpOutboxHandle,
    client: &AsyncApiClient,
) -> Result<RecoveryReport, CliError> {
    let pending: Vec<OutboxEntry> = durable_snapshot(outbox)
        .await?
        .into_iter()
        .filter(|entry| matches!(entry.state.as_str(), STATE_DISPATCHED | STATE_INDETERMINATE))
        .collect();

    let mut report = RecoveryReport::default();
    for entry in pending {
        let (Some(encapped), Some(ciphertext), Some(payload_sha256)) = (
            entry.encapsulated_key_base64url.clone(),
            entry.ciphertext_base64url.clone(),
            entry.payload_sha256.clone(),
        ) else {
            report.unresolved.push(UnresolvedEffect {
                record_id: entry.record_id,
                execution_idempotency_key: entry.execution_idempotency_key,
                intent_id: entry.intent_id,
                state: entry.state,
                missing_ciphertext: true,
            });
            continue;
        };
        let ack_body = serde_json::json!({
            "append_identity": entry.append_identity.to_string(),
            "recipient_generation": entry.recipient_generation,
            "event_kind": entry.event_kind,
            "encapsulated_key_base64url": encapped,
            "ciphertext_base64url": ciphertext,
            "payload_sha256": payload_sha256,
        });
        let ack_path = format!("/v1/trail/intents/{}/acknowledge", entry.intent_id);
        let acknowledged = client.post_json_value(&ack_path, &ack_body).await;

        let Some(current) = durable_current(outbox, entry.record_id).await? else {
            continue;
        };
        if !matches!(
            current.state.as_str(),
            STATE_DISPATCHED | STATE_INDETERMINATE
        ) {
            continue;
        }
        let mut next = current;
        match acknowledged {
            Ok(_) => {
                next.state = STATE_COMPLETED.to_string();
                next.checksum = 0;
                durable_append(outbox, next).await?;
                report.completed += 1;
            }
            Err(_) => {
                if next.state != STATE_INDETERMINATE {
                    next.state = STATE_INDETERMINATE.to_string();
                    next.checksum = 0;
                    durable_append(outbox, next.clone()).await?;
                }
                report.unresolved.push(UnresolvedEffect {
                    record_id: next.record_id,
                    execution_idempotency_key: next.execution_idempotency_key,
                    intent_id: next.intent_id,
                    state: next.state,
                    missing_ciphertext: false,
                });
            }
        }
    }
    Ok(report)
}

/// Count durable records that still require recovery before new MCP effects.
pub fn pending_recoverable_effects(outbox: &McpOutboxHandle) -> Result<usize, CliError> {
    Ok(read_outbox_records(outbox)?
        .into_iter()
        .filter(|record| {
            matches!(
                record.state.as_str(),
                STATE_DISPATCHED | STATE_INDETERMINATE
            )
        })
        .count())
}

/// Run sealed-outbox recovery before accepting new MCP tool calls.
///
/// Empty outboxes are a no-op. Records with sealed ciphertext are
/// re-acknowledged once. Dispatched records missing ciphertext (and any still
/// unresolved after acknowledgement) fail closed so a later call cannot
/// re-dispatch the same effect.
pub async fn ensure_recovered_before_serving(
    outbox: &McpOutboxHandle,
    client: &AsyncApiClient,
) -> Result<RecoveryReport, CliError> {
    let pending = pending_recoverable_effects(outbox)?;
    if pending == 0 {
        return Ok(RecoveryReport::default());
    }

    let report = recover_sealed_outbox(outbox, client).await?;
    if report.unresolved.is_empty() {
        tracing::info!(
            recovered_effects = report.completed,
            "completed sealed MCP outbox recovery before serving calls"
        );
        return Ok(report);
    }

    let execution_ids = report
        .unresolved
        .iter()
        .map(|effect| effect.execution_idempotency_key.to_string())
        .collect::<Vec<_>>()
        .join(",");
    Err(CliError::internal(format!(
        "{} sealed MCP effects remain unresolved after recovery before serving calls; execution ids: {execution_ids}",
        report.unresolved.len()
    )))
}

// ── Test / diagnostics-visible read model ────────────────────────────────────

/// Current (folded) view of one sealed-outbox record. Exposes only the
/// non-sensitive metadata needed for diagnostics and tests.
#[derive(Debug, Clone)]
pub struct OutboxRecordView {
    pub record_id: Uuid,
    pub execution_idempotency_key: Uuid,
    pub intent_id: Uuid,
    pub region_registry_id: Uuid,
    pub append_identity: Uuid,
    pub recipient_generation: u64,
    pub subject_pseudonym: String,
    pub state: String,
    pub has_ciphertext: bool,
}

/// Read the current state of every sealed-outbox record (latest entry per id).
pub fn read_outbox_records(outbox: &McpOutboxHandle) -> Result<Vec<OutboxRecordView>, CliError> {
    let sealed = SealedOutbox::open(outbox)?;
    let _guard = sealed.lock()?;
    let state = sealed.load_state()?;
    Ok(state
        .entries()
        .into_iter()
        .map(|entry| OutboxRecordView {
            record_id: entry.record_id,
            execution_idempotency_key: entry.execution_idempotency_key,
            intent_id: entry.intent_id,
            region_registry_id: entry.region_registry_id,
            append_identity: entry.append_identity,
            recipient_generation: entry.recipient_generation,
            subject_pseudonym: entry.subject_pseudonym.clone(),
            state: entry.state.clone(),
            has_ciphertext: entry.ciphertext_base64url.is_some(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::bool_assert_comparison,
        clippy::const_is_empty
    )]
    use super::*;

    #[test]
    fn sanitize_redacts_bearer_tokens() {
        let input = r#"{"authorization": "Bearer sk-abc123xyz"}"#;
        let result = sanitize_for_audit(input);
        assert!(!result.contains("sk-abc123xyz"));
        assert!(result.contains("[REDACTED]"));
    }

    #[test]
    fn sanitize_redacts_api_key_prefixes() {
        let token = format!("ghp_{}", "fixture-redact-sample");
        let input = format!("token: {token}");
        let result = sanitize_for_audit(&input);
        assert!(!result.contains(&token));
        assert!(result.contains("[REDACTED]"));
    }

    #[test]
    fn sanitize_leaves_normal_text_unchanged() {
        let input = "searching for context about deployment strategies";
        assert_eq!(sanitize_for_audit(input), input);
    }

    #[test]
    fn sanitize_redacts_email_addresses() {
        let input = r#"user logged in: admin@example.com with token"#;
        let result = sanitize_for_audit(input);
        assert!(!result.contains("admin@example.com"));
        assert!(result.contains("[REDACTED]"));
    }

    #[test]
    fn summarize_json_short_value() {
        let v = serde_json::json!({"key": "value"});
        let summary = summarize_json(&v);
        assert_eq!(summary, v.to_string());
        assert!(!summary.ends_with("..."));
    }

    #[test]
    fn summarize_json_long_value_is_truncated() {
        let long_text = "x".repeat(500);
        let v = serde_json::json!({"data": long_text});
        let summary = summarize_json(&v);
        assert!(summary.len() < v.to_string().len());
        assert!(summary.ends_with("..."));
    }

    #[test]
    fn truncate_handles_multibyte_boundaries() {
        let s = "áéíóú";
        let out = truncate(s, 3);
        assert!(s.starts_with(out));
        assert!(out.len() <= 3);
    }

    #[test]
    fn subject_pseudonym_is_domain_separated_hmac_hex() {
        let key = [7u8; 32];
        let pseudonym = subject_pseudonym(&key, "session-42").expect("pseudonym");
        assert!(pseudonym.starts_with("hmac-sha256:"));
        assert_eq!(pseudonym.len(), "hmac-sha256:".len() + 64);
        assert!(!pseudonym.contains("session-42"));

        // A bare (non-domain-separated) HMAC over the raw subject must differ,
        // proving the CLI pseudonym is not the API subject-lookup HMAC.
        let mut bare = <HmacSha256 as Mac>::new_from_slice(&key).expect("mac");
        bare.update(b"session-42");
        let bare_hex = format!("hmac-sha256:{:x}", bare.finalize().into_bytes());
        assert_ne!(pseudonym, bare_hex);
    }

    #[test]
    fn decode_key_material_accepts_hex_base64_and_rejects_wrong_length() {
        let key = [3u8; 32];
        let hex_key = hex::encode(key);
        assert_eq!(decode_key_material(&hex_key), Some(key.to_vec()));
        let b64 = base64::engine::general_purpose::STANDARD.encode(key);
        assert_eq!(decode_key_material(&b64), Some(key.to_vec()));
        assert_eq!(decode_key_material("deadbeef"), None);
    }

    #[test]
    fn hpke_seal_round_trips_only_with_recipient_key() {
        use hpke::{single_shot_open, OpModeR};
        let (private_key, public_key) = OutboxKem::gen_keypair();
        let aad = b"aad-bytes";
        let plaintext = br#"{"session_id":"s","tool_name":"t"}"#;
        let (encapped, ciphertext) =
            hpke_seal(&public_key.to_bytes(), aad, plaintext).expect("seal");

        let encapped_key =
            <OutboxKem as KemTrait>::EncappedKey::from_bytes(&encapped).expect("encapped");
        let opened = single_shot_open::<OutboxAead, OutboxKdf, OutboxKem>(
            &OpModeR::Base,
            &private_key,
            &encapped_key,
            TRAIL_INTENT_INFO,
            &ciphertext,
            aad,
        )
        .expect("open with recipient key");
        assert_eq!(opened, plaintext);

        // A different recipient key must fail to open.
        let (wrong_key, _) = OutboxKem::gen_keypair();
        let encapped_key2 =
            <OutboxKem as KemTrait>::EncappedKey::from_bytes(&encapped).expect("encapped");
        assert!(single_shot_open::<OutboxAead, OutboxKdf, OutboxKem>(
            &OpModeR::Base,
            &wrong_key,
            &encapped_key2,
            TRAIL_INTENT_INFO,
            &ciphertext,
            aad,
        )
        .is_err());
    }

    #[test]
    fn outbox_entry_checksum_detects_tampering() {
        let mut entry = OutboxEntry {
            schema: OUTBOX_ENTRY_SCHEMA.to_string(),
            record_id: Uuid::new_v4(),
            execution_idempotency_key: Uuid::new_v4(),
            intent_id: Uuid::new_v4(),
            region_registry_id: Uuid::new_v4(),
            append_identity: Uuid::new_v4(),
            event_kind: EVENT_KIND_MCP_TOOL_CALL.to_string(),
            recipient_generation: 1,
            subject_pseudonym: "hmac-sha256:aa".to_string(),
            state: STATE_PREPARED.to_string(),
            recipient_public_key_base64url: "pk".to_string(),
            aad_base64url: "aad".to_string(),
            expires_at: "2026-01-01T00:00:00Z".to_string(),
            encapsulated_key_base64url: None,
            ciphertext_base64url: None,
            payload_sha256: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            checksum: 0,
        };
        entry.checksum = entry.compute_checksum();
        assert!(entry.verify_checksum());
        entry.state = STATE_COMPLETED.to_string();
        assert!(!entry.verify_checksum());
    }

    #[test]
    fn both_compaction_thresholds_survive_missing_checkpoint_boundary() {
        for threshold in ["wal_size", "tombstones"] {
            let temp = tempfile::tempdir().expect("tempdir");
            let dir = temp.path().join(SEALED_OUTBOX_DIR_NAME);
            std::fs::create_dir_all(&dir).expect("outbox dir");
            let wal_path = dir.join(SEALED_OUTBOX_WAL_FILE);
            let lock_path = dir.join(SEALED_OUTBOX_LOCK_FILE);
            ensure_secure_file(&wal_path).expect("wal");
            ensure_secure_file(&lock_path).expect("lock");
            let outbox = SealedOutbox {
                checkpoint_path: dir.join(SEALED_OUTBOX_CHECKPOINT_FILE),
                dir,
                wal_path,
                lock_path,
            };
            let mut entry = OutboxEntry {
                schema: OUTBOX_ENTRY_SCHEMA.to_string(),
                record_id: Uuid::new_v4(),
                execution_idempotency_key: Uuid::new_v4(),
                intent_id: Uuid::new_v4(),
                region_registry_id: Uuid::new_v4(),
                append_identity: Uuid::new_v4(),
                event_kind: EVENT_KIND_MCP_TOOL_CALL.to_string(),
                recipient_generation: 1,
                subject_pseudonym: "hmac-sha256:aa".to_string(),
                state: STATE_COMPLETED.to_string(),
                recipient_public_key_base64url: "pk".to_string(),
                aad_base64url: "aad".to_string(),
                expires_at: "2027-01-01T00:00:00Z".to_string(),
                encapsulated_key_base64url: Some("enc".to_string()),
                ciphertext_base64url: Some("ciphertext".to_string()),
                payload_sha256: Some("digest".to_string()),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                checksum: 0,
            };
            entry.checksum = entry.compute_checksum();
            let mut state = OutboxState::default();
            let retained_id = match threshold {
                "wal_size" => {
                    entry.state = STATE_DISPATCHED.to_string();
                    entry.checksum = entry.compute_checksum();
                    state.apply(entry.clone());
                    state.wal_bytes = MAX_WAL_BYTES;
                    state.wal_records = 1;
                    entry.record_id
                }
                "tombstones" => {
                    state.apply(entry);
                    let mut active = OutboxEntry {
                        schema: OUTBOX_ENTRY_SCHEMA.to_string(),
                        record_id: Uuid::new_v4(),
                        execution_idempotency_key: Uuid::new_v4(),
                        intent_id: Uuid::new_v4(),
                        region_registry_id: Uuid::new_v4(),
                        append_identity: Uuid::new_v4(),
                        event_kind: EVENT_KIND_MCP_TOOL_CALL.to_string(),
                        recipient_generation: 1,
                        subject_pseudonym: "hmac-sha256:bb".to_string(),
                        state: STATE_DISPATCHED.to_string(),
                        recipient_public_key_base64url: "pk".to_string(),
                        aad_base64url: "aad".to_string(),
                        expires_at: "2027-01-01T00:00:00Z".to_string(),
                        encapsulated_key_base64url: None,
                        ciphertext_base64url: None,
                        payload_sha256: None,
                        created_at: "2026-01-01T00:00:00Z".to_string(),
                        checksum: 0,
                    };
                    active.checksum = active.compute_checksum();
                    let active_id = active.record_id;
                    state.apply(active);
                    state.wal_bytes = 1024;
                    state.wal_records = 2;
                    active_id
                }
                _ => unreachable!(),
            };

            assert!(
                outbox
                    .compact_if_needed(&mut state)
                    .expect("threshold compaction"),
                "{threshold} threshold must compact"
            );
            std::fs::remove_file(&outbox.checkpoint_path)
                .expect("simulate crash before checkpoint durability");
            let recovered = outbox.load_state().expect("recover compacted WAL");
            assert_eq!(recovered.current.len(), 1);
            assert!(recovered.current.contains_key(&retained_id));
        }
    }
}
