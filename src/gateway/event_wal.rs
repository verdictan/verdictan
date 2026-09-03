// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Segmented append-only WAL for gateway event delivery.
//!
//! Replaces the flat NDJSON spool with checksum-protected records, stable
//! IDs, immutable timestamps, segment/offset tracking, and persisted
//! acknowledgement checkpoints.
//!
//! Records are appended and `fsync`d before the first API delivery attempt.
//! Delivery uses a fixed pool with `try_acquire` for immediate admission.
//! Acknowledged records are compacted by advancing the checkpoint.
//!
//! Storage layout under `VERDICTAN_DATA_DIR/event-retry/`:
//! ```text
//! event-retry/
//!   segment-0000000000.wal
//!   segment-0000000001.wal
//!   checkpoint.json
//!   quarantine/
//! ```

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// ── Configuration ───────────────────────────────────────────────────────────

/// Default total WAL size limit.
const DEFAULT_TOTAL_BYTES: u64 = 1_073_741_824; // 1 GiB
/// Maximum total WAL size limit.
const MAX_TOTAL_BYTES: u64 = 10_737_418_240; // 10 GiB
/// Default per-segment size.
const DEFAULT_SEGMENT_BYTES: u64 = 16_777_216; // 16 MiB
/// Maximum per-segment size.
const MAX_SEGMENT_BYTES: u64 = 67_108_864; // 64 MiB
/// Default delivery pool size.
const DEFAULT_DELIVERY_POOL: usize = 4;
/// Maximum delivery pool size.
const MAX_DELIVERY_POOL: usize = 32;
/// Default filesystem blocking pool size.
const DEFAULT_FS_POOL: usize = 2;
/// Maximum filesystem blocking pool size.
const MAX_FS_POOL: usize = 8;
/// Maximum records per drain tick.
pub const DRAIN_TICK_RECORDS: usize = 256;
/// Maximum decoded+HTTP bytes per drain tick.
pub const DRAIN_TICK_BYTES: usize = 16_777_216; // 16 MiB
/// Maximum drain tick duration.
pub const DRAIN_TICK_DURATION: Duration = Duration::from_secs(5);
/// Connect timeout per delivery attempt.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Response timeout per delivery attempt.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
/// Absolute attempt deadline.
pub const ATTEMPT_DEADLINE: Duration = Duration::from_secs(15);
/// Maximum serialized size of one sanitized durable event, including WAL metadata.
pub const MAX_DURABLE_EVENT_BYTES: u64 = 262_144;
/// Maximum number of durable event records emitted by one governed request.
pub const MAX_DURABLE_EVENTS_PER_REQUEST: usize = 8;
/// Capacity reserved before a governed request is admitted (exactly 2 MiB).
pub const DURABLE_REQUEST_RESERVATION_BYTES: u64 =
    MAX_DURABLE_EVENT_BYTES * MAX_DURABLE_EVENTS_PER_REQUEST as u64;

const _: () = assert!(MAX_DURABLE_EVENT_BYTES == 262_144);
const _: () = assert!(MAX_DURABLE_EVENTS_PER_REQUEST == 8);
const _: () = assert!(DURABLE_REQUEST_RESERVATION_BYTES == 2_097_152);

/// Validated WAL configuration.
#[derive(Debug, Clone)]
pub struct WalConfig {
    /// Base directory for WAL segments.
    pub dir: PathBuf,
    /// Total WAL size limit.
    pub total_bytes: u64,
    /// Per-segment size limit.
    pub segment_bytes: u64,
    /// Delivery worker pool size.
    pub delivery_pool: usize,
    /// Filesystem blocking pool size.
    pub fs_pool: usize,
}

/// Configuration validation error.
#[derive(Debug, thiserror::Error)]
pub enum WalConfigError {
    #[error("{0}")]
    Invalid(String),
}

impl WalConfig {
    /// Create default configuration for a given data directory.
    pub fn new(data_dir: &Path) -> Result<Self, WalConfigError> {
        let dir = data_dir.join("event-retry");
        let total_bytes = match std::env::var("VERDICTAN_EVENT_WAL_MAX_BYTES") {
            Ok(value) => value.parse::<u64>().map_err(|_| {
                WalConfigError::Invalid(
                    "VERDICTAN_EVENT_WAL_MAX_BYTES must be an integer".to_string(),
                )
            })?,
            Err(std::env::VarError::NotPresent) => DEFAULT_TOTAL_BYTES,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(WalConfigError::Invalid(
                    "VERDICTAN_EVENT_WAL_MAX_BYTES must be valid UTF-8".to_string(),
                ));
            }
        };
        let config = Self {
            dir,
            total_bytes,
            segment_bytes: DEFAULT_SEGMENT_BYTES.min(total_bytes),
            delivery_pool: DEFAULT_DELIVERY_POOL,
            fs_pool: DEFAULT_FS_POOL,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), WalConfigError> {
        if self.total_bytes == 0 || self.total_bytes > MAX_TOTAL_BYTES {
            return Err(WalConfigError::Invalid(format!(
                "total_bytes must be in [1, {MAX_TOTAL_BYTES}], got {}",
                self.total_bytes
            )));
        }
        if self.segment_bytes == 0 || self.segment_bytes > MAX_SEGMENT_BYTES {
            return Err(WalConfigError::Invalid(format!(
                "segment_bytes must be in [1, {MAX_SEGMENT_BYTES}], got {}",
                self.segment_bytes
            )));
        }
        if self.segment_bytes > self.total_bytes {
            return Err(WalConfigError::Invalid(
                "segment_bytes cannot exceed total_bytes".into(),
            ));
        }
        if self.delivery_pool == 0 || self.delivery_pool > MAX_DELIVERY_POOL {
            return Err(WalConfigError::Invalid(format!(
                "delivery_pool must be in [1, {MAX_DELIVERY_POOL}], got {}",
                self.delivery_pool
            )));
        }
        if self.fs_pool == 0 || self.fs_pool > MAX_FS_POOL {
            return Err(WalConfigError::Invalid(format!(
                "fs_pool must be in [1, {MAX_FS_POOL}], got {}",
                self.fs_pool
            )));
        }
        Ok(())
    }
}

// ── WAL record ──────────────────────────────────────────────────────────────

/// A single WAL record with checksum protection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalRecord {
    /// Stable event identifier.
    pub event_id: String,
    /// Immutable creation timestamp (RFC 3339).
    pub timestamp: String,
    /// Segment number containing this record.
    pub segment: u64,
    /// Byte offset within the segment.
    pub offset: u64,
    /// CRC32 checksum of the serialized payload.
    pub checksum: u32,
    /// Serialized event payload.
    pub payload: serde_json::Value,
}

impl WalRecord {
    /// Compute CRC32 checksum of the payload.
    pub fn compute_checksum(payload: &serde_json::Value) -> u32 {
        let bytes = serde_json::to_vec(payload).unwrap_or_default();
        crc32fast::hash(&bytes)
    }

    /// Verify the record's checksum.
    pub fn verify_checksum(&self) -> bool {
        Self::compute_checksum(&self.payload) == self.checksum
    }
}

// ── Checkpoint ──────────────────────────────────────────────────────────────

/// Persisted acknowledgement checkpoint.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    /// Segment containing the next record that has not been acknowledged.
    pub segment: u64,
    /// Byte offset of the next record that has not been acknowledged.
    pub offset: u64,
    /// Number of records acknowledged in this checkpoint.
    pub acknowledged_count: u64,
}

/// One valid record and the durable frontier immediately after it.
#[derive(Debug, Clone)]
pub struct PendingRecord {
    pub record: WalRecord,
    pub next_segment: u64,
    pub next_offset: u64,
}

/// A malformed record that was quarantined and can be skipped durably.
#[derive(Debug, Clone)]
pub struct QuarantinedRecord {
    pub segment: u64,
    pub offset: u64,
    pub next_segment: u64,
    pub next_offset: u64,
    pub reason: String,
}

/// Next item observed at the persisted delivery frontier.
#[derive(Debug, Clone)]
pub enum PendingItem {
    Record(PendingRecord),
    Quarantined(QuarantinedRecord),
}

// ── Request reservation ─────────────────────────────────────────────────────

/// Capacity reserved before admitting one governed request.
///
/// Any bytes not converted into durable WAL records are released by `Drop`, so
/// early returns and every other terminal path return unused capacity.
#[derive(Debug)]
pub struct WalReservation {
    remaining_bytes: u64,
    events_written: usize,
    reserved_bytes: Arc<AtomicU64>,
}

impl WalReservation {
    /// Reserved capacity that remains available to this request.
    pub fn remaining_bytes(&self) -> u64 {
        self.remaining_bytes
    }

    /// Number of durable events written under this reservation.
    pub fn events_written(&self) -> usize {
        self.events_written
    }

    fn consume(&mut self, bytes: u64) {
        self.remaining_bytes -= bytes;
        self.events_written += 1;
        self.reserved_bytes.fetch_sub(bytes, Ordering::AcqRel);
    }
}

impl Drop for WalReservation {
    fn drop(&mut self) {
        if self.remaining_bytes > 0 {
            self.reserved_bytes
                .fetch_sub(self.remaining_bytes, Ordering::AcqRel);
            self.remaining_bytes = 0;
        }
    }
}

/// Group policy results into at most eight ordered durable-event batches.
///
/// The caller serializes each returned batch as one event. Order is preserved,
/// and no result is dropped when a request evaluates more than eight policies.
pub fn coalesce_policy_results(results: Vec<serde_json::Value>) -> Vec<Vec<serde_json::Value>> {
    if results.is_empty() {
        return Vec::new();
    }

    let batch_count = results.len().min(MAX_DURABLE_EVENTS_PER_REQUEST);
    let base_size = results.len() / batch_count;
    let larger_batches = results.len() % batch_count;
    let mut iter = results.into_iter();
    (0..batch_count)
        .map(|index| {
            let batch_size = base_size + usize::from(index < larger_batches);
            iter.by_ref().take(batch_size).collect()
        })
        .collect()
}

// ── WAL writer ──────────────────────────────────────────────────────────────

/// Append-only WAL writer with segment rotation and `fsync`.
pub struct WalWriter {
    config: WalConfig,
    current_segment: u64,
    current_offset: u64,
    current_file: Option<File>,
    total_bytes_written: AtomicU64,
    records_written: AtomicU64,
    reserved_bytes: Arc<AtomicU64>,
}

impl WalWriter {
    /// Open or create the WAL directory and recover state.
    pub fn open(config: WalConfig) -> io::Result<Self> {
        config
            .validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        fs::create_dir_all(&config.dir)?;
        load_checkpoint(&config.dir)?;

        // Find the latest segment and recover durable occupancy.
        let (segment, offset, total_bytes, record_count) = Self::recover_position(&config.dir)?;

        Ok(Self {
            config,
            current_segment: segment,
            current_offset: offset,
            current_file: None,
            total_bytes_written: AtomicU64::new(total_bytes),
            records_written: AtomicU64::new(record_count),
            reserved_bytes: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Recover the current write position from existing segments.
    fn recover_position(dir: &Path) -> io::Result<(u64, u64, u64, u64)> {
        let segments = segment_files(dir)?;
        let mut max_segment = 0;
        let mut latest_size = 0;
        let mut total_bytes = 0u64;
        let mut record_count = 0u64;

        for (segment, path) in segments {
            let size = path.metadata()?.len();
            total_bytes = total_bytes.checked_add(size).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "WAL byte count overflow")
            })?;
            record_count = record_count
                .checked_add(count_physical_records(&path)?)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "WAL record count overflow")
                })?;
            if segment >= max_segment {
                max_segment = segment;
                latest_size = size;
            }
        }

        Ok((max_segment, latest_size, total_bytes, record_count))
    }

    /// Segment file path for a given segment number.
    fn segment_path(&self, segment: u64) -> PathBuf {
        self.config.dir.join(format!("segment-{:010}.wal", segment))
    }

    /// Open the current segment file for appending.
    fn ensure_file(&mut self) -> io::Result<&mut File> {
        if self.current_file.is_none() {
            let path = self.segment_path(self.current_segment);
            let created = !path.exists();
            let file = OpenOptions::new().create(true).append(true).open(&path)?;
            if created {
                sync_directory(&self.config.dir)?;
            }
            self.current_file = Some(file);
        }
        self.current_file
            .as_mut()
            .ok_or_else(|| io::Error::other("WAL current file was not initialized"))
    }

    /// Rotate to a new segment.
    fn rotate(&mut self) -> io::Result<()> {
        if let Some(file) = self.current_file.take() {
            file.sync_all()?;
        }
        self.current_segment += 1;
        self.current_offset = 0;
        Ok(())
    }

    /// Reserve the worst-case WAL capacity for one governed request.
    ///
    /// Admission fails immediately unless all 2 MiB can be reserved.
    pub fn reserve_request(&self) -> io::Result<WalReservation> {
        loop {
            let reserved = self.reserved_bytes.load(Ordering::Acquire);
            let durable = self.total_bytes_written.load(Ordering::Acquire);
            let occupied = durable
                .checked_add(reserved)
                .ok_or_else(|| io::Error::other("WAL occupancy overflow"))?;
            let after_reservation = occupied
                .checked_add(DURABLE_REQUEST_RESERVATION_BYTES)
                .ok_or_else(|| io::Error::other("WAL occupancy overflow"))?;
            if after_reservation > self.config.total_bytes {
                return Err(io::Error::other(
                    "WAL full: request reservation cannot be satisfied",
                ));
            }
            if self
                .reserved_bytes
                .compare_exchange_weak(
                    reserved,
                    reserved + DURABLE_REQUEST_RESERVATION_BYTES,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return Ok(WalReservation {
                    remaining_bytes: DURABLE_REQUEST_RESERVATION_BYTES,
                    events_written: 0,
                    reserved_bytes: Arc::clone(&self.reserved_bytes),
                });
            }
        }
    }

    /// Append a record, `fsync`, and return the segment/offset.
    ///
    /// Returns `Err` if the WAL is full or the write fails. On error,
    /// no partial record is left — the caller must not proceed with
    /// upstream dispatch.
    pub fn append(
        &mut self,
        event_id: String,
        payload: serde_json::Value,
    ) -> io::Result<WalRecord> {
        self.append_internal(event_id, payload, None)
    }

    /// Append a sanitized event using capacity reserved before request admission.
    pub fn append_reserved(
        &mut self,
        reservation: &mut WalReservation,
        event_id: String,
        payload: serde_json::Value,
    ) -> io::Result<WalRecord> {
        if !Arc::ptr_eq(&self.reserved_bytes, &reservation.reserved_bytes) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "WAL reservation belongs to a different writer",
            ));
        }
        if reservation.events_written >= MAX_DURABLE_EVENTS_PER_REQUEST {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "durable event count exceeds per-request limit",
            ));
        }
        self.append_internal(event_id, payload, Some(reservation))
    }

    fn append_internal(
        &mut self,
        event_id: String,
        payload: serde_json::Value,
        mut reservation: Option<&mut WalReservation>,
    ) -> io::Result<WalRecord> {
        let checksum = WalRecord::compute_checksum(&payload);
        let timestamp = chrono::Utc::now().to_rfc3339();

        let mut record = WalRecord {
            event_id,
            timestamp,
            segment: self.current_segment,
            offset: self.current_offset,
            checksum,
            payload,
        };

        let mut encoded = encode_record(&record)?;
        let initial_encoded_bytes = encoded.len() as u64;
        if initial_encoded_bytes > MAX_DURABLE_EVENT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sanitized durable event exceeds 262144-byte limit",
            ));
        }
        if initial_encoded_bytes > self.config.segment_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "durable event exceeds WAL segment byte limit",
            ));
        }
        if self.current_offset > 0
            && self.current_offset + encoded.len() as u64 > self.config.segment_bytes
        {
            self.rotate()?;
            record.segment = self.current_segment;
            record.offset = 0;
            encoded = encode_record(&record)?;
        }
        let encoded_bytes = encoded.len() as u64;

        if let Some(active_reservation) = reservation.as_deref_mut() {
            if encoded_bytes > active_reservation.remaining_bytes {
                return Err(io::Error::other(
                    "WAL reservation exhausted by durable event",
                ));
            }
        } else {
            let mut durable = self.total_bytes_written.load(Ordering::Acquire);
            let reserved = self.reserved_bytes.load(Ordering::Acquire);
            let mut occupied = durable
                .checked_add(reserved)
                .and_then(|value| value.checked_add(encoded_bytes))
                .ok_or_else(|| io::Error::other("WAL occupancy overflow"))?;
            if occupied > self.config.total_bytes {
                let checkpoint = load_checkpoint(&self.config.dir)?;
                compact_segments(&self.config.dir, &checkpoint)?;
                durable = segment_files(&self.config.dir)?.into_iter().try_fold(
                    0u64,
                    |total, (_, path)| {
                        total
                            .checked_add(path.metadata()?.len())
                            .ok_or_else(|| io::Error::other("WAL byte count overflow"))
                    },
                )?;
                self.total_bytes_written.store(durable, Ordering::Release);
                occupied = durable
                    .checked_add(reserved)
                    .and_then(|value| value.checked_add(encoded_bytes))
                    .ok_or_else(|| io::Error::other("WAL occupancy overflow"))?;
                if occupied > self.config.total_bytes {
                    return Err(io::Error::other("WAL full: total byte limit exceeded"));
                }
            }
        }

        let write_offset = self.current_offset;
        let file = self.ensure_file()?;
        let rollback_len = file.metadata()?.len();
        if let Err(error) = file.write_all(&encoded).and_then(|()| file.sync_all()) {
            let _ = file.set_len(rollback_len);
            let _ = file.sync_all();
            return Err(error);
        }

        self.current_offset += encoded_bytes;
        self.total_bytes_written
            .fetch_add(encoded_bytes, Ordering::AcqRel);
        self.records_written.fetch_add(1, Ordering::AcqRel);
        if let Some(active_reservation) = reservation {
            active_reservation.consume(encoded_bytes);
        }

        Ok(WalRecord {
            segment: self.current_segment,
            offset: write_offset,
            ..record
        })
    }

    /// Read records from a segment starting at the given offset.
    pub fn read_segment(
        &self,
        segment: u64,
        start_offset: u64,
        max_records: usize,
    ) -> io::Result<Vec<WalRecord>> {
        let path = self.segment_path(segment);
        if !path.exists() {
            return Ok(Vec::new());
        }
        read_records_from_file(&self.config.dir, segment, &path, start_offset, max_records)
    }

    /// Read records from a checkpoint across all rotated segments.
    pub fn read_from(
        &self,
        checkpoint: &Checkpoint,
        max_records: usize,
    ) -> io::Result<Vec<WalRecord>> {
        validate_checkpoint_position(&self.config.dir, checkpoint)?;
        let mut records = Vec::new();
        for (segment, path) in segment_files(&self.config.dir)?
            .into_iter()
            .filter(|(segment, _)| *segment >= checkpoint.segment)
        {
            if records.len() >= max_records {
                break;
            }
            let start_offset = if segment == checkpoint.segment {
                checkpoint.offset
            } else {
                0
            };
            records.extend(read_records_from_file(
                &self.config.dir,
                segment,
                &path,
                start_offset,
                max_records - records.len(),
            )?);
        }
        Ok(records)
    }

    /// Return the next pending item, quarantining malformed complete records.
    pub fn next_pending(&self, checkpoint: &Checkpoint) -> io::Result<Option<PendingItem>> {
        validate_checkpoint_position(&self.config.dir, checkpoint)?;
        for (segment, path) in segment_files(&self.config.dir)?
            .into_iter()
            .filter(|(segment, _)| *segment >= checkpoint.segment)
        {
            let start_offset = if segment == checkpoint.segment {
                checkpoint.offset
            } else {
                0
            };
            let file_len = path.metadata()?.len();
            validate_record_boundary(&path, start_offset, file_len)?;
            if start_offset == file_len {
                continue;
            }

            let mut reader = BufReader::new(File::open(&path)?);
            reader.seek(SeekFrom::Start(start_offset))?;
            let mut bytes = Vec::new();
            let read = reader.read_until(b'\n', &mut bytes)?;
            if read == 0 {
                continue;
            }
            let next_offset = start_offset + read as u64;
            if bytes.last() != Some(&b'\n') {
                quarantine_corrupt_record(
                    &self.config.dir,
                    segment,
                    start_offset,
                    "truncated_record",
                    &bytes,
                )?;
                return Ok(Some(PendingItem::Quarantined(QuarantinedRecord {
                    segment,
                    offset: start_offset,
                    next_segment: segment,
                    next_offset,
                    reason: "truncated_record".to_string(),
                })));
            }

            let line = &bytes[..bytes.len() - 1];
            let parsed = serde_json::from_slice::<WalRecord>(line);
            let (record, reason) = match parsed {
                Ok(record) if record.segment != segment || record.offset != start_offset => {
                    (None, Some("position_mismatch"))
                }
                Ok(record) if !record.verify_checksum() => (None, Some("checksum_mismatch")),
                Ok(record) => (Some(record), None),
                Err(_) => (None, Some("invalid_json")),
            };
            if let Some(record) = record {
                return Ok(Some(PendingItem::Record(PendingRecord {
                    record,
                    next_segment: segment,
                    next_offset,
                })));
            }

            let reason = reason.unwrap_or("invalid_record");
            quarantine_corrupt_record(&self.config.dir, segment, start_offset, reason, line)?;
            return Ok(Some(PendingItem::Quarantined(QuarantinedRecord {
                segment,
                offset: start_offset,
                next_segment: segment,
                next_offset,
                reason: reason.to_string(),
            })));
        }
        Ok(None)
    }

    /// Persist the next unread frontier after one accepted or quarantined item.
    pub fn acknowledge(&mut self, next_segment: u64, next_offset: u64) -> io::Result<Checkpoint> {
        let mut checkpoint = load_checkpoint(&self.config.dir)?;
        if (next_segment, next_offset) < (checkpoint.segment, checkpoint.offset) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "WAL acknowledgement cannot move backwards",
            ));
        }
        checkpoint.segment = next_segment;
        checkpoint.offset = next_offset;
        checkpoint.acknowledged_count = checkpoint
            .acknowledged_count
            .checked_add(1)
            .ok_or_else(|| io::Error::other("WAL acknowledgement count overflow"))?;
        save_checkpoint(&self.config.dir, &checkpoint)?;

        let before = self.total_bytes_written.load(Ordering::Acquire);
        compact_segments(&self.config.dir, &checkpoint)?;
        let after =
            segment_files(&self.config.dir)?
                .into_iter()
                .try_fold(0u64, |total, (_, path)| {
                    total
                        .checked_add(path.metadata()?.len())
                        .ok_or_else(|| io::Error::other("WAL byte count overflow"))
                })?;
        if after <= before {
            self.total_bytes_written.store(after, Ordering::Release);
        }
        Ok(checkpoint)
    }

    /// Persist an operator-visible quarantine document for a permanent response.
    pub fn quarantine_permanent(
        &self,
        record: &WalRecord,
        status: u16,
        response_body: &str,
    ) -> io::Result<PathBuf> {
        let quarantine_dir = self.config.dir.join("quarantine");
        fs::create_dir_all(&quarantine_dir)?;
        let path = quarantine_dir.join(format!(
            "permanent-segment-{:010}-offset-{:020}.json",
            record.segment, record.offset
        ));
        if path.exists() {
            return Ok(path);
        }
        let temporary = quarantine_dir.join(format!(
            ".permanent-segment-{:010}-offset-{:020}.tmp-{}-{}",
            record.segment,
            record.offset,
            std::process::id(),
            CHECKPOINT_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let document = serde_json::json!({
            "segment": record.segment,
            "offset": record.offset,
            "event_id": record.event_id,
            "status": status,
            "response_body": response_body,
            "payload": record.payload,
        });
        let encoded = serde_json::to_vec(&document)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        fs::rename(&temporary, &path)?;
        sync_directory(&quarantine_dir)?;
        Ok(path)
    }

    pub fn checkpoint(&self) -> io::Result<Checkpoint> {
        load_checkpoint(&self.config.dir)
    }

    /// Current write position.
    pub fn position(&self) -> (u64, u64) {
        (self.current_segment, self.current_offset)
    }

    /// Total records written.
    pub fn records_written(&self) -> u64 {
        self.records_written.load(Ordering::Relaxed)
    }

    /// Total bytes written.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes_written.load(Ordering::Acquire)
    }

    /// Bytes currently held by admitted requests but not yet written.
    pub fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes.load(Ordering::Acquire)
    }
}

fn encode_record(record: &WalRecord) -> io::Result<Vec<u8>> {
    let mut encoded = serde_json::to_vec(record)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    encoded.push(b'\n');
    Ok(encoded)
}

fn parse_segment_number(name: &str) -> Option<u64> {
    name.strip_prefix("segment-")
        .and_then(|value| value.strip_suffix(".wal"))
        .and_then(|value| value.parse::<u64>().ok())
}

fn segment_files(dir: &Path) -> io::Result<Vec<(u64, PathBuf)>> {
    let mut segments = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if let Some(segment) = parse_segment_number(&name.to_string_lossy()) {
            let file_type = entry.file_type()?;
            if !file_type.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "WAL segment is not a regular file: {}",
                        entry.path().display()
                    ),
                ));
            }
            segments.push((segment, entry.path()));
        }
    }
    segments.sort_unstable_by_key(|(segment, _)| *segment);
    Ok(segments)
}

fn count_physical_records(path: &Path) -> io::Result<u64> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut count = 0u64;
    let mut bytes = Vec::new();
    loop {
        bytes.clear();
        if reader.read_until(b'\n', &mut bytes)? == 0 {
            break;
        }
        count += 1;
    }
    Ok(count)
}

fn read_records_from_file(
    dir: &Path,
    segment: u64,
    path: &Path,
    start_offset: u64,
    max_records: usize,
) -> io::Result<Vec<WalRecord>> {
    if max_records == 0 {
        return Ok(Vec::new());
    }
    let file_len = path.metadata()?.len();
    validate_record_boundary(path, start_offset, file_len)?;
    let mut reader = BufReader::new(File::open(path)?);
    reader.seek(SeekFrom::Start(start_offset))?;
    let mut records = Vec::new();
    let mut current_offset = start_offset;
    let mut bytes = Vec::new();

    while records.len() < max_records {
        bytes.clear();
        let read = reader.read_until(b'\n', &mut bytes)?;
        if read == 0 {
            break;
        }
        let line_offset = current_offset;
        current_offset += read as u64;
        if bytes.last() != Some(&b'\n') {
            quarantine_corrupt_record(dir, segment, line_offset, "truncated_record", &bytes)?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("truncated WAL record at segment {segment} offset {line_offset}"),
            ));
        }
        let line = &bytes[..bytes.len() - 1];
        let record = match serde_json::from_slice::<WalRecord>(line) {
            Ok(record) => record,
            Err(error) => {
                quarantine_corrupt_record(dir, segment, line_offset, "invalid_json", line)?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "invalid WAL record at segment {segment} offset {line_offset}: {error}"
                    ),
                ));
            }
        };
        if record.segment != segment || record.offset != line_offset {
            quarantine_corrupt_record(dir, segment, line_offset, "position_mismatch", line)?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("WAL record position mismatch at segment {segment} offset {line_offset}"),
            ));
        }
        if !record.verify_checksum() {
            warn!(
                segment,
                offset = line_offset,
                "WAL checksum mismatch quarantined"
            );
            quarantine_corrupt_record(dir, segment, line_offset, "checksum_mismatch", line)?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("WAL checksum mismatch at segment {segment} offset {line_offset}"),
            ));
        }
        records.push(record);
    }
    Ok(records)
}

#[derive(Serialize)]
struct CorruptRecordQuarantine<'a> {
    segment: u64,
    offset: u64,
    reason: &'a str,
    raw_record: String,
}

fn quarantine_corrupt_record(
    dir: &Path,
    segment: u64,
    offset: u64,
    reason: &str,
    raw_record: &[u8],
) -> io::Result<PathBuf> {
    let quarantine_dir = dir.join("quarantine");
    fs::create_dir_all(&quarantine_dir)?;
    let path = quarantine_dir.join(format!(
        "corrupt-segment-{segment:010}-offset-{offset:020}.json"
    ));
    if path.exists() {
        return Ok(path);
    }
    let temporary = quarantine_dir.join(format!(
        ".corrupt-segment-{segment:010}-offset-{offset:020}.tmp-{}",
        std::process::id()
    ));
    let document = CorruptRecordQuarantine {
        segment,
        offset,
        reason,
        raw_record: String::from_utf8_lossy(raw_record).into_owned(),
    };
    let encoded = serde_json::to_vec(&document)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    fs::rename(&temporary, &path)?;
    sync_directory(&quarantine_dir)?;
    Ok(path)
}

fn sync_directory(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

fn validate_record_boundary(path: &Path, offset: u64, file_len: u64) -> io::Result<()> {
    if offset > file_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint offset exceeds WAL segment length",
        ));
    }
    if offset == 0 || offset == file_len {
        return Ok(());
    }
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset - 1))?;
    let mut previous = [0u8; 1];
    file.read_exact(&mut previous)?;
    if previous[0] != b'\n' {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint offset is not a WAL record boundary",
        ));
    }
    Ok(())
}

fn validate_checkpoint_position(dir: &Path, checkpoint: &Checkpoint) -> io::Result<()> {
    if checkpoint.segment == 0 && checkpoint.offset == 0 && checkpoint.acknowledged_count == 0 {
        return Ok(());
    }
    let path = dir.join(format!("segment-{:010}.wal", checkpoint.segment));
    if !path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint references a missing WAL segment",
        ));
    }
    validate_record_boundary(&path, checkpoint.offset, path.metadata()?.len())
}

// ── Checkpoint persistence ──────────────────────────────────────────────────

/// Load the checkpoint from disk.
pub fn load_checkpoint(dir: &Path) -> io::Result<Checkpoint> {
    let path = dir.join("checkpoint.json");
    if !path.exists() {
        return Ok(Checkpoint::default());
    }
    let content = fs::read_to_string(&path)?;
    let checkpoint: Checkpoint = serde_json::from_str(&content)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    validate_checkpoint_position(dir, &checkpoint)?;
    Ok(checkpoint)
}

/// Persist the checkpoint atomically (write + rename + fsync).
pub fn save_checkpoint(dir: &Path, checkpoint: &Checkpoint) -> io::Result<()> {
    validate_checkpoint_position(dir, checkpoint)?;
    let path = dir.join("checkpoint.json");
    let tmp_path = dir.join(format!(
        ".checkpoint.json.tmp-{}-{}",
        std::process::id(),
        CHECKPOINT_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));

    let content = serde_json::to_string_pretty(checkpoint)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp_path)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;

    fs::rename(&tmp_path, &path)?;
    sync_directory(dir)?;

    Ok(())
}

static CHECKPOINT_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Remove segments that are fully acknowledged.
pub fn compact_segments(dir: &Path, checkpoint: &Checkpoint) -> io::Result<usize> {
    validate_checkpoint_position(dir, checkpoint)?;
    let mut removed = 0;

    for (segment, path) in segment_files(dir)? {
        // The checkpoint is the next unread byte. Only an earlier segment is
        // unambiguously fully acknowledged; the checkpoint segment is retained
        // even when the frontier currently equals its length.
        if segment < checkpoint.segment {
            fs::remove_file(path)?;
            removed += 1;
        }
    }

    if removed > 0 {
        sync_directory(dir)?;
        info!(removed, "compacted acknowledged WAL segments");
    }

    Ok(removed)
}

#[cfg(test)]
mod tests {
    // Test-only lint suppressions. No production `dead_code` annotations remain
    // for pending delivery work in this module.
    #![allow(
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
    use tempfile::TempDir;

    fn test_config(dir: &Path) -> WalConfig {
        WalConfig {
            dir: dir.to_path_buf(),
            total_bytes: 1_048_576, // 1 MiB for tests
            segment_bytes: 4_096,
            delivery_pool: 2,
            fs_pool: 1,
        }
    }

    #[test]
    fn append_and_read() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let mut writer = WalWriter::open(config).unwrap();

        let record = writer
            .append("evt-001".to_string(), serde_json::json!({"type": "test"}))
            .unwrap();

        assert!(record.verify_checksum());
        assert_eq!(record.event_id, "evt-001");
        assert_eq!(writer.records_written(), 1);

        let records = writer.read_segment(record.segment, 0, 10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].event_id, "evt-001");
    }

    #[test]
    fn segment_rotation() {
        let tmp = TempDir::new().unwrap();
        let config = WalConfig {
            segment_bytes: 512, // tiny segment to force rotation
            ..test_config(tmp.path())
        };
        let mut writer = WalWriter::open(config).unwrap();

        // Write enough records to force rotation.
        for i in 0..10 {
            writer
                .append(
                    format!("evt-{i:03}"),
                    serde_json::json!({"idx": i, "data": "padding-padding-padding"}),
                )
                .unwrap();
        }

        // Should have rotated to multiple segments.
        assert!(writer.position().0 > 0);
    }

    #[test]
    fn wal_full_rejection() {
        let tmp = TempDir::new().unwrap();
        let config = WalConfig {
            total_bytes: 512,
            segment_bytes: 512,
            ..test_config(tmp.path())
        };
        let mut writer = WalWriter::open(config).unwrap();

        // Fill the WAL.
        let mut last_ok = true;
        for i in 0..100 {
            match writer.append(
                format!("evt-{i:03}"),
                serde_json::json!({"data": "x".repeat(100)}),
            ) {
                Ok(_) => {}
                Err(e) => {
                    assert!(e.to_string().contains("WAL full"));
                    last_ok = false;
                    break;
                }
            }
        }
        assert!(!last_ok, "WAL should have rejected at least one write");
    }

    #[test]
    fn checkpoint_round_trip() {
        let tmp = TempDir::new().unwrap();
        let mut writer = WalWriter::open(test_config(tmp.path())).unwrap();
        writer
            .append(
                "evt-checkpoint".to_string(),
                serde_json::json!({"ok": true}),
            )
            .unwrap();
        let (segment, offset) = writer.position();
        let checkpoint = Checkpoint {
            segment,
            offset,
            acknowledged_count: 1,
        };

        save_checkpoint(tmp.path(), &checkpoint).unwrap();
        let loaded = load_checkpoint(tmp.path()).unwrap();

        assert_eq!(loaded.segment, segment);
        assert_eq!(loaded.offset, offset);
        assert_eq!(loaded.acknowledged_count, 1);
        assert!(fs::read_dir(tmp.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("checkpoint.json.tmp")));
    }

    #[test]
    fn missing_checkpoint_returns_default() {
        let tmp = TempDir::new().unwrap();
        let checkpoint = load_checkpoint(tmp.path()).unwrap();
        assert_eq!(checkpoint.segment, 0);
        assert_eq!(checkpoint.offset, 0);
    }

    #[test]
    fn compact_removes_old_segments() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();

        // Create fake segment files.
        for i in 0..5 {
            File::create(dir.join(format!("segment-{:010}.wal", i))).unwrap();
        }

        let checkpoint = Checkpoint {
            segment: 3,
            offset: 0,
            acknowledged_count: 0,
        };

        let removed = compact_segments(dir, &checkpoint).unwrap();
        assert_eq!(removed, 3); // segments 0, 1, 2 removed

        // segments 3 and 4 should remain.
        assert!(dir.join("segment-0000000003.wal").exists());
        assert!(dir.join("segment-0000000004.wal").exists());
    }

    #[test]
    fn corrupt_record_is_quarantined_and_fails_closed() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        fs::create_dir_all(&config.dir).unwrap();

        // Write a valid record followed by a corrupt one.
        let path = config.dir.join("segment-0000000000.wal");
        let mut file = File::create(&path).unwrap();
        let valid = serde_json::json!({
            "event_id": "evt-valid",
            "timestamp": "2024-01-01T00:00:00Z",
            "segment": 0,
            "offset": 0,
            "checksum": WalRecord::compute_checksum(&serde_json::json!({"ok": true})),
            "payload": {"ok": true}
        });
        writeln!(file, "{}", serde_json::to_string(&valid).unwrap()).unwrap();
        writeln!(file, "{{corrupt garbage}}").unwrap();
        file.sync_all().unwrap();

        let writer = WalWriter::open(config).unwrap();
        let error = writer.read_segment(0, 0, 10).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let quarantined = fs::read_dir(tmp.path().join("quarantine"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(quarantined.len(), 1);
        let document: serde_json::Value =
            serde_json::from_slice(&fs::read(&quarantined[0]).unwrap()).unwrap();
        assert_eq!(document["reason"], "invalid_json");
        assert!(document["raw_record"]
            .as_str()
            .unwrap()
            .contains("corrupt garbage"));
    }

    #[test]
    fn config_validation() {
        let tmp = TempDir::new().unwrap();

        // Zero total bytes.
        let mut config = test_config(tmp.path());
        config.total_bytes = 0;
        assert!(config.validate().is_err());

        // Segment > total.
        let mut config = test_config(tmp.path());
        config.segment_bytes = config.total_bytes + 1;
        assert!(config.validate().is_err());

        // Valid default.
        let config = test_config(tmp.path());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn open_recovers_total_bytes_and_record_count() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let (bytes, count) = {
            let mut writer = WalWriter::open(config.clone()).unwrap();
            for index in 0..3 {
                writer
                    .append(format!("evt-{index}"), serde_json::json!({"index": index}))
                    .unwrap();
            }
            (writer.total_bytes(), writer.records_written())
        };

        let recovered = WalWriter::open(config).unwrap();
        assert_eq!(recovered.total_bytes(), bytes);
        assert_eq!(recovered.records_written(), count);
        assert_eq!(count, 3);
    }

    #[test]
    fn read_from_iterates_across_rotated_segments() {
        let tmp = TempDir::new().unwrap();
        let config = WalConfig {
            segment_bytes: 512,
            ..test_config(tmp.path())
        };
        let mut writer = WalWriter::open(config).unwrap();
        for index in 0..12 {
            writer
                .append(
                    format!("evt-{index:02}"),
                    serde_json::json!({"index": index, "padding": "xxxxxxxxxxxxxxxx"}),
                )
                .unwrap();
        }
        assert!(writer.position().0 > 0);

        let records = writer.read_from(&Checkpoint::default(), 100).unwrap();
        assert_eq!(records.len(), 12);
        assert_eq!(records.first().unwrap().event_id, "evt-00");
        assert_eq!(records.last().unwrap().event_id, "evt-11");
        assert!(records
            .windows(2)
            .all(|pair| (pair[0].segment, pair[0].offset) < (pair[1].segment, pair[1].offset)));
    }

    #[test]
    fn rotated_record_persists_its_actual_position() {
        let tmp = TempDir::new().unwrap();
        let config = WalConfig {
            segment_bytes: 400,
            ..test_config(tmp.path())
        };
        let mut writer = WalWriter::open(config).unwrap();
        writer
            .append(
                "evt-first".to_string(),
                serde_json::json!({"padding": "x".repeat(120)}),
            )
            .unwrap();
        let rotated = writer
            .append(
                "evt-rotated".to_string(),
                serde_json::json!({"padding": "x".repeat(120)}),
            )
            .unwrap();

        assert!(rotated.segment > 0);
        assert_eq!(rotated.offset, 0);
        let persisted = writer
            .read_segment(rotated.segment, 0, 1)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(persisted.segment, rotated.segment);
        assert_eq!(persisted.offset, rotated.offset);
    }

    #[test]
    fn corrupt_checkpoint_is_rejected_on_open() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        fs::create_dir_all(&config.dir).unwrap();
        fs::write(config.dir.join("checkpoint.json"), b"{not-json").unwrap();

        let error = WalWriter::open(config).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn checkpoint_rejects_non_boundary_offset() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let mut writer = WalWriter::open(config.clone()).unwrap();
        writer
            .append("evt".to_string(), serde_json::json!({"ok": true}))
            .unwrap();
        let checkpoint = Checkpoint {
            segment: 0,
            offset: 1,
            acknowledged_count: 0,
        };

        let error = save_checkpoint(&config.dir, &checkpoint).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn checksum_failure_is_quarantined() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        fs::create_dir_all(&config.dir).unwrap();
        let record = WalRecord {
            event_id: "evt-bad-checksum".to_string(),
            timestamp: "2026-08-01T00:00:00Z".to_string(),
            segment: 0,
            offset: 0,
            checksum: WalRecord::compute_checksum(&serde_json::json!({"important": true}))
                ^ u32::MAX,
            payload: serde_json::json!({"important": true}),
        };
        fs::write(
            config.dir.join("segment-0000000000.wal"),
            encode_record(&record).unwrap(),
        )
        .unwrap();
        let writer = WalWriter::open(config.clone()).unwrap();

        let error = writer.read_segment(0, 0, 1).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let quarantine_path = config
            .dir
            .join("quarantine/corrupt-segment-0000000000-offset-00000000000000000000.json");
        let document: serde_json::Value =
            serde_json::from_slice(&fs::read(quarantine_path).unwrap()).unwrap();
        assert_eq!(document["reason"], "checksum_mismatch");
    }

    #[test]
    fn compaction_retains_checkpoint_segment() {
        let tmp = TempDir::new().unwrap();
        for segment in 0..=2 {
            fs::write(tmp.path().join(format!("segment-{segment:010}.wal")), b"").unwrap();
        }
        let checkpoint = Checkpoint {
            segment: 2,
            offset: 0,
            acknowledged_count: 2,
        };

        assert_eq!(compact_segments(tmp.path(), &checkpoint).unwrap(), 2);
        assert!(!tmp.path().join("segment-0000000000.wal").exists());
        assert!(!tmp.path().join("segment-0000000001.wal").exists());
        assert!(tmp.path().join("segment-0000000002.wal").exists());
    }

    fn reservation_config(dir: &Path) -> WalConfig {
        WalConfig {
            dir: dir.to_path_buf(),
            total_bytes: DURABLE_REQUEST_RESERVATION_BYTES * 2,
            segment_bytes: 1_048_576,
            delivery_pool: 2,
            fs_pool: 1,
        }
    }

    #[test]
    fn request_reservation_is_exact_and_drop_releases_unused_bytes() {
        let tmp = TempDir::new().unwrap();
        let mut writer = WalWriter::open(reservation_config(tmp.path())).unwrap();
        {
            let mut reservation = writer.reserve_request().unwrap();
            assert_eq!(
                reservation.remaining_bytes(),
                DURABLE_REQUEST_RESERVATION_BYTES
            );
            assert_eq!(writer.reserved_bytes(), DURABLE_REQUEST_RESERVATION_BYTES);
            writer
                .append_reserved(
                    &mut reservation,
                    "evt-reserved".to_string(),
                    serde_json::json!({"ok": true}),
                )
                .unwrap();
            assert_eq!(reservation.events_written(), 1);
            assert!(reservation.remaining_bytes() < DURABLE_REQUEST_RESERVATION_BYTES);
            assert_eq!(
                writer.total_bytes() + writer.reserved_bytes(),
                DURABLE_REQUEST_RESERVATION_BYTES
            );
        }
        assert_eq!(writer.reserved_bytes(), 0);
        assert!(writer.total_bytes() > 0);
    }

    #[test]
    fn reservation_blocks_over_admission_and_can_be_reused_after_drop() {
        let tmp = TempDir::new().unwrap();
        let config = WalConfig {
            total_bytes: DURABLE_REQUEST_RESERVATION_BYTES,
            ..reservation_config(tmp.path())
        };
        let writer = WalWriter::open(config).unwrap();
        let first = writer.reserve_request().unwrap();
        assert!(writer.reserve_request().is_err());
        drop(first);
        assert!(writer.reserve_request().is_ok());
    }

    #[test]
    fn reservation_enforces_eight_event_limit() {
        let tmp = TempDir::new().unwrap();
        let mut writer = WalWriter::open(reservation_config(tmp.path())).unwrap();
        let mut reservation = writer.reserve_request().unwrap();
        for index in 0..MAX_DURABLE_EVENTS_PER_REQUEST {
            writer
                .append_reserved(
                    &mut reservation,
                    format!("evt-{index}"),
                    serde_json::json!({"index": index}),
                )
                .unwrap();
        }

        let error = writer
            .append_reserved(
                &mut reservation,
                "evt-too-many".to_string(),
                serde_json::json!({"index": 9}),
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn oversized_sanitized_record_is_rejected_without_writing() {
        let tmp = TempDir::new().unwrap();
        let config = WalConfig {
            segment_bytes: MAX_DURABLE_EVENT_BYTES,
            ..reservation_config(tmp.path())
        };
        let mut writer = WalWriter::open(config).unwrap();
        let error = writer
            .append(
                "evt-oversized".to_string(),
                serde_json::json!({"sanitized": "x".repeat(MAX_DURABLE_EVENT_BYTES as usize)}),
            )
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(writer.total_bytes(), 0);
        assert_eq!(writer.records_written(), 0);
    }

    #[test]
    fn policy_results_coalesce_to_eight_ordered_batches() {
        let results = (0..19)
            .map(|index| serde_json::json!({"index": index}))
            .collect::<Vec<_>>();
        let batches = coalesce_policy_results(results);

        assert_eq!(batches.len(), MAX_DURABLE_EVENTS_PER_REQUEST);
        let flattened = batches.into_iter().flatten().collect::<Vec<_>>();
        assert_eq!(flattened.len(), 19);
        assert!(flattened
            .iter()
            .enumerate()
            .all(|(index, value)| value["index"] == index));
    }

    #[test]
    fn hard_cap_is_ten_gibibytes() {
        let tmp = TempDir::new().unwrap();
        let mut config = test_config(tmp.path());
        config.total_bytes = 10_737_418_240;
        assert!(config.validate().is_ok());
        config.total_bytes += 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn append_before_checkpoint_replays_after_restart() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let event_id = {
            let mut writer = WalWriter::open(config.clone()).unwrap();
            writer
                .append(
                    "evt-crash".to_string(),
                    serde_json::json!({"crash": "after_append"}),
                )
                .unwrap()
                .event_id
        };

        let reopened = WalWriter::open(config).unwrap();
        let pending = reopened
            .next_pending(&reopened.checkpoint().unwrap())
            .unwrap()
            .unwrap();
        let PendingItem::Record(pending) = pending else {
            panic!("expected durable record");
        };
        assert_eq!(pending.record.event_id, event_id);
    }

    #[test]
    fn malformed_record_is_quarantined_and_checkpointed_past() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        fs::create_dir_all(&config.dir).unwrap();
        let path = config.dir.join("segment-0000000000.wal");
        fs::write(&path, b"{malformed}\n").unwrap();
        let mut writer = WalWriter::open(config.clone()).unwrap();

        let item = writer
            .next_pending(&Checkpoint::default())
            .unwrap()
            .unwrap();
        let PendingItem::Quarantined(item) = item else {
            panic!("expected quarantined record");
        };
        assert_eq!(item.reason, "invalid_json");
        writer
            .acknowledge(item.next_segment, item.next_offset)
            .unwrap();
        assert!(writer
            .next_pending(&writer.checkpoint().unwrap())
            .unwrap()
            .is_none());
        assert!(config
            .dir
            .join("quarantine/corrupt-segment-0000000000-offset-00000000000000000000.json")
            .exists());
    }

    #[test]
    fn permanent_rejection_quarantine_is_durable() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path());
        let mut writer = WalWriter::open(config.clone()).unwrap();
        let record = writer
            .append(
                "evt-permanent".to_string(),
                serde_json::json!({"event_id": "evt-permanent"}),
            )
            .unwrap();
        let path = writer
            .quarantine_permanent(&record, 422, "invalid event")
            .unwrap();

        let document: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(document["event_id"], "evt-permanent");
        assert_eq!(document["status"], 422);
        assert_eq!(document["response_body"], "invalid event");
    }
}
