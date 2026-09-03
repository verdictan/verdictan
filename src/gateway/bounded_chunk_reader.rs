// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! PERF-012 — single bounded chunk reader for non-streaming upstream bodies.
//!
//! Production hard cap is 16 MiB. Larger `Content-Length` values are rejected
//! before any body bytes are buffered. Chunked / misreported bodies stop at
//! `limit + 1` bytes so overflow is detectable without exceeding the 20 MiB
//! in-flight RSS ceiling.

use bytes::{Bytes, BytesMut};
use futures_util::stream::Stream;
use futures_util::StreamExt;
use http::HeaderMap;

/// Production response body hard limit (PERF-012).
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Maximum buffered bytes permitted per in-flight response (PERF-012 completion).
pub const MAX_IN_FLIGHT_RESPONSE_BUFFER_BYTES: usize = 20 * 1024 * 1024;

/// Stop reading after this many bytes (`limit + 1`) to detect overflow.
#[inline]
pub fn overflow_stop_bytes(limit: usize) -> usize {
    limit.saturating_add(1)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundedChunkReadError {
    /// Declared `Content-Length` exceeds the configured limit.
    ContentLengthExceeded { content_length: usize, limit: usize },
    /// Body bytes read exceeded the limit (stopped at `limit + 1`).
    BodyExceeded { read: usize, limit: usize },
    /// Underlying stream/body read failure.
    BodyRead(String),
}

impl std::fmt::Display for BoundedChunkReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ContentLengthExceeded {
                content_length,
                limit,
            } => write!(
                f,
                "Content-Length {content_length} exceeds response size limit of {limit} bytes"
            ),
            Self::BodyExceeded { read, limit } => write!(
                f,
                "response body size {read} bytes exceeds limit of {limit} bytes"
            ),
            Self::BodyRead(message) => write!(f, "response body read failed: {message}"),
        }
    }
}

impl std::error::Error for BoundedChunkReadError {}

impl BoundedChunkReadError {
    pub fn actual(&self) -> usize {
        match self {
            Self::ContentLengthExceeded { content_length, .. } => *content_length,
            Self::BodyExceeded { read, .. } => *read,
            Self::BodyRead(_) => 0,
        }
    }

    pub fn limit(&self) -> usize {
        match self {
            Self::ContentLengthExceeded { limit, .. } | Self::BodyExceeded { limit, .. } => *limit,
            Self::BodyRead(_) => DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    pub fn is_size_exceeded(&self) -> bool {
        matches!(
            self,
            Self::ContentLengthExceeded { .. } | Self::BodyExceeded { .. }
        )
    }
}

/// Parse `Content-Length` when present and well-formed.
pub fn content_length_from_headers(headers: &HeaderMap) -> Option<usize> {
    let value = headers.get(http::header::CONTENT_LENGTH)?;
    let text = value.to_str().ok()?;
    text.parse::<usize>().ok()
}

/// Reject responses whose declared `Content-Length` already exceeds `limit`.
pub fn reject_oversized_content_length(
    headers: &HeaderMap,
    limit: usize,
) -> Result<(), BoundedChunkReadError> {
    if let Some(content_length) = content_length_from_headers(headers) {
        if content_length > limit {
            return Err(BoundedChunkReadError::ContentLengthExceeded {
                content_length,
                limit,
            });
        }
    }
    Ok(())
}

/// Effective production response limit: configured value tightened to the 16 MiB hard cap.
pub fn effective_response_limit(configured: Option<usize>) -> usize {
    match configured {
        Some(value) => value.min(DEFAULT_MAX_RESPONSE_BYTES),
        None => DEFAULT_MAX_RESPONSE_BYTES,
    }
}

/// Read a byte stream with a hard stop at `limit + 1` bytes.
///
/// On success the returned buffer is `<= limit`. On overflow the error reports
/// `read == limit + 1` (or less when the final chunk was partially taken) and
/// never retains more than `overflow_stop_bytes(limit)` bytes.
pub async fn read_bounded_chunks<S, E>(
    mut stream: S,
    limit: usize,
) -> Result<Bytes, BoundedChunkReadError>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    let stop_at = overflow_stop_bytes(limit);
    debug_assert!(
        stop_at <= MAX_IN_FLIGHT_RESPONSE_BUFFER_BYTES,
        "PERF-012: stop_at must stay within the 20 MiB in-flight RSS ceiling"
    );

    let mut buf = BytesMut::with_capacity(limit.min(65_536));
    while let Some(item) = stream.next().await {
        let chunk = item.map_err(|error| BoundedChunkReadError::BodyRead(error.to_string()))?;
        if chunk.is_empty() {
            continue;
        }
        let remaining = stop_at.saturating_sub(buf.len());
        if remaining == 0 {
            return Err(BoundedChunkReadError::BodyExceeded {
                read: buf.len(),
                limit,
            });
        }
        if chunk.len() > remaining {
            buf.extend_from_slice(&chunk[..remaining]);
            return Err(BoundedChunkReadError::BodyExceeded {
                read: buf.len(),
                limit,
            });
        }
        buf.extend_from_slice(&chunk);
    }

    if buf.len() > limit {
        return Err(BoundedChunkReadError::BodyExceeded {
            read: buf.len(),
            limit,
        });
    }
    Ok(buf.freeze())
}

/// Read a `reqwest::Response` body with Content-Length rejection and chunk bounds.
pub async fn read_reqwest_response_bounded(
    response: reqwest::Response,
    limit: usize,
) -> Result<(http::StatusCode, HeaderMap, Bytes), BoundedChunkReadError> {
    let status = response.status();
    let headers = response.headers().clone();
    reject_oversized_content_length(&headers, limit)?;

    let stream = response.bytes_stream();
    let body = read_bounded_chunks(stream, limit).await?;
    Ok((status, headers, body))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use bytes::Bytes;
    use futures_util::stream;
    use http::{HeaderMap, HeaderValue};

    #[test]
    fn production_defaults_match_perf_012() {
        assert_eq!(DEFAULT_MAX_RESPONSE_BYTES, 16 * 1024 * 1024);
        assert_eq!(MAX_IN_FLIGHT_RESPONSE_BUFFER_BYTES, 20 * 1024 * 1024);
        assert!(
            overflow_stop_bytes(DEFAULT_MAX_RESPONSE_BYTES) <= MAX_IN_FLIGHT_RESPONSE_BUFFER_BYTES
        );
        assert_eq!(
            overflow_stop_bytes(DEFAULT_MAX_RESPONSE_BYTES),
            DEFAULT_MAX_RESPONSE_BYTES + 1
        );
    }

    #[test]
    fn effective_response_limit_defaults_to_sixteen_mib() {
        assert_eq!(effective_response_limit(None), DEFAULT_MAX_RESPONSE_BYTES);
        assert_eq!(effective_response_limit(Some(1024)), 1024);
        assert_eq!(
            effective_response_limit(Some(DEFAULT_MAX_RESPONSE_BYTES * 2)),
            DEFAULT_MAX_RESPONSE_BYTES
        );
    }

    #[test]
    fn reject_content_length_over_limit() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_static("100"),
        );
        let err = reject_oversized_content_length(&headers, 50).unwrap_err();
        assert!(matches!(
            err,
            BoundedChunkReadError::ContentLengthExceeded {
                content_length: 100,
                limit: 50
            }
        ));
    }

    #[test]
    fn accept_content_length_at_limit() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("50"));
        assert!(reject_oversized_content_length(&headers, 50).is_ok());
    }

    #[tokio::test]
    async fn read_bounded_chunks_stops_at_limit_plus_one() {
        let chunks = vec![
            Ok::<Bytes, std::io::Error>(Bytes::from(vec![b'a'; 40])),
            Ok(Bytes::from(vec![b'b'; 20])),
        ];
        let err = read_bounded_chunks(stream::iter(chunks), 50)
            .await
            .unwrap_err();
        match err {
            BoundedChunkReadError::BodyExceeded { read, limit } => {
                assert_eq!(limit, 50);
                assert_eq!(read, 51);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[tokio::test]
    async fn read_bounded_chunks_accepts_exact_limit() {
        let chunks = vec![Ok::<Bytes, std::io::Error>(Bytes::from(vec![b'x'; 50]))];
        let body = read_bounded_chunks(stream::iter(chunks), 50)
            .await
            .expect("exact limit ok");
        assert_eq!(body.len(), 50);
    }

    #[tokio::test]
    async fn read_bounded_chunks_never_buffers_past_stop_at() {
        let huge = Bytes::from(vec![b'z'; 1024]);
        let chunks = vec![
            Ok::<Bytes, std::io::Error>(huge.clone()),
            Ok(huge.clone()),
            Ok(huge),
        ];
        let err = read_bounded_chunks(stream::iter(chunks), 100)
            .await
            .unwrap_err();
        match err {
            BoundedChunkReadError::BodyExceeded { read, limit } => {
                assert_eq!(limit, 100);
                assert_eq!(read, 101);
                assert!(read <= MAX_IN_FLIGHT_RESPONSE_BUFFER_BYTES);
            }
            other => panic!("unexpected error: {other}"),
        }
    }
}
