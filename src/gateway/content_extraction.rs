// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use futures_util::{stream, StreamExt};
use reqwest::Url;
use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const MAX_URLS: usize = 8;
const MAX_TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_AGGREGATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CONCURRENT_FETCHES: usize = 4;

macro_rules! static_regex {
    ($pattern:expr) => {{
        static RE: std::sync::OnceLock<regex_lite::Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| {
            #[allow(clippy::expect_used)]
            regex_lite::Regex::new($pattern).expect("static regex pattern")
        })
    }};
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ExtractionErrorAction {
    #[default]
    Warn,
    Block,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ContentExtractorConfig {
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: usize,
    #[serde(default = "default_true")]
    pub fetch_urls: bool,
    #[serde(default)]
    pub action_on_error: ExtractionErrorAction,
}

impl Default for ContentExtractorConfig {
    fn default() -> Self {
        Self {
            allow_hosts: Vec::new(),
            timeout_ms: default_timeout_ms(),
            max_bytes: default_max_bytes(),
            fetch_urls: true,
            action_on_error: ExtractionErrorAction::Warn,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ExtractionResult {
    pub urls: Vec<String>,
    pub extracted_text: Vec<String>,
    pub blocked_reason: Option<String>,
}

fn default_timeout_ms() -> u64 {
    2_000
}

fn default_max_bytes() -> usize {
    65_536
}

fn default_true() -> bool {
    true
}

fn bounded_total_timeout(timeout_ms: u64) -> Duration {
    Duration::from_millis(timeout_ms.max(1)).min(MAX_TOTAL_TIMEOUT)
}

fn bounded_body_limit(max_bytes: usize) -> usize {
    max_bytes.min(MAX_BODY_BYTES)
}

fn extract_urls(text: &str) -> Vec<String> {
    let re = static_regex!(r#"https?://[^\s)\]>'\"]+"#);
    re.find_iter(text).map(|m| m.as_str().to_string()).collect()
}

fn extract_bounded_urls(text: &str) -> (Vec<String>, bool) {
    let re = static_regex!(r#"https?://[^\s)\]>'\"]+"#);
    let mut matches = re.find_iter(text);
    let urls = matches
        .by_ref()
        .take(MAX_URLS)
        .map(|matched| matched.as_str().to_string())
        .collect();
    (urls, matches.next().is_some())
}

fn host_allowed(host: &str, config: &ContentExtractorConfig) -> bool {
    if config.allow_hosts.is_empty() {
        return false;
    }
    config
        .allow_hosts
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(host))
}

const RESTRICTED_IPV4_RANGES: &[([u8; 4], u8)] = &[
    ([0, 0, 0, 0], 8),
    ([10, 0, 0, 0], 8),
    ([100, 64, 0, 0], 10),
    ([127, 0, 0, 0], 8),
    ([169, 254, 0, 0], 16),
    ([172, 16, 0, 0], 12),
    ([192, 0, 0, 0], 24),
    ([192, 0, 2, 0], 24),
    ([192, 31, 196, 0], 24),
    ([192, 52, 193, 0], 24),
    ([192, 88, 99, 0], 24),
    ([192, 168, 0, 0], 16),
    ([192, 175, 48, 0], 24),
    ([198, 18, 0, 0], 15),
    ([198, 51, 100, 0], 24),
    ([203, 0, 113, 0], 24),
    ([224, 0, 0, 0], 4),
    ([240, 0, 0, 0], 4),
];

const RESTRICTED_IPV6_RANGES: &[([u16; 8], u8)] = &[
    ([0, 0, 0, 0, 0, 0, 0, 0], 96),
    ([0, 0, 0, 0, 0, 0xffff, 0, 0], 96),
    ([0, 0, 0, 0, 0xffff, 0, 0, 0], 96),
    ([0x0064, 0xff9b, 0, 0, 0, 0, 0, 0], 96),
    ([0x0064, 0xff9b, 1, 0, 0, 0, 0, 0], 48),
    ([0x0100, 0, 0, 0, 0, 0, 0, 0], 64),
    ([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
    ([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32),
    ([0x2002, 0, 0, 0, 0, 0, 0, 0], 16),
    ([0x2620, 0x004f, 0x8000, 0, 0, 0, 0, 0], 48),
    ([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),
    ([0x5f00, 0, 0, 0, 0, 0, 0, 0], 16),
    ([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
    ([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
    ([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10),
    ([0xff00, 0, 0, 0, 0, 0, 0, 0], 8),
];

fn ipv4_in_prefix(address: [u8; 4], network: [u8; 4], prefix: u8) -> bool {
    let address = u32::from_be_bytes(address);
    let network = u32::from_be_bytes(network);
    let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
    address & mask == network & mask
}

fn ipv6_in_prefix(address: [u16; 8], network: [u16; 8], prefix: u8) -> bool {
    let address = address
        .into_iter()
        .fold(0_u128, |value, segment| (value << 16) | u128::from(segment));
    let network = network
        .into_iter()
        .fold(0_u128, |value, segment| (value << 16) | u128::from(segment));
    let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
    address & mask == network & mask
}

fn ip_is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => RESTRICTED_IPV4_RANGES
            .iter()
            .any(|(network, prefix)| ipv4_in_prefix(v4.octets(), *network, *prefix)),
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            !ipv6_in_prefix(segments, [0x2000, 0, 0, 0, 0, 0, 0, 0], 3)
                || RESTRICTED_IPV6_RANGES
                    .iter()
                    .any(|(network, prefix)| ipv6_in_prefix(segments, *network, *prefix))
        }
    }
}

fn is_exact_loopback_host(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn loopback_development_enabled() -> bool {
    matches!(
        std::env::var("VERDICTAN_ENV")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "development" | "dev"
    )
}

#[derive(Clone, Debug)]
struct OutboundCandidate {
    url: Url,
    host: String,
    port: u16,
    loopback_exception: bool,
}

#[derive(Clone, Debug)]
struct PinnedTarget {
    url: Url,
    host: String,
    addrs: Box<[SocketAddr]>,
}

type ResolveFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, &'static str>> + Send + 'a>>;
type FetchFuture<'a> = Pin<Box<dyn Future<Output = Result<String, &'static str>> + Send + 'a>>;

trait OutboundResolver: Send + Sync {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a>;
}

struct SystemOutboundResolver;

impl OutboundResolver for SystemOutboundResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a> {
        Box::pin(async move {
            tokio::net::lookup_host((host, port))
                .await
                .map(|addresses| addresses.collect())
                .map_err(|_| "dns_resolution_failed")
        })
    }
}

trait ContentFetcher: Send + Sync {
    fn fetch<'a>(
        &'a self,
        target: PinnedTarget,
        body_limit: usize,
        aggregate_bytes: Arc<AtomicUsize>,
        request_timeout: Duration,
    ) -> FetchFuture<'a>;
}

struct PinnedReqwestFetcher;

impl ContentFetcher for PinnedReqwestFetcher {
    fn fetch<'a>(
        &'a self,
        target: PinnedTarget,
        body_limit: usize,
        aggregate_bytes: Arc<AtomicUsize>,
        request_timeout: Duration,
    ) -> FetchFuture<'a> {
        Box::pin(fetch_pinned_content(
            target,
            body_limit,
            aggregate_bytes,
            request_timeout,
        ))
    }
}

fn parse_candidate(
    raw_url: &str,
    config: &ContentExtractorConfig,
    allow_loopback_development: bool,
) -> Result<OutboundCandidate, &'static str> {
    let url = Url::parse(raw_url).map_err(|_| "invalid_url")?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("url_userinfo_blocked");
    }

    let loopback_exception = allow_loopback_development && is_exact_loopback_host(&url);
    match url.scheme() {
        "https" => {}
        "http" if loopback_exception => {}
        "http" => return Err("https_required"),
        _ => return Err("unsupported_url_scheme"),
    }

    let host = url.host_str().ok_or("missing_host")?.to_string();
    if !host_allowed(&host, config) {
        return Err("host_not_allowlisted");
    }
    let port = url.port_or_known_default().ok_or("invalid_url")?;
    Ok(OutboundCandidate {
        url,
        host,
        port,
        loopback_exception,
    })
}

async fn resolve_candidate(
    candidate: OutboundCandidate,
    resolver: &dyn OutboundResolver,
) -> Result<PinnedTarget, &'static str> {
    let addresses = if let Ok(ip) = candidate.host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, candidate.port)]
    } else {
        resolver.resolve(&candidate.host, candidate.port).await?
    };
    if addresses.is_empty() {
        return Err("dns_resolution_failed");
    }

    if candidate.loopback_exception {
        if !addresses.iter().all(|address| address.ip().is_loopback()) {
            return Err("private_address_blocked");
        }
    } else if addresses.iter().any(|address| ip_is_private(address.ip())) {
        return Err("private_address_blocked");
    }

    let mut seen = HashSet::new();
    let addrs: Vec<_> = addresses
        .into_iter()
        .filter(|address| seen.insert(*address))
        .collect();
    Ok(PinnedTarget {
        url: candidate.url,
        host: candidate.host,
        addrs: addrs.into_boxed_slice(),
    })
}

fn reserve_aggregate_bytes(
    aggregate_bytes: &AtomicUsize,
    requested: usize,
) -> Result<(), &'static str> {
    let mut current = aggregate_bytes.load(Ordering::Relaxed);
    loop {
        let next = current
            .checked_add(requested)
            .filter(|next| *next <= MAX_AGGREGATE_BYTES)
            .ok_or("aggregate_body_limit_exceeded")?;
        match aggregate_bytes.compare_exchange_weak(
            current,
            next,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Ok(()),
            Err(observed) => current = observed,
        }
    }
}

fn decode_utf8_prefix(bytes: &[u8]) -> Result<String, &'static str> {
    match std::str::from_utf8(bytes) {
        Ok(text) => Ok(text.to_string()),
        Err(error) if error.error_len().is_none() => {
            Ok(std::str::from_utf8(&bytes[..error.valid_up_to()])
                .map_err(|_| "invalid_utf8")?
                .to_string())
        }
        Err(_) => Err("invalid_utf8"),
    }
}

async fn fetch_pinned_content(
    target: PinnedTarget,
    body_limit: usize,
    aggregate_bytes: Arc<AtomicUsize>,
    request_timeout: Duration,
) -> Result<String, &'static str> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(request_timeout)
        .read_timeout(request_timeout)
        .timeout(request_timeout)
        .resolve_to_addrs(&target.host, &target.addrs)
        .build()
        .map_err(|_| "client_build_failed")?;
    let response = client
        .get(target.url)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(|error| {
            if error.is_timeout() {
                "timeout"
            } else {
                "fetch_failed"
            }
        })?;

    if response.status().is_redirection() {
        return Err("redirect_blocked");
    }
    if !response.status().is_success() {
        return Err("http_status_error");
    }
    if response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
    {
        return Err("unsupported_content_encoding");
    }

    let mut body = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or_default()
            .min(body_limit),
    );
    let mut chunks = response.bytes_stream();
    while body.len() < body_limit {
        let Some(chunk) = chunks.next().await else {
            break;
        };
        let chunk = chunk.map_err(|error| {
            if error.is_timeout() {
                "timeout"
            } else {
                "body_read_failed"
            }
        })?;
        let retained = chunk.len().min(body_limit - body.len());
        reserve_aggregate_bytes(&aggregate_bytes, retained)?;
        body.extend_from_slice(&chunk[..retained]);
        if retained < chunk.len() {
            break;
        }
    }
    Ok(strip_html_tags(&decode_utf8_prefix(&body)?))
}

pub fn strip_html_tags(input: &str) -> String {
    let re = static_regex!(r"<[^>]+>");
    re.replace_all(input, " ").to_string()
}

pub async fn extract_content(text: &str, config: &ContentExtractorConfig) -> ExtractionResult {
    extract_content_with(
        text,
        config,
        &SystemOutboundResolver,
        &PinnedReqwestFetcher,
        loopback_development_enabled(),
    )
    .await
}

async fn extract_content_with(
    text: &str,
    config: &ContentExtractorConfig,
    resolver: &dyn OutboundResolver,
    fetcher: &dyn ContentFetcher,
    allow_loopback_development: bool,
) -> ExtractionResult {
    let (urls, url_limit_exceeded) = extract_bounded_urls(text);
    if url_limit_exceeded {
        return ExtractionResult {
            urls,
            extracted_text: Vec::new(),
            blocked_reason: Some("url_limit_exceeded".to_string()),
        };
    }
    if !config.fetch_urls || urls.is_empty() {
        return ExtractionResult {
            urls,
            extracted_text: Vec::new(),
            blocked_reason: None,
        };
    }

    let request_timeout = bounded_total_timeout(config.timeout_ms);
    let body_limit = bounded_body_limit(config.max_bytes);
    let aggregate_bytes = Arc::new(AtomicUsize::new(0));
    let extraction = async {
        let fetches = stream::iter(urls.iter().cloned().enumerate().map(|(index, raw_url)| {
            let aggregate_bytes = Arc::clone(&aggregate_bytes);
            async move {
                let candidate = parse_candidate(&raw_url, config, allow_loopback_development)?;
                let target = resolve_candidate(candidate, resolver).await?;
                let text = fetcher
                    .fetch(target, body_limit, aggregate_bytes, request_timeout)
                    .await?;
                Ok::<_, &'static str>((index, text))
            }
        }))
        .buffer_unordered(MAX_CONCURRENT_FETCHES);
        futures_util::pin_mut!(fetches);

        let mut extracted = Vec::with_capacity(urls.len());
        while let Some(result) = fetches.next().await {
            match result {
                Ok(item) => extracted.push(item),
                Err(reason) => return Err((reason, extracted)),
            }
        }
        extracted.sort_unstable_by_key(|(index, _)| *index);
        Ok(extracted
            .into_iter()
            .map(|(_, extracted)| extracted)
            .collect::<Vec<_>>())
    };

    match tokio::time::timeout(request_timeout, extraction).await {
        Ok(Ok(extracted_text)) => ExtractionResult {
            urls,
            extracted_text,
            blocked_reason: None,
        },
        Ok(Err((reason, mut extracted))) => {
            extracted.sort_unstable_by_key(|(index, _)| *index);
            ExtractionResult {
                urls,
                extracted_text: extracted
                    .into_iter()
                    .map(|(_, extracted)| extracted)
                    .collect(),
                blocked_reason: Some(reason.to_string()),
            }
        }
        Err(_) => ExtractionResult {
            urls,
            extracted_text: Vec::new(),
            blocked_reason: Some("timeout".to_string()),
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestPayloadFamily {
    Chat,
    Responses,
    Embeddings,
    AudioTranscriptions,
    AudioSpeech,
    Completions,
    Moderations,
    Messages,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedRequestMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestTextSegment {
    pub pointer: String,
    pub role: String,
    pub text: String,
}

pub fn request_payload_family_for_path(path: &str) -> Option<RequestPayloadFamily> {
    match path {
        "/v1/chat/completions" => Some(RequestPayloadFamily::Chat),
        "/v1/responses" => Some(RequestPayloadFamily::Responses),
        "/v1/embeddings" => Some(RequestPayloadFamily::Embeddings),
        "/v1/audio/transcriptions" => Some(RequestPayloadFamily::AudioTranscriptions),
        "/v1/audio/speech" => Some(RequestPayloadFamily::AudioSpeech),
        "/v1/completions" => Some(RequestPayloadFamily::Completions),
        "/v1/moderations" => Some(RequestPayloadFamily::Moderations),
        "/v1/messages" => Some(RequestPayloadFamily::Messages),
        _ => None,
    }
}

fn join_pointer(base: &str, token: &str) -> String {
    if base.is_empty() {
        format!("/{token}")
    } else {
        format!("{base}/{token}")
    }
}

fn push_text_segment(out: &mut Vec<RequestTextSegment>, pointer: String, role: &str, text: &str) {
    if text.trim().is_empty() {
        return;
    }
    out.push(RequestTextSegment {
        pointer,
        role: role.to_string(),
        text: text.to_string(),
    });
}

fn collect_selected_string_fields(
    base_pointer: &str,
    role: &str,
    value: &serde_json::Value,
    out: &mut Vec<RequestTextSegment>,
) {
    match value {
        serde_json::Value::String(text) => {
            push_text_segment(out, base_pointer.to_string(), role, text);
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_selected_string_fields(
                    &join_pointer(base_pointer, &index.to_string()),
                    role,
                    item,
                    out,
                );
            }
        }
        serde_json::Value::Object(object) => {
            if let Some(text) = object.get("text").and_then(serde_json::Value::as_str) {
                push_text_segment(out, join_pointer(base_pointer, "text"), role, text);
            }
            if let Some(content) = object.get("content") {
                collect_selected_string_fields(
                    &join_pointer(base_pointer, "content"),
                    role,
                    content,
                    out,
                );
            }
            if let Some(input) = object.get("input") {
                collect_selected_string_fields(
                    &join_pointer(base_pointer, "input"),
                    role,
                    input,
                    out,
                );
            }
            if let Some(arguments) = object.get("arguments") {
                collect_selected_string_fields(
                    &join_pointer(base_pointer, "arguments"),
                    role,
                    arguments,
                    out,
                );
            }
        }
        _ => {}
    }
}

fn collect_messages_segments(
    body: &serde_json::Value,
    include_top_level_system: bool,
    require_explicit_role: bool,
) -> Vec<RequestTextSegment> {
    let mut segments = Vec::new();

    if include_top_level_system {
        if let Some(system) = body.get("system").and_then(serde_json::Value::as_str) {
            push_text_segment(&mut segments, "/system".to_string(), "system", system);
        }
    }

    let Some(messages) = body.get("messages").and_then(serde_json::Value::as_array) else {
        return segments;
    };

    for (index, message) in messages.iter().enumerate() {
        let role = match message.get("role").and_then(serde_json::Value::as_str) {
            Some(role) => role,
            None if require_explicit_role => continue,
            None => "user",
        };

        if let Some(content) = message.get("content") {
            collect_selected_string_fields(
                &format!("/messages/{index}/content"),
                role,
                content,
                &mut segments,
            );
        }
    }

    segments
}

fn join_segment_texts(segments: &[RequestTextSegment]) -> Option<String> {
    if segments.is_empty() {
        return None;
    }
    let text = segments
        .iter()
        .map(|segment| segment.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    (!text.trim().is_empty()).then_some(text)
}

pub fn extract_request_messages(body: &serde_json::Value) -> Vec<ExtractedRequestMessage> {
    let mut messages = Vec::new();

    if let Some(system) = body.get("system").and_then(serde_json::Value::as_str) {
        if !system.trim().is_empty() {
            messages.push(ExtractedRequestMessage {
                role: "system".to_string(),
                content: system.to_string(),
            });
        }
    }

    let Some(raw_messages) = body.get("messages").and_then(serde_json::Value::as_array) else {
        return messages;
    };

    for (index, message) in raw_messages.iter().enumerate() {
        let Some(role) = message.get("role").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(content) = message.get("content") else {
            continue;
        };

        let mut segments = Vec::new();
        collect_selected_string_fields(
            &format!("/messages/{index}/content"),
            role,
            content,
            &mut segments,
        );
        if let Some(content) = join_segment_texts(&segments) {
            messages.push(ExtractedRequestMessage {
                role: role.to_string(),
                content,
            });
        }
    }

    messages
}

pub fn extract_responses_messages(body: &serde_json::Value) -> Vec<ExtractedRequestMessage> {
    let mut messages = extract_request_messages(body);
    if !messages.is_empty() {
        return messages;
    }

    if let Some(instructions) = body
        .get("instructions")
        .and_then(serde_json::Value::as_str)
        .filter(|text| !text.trim().is_empty())
    {
        messages.push(ExtractedRequestMessage {
            role: "system".to_string(),
            content: instructions.to_string(),
        });
    }

    let Some(input) = body.get("input") else {
        return messages;
    };

    match input {
        serde_json::Value::String(text) => {
            if !text.trim().is_empty() {
                messages.push(ExtractedRequestMessage {
                    role: "user".to_string(),
                    content: text.to_string(),
                });
            }
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let role = item
                    .get("role")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("user");
                let mut segments = Vec::new();
                collect_selected_string_fields(
                    &format!("/input/{index}"),
                    role,
                    item,
                    &mut segments,
                );
                if let Some(content) = join_segment_texts(&segments) {
                    messages.push(ExtractedRequestMessage {
                        role: role.to_string(),
                        content,
                    });
                }
            }
        }
        serde_json::Value::Object(object) => {
            let role = object
                .get("role")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("user");
            let mut segments = Vec::new();
            collect_selected_string_fields("/input", role, input, &mut segments);
            if let Some(content) = join_segment_texts(&segments) {
                messages.push(ExtractedRequestMessage {
                    role: role.to_string(),
                    content,
                });
            }
        }
        _ => {}
    }

    messages
}

pub fn collect_request_text_segments_for_path(
    path: &str,
    body: &serde_json::Value,
) -> Vec<RequestTextSegment> {
    let Some(family) = request_payload_family_for_path(path) else {
        return Vec::new();
    };

    match family {
        RequestPayloadFamily::Chat => collect_messages_segments(body, false, true),
        RequestPayloadFamily::Messages => collect_messages_segments(body, true, true),
        RequestPayloadFamily::Responses => {
            let message_segments = collect_messages_segments(body, true, true);
            if !message_segments.is_empty() {
                return message_segments;
            }

            let mut segments = Vec::new();
            if let Some(instructions) = body.get("instructions") {
                collect_selected_string_fields(
                    "/instructions",
                    "system",
                    instructions,
                    &mut segments,
                );
            }
            if let Some(input) = body.get("input") {
                collect_selected_string_fields("/input", "user", input, &mut segments);
            }
            segments
        }
        RequestPayloadFamily::Embeddings | RequestPayloadFamily::Moderations => {
            let mut segments = Vec::new();
            if let Some(input) = body.get("input") {
                collect_selected_string_fields("/input", "user", input, &mut segments);
            }
            segments
        }
        RequestPayloadFamily::AudioSpeech => {
            let mut segments = Vec::new();
            if let Some(input) = body.get("input") {
                collect_selected_string_fields("/input", "user", input, &mut segments);
            }
            segments
        }
        RequestPayloadFamily::AudioTranscriptions => {
            let mut segments = Vec::new();
            if let Some(prompt) = body.get("prompt") {
                collect_selected_string_fields("/prompt", "user", prompt, &mut segments);
            }
            segments
        }
        RequestPayloadFamily::Completions => {
            let mut segments = Vec::new();
            if let Some(prompt) = body.get("prompt") {
                collect_selected_string_fields("/prompt", "user", prompt, &mut segments);
            }
            segments
        }
    }
}

pub fn rewrite_request_text_segments_for_path<F>(
    path: &str,
    body: &mut serde_json::Value,
    mut rewrite: F,
) -> bool
where
    F: FnMut(&RequestTextSegment) -> Option<String>,
{
    let segments = collect_request_text_segments_for_path(path, body);
    let mut seen_pointers = std::collections::HashSet::new();
    let mut applied = false;

    for segment in segments {
        if !seen_pointers.insert(segment.pointer.clone()) {
            continue;
        }
        let Some(replacement) = rewrite(&segment) else {
            continue;
        };
        if replacement == segment.text {
            continue;
        }
        let Some(target) = body.pointer_mut(&segment.pointer) else {
            continue;
        };
        if target.as_str().is_none() {
            continue;
        }
        *target = serde_json::Value::String(replacement);
        applied = true;
    }

    applied
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
    use axum::body::Body;
    use axum::http::{header, Response, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use std::convert::Infallible;
    use std::sync::Mutex;

    struct StaticResolver {
        addresses: Vec<SocketAddr>,
        calls: AtomicUsize,
        delay: Duration,
    }

    impl StaticResolver {
        fn new(addresses: Vec<SocketAddr>) -> Self {
            Self {
                addresses,
                calls: AtomicUsize::new(0),
                delay: Duration::ZERO,
            }
        }
    }

    impl OutboundResolver for StaticResolver {
        fn resolve<'a>(&'a self, _host: &'a str, _port: u16) -> ResolveFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if !self.delay.is_zero() {
                    tokio::time::sleep(self.delay).await;
                }
                Ok(self.addresses.clone())
            })
        }
    }

    struct RecordingFetcher {
        calls: AtomicUsize,
        active: AtomicUsize,
        max_active: AtomicUsize,
        targets: Mutex<Vec<Vec<SocketAddr>>>,
        delay: Duration,
        retained_bytes: usize,
    }

    impl RecordingFetcher {
        fn new(delay: Duration, retained_bytes: usize) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                active: AtomicUsize::new(0),
                max_active: AtomicUsize::new(0),
                targets: Mutex::new(Vec::new()),
                delay,
                retained_bytes,
            }
        }
    }

    impl ContentFetcher for RecordingFetcher {
        fn fetch<'a>(
            &'a self,
            target: PinnedTarget,
            body_limit: usize,
            aggregate_bytes: Arc<AtomicUsize>,
            _request_timeout: Duration,
        ) -> FetchFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.targets
                    .lock()
                    .expect("target lock")
                    .push(target.addrs.to_vec());
                let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
                self.max_active.fetch_max(active, Ordering::SeqCst);
                if !self.delay.is_zero() {
                    tokio::time::sleep(self.delay).await;
                }
                let retained = self.retained_bytes.min(body_limit);
                let result = reserve_aggregate_bytes(&aggregate_bytes, retained)
                    .map(|()| "x".repeat(retained));
                self.active.fetch_sub(1, Ordering::SeqCst);
                result
            })
        }
    }

    fn extraction_config(host: &str) -> ContentExtractorConfig {
        ContentExtractorConfig {
            allow_hosts: vec![host.to_string()],
            timeout_ms: 1_000,
            max_bytes: MAX_BODY_BYTES,
            fetch_urls: true,
            action_on_error: ExtractionErrorAction::Block,
        }
    }

    fn public_address() -> SocketAddr {
        "8.8.8.8:443".parse().expect("public test address")
    }

    #[test]
    fn extract_urls_stops_before_trailing_delimiters() {
        let urls =
            extract_urls("See (https://docs.verdictan.com/guide) and https://example.com/page>");
        assert_eq!(
            urls,
            vec![
                "https://docs.verdictan.com/guide".to_string(),
                "https://example.com/page".to_string()
            ]
        );
    }

    #[test]
    fn candidate_rejects_non_development_http_and_unsupported_scheme() {
        let private_cfg = ContentExtractorConfig {
            allow_hosts: vec!["localhost".to_string()],
            ..Default::default()
        };
        assert_eq!(
            parse_candidate("http://localhost/internal", &private_cfg, false).unwrap_err(),
            "https_required"
        );

        let ftp_cfg = ContentExtractorConfig {
            allow_hosts: vec!["example.com".to_string()],
            ..Default::default()
        };
        assert_eq!(
            parse_candidate("ftp://example.com/file.txt", &ftp_cfg, false).unwrap_err(),
            "unsupported_url_scheme"
        );
    }

    #[tokio::test]
    async fn extract_content_rejects_invalid_urls_before_fetching() {
        let cfg = ContentExtractorConfig {
            allow_hosts: vec!["example.com".to_string()],
            ..Default::default()
        };
        let resolver = StaticResolver::new(vec![public_address()]);
        let fetcher = RecordingFetcher::new(Duration::ZERO, 1);

        let result = extract_content_with(
            "check https://example.com:abc/path",
            &cfg,
            &resolver,
            &fetcher,
            false,
        )
        .await;
        assert_eq!(
            result.urls,
            vec!["https://example.com:abc/path".to_string()]
        );
        assert_eq!(result.blocked_reason.as_deref(), Some("invalid_url"));
        assert!(result.extracted_text.is_empty());
    }

    #[test]
    fn content_extractor_config_defaults() {
        let cfg = ContentExtractorConfig::default();
        assert!(cfg.allow_hosts.is_empty());
        assert_eq!(cfg.timeout_ms, 2_000);
        assert_eq!(cfg.max_bytes, 65_536);
        assert!(cfg.fetch_urls);
        assert_eq!(cfg.action_on_error, ExtractionErrorAction::Warn);
    }

    #[test]
    fn configured_bounds_are_clamped_to_lane_limits() {
        assert_eq!(bounded_total_timeout(0), Duration::from_millis(1));
        assert_eq!(bounded_total_timeout(60_000), MAX_TOTAL_TIMEOUT);
        assert_eq!(bounded_body_limit(MAX_BODY_BYTES + 1), MAX_BODY_BYTES);
    }

    #[test]
    fn extraction_error_action_serde_roundtrip() {
        let warn: ExtractionErrorAction = serde_json::from_str("\"warn\"").unwrap();
        assert_eq!(warn, ExtractionErrorAction::Warn);
        let block: ExtractionErrorAction = serde_json::from_str("\"block\"").unwrap();
        assert_eq!(block, ExtractionErrorAction::Block);
    }

    #[test]
    fn extract_urls_empty_text() {
        assert!(extract_urls("").is_empty());
    }

    #[test]
    fn extract_urls_no_urls() {
        assert!(extract_urls("just plain text with no links").is_empty());
    }

    #[test]
    fn extract_urls_multiple() {
        let urls = extract_urls("Visit https://a.com and http://b.org/path for info.");
        assert_eq!(urls.len(), 2);
        assert!(urls[0].starts_with("https://a.com"));
        assert!(urls[1].starts_with("http://b.org/path"));
    }

    #[test]
    fn host_allowed_empty_list_rejects_all() {
        let cfg = ContentExtractorConfig::default();
        assert!(!host_allowed("example.com", &cfg));
    }

    #[test]
    fn host_allowed_case_insensitive() {
        let cfg = ContentExtractorConfig {
            allow_hosts: vec!["Example.COM".to_string()],
            ..Default::default()
        };
        assert!(host_allowed("example.com", &cfg));
        assert!(host_allowed("EXAMPLE.COM", &cfg));
    }

    #[test]
    fn host_allowed_mismatch() {
        let cfg = ContentExtractorConfig {
            allow_hosts: vec!["a.com".to_string()],
            ..Default::default()
        };
        assert!(!host_allowed("b.com", &cfg));
    }

    #[test]
    fn ip_is_private_loopback_v4() {
        assert!(ip_is_private("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn ip_is_private_rfc1918() {
        assert!(ip_is_private("10.0.0.1".parse().unwrap()));
        assert!(ip_is_private("172.16.0.1".parse().unwrap()));
        assert!(ip_is_private("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn ip_is_private_link_local_v4() {
        assert!(ip_is_private("169.254.1.1".parse().unwrap()));
    }

    #[test]
    fn ip_is_private_zero_v4() {
        assert!(ip_is_private("0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn ip_is_private_broadcast_v4() {
        assert!(ip_is_private("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn ip_is_private_loopback_v6() {
        assert!(ip_is_private("::1".parse().unwrap()));
    }

    #[test]
    fn ip_is_private_unspecified_v6() {
        assert!(ip_is_private("::".parse().unwrap()));
    }

    #[test]
    fn ip_is_private_unique_local_v6() {
        assert!(ip_is_private("fc00::1".parse().unwrap()));
        assert!(ip_is_private("fd12::1".parse().unwrap()));
    }

    #[test]
    fn ip_is_private_link_local_v6() {
        assert!(ip_is_private("fe80::1".parse().unwrap()));
    }

    #[test]
    fn ip_is_not_private_public_v4() {
        assert!(!ip_is_private("8.8.8.8".parse().unwrap()));
        assert!(ip_is_private("203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn ip_is_not_private_public_v6() {
        assert!(!ip_is_private("2606:4700:4700::1111".parse().unwrap()));
        assert!(ip_is_private("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn strip_html_tags_removes_tags() {
        assert_eq!(strip_html_tags("<p>Hello</p>"), " Hello ");
    }

    #[test]
    fn strip_html_tags_no_tags() {
        assert_eq!(strip_html_tags("plain text"), "plain text");
    }

    #[test]
    fn strip_html_tags_nested() {
        assert_eq!(
            strip_html_tags("<div><span>nested</span></div>"),
            "  nested  "
        );
    }

    #[test]
    fn candidate_rejects_missing_host() {
        let cfg = ContentExtractorConfig {
            allow_hosts: vec!["example.com".to_string()],
            ..Default::default()
        };
        assert_eq!(
            parse_candidate("file:///etc/passwd", &cfg, false).unwrap_err(),
            "unsupported_url_scheme"
        );
    }

    #[test]
    fn candidate_rejects_non_allowlisted_host() {
        let cfg = ContentExtractorConfig {
            allow_hosts: vec!["allowed.com".to_string()],
            ..Default::default()
        };
        assert_eq!(
            parse_candidate("https://evil.com/path", &cfg, false).unwrap_err(),
            "host_not_allowlisted"
        );
    }

    #[tokio::test]
    async fn extract_content_returns_empty_when_fetch_disabled() {
        let cfg = ContentExtractorConfig {
            fetch_urls: false,
            ..Default::default()
        };
        let result = extract_content("Visit https://example.com/page", &cfg).await;
        assert!(!result.urls.is_empty());
        assert!(result.extracted_text.is_empty());
        assert!(result.blocked_reason.is_none());
    }

    #[tokio::test]
    async fn extract_content_returns_empty_when_no_urls() {
        let cfg = ContentExtractorConfig::default();
        let result = extract_content("no links here", &cfg).await;
        assert!(result.urls.is_empty());
        assert!(result.extracted_text.is_empty());
        assert!(result.blocked_reason.is_none());
    }

    #[tokio::test]
    async fn ssrf_private_and_mixed_dns_answers_never_reach_transport() {
        for addresses in [
            vec!["127.0.0.1:443".parse().unwrap()],
            vec![
                public_address(),
                "169.254.169.254:443".parse().expect("metadata address"),
            ],
            vec!["[::1]:443".parse().unwrap()],
        ] {
            let resolver = StaticResolver::new(addresses);
            let fetcher = RecordingFetcher::new(Duration::ZERO, 1);
            let result = extract_content_with(
                "https://allowed.example/data",
                &extraction_config("allowed.example"),
                &resolver,
                &fetcher,
                false,
            )
            .await;

            assert_eq!(
                result.blocked_reason.as_deref(),
                Some("private_address_blocked")
            );
            assert_eq!(fetcher.calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn ssrf_private_ip_literal_never_reaches_dns_or_transport() {
        let resolver = StaticResolver::new(vec![public_address()]);
        let fetcher = RecordingFetcher::new(Duration::ZERO, 1);
        let result = extract_content_with(
            "https://127.0.0.1/internal",
            &extraction_config("127.0.0.1"),
            &resolver,
            &fetcher,
            false,
        )
        .await;

        assert_eq!(
            result.blocked_reason.as_deref(),
            Some("private_address_blocked")
        );
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn pinned_target_prevents_dns_rebinding_resolution() {
        let resolver = StaticResolver::new(vec![public_address()]);
        let fetcher = RecordingFetcher::new(Duration::ZERO, 1);
        let result = extract_content_with(
            "https://allowed.example/data",
            &extraction_config("allowed.example"),
            &resolver,
            &fetcher,
            false,
        )
        .await;

        assert!(result.blocked_reason.is_none());
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            fetcher.targets.lock().expect("target lock").as_slice(),
            &[vec![public_address()]]
        );
    }

    #[tokio::test]
    async fn url_flood_is_rejected_before_dns_or_socket_access() {
        let text = (0..9)
            .map(|index| format!("https://allowed.example/{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        let resolver = StaticResolver::new(vec![public_address()]);
        let fetcher = RecordingFetcher::new(Duration::ZERO, 1);
        let result = extract_content_with(
            &text,
            &extraction_config("allowed.example"),
            &resolver,
            &fetcher,
            false,
        )
        .await;

        assert_eq!(result.urls.len(), MAX_URLS);
        assert_eq!(result.blocked_reason.as_deref(), Some("url_limit_exceeded"));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn aggregate_body_budget_stops_after_four_mibibytes() {
        let text = (0..MAX_URLS)
            .map(|index| format!("https://allowed.example/{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        let resolver = StaticResolver::new(vec![public_address()]);
        let fetcher = RecordingFetcher::new(Duration::ZERO, MAX_BODY_BYTES);
        let result = extract_content_with(
            &text,
            &extraction_config("allowed.example"),
            &resolver,
            &fetcher,
            false,
        )
        .await;

        assert_eq!(
            result.blocked_reason.as_deref(),
            Some("aggregate_body_limit_exceeded")
        );
        assert_eq!(
            result.extracted_text.iter().map(String::len).sum::<usize>(),
            MAX_AGGREGATE_BYTES
        );
    }

    #[test]
    fn utf8_truncation_is_safe_at_every_multibyte_boundary() {
        let source = "a¢ह€🙂z";
        for boundary in 0..=source.len() {
            let decoded =
                decode_utf8_prefix(&source.as_bytes()[..boundary]).expect("valid UTF-8 prefix");
            assert!(
                source.starts_with(&decoded),
                "boundary {boundary} produced {decoded:?}"
            );
            assert!(!decoded.contains('\u{fffd}'));
        }
    }

    #[test]
    fn invalid_utf8_is_rejected_without_lossy_expansion() {
        assert_eq!(decode_utf8_prefix(&[0xff]), Err("invalid_utf8"));
    }

    #[tokio::test]
    async fn redirect_response_is_rejected_without_following_location() {
        let final_hits = Arc::new(AtomicUsize::new(0));
        let hits = Arc::clone(&final_hits);
        let app = Router::new()
            .route(
                "/redirect",
                get(|| async {
                    Response::builder()
                        .status(StatusCode::FOUND)
                        .header(header::LOCATION, "/private")
                        .body(Body::empty())
                        .expect("redirect response")
                }),
            )
            .route(
                "/private",
                get(move || {
                    let hits = Arc::clone(&hits);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        "private"
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind redirect fixture");
        let address = listener.local_addr().expect("redirect fixture address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("redirect fixture");
        });
        let resolver = StaticResolver::new(vec![address]);
        let config = extraction_config("localhost");
        let result = extract_content_with(
            &format!("http://localhost:{}/redirect", address.port()),
            &config,
            &resolver,
            &PinnedReqwestFetcher,
            true,
        )
        .await;
        server.abort();

        assert_eq!(result.blocked_reason.as_deref(), Some("redirect_blocked"));
        assert_eq!(final_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn endless_body_stops_at_hard_per_body_limit() {
        let app = Router::new().route(
            "/endless",
            get(|| async {
                let chunks = stream::repeat_with(|| {
                    Ok::<_, Infallible>(bytes::Bytes::from(vec![b'a'; 16 * 1024]))
                });
                Response::new(Body::from_stream(chunks))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind endless fixture");
        let address = listener.local_addr().expect("endless fixture address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("endless fixture");
        });
        let resolver = StaticResolver::new(vec![address]);
        let mut config = extraction_config("localhost");
        config.max_bytes = MAX_BODY_BYTES + 1;
        let result = extract_content_with(
            &format!("http://localhost:{}/endless", address.port()),
            &config,
            &resolver,
            &PinnedReqwestFetcher,
            true,
        )
        .await;
        server.abort();

        assert!(result.blocked_reason.is_none());
        assert_eq!(result.extracted_text.len(), 1);
        assert_eq!(result.extracted_text[0].len(), MAX_BODY_BYTES);
    }

    #[tokio::test]
    async fn compressed_body_is_rejected_before_decompression() {
        let app = Router::new().route(
            "/compressed",
            get(|| async {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_ENCODING, "gzip")
                    .body(Body::from(vec![0_u8; 64]))
                    .expect("compressed response")
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind compressed fixture");
        let address = listener.local_addr().expect("compressed fixture address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("compressed fixture");
        });
        let resolver = StaticResolver::new(vec![address]);
        let result = extract_content_with(
            &format!("http://localhost:{}/compressed", address.port()),
            &extraction_config("localhost"),
            &resolver,
            &PinnedReqwestFetcher,
            true,
        )
        .await;
        server.abort();

        assert_eq!(
            result.blocked_reason.as_deref(),
            Some("unsupported_content_encoding")
        );
        assert!(result.extracted_text.is_empty());
    }
}
