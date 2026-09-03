// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use regex_lite::Regex;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

macro_rules! static_regex {
    ($pattern:expr) => {{
        static RE: std::sync::OnceLock<regex_lite::Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| {
            #[allow(clippy::expect_used)]
            regex_lite::Regex::new($pattern).expect("static regex pattern")
        })
    }};
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PiiKind {
    // HIPAA-like identifiers / PHI-adjacent
    Name,
    Address,
    City,
    Fax,
    Mrn,
    HealthPlanBeneficiary,
    CertificateOrLicense,
    DeviceId,
    BiometricMention,
    PhotoMention,

    // Common PII
    Email,
    Ssn,
    Phone,

    // PCI-like
    Pan,
    Cvv,
    ExpirationDate,

    IpV4,
    IpV6,
    Url,
    Mac,
    Imei,
    Vin,
    Zip,
    Date,
    AccountNumber,
    LicensePlate,
    GenericId,
}

impl PiiKind {
    pub fn marker_key(&self) -> &'static str {
        match self {
            PiiKind::Name => "name",
            PiiKind::Address => "address",
            PiiKind::City => "city",
            PiiKind::Fax => "fax",
            PiiKind::Mrn => "mrn",
            PiiKind::HealthPlanBeneficiary => "health_plan_beneficiary",
            PiiKind::CertificateOrLicense => "certificate_or_license",
            PiiKind::DeviceId => "device_id",
            PiiKind::BiometricMention => "biometric",
            PiiKind::PhotoMention => "photo",
            PiiKind::Email => "email",
            PiiKind::Ssn => "ssn",
            PiiKind::Phone => "phone",
            PiiKind::Pan => "pan",
            PiiKind::Cvv => "cvv",
            PiiKind::ExpirationDate => "expiration_date",
            PiiKind::IpV4 => "ip",
            PiiKind::IpV6 => "ip",
            PiiKind::Url => "url",
            PiiKind::Mac => "mac",
            PiiKind::Imei => "imei",
            PiiKind::Vin => "vin",
            PiiKind::Zip => "zip",
            PiiKind::Date => "date",
            PiiKind::AccountNumber => "account_number",
            PiiKind::LicensePlate => "license_plate",
            PiiKind::GenericId => "generic_id",
        }
    }

    pub fn as_kind_str(&self) -> &'static str {
        match self {
            PiiKind::Name
            | PiiKind::Address
            | PiiKind::City
            | PiiKind::Fax
            | PiiKind::Mrn
            | PiiKind::HealthPlanBeneficiary
            | PiiKind::CertificateOrLicense
            | PiiKind::DeviceId
            | PiiKind::BiometricMention
            | PiiKind::PhotoMention
            | PiiKind::Date => "phi",
            PiiKind::Email => "pii",
            PiiKind::Ssn => "pii",
            PiiKind::Phone => "pii",
            PiiKind::Pan | PiiKind::Cvv | PiiKind::ExpirationDate => "pan",
            PiiKind::IpV4 => "pii",
            PiiKind::IpV6 => "pii",
            PiiKind::Url => "pii",
            PiiKind::Mac => "pii",
            PiiKind::Imei => "pii",
            PiiKind::Vin => "pii",
            PiiKind::Zip => "pii",
            PiiKind::AccountNumber => "pii",
            PiiKind::LicensePlate => "pii",
            PiiKind::GenericId => "other",
        }
    }

    pub fn replacement(&self) -> &'static str {
        match self {
            PiiKind::Name => "[REDACTED:NAME]",
            PiiKind::Address => "[REDACTED:ADDRESS]",
            PiiKind::City => "[REDACTED:CITY]",
            PiiKind::Fax => "[REDACTED:FAX]",
            PiiKind::Mrn => "[REDACTED:MRN]",
            PiiKind::HealthPlanBeneficiary => "[REDACTED:HEALTH_PLAN]",
            PiiKind::CertificateOrLicense => "[REDACTED:LICENSE]",
            PiiKind::DeviceId => "[REDACTED:DEVICE_ID]",
            PiiKind::BiometricMention => "[REDACTED:BIOMETRIC]",
            PiiKind::PhotoMention => "[REDACTED:PHOTO]",
            PiiKind::Email => "[REDACTED:EMAIL]",
            PiiKind::Ssn => "[REDACTED:SSN]",
            PiiKind::Phone => "[REDACTED:PHONE]",
            PiiKind::Pan => "[REDACTED:CARD]",
            PiiKind::Cvv => "[REDACTED:CVV]",
            PiiKind::ExpirationDate => "[REDACTED:EXPIRY]",
            PiiKind::IpV4 => "[REDACTED:IP]",
            PiiKind::IpV6 => "[REDACTED:IP]",
            PiiKind::Url => "[REDACTED:URL]",
            PiiKind::Mac => "[REDACTED:MAC]",
            PiiKind::Imei => "[REDACTED:IMEI]",
            PiiKind::Vin => "[REDACTED:VIN]",
            PiiKind::Zip => "[REDACTED:ZIP]",
            PiiKind::Date => "[REDACTED:DATE]",
            PiiKind::AccountNumber => "[REDACTED:ACCOUNT]",
            PiiKind::LicensePlate => "[REDACTED:LICENSE_PLATE]",
            PiiKind::GenericId => "[REDACTED:ID]",
        }
    }

    pub fn reason_code(&self) -> &'static str {
        match self {
            PiiKind::Name => "phi.name_detected",
            PiiKind::Address => "phi.address_detected",
            PiiKind::City => "phi.city_detected",
            PiiKind::Fax => "phi.fax_detected",
            PiiKind::Mrn => "phi.mrn_detected",
            PiiKind::HealthPlanBeneficiary => "phi.health_plan_beneficiary_detected",
            PiiKind::CertificateOrLicense => "phi.license_detected",
            PiiKind::DeviceId => "phi.device_id_detected",
            PiiKind::BiometricMention => "phi.biometric_mention_detected",
            PiiKind::PhotoMention => "phi.photo_mention_detected",
            PiiKind::Email => "pii.email_detected",
            PiiKind::Ssn => "pii.ssn_detected",
            PiiKind::Phone => "pii.phone_detected",
            PiiKind::Pan => "pii.pan_detected",
            PiiKind::Cvv => "pci.cvv_detected",
            PiiKind::ExpirationDate => "pci.expiration_date_detected",
            PiiKind::IpV4 | PiiKind::IpV6 => "pii.ip_detected",
            PiiKind::Url => "pii.url_detected",
            PiiKind::Mac => "pii.mac_detected",
            PiiKind::Imei => "pii.imei_detected",
            PiiKind::Vin => "pii.vin_detected",
            PiiKind::Zip => "pii.zip_detected",
            PiiKind::Date => "pii.date_detected",
            PiiKind::AccountNumber => "pii.account_detected",
            PiiKind::LicensePlate => "pii.license_plate_detected",
            PiiKind::GenericId => "pii.id_detected",
        }
    }

    pub fn priority(&self) -> u8 {
        match self {
            PiiKind::Pan | PiiKind::Cvv | PiiKind::ExpirationDate => 0,
            PiiKind::Ssn => 1,
            PiiKind::Email => 2,
            PiiKind::Mrn | PiiKind::HealthPlanBeneficiary => 3,
            PiiKind::Phone | PiiKind::Fax => 4,
            PiiKind::Imei | PiiKind::Vin | PiiKind::Mac | PiiKind::DeviceId => 5,
            PiiKind::IpV4 | PiiKind::IpV6 | PiiKind::Url => 6,
            PiiKind::Address | PiiKind::City | PiiKind::Zip => 7,
            PiiKind::Date => 8,
            PiiKind::Name => 9,
            PiiKind::AccountNumber | PiiKind::CertificateOrLicense => 10,
            PiiKind::BiometricMention | PiiKind::PhotoMention => 11,
            PiiKind::LicensePlate => 12,
            PiiKind::GenericId => 12,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub kind: PiiKind,
    pub start: usize,
    pub end: usize,
    pub confidence: Confidence,
}

pub fn detect_all(text: &str) -> Vec<Detection> {
    let mut out = Vec::new();

    // Email
    push_matches_filtered(
        &mut out,
        text,
        PiiKind::Email,
        static_regex!(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
        validate_email,
        Confidence::High,
    );

    // US SSN (with separators)
    push_matches_filtered(
        &mut out,
        text,
        PiiKind::Ssn,
        static_regex!(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b"),
        validate_ssn,
        Confidence::High,
    );

    // US SSN (bare 9 digits) only when contextual.
    push_contextual_matches_filtered(
        &mut out,
        text,
        PiiKind::Ssn,
        static_regex!(
            r"(?i)\b(?:ssn|social\s*security)\s*(?:#|number|no\.)?\s*[:#]?\s*([0-9]{9})\b"
        ),
        1,
        validate_ssn,
        Confidence::High,
    );

    // Phone (US-ish + simple intl prefix)
    push_matches(
        &mut out,
        text,
        PiiKind::Phone,
        static_regex!(
            r"\b(?:\+\d{1,3}[ -]?)?(?:\(\d{3}\)|\d{3})[ .-]?\d{3}[ .-]?\d{4}(?:\s*(?:x|ext\.?|extension)\s*\d{1,6})?\b"
        ),
        Confidence::Medium,
    );

    // Phone with leading '(' won't match the leading \b (word boundary), so include
    // an explicit variant to cover common "(555) 111-2222" formatting.
    push_matches(
        &mut out,
        text,
        PiiKind::Phone,
        static_regex!(
            r"(?:\+\d{1,3}[ -]?)?\(\d{3}\)[ .-]?\d{3}[ .-]?\d{4}(?:\s*(?:x|ext\.?|extension)\s*\d{1,6})?\b"
        ),
        Confidence::Medium,
    );

    // Phone (E.164-ish international). Keep is intentionally strict to reduce false positives.
    push_matches_filtered(
        &mut out,
        text,
        PiiKind::Phone,
        static_regex!(r"\+\d[\d\s().-]{7,}\d(?:\s*(?:x|ext\.?|extension)\s*\d{1,6})?\b"),
        validate_e164ish_phone,
        Confidence::Medium,
    );

    // IPv4
    push_matches_filtered(
        &mut out,
        text,
        PiiKind::IpV4,
        static_regex!(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
        is_public_ip,
        Confidence::High,
    );

    // IPv6 (including compressed forms like 2001:db8::1).
    // We grab candidate tokens and let the parser + public-IP filter validate.
    push_matches_filtered(
        &mut out,
        text,
        PiiKind::IpV6,
        static_regex!(r"\b[0-9A-Fa-f:]{2,39}\b"),
        is_public_ipv6_candidate,
        Confidence::High,
    );

    // URLs
    push_matches_filtered(
        &mut out,
        text,
        PiiKind::Url,
        static_regex!(r"\bhttps?://[^\s]+\b"),
        url_has_specific_path_or_query,
        Confidence::Medium,
    );

    // MAC
    push_matches(
        &mut out,
        text,
        PiiKind::Mac,
        static_regex!(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"),
        Confidence::High,
    );

    // MAC (hyphen separated)
    push_matches(
        &mut out,
        text,
        PiiKind::Mac,
        static_regex!(r"\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b"),
        Confidence::High,
    );

    // MAC (Cisco dotted)
    push_matches(
        &mut out,
        text,
        PiiKind::Mac,
        static_regex!(r"\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b"),
        Confidence::High,
    );

    // IMEI (15 digits, Luhn validated)
    push_matches_filtered(
        &mut out,
        text,
        PiiKind::Imei,
        static_regex!(r"\b\d{15}\b"),
        validate_imei_luhn,
        Confidence::High,
    );

    // VIN (17 chars excluding I,O,Q). Make it contextual to avoid false positives on
    // random 17-digit strings.
    push_contextual_matches(
        &mut out,
        text,
        PiiKind::Vin,
        static_regex!(r"(?i)\bvin\s*(?::)?\s*([A-HJ-NPR-Za-hj-npr-z0-9]{17})\b"),
        1,
        Confidence::High,
    );

    // US ZIP (5 or 9)
    push_matches(
        &mut out,
        text,
        PiiKind::Zip,
        static_regex!(r"\b\d{5}(?:-\d{4})?\b"),
        Confidence::High,
    );

    // Dates (common)
    push_matches(
        &mut out,
        text,
        PiiKind::Date,
        static_regex!(r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b"),
        Confidence::Medium,
    );
    push_matches(
        &mut out,
        text,
        PiiKind::Date,
        static_regex!(r"\b\d{4}-\d{1,2}-\d{1,2}\b"),
        Confidence::Medium,
    );
    // Month names (January 15, 1980)
    push_matches(
        &mut out,
        text,
        PiiKind::Date,
        static_regex!(
            r"(?i)\b(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\s+\d{1,2},?\s+\d{4}\b"
        ),
        Confidence::Medium,
    );
    // Relative / DOB-ish: "born on 01/02/2003" (capture the date span)
    push_contextual_matches(
        &mut out,
        text,
        PiiKind::Date,
        static_regex!(
            r"(?i)\b(?:born|dob)\s*(?:on|:)?\s*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{1,2}-\d{1,2})\b"
        ),
        1,
        Confidence::High,
    );

    // Account-ish numbers in context
    push_contextual_matches(
        &mut out,
        text,
        PiiKind::AccountNumber,
        static_regex!(r"(?i)\b(?:account|acct)\s*(?:#|number|no\.)?\s*[:#]?\s*([0-9]{6,17})\b"),
        1,
        Confidence::High,
    );

    // Routing numbers (ABA 9-digit with checksum validation)
    push_contextual_matches_filtered(
        &mut out,
        text,
        PiiKind::AccountNumber,
        static_regex!(r"(?i)\b(?:routing|aba|transit)\s*(?:#|number|no\.)?\s*[:#]?\s*([0-9]{9})\b"),
        1,
        validate_aba_routing,
        Confidence::High,
    );

    // IBAN (with optional spaces). Keep the regex intentionally simple and rely on
    // the validator to reduce false positives.
    push_contextual_matches_filtered(
        &mut out,
        text,
        PiiKind::AccountNumber,
        static_regex!(r"(?i)\biban\s*(?::)?\s*([A-Za-z0-9 ]*[0-9])(?:[^A-Za-z0-9]|$)"),
        1,
        validate_iban,
        Confidence::High,
    );

    // SWIFT/BIC (8 or 11 chars). Make it contextual to avoid false positives on ordinary words.
    push_contextual_matches_filtered(
        &mut out,
        text,
        PiiKind::AccountNumber,
        static_regex!(
            r"(?i)\b(?:swift|bic)\s*(?::)?\s*([A-Za-z]{6}[A-Za-z0-9]{2}(?:[A-Za-z0-9]{3})?)\b"
        ),
        1,
        validate_swift_bic,
        Confidence::High,
    );

    // License plates (contextual). This is intentionally conservative.
    push_contextual_matches(
        &mut out,
        text,
        PiiKind::LicensePlate,
        static_regex!(
            r"(?i)\b(?:license\s*plate|plate)\s*(?:#|number|no\.|:)?\s*([A-Z0-9]{2,8}(?:-[A-Z0-9]{1,4})?)\b"
        ),
        1,
        Confidence::Medium,
    );

    // Generic ID in context. Require at least one digit to avoid false positives on ordinary words
    // like "identifiers" (where "id" can match the contextual prefix).
    push_contextual_matches_filtered(
        &mut out,
        text,
        PiiKind::GenericId,
        static_regex!(
            r"(?i)\b(?:id|mrn|member|policy|code|number)\s*(?:#|number|no\.)?\s*[:#]?\s*([A-Z0-9-]{6,})\b"
        ),
        1,
        contains_digit,
        Confidence::Low,
    );

    // Prefer earliest spans; resolve overlaps by kind priority and span length.
    out.sort_by(|a, b| {
        (
            a.start,
            a.kind.priority(),
            std::cmp::Reverse(a.end - a.start),
        )
            .cmp(&(
                b.start,
                b.kind.priority(),
                std::cmp::Reverse(b.end - b.start),
            ))
    });
    dedupe_overlaps(out)
}

fn push_matches(
    out: &mut Vec<Detection>,
    text: &str,
    kind: PiiKind,
    re: &Regex,
    confidence: Confidence,
) {
    for m in re.find_iter(text) {
        out.push(Detection {
            kind: kind.clone(),
            start: m.start(),
            end: m.end(),
            confidence,
        });
    }
}

fn push_matches_filtered(
    out: &mut Vec<Detection>,
    text: &str,
    kind: PiiKind,
    re: &Regex,
    keep: fn(&str) -> bool,
    confidence: Confidence,
) {
    for m in re.find_iter(text) {
        let span = &text[m.start()..m.end()];
        if !keep(span) {
            continue;
        }
        out.push(Detection {
            kind: kind.clone(),
            start: m.start(),
            end: m.end(),
            confidence,
        });
    }
}

fn push_contextual_matches(
    out: &mut Vec<Detection>,
    text: &str,
    kind: PiiKind,
    re: &Regex,
    capture_group_index: usize,
    confidence: Confidence,
) {
    for caps in re.captures_iter(text) {
        if let Some(m) = caps.get(capture_group_index) {
            out.push(Detection {
                kind: kind.clone(),
                start: m.start(),
                end: m.end(),
                confidence,
            });
        }
    }
}

fn push_contextual_matches_filtered(
    out: &mut Vec<Detection>,
    text: &str,
    kind: PiiKind,
    re: &Regex,
    capture_group_index: usize,
    keep: fn(&str) -> bool,
    confidence: Confidence,
) {
    for caps in re.captures_iter(text) {
        if let Some(m) = caps.get(capture_group_index) {
            let span = &text[m.start()..m.end()];
            if !keep(span) {
                continue;
            }
            out.push(Detection {
                kind: kind.clone(),
                start: m.start(),
                end: m.end(),
                confidence,
            });
        }
    }
}

fn dedupe_overlaps(detections: Vec<Detection>) -> Vec<Detection> {
    let mut out = Vec::new();

    let mut i = 0;
    while i < detections.len() {
        let mut best = detections[i].clone();
        let mut cluster_end = best.end;

        let mut j = i + 1;
        while j < detections.len() && detections[j].start < cluster_end {
            cluster_end = cluster_end.max(detections[j].end);
            let cand = &detections[j];
            let cand_len = cand.end.saturating_sub(cand.start);
            let best_len = best.end.saturating_sub(best.start);
            let cand_key = (cand.kind.priority(), std::cmp::Reverse(cand_len));
            let best_key = (best.kind.priority(), std::cmp::Reverse(best_len));
            if cand_key < best_key {
                best = cand.clone();
            }
            j += 1;
        }

        out.push(best);
        i = j;
    }

    out.sort_by_key(|d| (d.start, d.end));
    out
}

fn validate_email(span: &str) -> bool {
    let Some((local, domain)) = span.split_once('@') else {
        return false;
    };
    if local.is_empty() || domain.is_empty() {
        return false;
    }

    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }

    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }

    let tld = labels[labels.len() - 1];
    (2..=24).contains(&tld.len()) && tld.chars().all(|c| c.is_ascii_alphabetic())
}

fn contains_digit(span: &str) -> bool {
    span.chars().any(|c| c.is_ascii_digit())
}

fn validate_ssn(span: &str) -> bool {
    let digits: String = span.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 9 {
        return false;
    }
    let area: u16 = digits[0..3].parse().unwrap_or(0);
    let group: u16 = digits[3..5].parse().unwrap_or(0);
    let serial: u16 = digits[5..9].parse().unwrap_or(0);

    if area == 0 || group == 0 || serial == 0 {
        return false;
    }
    if area == 666 || area >= 900 {
        return false;
    }
    true
}

fn is_public_ip(span: &str) -> bool {
    let Ok(ip) = span.parse::<IpAddr>() else {
        return false;
    };
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() || v4.is_link_local() || v4.is_private() {
                return false;
            }
            if v4 == Ipv4Addr::new(0, 0, 0, 0) {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6 == Ipv6Addr::UNSPECIFIED {
                return false;
            }
            let seg0 = v6.segments()[0];
            // Unique local (fc00::/7)
            if (seg0 & 0xfe00) == 0xfc00 {
                return false;
            }
            // Link local (fe80::/10)
            if (seg0 & 0xffc0) == 0xfe80 {
                return false;
            }
            true
        }
    }
}

fn is_public_ipv6_candidate(span: &str) -> bool {
    if span.matches(':').count() < 2 {
        return false;
    }
    if span.starts_with(':') && !span.starts_with("::") {
        return false;
    }
    if span.ends_with(':') && !span.ends_with("::") {
        return false;
    }
    if span.contains(":::") {
        return false;
    }
    let Ok(ip) = span.parse::<IpAddr>() else {
        return false;
    };
    match ip {
        IpAddr::V6(_) => is_public_ip(span),
        IpAddr::V4(_) => false,
    }
}

fn validate_e164ish_phone(span: &str) -> bool {
    // Remove optional extension portion for digit-count validation.
    let lower = span.to_ascii_lowercase();
    let base = if let Some(idx) = lower.find("extension") {
        &span[..idx]
    } else if let Some(idx) = lower.find("ext") {
        &span[..idx]
    } else {
        // Heuristic: ' x123' extension
        match lower.rfind('x') {
            Some(ix) if ix > 0 && lower.as_bytes()[ix - 1].is_ascii_whitespace() => &span[..ix],
            _ => span,
        }
    };

    if !base.starts_with('+') {
        return false;
    }
    let digits: String = base.chars().filter(|c| c.is_ascii_digit()).collect();
    // E.164 max is 15, min varies; keep it conservative.
    (8..=15).contains(&digits.len())
}

fn validate_imei_luhn(span: &str) -> bool {
    let digits: Vec<u32> = span
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 15 {
        return false;
    }

    // Luhn checksum over all digits.
    let mut sum = 0u32;
    for (i, d) in digits.iter().rev().enumerate() {
        let mut v = *d;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum.is_multiple_of(10)
}

fn validate_iban(span: &str) -> bool {
    let compact: String = span
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();

    let len = compact.len();
    if !(15..=34).contains(&len) {
        return false;
    }
    if !compact.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    let (cc, rest) = compact.split_at(2);
    if !cc.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    if !rest.chars().take(2).all(|c| c.is_ascii_digit()) {
        return false;
    }

    // ISO 13616 / mod-97 check: move first 4 to end, convert letters to numbers, mod 97 == 1
    let rearranged = format!("{}{}", &compact[4..], &compact[..4]);
    let mut rem: u32 = 0;
    for ch in rearranged.chars() {
        if ch.is_ascii_digit() {
            rem = (rem * 10 + (ch as u8 - b'0') as u32) % 97;
        } else if ch.is_ascii_alphabetic() {
            let v = (ch as u8 - b'A') as u32 + 10;
            // v is two digits (10..35)
            rem = (rem * 10 + (v / 10)) % 97;
            rem = (rem * 10 + (v % 10)) % 97;
        } else {
            return false;
        }
    }
    rem == 1
}

fn validate_aba_routing(span: &str) -> bool {
    let digits: Vec<u32> = span
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 9 {
        return false;
    }
    // ABA checksum: 3*d1 + 7*d2 + d3 + 3*d4 + 7*d5 + d6 + 3*d7 + 7*d8 + d9 ≡ 0 (mod 10)
    let weights = [3u32, 7, 1, 3, 7, 1, 3, 7, 1];
    let checksum: u32 = digits.iter().zip(weights.iter()).map(|(d, w)| d * w).sum();
    checksum.is_multiple_of(10)
}

fn validate_swift_bic(span: &str) -> bool {
    if span.len() != 8 && span.len() != 11 {
        return false;
    }
    if !span.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    let bytes = span.as_bytes();
    // Bank code: first 4 letters
    if !bytes[0..4]
        .iter()
        .all(|c| (*c as char).is_ascii_alphabetic())
    {
        return false;
    }
    // Country code: next 2 letters
    if !bytes[4..6]
        .iter()
        .all(|c| (*c as char).is_ascii_alphabetic())
    {
        return false;
    }
    // Location code: next 2 alnum
    true
}

fn url_has_specific_path_or_query(url: &str) -> bool {
    // Preserve generic domains (e.g. https://example.com). Redact only if the URL has
    // a non-trivial path/query/fragment.
    let lower = url.to_ascii_lowercase();
    let Some(rest) = lower.split_once("://").map(|(_, r)| r) else {
        return false;
    };

    let (_host_and_port, remainder) = match rest.split_once('/') {
        Some((h, r)) => (h, Some(r)),
        None => (rest, None),
    };
    let Some(remainder) = remainder else {
        return false;
    };
    if remainder.is_empty() {
        return false;
    }

    // "https://x/#" or "https://x/?" are treated as generic.
    remainder != "#" && remainder != "?"
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

    fn has_kind(detections: &[Detection], kind: &PiiKind) -> bool {
        detections.iter().any(|d| &d.kind == kind)
    }

    // --- PiiKind trait methods ---

    #[test]
    fn pii_kind_marker_key_coverage() {
        assert_eq!(PiiKind::Email.marker_key(), "email");
        assert_eq!(PiiKind::Ssn.marker_key(), "ssn");
        assert_eq!(PiiKind::Phone.marker_key(), "phone");
        assert_eq!(PiiKind::Pan.marker_key(), "pan");
        assert_eq!(PiiKind::IpV4.marker_key(), "ip");
        assert_eq!(PiiKind::IpV6.marker_key(), "ip");
        assert_eq!(PiiKind::Mac.marker_key(), "mac");
        assert_eq!(PiiKind::Vin.marker_key(), "vin");
        assert_eq!(PiiKind::Imei.marker_key(), "imei");
        assert_eq!(PiiKind::Zip.marker_key(), "zip");
        assert_eq!(PiiKind::Date.marker_key(), "date");
        assert_eq!(PiiKind::Url.marker_key(), "url");
        assert_eq!(PiiKind::GenericId.marker_key(), "generic_id");
    }

    #[test]
    fn pii_kind_as_kind_str() {
        assert_eq!(PiiKind::Email.as_kind_str(), "pii");
        assert_eq!(PiiKind::Ssn.as_kind_str(), "pii");
        assert_eq!(PiiKind::Pan.as_kind_str(), "pan");
        assert_eq!(PiiKind::Name.as_kind_str(), "phi");
        assert_eq!(PiiKind::GenericId.as_kind_str(), "other");
    }

    #[test]
    fn pii_kind_replacement_non_empty() {
        let kinds = [
            PiiKind::Email,
            PiiKind::Ssn,
            PiiKind::Phone,
            PiiKind::Pan,
            PiiKind::IpV4,
            PiiKind::Name,
            PiiKind::AccountNumber,
        ];
        for kind in kinds {
            assert!(kind.replacement().starts_with("[REDACTED:"));
        }
    }

    #[test]
    fn pii_kind_reason_code_non_empty() {
        assert_eq!(PiiKind::Email.reason_code(), "pii.email_detected");
        assert_eq!(PiiKind::Ssn.reason_code(), "pii.ssn_detected");
        assert_eq!(PiiKind::Pan.reason_code(), "pii.pan_detected");
    }

    // --- Confidence ---

    #[test]
    fn confidence_as_str() {
        assert_eq!(Confidence::High.as_str(), "high");
        assert_eq!(Confidence::Medium.as_str(), "medium");
        assert_eq!(Confidence::Low.as_str(), "low");
    }

    // --- Email detection ---

    #[test]
    fn detect_email() {
        let dets = detect_all("Contact: user@example.com for info.");
        assert!(has_kind(&dets, &PiiKind::Email));
    }

    #[test]
    fn email_with_plus() {
        let dets = detect_all("Send to user+tag@example.com please.");
        assert!(has_kind(&dets, &PiiKind::Email));
    }

    #[test]
    fn reject_invalid_email_no_tld() {
        assert!(!validate_email("user@localhost"));
    }

    #[test]
    fn reject_invalid_email_empty_local() {
        assert!(!validate_email("@example.com"));
    }

    #[test]
    fn reject_email_label_starts_with_hyphen() {
        assert!(!validate_email("user@-example.com"));
    }

    // --- SSN detection ---

    #[test]
    fn detect_ssn_with_dashes() {
        let dets = detect_all("SSN is 123-45-6789 on file.");
        assert!(has_kind(&dets, &PiiKind::Ssn));
    }

    #[test]
    fn detect_ssn_with_spaces() {
        let dets = detect_all("Social security: 234 56 7890.");
        assert!(has_kind(&dets, &PiiKind::Ssn));
    }

    #[test]
    fn reject_ssn_area_000() {
        assert!(!validate_ssn("000-12-3456"));
    }

    #[test]
    fn reject_ssn_area_666() {
        assert!(!validate_ssn("666-12-3456"));
    }

    #[test]
    fn reject_ssn_area_900_plus() {
        assert!(!validate_ssn("900-12-3456"));
    }

    #[test]
    fn reject_ssn_group_00() {
        assert!(!validate_ssn("123-00-4567"));
    }

    #[test]
    fn reject_ssn_serial_0000() {
        assert!(!validate_ssn("123-45-0000"));
    }

    // --- Phone detection ---

    #[test]
    fn detect_phone_us_format() {
        let dets = detect_all("Call (555) 123-4567 now.");
        assert!(has_kind(&dets, &PiiKind::Phone));
    }

    #[test]
    fn detect_phone_with_extension() {
        let dets = detect_all("Phone: 555-123-4567 ext. 890.");
        assert!(has_kind(&dets, &PiiKind::Phone));
    }

    #[test]
    fn detect_international_phone() {
        let dets = detect_all("Contact +44 20 7946 0958 for details.");
        assert!(has_kind(&dets, &PiiKind::Phone));
    }

    // --- IPv4 detection ---

    #[test]
    fn detect_public_ipv4() {
        let dets = detect_all("Server at 203.0.113.42 is up.");
        assert!(has_kind(&dets, &PiiKind::IpV4));
    }

    #[test]
    fn skip_private_ipv4() {
        assert!(!is_public_ip("192.168.1.1"));
        assert!(!is_public_ip("10.0.0.1"));
        assert!(!is_public_ip("127.0.0.1"));
    }

    #[test]
    fn skip_link_local_ipv4() {
        assert!(!is_public_ip("169.254.1.1"));
    }

    // --- IPv6 detection ---

    #[test]
    fn detect_public_ipv6() {
        let dets = detect_all("Host: 2001:db8:85a3::8a2e:370:7334 reachable.");
        assert!(has_kind(&dets, &PiiKind::IpV6));
    }

    #[test]
    fn skip_loopback_ipv6() {
        assert!(!is_public_ip("::1"));
    }

    // --- URL detection ---

    #[test]
    fn detect_url_with_path() {
        let dets = detect_all("Visit https://example.com/user/profile for details.");
        assert!(has_kind(&dets, &PiiKind::Url));
    }

    #[test]
    fn skip_generic_url() {
        assert!(!url_has_specific_path_or_query("https://example.com"));
        assert!(!url_has_specific_path_or_query("https://example.com/"));
    }

    #[test]
    fn url_with_query_detected() {
        assert!(url_has_specific_path_or_query(
            "https://example.com/search?q=test"
        ));
    }

    #[test]
    fn url_hash_or_question_only_generic() {
        assert!(!url_has_specific_path_or_query("https://example.com/#"));
        assert!(!url_has_specific_path_or_query("https://example.com/?"));
    }

    // --- MAC detection ---

    #[test]
    fn detect_mac_colon_separated() {
        let dets = detect_all("MAC: 00:1A:2B:3C:4D:5E found.");
        assert!(has_kind(&dets, &PiiKind::Mac));
    }

    #[test]
    fn detect_mac_hyphen_separated() {
        let dets = detect_all("Device 00-1A-2B-3C-4D-5E connected.");
        assert!(has_kind(&dets, &PiiKind::Mac));
    }

    #[test]
    fn detect_mac_cisco_dotted() {
        let dets = detect_all("Switch port 001A.2B3C.4D5E active.");
        assert!(has_kind(&dets, &PiiKind::Mac));
    }

    // --- ZIP code detection ---

    #[test]
    fn detect_zip_5() {
        let dets = detect_all("ZIP code 90210 for the area.");
        assert!(has_kind(&dets, &PiiKind::Zip));
    }

    #[test]
    fn detect_zip_9() {
        let dets = detect_all("ZIP 90210-1234 on the form.");
        assert!(has_kind(&dets, &PiiKind::Zip));
    }

    // --- Date detection ---

    #[test]
    fn detect_date_slash() {
        let dets = detect_all("Date: 01/15/2023 recorded.");
        assert!(has_kind(&dets, &PiiKind::Date));
    }

    #[test]
    fn detect_date_iso() {
        let dets = detect_all("Event on 2023-06-15 scheduled.");
        assert!(has_kind(&dets, &PiiKind::Date));
    }

    #[test]
    fn detect_date_month_name() {
        let dets = detect_all("Born January 15, 1980 in the record.");
        assert!(has_kind(&dets, &PiiKind::Date));
    }

    #[test]
    fn detect_dob_contextual() {
        let dets = detect_all("DOB: 03/15/1990 confirmed.");
        assert!(has_kind(&dets, &PiiKind::Date));
    }

    // --- Account number detection ---

    #[test]
    fn detect_account_number() {
        let dets = detect_all("Account #12345678901234 on file.");
        assert!(has_kind(&dets, &PiiKind::AccountNumber));
    }

    // --- ABA routing validation ---

    #[test]
    fn valid_aba_routing() {
        assert!(validate_aba_routing("021000021"));
    }

    #[test]
    fn invalid_aba_routing() {
        assert!(!validate_aba_routing("123456789"));
    }

    // --- IBAN validation ---

    #[test]
    fn valid_iban_gb() {
        assert!(validate_iban("GB29NWBK60161331926819"));
    }

    #[test]
    fn invalid_iban_bad_checksum() {
        assert!(!validate_iban("GB00NWBK60161331926819"));
    }

    #[test]
    fn iban_too_short() {
        assert!(!validate_iban("GB29NW"));
    }

    // --- SWIFT/BIC validation ---

    #[test]
    fn valid_swift_8_char() {
        assert!(validate_swift_bic("DEUTDEFF"));
    }

    #[test]
    fn valid_swift_11_char() {
        assert!(validate_swift_bic("DEUTDEFF500"));
    }

    #[test]
    fn invalid_swift_wrong_length() {
        assert!(!validate_swift_bic("DEUT"));
    }

    #[test]
    fn invalid_swift_digits_in_bank_code() {
        assert!(!validate_swift_bic("1234DEFF"));
    }

    // --- IMEI Luhn validation ---

    #[test]
    fn valid_imei() {
        assert!(validate_imei_luhn("490154203237518"));
    }

    #[test]
    fn invalid_imei_bad_checksum() {
        assert!(!validate_imei_luhn("490154203237519"));
    }

    #[test]
    fn imei_wrong_length() {
        assert!(!validate_imei_luhn("12345"));
    }

    // --- VIN detection ---

    #[test]
    fn detect_vin_contextual() {
        let dets = detect_all("VIN: 1HGBH41JXMN109186 on the registration.");
        assert!(has_kind(&dets, &PiiKind::Vin));
    }

    // --- License plate detection ---

    #[test]
    fn detect_license_plate() {
        let dets = detect_all("License plate: ABC1234 seen.");
        assert!(has_kind(&dets, &PiiKind::LicensePlate));
    }

    // --- E.164 phone validation ---

    #[test]
    fn validate_e164_valid() {
        assert!(validate_e164ish_phone("+14155551234"));
    }

    #[test]
    fn validate_e164_too_short() {
        assert!(!validate_e164ish_phone("+1234"));
    }

    #[test]
    fn validate_e164_no_plus() {
        assert!(!validate_e164ish_phone("14155551234"));
    }

    // --- dedupe_overlaps ---

    #[test]
    fn dedupe_overlaps_removes_overlapping() {
        let dets = vec![
            Detection {
                kind: PiiKind::Email,
                start: 0,
                end: 20,
                confidence: Confidence::High,
            },
            Detection {
                kind: PiiKind::Url,
                start: 5,
                end: 25,
                confidence: Confidence::Medium,
            },
        ];
        let deduped = dedupe_overlaps(dets);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn dedupe_overlaps_keeps_non_overlapping() {
        let dets = vec![
            Detection {
                kind: PiiKind::Email,
                start: 0,
                end: 10,
                confidence: Confidence::High,
            },
            Detection {
                kind: PiiKind::Phone,
                start: 20,
                end: 30,
                confidence: Confidence::Medium,
            },
        ];
        let deduped = dedupe_overlaps(dets);
        assert_eq!(deduped.len(), 2);
    }

    // --- detect_all: sorted output ---

    #[test]
    fn detect_all_results_sorted_by_start() {
        let text = "Email user@example.com and phone 555-123-4567 and SSN 123-45-6789.";
        let dets = detect_all(text);
        for window in dets.windows(2) {
            assert!(window[0].start <= window[1].start);
        }
    }

    // --- contains_digit ---

    #[test]
    fn contains_digit_true() {
        assert!(contains_digit("abc123"));
    }

    #[test]
    fn contains_digit_false() {
        assert!(!contains_digit("abcdef"));
    }

    // --- PiiKind priority ordering ---

    #[test]
    fn pan_has_highest_priority() {
        assert!(PiiKind::Pan.priority() < PiiKind::Email.priority());
        assert!(PiiKind::Pan.priority() < PiiKind::Name.priority());
    }

    #[test]
    fn ssn_higher_priority_than_email() {
        assert!(PiiKind::Ssn.priority() < PiiKind::Email.priority());
    }
}
