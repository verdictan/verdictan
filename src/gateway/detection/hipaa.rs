// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use super::pii::{Detection, PiiKind};

use regex_lite::Regex;

macro_rules! static_regex {
    ($pattern:expr) => {{
        static RE: std::sync::OnceLock<regex_lite::Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| {
            #[allow(clippy::expect_used)]
            regex_lite::Regex::new($pattern).expect("static regex pattern")
        })
    }};
}

/// Detect HIPAA Safe Harbor-style identifiers.
///
/// This module focuses on deterministic, demo-oriented coverage of the 18 identifiers.
/// It intentionally avoids heavy external datasets; we include a curated city list.
pub fn detect_hipaa_18_like(text: &str) -> Vec<Detection> {
    let mut out: Vec<Detection> = Vec::new();

    // Names: "Dr. John Smith", "Jane Doe, MD", etc.
    push_matches(
        &mut out,
        text,
        PiiKind::Name,
        static_regex!(
            r"\b(?:(?i:dr\.?|mr\.?|mrs\.?|ms\.?)\s+)?(?:[A-Z][a-z]+)\s+(?:[A-Z][a-z]+)(?:\s+(?i:jr\.?|sr\.?|iii|iv|md|phd))?\b"
        ),
        super::pii::Confidence::Medium,
    );

    // Street addresses (US-ish)
    push_matches(
        &mut out,
        text,
        PiiKind::Address,
        static_regex!(
            r"(?i)\b\d{1,6}\s+[A-Z0-9][A-Z0-9\s\.\-]{2,}\s+(?:st|street|ave|avenue|rd|road|blvd|boulevard|ln|lane|dr|drive|ct|court|pl|place|way|pkwy|parkway)\b\.?(?:\s+(?:apt|unit|suite|ste)\s*#?\s*[A-Z0-9\-]{1,10})?\b"
        ),
        super::pii::Confidence::Medium,
    );

    // International-ish address (very light): "Main Street 12, 10115 Berlin"
    push_matches(
        &mut out,
        text,
        PiiKind::Address,
        static_regex!(
            r"(?i)\b[A-Z][A-Za-z\s\.\-]{2,}\s+\d{1,4},\s*\d{4,6}\s+[A-Z][A-Za-z\s\-]{2,}\b"
        ),
        super::pii::Confidence::Low,
    );

    // City names from a curated list (top cities). Best-effort heuristic.
    out.extend(detect_us_top_cities(text));

    // Fax numbers: phone patterns near "fax" context.
    out.extend(detect_fax_numbers(text));

    // MRN: "MRN: 1234567", "MR# 123456"
    push_contextual_numeric(
        &mut out,
        text,
        PiiKind::Mrn,
        static_regex!(r"(?i)\b(?:mrn|mr#)\s*(?:#|:)?\s*([0-9]{6,10})\b"),
        super::pii::Confidence::High,
    );
    // Medical context numeric IDs (best-effort)
    push_contextual_numeric(
        &mut out,
        text,
        PiiKind::Mrn,
        static_regex!(
            r"(?i)\b(?:medical\s*record|record)\s*(?:#|number|no\.)\s*:?\s*([0-9]{6,10})\b"
        ),
        super::pii::Confidence::Medium,
    );

    // Health plan beneficiary numbers / insurance IDs.
    push_contextual_alnum(
        &mut out,
        text,
        PiiKind::HealthPlanBeneficiary,
        static_regex!(
            r"(?i)\b(?:member\s*id|policy\s*(?:id|number)|insurance\s*id|medicare|medicaid)\s*(?:#|number|no\.)?\s*[:#]?\s*([A-Z0-9\-]{6,20})\b"
        ),
        super::pii::Confidence::Medium,
    );

    // Certificate / license numbers.
    push_contextual_alnum(
        &mut out,
        text,
        PiiKind::CertificateOrLicense,
        static_regex!(
            r"(?i)\b(?:driver'?s?\s*license|dl|license|lic\.)\s*(?:#|number|no\.)?\s*[:#]?\s*([A-Z0-9\-]{5,20})\b"
        ),
        super::pii::Confidence::Medium,
    );
    // State-specific driver's license patterns (common formats):
    // California: 1 letter + 7 digits, New York: 9 digits, Texas: 8 digits, etc.
    push_contextual_alnum(
        &mut out,
        text,
        PiiKind::CertificateOrLicense,
        static_regex!(
            r"(?i)\b(?:driver'?s?\s*license|dl)\s*(?:#|number|no\.)?\s*[:#]?\s*([A-Z]\d{7,8})\b"
        ),
        super::pii::Confidence::High,
    );
    push_contextual_alnum(
        &mut out,
        text,
        PiiKind::CertificateOrLicense,
        static_regex!(
            r"(?i)\b(?:certificate|cert\.)\s*(?:#|id|number|no\.)?\s*[:#]?\s*([A-Z0-9\-]{5,24})\b"
        ),
        super::pii::Confidence::Medium,
    );

    // Device identifiers / serial numbers.
    push_contextual_alnum(
        &mut out,
        text,
        PiiKind::DeviceId,
        static_regex!(
            r"(?i)\b(?:serial|sn|s\/n|device\s*id)\s*(?:#|number|no\.)?\s*[:#]?\s*([A-Z0-9\-]{6,30})\b"
        ),
        super::pii::Confidence::Medium,
    );

    // Biometric identifiers (mentions)
    push_keyword_mentions(
        &mut out,
        text,
        PiiKind::BiometricMention,
        &[
            "fingerprint",
            "retina scan",
            "facial recognition",
            "iris scan",
            "voiceprint",
            "biometric id",
            "biometric identifier",
            "biometric data",
            "biometric sample",
            "biometric template",
            "biometric record",
            "biometric enrollment",
            "palm print",
            "hand geometry",
            "gait analysis",
        ],
    );

    // Biometric ID references (structured patterns like "Biometric ID: BIO-12345")
    push_contextual_alnum(
        &mut out,
        text,
        PiiKind::BiometricMention,
        static_regex!(
            r"(?i)\b(?:biometric\s*(?:id|identifier|record|template))\s*(?:#|number|no\.)?\s*[:#]?\s*([A-Z0-9\-]{4,20})\b"
        ),
        super::pii::Confidence::High,
    );

    // Full-face photos and comparable images (mentions)
    push_keyword_mentions(
        &mut out,
        text,
        PiiKind::PhotoMention,
        &[
            "photo",
            "image",
            "selfie",
            "face photo",
            "full-face",
            "photograph",
            "headshot",
            "mugshot",
            "portrait",
            "profile picture",
            "image attachment",
            "photo id",
            "photo identification",
            "facial image",
            "body scan",
        ],
    );

    out.sort_by(|a, b| {
        (a.start, a.kind.priority(), a.end).cmp(&(b.start, b.kind.priority(), b.end))
    });
    out
}

fn push_matches(
    out: &mut Vec<Detection>,
    text: &str,
    kind: PiiKind,
    re: &Regex,
    confidence: super::pii::Confidence,
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

fn push_contextual_numeric(
    out: &mut Vec<Detection>,
    text: &str,
    kind: PiiKind,
    re: &Regex,
    confidence: super::pii::Confidence,
) {
    for caps in re.captures_iter(text) {
        if let Some(m) = caps.get(1) {
            out.push(Detection {
                kind: kind.clone(),
                start: m.start(),
                end: m.end(),
                confidence,
            });
        }
    }
}

fn push_contextual_alnum(
    out: &mut Vec<Detection>,
    text: &str,
    kind: PiiKind,
    re: &Regex,
    confidence: super::pii::Confidence,
) {
    for caps in re.captures_iter(text) {
        if let Some(m) = caps.get(1) {
            out.push(Detection {
                kind: kind.clone(),
                start: m.start(),
                end: m.end(),
                confidence,
            });
        }
    }
}

fn detect_fax_numbers(text: &str) -> Vec<Detection> {
    let mut out = Vec::new();
    let re = static_regex!(
        r"(?i)\b(?:fax|f)\s*(?::|\.)\s*((?:\+\d{1,3}[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]?\d{3}[ .-]?\d{4})\b"
    );
    for caps in re.captures_iter(text) {
        if let Some(m) = caps.get(1) {
            out.push(Detection {
                kind: PiiKind::Fax,
                start: m.start(),
                end: m.end(),
                confidence: super::pii::Confidence::High,
            });
        }
    }
    out
}

fn detect_us_top_cities(text: &str) -> Vec<Detection> {
    // Best-effort substring search using a curated list. This is intentionally simple.
    let cities_raw = include_str!("data/us_top_cities_500.txt");
    let mut out = Vec::new();
    let lower = text.to_ascii_lowercase();

    for city in cities_raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let city_lower = city.to_ascii_lowercase();
        // Word-ish boundaries: require spaces/punct around the match.
        let mut search_from = 0;
        while let Some(idx) = lower[search_from..].find(&city_lower) {
            let start = search_from + idx;
            let end = start + city_lower.len();

            let before_ok = start == 0
                || !lower
                    .as_bytes()
                    .get(start.saturating_sub(1))
                    .map(|b| b.is_ascii_alphanumeric())
                    .unwrap_or(false);
            let after_ok = end >= lower.len()
                || !lower
                    .as_bytes()
                    .get(end)
                    .map(|b| b.is_ascii_alphanumeric())
                    .unwrap_or(false);

            if before_ok && after_ok {
                out.push(Detection {
                    kind: PiiKind::City,
                    start,
                    end,
                    confidence: super::pii::Confidence::Low,
                });
            }

            search_from = end;
            if search_from >= lower.len() {
                break;
            }
        }
    }

    out
}

fn push_keyword_mentions(out: &mut Vec<Detection>, text: &str, kind: PiiKind, keywords: &[&str]) {
    let lower = text.to_ascii_lowercase();
    for kw in keywords {
        let kw_lower = kw.to_ascii_lowercase();
        let mut from = 0;
        while let Some(idx) = lower[from..].find(&kw_lower) {
            let start = from + idx;
            let end = start + kw_lower.len();
            out.push(Detection {
                kind: kind.clone(),
                start,
                end,
                confidence: super::pii::Confidence::Low,
            });
            from = end;
            if from >= lower.len() {
                break;
            }
        }
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

    fn has_kind(detections: &[Detection], kind: &PiiKind) -> bool {
        detections.iter().any(|d| &d.kind == kind)
    }

    fn detected_text<'a>(text: &'a str, d: &Detection) -> &'a str {
        &text[d.start..d.end]
    }

    // --- Name detection ---

    #[test]
    fn detect_simple_name() {
        let text = "The patient is John Smith from the clinic.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::Name));
    }

    #[test]
    fn detect_name_with_title() {
        let text = "Dr. Jane Williams examined the patient.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::Name));
    }

    #[test]
    fn detect_name_with_suffix() {
        let text = "Robert Johnson Jr. is the attending physician.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::Name));
    }

    // --- Address detection ---

    #[test]
    fn detect_us_street_address() {
        let text = "Patient lives at 123 Main Street, Springfield.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::Address));
    }

    #[test]
    fn detect_address_with_apartment() {
        let text = "Send to 456 Oak Avenue Apt 12B please.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::Address));
    }

    #[test]
    fn detect_international_address() {
        let text = "Office at Hauptstrasse 42, 10115 Berlin for reference.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::Address));
    }

    // --- Fax detection ---

    #[test]
    fn detect_fax_number() {
        let text = "Fax: (555) 123-4567 for records.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::Fax));
    }

    #[test]
    fn detect_fax_with_prefix() {
        let text = "Fax: +1 555-123-4567 for medical records.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::Fax));
    }

    // --- MRN detection ---

    #[test]
    fn detect_mrn_with_prefix() {
        let text = "MRN: 12345678 is the patient's record.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::Mrn));
    }

    #[test]
    fn detect_medical_record_number() {
        let text = "Medical record number: 9876543 for this visit.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::Mrn));
    }

    #[test]
    fn detect_mr_hash() {
        let text = "MR# 1234567 is on file.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::Mrn));
    }

    // --- Health plan beneficiary ---

    #[test]
    fn detect_member_id() {
        let text = "Member ID: ABC123456789 for coverage.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::HealthPlanBeneficiary));
    }

    #[test]
    fn detect_insurance_id() {
        let text = "Insurance ID XYZ-987654 is the primary.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::HealthPlanBeneficiary));
    }

    #[test]
    fn detect_medicare() {
        let text = "Medicare 1EG4-TE5-MK72 on file.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::HealthPlanBeneficiary));
    }

    // --- Certificate/License ---

    #[test]
    fn detect_drivers_license() {
        let text = "Driver's license DL# A1234567 on file.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::CertificateOrLicense));
    }

    #[test]
    fn detect_certificate_number() {
        let text = "Certificate #ABC-12345-XYZ issued.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::CertificateOrLicense));
    }

    // --- Device ID ---

    #[test]
    fn detect_serial_number() {
        let text = "Serial number SN: ABC123-DEF456 for the device.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::DeviceId));
    }

    #[test]
    fn detect_device_id() {
        let text = "Device ID: MED-PUMP-789012 assigned.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::DeviceId));
    }

    // --- Biometric mentions ---

    #[test]
    fn detect_fingerprint_mention() {
        let text = "The fingerprint scan was completed.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::BiometricMention));
    }

    #[test]
    fn detect_retina_scan_mention() {
        let text = "A retina scan is required for access.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::BiometricMention));
    }

    #[test]
    fn detect_facial_recognition_mention() {
        let text = "facial recognition data was collected.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::BiometricMention));
    }

    #[test]
    fn detect_biometric_id_reference() {
        let text = "Biometric ID: BIO-12345 stored in the system.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::BiometricMention));
    }

    // --- Photo mentions ---

    #[test]
    fn detect_photo_mention() {
        let text = "A photo was taken for the patient file.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::PhotoMention));
    }

    #[test]
    fn detect_selfie_mention() {
        let text = "The selfie was used for verification.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::PhotoMention));
    }

    #[test]
    fn detect_headshot_mention() {
        let text = "A headshot is required for ID badge.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::PhotoMention));
    }

    // --- No false positives on clean text ---

    #[test]
    fn no_detections_on_clean_text() {
        let text = "The system processed the request successfully.";
        let dets = detect_hipaa_18_like(text);
        let phi_kinds: Vec<_> = dets
            .iter()
            .filter(|d| {
                matches!(
                    d.kind,
                    PiiKind::Mrn
                        | PiiKind::Fax
                        | PiiKind::HealthPlanBeneficiary
                        | PiiKind::CertificateOrLicense
                        | PiiKind::DeviceId
                )
            })
            .collect();
        assert!(phi_kinds.is_empty());
    }

    // --- Sorting ---

    #[test]
    fn detections_sorted_by_start() {
        let text = "MRN: 12345678 and fingerprint data for John Smith was received.";
        let dets = detect_hipaa_18_like(text);
        for window in dets.windows(2) {
            assert!(window[0].start <= window[1].start);
        }
    }

    // --- City detection ---

    #[test]
    fn detect_us_city() {
        let text = "The patient resides in Houston and works nearby.";
        let dets = detect_hipaa_18_like(text);
        assert!(has_kind(&dets, &PiiKind::City));
        let city_det = dets.iter().find(|d| d.kind == PiiKind::City).unwrap();
        assert_eq!(detected_text(text, city_det).to_lowercase(), "houston");
    }

    #[test]
    fn city_detection_respects_word_boundaries() {
        let text = "The application is running.";
        let dets = detect_hipaa_18_like(text);
        let cities: Vec<_> = dets.iter().filter(|d| d.kind == PiiKind::City).collect();
        for c in &cities {
            let t = detected_text(text, c).to_lowercase();
            assert_ne!(t, "app", "should not match partial word");
        }
    }
}
