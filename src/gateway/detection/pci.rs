// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use super::pii::{Detection, PiiKind};

macro_rules! static_regex {
    ($pattern:expr) => {{
        static RE: std::sync::OnceLock<regex_lite::Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| {
            #[allow(clippy::expect_used)]
            regex_lite::Regex::new($pattern).expect("static regex pattern")
        })
    }};
}

pub fn detect_pan(text: &str) -> Vec<Detection> {
    detect_card_numbers(text)
}

pub fn detect_cvv(text: &str) -> Vec<Detection> {
    let mut out = Vec::new();
    let re = static_regex!(r"(?i)\b(?:cvv|cvc|security\s*code)\s*(?::|\#)?\s*([0-9]{3,4})\b");
    for caps in re.captures_iter(text) {
        if let Some(m) = caps.get(1) {
            out.push(Detection {
                kind: PiiKind::Cvv,
                start: m.start(),
                end: m.end(),
                confidence: super::pii::Confidence::High,
            });
        }
    }
    out
}

pub fn detect_expiration_date(text: &str) -> Vec<Detection> {
    let mut out = Vec::new();
    let re = static_regex!(
        r"(?i)\b(?:exp|expires|expiration)\s*(?::)?\s*([01]?\d\s*/\s*(?:\d{2}|\d{4}))\b"
    );
    for caps in re.captures_iter(text) {
        if let Some(m) = caps.get(1) {
            let span = text[m.start()..m.end()].to_string();
            if is_plausible_mm_yy(&span) {
                out.push(Detection {
                    kind: PiiKind::ExpirationDate,
                    start: m.start(),
                    end: m.end(),
                    confidence: super::pii::Confidence::High,
                });
            }
        }
    }
    out
}

pub fn detect_pci_dss(text: &str) -> Vec<Detection> {
    let mut out = Vec::new();
    out.extend(detect_pan(text));
    out.extend(detect_cvv(text));
    out.extend(detect_expiration_date(text));
    out.sort_by_key(|d| (d.start, d.end));
    out
}

pub fn detect_card_numbers(text: &str) -> Vec<Detection> {
    let mut out = Vec::new();
    let re = static_regex!(r"\b(?:\d[ -]*?){13,19}\b");

    for m in re.find_iter(text) {
        let span = &text[m.start()..m.end()];
        let digits: String = span.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() < 13 || digits.len() > 19 {
            continue;
        }

        if !is_known_card_prefix_and_length(&digits) {
            continue;
        }
        if !luhn_valid(&digits) {
            continue;
        }

        out.push(Detection {
            kind: PiiKind::Pan,
            start: m.start(),
            end: m.end(),
            confidence: super::pii::Confidence::High,
        });
    }

    out
}

fn is_known_card_prefix_and_length(d: &str) -> bool {
    // Visa: 4, 13/16/19
    if d.starts_with('4') && matches!(d.len(), 13 | 16 | 19) {
        return true;
    }
    // MasterCard: 51-55, 16
    if d.len() == 16 {
        if let Ok(prefix) = d[0..2].parse::<u8>() {
            if (51..=55).contains(&prefix) {
                return true;
            }
        }
    }
    // Amex: 34/37, 15
    if d.len() == 15 && (d.starts_with("34") || d.starts_with("37")) {
        return true;
    }
    // Discover: 6011, 65, 16
    if d.len() == 16 && (d.starts_with("6011") || d.starts_with("65")) {
        return true;
    }
    false
}

fn luhn_valid(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for ch in digits.chars().rev() {
        let Some(mut n) = ch.to_digit(10) else {
            return false;
        };
        if double {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        double = !double;
    }
    sum.is_multiple_of(10)
}

fn is_plausible_mm_yy(span: &str) -> bool {
    let cleaned = span.replace(' ', "");
    let Some((mm, yy)) = cleaned.split_once('/') else {
        return false;
    };
    let Ok(m) = mm.parse::<u8>() else {
        return false;
    };
    if !(1..=12).contains(&m) {
        return false;
    }
    // yy can be 2 or 4 digits.
    yy.len() == 2 || yy.len() == 4
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

    #[test]
    fn luhn_valid_known_test_card() {
        assert!(luhn_valid("4111111111111111"));
    }

    #[test]
    fn luhn_valid_amex_test() {
        assert!(luhn_valid("378282246310005"));
    }

    #[test]
    fn luhn_invalid() {
        assert!(!luhn_valid("1234567890123456"));
    }

    #[test]
    fn luhn_too_short() {
        assert!(!luhn_valid("123"));
    }

    #[test]
    fn is_known_card_prefix_visa_16() {
        assert!(is_known_card_prefix_and_length("4111111111111111"));
    }

    #[test]
    fn is_known_card_prefix_mastercard() {
        assert!(is_known_card_prefix_and_length("5111111111111118"));
    }

    #[test]
    fn is_known_card_prefix_amex() {
        assert!(is_known_card_prefix_and_length("378282246310005"));
    }

    #[test]
    fn is_known_card_prefix_discover() {
        assert!(is_known_card_prefix_and_length("6011111111111117"));
    }

    #[test]
    fn is_known_card_prefix_unknown() {
        assert!(!is_known_card_prefix_and_length("1234567890123456"));
    }

    #[test]
    fn is_plausible_mm_yy_valid_short() {
        assert!(is_plausible_mm_yy("01/25"));
        assert!(is_plausible_mm_yy("12/30"));
    }

    #[test]
    fn is_plausible_mm_yy_valid_long() {
        assert!(is_plausible_mm_yy("01/2025"));
    }

    #[test]
    fn is_plausible_mm_yy_invalid_month() {
        assert!(!is_plausible_mm_yy("13/25"));
        assert!(!is_plausible_mm_yy("00/25"));
    }

    #[test]
    fn is_plausible_mm_yy_no_slash() {
        assert!(!is_plausible_mm_yy("0125"));
    }

    #[test]
    fn detect_pan_visa() {
        let detections = detect_pan("Card: 4111111111111111");
        assert!(!detections.is_empty());
        assert_eq!(detections[0].kind, PiiKind::Pan);
    }

    #[test]
    fn detect_pan_no_card() {
        let detections = detect_pan("No card here");
        assert!(detections.is_empty());
    }

    #[test]
    fn detect_pan_invalid_luhn() {
        let detections = detect_pan("Card: 4111111111111112");
        assert!(detections.is_empty());
    }

    #[test]
    fn detect_cvv_present() {
        let detections = detect_cvv("CVV: 123");
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].kind, PiiKind::Cvv);
    }

    #[test]
    fn detect_cvv_four_digits() {
        let detections = detect_cvv("security code: 1234");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn detect_cvv_missing() {
        let detections = detect_cvv("no cvv here");
        assert!(detections.is_empty());
    }

    #[test]
    fn detect_expiration_date_present() {
        let detections = detect_expiration_date("Exp: 01/25");
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].kind, PiiKind::ExpirationDate);
    }

    #[test]
    fn detect_expiration_date_full_word() {
        let detections = detect_expiration_date("Expires: 12/2030");
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn detect_expiration_date_missing() {
        let detections = detect_expiration_date("no date here");
        assert!(detections.is_empty());
    }

    #[test]
    fn detect_pci_dss_all_present() {
        let text = "Card: 4111111111111111 CVV: 123 Exp: 01/25";
        let detections = detect_pci_dss(text);
        assert!(detections.iter().any(|d| d.kind == PiiKind::Pan));
        assert!(detections.iter().any(|d| d.kind == PiiKind::Cvv));
        assert!(detections.iter().any(|d| d.kind == PiiKind::ExpirationDate));
    }

    #[test]
    fn detect_pci_dss_sorted_by_position() {
        let text = "CVV: 999 Card: 4111111111111111";
        let detections = detect_pci_dss(text);
        if detections.len() >= 2 {
            assert!(detections[0].start <= detections[1].start);
        }
    }

    #[test]
    fn detect_card_numbers_with_spaces() {
        let detections = detect_card_numbers("4111 1111 1111 1111");
        assert!(!detections.is_empty());
    }

    #[test]
    fn detect_card_numbers_with_dashes() {
        let detections = detect_card_numbers("4111-1111-1111-1111");
        assert!(!detections.is_empty());
    }
}
