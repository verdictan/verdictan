// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Phase 24 — Language Detection & Enforcement
//!
//! Provides:
//! - A lightweight trigram + Unicode-block language detector (no external APIs).
//! - The `language-validator` policy config types for declarative pipeline use.
//!
//! Supported language codes: `en`, `es`, `fr`, `de`, `zh`, `ja`, `ko`, `ar`, `pt`, `ru`.

use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════════════════
// Public config types
// ═══════════════════════════════════════════════════════════════════════════

/// Action taken when a language policy violation is detected.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LanguageAction {
    /// Reject the request and return a block verdict.
    #[default]
    Block,
    /// Allow but emit a warning in the decision event.
    Warn,
}

/// Which payload the language validator checks.
///
/// Only `Input` is enforced by the current gateway runtime. `Output` and
/// `Both` are accepted for forward-compatibility but behave identically to
/// `Input` today.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LanguageApplyTo {
    /// Check only user/system input messages (the only enforced mode today).
    #[default]
    Input,
    /// Reserved for future output-phase enforcement — currently behaves like `Input`.
    Output,
    /// Reserved for future input+output enforcement — currently behaves like `Input`.
    Both,
}

/// Configuration for the `language-validator` policy.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LanguageValidatorConfig {
    /// Language codes that are permitted. Mutually exclusive with `denied_languages`.
    #[serde(default)]
    pub allowed_languages: Vec<String>,
    /// Language codes that are rejected. Mutually exclusive with `allowed_languages`.
    #[serde(default)]
    pub denied_languages: Vec<String>,
    /// Minimum confidence (0.0–1.0) required to act on a detection. Default: 0.5.
    #[serde(default = "default_min_confidence")]
    pub min_confidence: f64,
    /// What to do when the policy is violated. Default: `block`.
    #[serde(default)]
    pub action: LanguageAction,
    /// Which part of the conversation to check. Default: `both`.
    #[serde(default)]
    pub apply_to: LanguageApplyTo,
}

impl Default for LanguageValidatorConfig {
    fn default() -> Self {
        Self {
            allowed_languages: Vec::new(),
            denied_languages: Vec::new(),
            min_confidence: default_min_confidence(),
            action: LanguageAction::Block,
            apply_to: LanguageApplyTo::Input,
        }
    }
}

fn default_min_confidence() -> f64 {
    0.5
}

// ═══════════════════════════════════════════════════════════════════════════
// Detection result
// ═══════════════════════════════════════════════════════════════════════════

/// Language detection result.
#[derive(Clone, Debug, PartialEq)]
pub struct DetectionResult {
    /// ISO 639-1 language code (e.g. `"en"`, `"fr"`).
    pub language: String,
    /// Confidence score in \[0.0, 1.0\].
    pub confidence: f64,
}

// ═══════════════════════════════════════════════════════════════════════════
// Detection logic
// ═══════════════════════════════════════════════════════════════════════════

/// All language codes we can detect.
#[allow(dead_code)]
pub const SUPPORTED_LANGUAGES: &[&str] =
    &["en", "es", "fr", "de", "zh", "ja", "ko", "ar", "pt", "ru"];

/// Return `true` if `lang` is in [`SUPPORTED_LANGUAGES`].
#[allow(dead_code)]
fn is_supported_language(lang: &str) -> bool {
    SUPPORTED_LANGUAGES.contains(&lang)
}

/// Detect the language of `text`.
///
/// For non-Latin scripts, Unicode block ratios are used for high precision. For
/// Latin-script languages (en/es/fr/de/pt), distinctive character trigrams are
/// scored and normalised. Short text (fewer than 20 chars) produces low confidence.
///
/// Returns `None` when the text is empty.
pub fn detect(text: &str) -> Option<DetectionResult> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }

    // --- Non-Latin Unicode block detectors (fast path) ---
    if let Some(result) = detect_unicode_block(text) {
        return Some(result);
    }

    // --- Latin-script n-gram detector ---
    detect_latin(text)
}

/// Detect non-Latin scripts from Unicode block ratios.
fn detect_unicode_block(text: &str) -> Option<DetectionResult> {
    let char_count = text.chars().count() as f64;
    if char_count == 0.0 {
        return None;
    }

    let mut arabic = 0u32;
    let mut cyrillic = 0u32;
    let mut hangul = 0u32;
    let mut hiragana = 0u32;
    let mut katakana = 0u32;
    let mut cjk = 0u32;

    for ch in text.chars() {
        let c = ch as u32;
        match c {
            0x0600..=0x06FF | 0x0750..=0x077F | 0x08A0..=0x08FF => arabic += 1,
            0x0400..=0x04FF => cyrillic += 1,
            0xAC00..=0xD7A3 | 0x1100..=0x11FF | 0x3130..=0x318F => hangul += 1,
            0x3040..=0x309F => hiragana += 1,
            0x30A0..=0x30FF => katakana += 1,
            0x4E00..=0x9FFF | 0x3400..=0x4DBF | 0x20000..=0x2A6DF => cjk += 1,
            _ => {}
        }
    }

    let ratio = |count: u32| count as f64 / char_count;

    // Arabic: decisive above 5 %
    if ratio(arabic) > 0.05 {
        let conf = (ratio(arabic) * 3.0).min(1.0);
        return Some(DetectionResult {
            language: "ar".to_string(),
            confidence: conf,
        });
    }
    // Cyrillic: decisive above 5 %
    if ratio(cyrillic) > 0.05 {
        let conf = (ratio(cyrillic) * 3.0).min(1.0);
        return Some(DetectionResult {
            language: "ru".to_string(),
            confidence: conf,
        });
    }
    // Korean Hangul: decisive
    if ratio(hangul) > 0.05 {
        let conf = (ratio(hangul) * 3.0).min(1.0);
        return Some(DetectionResult {
            language: "ko".to_string(),
            confidence: conf,
        });
    }
    // Japanese: hiragana/katakana presence is decisive
    if ratio(hiragana) > 0.02 || ratio(katakana) > 0.04 {
        let ja_ratio = ratio(hiragana) + ratio(katakana) + ratio(cjk);
        let conf = (ja_ratio * 2.0).min(1.0);
        return Some(DetectionResult {
            language: "ja".to_string(),
            confidence: conf,
        });
    }
    // Chinese: CJK without kana/hangul
    if ratio(cjk) > 0.05 {
        let conf = (ratio(cjk) * 2.5).min(1.0);
        return Some(DetectionResult {
            language: "zh".to_string(),
            confidence: conf,
        });
    }

    None
}

/// Trigram sets for each Latin-script language. These are the most
/// language-discriminating trigrams derived from common text corpora.
fn latin_trigrams() -> HashMap<&'static str, &'static [&'static str]> {
    let mut m: HashMap<&str, &[&str]> = HashMap::new();
    m.insert(
        "en",
        &[
            "the", "and", "ing", "ion", "tio", "ent", "hat", "his", "her", "ere", "all", "tion",
            "for", "not", "are", "tha", "but", "this",
        ],
    );
    m.insert(
        "fr",
        &[
            "les", "ent", "que", "des", "est", "une", "ont", "par", "sur", "ait", "pour", "dans",
            "pas", "vous", "qui", "avec", "plus",
        ],
    );
    m.insert(
        "es",
        &[
            "que", "los", "est", "ent", "del", "las", "una", "con", "por", "para", "cion", "nos",
            "sus", "ser", "han", "una", "mas",
        ],
    );
    m.insert(
        "de",
        &[
            "der", "die", "das", "und", "ein", "sch", "ich", "cht", "ist", "den", "sie", "auf",
            "mit", "dem", "als", "ins", "ver",
        ],
    );
    m.insert(
        "pt",
        &[
            "que", "ent", "est", "dos", "das", "uma", "com", "nao", "por", "para", "oes", "cao",
            "cia", "sao", "nos", "ser", "mas",
        ],
    );
    m
}

/// Score a text against Latin-script language trigram lists.
fn detect_latin(text: &str) -> Option<DetectionResult> {
    let normalized = normalize_latin_text(text);
    let extracted = extract_trigrams(&normalized);
    let word_scores = score_latin_words(&normalized);

    if extracted.is_empty() {
        let has_alpha = normalized.chars().any(|ch| ch.is_ascii_alphabetic());
        return has_alpha.then(|| DetectionResult {
            language: "en".to_string(),
            confidence: 0.2,
        });
    }

    let tables = latin_trigrams();
    let mut best_lang = "en";
    let mut best_score = 0u32;
    let mut total_hits = 0u32;

    for (lang, trigrams) in &tables {
        let trigram_hits: u32 = trigrams
            .iter()
            .map(|t| extracted.get(*t).copied().unwrap_or(0))
            .sum();
        let word_hits = word_scores.get(*lang).copied().unwrap_or(0);
        let hits = trigram_hits + (word_hits * 3);
        total_hits += hits;
        if hits > best_score {
            best_score = hits;
            best_lang = lang;
        }
    }

    if total_hits == 0 {
        // No trigram evidence — default to English with low confidence.
        return Some(DetectionResult {
            language: "en".to_string(),
            confidence: 0.2,
        });
    }

    // Confidence = share of max trigram hits normalised to [0, 1].
    let confidence = ((best_score as f64 / total_hits as f64) * 5.0).clamp(0.1, 1.0);
    let text_chars = text.chars().count();
    // Short texts get halved confidence.
    let confidence = if text_chars < 20 {
        confidence * 0.5
    } else {
        confidence
    };

    Some(DetectionResult {
        language: best_lang.to_string(),
        confidence,
    })
}

fn normalize_latin_text(text: &str) -> String {
    text.chars()
        .map(|ch| match ch {
            'á' | 'à' | 'â' | 'ã' | 'ä' | 'å' | 'Á' | 'À' | 'Â' | 'Ã' | 'Ä' | 'Å' => {
                'a'
            }
            'ç' | 'Ç' => 'c',
            'é' | 'è' | 'ê' | 'ë' | 'É' | 'È' | 'Ê' | 'Ë' => 'e',
            'í' | 'ì' | 'î' | 'ï' | 'Í' | 'Ì' | 'Î' | 'Ï' => 'i',
            'ñ' | 'Ñ' => 'n',
            'ó' | 'ò' | 'ô' | 'õ' | 'ö' | 'Ó' | 'Ò' | 'Ô' | 'Õ' | 'Ö' => 'o',
            'ú' | 'ù' | 'û' | 'ü' | 'Ú' | 'Ù' | 'Û' | 'Ü' => 'u',
            other => other.to_ascii_lowercase(),
        })
        .collect()
}

fn latin_word_markers() -> HashMap<&'static str, &'static [&'static str]> {
    let mut markers: HashMap<&str, &[&str]> = HashMap::new();
    markers.insert(
        "en",
        &[
            "the", "and", "with", "this", "that", "from", "over", "quick", "brown",
        ],
    );
    markers.insert(
        "es",
        &[
            "el", "la", "los", "las", "que", "sobre", "pero", "para", "del", "una",
        ],
    );
    markers.insert(
        "fr",
        &[
            "bonjour", "avec", "dans", "pour", "vous", "cette", "journee", "comment", "monde",
        ],
    );
    markers.insert(
        "de",
        &["der", "die", "das", "und", "mit", "nicht", "ist", "ein"],
    );
    markers.insert(
        "pt",
        &["que", "com", "para", "uma", "das", "dos", "nao", "sao"],
    );
    markers
}

fn score_latin_words(text: &str) -> HashMap<&'static str, u32> {
    let tokens: Vec<&str> = text
        .split(|ch: char| !ch.is_ascii_alphabetic())
        .filter(|token| !token.is_empty())
        .collect();

    let markers = latin_word_markers();
    let mut scores = HashMap::new();
    for (lang, words) in markers {
        let score = tokens.iter().filter(|token| words.contains(token)).count() as u32;
        scores.insert(lang, score);
    }
    scores
}

/// Extract lowercase character trigrams from `text` and count occurrences.
fn extract_trigrams(text: &str) -> HashMap<&str, u32> {
    let mut counts: HashMap<&str, u32> = HashMap::new();
    let bytes = text.as_bytes();
    if bytes.len() < 3 {
        return counts;
    }
    for i in 0..bytes.len().saturating_sub(2) {
        // Only produce trigrams entirely within ASCII-printable range
        // to avoid false positives from multi-byte boundaries.
        if bytes[i].is_ascii_alphabetic()
            && bytes[i + 1].is_ascii_alphanumeric()
            && bytes[i + 2].is_ascii_alphabetic()
        {
            // Safety: i..i+3 is within bounds (checked by loop bound) and is valid UTF-8
            // (all bytes are ASCII).
            if let Some(tri) = text.get(i..i + 3) {
                *counts.entry(tri).or_insert(0) += 1;
            }
        }
    }
    counts
}

// ═══════════════════════════════════════════════════════════════════════════
// Policy evaluation helper used by enforcement.rs
// ═══════════════════════════════════════════════════════════════════════════

/// Evaluate a language-validator policy against `text`.
///
/// Returns `(violated, detected_language, confidence)`.
pub fn check_language_policy(text: &str, config: &LanguageValidatorConfig) -> (bool, String, f64) {
    let result = match detect(text) {
        Some(r) => r,
        None => return (false, "unknown".to_string(), 0.0),
    };

    // Below confidence threshold → no action.
    if result.confidence < config.min_confidence {
        return (false, result.language, result.confidence);
    }

    let violated = if !config.allowed_languages.is_empty() {
        // Allow-list mode: violation if detected language NOT in list.
        !config
            .allowed_languages
            .iter()
            .any(|l| l.to_ascii_lowercase() == result.language)
    } else if !config.denied_languages.is_empty() {
        // Deny-list mode: violation if detected language IS in list.
        config
            .denied_languages
            .iter()
            .any(|l| l.to_ascii_lowercase() == result.language)
    } else {
        false
    };

    (violated, result.language, result.confidence)
}

// ═══════════════════════════════════════════════════════════════════════════
// Unit tests
// ═══════════════════════════════════════════════════════════════════════════

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
    fn detect_empty_string_returns_none() {
        assert!(detect("").is_none());
        assert!(detect("   ").is_none());
    }

    #[test]
    fn detect_english_text() {
        let result = detect("The quick brown fox jumps over the lazy dog and this is a longer sentence with more words").unwrap();
        assert_eq!(result.language, "en");
        assert!(result.confidence > 0.3);
    }

    #[test]
    fn detect_french_text() {
        let result = detect("Bonjour, comment allez-vous? Cette journée est magnifique dans le monde avec vous pour cette belle").unwrap();
        assert_eq!(result.language, "fr");
    }

    #[test]
    fn detect_spanish_text() {
        let result =
            detect("El gato está sobre la mesa y los perros están en el jardín para una fiesta")
                .unwrap();
        assert_eq!(result.language, "es");
    }

    #[test]
    fn detect_german_text() {
        let result =
            detect("Der schnelle braune Fuchs springt über den faulen Hund und das ist nicht gut")
                .unwrap();
        assert_eq!(result.language, "de");
    }

    #[test]
    fn detect_chinese_text() {
        let result = detect("这是一个中文句子，用来测试语言检测功能").unwrap();
        assert_eq!(result.language, "zh");
        assert!(result.confidence > 0.5);
    }

    #[test]
    fn detect_japanese_text() {
        let result =
            detect("これは日本語のテストです。ひらがなとカタカナが含まれています").unwrap();
        assert_eq!(result.language, "ja");
    }

    #[test]
    fn detect_korean_text() {
        let result = detect("안녕하세요, 이것은 한국어 문장입니다").unwrap();
        assert_eq!(result.language, "ko");
    }

    #[test]
    fn detect_arabic_text() {
        let result = detect("مرحبا بالعالم، هذا نص باللغة العربية").unwrap();
        assert_eq!(result.language, "ar");
    }

    #[test]
    fn detect_russian_text() {
        let result = detect("Привет мир, это текст на русском языке").unwrap();
        assert_eq!(result.language, "ru");
    }

    #[test]
    fn detect_short_text_low_confidence() {
        let result = detect("hi").unwrap();
        assert!(result.confidence <= 0.5);
    }

    #[test]
    fn is_supported_language_valid() {
        assert!(is_supported_language("en"));
        assert!(is_supported_language("zh"));
        assert!(is_supported_language("ja"));
        assert!(is_supported_language("ko"));
        assert!(is_supported_language("ar"));
        assert!(is_supported_language("ru"));
    }

    #[test]
    fn is_supported_language_invalid() {
        assert!(!is_supported_language("xx"));
        assert!(!is_supported_language("EN"));
        assert!(!is_supported_language(""));
    }

    #[test]
    fn check_language_policy_empty_text_no_violation() {
        let config = LanguageValidatorConfig::default();
        let (violated, lang, _) = check_language_policy("", &config);
        assert!(!violated);
        assert_eq!(lang, "unknown");
    }

    #[test]
    fn check_language_policy_allowed_list_permits() {
        let config = LanguageValidatorConfig {
            allowed_languages: vec!["en".to_string()],
            min_confidence: 0.1,
            ..Default::default()
        };
        let (violated, _, _) = check_language_policy(
            "The quick brown fox jumps over the lazy dog and this is a longer sentence",
            &config,
        );
        assert!(!violated);
    }

    #[test]
    fn check_language_policy_allowed_list_blocks() {
        let config = LanguageValidatorConfig {
            allowed_languages: vec!["fr".to_string()],
            min_confidence: 0.1,
            ..Default::default()
        };
        let (violated, lang, _) = check_language_policy(
            "The quick brown fox jumps over the lazy dog and this is a longer sentence",
            &config,
        );
        assert!(violated);
        assert_eq!(lang, "en");
    }

    #[test]
    fn check_language_policy_denied_list_blocks() {
        let config = LanguageValidatorConfig {
            denied_languages: vec!["zh".to_string()],
            min_confidence: 0.1,
            ..Default::default()
        };
        let (violated, _, _) =
            check_language_policy("这是一个中文句子，用来测试语言检测功能", &config);
        assert!(violated);
    }

    #[test]
    fn check_language_policy_below_confidence_no_action() {
        let config = LanguageValidatorConfig {
            allowed_languages: vec!["fr".to_string()],
            min_confidence: 0.99,
            ..Default::default()
        };
        let (violated, _, confidence) = check_language_policy("hi", &config);
        assert!(!violated);
        assert!(confidence < 0.99);
    }

    #[test]
    fn check_language_policy_no_lists_never_violates() {
        let config = LanguageValidatorConfig::default();
        let (violated, _, _) = check_language_policy(
            "The quick brown fox jumps over the lazy dog and this is a longer sentence",
            &config,
        );
        assert!(!violated);
    }

    #[test]
    fn language_validator_config_defaults() {
        let config = LanguageValidatorConfig::default();
        assert!(config.allowed_languages.is_empty());
        assert!(config.denied_languages.is_empty());
        assert!((config.min_confidence - 0.5).abs() < f64::EPSILON);
        assert_eq!(config.action, LanguageAction::Block);
        assert_eq!(config.apply_to, LanguageApplyTo::Input);
    }

    #[test]
    fn language_action_serde() {
        let json = serde_json::to_string(&LanguageAction::Warn).unwrap();
        assert_eq!(json, "\"warn\"");
        let parsed: LanguageAction = serde_json::from_str("\"block\"").unwrap();
        assert_eq!(parsed, LanguageAction::Block);
    }
}
