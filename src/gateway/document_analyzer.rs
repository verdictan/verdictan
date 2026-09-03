// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::io::Read;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde_json::Value;

macro_rules! static_regex {
    ($pattern:expr) => {{
        static RE: std::sync::OnceLock<regex_lite::Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| {
            #[allow(clippy::expect_used)]
            regex_lite::Regex::new($pattern).expect("static regex pattern")
        })
    }};
}

use super::code_sanitation::{extract_code_blocks, sanitize_text, CodeSanitationConfig};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DocumentAnalyzerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub sanitize_code: bool,
    #[serde(default = "default_max_document_bytes")]
    pub max_document_bytes: usize,
    #[serde(default)]
    pub allowed_mime_types: Vec<String>,
}

impl Default for DocumentAnalyzerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sanitize_code: true,
            max_document_bytes: default_max_document_bytes(),
            allowed_mime_types: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct DocumentFinding {
    pub source: String,
    pub mime_type: String,
    pub extracted_chars: usize,
    pub code_findings: usize,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct DocumentAnalysisResult {
    pub text_fragments: Vec<String>,
    pub findings: Vec<DocumentFinding>,
    pub blocked_reason: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_max_document_bytes() -> usize {
    512 * 1024
}

pub fn analyze_request_documents(
    request_json: Option<&Value>,
    messages: &[crate::gateway::enforcement::ChatMessage],
    config: &DocumentAnalyzerConfig,
) -> DocumentAnalysisResult {
    if !config.enabled {
        return DocumentAnalysisResult {
            text_fragments: Vec::new(),
            findings: Vec::new(),
            blocked_reason: None,
        };
    }

    let mut text_fragments = messages
        .iter()
        .flat_map(|message| extract_code_blocks(&message.content))
        .collect::<Vec<_>>();
    let mut findings = Vec::new();

    for (source, mime_type, raw_bytes) in collect_documents(request_json) {
        if raw_bytes.len() > config.max_document_bytes {
            return DocumentAnalysisResult {
                text_fragments,
                findings,
                blocked_reason: Some(format!("document_too_large:{source}")),
            };
        }

        if !config.allowed_mime_types.is_empty()
            && !config
                .allowed_mime_types
                .iter()
                .any(|allowed| allowed == &mime_type)
        {
            return DocumentAnalysisResult {
                text_fragments,
                findings,
                blocked_reason: Some(format!("mime_type_not_allowed:{mime_type}")),
            };
        }

        let extracted = extract_document_text(&mime_type, &raw_bytes);
        let sanitized = if config.sanitize_code {
            sanitize_text(&extracted, &CodeSanitationConfig::default()).sanitized_text
        } else {
            extracted
        };
        let code_findings = extract_code_blocks(&sanitized).len();
        findings.push(DocumentFinding {
            source,
            mime_type,
            extracted_chars: sanitized.len(),
            code_findings,
        });
        if !sanitized.trim().is_empty() {
            text_fragments.push(sanitized);
        }
    }

    DocumentAnalysisResult {
        text_fragments,
        findings,
        blocked_reason: None,
    }
}

fn collect_documents(request_json: Option<&Value>) -> Vec<(String, String, Vec<u8>)> {
    let Some(request_json) = request_json else {
        return Vec::new();
    };

    ["documents", "attachments", "input_documents", "files"]
        .iter()
        .filter_map(|key| request_json.get(*key).and_then(Value::as_array))
        .flat_map(|documents| documents.iter())
        .filter_map(|document| {
            let source = document
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("inline-document")
                .to_string();
            let mime_type = document
                .get("mime_type")
                .or_else(|| document.get("content_type"))
                .and_then(Value::as_str)
                .unwrap_or("text/plain")
                .to_string();

            if let Some(text) = document.get("text").and_then(Value::as_str) {
                return Some((source, mime_type, text.as_bytes().to_vec()));
            }

            let encoded = document
                .get("content_base64")
                .or_else(|| document.get("data"))
                .and_then(Value::as_str)?;
            let bytes = BASE64_STANDARD.decode(encoded).ok()?;
            Some((source, mime_type, bytes))
        })
        .collect()
}

fn extract_document_text(mime_type: &str, raw_bytes: &[u8]) -> String {
    if mime_type.contains("wordprocessingml.document") {
        return extract_docx_text(raw_bytes).unwrap_or_default();
    }
    if mime_type.contains("pdf") {
        return extract_pdf_text(raw_bytes);
    }
    String::from_utf8_lossy(raw_bytes).to_string()
}

fn extract_docx_text(raw_bytes: &[u8]) -> Option<String> {
    let cursor = std::io::Cursor::new(raw_bytes);
    let mut archive = zip::ZipArchive::new(cursor).ok()?;
    let mut document = archive.by_name("word/document.xml").ok()?;
    let mut xml = String::new();
    document.read_to_string(&mut xml).ok()?;
    Some(static_regex!(r"<[^>]+>").replace_all(&xml, " ").to_string())
}

fn extract_pdf_text(raw_bytes: &[u8]) -> String {
    let mut text = String::new();
    let mut current = String::new();
    for byte in raw_bytes {
        let ch = *byte as char;
        if ch.is_ascii_graphic() || ch == ' ' || ch == '\n' {
            current.push(ch);
        } else if current.len() >= 4 {
            text.push_str(&current);
            text.push('\n');
            current.clear();
        } else {
            current.clear();
        }
    }
    if current.len() >= 4 {
        text.push_str(&current);
    }
    text
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
    use std::io::Write;

    #[test]
    fn analyze_request_documents_blocks_oversized_documents() {
        let request = serde_json::json!({
            "documents": [{
                "name": "large.txt",
                "mime_type": "text/plain",
                "text": "123456789"
            }]
        });
        let config = DocumentAnalyzerConfig {
            max_document_bytes: 4,
            ..Default::default()
        };

        let result = analyze_request_documents(Some(&request), &[], &config);
        assert_eq!(
            result.blocked_reason.as_deref(),
            Some("document_too_large:large.txt")
        );
        assert!(result.findings.is_empty());
    }

    #[test]
    fn analyze_request_documents_enforces_mime_allowlist() {
        let request = serde_json::json!({
            "attachments": [{
                "name": "snippet.md",
                "mime_type": "text/markdown",
                "text": "hello"
            }]
        });
        let config = DocumentAnalyzerConfig {
            allowed_mime_types: vec!["text/plain".to_string()],
            ..Default::default()
        };

        let result = analyze_request_documents(Some(&request), &[], &config);
        assert_eq!(
            result.blocked_reason.as_deref(),
            Some("mime_type_not_allowed:text/markdown")
        );
    }

    #[test]
    fn collect_documents_reads_text_and_base64_variants() {
        let request = serde_json::json!({
            "documents": [{
                "name": "plain.txt",
                "mime_type": "text/plain",
                "text": "hello"
            }],
            "files": [{
                "name": "encoded.txt",
                "content_type": "text/plain",
                "content_base64": BASE64_STANDARD.encode("encoded body")
            }]
        });

        let docs = collect_documents(Some(&request));
        assert_eq!(docs.len(), 2);
        assert_eq!(docs[0].0, "plain.txt");
        assert_eq!(docs[0].1, "text/plain");
        assert_eq!(docs[0].2, b"hello".to_vec());
        assert_eq!(docs[1].0, "encoded.txt");
        assert_eq!(docs[1].2, b"encoded body".to_vec());
    }

    #[test]
    fn extract_docx_text_reads_document_xml_contents() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut archive = zip::ZipWriter::new(&mut cursor);
            archive
                .start_file(
                    "word/document.xml",
                    zip::write::SimpleFileOptions::default(),
                )
                .expect("start file");
            archive
                .write_all(
                    br#"<w:document><w:p><w:t>Hello</w:t><w:t> world</w:t></w:p></w:document>"#,
                )
                .expect("write xml");
            archive.finish().expect("finish zip");
        }

        let extracted = extract_docx_text(cursor.get_ref()).expect("docx text");
        assert!(extracted.contains("Hello"));
        assert!(extracted.contains("world"));
    }

    #[test]
    fn extract_pdf_text_collects_ascii_runs() {
        let extracted = extract_pdf_text(b"\x00\x01Invoice 1234\x00\x02AB\x00Receipt line");
        assert!(extracted.contains("Invoice 1234"));
        assert!(extracted.contains("Receipt line"));
        assert!(!extracted.contains("AB"));
    }

    #[test]
    fn document_analyzer_config_defaults() {
        let config = DocumentAnalyzerConfig::default();
        assert!(config.enabled);
        assert!(config.sanitize_code);
        assert_eq!(config.max_document_bytes, 512 * 1024);
        assert!(config.allowed_mime_types.is_empty());
    }

    #[test]
    fn analyze_request_documents_disabled_returns_empty() {
        let request = serde_json::json!({
            "documents": [{
                "name": "test.txt",
                "mime_type": "text/plain",
                "text": "sensitive data"
            }]
        });
        let config = DocumentAnalyzerConfig {
            enabled: false,
            ..Default::default()
        };
        let result = analyze_request_documents(Some(&request), &[], &config);
        assert!(result.text_fragments.is_empty());
        assert!(result.findings.is_empty());
        assert!(result.blocked_reason.is_none());
    }

    #[test]
    fn analyze_request_documents_no_request_json() {
        let config = DocumentAnalyzerConfig::default();
        let result = analyze_request_documents(None, &[], &config);
        assert!(result.text_fragments.is_empty());
        assert!(result.findings.is_empty());
        assert!(result.blocked_reason.is_none());
    }

    #[test]
    fn analyze_request_documents_empty_allowlist_permits_all_types() {
        let request = serde_json::json!({
            "documents": [{
                "name": "any.txt",
                "mime_type": "application/octet-stream",
                "text": "data here"
            }]
        });
        let config = DocumentAnalyzerConfig {
            sanitize_code: false,
            ..Default::default()
        };
        let result = analyze_request_documents(Some(&request), &[], &config);
        assert!(result.blocked_reason.is_none());
        assert!(!result.findings.is_empty());
    }

    #[test]
    fn analyze_request_documents_records_finding_metadata() {
        let request = serde_json::json!({
            "documents": [{
                "name": "report.txt",
                "mime_type": "text/plain",
                "text": "hello world"
            }]
        });
        let config = DocumentAnalyzerConfig {
            sanitize_code: false,
            ..Default::default()
        };
        let result = analyze_request_documents(Some(&request), &[], &config);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].source, "report.txt");
        assert_eq!(result.findings[0].mime_type, "text/plain");
        assert!(result.findings[0].extracted_chars > 0);
    }

    #[test]
    fn collect_documents_reads_from_data_key() {
        let request = serde_json::json!({
            "files": [{
                "name": "encoded.txt",
                "content_type": "text/plain",
                "data": BASE64_STANDARD.encode("from data key")
            }]
        });
        let docs = collect_documents(Some(&request));
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].2, b"from data key".to_vec());
    }

    #[test]
    fn collect_documents_no_request_returns_empty() {
        assert!(collect_documents(None).is_empty());
    }

    #[test]
    fn collect_documents_no_document_keys_returns_empty() {
        let request = serde_json::json!({"model": "gpt-4"});
        assert!(collect_documents(Some(&request)).is_empty());
    }

    #[test]
    fn collect_documents_default_name_and_mime_type() {
        let request = serde_json::json!({
            "documents": [{"text": "no name or mime"}]
        });
        let docs = collect_documents(Some(&request));
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].0, "inline-document");
        assert_eq!(docs[0].1, "text/plain");
    }

    #[test]
    fn collect_documents_skips_invalid_base64() {
        let request = serde_json::json!({
            "documents": [{
                "name": "bad.txt",
                "content_base64": "not-valid-base64!!!"
            }]
        });
        let docs = collect_documents(Some(&request));
        assert!(docs.is_empty());
    }

    #[test]
    fn collect_documents_reads_input_documents_key() {
        let request = serde_json::json!({
            "input_documents": [{
                "name": "spec.txt",
                "text": "some spec"
            }]
        });
        let docs = collect_documents(Some(&request));
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].0, "spec.txt");
    }

    #[test]
    fn extract_document_text_plain_text() {
        let result = extract_document_text("text/plain", b"simple text");
        assert_eq!(result, "simple text");
    }

    #[test]
    fn extract_document_text_lossy_utf8() {
        let bytes = b"valid \xff text";
        let result = extract_document_text("text/plain", bytes);
        assert!(result.contains("valid"));
        assert!(result.contains("text"));
    }

    #[test]
    fn extract_docx_text_invalid_zip_returns_none() {
        assert!(extract_docx_text(b"not a zip file").is_none());
    }

    #[test]
    fn extract_pdf_text_empty_input() {
        assert!(extract_pdf_text(b"").is_empty());
    }

    #[test]
    fn extract_pdf_text_all_binary_no_runs() {
        let result = extract_pdf_text(&[0x00, 0x01, 0x02, 0x03, 0xFF]);
        assert!(result.is_empty());
    }

    #[test]
    fn extract_pdf_text_trailing_run() {
        let result = extract_pdf_text(b"\x00long enough trailing");
        assert!(result.contains("long enough trailing"));
    }

    #[test]
    fn extract_pdf_text_short_trailing_run_skipped() {
        let result = extract_pdf_text(b"\x00ab");
        assert!(!result.contains("ab"));
    }

    #[test]
    fn document_finding_serialization() {
        let finding = DocumentFinding {
            source: "test.txt".to_string(),
            mime_type: "text/plain".to_string(),
            extracted_chars: 42,
            code_findings: 1,
        };
        let json = serde_json::to_value(&finding).unwrap();
        assert_eq!(json["source"], "test.txt");
        assert_eq!(json["extracted_chars"], 42);
        assert_eq!(json["code_findings"], 1);
    }

    #[test]
    fn document_analysis_result_serialization() {
        let result = DocumentAnalysisResult {
            text_fragments: vec!["fragment".to_string()],
            findings: vec![],
            blocked_reason: Some("too_large".to_string()),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["text_fragments"][0], "fragment");
        assert_eq!(json["blocked_reason"], "too_large");
    }

    #[test]
    fn document_analyzer_config_serde_roundtrip() {
        let config = DocumentAnalyzerConfig {
            enabled: false,
            sanitize_code: true,
            max_document_bytes: 1024,
            allowed_mime_types: vec!["text/plain".to_string()],
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: DocumentAnalyzerConfig = serde_json::from_str(&json).unwrap();
        assert!(!deserialized.enabled);
        assert!(deserialized.sanitize_code);
        assert_eq!(deserialized.max_document_bytes, 1024);
        assert_eq!(deserialized.allowed_mime_types, vec!["text/plain"]);
    }

    #[test]
    fn document_analyzer_config_deserialization_defaults() {
        let json = serde_json::json!({});
        let config: DocumentAnalyzerConfig = serde_json::from_value(json).unwrap();
        assert!(config.enabled);
        assert!(!config.sanitize_code);
        assert_eq!(config.max_document_bytes, 512 * 1024);
        assert!(config.allowed_mime_types.is_empty());
    }
}
