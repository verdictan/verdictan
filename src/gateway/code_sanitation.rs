// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

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

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CodeSanitationConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub block_on_match: bool,
    #[serde(default)]
    pub additional_patterns: Vec<String>,
}

impl Default for CodeSanitationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_on_match: false,
            additional_patterns: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct CodeSanitationFinding {
    pub pattern: String,
    pub snippet: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct CodeSanitationResult {
    pub flagged: bool,
    pub sanitized_text: String,
    pub findings: Vec<CodeSanitationFinding>,
}

const DEFAULT_PATTERNS: &[&str] = &[
    r"(?i)rm\s+-rf",
    r"(?i)drop\s+table",
    r"(?i)169\.254\.169\.254",
    r"(?i)curl\s+https?://localhost",
    r"(?i)chmod\s+777",
    r"(?i)aws\s+s3\s+cp.+--recursive",
];

fn default_true() -> bool {
    true
}

pub fn sanitize_text(input: &str, config: &CodeSanitationConfig) -> CodeSanitationResult {
    if !config.enabled {
        return CodeSanitationResult {
            flagged: false,
            sanitized_text: input.to_string(),
            findings: Vec::new(),
        };
    }

    let mut findings = Vec::new();
    let mut output = input.to_string();

    for pattern in DEFAULT_PATTERNS
        .iter()
        .map(|pattern| (*pattern).to_string())
        .chain(config.additional_patterns.iter().cloned())
    {
        let Ok(regex) = Regex::new(&pattern) else {
            continue;
        };
        let matches = regex
            .find_iter(&output)
            .map(|capture| capture.as_str().to_string())
            .collect::<Vec<_>>();
        for snippet in matches {
            findings.push(CodeSanitationFinding {
                pattern: pattern.clone(),
                snippet: snippet.clone(),
            });
            output = output.replace(&snippet, "[redacted code pattern]");
        }
    }

    CodeSanitationResult {
        flagged: !findings.is_empty(),
        sanitized_text: output,
        findings,
    }
}

pub fn extract_code_blocks(input: &str) -> Vec<String> {
    let re = static_regex!(r"(?s)```[a-zA-Z0-9_-]*\n(.*?)```");
    re.captures_iter(input)
        .filter_map(|capture| capture.get(1).map(|value| value.as_str().to_string()))
        .collect()
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
    fn sanitize_disabled_returns_input_unchanged() {
        let config = CodeSanitationConfig {
            enabled: false,
            ..Default::default()
        };
        let result = sanitize_text("rm -rf /", &config);
        assert!(!result.flagged);
        assert_eq!(result.sanitized_text, "rm -rf /");
        assert!(result.findings.is_empty());
    }

    #[test]
    fn sanitize_no_match_returns_clean() {
        let config = CodeSanitationConfig::default();
        let result = sanitize_text("hello world", &config);
        assert!(!result.flagged);
        assert_eq!(result.sanitized_text, "hello world");
        assert!(result.findings.is_empty());
    }

    #[test]
    fn sanitize_detects_rm_rf() {
        let config = CodeSanitationConfig::default();
        let result = sanitize_text("please run rm -rf / now", &config);
        assert!(result.flagged);
        assert!(result.sanitized_text.contains("[redacted code pattern]"));
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].snippet, "rm -rf");
    }

    #[test]
    fn sanitize_detects_drop_table() {
        let config = CodeSanitationConfig::default();
        let result = sanitize_text("DROP TABLE users;", &config);
        assert!(result.flagged);
        assert_eq!(result.findings.len(), 1);
    }

    #[test]
    fn sanitize_detects_metadata_endpoint() {
        let config = CodeSanitationConfig::default();
        let result = sanitize_text("curl 169.254.169.254/latest/meta-data", &config);
        assert!(result.flagged);
    }

    #[test]
    fn sanitize_detects_chmod_777() {
        let config = CodeSanitationConfig::default();
        let result = sanitize_text("chmod 777 /etc/passwd", &config);
        assert!(result.flagged);
    }

    #[test]
    fn sanitize_detects_curl_localhost() {
        let config = CodeSanitationConfig::default();
        let result = sanitize_text("curl http://localhost:8080/admin", &config);
        assert!(result.flagged);
    }

    #[test]
    fn sanitize_detects_aws_s3_recursive() {
        let config = CodeSanitationConfig::default();
        let result = sanitize_text("aws s3 cp s3://bucket /tmp --recursive", &config);
        assert!(result.flagged);
    }

    #[test]
    fn sanitize_multiple_patterns() {
        let config = CodeSanitationConfig::default();
        let result = sanitize_text("rm -rf / && DROP TABLE x", &config);
        assert!(result.flagged);
        assert_eq!(result.findings.len(), 2);
    }

    #[test]
    fn sanitize_additional_patterns() {
        let config = CodeSanitationConfig {
            enabled: true,
            block_on_match: false,
            additional_patterns: vec![r"eval\(".to_string()],
        };
        let result = sanitize_text("eval(user_input)", &config);
        assert!(result.flagged);
        assert_eq!(result.findings[0].snippet, "eval(");
    }

    #[test]
    fn sanitize_invalid_additional_pattern_skipped() {
        let config = CodeSanitationConfig {
            enabled: true,
            block_on_match: false,
            additional_patterns: vec!["[invalid".to_string()],
        };
        let result = sanitize_text("nothing here", &config);
        assert!(!result.flagged);
    }

    #[test]
    fn config_default_values() {
        let config = CodeSanitationConfig::default();
        assert!(config.enabled);
        assert!(!config.block_on_match);
        assert!(config.additional_patterns.is_empty());
    }

    #[test]
    fn extract_code_blocks_none() {
        let blocks = extract_code_blocks("no code blocks here");
        assert!(blocks.is_empty());
    }

    #[test]
    fn extract_code_blocks_single() {
        let input = "text\n```rust\nfn main() {}\n```\nmore text";
        let blocks = extract_code_blocks(input);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0], "fn main() {}\n");
    }

    #[test]
    fn extract_code_blocks_multiple() {
        let input = "```python\nprint('a')\n```\n\n```js\nconsole.log('b')\n```";
        let blocks = extract_code_blocks(input);
        assert_eq!(blocks.len(), 2);
        assert!(blocks[0].contains("print"));
        assert!(blocks[1].contains("console"));
    }

    #[test]
    fn extract_code_blocks_no_language_tag() {
        let input = "```\nhello\n```";
        let blocks = extract_code_blocks(input);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0], "hello\n");
    }
}
