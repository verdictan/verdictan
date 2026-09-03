// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::CliError;

// ── TestingSection ─────────────────────────────────────────────────────────────

/// Top-level `testing` section of a policy-config.yaml.
///
/// Parsed from:
/// ```yaml
/// testing:
/// default_threshold: 0.8
/// suites:
/// - name: "smoke"
/// description: "Basic smoke tests"
/// cases:
/// - name: "test case 1"
/// input: { messages: [...] }
/// expected: { verdict: "allow", reason_code: "ok" }
/// assertions: [...]
/// ```
///
/// `plugins`, `strategies`, and `suites[].target` are removed because no
/// plugin or strategy executor exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestingSection {
    #[serde(default)]
    pub suites: Vec<TestSuite>,
    pub default_threshold: Option<f64>,
}

/// Fields removed from the testing section.
pub const REMOVED_TESTING_FIELDS: &[&str] = &["plugins", "strategies"];

impl TestingSection {
    /// Parse the `testing` section from the root config JSON value.
    ///
    /// Returns `Ok(None)` if the `testing` key is absent.
    /// Returns an error if removed fields (`plugins`, `strategies`) are present.
    pub fn from_json(root: &Value) -> Result<Option<Self>, CliError> {
        let Some(testing_val) = root.get("testing") else {
            return Ok(None);
        };

        // Reject removed fields.
        for field in REMOVED_TESTING_FIELDS {
            if testing_val.get(*field).is_some() {
                return Err(CliError::user(format!(
                    "testing.{field} has been removed; no plugin/strategy executor exists"
                )));
            }
        }

        let suites: Vec<TestSuite> = testing_val
            .get("suites")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .map(TestSuite::from_json)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();

        let default_threshold = testing_val
            .get("default_threshold")
            .and_then(|v| v.as_f64());

        Ok(Some(TestingSection {
            suites,
            default_threshold,
        }))
    }
}

// ── TestSuite ──────────────────────────────────────────────────────────────────

/// A named suite of test cases within the `testing` section.
///
/// `target` was removed (no target executor exists).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSuite {
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub assertions: Vec<Value>,
    #[serde(default)]
    pub cases: Vec<TestCase>,
}

impl TestSuite {
    fn from_json(v: &Value) -> Result<Self, CliError> {
        let name = v
            .get("name")
            .and_then(|n| n.as_str())
            .ok_or_else(|| CliError::user("testing.suites[]: each suite must have a 'name'"))?
            .to_string();

        // Reject removed `target` field.
        if v.get("target").is_some() {
            return Err(CliError::user(format!(
                "testing.suites['{name}'].target has been removed; no target executor exists"
            )));
        }

        let description = v
            .get("description")
            .and_then(|d| d.as_str())
            .map(|s| s.to_string());

        let assertions: Vec<Value> = v
            .get("assertions")
            .and_then(|a| a.as_array())
            .cloned()
            .unwrap_or_default();

        let cases: Vec<TestCase> = v
            .get("cases")
            .and_then(|c| c.as_array())
            .map(|arr| {
                arr.iter()
                    .map(TestCase::from_json)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();

        Ok(TestSuite {
            name,
            description,
            assertions,
            cases,
        })
    }
}

// ── TestCase ──────────────────────────────────────────────────────────────────

/// A single test case within a suite. Follows the `GoldenTest` shape in
/// `test_runner.rs` but is parsed inline from the `testing` YAML section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    pub name: String,
    pub input: TestCaseInput,
    pub expected: TestCaseExpected,
    /// Per-case assertion overrides (inlined from the case or inherited from
    /// the suite-level `assertions` array).
    #[serde(default)]
    pub assertions: Vec<Value>,
}

impl TestCase {
    fn from_json(v: &Value) -> Result<Self, CliError> {
        let name = v
            .get("name")
            .and_then(|n| n.as_str())
            .ok_or_else(|| {
                CliError::user("testing.suites[].cases[]: each case must have a 'name'")
            })?
            .to_string();

        let input = TestCaseInput::from_json(v.get("input").unwrap_or(&Value::Null));
        let expected = TestCaseExpected::from_json(v.get("expected").unwrap_or(&Value::Null));

        let assertions: Vec<Value> = v
            .get("assertions")
            .and_then(|a| a.as_array())
            .cloned()
            .unwrap_or_default();

        Ok(TestCase {
            name,
            input,
            expected,
            assertions,
        })
    }
}

// ── TestCaseInput ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCaseInput {
    #[serde(default)]
    pub(crate) messages: Vec<TestMessage>,
    #[serde(default)]
    pub(crate) headers: std::collections::BTreeMap<String, String>,
    pub(crate) request: Option<Value>,
    pub(crate) upstream_response: Option<Value>,
    /// Optional proxy name for targeting-aware test evaluation.
    pub(crate) proxy_name: Option<String>,
    /// Optional team slugs for targeting-aware test evaluation.
    pub(crate) team_slugs: Option<Vec<String>>,
}

impl TestCaseInput {
    fn from_json(v: &Value) -> Self {
        let messages: Vec<TestMessage> = v
            .get("messages")
            .and_then(|m| m.as_array())
            .map(|arr| arr.iter().map(TestMessage::from_json).collect())
            .unwrap_or_default();

        let headers: std::collections::BTreeMap<String, String> = v
            .get("headers")
            .and_then(|h| h.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        let proxy_name = v
            .get("proxy_name")
            .and_then(|n| n.as_str())
            .map(|s| s.to_string());

        let team_slugs: Option<Vec<String>> =
            v.get("team_slugs").and_then(|a| a.as_array()).map(|arr| {
                arr.iter()
                    .filter_map(|s| s.as_str().map(|s| s.to_string()))
                    .collect()
            });

        Self {
            messages,
            headers,
            request: v.get("request").cloned(),
            upstream_response: v.get("upstream_response").cloned(),
            proxy_name,
            team_slugs,
        }
    }
}

// ── TestMessage ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestMessage {
    pub(crate) role: String,
    pub(crate) content: String,
}

impl TestMessage {
    fn from_json(v: &Value) -> Self {
        Self {
            role: v
                .get("role")
                .and_then(|r| r.as_str())
                .unwrap_or("user")
                .to_string(),
            content: v
                .get("content")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string(),
        }
    }
}

// ── TestCaseExpected ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCaseExpected {
    pub(crate) verdict: String,
    pub(crate) reason_code: String,
}

impl TestCaseExpected {
    fn from_json(v: &Value) -> Self {
        Self {
            verdict: v
                .get("verdict")
                .and_then(|x| x.as_str())
                .unwrap_or("allow")
                .to_string(),
            reason_code: v
                .get("reason_code")
                .and_then(|x| x.as_str())
                .unwrap_or("ok")
                .to_string(),
        }
    }
}

// ── Unit tests ─────────────────────────────────────────────────────────────────

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
    use serde_json::json;

    #[test]
    fn policy_testing_config_rejects_removed_plugins() {
        let root = json!({
            "testing": {
                "plugins": ["trace"],
                "suites": []
            }
        });
        let err = TestingSection::from_json(&root).unwrap_err();
        assert!(err.to_string().contains("plugins"), "error: {err}");
    }

    #[test]
    fn policy_testing_config_rejects_removed_strategies() {
        let root = json!({
            "testing": {
                "strategies": ["smoke"],
                "suites": []
            }
        });
        let err = TestingSection::from_json(&root).unwrap_err();
        assert!(err.to_string().contains("strategies"), "error: {err}");
    }

    #[test]
    fn policy_testing_config_rejects_suite_target() {
        let root = json!({
            "testing": {
                "suites": [{
                    "name": "smoke",
                    "target": "judge-provider",
                    "cases": []
                }]
            }
        });
        let err = TestingSection::from_json(&root).unwrap_err();
        assert!(err.to_string().contains("target"), "error: {err}");
    }

    #[test]
    fn policy_testing_config_parses_suite_and_case_defaults() {
        let root = json!({
            "testing": {
                "default_threshold": 0.65,
                "suites": [{
                    "name": "smoke",
                    "assertions": [{"type": "contains", "value": "ok"}],
                    "cases": [{
                        "name": "defaults",
                        "input": {
                            "messages": [{}],
                            "headers": {
                                "x-tenant": "alpha",
                                "x-ignore": 7
                            },
                            "proxy_name": "gw-eu",
                            "team_slugs": ["ops"],
                            "request": {"custom": true},
                            "upstream_response": {"choices": []}
                        }
                    }]
                }]
            }
        });

        let section = TestingSection::from_json(&root)
            .expect("testing parse")
            .expect("testing section");

        assert_eq!(section.default_threshold, Some(0.65));
        assert_eq!(section.suites[0].assertions.len(), 1);
        assert_eq!(section.suites[0].cases[0].input.messages[0].role, "user");
        assert_eq!(section.suites[0].cases[0].input.messages[0].content, "");
        assert_eq!(
            section.suites[0].cases[0].input.headers.get("x-tenant"),
            Some(&"alpha".to_string())
        );
        assert_eq!(section.suites[0].cases[0].input.headers.len(), 1);
        assert_eq!(
            section.suites[0].cases[0].input.proxy_name.as_deref(),
            Some("gw-eu")
        );
        assert_eq!(
            section.suites[0].cases[0].input.team_slugs.as_ref(),
            Some(&vec!["ops".to_string()])
        );
        assert_eq!(section.suites[0].cases[0].expected.verdict, "allow");
        assert_eq!(section.suites[0].cases[0].expected.reason_code, "ok");
    }

    #[test]
    fn policy_testing_config_requires_case_names() {
        let root = json!({
            "testing": {
                "suites": [{
                    "name": "smoke",
                    "cases": [{
                        "input": {},
                        "expected": {}
                    }]
                }]
            }
        });

        let error = TestingSection::from_json(&root).expect_err("missing case name");
        assert!(error.to_string().contains("each case must have a 'name'"));
    }

    #[test]
    fn policy_testing_config_defaults_expected_fields_when_absent() {
        let expected = TestCaseExpected::from_json(&json!({}));
        assert_eq!(expected.verdict, "allow");
        assert_eq!(expected.reason_code, "ok");
    }
}
