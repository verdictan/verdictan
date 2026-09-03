// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::CliError;
use crate::gateway::{
    declarative_config::LoadedDeclarativeConfig,
    enforcement::{self, PolicyResult, Verdict},
};

#[derive(Debug, Deserialize)]
pub(crate) struct GoldenTest {
    pub name: String,
    pub(crate) input: GoldenInput,
    pub(crate) expected: GoldenExpected,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GoldenInput {
    pub(crate) messages: Vec<ChatMessage>,
    #[serde(default)]
    pub(crate) headers: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) request: Option<Value>,
    #[serde(default)]
    pub(crate) upstream_response: Option<Value>,
    /// Optional proxy name for targeting-aware test evaluation.
    #[serde(default)]
    pub(crate) proxy_name: Option<String>,
    /// Optional team slugs for targeting-aware test evaluation.
    #[serde(default)]
    pub(crate) team_slugs: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ChatMessage {
    #[allow(dead_code)]
    pub(crate) role: String,
    pub(crate) content: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GoldenExpected {
    pub verdict: String,
    pub reason_code: String,
}

#[derive(Debug, Serialize)]
pub struct TestRunOutput {
    pub ok: bool,
    pub results: Vec<TestCaseResult>,
}

#[derive(Debug, Serialize)]
pub struct TestCaseResult {
    pub name: String,
    pub verdict: String,
    pub reason_code: String,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

pub async fn run_pack_tests(pack_dir: &Path) -> Result<TestRunOutput, CliError> {
    let tests_dir = pack_dir.join("tests");
    let config = LoadedDeclarativeConfig::from_path(&pack_dir.join("policy-config.yaml"))?;
    let has_inline_testing = config
        .testing
        .as_ref()
        .is_some_and(|testing| !testing.suites.is_empty());

    if !tests_dir.exists() && !has_inline_testing {
        return Err(CliError::user(
            "missing tests/ directory (run `verdictan init` to scaffold a pack)",
        ));
    }

    let mut files: Vec<PathBuf> = if tests_dir.exists() {
        std::fs::read_dir(&tests_dir)
            .map_err(|e| CliError::user(format!("failed to read tests directory: {e}")))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
            .collect()
    } else {
        Vec::new()
    };

    files.sort();
    let mut results = Vec::new();
    let mut seen_names: std::collections::HashSet<String> = std::collections::HashSet::new();

    // --- Golden JSON tests from tests/*.json ---
    for path in files {
        let bytes = std::fs::read(&path)
            .map_err(|e| CliError::user(format!("failed to read {}: {e}", path.display())))?;

        let test: GoldenTest = serde_json::from_slice(&bytes)
            .map_err(|e| CliError::user(format!("invalid test JSON {}: {e}", path.display())))?;

        seen_names.insert(test.name.clone());
        let evaluation = evaluate_test_case(&config, &test).await?;
        let verdict = evaluation.final_verdict.to_string();
        let reason_code = evaluation.reason_code.clone();
        let passed = verdict == test.expected.verdict && reason_code == test.expected.reason_code;
        results.push(TestCaseResult {
            name: test.name,
            verdict,
            reason_code,
            passed,
            details: Some(json!({
                "policy_results": evaluation.results,
                "quality_scores": evaluation.quality_scores,
            })),
        });
    }

    // --- Inline testing section suites from policy-config.yaml ---
    if let Some(testing) = &config.testing {
        for suite in &testing.suites {
            for case in &suite.cases {
                // Deduplicate by name: JSON golden tests take precedence.
                let qualified_name = format!("{}/{}", suite.name, case.name);
                if seen_names.contains(&qualified_name) || seen_names.contains(&case.name) {
                    continue;
                }
                seen_names.insert(qualified_name.clone());

                let result =
                    evaluate_testing_case(&config, suite, case, testing.default_threshold).await?;
                results.push(result);
            }
        }
    }

    let ok = results.iter().all(|r| r.passed);

    Ok(TestRunOutput { ok, results })
}

struct TestEvaluation {
    final_verdict: Verdict,
    reason_code: String,
    results: Vec<PolicyResult>,
    quality_scores: Option<Value>,
}

fn public_quality_scores_map(
    quality_scores_map: &std::collections::BTreeMap<String, f64>,
) -> std::collections::BTreeMap<String, f64> {
    quality_scores_map
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                crate::gateway::quality::scale_public_quality_percent(*value),
            )
        })
        .collect()
}

async fn evaluate_test_case(
    config: &LoadedDeclarativeConfig,
    test: &GoldenTest,
) -> Result<TestEvaluation, CliError> {
    let messages = test
        .input
        .messages
        .iter()
        .map(|message| enforcement::ChatMessage {
            role: message.role.clone(),
            content: message.content.clone(),
        })
        .collect::<Vec<_>>();

    let request_json = build_request_json(&test.input, &messages);
    let headers = build_headers(&test.input.headers)?;

    // When proxy_name or team_slugs are provided, filter chain entries by
    // targeting before evaluation — mirrors server.rs effective_chain_for_request.
    let effective_entries: Vec<enforcement::ChainEntry> =
        if test.input.proxy_name.is_some() || test.input.team_slugs.is_some() {
            let proxy_name = test.input.proxy_name.as_deref();
            let team_slugs: Vec<String> = test.input.team_slugs.clone().unwrap_or_default();
            config
                .chain_entries
                .iter()
                .filter(|entry| entry.is_applicable_for(proxy_name, &team_slugs))
                .cloned()
                .collect()
        } else {
            config.chain_entries.clone()
        };

    let mut decision = enforcement::evaluate_chain_entries(
        &effective_entries,
        "",
        &config.policy_blocks,
        Some(&request_json),
        &headers,
        &messages,
    )
    .await;
    let mut quality_scores = None;

    if decision.final_verdict != Verdict::Block && decision.final_verdict != Verdict::Escalate {
        for kind in effective_entries
            .iter()
            .map(|e| e.kind().to_string())
            .collect::<Vec<_>>()
            .iter()
        {
            match kind.as_str() {
                "quality-scorer" => {
                    let Some(quality_cfg) = config.policy_blocks.get("quality-scorer") else {
                        continue;
                    };
                    let Some(upstream_response) = &test.input.upstream_response else {
                        continue;
                    };

                    let upstream_bytes =
                        serde_json::to_vec(upstream_response).map_err(|error| {
                            CliError::user(format!(
                                "failed to serialize upstream_response for {}: {error}",
                                test.name
                            ))
                        })?;

                    let quality_eval = crate::gateway::quality::evaluate_quality_scorer(
                        &request_json,
                        &upstream_bytes,
                        quality_cfg,
                    )
                    .await
                    .map_err(|error| {
                        CliError::user(format!(
                            "quality-scorer evaluation failed for {}: {error}",
                            test.name
                        ))
                    })?;

                    quality_scores = Some(quality_eval.scores.clone());
                    let failure_action = quality_cfg
                        .get("failure_action")
                        .and_then(|value| value.get("action"))
                        .and_then(|value| value.as_str())
                        .unwrap_or("block");

                    if quality_eval.block && failure_action == "fallback" {
                        let mut policy_result = quality_eval.policy_result;
                        policy_result.verdict = Verdict::Allow;
                        policy_result.reason_code = "quality.fallback".to_string();
                        policy_result.details = Some(json!({
                            "action": "fallback",
                            "original_failure_reason": quality_eval.reason_code,
                            "scores": quality_scores,
                        }));
                        decision.results.push(policy_result);
                    } else {
                        decision.results.push(quality_eval.policy_result);
                        if quality_eval.block {
                            decision.final_verdict = Verdict::Block;
                            decision.reason_code = quality_eval.reason_code;
                        }
                    }
                }
                "human-oversight" => {
                    let Some(oversight_cfg) = config.policy_blocks.get("human-oversight") else {
                        continue;
                    };
                    if oversight_cfg.get("action").and_then(|value| value.as_str())
                        == Some("escalate")
                    {
                        decision.final_verdict = Verdict::Escalate;
                        decision.reason_code = "oversight.required".to_string();
                        decision.results.push(PolicyResult {
                            policy_kind: "human-oversight".to_string(),
                            phase: "output".to_string(),
                            verdict: Verdict::Escalate,
                            reason_code: "oversight.required".to_string(),
                            details: None,
                            redaction_targets: None,
                        });
                    }
                }
                _ => {}
            }

            if decision.final_verdict == Verdict::Block
                || decision.final_verdict == Verdict::Escalate
            {
                break;
            }
        }
    }

    Ok(TestEvaluation {
        final_verdict: decision.final_verdict,
        reason_code: decision.reason_code,
        results: decision.results,
        quality_scores,
    })
}

/// Evaluate a single `TestCase` from the inline `testing` section.
///
/// Mirrors the flow of `evaluate_test_case` but operates on the inline
/// `testing_config::TestCase` struct and evaluates the case's assertion list
/// via the `assertions` orchestrator.
async fn evaluate_testing_case(
    config: &LoadedDeclarativeConfig,
    suite: &crate::policy::testing_config::TestSuite,
    case: &crate::policy::testing_config::TestCase,
    default_threshold: Option<f64>,
) -> Result<TestCaseResult, CliError> {
    use crate::policy::assertions::{
        evaluate_assertions, parse_assertion_packs, resolve_assertions, AssertionContext,
    };

    let qualified_name = format!("{}/{}", suite.name, case.name);

    let messages: Vec<enforcement::ChatMessage> = case
        .input
        .messages
        .iter()
        .map(|m| enforcement::ChatMessage {
            role: m.role.clone(),
            content: m.content.clone(),
        })
        .collect();

    let mut request_json = case.input.request.clone().unwrap_or_else(|| json!({}));
    if !request_json.is_object() {
        request_json = json!({});
    }
    if request_json.get("messages").is_none() {
        request_json["messages"] = Value::Array(
            messages
                .iter()
                .map(|m| json!({"role": m.role, "content": m.content}))
                .collect(),
        );
    }

    let headers = build_headers(&case.input.headers)?;

    // When proxy_name or team_slugs are provided, filter chain entries by
    // targeting before evaluation.
    let effective_entries: Vec<enforcement::ChainEntry> =
        if case.input.proxy_name.is_some() || case.input.team_slugs.is_some() {
            let proxy_name = case.input.proxy_name.as_deref();
            let team_slugs: Vec<String> = case.input.team_slugs.clone().unwrap_or_default();
            config
                .chain_entries
                .iter()
                .filter(|entry| entry.is_applicable_for(proxy_name, &team_slugs))
                .cloned()
                .collect()
        } else {
            config.chain_entries.clone()
        };

    let mut decision = enforcement::evaluate_chain_entries(
        &effective_entries,
        "",
        &config.policy_blocks,
        Some(&request_json),
        &headers,
        &messages,
    )
    .await;

    let raw_assertions = if !case.assertions.is_empty() {
        &case.assertions
    } else {
        &suite.assertions
    };

    let mut assertion_results = Vec::new();
    let mut quality_scores_map = std::collections::BTreeMap::<String, f64>::new();

    if let Some(upstream_response) = &case.input.upstream_response {
        let assertion_json_with_defaults: Vec<Value> = raw_assertions
            .iter()
            .map(|a| {
                if let Some(threshold) = default_threshold.filter(|_| a.get("threshold").is_none())
                {
                    let mut patched = a.clone();
                    if let Some(obj) = patched.as_object_mut() {
                        obj.insert("threshold".to_string(), serde_json::json!(threshold));
                    }
                    patched
                } else {
                    a.clone()
                }
            })
            .collect();

        let synthetic_cfg = serde_json::json!({ "assertions": assertion_json_with_defaults });
        let packs = parse_assertion_packs(&synthetic_cfg);
        let resolved_specs = resolve_assertions(&synthetic_cfg, &packs);

        let output_text = upstream_response
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|choice| choice.get("message"))
            .and_then(|msg| msg.get("content"))
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string();

        let query_text: String = messages
            .iter()
            .rfind(|m| m.role == "user")
            .map(|m| m.content.clone())
            .unwrap_or_default();

        let context_text = request_json
            .get("verdictan")
            .and_then(|x| x.get("context_documents"))
            .and_then(|d| d.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|doc| doc.get("content").and_then(|c| c.as_str()))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();

        let ctx = AssertionContext {
            output_text: &output_text,
            query_text: &query_text,
            context_text: &context_text,
            request_json: &request_json,
            upstream_json: upstream_response,
            quality_scores: &quality_scores_map,
            provider_registry: config.provider_registry.as_ref(),
        };

        assertion_results = evaluate_assertions(&resolved_specs, &ctx).await;

        for result in &assertion_results {
            if let Some(score) = result.score {
                let key = result
                    .name
                    .as_deref()
                    .unwrap_or(&result.assertion_type)
                    .to_string();
                quality_scores_map.insert(key, score);
            }
        }

        let has_blocking_failure = assertion_results.iter().any(|r| r.is_blocking_failure());
        if has_blocking_failure
            && decision.final_verdict != enforcement::Verdict::Block
            && decision.final_verdict != enforcement::Verdict::Escalate
        {
            let codes: Vec<String> = assertion_results
                .iter()
                .filter(|r| r.is_blocking_failure())
                .map(|r| r.reason_code.clone())
                .collect();
            decision.final_verdict = enforcement::Verdict::Block;
            decision.reason_code = codes.join(",");
        }
    }

    let verdict = decision.final_verdict.to_string();
    let reason_code = decision.reason_code.clone();
    let passed = verdict == case.expected.verdict && reason_code == case.expected.reason_code;

    let assertion_details: Vec<Value> = assertion_results
        .iter()
        .filter(|r| r.is_visible())
        .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
        .collect();

    Ok(TestCaseResult {
        name: qualified_name,
        verdict,
        reason_code,
        passed,
        details: Some(json!({
            "policy_results": decision.results,
            "quality_scores": public_quality_scores_map(&quality_scores_map),
            "assertion_results": assertion_details,
            "source": "testing_section",
        })),
    })
}

fn build_request_json(input: &GoldenInput, messages: &[enforcement::ChatMessage]) -> Value {
    let mut request_json = input.request.clone().unwrap_or_else(|| json!({}));
    if !request_json.is_object() {
        request_json = json!({});
    }

    if request_json.get("messages").is_none() {
        request_json["messages"] = Value::Array(
            messages
                .iter()
                .map(|message| {
                    json!({
                        "role": message.role,
                        "content": message.content,
                    })
                })
                .collect(),
        );
    }

    request_json
}

fn build_headers(
    raw_headers: &std::collections::BTreeMap<String, String>,
) -> Result<axum::http::HeaderMap, CliError> {
    let mut headers = axum::http::HeaderMap::new();
    for (name, value) in raw_headers {
        let header_name = axum::http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| CliError::user(format!("invalid header name {name}: {error}")))?;
        let header_value = axum::http::HeaderValue::from_str(value)
            .map_err(|error| CliError::user(format!("invalid header value for {name}: {error}")))?;
        headers.insert(header_name, header_value);
    }
    Ok(headers)
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

    fn pack_yaml(extra: &str) -> String {
        format!("pack:\n  name: test-pack\n  version: 0.1.0\npolicies:\n  chain: []\n{extra}")
    }

    #[test]
    fn policy_test_runner_build_request_json_inserts_messages_and_resets_non_objects() {
        let messages = vec![enforcement::ChatMessage {
            role: "user".to_string(),
            content: "hello".to_string(),
        }];

        let inserted = build_request_json(
            &GoldenInput {
                messages: vec![ChatMessage {
                    role: "user".to_string(),
                    content: "hello".to_string(),
                }],
                headers: std::collections::BTreeMap::new(),
                request: None,
                upstream_response: None,
                proxy_name: None,
                team_slugs: None,
            },
            &messages,
        );
        assert_eq!(inserted["messages"][0]["content"], json!("hello"));

        let reset = build_request_json(
            &GoldenInput {
                messages: Vec::new(),
                headers: std::collections::BTreeMap::new(),
                request: Some(json!("not-an-object")),
                upstream_response: None,
                proxy_name: None,
                team_slugs: None,
            },
            &messages,
        );
        assert_eq!(reset["messages"][0]["role"], json!("user"));

        let preserved = build_request_json(
            &GoldenInput {
                messages: Vec::new(),
                headers: std::collections::BTreeMap::new(),
                request: Some(json!({"messages": [{"role": "assistant", "content": "kept"}]})),
                upstream_response: None,
                proxy_name: None,
                team_slugs: None,
            },
            &messages,
        );
        assert_eq!(preserved["messages"][0]["content"], json!("kept"));
    }

    #[test]
    fn policy_test_runner_build_headers_rejects_invalid_names_and_values() {
        let invalid_name =
            std::collections::BTreeMap::from([("bad header".to_string(), "value".to_string())]);
        assert!(build_headers(&invalid_name)
            .expect_err("invalid header name")
            .to_string()
            .contains("invalid header name"));

        let invalid_value =
            std::collections::BTreeMap::from([("x-test".to_string(), "line1\nline2".to_string())]);
        assert!(build_headers(&invalid_value)
            .expect_err("invalid header value")
            .to_string()
            .contains("invalid header value"));
    }

    #[tokio::test]
    async fn policy_test_runner_build_headers_accepts_valid_names_and_values() {
        let raw_headers = std::collections::BTreeMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            ("x-trace-id".to_string(), "trace-123".to_string()),
        ]);

        let headers = build_headers(&raw_headers).expect("valid headers");

        assert_eq!(
            headers
                .get("content-type")
                .expect("content-type header")
                .to_str()
                .expect("content-type text"),
            "application/json"
        );
        assert_eq!(
            headers
                .get("x-trace-id")
                .expect("x-trace-id header")
                .to_str()
                .expect("trace header text"),
            "trace-123"
        );
    }

    #[tokio::test]
    async fn policy_test_runner_run_pack_tests_requires_tests_directory() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(temp_dir.path().join("policy-config.yaml"), pack_yaml(""))
            .expect("write config");

        let error = run_pack_tests(temp_dir.path())
            .await
            .expect_err("missing tests dir");
        assert!(error.to_string().contains("missing tests/ directory"));
    }

    #[tokio::test]
    async fn policy_test_runner_run_pack_tests_allows_inline_testing_without_tests_directory() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            temp_dir.path().join("policy-config.yaml"),
            pack_yaml(
                "testing:\n  suites:\n    - name: smoke\n      cases:\n        - name: inline-only\n          input:\n            messages:\n              - role: user\n                content: hello\n          expected:\n            verdict: allow\n            reason_code: ok\n",
            ),
        )
        .expect("write config");

        let output = run_pack_tests(temp_dir.path())
            .await
            .expect("run inline-only pack tests");

        assert!(output.ok);
        assert_eq!(output.results.len(), 1);
        assert_eq!(output.results[0].name, "smoke/inline-only");
    }

    #[tokio::test]
    async fn policy_test_runner_run_pack_tests_prefers_json_golden_over_inline_duplicate() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(temp_dir.path().join("tests")).expect("create tests dir");
        std::fs::write(
            temp_dir.path().join("policy-config.yaml"),
            pack_yaml(
                "testing:\n  suites:\n    - name: smoke\n      cases:\n        - name: duplicate\n          input:\n            messages:\n              - role: user\n                content: hello\n          expected:\n            verdict: allow\n            reason_code: ok\n",
            ),
        )
        .expect("write config");
        std::fs::write(
            temp_dir.path().join("tests/duplicate.json"),
            serde_json::to_vec_pretty(&json!({
                "name": "smoke/duplicate",
                "input": {
                    "messages": [{"role": "user", "content": "golden"}]
                },
                "expected": {
                    "verdict": "allow",
                    "reason_code": "ok"
                }
            }))
            .expect("serialize golden"),
        )
        .expect("write golden");

        let output = run_pack_tests(temp_dir.path())
            .await
            .expect("run pack tests");
        assert!(output.ok);
        assert_eq!(output.results.len(), 1);
        assert_eq!(output.results[0].name, "smoke/duplicate");
    }

    #[tokio::test]
    async fn policy_test_runner_run_pack_tests_skips_inline_duplicate_for_bare_json_name() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(temp_dir.path().join("tests")).expect("create tests dir");
        std::fs::write(
            temp_dir.path().join("policy-config.yaml"),
            pack_yaml(
                "testing:\n  suites:\n    - name: smoke\n      cases:\n        - name: duplicate\n          input:\n            messages:\n              - role: user\n                content: hello\n          expected:\n            verdict: allow\n            reason_code: ok\n",
            ),
        )
        .expect("write config");
        std::fs::write(
            temp_dir.path().join("tests/duplicate.json"),
            serde_json::to_vec_pretty(&json!({
                "name": "duplicate",
                "input": {
                    "messages": [{"role": "user", "content": "golden"}]
                },
                "expected": {
                    "verdict": "allow",
                    "reason_code": "ok"
                }
            }))
            .expect("serialize golden"),
        )
        .expect("write golden");

        let output = run_pack_tests(temp_dir.path())
            .await
            .expect("run pack tests");
        assert!(output.ok);
        assert_eq!(output.results.len(), 1);
        assert_eq!(output.results[0].name, "duplicate");
    }

    #[tokio::test]
    async fn policy_test_runner_run_pack_tests_rejects_invalid_json_fixture() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(temp_dir.path().join("tests")).expect("create tests dir");
        std::fs::write(temp_dir.path().join("policy-config.yaml"), pack_yaml(""))
            .expect("write config");
        std::fs::write(temp_dir.path().join("tests/bad.json"), "{not valid json")
            .expect("write bad test");

        let error = run_pack_tests(temp_dir.path())
            .await
            .expect_err("invalid json should fail");
        assert!(error.to_string().contains("invalid test JSON"));
        assert!(error.to_string().contains("bad.json"));
    }

    #[tokio::test]
    async fn policy_test_runner_run_pack_tests_runs_inline_suite_and_ignores_non_json_files() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(temp_dir.path().join("tests")).expect("create tests dir");
        std::fs::write(
            temp_dir.path().join("policy-config.yaml"),
            pack_yaml(
                "testing:\n  suites:\n    - name: smoke\n      cases:\n        - name: inline-only\n          input:\n            messages:\n              - role: user\n                content: hello\n          expected:\n            verdict: allow\n            reason_code: ok\n",
            ),
        )
        .expect("write config");
        std::fs::write(temp_dir.path().join("tests/notes.txt"), "ignore me")
            .expect("write ignored file");

        let output = run_pack_tests(temp_dir.path())
            .await
            .expect("run inline suite");

        assert!(output.ok);
        assert_eq!(output.results.len(), 1);
        assert_eq!(output.results[0].name, "smoke/inline-only");
        assert_eq!(
            output.results[0]
                .details
                .as_ref()
                .and_then(|details| details.get("source")),
            Some(&json!("testing_section"))
        );
    }

    fn write_inline_pack(dir: &std::path::Path, yaml: &str) {
        std::fs::create_dir(dir.join("tests")).expect("create tests dir");
        std::fs::write(dir.join("policy-config.yaml"), yaml).expect("write config");
    }

    #[tokio::test]
    async fn policy_test_executes_inline_testing_section_assertions() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_inline_pack(
            dir.path(),
            r#"pack:
  name: testing-e2e
  version: "0.1.0"
  enabled: true

policies:
  chain: []

testing:
  default_threshold: 0.3
  suites:
    - name: inline-assertions
      description: validates inline testing section assertions
      cases:
        - name: disclaimer-and-quality
          input:
            messages:
              - role: user
                content: What is the policy?
            request:
              model: gpt-5.4-mini
              messages:
                - role: user
                  content: What is the policy?
              verdictan:
                context_documents:
                  - content: The policy requires a disclaimer and cites the source material.
            upstream_response:
              choices:
                - message:
                    content: "Disclaimer: The policy requires a disclaimer and cites the source material."
          expected:
            verdict: allow
            reason_code: ok
          assertions:
            - type: contains
              value: Disclaimer
            - type: moderation
            - type: context-faithfulness
            - type: g-eval
              threshold: 0.2
              config:
                criteria: disclaimer and source fidelity
            - type: rouge
              config:
                reference: The policy requires a disclaimer and cites the source material.
"#,
        );

        let output = run_pack_tests(dir.path()).await.expect("run pack tests");
        assert!(output.ok);
        let details = output.results[0].details.as_ref().expect("details");
        assert_eq!(details["source"], "testing_section");

        let assertion_results = details["assertion_results"]
            .as_array()
            .expect("assertion results array");
        let assertion_types = assertion_results
            .iter()
            .filter_map(|item| item.get("assertion_type").and_then(|value| value.as_str()))
            .collect::<Vec<_>>();

        assert!(assertion_types.contains(&"contains"));
        assert!(assertion_types.contains(&"moderation"));
        assert!(assertion_types.contains(&"context-faithfulness"));
        assert!(assertion_types.contains(&"g-eval"));
        assert!(assertion_types.contains(&"rouge"));
    }

    #[tokio::test]
    async fn policy_test_supports_conversation_refusal_and_trajectory_assertions() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_inline_pack(
            dir.path(),
            r#"pack:
  name: advanced-assertions
  version: "0.1.0"
  enabled: true

policies:
  chain: []

testing:
  suites:
    - name: advanced
      cases:
        - name: conversation-and-trajectory
          input:
            messages:
              - role: user
                content: How do I process a refund?
              - role: assistant
                content: I can help with that.
              - role: user
                content: Summarize the refund workflow.
            request:
              verdictan:
                trajectory:
                  - type: tool
                    tool: lookup_order
                    result: Order found
                  - type: tool
                    tool: issue_refund
                    result: Refund complete
            upstream_response:
              choices:
                - finish_reason: content_filter
                  message:
                    content: I'm sorry, but I can't assist with executing that refund workflow directly.
          expected:
            verdict: allow
            reason_code: ok
          assertions:
            - type: conversation-relevance
              threshold: 0.1
            - type: is-refusal
            - type: trajectory:tool-used
              config:
                tools: [lookup_order]
            - type: trajectory:tool-sequence
              config:
                tools: [lookup_order, issue_refund]
            - type: trajectory:step-count
              config:
                min: 2
                max: 3
"#,
        );

        let output = run_pack_tests(dir.path()).await.expect("run pack tests");
        assert!(output.ok);

        let assertion_results = output.results[0]
            .details
            .as_ref()
            .and_then(|details| details.get("assertion_results"))
            .and_then(|value| value.as_array())
            .expect("assertions array");
        let assertion_types = assertion_results
            .iter()
            .filter_map(|item| item.get("assertion_type").and_then(|value| value.as_str()))
            .collect::<Vec<_>>();
        assert!(assertion_types.contains(&"conversation-relevance"));
        assert!(assertion_types.contains(&"is-refusal"));
        assert!(assertion_types.contains(&"trajectory:tool-used"));
        assert!(assertion_types.contains(&"trajectory:tool-sequence"));
        assert!(assertion_types.contains(&"trajectory:step-count"));
    }

    #[tokio::test]
    async fn policy_test_inherits_suite_assertions_applies_default_threshold_and_hides_shadow_results(
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        write_inline_pack(
            dir.path(),
            r#"pack:
  name: inherited-assertions
  version: "0.1.0"
  enabled: true

policies:
  chain: []

testing:
  default_threshold: 1.0
  suites:
    - name: inherited
      assertions:
        - name: visible_disclaimer
          type: contains
          value: Disclaimer
        - name: audit_missing
          type: contains
          value: forbidden
          mode: audit
        - name: shadow_missing
          type: contains
          value: hidden
          mode: shadow
        - name: disabled_missing
          type: contains
          value: disabled
          enabled: false
      cases:
        - name: suite-defaults
          input:
            messages:
              - role: user
                content: Summarize the policy.
            upstream_response:
              choices:
                - message:
                    content: "Disclaimer: follow the policy."
          expected:
            verdict: allow
            reason_code: ok
"#,
        );

        let output = run_pack_tests(dir.path()).await.expect("run pack tests");
        let details = output.results[0].details.as_ref().expect("details");
        assert_eq!(details["source"], "testing_section");

        let assertion_results = details["assertion_results"]
            .as_array()
            .expect("assertion results array");
        assert_eq!(assertion_results.len(), 2);

        let assertion_names = assertion_results
            .iter()
            .filter_map(|item| item.get("name").and_then(|value| value.as_str()))
            .collect::<Vec<_>>();
        assert!(assertion_names.contains(&"visible_disclaimer"));
        assert!(assertion_names.contains(&"audit_missing"));
        assert!(!assertion_names.contains(&"shadow_missing"));
        assert!(!assertion_names.contains(&"disabled_missing"));

        let visible = assertion_results
            .iter()
            .find(|item| item["name"] == "visible_disclaimer")
            .expect("visible assertion");
        assert_eq!(visible["threshold"], json!(1.0));
        assert_eq!(visible["passed"], true);

        let audit = assertion_results
            .iter()
            .find(|item| item["name"] == "audit_missing")
            .expect("audit assertion");
        assert_eq!(audit["threshold"], json!(1.0));
        assert_eq!(audit["mode"], "audit");
        assert_eq!(audit["passed"], false);
    }

    #[tokio::test]
    async fn policy_test_skips_inline_assertions_without_upstream_response() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_inline_pack(
            dir.path(),
            r#"pack:
  name: missing-upstream
  version: "0.1.0"
  enabled: true

policies:
  chain: []

testing:
  suites:
    - name: no-upstream
      cases:
        - name: skipped-assertions
          input:
            messages:
              - role: user
                content: Summarize the policy.
          expected:
            verdict: allow
            reason_code: ok
          assertions:
            - type: contains
              value: Disclaimer
"#,
        );

        let output = run_pack_tests(dir.path()).await.expect("run pack tests");
        assert!(output.ok);
        assert_eq!(
            output.results[0]
                .details
                .as_ref()
                .and_then(|d| d.get("assertion_results")),
            Some(&json!([]))
        );
        assert_eq!(
            output.results[0]
                .details
                .as_ref()
                .and_then(|d| d.get("quality_scores")),
            Some(&json!({}))
        );
    }
}
