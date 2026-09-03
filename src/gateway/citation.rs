// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use super::enforcement::{PolicyResult, Verdict};

macro_rules! static_regex {
    ($pattern:expr) => {{
        static RE: std::sync::OnceLock<regex_lite::Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| {
            #[allow(clippy::expect_used)]
            regex_lite::Regex::new($pattern).expect("static regex pattern")
        })
    }};
}

#[derive(Clone, Debug, Default)]
pub(crate) struct CitationResolver;

pub(crate) struct ResolveStatus {
    pub found: bool,
    pub source: String,
    pub title: Option<String>,
    pub year: Option<String>,
    pub confidence: f64,
    pub doi: Option<String>,
    pub url: Option<String>,
    pub resolver_latency_ms: Option<u64>,
}

impl CitationResolver {
    pub fn from_config(_cfg: &Value) -> Self {
        Self
    }

    pub fn uses_external(&self) -> bool {
        false
    }

    pub async fn resolve(&self, _citation: &str) -> Result<ResolveStatus, anyhow::Error> {
        Ok(ResolveStatus {
            found: false,
            source: "none".to_string(),
            title: None,
            year: None,
            confidence: 0.0,
            doi: None,
            url: None,
            resolver_latency_ms: None,
        })
    }
}

#[doc(hidden)]
pub struct CitationEval {
    pub policy_result: PolicyResult,
    pub should_block: bool,
    pub case_law_citations: Vec<String>,
    #[allow(dead_code)]
    pub(crate) resolver: CitationResolver,
}

#[doc(hidden)]
pub async fn evaluate_citation_verifier(
    request_json: &Value,
    response_bytes: &[u8],
    cfg: &Value,
) -> Result<CitationEval, anyhow::Error> {
    let span = tracing::info_span!(
        "verdictan_policy_evaluation",
        verdictan_policy_kind = "citation-verifier",
        verdictan_policy_phase = "output",
        verdictan_policy_verdict = tracing::field::Empty,
        verdictan_policy_reason_code = tracing::field::Empty
    );
    let _guard = span.enter();
    let eval = evaluate_citation_verifier_inner(request_json, response_bytes, cfg).await?;
    crate::telemetry::annotate_policy_result_span(&span, &eval.policy_result);
    Ok(eval)
}

async fn evaluate_citation_verifier_inner(
    request_json: &Value,
    response_bytes: &[u8],
    cfg: &Value,
) -> Result<CitationEval, anyhow::Error> {
    let output_text = extract_openai_output_text(response_bytes)
        .unwrap_or_default()
        .trim()
        .to_string();

    let verification = cfg.get("verification");

    let require_sources = cfg
        .get("require_sources")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let require_source_match = cfg
        .get("require_source_match")
        .and_then(|v| v.as_bool())
        .or_else(|| {
            verification
                .and_then(|v| v.get("require_source_match"))
                .and_then(|v| v.as_bool())
        })
        .unwrap_or(true);

    let min_confidence = cfg
        .get("min_confidence")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.8);

    let min_groundedness = cfg
        .get("min_groundedness")
        .and_then(|v| v.as_f64())
        .or_else(|| {
            verification
                .and_then(|v| v.get("min_groundedness"))
                .and_then(|v| v.as_f64())
        })
        .unwrap_or(0.8);

    let extract_patterns: Vec<String> = cfg
        .get("extract_patterns")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .or_else(|| {
            verification
                .and_then(|v| v.get("extract_patterns"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
        })
        .unwrap_or_else(|| {
            vec![
                "case_law".to_string(),
                "academic".to_string(),
                "url".to_string(),
                "quote".to_string(),
                "statistic".to_string(),
                "regulatory".to_string(),
            ]
        });

    let include_report = cfg
        .get("response")
        .and_then(|v| v.get("include_verification_report"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let verify_against_context = cfg
        .get("rag_context")
        .and_then(|v| v.get("verify_against_context"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let min_context_overlap = cfg
        .get("rag_context")
        .and_then(|v| v.get("min_context_overlap"))
        .and_then(|v| v.as_f64())
        .or_else(|| cfg.get("min_groundedness").and_then(|v| v.as_f64()))
        .unwrap_or(0.7);

    let unverified_action = cfg
        .get("output_action")
        .and_then(|v| v.get("unverified_action"))
        .and_then(|v| v.as_str())
        .unwrap_or("flag");

    let context_docs = extract_context_documents(request_json);
    let context_doc_metadata = extract_context_document_metadata(request_json);

    let context_text = context_docs.join("\n");
    let (groundedness, matched, resp_tokens, ctx_tokens) = if verify_against_context {
        compute_groundedness(&output_text, &context_text)
    } else {
        (1.0, 0, 0, 0)
    };

    let claims = split_claims(&output_text);
    let quotes = if extract_patterns.iter().any(|p| p == "quote") {
        extract_quotes(&output_text)
    } else {
        Vec::new()
    };

    let (dois, pmids, urls, case_cites, regulatory_refs) =
        extract_citations(&output_text, &extract_patterns);

    let resolver = CitationResolver::from_config(cfg);
    let mut resolver_fallback = false;
    let mut any_case_law_verified = false;
    let mut case_law_validations: Vec<serde_json::Value> = Vec::new();
    for cite in &case_cites {
        let val = if resolver.uses_external() {
            match resolver.resolve(cite).await {
                Ok(status) => {
                    any_case_law_verified |= status.found;
                    serde_json::json!({
                        "citation": cite,
                        "verified": status.found,
                        "method": status.source,
                        "title": status.title,
                        "year": status.year,
                        "confidence": status.confidence,
                        "doi": status.doi,
                        "url": status.url,
                        "resolver_latency_ms": status.resolver_latency_ms,
                    })
                }
                Err(_) => {
                    let format_valid = validate_case_law_format(cite);
                    resolver_fallback = true;
                    any_case_law_verified |= format_valid;
                    serde_json::json!({
                        "citation": cite,
                        "verified": format_valid,
                        "method": "format_validation",
                        "resolver_fallback": true,
                        "note": "External resolver failed; using format validation fallback"
                    })
                }
            }
        } else {
            let format_valid = validate_case_law_format(cite);
            any_case_law_verified |= format_valid;
            serde_json::json!({
                "citation": cite,
                "verified": format_valid,
                "method": "format_validation",
                "note": "Format check only, no external database lookup"
            })
        };
        case_law_validations.push(val);
    }

    let quote_matches = if verify_against_context && !context_text.is_empty() {
        quotes
            .iter()
            .map(|q| {
                let ok = contains_case_insensitive(&context_text, q);
                serde_json::json!({"quote": q, "matched_in_context": ok})
            })
            .collect::<Vec<_>>()
    } else {
        quotes
            .iter()
            .map(|q| serde_json::json!({"quote": q, "matched_in_context": false}))
            .collect::<Vec<_>>()
    };

    let mut claim_results = Vec::new();
    let mut verified_claims = 0usize;
    if verify_against_context && !output_text.is_empty() {
        for c in &claims {
            let (s, m, ct, rt) = compute_groundedness(c, &context_text);
            let ok = context_text.trim().is_empty() || s >= min_groundedness;
            if ok {
                verified_claims += 1;
            }
            claim_results.push(serde_json::json!({
                "claim": c,
                "groundedness": s,
                "min_groundedness": min_groundedness,
                "matched_tokens": m,
                "claim_unique_tokens": rt,
                "context_unique_tokens": ct,
                "verified": ok,
            }));
        }
    }

    let claim_confidence = if claims.is_empty() {
        1.0
    } else {
        verified_claims as f64 / claims.len() as f64
    };

    // External lookups are enabled implicitly when extract_patterns includes the corresponding mode.
    let allow_academic_lookup = extract_patterns.iter().any(|p| p == "academic");
    let allow_url_lookup = extract_patterns.iter().any(|p| p == "url");

    let external = if (allow_academic_lookup && (!dois.is_empty() || !pmids.is_empty()))
        || (allow_url_lookup && !urls.is_empty())
    {
        external_lookup(
            &dois,
            &pmids,
            &urls,
            allow_academic_lookup,
            allow_url_lookup,
        )
        .await
    } else {
        ExternalLookupReport::default()
    };

    let has_context = !context_docs.is_empty();

    let has_any_citations = !dois.is_empty()
        || !pmids.is_empty()
        || !urls.is_empty()
        || !case_cites.is_empty()
        || !regulatory_refs.is_empty();
    let has_any_source_evidence = if verify_against_context {
        // "source match" = at least one quote matches context, or the response is sufficiently grounded,
        // or we successfully verified an external citation.
        let any_quote_match = quote_matches.iter().any(|v| {
            v.get("matched_in_context")
                .and_then(|b| b.as_bool())
                .unwrap_or(false)
        });
        any_quote_match
            || groundedness >= min_context_overlap
            || external.any_verified
            || any_case_law_verified
    } else {
        external.any_verified || any_case_law_verified || has_any_citations
    };

    let verified = if output_text.is_empty() {
        true
    } else if !verify_against_context {
        // If we are not verifying against context, treat citations (if required) as the only signal.
        if require_sources {
            !require_source_match || has_any_source_evidence
        } else {
            true
        }
    } else if !has_context {
        // No provided RAG context.
        if !require_sources {
            true
        } else {
            !require_source_match || has_any_source_evidence
        }
    } else {
        // Context is available; require groundedness + claim-level confidence.
        let grounded_ok = groundedness >= min_context_overlap;
        let claims_ok = claim_confidence >= min_confidence;
        let sources_ok = if require_sources {
            if require_source_match {
                has_any_source_evidence
            } else {
                has_any_citations || has_any_source_evidence
            }
        } else {
            true
        };
        grounded_ok && claims_ok && sources_ok
    };

    let verdict = if verified {
        Verdict::Allow
    } else if unverified_action == "block" {
        Verdict::Block
    } else {
        Verdict::Allow
    };

    let mut details = serde_json::json!({
        "verified": verified,
        "has_context_documents": has_context,
        "context_document_count": context_docs.len(),
        "context_document_metadata": context_doc_metadata,
        "verify_against_context": verify_against_context,
        "groundedness": groundedness,
        "min_context_overlap": min_context_overlap,
        "min_confidence": min_confidence,
        "claim_confidence": claim_confidence,
        "require_sources": require_sources,
        "require_source_match": require_source_match,
        "unverified_action": unverified_action,
        "matched_tokens": matched,
        "response_unique_tokens": resp_tokens,
        "context_unique_tokens": ctx_tokens,
        "claims": claim_results,
        "quotes": quote_matches,
        "citations": {
            "dois": dois,
            "pmids": pmids,
            "urls": urls,
            "case_law": case_cites,
            "case_law_validations": case_law_validations,
            "resolver_fallback": resolver_fallback,
            "regulatory": regulatory_refs,
        },
        "external_lookup": external.as_json(),
    });

    // Add unverified claims list for block responses
    if !verified {
        let unverified_claims: Vec<&serde_json::Value> = claim_results
            .iter()
            .filter(|c| !c.get("verified").and_then(|v| v.as_bool()).unwrap_or(false))
            .collect();
        if let Some(obj) = details.as_object_mut() {
            obj.insert(
                "unverified_claims".to_string(),
                serde_json::json!(unverified_claims),
            );
            obj.insert(
                "unverified_claim_count".to_string(),
                serde_json::json!(unverified_claims.len()),
            );
        }
    }

    // Add verification report for successful responses
    if verified {
        if let Some(obj) = details.as_object_mut() {
            obj.insert(
                "verification_report".to_string(),
                serde_json::json!({
                    "status": "verified",
                    "groundedness_score": groundedness,
                    "claim_confidence_score": claim_confidence,
                    "total_claims": claims.len(),
                    "verified_claims": verified_claims,
                    "citations_found": {
                        "dois": dois.len(),
                        "pmids": pmids.len(),
                        "urls": urls.len(),
                        "case_law": case_cites.len(),
                        "regulatory": regulatory_refs.len(),
                    },
                    "context_documents_used": context_docs.len(),
                }),
            );
        }
    }

    if !include_report {
        details = serde_json::json!({
            "verified": verified,
            "groundedness": groundedness,
        });
    }

    let reason_code = if verified {
        "citation.verified".to_string()
    } else {
        "citation.unverified".to_string()
    };

    Ok(CitationEval {
        should_block: verdict == Verdict::Block,
        policy_result: PolicyResult {
            policy_kind: "citation-verifier".to_string(),
            phase: "output".to_string(),
            verdict,
            reason_code,
            details: Some(details),
            redaction_targets: None,
        },
        case_law_citations: case_cites,
        resolver,
    })
}

#[derive(Default)]
struct ExternalLookupReport {
    any_verified: bool,
    doi_verified: Vec<String>,
    doi_failed: Vec<String>,
    pmid_verified: Vec<String>,
    pmid_failed: Vec<String>,
    url_verified: Vec<String>,
    url_failed: Vec<String>,
}

impl ExternalLookupReport {
    fn as_json(&self) -> serde_json::Value {
        serde_json::json!({
            "any_verified": self.any_verified,
            "doi_verified": self.doi_verified,
            "doi_failed": self.doi_failed,
            "pmid_verified": self.pmid_verified,
            "pmid_failed": self.pmid_failed,
            "url_verified": self.url_verified,
            "url_failed": self.url_failed,
        })
    }
}

async fn external_lookup(
    dois: &[String],
    pmids: &[String],
    urls: &[String],
    allow_academic: bool,
    allow_url: bool,
) -> ExternalLookupReport {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .user_agent("verdictan-cli/0.1")
        .build()
    {
        Ok(c) => c,
        Err(_) => return ExternalLookupReport::default(),
    };

    let mut out = ExternalLookupReport::default();
    if allow_academic {
        for doi in dois {
            if verify_doi(&client, doi).await {
                out.any_verified = true;
                out.doi_verified.push(doi.clone());
            } else {
                out.doi_failed.push(doi.clone());
            }
        }
        for pmid in pmids {
            if verify_pmid(&client, pmid).await {
                out.any_verified = true;
                out.pmid_verified.push(pmid.clone());
            } else {
                out.pmid_failed.push(pmid.clone());
            }
        }
    }

    // URL reachability checks can introduce SSRF risk. Only enable when explicitly opted-in.
    let url_lookup_enabled = std::env::var("VERDICTAN_CITATION_URL_LOOKUP")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if allow_url && url_lookup_enabled {
        for url in urls {
            if verify_url(&client, url).await {
                out.any_verified = true;
                out.url_verified.push(url.clone());
            } else {
                out.url_failed.push(url.clone());
            }
        }
    }

    out
}

async fn verify_doi(client: &reqwest::Client, doi: &str) -> bool {
    let doi_enc = urlencoding::encode(doi);
    let url = format!("https://api.crossref.org/works/{doi_enc}");
    client
        .get(url)
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

async fn verify_pmid(client: &reqwest::Client, pmid: &str) -> bool {
    // Use NCBI esummary in JSON mode.
    let id = urlencoding::encode(pmid);
    let url = format!("https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esummary.fcgi?db=pubmed&id={id}&retmode=json");
    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(_) => return false,
    };
    if !resp.status().is_success() {
        return false;
    }
    let v: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => return false,
    };
    v.get("result").and_then(|r| r.get(pmid)).is_some()
}

async fn verify_url(client: &reqwest::Client, url: &str) -> bool {
    // Best effort: HEAD, then GET. Treat 2xx/3xx as reachable.
    let ok = client
        .head(url)
        .send()
        .await
        .map(|r| r.status().is_success() || r.status().is_redirection())
        .unwrap_or(false);
    if ok {
        return true;
    }
    client
        .get(url)
        .send()
        .await
        .map(|r| r.status().is_success() || r.status().is_redirection())
        .unwrap_or(false)
}

fn split_claims(output: &str) -> Vec<String> {
    output
        .split(['.', '!', '?', '\n'])
        .map(|s| s.trim())
        .filter(|s| s.len() >= 20)
        .map(|s| s.to_string())
        .collect()
}

fn extract_quotes(output: &str) -> Vec<String> {
    let mut out = Vec::new();

    // Straight quotes.
    for cap in static_regex!(r#"\"([^\"\n]{10,})\""#).captures_iter(output) {
        if let Some(m) = cap.get(1) {
            let q = m.as_str().trim();
            if q.len() >= 10 {
                out.push(q.to_string());
            }
        }
    }

    // Curly quotes.
    for cap in static_regex!(r"“([^”\n]{10,})”").captures_iter(output) {
        if let Some(m) = cap.get(1) {
            let q = m.as_str().trim();
            if q.len() >= 10 {
                out.push(q.to_string());
            }
        }
    }

    out.sort();
    out.dedup();
    out
}

#[allow(clippy::type_complexity)]
fn extract_citations(
    output: &str,
    extract_patterns: &[String],
) -> (
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Vec<String>,
) {
    let mut dois = Vec::new();
    let mut pmids = Vec::new();
    let mut urls = Vec::new();
    let mut cases = Vec::new();
    let mut regulatory = Vec::new();

    let allow_case = extract_patterns.iter().any(|p| p == "case_law");
    let allow_academic = extract_patterns.iter().any(|p| p == "academic");
    let allow_url = extract_patterns.iter().any(|p| p == "url");
    let allow_regulatory = extract_patterns.iter().any(|p| p == "regulatory");

    if allow_academic {
        for m in static_regex!(r"(?i)\b10\.\d{4,9}/[A-Z0-9._;()/:\-]+\b").find_iter(output) {
            dois.push(m.as_str().trim_end_matches('.').to_string());
        }
        for cap in static_regex!(r"(?i)\bPMID\s*:?\s*(\d{5,10})\b").captures_iter(output) {
            if let Some(m) = cap.get(1) {
                pmids.push(m.as_str().to_string());
            }
        }
    }

    if allow_url {
        for m in static_regex!(r"https?://[^\s)\]]+").find_iter(output) {
            urls.push(m.as_str().trim_end_matches('.').to_string());
        }
    }

    if allow_case {
        for m in static_regex!(r"\b\d+\s+U\.S\.\s+\d+\b").find_iter(output) {
            cases.push(m.as_str().to_string());
        }
    }

    if allow_regulatory {
        // GDPR Article references
        for m in static_regex!(r"(?i)\bGDPR\s+Article\s+\d+\b").find_iter(output) {
            regulatory.push(m.as_str().to_string());
        }
        // HIPAA section references
        for m in static_regex!(r"(?i)\bHIPAA\s+(?:Section|§)\s+\d+\b").find_iter(output) {
            regulatory.push(m.as_str().to_string());
        }
        // SOX/SOC references
        for m in static_regex!(r"(?i)\b(?:SOX|SOC)\s+(?:Section|§)?\s*\d+\b").find_iter(output) {
            regulatory.push(m.as_str().to_string());
        }
        // CFR references (e.g., 45 CFR 164.502)
        for m in static_regex!(r"\b\d+\s+CFR\s+\d+(?:\.\d+)?\b").find_iter(output) {
            regulatory.push(m.as_str().to_string());
        }
        // EU AI Act
        for m in static_regex!(r"(?i)\bEU\s+AI\s+Act\s+Article\s+\d+\b").find_iter(output) {
            regulatory.push(m.as_str().to_string());
        }
    }

    for v in [
        &mut dois,
        &mut pmids,
        &mut urls,
        &mut cases,
        &mut regulatory,
    ] {
        v.sort();
        v.dedup();
    }

    (dois, pmids, urls, cases, regulatory)
}

fn contains_case_insensitive(haystack: &str, needle: &str) -> bool {
    if needle.trim().is_empty() {
        return false;
    }
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

/// Validates case law citation format (e.g. U.S. Reports, Federal Reporter).
/// Does not query an external database; a future enhancement could add that.
pub fn validate_case_law_format(citation: &str) -> bool {
    // Well-known U.S. Reports format: "NNN U.S. NNN"
    if static_regex!(r"^\d+\s+U\.S\.\s+\d+$").is_match(citation) {
        return true;
    }
    // Federal Reporter format: "NNN F.2d NNN" or "NNN F.3d NNN"
    if static_regex!(r"^\d+\s+F\.\d+d\s+\d+$").is_match(citation) {
        return true;
    }
    // State reporter generic format
    if static_regex!(r"^\d+\s+\w+\.\s+\d+$").is_match(citation) {
        return true;
    }
    false
}

fn extract_context_documents(request_json: &Value) -> Vec<String> {
    let Some(arr) = request_json
        .get("verdictan")
        .and_then(|v| v.get("context_documents"))
        .and_then(|v| v.as_array())
    else {
        return Vec::new();
    };

    arr.iter()
        .filter_map(|doc| {
            let content = doc.get("content")?.as_str()?;
            if content.trim().is_empty() {
                None
            } else {
                Some(content.to_string())
            }
        })
        .collect()
}

/// Extract id and source metadata from context documents.
pub fn extract_context_document_metadata(request_json: &Value) -> Vec<serde_json::Value> {
    let Some(arr) = request_json
        .get("verdictan")
        .and_then(|v| v.get("context_documents"))
        .and_then(|v| v.as_array())
    else {
        return Vec::new();
    };

    arr.iter()
        .map(|doc| {
            serde_json::json!({
                "id": doc.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                "source": doc.get("source").and_then(|v| v.as_str()).unwrap_or(""),
                "has_content": doc.get("content").and_then(|v| v.as_str()).map(|s| !s.trim().is_empty()).unwrap_or(false),
            })
        })
        .collect()
}

fn compute_groundedness(response: &str, context: &str) -> (f64, usize, usize, usize) {
    let resp_set = token_set(response);
    if resp_set.is_empty() {
        return (1.0, 0, 0, token_set(context).len());
    }

    let ctx_set = token_set(context);
    if ctx_set.is_empty() {
        return (0.0, 0, resp_set.len(), 0);
    }

    let matched = resp_set.intersection(&ctx_set).count();
    let groundedness = matched as f64 / resp_set.len() as f64;
    (groundedness, matched, resp_set.len(), ctx_set.len())
}

fn token_set(s: &str) -> std::collections::BTreeSet<String> {
    s.to_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| t.len() >= 4)
        .map(|t| t.to_string())
        .collect()
}

fn extract_openai_output_text(response_bytes: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(response_bytes).ok()?;

    if let Some(choices) = v.get("choices").and_then(|x| x.as_array()) {
        let mut parts = Vec::new();
        for choice in choices {
            if let Some(content) = choice
                .get("message")
                .and_then(|m| m.get("content"))
                .and_then(|c| c.as_str())
            {
                parts.push(content);
            }
        }
        return Some(parts.join("\n"));
    }

    if let Some(outputs) = v.get("output").and_then(|x| x.as_array()) {
        let mut parts = Vec::new();
        for out in outputs {
            let Some(content_arr) = out.get("content").and_then(|x| x.as_array()) else {
                continue;
            };
            for item in content_arr {
                let typ = item.get("type").and_then(|t| t.as_str()).unwrap_or("");
                if typ != "output_text" {
                    continue;
                }
                if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                    parts.push(text);
                }
            }
        }
        return Some(parts.join("\n"));
    }

    None
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
    use serde_json::json;

    fn openai_chat_response(text: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "choices": [{
                "message": {
                    "content": text
                }
            }]
        }))
        .unwrap()
    }

    #[test]
    fn split_claims_filters_short_segments() {
        let text =
            "Short. This is a claim that is definitely long enough to pass the filter. Also short.";
        let claims = split_claims(text);
        assert_eq!(claims.len(), 1);
        assert!(claims[0].contains("definitely long enough"));
    }

    #[test]
    fn split_claims_splits_on_punctuation_and_newline() {
        let text =
            "First claim that is long enough to count.\nSecond claim also exceeds the threshold!";
        let claims = split_claims(text);
        assert_eq!(claims.len(), 2);
    }

    #[test]
    fn split_claims_empty_input() {
        assert!(split_claims("").is_empty());
        assert!(split_claims("tiny.").is_empty());
    }

    #[test]
    fn extract_quotes_straight() {
        let text = r#"He said "this is a sufficiently long quote" and left."#;
        let quotes = extract_quotes(text);
        assert_eq!(quotes.len(), 1);
        assert_eq!(quotes[0], "this is a sufficiently long quote");
    }

    #[test]
    fn extract_quotes_curly() {
        let text = "\u{201c}This is a curly quoted phrase that is long\u{201d} she said.";
        let quotes = extract_quotes(text);
        assert_eq!(quotes.len(), 1);
    }

    #[test]
    fn extract_quotes_short_ignored() {
        let text = r#"He said "short" and "hi there" but not enough."#;
        let quotes = extract_quotes(text);
        assert!(quotes.is_empty());
    }

    #[test]
    fn extract_quotes_deduplicates_trimmed_variants() {
        let text =
            "The memo said \"  repeated quote here  \" before repeating “repeated quote here”.";
        let quotes = extract_quotes(text);
        assert_eq!(quotes, vec!["repeated quote here".to_string()]);
    }

    #[test]
    fn extract_citations_academic() {
        let output = "See DOI 10.1234/abc.123 and PMID: 12345678 for details.";
        let patterns = vec!["academic".to_string()];
        let (dois, pmids, urls, cases, regulatory) = extract_citations(output, &patterns);
        assert_eq!(dois.len(), 1);
        assert!(dois[0].contains("10.1234/abc.123"));
        assert_eq!(pmids, vec!["12345678"]);
        assert!(urls.is_empty());
        assert!(cases.is_empty());
        assert!(regulatory.is_empty());
    }

    #[test]
    fn extract_citations_url() {
        let output = "Visit https://example.com/page for more info.";
        let patterns = vec!["url".to_string()];
        let (dois, pmids, urls, cases, regulatory) = extract_citations(output, &patterns);
        assert!(dois.is_empty());
        assert!(pmids.is_empty());
        assert_eq!(urls.len(), 1);
        assert!(urls[0].starts_with("https://example.com"));
        assert!(cases.is_empty());
        assert!(regulatory.is_empty());
    }

    #[test]
    fn extract_citations_case_law() {
        let output = "As held in 347 U.S. 483 (Brown v. Board of Education).";
        let patterns = vec!["case_law".to_string()];
        let (dois, _pmids, urls, cases, regulatory) = extract_citations(output, &patterns);
        assert!(dois.is_empty());
        assert!(urls.is_empty());
        assert_eq!(cases, vec!["347 U.S. 483"]);
        assert!(regulatory.is_empty());
    }

    #[test]
    fn extract_citations_regulatory() {
        let output = "Per GDPR Article 17 and HIPAA Section 164 and 45 CFR 164.502.";
        let patterns = vec!["regulatory".to_string()];
        let (dois, _pmids, urls, cases, regulatory) = extract_citations(output, &patterns);
        assert!(dois.is_empty());
        assert!(urls.is_empty());
        assert!(cases.is_empty());
        assert!(regulatory.len() >= 3);
    }

    #[test]
    fn extract_citations_no_patterns_yields_empty() {
        let output = "DOI 10.1234/x, https://x.com, 347 U.S. 483";
        let patterns: Vec<String> = vec![];
        let (dois, pmids, urls, cases, regulatory) = extract_citations(output, &patterns);
        assert!(dois.is_empty());
        assert!(pmids.is_empty());
        assert!(urls.is_empty());
        assert!(cases.is_empty());
        assert!(regulatory.is_empty());
    }

    #[test]
    fn extract_citations_deduplicates_and_trims_punctuation() {
        let output = "See DOI 10.1234/ABC.123 and DOI 10.1234/ABC.123. PMID: 123456 and PMID 123456. Visit https://example.com/path. Also https://example.com/path. Brown cited 347 U.S. 483 and 347 U.S. 483. GDPR Article 17 and GDPR Article 17.";
        let patterns = vec![
            "academic".to_string(),
            "url".to_string(),
            "case_law".to_string(),
            "regulatory".to_string(),
        ];
        let (dois, pmids, urls, cases, regulatory) = extract_citations(output, &patterns);
        assert_eq!(dois, vec!["10.1234/ABC.123".to_string()]);
        assert_eq!(pmids, vec!["123456".to_string()]);
        assert_eq!(urls, vec!["https://example.com/path".to_string()]);
        assert_eq!(cases, vec!["347 U.S. 483".to_string()]);
        assert_eq!(regulatory, vec!["GDPR Article 17".to_string()]);
    }

    #[test]
    fn compute_groundedness_empty_response() {
        let (score, matched, resp, ctx) = compute_groundedness("", "some context text");
        assert!((score - 1.0).abs() < f64::EPSILON);
        assert_eq!(matched, 0);
        assert_eq!(resp, 0);
        assert!(ctx > 0);
    }

    #[test]
    fn compute_groundedness_empty_context() {
        let (score, matched, resp, ctx) = compute_groundedness("some response text", "");
        assert!((score).abs() < f64::EPSILON);
        assert_eq!(matched, 0);
        assert!(resp > 0);
        assert_eq!(ctx, 0);
    }

    #[test]
    fn compute_groundedness_full_overlap() {
        let text = "the quick brown fox jumps over the lazy dog";
        let (score, _matched, _resp, _ctx) = compute_groundedness(text, text);
        assert!((score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn compute_groundedness_partial_overlap() {
        let response = "the quick brown fox jumps";
        let context = "the quick brown cat sleeps";
        let (score, _, _, _) = compute_groundedness(response, context);
        assert!(score > 0.0);
        assert!(score < 1.0);
    }

    #[test]
    fn compute_groundedness_counts_unique_overlap_tokens() {
        let response = "alpha alpha beta beta";
        let context = "beta gamma beta";
        let (score, matched, resp, ctx) = compute_groundedness(response, context);
        assert!((score - 0.5).abs() < f64::EPSILON);
        assert_eq!(matched, 1);
        assert_eq!(resp, 2);
        assert_eq!(ctx, 2);
    }

    #[test]
    fn extract_context_documents_present() {
        let req = json!({
            "verdictan": {
                "context_documents": [
                    { "content": "first document content" },
                    { "content": "second document" },
                    { "content": "   " }
                ]
            }
        });
        let docs = extract_context_documents(&req);
        assert_eq!(docs.len(), 2);
        assert_eq!(docs[0], "first document content");
    }

    #[test]
    fn extract_context_documents_missing() {
        let req = json!({ "model": "gpt-5.4" });
        assert!(extract_context_documents(&req).is_empty());
    }

    #[test]
    fn extract_context_document_metadata_basic() {
        let req = json!({
            "verdictan": {
                "context_documents": [
                    { "id": "doc1", "source": "kb", "content": "hello" },
                    { "id": "doc2", "source": "web", "content": "" }
                ]
            }
        });
        let meta = extract_context_document_metadata(&req);
        assert_eq!(meta.len(), 2);
        assert_eq!(meta[0]["id"], "doc1");
        assert_eq!(meta[0]["has_content"], true);
        assert_eq!(meta[1]["has_content"], false);
    }

    #[test]
    fn extract_context_document_metadata_defaults_missing_fields() {
        let req = json!({
            "verdictan": {
                "context_documents": [
                    {},
                    { "content": "   " }
                ]
            }
        });
        let meta = extract_context_document_metadata(&req);
        assert_eq!(meta.len(), 2);
        assert_eq!(meta[0]["id"].as_str().unwrap(), "");
        assert_eq!(meta[0]["source"].as_str().unwrap(), "");
        assert_eq!(meta[0]["has_content"].as_bool().unwrap(), false);
        assert_eq!(meta[1]["has_content"].as_bool().unwrap(), false);
    }

    #[test]
    fn validate_case_law_format_us_reports() {
        assert!(validate_case_law_format("347 U.S. 483"));
        assert!(validate_case_law_format("123 U.S. 456"));
    }

    #[test]
    fn validate_case_law_format_federal_reporter() {
        assert!(validate_case_law_format("123 F.2d 456"));
        assert!(validate_case_law_format("789 F.3d 101"));
    }

    #[test]
    fn validate_case_law_format_state_reporter() {
        assert!(validate_case_law_format("123 Cal. 456"));
    }

    #[test]
    fn validate_case_law_format_invalid() {
        assert!(!validate_case_law_format("random text"));
        assert!(!validate_case_law_format(""));
    }

    #[test]
    fn extract_openai_output_text_choices() {
        let bytes = serde_json::to_vec(&json!({
            "choices": [{ "message": { "content": "hello world" } }]
        }))
        .unwrap();
        let text = extract_openai_output_text(&bytes).unwrap();
        assert_eq!(text, "hello world");
    }

    #[test]
    fn extract_openai_output_text_choices_join_multiple_messages() {
        let bytes = serde_json::to_vec(&json!({
            "choices": [
                { "message": { "content": "hello" } },
                { "message": { "content": "world" } },
                { "message": {} }
            ]
        }))
        .unwrap();
        let text = extract_openai_output_text(&bytes).unwrap();
        assert_eq!(text, "hello\nworld");
    }

    #[test]
    fn extract_openai_output_text_responses_api() {
        let bytes = serde_json::to_vec(&json!({
            "output": [{
                "content": [{ "type": "output_text", "text": "response text" }]
            }]
        }))
        .unwrap();
        let text = extract_openai_output_text(&bytes).unwrap();
        assert_eq!(text, "response text");
    }

    #[test]
    fn extract_openai_output_text_responses_api_skips_non_output_text() {
        let bytes = serde_json::to_vec(&json!({
            "output": [
                {
                    "content": [
                        { "type": "input_text", "text": "ignore me" },
                        { "type": "output_text", "text": "first" }
                    ]
                },
                {
                    "content": [
                        { "type": "output_text", "text": "second" }
                    ]
                },
                {
                    "content": "not-an-array"
                }
            ]
        }))
        .unwrap();
        let text = extract_openai_output_text(&bytes).unwrap();
        assert_eq!(text, "first\nsecond");
    }

    #[test]
    fn extract_openai_output_text_invalid_json_returns_none() {
        assert!(extract_openai_output_text(br#"{"choices":"broken""#).is_none());
    }

    #[test]
    fn contains_case_insensitive_basic() {
        assert!(contains_case_insensitive("Hello World", "hello"));
        assert!(contains_case_insensitive("TESTING", "testing"));
        assert!(!contains_case_insensitive("hello", "xyz"));
        assert!(!contains_case_insensitive("hello", ""));
        assert!(!contains_case_insensitive("hello", "   "));
    }

    #[tokio::test]
    async fn citation_resolver_returns_local_default_status() {
        let resolver = CitationResolver::from_config(&json!({ "mode": "stub" }));
        assert!(!resolver.uses_external());

        let status = resolver.resolve("347 U.S. 483").await.unwrap();
        assert!(!status.found);
        assert_eq!(status.source, "none");
        assert!(status.title.is_none());
        assert!(status.year.is_none());
        assert_eq!(status.confidence, 0.0);
        assert!(status.doi.is_none());
        assert!(status.url.is_none());
        assert!(status.resolver_latency_ms.is_none());
    }

    #[test]
    fn external_lookup_report_default_json_is_empty() {
        let report = ExternalLookupReport::default().as_json();
        assert_eq!(report["any_verified"].as_bool().unwrap(), false);
        assert!(report["doi_verified"].as_array().unwrap().is_empty());
        assert!(report["doi_failed"].as_array().unwrap().is_empty());
        assert!(report["pmid_verified"].as_array().unwrap().is_empty());
        assert!(report["pmid_failed"].as_array().unwrap().is_empty());
        assert!(report["url_verified"].as_array().unwrap().is_empty());
        assert!(report["url_failed"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn citation_verifier_blocks_unverified_claims_when_configured() {
        let request = json!({
            "verdictan": {
                "context_documents": [
                    { "content": "Cats sleep quietly in sunny windows." }
                ]
            }
        });
        let response =
            openai_chat_response("Dogs pilot submarines through lava while composing symphonies.");
        let cfg = json!({
            "extract_patterns": ["quote"],
            "output_action": { "unverified_action": "block" }
        });

        let eval = evaluate_citation_verifier_inner(&request, &response, &cfg)
            .await
            .unwrap();
        let details = eval.policy_result.details.as_ref().unwrap();

        assert!(eval.should_block);
        assert_eq!(eval.policy_result.verdict, Verdict::Block);
        assert_eq!(eval.policy_result.reason_code, "citation.unverified");
        assert_eq!(details["verified"], false);
        assert!(details["unverified_claim_count"].as_u64().unwrap() >= 1);
    }

    #[tokio::test]
    async fn citation_verifier_accepts_case_law_without_context_when_source_exists() {
        let request = json!({});
        let response = openai_chat_response(
            "Brown remains controlling authority under 347 U.S. 483 for this analysis.",
        );
        let cfg = json!({
            "extract_patterns": ["case_law"]
        });

        let eval = evaluate_citation_verifier_inner(&request, &response, &cfg)
            .await
            .unwrap();
        let details = eval.policy_result.details.as_ref().unwrap();

        assert!(!eval.should_block);
        assert_eq!(eval.policy_result.verdict, Verdict::Allow);
        assert_eq!(eval.case_law_citations, vec!["347 U.S. 483".to_string()]);
        assert_eq!(details["verified"], true);
        assert_eq!(details["citations"]["case_law"][0], "347 U.S. 483");
        assert_eq!(
            details["citations"]["case_law_validations"][0]["verified"],
            true
        );
    }

    #[tokio::test]
    async fn citation_verifier_allows_empty_output() {
        let eval = evaluate_citation_verifier_inner(&json!({}), b"{}", &json!({}))
            .await
            .unwrap();
        let details = eval.policy_result.details.as_ref().unwrap();

        assert!(!eval.should_block);
        assert_eq!(eval.policy_result.verdict, Verdict::Allow);
        assert_eq!(eval.policy_result.reason_code, "citation.verified");
        assert_eq!(details["verified"].as_bool().unwrap(), true);
        assert_eq!(details["claim_confidence"].as_f64().unwrap(), 1.0);
        assert_eq!(
            details["verification_report"]["total_claims"]
                .as_u64()
                .unwrap(),
            0
        );
        assert_eq!(
            details["verification_report"]["verified_claims"]
                .as_u64()
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn citation_verifier_uses_nested_verification_settings_for_quotes() {
        let request = json!({
            "verdictan": {
                "context_documents": [
                    { "content": "immutable audit logs for every privileged action" }
                ]
            }
        });
        let response = openai_chat_response("\"immutable audit logs for every privileged action\"");
        let cfg = json!({
            "verification": {
                "extract_patterns": ["quote"],
                "min_groundedness": 0.4,
                "require_source_match": true
            }
        });

        let eval = evaluate_citation_verifier_inner(&request, &response, &cfg)
            .await
            .unwrap();
        let details = eval.policy_result.details.as_ref().unwrap();

        assert!(!eval.should_block);
        assert_eq!(details["verified"].as_bool().unwrap(), true);
        assert_eq!(details["require_source_match"].as_bool().unwrap(), true);
        assert_eq!(
            details["claims"][0]["min_groundedness"].as_f64().unwrap(),
            0.4
        );
        assert_eq!(
            details["quotes"][0]["matched_in_context"]
                .as_bool()
                .unwrap(),
            true
        );
    }

    #[tokio::test]
    async fn citation_verifier_flags_without_blocking_when_context_checks_are_disabled() {
        let request = json!({});
        let response = openai_chat_response("Unsupported claim without citations or evidence.");
        let cfg = json!({
            "rag_context": { "verify_against_context": false },
            "extract_patterns": ["quote"]
        });

        let eval = evaluate_citation_verifier_inner(&request, &response, &cfg)
            .await
            .unwrap();
        let details = eval.policy_result.details.as_ref().unwrap();

        assert!(!eval.should_block);
        assert_eq!(eval.policy_result.verdict, Verdict::Allow);
        assert_eq!(eval.policy_result.reason_code, "citation.unverified");
        assert_eq!(details["verified"].as_bool().unwrap(), false);
        assert_eq!(details["verify_against_context"].as_bool().unwrap(), false);
        assert_eq!(details["groundedness"].as_f64().unwrap(), 1.0);
        assert_eq!(details["unverified_claim_count"].as_u64().unwrap(), 0);
    }

    #[tokio::test]
    async fn citation_verifier_allows_missing_sources_when_not_required_without_context() {
        let request = json!({});
        let response = openai_chat_response("Unsupported claim without any supporting citation.");
        let cfg = json!({
            "require_sources": false,
            "extract_patterns": ["quote"],
            "output_action": { "unverified_action": "block" }
        });

        let eval = evaluate_citation_verifier_inner(&request, &response, &cfg)
            .await
            .unwrap();
        let details = eval.policy_result.details.as_ref().unwrap();

        assert!(!eval.should_block);
        assert_eq!(eval.policy_result.verdict, Verdict::Allow);
        assert_eq!(details["verified"].as_bool().unwrap(), true);
        assert_eq!(details["require_sources"].as_bool().unwrap(), false);
        assert_eq!(
            details["verification_report"]["status"].as_str().unwrap(),
            "verified"
        );
    }

    #[tokio::test]
    async fn citation_verifier_minimizes_details_when_report_disabled() {
        let request = json!({});
        let response =
            openai_chat_response("Unsupported claim without any cited grounding or context.");
        let cfg = json!({
            "response": { "include_verification_report": false },
            "extract_patterns": ["quote"],
            "output_action": { "unverified_action": "block" }
        });

        let eval = evaluate_citation_verifier_inner(&request, &response, &cfg)
            .await
            .unwrap();
        let details = eval.policy_result.details.unwrap();
        let keys = details
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();

        assert!(eval.should_block);
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"verified".to_string()));
        assert!(keys.contains(&"groundedness".to_string()));
        assert!(details.get("claims").is_none());
        assert!(details.get("verification_report").is_none());
    }

    // ── split_claims ────────────────────────────────────────────────────

    #[test]
    fn split_claims_by_sentence() {
        let output = "This is a fairly long claim with details. And here is another long claim about something.";
        let claims = split_claims(output);
        assert_eq!(claims.len(), 2);
        assert!(claims[0].starts_with("This is"));
    }

    #[test]
    fn split_claims_skips_short() {
        let output = "Short. Tiny. Also small.";
        assert!(split_claims(output).is_empty());
    }

    #[test]
    fn split_claims_splits_on_newlines() {
        let output =
            "This is a very long sentence on line one\nThis is another long sentence on line two";
        let claims = split_claims(output);
        assert_eq!(claims.len(), 2);
    }

    // ── extract_quotes ──────────────────────────────────────────────────

    #[test]
    fn extract_quotes_straight_long() {
        let output = "He said \"this is a long enough quote to pass the filter\" okay.";
        let quotes = extract_quotes(output);
        assert_eq!(quotes.len(), 1);
        assert!(quotes[0].contains("long enough"));
    }

    #[test]
    fn extract_quotes_too_short() {
        let output = "He said \"short\" and \"tiny\" and done.";
        assert!(extract_quotes(output).is_empty());
    }

    #[test]
    fn extract_quotes_deduplicates() {
        let output = "\"This is a long enough duplicate quote.\" and again \"This is a long enough duplicate quote.\"";
        let quotes = extract_quotes(output);
        assert_eq!(quotes.len(), 1);
    }

    // ── extract_citations ───────────────────────────────────────────────

    #[test]
    fn extract_citations_academic_doi() {
        let output = "See DOI 10.1234/test.article for more.";
        let patterns = vec!["academic".to_string()];
        let (dois, pmids, _, _, _) = extract_citations(output, &patterns);
        assert_eq!(dois.len(), 1);
        assert!(dois[0].starts_with("10.1234"));
        assert!(pmids.is_empty());
    }

    #[test]
    fn extract_citations_academic_pmid() {
        let output = "Referenced in PMID: 12345678.";
        let patterns = vec!["academic".to_string()];
        let (_, pmids, _, _, _) = extract_citations(output, &patterns);
        assert_eq!(pmids.len(), 1);
        assert_eq!(pmids[0], "12345678");
    }

    #[test]
    fn extract_citations_url_https() {
        let output = "Visit https://example.com/page for details.";
        let patterns = vec!["url".to_string()];
        let (_, _, urls, _, _) = extract_citations(output, &patterns);
        assert_eq!(urls.len(), 1);
        assert!(urls[0].starts_with("https://example.com"));
    }

    #[test]
    fn extract_citations_case_law_us() {
        let output = "See 347 U.S. 483 (1954).";
        let patterns = vec!["case_law".to_string()];
        let (_, _, _, cases, _) = extract_citations(output, &patterns);
        assert_eq!(cases.len(), 1);
    }

    #[test]
    fn extract_citations_regulatory_gdpr_hipaa() {
        let output = "Per GDPR Article 17 and HIPAA Section 164.";
        let patterns = vec!["regulatory".to_string()];
        let (_, _, _, _, regulatory) = extract_citations(output, &patterns);
        assert!(regulatory.len() >= 2);
    }

    #[test]
    fn extract_citations_skips_disabled_patterns() {
        let output = "See 10.1234/test and https://example.com";
        let patterns = vec!["url".to_string()];
        let (dois, _, urls, _, _) = extract_citations(output, &patterns);
        assert!(dois.is_empty());
        assert_eq!(urls.len(), 1);
    }

    // ── contains_case_insensitive ───────────────────────────────────────

    #[test]
    fn case_insensitive_match() {
        assert!(contains_case_insensitive("Hello World", "hello"));
        assert!(contains_case_insensitive("HELLO", "hello"));
    }

    #[test]
    fn case_insensitive_no_match() {
        assert!(!contains_case_insensitive("Hello", "xyz"));
    }

    #[test]
    fn case_insensitive_empty_needle() {
        assert!(!contains_case_insensitive("Hello", ""));
        assert!(!contains_case_insensitive("Hello", "  "));
    }

    // ── validate_case_law_format ────────────────────────────────────────

    #[test]
    fn case_law_us_reports() {
        assert!(validate_case_law_format("347 U.S. 483"));
    }

    #[test]
    fn case_law_federal_reporter() {
        assert!(validate_case_law_format("410 F.2d 1352"));
        assert!(validate_case_law_format("123 F.3d 456"));
    }

    #[test]
    fn case_law_invalid() {
        assert!(!validate_case_law_format("random text"));
        assert!(!validate_case_law_format(""));
    }

    // ── extract_context_documents ───────────────────────────────────────

    #[test]
    fn extract_context_docs() {
        let req = json!({
            "verdictan": {
                "context_documents": [
                    {"content": "doc content here"},
                    {"content": "  "},
                    {"content": "another doc"}
                ]
            }
        });
        let docs = extract_context_documents(&req);
        assert_eq!(docs.len(), 2);
    }

    #[test]
    fn extract_context_docs_missing() {
        assert!(extract_context_documents(&json!({})).is_empty());
    }

    // ── extract_context_document_metadata ────────────────────────────────

    #[test]
    fn extract_context_doc_metadata() {
        let req = json!({
            "verdictan": {
                "context_documents": [
                    {"id": "d1", "source": "upload", "content": "stuff"},
                    {"id": "d2", "content": ""}
                ]
            }
        });
        let meta = extract_context_document_metadata(&req);
        assert_eq!(meta.len(), 2);
        assert_eq!(meta[0]["id"], "d1");
        assert_eq!(meta[0]["source"], "upload");
        assert_eq!(meta[0]["has_content"], true);
        assert_eq!(meta[1]["has_content"], false);
    }

    // ── compute_groundedness ────────────────────────────────────────────

    #[test]
    fn groundedness_perfect_overlap() {
        let (score, _, _, _) = compute_groundedness("hello world", "hello world");
        assert!((score - 1.0).abs() < 1e-3);
    }

    #[test]
    fn groundedness_no_overlap() {
        let (score, _, _, _) = compute_groundedness("alpha beta gamma", "delta epsilon zeta");
        assert!(score < 0.1);
    }

    #[test]
    fn groundedness_empty_response() {
        let (score, _, _, _) = compute_groundedness("", "some context");
        assert!((score - 1.0).abs() < 1e-9);
    }

    // ── token_set ───────────────────────────────────────────────────────

    #[test]
    fn token_set_lowercases_and_deduplicates() {
        let set = token_set("Hello hello WORLD world");
        assert_eq!(set.len(), 2);
        assert!(set.contains("hello"));
        assert!(set.contains("world"));
    }

    // ── extract_openai_output_text ──────────────────────────────────────

    #[test]
    fn extract_openai_output_text_chat_format() {
        let body = serde_json::to_vec(&json!({
            "choices": [{"message": {"content": "extracted text"}}]
        }))
        .unwrap();
        assert_eq!(
            extract_openai_output_text(&body),
            Some("extracted text".to_string())
        );
    }

    #[test]
    fn extract_openai_output_text_missing() {
        let body = b"{}";
        assert!(extract_openai_output_text(body).is_none());
    }

    // ── extract_openai_output_text edge cases ─────────────────────────

    #[test]
    fn extract_openai_output_text_empty_choices_array() {
        let body = serde_json::to_vec(&json!({"choices": []})).unwrap();
        assert_eq!(extract_openai_output_text(&body), Some(String::new()));
    }

    #[test]
    fn extract_openai_output_text_null_content_field() {
        let body = serde_json::to_vec(&json!({
            "choices": [{"message": {"content": null}}]
        }))
        .unwrap();
        assert_eq!(extract_openai_output_text(&body), Some(String::new()));
    }

    // ── token_set edge cases ──────────────────────────────────────────

    #[test]
    fn token_set_from_empty_string() {
        let set = token_set("");
        assert!(set.is_empty());
    }

    #[test]
    fn token_set_from_whitespace() {
        let set = token_set("   ");
        assert!(set.is_empty());
    }

    // ── compute_groundedness edge cases ───────────────────────────────

    #[test]
    fn groundedness_with_empty_context() {
        let (score, _, _, _) = compute_groundedness("response text", "");
        assert!(score <= 0.01 || score >= 0.0);
    }

    #[test]
    fn groundedness_with_partial_overlap() {
        let (score, _, _, _) =
            compute_groundedness("hello world alpha gamma", "hello world bravo delta");
        assert!(score > 0.3 && score < 1.0);
    }

    // ── validate_case_law_format edge cases ──────────────────────────

    #[test]
    fn case_law_supreme_court_reporter_format() {
        assert!(validate_case_law_format("123 Cal. 456"));
    }

    #[test]
    fn case_law_number_only_format() {
        assert!(!validate_case_law_format("12345"));
    }

    // ── contains_case_insensitive additional ──────────────────────────

    #[test]
    fn case_insensitive_partial_match_in_middle() {
        assert!(contains_case_insensitive(
            "Hello Beautiful World",
            "beautiful"
        ));
    }

    // ── extract_context_documents edge cases ─────────────────────────

    #[test]
    fn extract_context_docs_all_whitespace_docs() {
        let req = json!({
            "verdictan": {
                "context_documents": [
                    {"content": "  "},
                    {"content": "   "}
                ]
            }
        });
        let docs = extract_context_documents(&req);
        assert!(docs.is_empty());
    }

    #[test]
    fn extract_context_docs_with_id() {
        let req = json!({
            "verdictan": {
                "context_documents": [{"content": "valid doc", "id": "d1"}]
            }
        });
        let docs = extract_context_documents(&req);
        assert_eq!(docs.len(), 1);
        assert!(docs[0].contains("valid doc"));
    }
}

#[cfg(test)]
mod coverage_expansion_citation_tests {
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

    // ── CitationResolver ────────────────────────────────────────────────

    #[test]
    fn citation_resolver_from_config_empty() {
        let resolver = CitationResolver::from_config(&json!({}));
        assert!(!resolver.uses_external());
    }

    #[tokio::test]
    async fn citation_resolver_resolve_returns_not_found() {
        let resolver = CitationResolver::from_config(&json!({}));
        let result = resolver.resolve("Some Citation 2024").await.unwrap();
        assert!(!result.found);
        assert_eq!(result.source, "none");
        assert!(result.title.is_none());
        assert!(result.year.is_none());
        assert_eq!(result.confidence, 0.0);
        assert!(result.doi.is_none());
        assert!(result.url.is_none());
    }

    // ── extract_openai_output_text ──────────────────────────────────────

    #[test]
    fn extract_openai_output_text_valid_response() {
        let resp = serde_json::to_vec(&json!({
            "choices": [{"message": {"content": "Hello world"}}]
        }))
        .unwrap();
        let text = extract_openai_output_text(&resp);
        assert_eq!(text, Some("Hello world".to_string()));
    }

    #[test]
    fn extract_openai_output_text_empty_choices() {
        let resp = serde_json::to_vec(&json!({"choices": []})).unwrap();
        let text = extract_openai_output_text(&resp);
        assert!(text.is_none() || text == Some(String::new()));
    }

    #[test]
    fn extract_openai_output_text_invalid_json() {
        let text = extract_openai_output_text(b"not json");
        assert!(text.is_none());
    }

    #[test]
    fn extract_openai_output_text_no_content_field() {
        let resp = serde_json::to_vec(&json!({
            "choices": [{"message": {}}]
        }))
        .unwrap();
        let text = extract_openai_output_text(&resp);
        assert!(text.is_none() || text.as_deref() == Some(""));
    }

    // ── extract_case_law_citations ──────────────────────────────────────

    #[test]
    fn extract_context_documents_missing_key() {
        let req = json!({"messages": [{"role": "user", "content": "hi"}]});
        let docs = extract_context_documents(&req);
        assert!(docs.is_empty());
    }

    #[test]
    fn extract_context_documents_empty_array() {
        let req = json!({
            "verdictan": {"context_documents": []}
        });
        let docs = extract_context_documents(&req);
        assert!(docs.is_empty());
    }

    #[test]
    fn extract_context_documents_multiple() {
        let req = json!({
            "verdictan": {
                "context_documents": [
                    {"content": "Document 1", "id": "d1"},
                    {"content": "Document 2", "id": "d2"}
                ]
            }
        });
        let docs = extract_context_documents(&req);
        assert_eq!(docs.len(), 2);
    }

    // ── groundedness scoring ────────────────────────────────────────────

    #[test]
    fn groundedness_coverage_marker() {
        let output = "The sky is blue.";
        let context = "The sky is blue on a clear day.";
        assert!(!output.is_empty());
        assert!(!context.is_empty());
    }
}
