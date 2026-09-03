// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

pub use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::enforcement::ChainEntry;

// ═══════════════════════════════════════════════════════════════════════════
// Phase 16 — Route & Rule system
// ═══════════════════════════════════════════════════════════════════════════

/// How to match the path component of an incoming request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum MatchType {
    /// The request path must exactly equal the route path (after normalization).
    Exact,
    /// The request path must start with the route path (default).
    #[default]
    Prefix,
}

/// A single route rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    /// Unique route name — used in lint and operational logging.
    pub name: String,
    /// Path pattern to match against (normalized before comparison).
    pub path: String,
    /// Match mode: `prefix` (default) or `exact`.
    #[serde(default, rename = "match")]
    pub match_type: MatchType,
    /// Restrict to specific HTTP methods (case-insensitive). `None` = all methods.
    #[serde(default)]
    pub methods: Option<Vec<String>>,
    /// Header exact-match conditions (all must be present and match, case-insensitive value).
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    /// Resolution priority (higher wins). Defaults to `0`.
    #[serde(default)]
    pub priority: i32,
    /// Override the policy chain for requests matching this route.
    /// When `Some`, this list *replaces* (not merges with) the global chain.
    #[serde(default)]
    pub chain: Option<Vec<ChainEntry>>,
}

/// Top-level `routes` configuration section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteConfig {
    pub routes: Vec<Route>,
}

/// Normalize a path before matching.
///
/// - Collapses consecutive slashes into one.
/// - Strips trailing slash unless the path is `/`.
/// - Does NOT resolve `..` segments — those are handled by Axum's URI normalization layer
///   before the path reaches route matching.
pub fn normalize_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut prev_slash = false;
    for ch in path.chars() {
        if ch == '/' {
            if !prev_slash {
                out.push(ch);
            }
            prev_slash = true;
        } else {
            out.push(ch);
            prev_slash = false;
        }
    }
    // Strip trailing slash, but keep root.
    if out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

impl Route {
    /// Returns `true` if this route matches the given request.
    ///
    /// All declared conditions must hold (AND semantics):
    /// - path (prefix or exact, after normalization)
    /// - methods (if `Some`)
    /// - headers (all declared keys must be present with matching values, case-insensitive)
    pub fn matches(&self, path: &str, method: &str, headers: &HeaderMap) -> bool {
        let norm_path = normalize_path(path);
        let norm_route = normalize_path(&self.path);

        let path_ok = match self.match_type {
            MatchType::Exact => norm_path == norm_route,
            MatchType::Prefix => {
                norm_path == norm_route || norm_path.starts_with(&format!("{norm_route}/"))
            }
        };
        if !path_ok {
            return false;
        }

        if let Some(methods) = &self.methods {
            if !methods
                .iter()
                .any(|m| m.to_uppercase() == method.to_uppercase())
            {
                return false;
            }
        }

        if let Some(required_headers) = &self.headers {
            for (key, expected) in required_headers {
                match headers.get(key.as_str()) {
                    None => return false,
                    Some(actual) => {
                        let actual_str = actual.to_str().unwrap_or("").to_ascii_lowercase();
                        if actual_str != expected.to_ascii_lowercase() {
                            return false;
                        }
                    }
                }
            }
        }

        true
    }
}

impl RouteConfig {
    /// Returns the first matching route by priority (highest wins).
    /// When multiple routes share the same priority, the first one declared wins.
    pub fn resolve<'a>(
        &'a self,
        path: &str,
        method: &str,
        headers: &HeaderMap,
    ) -> Option<&'a Route> {
        let mut candidates: Vec<&Route> = self
            .routes
            .iter()
            .filter(|r| r.matches(path, method, headers))
            .collect();
        candidates.sort_by_key(|route| std::cmp::Reverse(route.priority));
        candidates.into_iter().next()
    }

    /// Returns the original path unchanged. Strip-path rewriting has been removed.
    fn rewrite_path(&self, _route: &Route, original_path: &str) -> String {
        original_path.to_string()
    }

    /// Parse from the `routes` top-level key of a policy-config JSON value.
    /// Returns an empty `RouteConfig` when the section is absent.
    pub fn from_json(root: &serde_json::Value) -> Result<Self, crate::error::CliError> {
        let Some(routes_val) = root.get("routes") else {
            return Ok(Self::default());
        };
        if routes_val.is_null() {
            return Ok(Self::default());
        }
        let routes: Vec<Route> = serde_json::from_value(routes_val.clone()).map_err(|e| {
            crate::error::CliError::user(format!("failed to parse routes section: {e}"))
        })?;
        Ok(Self { routes })
    }
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

    // --- normalize_path ---

    #[test]
    fn normalize_root_stays_root() {
        assert_eq!(normalize_path("/"), "/");
    }

    #[test]
    fn normalize_strips_trailing_slash() {
        assert_eq!(normalize_path("/v1/chat/"), "/v1/chat");
    }

    #[test]
    fn normalize_collapses_consecutive_slashes() {
        assert_eq!(normalize_path("//v1///chat//"), "/v1/chat");
    }

    #[test]
    fn normalize_preserves_simple_path() {
        assert_eq!(normalize_path("/v1/chat"), "/v1/chat");
    }

    #[test]
    fn normalize_empty_string() {
        assert_eq!(normalize_path(""), "");
    }

    // --- MatchType default ---

    #[test]
    fn match_type_default_is_prefix() {
        assert_eq!(MatchType::default(), MatchType::Prefix);
    }

    // --- Route::matches — path matching ---

    fn route(path: &str, match_type: MatchType) -> Route {
        Route {
            name: "test".into(),
            path: path.into(),
            match_type,
            methods: None,
            headers: None,
            priority: 0,
            chain: None,
        }
    }

    #[test]
    fn exact_match_succeeds_on_identical_path() {
        let r = route("/v1/chat", MatchType::Exact);
        assert!(r.matches("/v1/chat", "GET", &HeaderMap::new()));
    }

    #[test]
    fn exact_match_rejects_prefix_extension() {
        let r = route("/v1/chat", MatchType::Exact);
        assert!(!r.matches("/v1/chat/completions", "GET", &HeaderMap::new()));
    }

    #[test]
    fn exact_match_normalizes_before_compare() {
        let r = route("/v1/chat/", MatchType::Exact);
        assert!(r.matches("/v1/chat", "GET", &HeaderMap::new()));
    }

    #[test]
    fn prefix_match_on_exact_path() {
        let r = route("/v1", MatchType::Prefix);
        assert!(r.matches("/v1", "POST", &HeaderMap::new()));
    }

    #[test]
    fn prefix_match_on_deeper_path() {
        let r = route("/v1", MatchType::Prefix);
        assert!(r.matches("/v1/chat/completions", "POST", &HeaderMap::new()));
    }

    #[test]
    fn prefix_match_rejects_partial_segment() {
        let r = route("/v1", MatchType::Prefix);
        assert!(!r.matches("/v1beta", "POST", &HeaderMap::new()));
    }

    // --- Route::matches — method filtering ---

    #[test]
    fn method_filter_allows_matching_method() {
        let r = Route {
            methods: Some(vec!["POST".into(), "PUT".into()]),
            ..route("/api", MatchType::Prefix)
        };
        assert!(r.matches("/api/data", "post", &HeaderMap::new()));
    }

    #[test]
    fn method_filter_rejects_non_matching_method() {
        let r = Route {
            methods: Some(vec!["POST".into()]),
            ..route("/api", MatchType::Prefix)
        };
        assert!(!r.matches("/api/data", "GET", &HeaderMap::new()));
    }

    #[test]
    fn no_method_filter_allows_any() {
        let r = route("/api", MatchType::Prefix);
        assert!(r.matches("/api/data", "DELETE", &HeaderMap::new()));
    }

    // --- Route::matches — header matching ---

    #[test]
    fn header_match_case_insensitive_value() {
        let mut required = HashMap::new();
        required.insert("x-team".to_string(), "Alpha".to_string());
        let r = Route {
            headers: Some(required),
            ..route("/api", MatchType::Prefix)
        };
        let mut hm = HeaderMap::new();
        hm.insert("x-team", "alpha".parse().unwrap());
        assert!(r.matches("/api/data", "GET", &hm));
    }

    #[test]
    fn header_match_rejects_missing_header() {
        let mut required = HashMap::new();
        required.insert("x-team".to_string(), "Alpha".to_string());
        let r = Route {
            headers: Some(required),
            ..route("/api", MatchType::Prefix)
        };
        assert!(!r.matches("/api/data", "GET", &HeaderMap::new()));
    }

    #[test]
    fn header_match_rejects_wrong_value() {
        let mut required = HashMap::new();
        required.insert("x-team".to_string(), "Alpha".to_string());
        let r = Route {
            headers: Some(required),
            ..route("/api", MatchType::Prefix)
        };
        let mut hm = HeaderMap::new();
        hm.insert("x-team", "Beta".parse().unwrap());
        assert!(!r.matches("/api/data", "GET", &hm));
    }

    // --- RouteConfig::resolve ---

    #[test]
    fn resolve_returns_highest_priority() {
        let cfg = RouteConfig {
            routes: vec![
                Route {
                    priority: 1,
                    ..route("/v1", MatchType::Prefix)
                },
                Route {
                    name: "high".into(),
                    priority: 10,
                    ..route("/v1", MatchType::Prefix)
                },
            ],
        };
        let hit = cfg.resolve("/v1/chat", "GET", &HeaderMap::new()).unwrap();
        assert_eq!(hit.name, "high");
    }

    #[test]
    fn resolve_returns_none_when_no_match() {
        let cfg = RouteConfig {
            routes: vec![route("/api", MatchType::Exact)],
        };
        assert!(cfg.resolve("/other", "GET", &HeaderMap::new()).is_none());
    }

    #[test]
    fn resolve_first_declared_wins_on_tie() {
        let cfg = RouteConfig {
            routes: vec![
                Route {
                    name: "first".into(),
                    ..route("/v1", MatchType::Prefix)
                },
                Route {
                    name: "second".into(),
                    ..route("/v1", MatchType::Prefix)
                },
            ],
        };
        let hit = cfg.resolve("/v1/x", "GET", &HeaderMap::new()).unwrap();
        assert_eq!(hit.name, "first");
    }

    // --- RouteConfig::rewrite_path ---

    #[test]
    fn rewrite_path_no_strip() {
        let r = route("/v1", MatchType::Prefix);
        let cfg = RouteConfig { routes: vec![] };
        assert_eq!(cfg.rewrite_path(&r, "/v1/chat"), "/v1/chat");
    }

    #[test]
    fn rewrite_path_returns_original_path() {
        let r = route("/v1", MatchType::Prefix);
        let cfg = RouteConfig { routes: vec![] };
        assert_eq!(
            cfg.rewrite_path(&r, "/v1/chat/completions"),
            "/v1/chat/completions"
        );
    }

    // --- RouteConfig::from_json ---

    #[test]
    fn from_json_absent_routes_returns_default() {
        let root = serde_json::json!({});
        let cfg = RouteConfig::from_json(&root).unwrap();
        assert!(cfg.routes.is_empty());
    }

    #[test]
    fn from_json_null_routes_returns_default() {
        let root = serde_json::json!({"routes": null});
        let cfg = RouteConfig::from_json(&root).unwrap();
        assert!(cfg.routes.is_empty());
    }

    #[test]
    fn from_json_parses_routes() {
        let root = serde_json::json!({
            "routes": [
                {"name": "r1", "path": "/v1", "match": "prefix"},
                {"name": "r2", "path": "/v2", "match": "exact", "priority": 5}
            ]
        });
        let cfg = RouteConfig::from_json(&root).unwrap();
        assert_eq!(cfg.routes.len(), 2);
        assert_eq!(cfg.routes[0].name, "r1");
        assert_eq!(cfg.routes[1].priority, 5);
        assert_eq!(cfg.routes[1].match_type, MatchType::Exact);
    }

    #[test]
    fn from_json_invalid_routes_returns_err() {
        let root = serde_json::json!({"routes": "not_an_array"});
        assert!(RouteConfig::from_json(&root).is_err());
    }

    // --- Route serde round-trip ---

    #[test]
    fn route_serde_round_trip() {
        let r = Route {
            name: "test-route".into(),
            path: "/v1/chat".into(),
            match_type: MatchType::Exact,
            methods: Some(vec!["POST".into()]),
            headers: None,
            priority: 5,
            chain: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        let deser: Route = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.name, "test-route");
        assert_eq!(deser.match_type, MatchType::Exact);
        assert_eq!(deser.priority, 5);
    }
}
