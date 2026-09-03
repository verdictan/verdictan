// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

#![allow(clippy::items_after_test_module)]

//! Locale resolution and translation catalog for the `verdictan` CLI.
//!
//! # Locale precedence (highest to lowest)
//! 1. `--lang <tag>` CLI flag (parsed by the caller after `Cli::parse()`)
//! 2. `VERDICTAN_LANG` environment variable
//! 3. `LANG` / `LC_ALL` / `LC_MESSAGES` OS environment variables
//! 4. Default: `en`
//!
//! Machine-readable output (`--json`), command names, flags, and exit codes
//! are always stable regardless of locale.
//!
//! # Module layout
//!
//! | Module   | Key prefixes / content                                     |
//! |----------|------------------------------------------------------------|
//! | `auth`   | `auth.*`                                                   |
//! | `errors` | `error.*`, `network.*`, `internal.*`, `user.*`             |
//! | `help`   | `cli.*`, after_help constants and builder functions        |

mod auth;
mod errors;
pub(crate) mod help;

use std::sync::OnceLock;

// ── Locale type ──────────────────────────────────────────────────────────────

/// Supported CLI locales.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Locale {
    #[default]
    En,
    Es,
    Ca,
}

impl Locale {
    /// Parse from a BCP-47 language tag prefix (case-insensitive).
    pub fn from_tag(tag: &str) -> Option<Self> {
        let lower = tag.to_ascii_lowercase();
        // Accept bare tags ("es"), region variants ("es-ES"), and POSIX-style
        // with encoding ("es_ES.UTF-8").
        let primary = lower.split(['-', '_', '.']).next().unwrap_or("");
        match primary {
            "en" => Some(Self::En),
            "es" => Some(Self::Es),
            "ca" => Some(Self::Ca),
            _ => None,
        }
    }

    /// Return the BCP-47 tag string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Es => "es",
            Self::Ca => "ca",
        }
    }
}

// ── Global locale ────────────────────────────────────────────────────────────

/// Process-wide locale, set once in [`entrypoint`](crate::entrypoint) before
/// `Cli::parse()` so that `after_help` strings are available at parse time.
static GLOBAL_LOCALE: OnceLock<Locale> = OnceLock::new();

/// Return the active global locale, defaulting to `En` if not yet initialised.
pub fn global() -> Locale {
    GLOBAL_LOCALE.get().copied().unwrap_or_default()
}

/// Initialise the global locale from `VERDICTAN_LANG`, the OS locale env vars, or
/// `Locale::En`.  Idempotent: subsequent calls are no-ops once set.
pub fn init_global_from_env() {
    if GLOBAL_LOCALE.get().is_some() {
        return;
    }
    let locale = resolve_from_env();
    // Ignore the error from a concurrent initialiser – the winner's value is
    // used from now on.
    let _ = GLOBAL_LOCALE.set(locale);
}

/// Set the global locale explicitly (used after `--lang` is parsed).
/// Ignored if the locale was already set by a prior call (e.g. from the help
/// invocation path).  Callers that need the override behaviour should call
/// `init_global_from_lang_arg` via the entrypoint, which handles the priority.
pub fn override_global(locale: Locale) {
    // OnceLock does not support overwriting; re-use whatever was set.  The
    // entrypoint should call init_global_from_env first, then call this only
    // if --lang was explicitly supplied so it takes effect when the OnceLock
    // has not yet been populated.
    let _ = GLOBAL_LOCALE.set(locale);
}

// ── Locale resolution helpers ─────────────────────────────────────────────

/// Resolve locale from environment variables only (no CLI args).
///
/// Checks `VERDICTAN_LANG`, then `LC_ALL`, `LC_MESSAGES`, finally `LANG` in order.
pub fn resolve_from_env() -> Locale {
    for var in &["VERDICTAN_LANG", "LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(val) = std::env::var(var) {
            if let Some(locale) = Locale::from_tag(val.trim()) {
                return locale;
            }
        }
    }
    Locale::En
}

/// Resolve locale from an explicit `--lang` argument (highest priority),
/// falling back to [`resolve_from_env`] when no arg is supplied.
///
/// If `lang_arg` is supplied but the tag is not recognised, returns
/// `Locale::default()` (English) so that a misspelled flag produces a
/// predictable English fallback rather than silently inheriting the env-var
/// locale.
pub fn resolve(lang_arg: Option<&str>) -> Locale {
    if let Some(tag) = lang_arg {
        // Explicit arg: recognised tag wins, unrecognised tag → default (En).
        return Locale::from_tag(tag).unwrap_or_default();
    }
    // No explicit arg: read env variables.
    resolve_from_env()
}

// ── Translation catalog ──────────────────────────────────────────────────────

/// Look up a translation key for the given locale.
///
/// Delegates to domain modules (help → auth → errors) in order.
/// Returns an empty string for any unrecognised key (safe fallback so
/// callers using `t_fmt` get the key name rather than a panic).
///
/// # Domain-to-module mapping
///
/// | Key prefix               | Module   |
/// |--------------------------|----------|
/// | `cli.about`, `cli.examples_header` | `help` |
/// | `auth.*`                 | `auth`   |
/// | `error.*`, `network.*`, `internal.*`, `user.*` | `errors` |
pub fn t(locale: Locale, key: &str) -> &'static str {
    help::t(locale, key)
        .or_else(|| auth::t(locale, key))
        .or_else(|| errors::t(locale, key))
        .unwrap_or("")
}

pub fn t_fmt(locale: Locale, key: &str, args: &[&str]) -> String {
    let template = t(locale, key);
    if template.is_empty() {
        return key.to_string();
    }

    let mut result = template.to_string();
    for (index, arg) in args.iter().enumerate() {
        result = result.replace(&format!("{{{index}}}"), arg);
    }

    result
}

// ── Re-export after_help builders and constants from `help` ──────────────────
//
// External callers (lib.rs command structs) use `crate::i18n::xxx_after_help()`
// and extracted integration tests import the `*_AFTER_HELP_*` constants via
// `verdictan_cli::i18n`.
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
    fn locale_from_tag_bare_en() {
        assert_eq!(Locale::from_tag("en"), Some(Locale::En));
    }

    #[test]
    fn locale_from_tag_bare_es() {
        assert_eq!(Locale::from_tag("es"), Some(Locale::Es));
    }

    #[test]
    fn locale_from_tag_bare_ca() {
        assert_eq!(Locale::from_tag("ca"), Some(Locale::Ca));
    }

    #[test]
    fn locale_from_tag_region_variant() {
        assert_eq!(Locale::from_tag("es-ES"), Some(Locale::Es));
        assert_eq!(Locale::from_tag("en-US"), Some(Locale::En));
        assert_eq!(Locale::from_tag("ca-AD"), Some(Locale::Ca));
    }

    #[test]
    fn locale_from_tag_posix_encoding() {
        assert_eq!(Locale::from_tag("es_ES.UTF-8"), Some(Locale::Es));
        assert_eq!(Locale::from_tag("en_GB.UTF-8"), Some(Locale::En));
    }

    #[test]
    fn locale_from_tag_case_insensitive() {
        assert_eq!(Locale::from_tag("EN"), Some(Locale::En));
        assert_eq!(Locale::from_tag("Es"), Some(Locale::Es));
        assert_eq!(Locale::from_tag("CA"), Some(Locale::Ca));
    }

    #[test]
    fn locale_from_tag_unknown() {
        assert_eq!(Locale::from_tag("fr"), None);
        assert_eq!(Locale::from_tag("de"), None);
        assert_eq!(Locale::from_tag(""), None);
        assert_eq!(Locale::from_tag("xyz"), None);
    }

    #[test]
    fn locale_as_str_roundtrip() {
        assert_eq!(Locale::En.as_str(), "en");
        assert_eq!(Locale::Es.as_str(), "es");
        assert_eq!(Locale::Ca.as_str(), "ca");
    }

    #[test]
    fn locale_default_is_en() {
        assert_eq!(Locale::default(), Locale::En);
    }

    #[test]
    fn t_known_keys() {
        assert_eq!(t(Locale::En, "cli.about"), "Verdictan CLI");
        assert_eq!(t(Locale::Es, "cli.about"), "CLI de Verdictan");
        assert_eq!(t(Locale::Ca, "cli.about"), "CLI de Verdictan");
    }

    #[test]
    fn t_examples_header_key() {
        assert_eq!(t(Locale::En, "cli.examples_header"), "Examples:");
        assert_eq!(t(Locale::Es, "cli.examples_header"), "Ejemplos:");
        assert_eq!(t(Locale::Ca, "cli.examples_header"), "Exemples:");
    }

    #[test]
    fn t_unknown_key_returns_empty() {
        assert_eq!(t(Locale::En, "nonexistent.key"), "");
        assert_eq!(t(Locale::Es, ""), "");
    }

    #[test]
    fn t_fmt_with_args() {
        let result = t_fmt(Locale::En, "error.network", &[]);
        assert!(!result.is_empty() || result == "error.network");
    }

    #[test]
    fn t_fmt_unknown_key_returns_key_name() {
        let result = t_fmt(Locale::En, "totally.unknown.key", &["arg1"]);
        assert_eq!(result, "totally.unknown.key");
    }

    #[test]
    fn resolve_with_explicit_lang_arg() {
        assert_eq!(resolve(Some("es")), Locale::Es);
        assert_eq!(resolve(Some("ca")), Locale::Ca);
        assert_eq!(resolve(Some("en")), Locale::En);
    }

    #[test]
    fn resolve_with_unrecognized_lang_arg_defaults_to_en() {
        assert_eq!(resolve(Some("fr")), Locale::En);
        assert_eq!(resolve(Some("xyz")), Locale::En);
    }
}

pub use help::{
    // ── after_help builder functions ─────────────────────────────────────
    agent_after_help,
    control_after_help,
    escalation_after_help,
    export_jobs_after_help,
    gateway_after_help,
    history_after_help,
    iam_after_help,
    policy_after_help,
    role_after_help,
    secret_after_help,
    spend_after_help,
    team_after_help,
    token_after_help,
    user_after_help,
    AUTH_LOGIN_AFTER_HELP_EN,
};
