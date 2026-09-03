// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! CLI `--help` after-text builders and locale-aware section headers.
//!
//! Each `*_after_help()` function returns a `&'static str` suitable for
//! `#[command(after_help = crate::i18n::xxx_after_help())]`.  Because example
//! bodies contain only stable command names and flags, only the
//! section header is localised for v1.

use super::{global, Locale};

// ── after_help macro ──────────────────────────────────────────────────────────

macro_rules! after_help {
    ($name:ident, $en:expr, $es:expr, $ca:expr) => {
        pub fn $name() -> &'static str {
            match global() {
                Locale::Es => $es,
                Locale::Ca => $ca,
                Locale::En => $en,
            }
        }
    };
}

// ── CLI section-header translation keys ───────────────────────────────────────

pub(crate) fn t(locale: Locale, key: &str) -> Option<&'static str> {
    Some(match (locale, key) {
        (Locale::Es, "cli.about") => "CLI de Verdictan",
        (Locale::Ca, "cli.about") => "CLI de Verdictan",
        (_, "cli.about") => "Verdictan CLI",

        (Locale::Es, "cli.examples_header") => "Ejemplos:",
        (Locale::Ca, "cli.examples_header") => "Exemples:",
        (_, "cli.examples_header") => "Examples:",

        _ => return None,
    })
}

// ── after_help template ───────────────────────────────────────────────────────

fn examples_header() -> &'static str {
    t(global(), "cli.examples_header").unwrap_or("Examples:")
}

macro_rules! after_help_examples {
    ($name:ident, $body:expr) => {
        pub fn $name() -> String {
            format!("{}\n{}", examples_header(), $body)
        }
    };
}

// ── after_help with locale constants ──────────────────────────────────────────
// ponytail: :literal fragments are transparent to concat!, so the body is
// defined once and reused for both the runtime fn and the three locale consts.

macro_rules! after_help_with_locale_consts {
    ($fn_name:ident, $en:ident, $es:ident, $ca:ident, $body:literal) => {
        pub fn $fn_name() -> String {
            format!("{}\n{}", examples_header(), $body)
        }
        pub const $en: &str = concat!("Examples:\n", $body);
        pub const $es: &str = concat!("Ejemplos:\n", $body);
        pub const $ca: &str = concat!("Exemples:\n", $body);
    };
}

after_help_with_locale_consts!(control_after_help, CONTROL_AFTER_HELP_EN, CONTROL_AFTER_HELP_ES, CONTROL_AFTER_HELP_CA, "  verdictan control plan --file control-manifest.yaml\n  verdictan control plan --file control-manifest.yaml --prune --json\n  verdictan control apply --file control-manifest.yaml --yes\n  verdictan control apply --file control-manifest.yaml --prune --yes --json\n  verdictan control export --file control-manifest.yaml\n  verdictan control export --include-secret-stubs --json");
after_help_with_locale_consts!(history_after_help, HISTORY_AFTER_HELP_EN, HISTORY_AFTER_HELP_ES, HISTORY_AFTER_HELP_CA, "  verdictan history list-sessions\n  verdictan history list-sessions --json\n  verdictan history get-session --session-id <uuid> --include-entries\n  verdictan history learn --bind-to-session <uuid> --json");
after_help_with_locale_consts!(secret_after_help, SECRET_AFTER_HELP_EN, SECRET_AFTER_HELP_ES, SECRET_AFTER_HELP_CA, "  verdictan secret list\n  verdictan secret list --json\n  verdictan secret create --name VERDICTAN_OPENAI_API_KEY --env-var VERDICTAN_OPENAI_API_KEY\n  printf 'secret' | verdictan secret update --secret-id <uuid> --stdin --json");
after_help_with_locale_consts!(role_after_help, ROLE_AFTER_HELP_EN, ROLE_AFTER_HELP_ES, ROLE_AFTER_HELP_CA, "  verdictan role list\n  verdictan role list --json\n  verdictan role create --name support-analyst\n  verdictan role attach-policy --role-id <uuid> --policy-id <uuid> --json");
after_help_with_locale_consts!(iam_after_help, IAM_AFTER_HELP_EN, IAM_AFTER_HELP_ES, IAM_AFTER_HELP_CA, "  verdictan iam policy list\n  verdictan iam policy list --json\n  verdictan iam policy get --policy-id <uuid>\n  verdictan iam policy delete --policy-id <uuid> --yes --json");
after_help_with_locale_consts!(user_after_help, USER_AFTER_HELP_EN, USER_AFTER_HELP_ES, USER_AFTER_HELP_CA, "  verdictan user list\n  verdictan user list --json\n  verdictan user get --user-id <uuid>\n  verdictan user suspend --user-id <uuid> --yes --json");
after_help_with_locale_consts!(team_after_help, TEAM_AFTER_HELP_EN, TEAM_AFTER_HELP_ES, TEAM_AFTER_HELP_CA, "  verdictan team list\n  verdictan team list --json\n  verdictan team get --team-id <uuid>\n  verdictan team add-member --team-id <uuid> --email member@example.com --json");
after_help_with_locale_consts!(agent_after_help, AGENT_AFTER_HELP_EN, AGENT_AFTER_HELP_ES, AGENT_AFTER_HELP_CA, "  verdictan agent list\n  verdictan agent list --json\n  verdictan agent get --agent-id <uuid>\n  verdictan agent link-gateway --agent-id <uuid> --gateway-id gateway-1 --json");
after_help_with_locale_consts!(escalation_after_help, ESCALATION_AFTER_HELP_EN, ESCALATION_AFTER_HELP_ES, ESCALATION_AFTER_HELP_CA, "  verdictan escalation list --since 24h\n  verdictan escalation list --since 24h --status queued --json\n  verdictan escalation get --escalation-id <id>\n  verdictan escalation claim --escalation-id <id>\n  verdictan escalation resolve --escalation-id <id> --resolution allow");
after_help_with_locale_consts!(gateway_after_help, GATEWAY_AFTER_HELP_EN, GATEWAY_AFTER_HELP_ES, GATEWAY_AFTER_HELP_CA, "  verdictan gateway list --json\n  verdictan gateway status --gateway-id <uuid>\n  verdictan gateway run --listen 127.0.0.1:8080 --upstream https://api.openai.com\n  verdictan gateway reload --gateway-id <uuid> --json");
after_help_with_locale_consts!(policy_after_help, POLICY_AFTER_HELP_EN, POLICY_AFTER_HELP_ES, POLICY_AFTER_HELP_CA, "  verdictan policy lint --file policy-config.yaml\n  verdictan policy test --file policy-config.yaml\n  # eu-ai-act is reporting-only: set policy.eu-ai-act and call POST /verdictan/compliance/report\n  # Do not put eu-ai-act in policies.chain (rejected with policy.reporting_only)");
after_help_with_locale_consts!(
    spend_after_help,
    SPEND_AFTER_HELP_EN,
    SPEND_AFTER_HELP_ES,
    SPEND_AFTER_HELP_CA,
    "  verdictan spend summary\n  verdictan spend summary --since 30d --json\n  verdictan spend budget list"
);
after_help_with_locale_consts!(export_jobs_after_help, EXPORT_JOBS_AFTER_HELP_EN, EXPORT_JOBS_AFTER_HELP_ES, EXPORT_JOBS_AFTER_HELP_CA, "  verdictan export-jobs create --since 7d --format csv\n  verdictan export-jobs create --since 30d --format compliance-all --wait\n  verdictan export-jobs list --json\n  verdictan export-jobs download --job-id <id> > events.csv");

const TOKEN_EXAMPLES: &str = "  verdictan token list --alerts-only\n  verdictan token create --name ci-bot --purpose gateway-runtime --key-class disposable --max-budget 25 --max-requests 500 --expires-in 24h\n  verdictan token get <id>\n  verdictan token clone <id> --reason incident-response --model-filter gpt-5.4-mini\n  verdictan token emergency-revoke <id> --reason credential-exposed --yes\n  verdictan token rotate <id>\n  verdictan token delete <id> --yes\n  printf 'vdt_xxx' | verdictan token validate";

pub const AUTH_LOGIN_AFTER_HELP_EN: &str = "\
Examples:
  # Interactive browser login (default when stdin is a terminal):
  verdictan auth login
  verdictan auth login --browser

  # Browser login to a named profile:
  verdictan auth login --browser --profile work

  # Direct credential login:
  verdictan auth login --email user@example.com --password secret

  # Non-interactive environments (CI / scripts):
  #   Set VERDICTAN_API_TOKEN or use a gateway key as an alternative to verdictan auth login.
  export VERDICTAN_API_TOKEN=vdt_...

  # Use self-hosted API + console origins:
  verdictan auth login --browser --api-url https://api.acme.com --console-url https://console.acme.com";

pub const AUTH_LOGIN_AFTER_HELP_ES: &str = "\
Ejemplos:
  # Inicio de sesión con navegador (predeterminado cuando stdin es un terminal):
  verdictan auth login
  verdictan auth login --browser

  # Inicio de sesión con navegador en un perfil con nombre:
  verdictan auth login --browser --profile work

  # Inicio de sesión directo con credenciales (flujo heredado):
  verdictan auth login --email user@example.com --password secret

  # Entornos no interactivos (CI / scripts):
  #   Define VERDICTAN_API_TOKEN o usa una clave de gateway.
  export VERDICTAN_API_TOKEN=vdt_...

  # Usar orígenes autoalojados de API + consola:
  verdictan auth login --browser --api-url https://api.acme.com --console-url https://console.acme.com";

pub const AUTH_LOGIN_AFTER_HELP_CA: &str = "\
Exemples:
  # Inici de sessió amb navegador (per defecte quan stdin és un terminal):
  verdictan auth login
  verdictan auth login --browser

  # Inici de sessió amb navegador en un perfil amb nom:
  verdictan auth login --browser --profile work

  # Inici de sessió directe amb credencials (flux heretat):
  verdictan auth login --email user@example.com --password secret

  # Entorns no interactius (CI / scripts):
  #   Defineix VERDICTAN_API_TOKEN o utilitza una clau de gateway.
  export VERDICTAN_API_TOKEN=vdt_...

  # Fer servir orígens autoallotjats d'API + consola:
  verdictan auth login --browser --api-url https://api.acme.com --console-url https://console.acme.com";

// ── after_help function generators (remaining without locale consts) ─────────

after_help_examples!(token_after_help, TOKEN_EXAMPLES);
after_help!(
    auth_login_after_help,
    AUTH_LOGIN_AFTER_HELP_EN,
    AUTH_LOGIN_AFTER_HELP_ES,
    AUTH_LOGIN_AFTER_HELP_CA
);

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
    use crate::i18n::Locale;

    // ── t() translation lookup ─────────────────────────────────────────

    #[test]
    fn t_cli_about_en() {
        assert_eq!(t(Locale::En, "cli.about"), Some("Verdictan CLI"));
    }

    #[test]
    fn t_cli_about_es() {
        assert_eq!(t(Locale::Es, "cli.about"), Some("CLI de Verdictan"));
    }

    #[test]
    fn t_cli_about_ca() {
        assert_eq!(t(Locale::Ca, "cli.about"), Some("CLI de Verdictan"));
    }

    #[test]
    fn t_examples_header_en() {
        assert_eq!(t(Locale::En, "cli.examples_header"), Some("Examples:"));
    }

    #[test]
    fn t_examples_header_es() {
        assert_eq!(t(Locale::Es, "cli.examples_header"), Some("Ejemplos:"));
    }

    #[test]
    fn t_examples_header_ca() {
        assert_eq!(t(Locale::Ca, "cli.examples_header"), Some("Exemples:"));
    }

    #[test]
    fn t_unknown_key_returns_none() {
        assert_eq!(t(Locale::En, "nonexistent"), None);
        assert_eq!(t(Locale::Es, "nonexistent"), None);
    }

    // ── after_help with locale consts ──────────────────────────────────

    #[test]
    fn control_after_help_en_starts_with_examples() {
        assert!(CONTROL_AFTER_HELP_EN.starts_with("Examples:"));
    }

    #[test]
    fn control_after_help_es_starts_with_ejemplos() {
        assert!(CONTROL_AFTER_HELP_ES.starts_with("Ejemplos:"));
    }

    #[test]
    fn control_after_help_ca_starts_with_exemples() {
        assert!(CONTROL_AFTER_HELP_CA.starts_with("Exemples:"));
    }

    #[test]
    fn control_after_help_contains_vdt_command() {
        assert!(CONTROL_AFTER_HELP_EN.contains("verdictan control"));
    }

    #[test]
    fn history_after_help_contains_vdt_command() {
        assert!(HISTORY_AFTER_HELP_EN.contains("verdictan history"));
    }

    #[test]
    fn secret_after_help_contains_vdt_command() {
        assert!(SECRET_AFTER_HELP_EN.contains("verdictan secret"));
    }

    #[test]
    fn role_after_help_contains_vdt_command() {
        assert!(ROLE_AFTER_HELP_EN.contains("verdictan role"));
    }

    #[test]
    fn iam_after_help_contains_vdt_command() {
        assert!(IAM_AFTER_HELP_EN.contains("verdictan iam"));
    }

    #[test]
    fn user_after_help_contains_vdt_command() {
        assert!(USER_AFTER_HELP_EN.contains("verdictan user"));
    }

    #[test]
    fn team_after_help_contains_vdt_command() {
        assert!(TEAM_AFTER_HELP_EN.contains("verdictan team"));
    }

    #[test]
    fn agent_after_help_contains_vdt_command() {
        assert!(AGENT_AFTER_HELP_EN.contains("verdictan agent"));
    }

    #[test]
    fn escalation_after_help_contains_vdt_command() {
        assert!(ESCALATION_AFTER_HELP_EN.contains("verdictan escalation"));
    }

    #[test]
    fn gateway_after_help_contains_vdt_command() {
        assert!(GATEWAY_AFTER_HELP_EN.contains("verdictan gateway"));
    }

    #[test]
    fn policy_after_help_marks_eu_ai_act_reporting_only() {
        assert!(POLICY_AFTER_HELP_EN.contains("verdictan policy lint"));
        assert!(POLICY_AFTER_HELP_EN.contains("eu-ai-act is reporting-only"));
        assert!(POLICY_AFTER_HELP_EN.contains("policy.reporting_only"));
        assert!(POLICY_AFTER_HELP_EN.contains("POST /verdictan/compliance/report"));
        assert!(POLICY_AFTER_HELP_EN.contains("rejected with policy.reporting_only"));
    }

    #[test]
    fn spend_after_help_contains_vdt_command() {
        assert!(SPEND_AFTER_HELP_EN.contains("verdictan spend"));
    }

    #[test]
    fn export_jobs_after_help_contains_vdt_command() {
        assert!(EXPORT_JOBS_AFTER_HELP_EN.contains("verdictan export-jobs"));
    }

    // ── locale consts are non-empty ────────────────────────────────────

    #[test]
    fn all_locale_consts_are_non_empty() {
        let consts: &[&str] = &[
            CONTROL_AFTER_HELP_EN,
            CONTROL_AFTER_HELP_ES,
            CONTROL_AFTER_HELP_CA,
            HISTORY_AFTER_HELP_EN,
            HISTORY_AFTER_HELP_ES,
            HISTORY_AFTER_HELP_CA,
            SECRET_AFTER_HELP_EN,
            SECRET_AFTER_HELP_ES,
            SECRET_AFTER_HELP_CA,
            ROLE_AFTER_HELP_EN,
            ROLE_AFTER_HELP_ES,
            ROLE_AFTER_HELP_CA,
            IAM_AFTER_HELP_EN,
            IAM_AFTER_HELP_ES,
            IAM_AFTER_HELP_CA,
            USER_AFTER_HELP_EN,
            USER_AFTER_HELP_ES,
            USER_AFTER_HELP_CA,
            TEAM_AFTER_HELP_EN,
            TEAM_AFTER_HELP_ES,
            TEAM_AFTER_HELP_CA,
            AGENT_AFTER_HELP_EN,
            AGENT_AFTER_HELP_ES,
            AGENT_AFTER_HELP_CA,
            ESCALATION_AFTER_HELP_EN,
            ESCALATION_AFTER_HELP_ES,
            ESCALATION_AFTER_HELP_CA,
            POLICY_AFTER_HELP_EN,
            POLICY_AFTER_HELP_ES,
            POLICY_AFTER_HELP_CA,
            SPEND_AFTER_HELP_EN,
            SPEND_AFTER_HELP_ES,
            SPEND_AFTER_HELP_CA,
            EXPORT_JOBS_AFTER_HELP_EN,
            EXPORT_JOBS_AFTER_HELP_ES,
            EXPORT_JOBS_AFTER_HELP_CA,
        ];
        for (i, c) in consts.iter().enumerate() {
            assert!(!c.is_empty(), "locale const at index {i} is empty");
        }
    }

    // ── auth login after_help consts ──────────────────────────────────

    #[test]
    fn auth_login_after_help_en_contains_vdt_auth() {
        assert!(AUTH_LOGIN_AFTER_HELP_EN.contains("verdictan auth login"));
        assert!(AUTH_LOGIN_AFTER_HELP_EN.contains("as an alternative to verdictan auth login"));
        assert!(!AUTH_LOGIN_AFTER_HELP_EN.contains("instead of"));
    }

    #[test]
    fn auth_login_after_help_es_contains_vdt_auth() {
        assert!(AUTH_LOGIN_AFTER_HELP_ES.contains("verdictan auth login"));
    }

    #[test]
    fn auth_login_after_help_ca_contains_vdt_auth() {
        assert!(AUTH_LOGIN_AFTER_HELP_CA.contains("verdictan auth login"));
    }

    // ── TOKEN_EXAMPLES constant ────────────────────────────────────────

    #[test]
    fn token_examples_contains_vdt_token() {
        assert!(TOKEN_EXAMPLES.contains("verdictan token"));
    }

    #[test]
    fn token_examples_non_empty() {
        assert!(!TOKEN_EXAMPLES.is_empty());
    }

    // ── runtime after_help functions ──────────────────────────────────

    #[test]
    fn control_after_help_fn_contains_examples_header() {
        let result = control_after_help();
        assert!(result.contains("verdictan control"));
    }

    #[test]
    fn token_after_help_fn_contains_examples_header() {
        let result = token_after_help();
        assert!(result.contains("verdictan token"));
    }

    #[test]
    fn history_after_help_fn_non_empty() {
        assert!(!history_after_help().is_empty());
    }

    #[test]
    fn spend_after_help_fn_non_empty() {
        assert!(!spend_after_help().is_empty());
    }
}
