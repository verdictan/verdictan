// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Authentication translation keys for the CLI.
//!
//! Covers password login, browser/handoff OAuth, and API-level auth errors.

use super::Locale;

pub(crate) fn t(locale: Locale, key: &str) -> Option<&'static str> {
    Some(match (locale, key) {
        // ── password login ────────────────────────────────────────────────────
        (Locale::Es, "auth.login_failed_401") => "inicio de sesión fallido (401)",
        (Locale::Ca, "auth.login_failed_401") => "ha fallat l'inici de sessió (401)",
        (_, "auth.login_failed_401") => "login failed (401)",

        // ── browser / handoff OAuth (AUTH-020..024) ───────────────────────────
        (Locale::Es, "auth.browser_opening") => "Abriendo el navegador para autenticarse...",
        (Locale::Ca, "auth.browser_opening") => "Obrint el navegador per autenticar-se...",
        (_, "auth.browser_opening") => "Opening browser for authentication...",

        (Locale::Es, "auth.browser_waiting") => {
            "Esperando la autenticación (tiempo de espera: 5 minutos)..."
        }
        (Locale::Ca, "auth.browser_waiting") => {
            "Esperant l'autenticació (temps d'espera: 5 minuts)..."
        }
        (_, "auth.browser_waiting") => "Waiting for authentication (timeout: 5 minutes)...",

        (Locale::Es, "auth.browser_success") => "¡Autenticación exitosa!",
        (Locale::Ca, "auth.browser_success") => "Autenticació correcta!",
        (_, "auth.browser_success") => "Authentication successful!",

        (Locale::Es, "auth.browser_timeout") => "Tiempo de espera de autenticación agotado",
        (Locale::Ca, "auth.browser_timeout") => {
            "S'ha esgotat el temps d'espera d'autenticació"
        }
        (_, "auth.browser_timeout") => "Authentication timed out",

        (Locale::Es, "auth.browser_state_mismatch") => {
            "error de seguridad: el parámetro state no coincide"
        }
        (Locale::Ca, "auth.browser_state_mismatch") => {
            "error de seguretat: el paràmetre state no coincideix"
        }
        (_, "auth.browser_state_mismatch") => "security error: state parameter mismatch",

        (Locale::Es, "auth.browser_access_denied") => {
            "la autenticación en el navegador fue denegada"
        }
        (Locale::Ca, "auth.browser_access_denied") => {
            "l'autenticació al navegador ha estat denegada"
        }
        (_, "auth.browser_access_denied") => "browser authentication was denied",

        (Locale::Es, "auth.browser_failed_reason") => {
            "la autenticación en el navegador falló: {0}"
        }
        (Locale::Ca, "auth.browser_failed_reason") => {
            "l'autenticació al navegador ha fallat: {0}"
        }
        (_, "auth.browser_failed_reason") => "browser authentication failed: {0}",

        (Locale::Es, "auth.browser_manual_open") => {
            "No se pudo abrir el navegador automáticamente. Visita:\n  {0}"
        }
        (Locale::Ca, "auth.browser_manual_open") => {
            "No s'ha pogut obrir el navegador automàticament. Visita:\n  {0}"
        }
        (_, "auth.browser_manual_open") => {
            "Could not open browser automatically. Please visit:\n  {0}"
        }

        (Locale::Es, "auth.console_url_invalid") => {
            "--console-url debe ser una URL absoluta http o https"
        }
        (Locale::Ca, "auth.console_url_invalid") => {
            "--console-url ha de ser una URL absoluta http o https"
        }
        (_, "auth.console_url_invalid") => "--console-url must be an absolute http or https URL",

        (Locale::Es, "auth.console_url_https_required") => {
            "--console-url debe usar https, salvo para destinos localhost"
        }
        (Locale::Ca, "auth.console_url_https_required") => {
            "--console-url ha d'utilitzar https, excepte per a destinacions localhost"
        }
        (_, "auth.console_url_https_required") => {
            "--console-url must use https unless it points to localhost"
        }

        (Locale::Es, "auth.console_url_host_mismatch") => {
            "--console-url debe coincidir con el origen de la consola configurada para esta API"
        }
        (Locale::Ca, "auth.console_url_host_mismatch") => {
            "--console-url ha de coincidir amb l'origen de consola configurat per a aquesta API"
        }
        (_, "auth.console_url_host_mismatch") => {
            "--console-url must match the console origin configured for this API"
        }

        (Locale::Es, "auth.not_a_terminal") => {
            "la entrada no es un terminal — usa VERDICTAN_API_TOKEN o una clave de gateway para autenticación no interactiva"
        }
        (Locale::Ca, "auth.not_a_terminal") => {
            "l'entrada no és un terminal — utilitza VERDICTAN_API_TOKEN o una clau de gateway per a autenticació no interactiva"
        }
        (_, "auth.not_a_terminal") => {
            "not a terminal — use VERDICTAN_API_TOKEN or a gateway key for non-interactive auth"
        }

        (Locale::Es, "auth.login_choose_method") => {
            "elige --browser o --email/--password, pero no ambos"
        }
        (Locale::Ca, "auth.login_choose_method") => {
            "tria --browser o --email/--password, però no ambdós"
        }
        (_, "auth.login_choose_method") => "choose either --browser or --email/--password",

        (Locale::Es, "auth.login_password_requires_both") => {
            "proporciona tanto --email como --password para el inicio de sesión con credenciales"
        }
        (Locale::Ca, "auth.login_password_requires_both") => {
            "proporciona tant --email com --password per a l'inici de sessió amb credencials"
        }
        (_, "auth.login_password_requires_both") => {
            "provide both --email and --password for direct credential login"
        }

        (Locale::Es, "auth.handoff_redeem_failed_401") => {
            "el canje del código de autenticación falló (401)"
        }
        (Locale::Ca, "auth.handoff_redeem_failed_401") => {
            "el bescanvi del codi d'autenticació ha fallat (401)"
        }
        (_, "auth.handoff_redeem_failed_401") => "authentication code redemption failed (401)",

        (Locale::Es, "auth.handoff_redeem_invalid_422") => {
            "código de autenticación no válido o caducado (422)"
        }
        (Locale::Ca, "auth.handoff_redeem_invalid_422") => {
            "codi d'autenticació no vàlid o caducat (422)"
        }
        (_, "auth.handoff_redeem_invalid_422") => "invalid or expired authentication code (422)",

        // ── API-level auth errors ─────────────────────────────────────────────
        (Locale::Es, "auth.api_authentication_failed_401") => {
            "la autenticación de la API falló (401)"
        }
        (Locale::Ca, "auth.api_authentication_failed_401") => {
            "l'autenticació de l'API ha fallat (401)"
        }
        (_, "auth.api_authentication_failed_401") => "api authentication failed (401)",

        (Locale::Es, "auth.api_authorization_failed_403") => {
            "la autorización de la API falló (403)"
        }
        (Locale::Ca, "auth.api_authorization_failed_403") => {
            "l'autorització de l'API ha fallat (403)"
        }
        (_, "auth.api_authorization_failed_403") => "api authorization failed (403)",

        (Locale::Es, "auth.missing_api_token") => {
            "falta el token de la API (define VERDICTAN_API_TOKEN o ejecuta `verdictan auth login`)"
        }
        (Locale::Ca, "auth.missing_api_token") => {
            "falta el token de l'API (defineix VERDICTAN_API_TOKEN o executa `verdictan auth login`)"
        }
        (_, "auth.missing_api_token") => {
            "missing api token (set VERDICTAN_API_TOKEN or run `verdictan auth login`)"
        }

        _ => return None,
    })
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

    const ALL_LOCALES: [Locale; 3] = [Locale::En, Locale::Es, Locale::Ca];
    const ALL_AUTH_KEYS: &[&str] = &[
        "auth.login_failed_401",
        "auth.browser_opening",
        "auth.browser_waiting",
        "auth.browser_success",
        "auth.browser_timeout",
        "auth.browser_state_mismatch",
        "auth.browser_access_denied",
        "auth.browser_failed_reason",
        "auth.browser_manual_open",
        "auth.console_url_invalid",
        "auth.console_url_https_required",
        "auth.console_url_host_mismatch",
        "auth.not_a_terminal",
        "auth.login_choose_method",
        "auth.login_password_requires_both",
        "auth.handoff_redeem_failed_401",
        "auth.handoff_redeem_invalid_422",
        "auth.api_authentication_failed_401",
        "auth.api_authorization_failed_403",
        "auth.missing_api_token",
    ];

    #[test]
    fn auth_login_failed_localized() {
        assert_eq!(
            t(Locale::En, "auth.login_failed_401"),
            Some("login failed (401)")
        );
        assert!(t(Locale::Es, "auth.login_failed_401").is_some());
        assert!(t(Locale::Ca, "auth.login_failed_401").is_some());
    }

    #[test]
    fn auth_browser_opening_localized() {
        assert_eq!(
            t(Locale::En, "auth.browser_opening"),
            Some("Opening browser for authentication...")
        );
        assert!(t(Locale::Es, "auth.browser_opening").is_some());
        assert!(t(Locale::Ca, "auth.browser_opening").is_some());
    }

    #[test]
    fn auth_browser_success_localized() {
        assert_eq!(
            t(Locale::En, "auth.browser_success"),
            Some("Authentication successful!")
        );
        assert!(t(Locale::Es, "auth.browser_success").is_some());
        assert!(t(Locale::Ca, "auth.browser_success").is_some());
    }

    #[test]
    fn auth_browser_timeout_localized() {
        assert_eq!(
            t(Locale::En, "auth.browser_timeout"),
            Some("Authentication timed out")
        );
        assert!(t(Locale::Es, "auth.browser_timeout").is_some());
    }

    #[test]
    fn auth_browser_state_mismatch_localized() {
        assert_eq!(
            t(Locale::En, "auth.browser_state_mismatch"),
            Some("security error: state parameter mismatch")
        );
    }

    #[test]
    fn auth_api_authentication_failed_localized() {
        assert_eq!(
            t(Locale::En, "auth.api_authentication_failed_401"),
            Some("api authentication failed (401)")
        );
        assert!(t(Locale::Es, "auth.api_authentication_failed_401").is_some());
        assert!(t(Locale::Ca, "auth.api_authentication_failed_401").is_some());
    }

    #[test]
    fn auth_api_authorization_failed_localized() {
        assert_eq!(
            t(Locale::En, "auth.api_authorization_failed_403"),
            Some("api authorization failed (403)")
        );
    }

    #[test]
    fn auth_missing_api_token_localized() {
        let en = t(Locale::En, "auth.missing_api_token").unwrap();
        assert!(en.contains("VERDICTAN_API_TOKEN"));
        assert!(en.contains("verdictan auth login"));
        assert!(t(Locale::Es, "auth.missing_api_token").is_some());
        assert!(t(Locale::Ca, "auth.missing_api_token").is_some());
    }

    #[test]
    fn auth_not_a_terminal_localized() {
        let en = t(Locale::En, "auth.not_a_terminal").unwrap();
        assert!(en.contains("VERDICTAN_API_TOKEN"));
        assert!(t(Locale::Es, "auth.not_a_terminal").is_some());
    }

    #[test]
    fn auth_login_choose_method_localized() {
        let en = t(Locale::En, "auth.login_choose_method").unwrap();
        assert!(en.contains("--browser"));
        assert!(en.contains("--email/--password"));
    }

    #[test]
    fn auth_console_url_invalid_localized() {
        let en = t(Locale::En, "auth.console_url_invalid").unwrap();
        assert!(en.contains("--console-url"));
    }

    #[test]
    fn auth_handoff_redeem_failed_localized() {
        assert_eq!(
            t(Locale::En, "auth.handoff_redeem_failed_401"),
            Some("authentication code redemption failed (401)")
        );
    }

    #[test]
    fn all_auth_keys_exist_in_all_locales() {
        for locale in ALL_LOCALES {
            for key in ALL_AUTH_KEYS {
                assert!(
                    t(locale, key).is_some(),
                    "missing auth translation for {:?} / {}",
                    locale,
                    key
                );
            }
        }
    }

    #[test]
    fn unknown_key_returns_none() {
        assert!(t(Locale::En, "auth.nonexistent").is_none());
        assert!(t(Locale::Es, "").is_none());
    }
}
