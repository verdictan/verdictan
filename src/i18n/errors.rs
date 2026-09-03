// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Error-prefix and network/internal error translation keys for the CLI.
//!
//! Covers CliError category labels (`error.*`), network transport errors
//! (`network.*`), internal runtime errors (`internal.*`), and user-facing API
//! error summaries (`user.*`).
//!
//! New key added in I18N-023: `internal.runtime_failed`.

use super::Locale;

pub(crate) fn t(locale: Locale, key: &str) -> Option<&'static str> {
    Some(match (locale, key) {
        // ── CliError human-readable category prefixes ─────────────────────────
        (Locale::Es, "error.user") => "Error:",
        (Locale::Ca, "error.user") => "Error:",
        (_, "error.user") => "Error:",

        (Locale::Es, "error.auth") => "Error de autenticación:",
        (Locale::Ca, "error.auth") => "Error d'autenticació:",
        (_, "error.auth") => "Authentication error:",

        (Locale::Es, "error.network") => "Error de red:",
        (Locale::Ca, "error.network") => "Error de xarxa:",
        (_, "error.network") => "Network error:",

        (Locale::Es, "error.internal") => "Error interno:",
        (Locale::Ca, "error.internal") => "Error intern:",
        (_, "error.internal") => "Internal error:",

        (Locale::Es, "error.gateway") => "Error de gateway:",
        (Locale::Ca, "error.gateway") => "Error de gateway:",
        (_, "error.gateway") => "Gateway error:",

        // ── user-visible configuration / token errors ─────────────────────────
        (Locale::Es, "user.api_base_url_empty") => "la URL base de la API está vacía",
        (Locale::Ca, "user.api_base_url_empty") => "l'URL base de l'API és buida",
        (_, "user.api_base_url_empty") => "api base url is empty",

        (Locale::Es, "user.api_token_invalid_header_characters") => {
            "el token de la API contiene caracteres de cabecera no válidos"
        }
        (Locale::Ca, "user.api_token_invalid_header_characters") => {
            "el token de l'API conté caràcters de capçalera no vàlids"
        }
        (_, "user.api_token_invalid_header_characters") => {
            "api token contains invalid header characters"
        }

        (Locale::Es, "user.token_invalid_header_characters") => {
            "el token contiene caracteres de cabecera no válidos"
        }
        (Locale::Ca, "user.token_invalid_header_characters") => {
            "el token conté caràcters de capçalera no vàlids"
        }
        (_, "user.token_invalid_header_characters") => "token contains invalid header characters",

        // ── user-visible API response status errors ───────────────────────────
        (Locale::Es, "user.login_validation_failed_422") => {
            "la validación del inicio de sesión falló (422)"
        }
        (Locale::Ca, "user.login_validation_failed_422") => {
            "la validació de l'inici de sessió ha fallat (422)"
        }
        (_, "user.login_validation_failed_422") => "login validation failed (422)",

        (Locale::Es, "user.api_validation_failed_422") => "la validación de la API falló (422)",
        (Locale::Ca, "user.api_validation_failed_422") => "la validació de l'API ha fallat (422)",
        (_, "user.api_validation_failed_422") => "api validation failed (422)",

        (Locale::Es, "user.api_resource_not_found_404") => {
            "no se encontró el recurso de la API (404)"
        }
        (Locale::Ca, "user.api_resource_not_found_404") => {
            "no s'ha trobat el recurs de l'API (404)"
        }
        (_, "user.api_resource_not_found_404") => "api resource not found (404)",

        (Locale::Es, "user.api_conflict_409") => "conflicto en la API (409)",
        (Locale::Ca, "user.api_conflict_409") => "conflicte a l'API (409)",
        (_, "user.api_conflict_409") => "api conflict (409)",

        // ── network transport errors ──────────────────────────────────────────
        (Locale::Es, "network.login_request_failed_status") => {
            "la solicitud de inicio de sesión falló con estado {0}"
        }
        (Locale::Ca, "network.login_request_failed_status") => {
            "la sol·licitud d'inici de sessió ha fallat amb estat {0}"
        }
        (_, "network.login_request_failed_status") => "login request failed with status {0}",

        (Locale::Es, "network.api_request_failed_status") => {
            "la solicitud a la API falló con estado {0}"
        }
        (Locale::Ca, "network.api_request_failed_status") => {
            "la sol·licitud a l'API ha fallat amb estat {0}"
        }
        (_, "network.api_request_failed_status") => "api request failed with status {0}",

        (Locale::Es, "network.request_timed_out") => "la solicitud agotó el tiempo de espera",
        (Locale::Ca, "network.request_timed_out") => "la sol·licitud ha esgotat el temps d'espera",
        (_, "network.request_timed_out") => "request timed out",

        (Locale::Es, "network.failed_to_connect_api") => "no se pudo conectar con la API",
        (Locale::Ca, "network.failed_to_connect_api") => "no s'ha pogut connectar amb l'API",
        (_, "network.failed_to_connect_api") => "failed to connect to api",

        (Locale::Es, "network.http_error") => "error HTTP: {0}",
        (Locale::Ca, "network.http_error") => "error HTTP: {0}",
        (_, "network.http_error") => "http error: {0}",

        // ── internal / runtime errors ─────────────────────────────────────────
        (Locale::Es, "internal.failed_to_build_http_client") => {
            "no se pudo crear el cliente HTTP: {0}"
        }
        (Locale::Ca, "internal.failed_to_build_http_client") => {
            "no s'ha pogut crear el client HTTP: {0}"
        }
        (_, "internal.failed_to_build_http_client") => "failed to build http client: {0}",

        // I18N-023: async runtime initialisation failure (seen in many commands)
        (Locale::Es, "internal.runtime_failed") => {
            "no se pudo crear el tiempo de ejecución asíncrono: {0}"
        }
        (Locale::Ca, "internal.runtime_failed") => {
            "no s'ha pogut crear el temps d'execució asíncron: {0}"
        }
        (_, "internal.runtime_failed") => "failed to create async runtime: {0}",

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
    const ALL_ERROR_KEYS: &[&str] = &[
        "error.user",
        "error.auth",
        "error.network",
        "error.internal",
        "error.gateway",
        "user.api_base_url_empty",
        "user.api_token_invalid_header_characters",
        "user.token_invalid_header_characters",
        "user.login_validation_failed_422",
        "user.api_validation_failed_422",
        "user.api_resource_not_found_404",
        "user.api_conflict_409",
        "network.login_request_failed_status",
        "network.api_request_failed_status",
        "network.request_timed_out",
        "network.failed_to_connect_api",
        "network.http_error",
        "internal.failed_to_build_http_client",
        "internal.runtime_failed",
    ];

    #[test]
    fn error_user_available_in_all_locales() {
        assert_eq!(t(Locale::En, "error.user"), Some("Error:"));
        assert_eq!(t(Locale::Es, "error.user"), Some("Error:"));
        assert_eq!(t(Locale::Ca, "error.user"), Some("Error:"));
    }

    #[test]
    fn error_auth_localized() {
        assert_eq!(t(Locale::En, "error.auth"), Some("Authentication error:"));
        assert_eq!(t(Locale::Es, "error.auth"), Some("Error de autenticación:"));
        assert_eq!(t(Locale::Ca, "error.auth"), Some("Error d'autenticació:"));
    }

    #[test]
    fn error_network_localized() {
        assert_eq!(t(Locale::En, "error.network"), Some("Network error:"));
        assert_eq!(t(Locale::Es, "error.network"), Some("Error de red:"));
        assert_eq!(t(Locale::Ca, "error.network"), Some("Error de xarxa:"));
    }

    #[test]
    fn error_internal_localized() {
        assert_eq!(t(Locale::En, "error.internal"), Some("Internal error:"));
        assert_eq!(t(Locale::Es, "error.internal"), Some("Error interno:"));
        assert_eq!(t(Locale::Ca, "error.internal"), Some("Error intern:"));
    }

    #[test]
    fn error_gateway_localized() {
        assert_eq!(t(Locale::En, "error.gateway"), Some("Gateway error:"));
        assert_eq!(t(Locale::Es, "error.gateway"), Some("Error de gateway:"));
    }

    #[test]
    fn user_api_base_url_empty_localized() {
        assert_eq!(
            t(Locale::En, "user.api_base_url_empty"),
            Some("api base url is empty")
        );
        assert!(t(Locale::Es, "user.api_base_url_empty").is_some());
        assert!(t(Locale::Ca, "user.api_base_url_empty").is_some());
    }

    #[test]
    fn network_request_timed_out_localized() {
        assert_eq!(
            t(Locale::En, "network.request_timed_out"),
            Some("request timed out")
        );
        assert!(t(Locale::Es, "network.request_timed_out").is_some());
        assert!(t(Locale::Ca, "network.request_timed_out").is_some());
    }

    #[test]
    fn internal_runtime_failed_localized() {
        assert_eq!(
            t(Locale::En, "internal.runtime_failed"),
            Some("failed to create async runtime: {0}")
        );
        assert!(t(Locale::Es, "internal.runtime_failed").is_some());
        assert!(t(Locale::Ca, "internal.runtime_failed").is_some());
    }

    #[test]
    fn all_error_keys_exist_in_all_locales() {
        for locale in ALL_LOCALES {
            for key in ALL_ERROR_KEYS {
                assert!(
                    t(locale, key).is_some(),
                    "missing error translation for {:?} / {}",
                    locale,
                    key
                );
            }
        }
    }

    #[test]
    fn unknown_key_returns_none() {
        assert!(t(Locale::En, "nonexistent.key").is_none());
        assert!(t(Locale::Es, "").is_none());
    }
}
