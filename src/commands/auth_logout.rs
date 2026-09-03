// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;

use crate::auth::credential_store;
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct AuthLogoutArgs {
    #[arg(long)]
    pub(crate) json: bool,

    #[arg(long, default_value = "default")]
    pub(crate) profile: String,
}

pub(crate) fn run(args: AuthLogoutArgs) -> Result<(), CliError> {
    let removed = credential_store::delete(Some(&args.profile))?;

    if args.json {
        return print_json(&logout_payload(&args.profile, removed));
    }

    println!("{}", logout_message(&args.profile, removed));
    Ok(())
}

fn logout_payload(profile: &str, removed: bool) -> serde_json::Value {
    serde_json::json!({
        "logged_out": removed,
        "profile": profile,
    })
}

fn logout_message(profile: &str, removed: bool) -> String {
    if removed {
        format!("cleared stored credentials for profile {profile}")
    } else {
        format!("no stored credentials for profile {profile}")
    }
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
    use crate::auth::credential_store::{self, StoredCredentials};
    use tempfile::tempdir;

    struct EnvGuard {
        verdictan_test_home: Option<std::ffi::OsString>,
        home: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn capture() -> Self {
            Self {
                verdictan_test_home: std::env::var_os("VERDICTAN_TEST_HOME"),
                home: std::env::var_os("HOME"),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.verdictan_test_home {
                Some(value) => std::env::set_var("VERDICTAN_TEST_HOME", value),
                None => std::env::remove_var("VERDICTAN_TEST_HOME"),
            }
            match &self.home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    fn sample_credentials() -> StoredCredentials {
        StoredCredentials {
            api_url: "https://api.example.com".to_string(),
            api_token: "vdt_secret".to_string(),
            expires_at: Some("2030-01-01T00:00:00Z".to_string()),
            org_id: "org_123".to_string(),
            org_name: "Verdictan".to_string(),
            org_slug: Some("verdictan".to_string()),
            project_id: "proj_123".to_string(),
            role: "owner".to_string(),
            user_id: Some("user_123".to_string()),
            email: Some("owner@example.com".to_string()),
            display_name: Some("Owner".to_string()),
            team_ids: vec!["team_1".to_string()],
            capabilities: vec!["gateway:write".to_string()],
        }
    }

    #[test]
    fn logout_payload_contains_expected_fields() {
        assert_eq!(
            logout_payload("workspace", true),
            serde_json::json!({
                "logged_out": true,
                "profile": "workspace",
            })
        );
    }

    #[test]
    fn logout_message_covers_removed_and_missing_profiles() {
        assert_eq!(
            logout_message("workspace", true),
            "cleared stored credentials for profile workspace"
        );
        assert_eq!(
            logout_message("workspace", false),
            "no stored credentials for profile workspace"
        );
    }

    #[test]
    fn run_removes_credentials_when_present() {
        let _lock = crate::config::test_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _guard = EnvGuard::capture();
        let temp = tempdir().expect("tempdir");
        std::env::set_var("VERDICTAN_TEST_HOME", temp.path());
        std::env::set_var("HOME", temp.path());

        credential_store::save(Some("workspace"), sample_credentials()).expect("save credentials");

        run(AuthLogoutArgs {
            json: true,
            profile: "workspace".to_string(),
        })
        .expect("logout succeeds");

        let store_path = temp.path().join(".verdictan").join("credentials.json");
        let store: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(store_path).expect("read store"))
                .expect("parse store");
        assert!(store["profiles"]["workspace"].is_null());
    }

    #[test]
    fn run_succeeds_when_profile_is_missing() {
        let _lock = crate::config::test_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _guard = EnvGuard::capture();
        let temp = tempdir().expect("tempdir");
        std::env::set_var("VERDICTAN_TEST_HOME", temp.path());
        std::env::set_var("HOME", temp.path());

        run(AuthLogoutArgs {
            json: false,
            profile: "missing".to_string(),
        })
        .expect("logout succeeds");
    }

    #[test]
    fn logout_payload_removed_false() {
        let payload = logout_payload("prod", false);
        assert_eq!(payload["logged_out"], false);
        assert_eq!(payload["profile"], "prod");
    }

    #[test]
    fn logout_message_various_profiles() {
        assert_eq!(
            logout_message("default", true),
            "cleared stored credentials for profile default"
        );
        assert_eq!(
            logout_message("staging", false),
            "no stored credentials for profile staging"
        );
    }

    #[test]
    fn args_debug_impl() {
        let args = AuthLogoutArgs {
            json: true,
            profile: "workspace".to_string(),
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("AuthLogoutArgs"));
        assert!(debug.contains("workspace"));
    }
}
