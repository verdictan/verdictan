// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::sync::LazyLock;
use std::time::Duration;

static SHARED_GATEWAY_HTTP_CLIENT: LazyLock<Result<reqwest::Client, String>> =
    LazyLock::new(|| {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .pool_idle_timeout(Duration::from_secs(90))
            .user_agent(concat!("verdictan-gateway/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| error.to_string())
    });

pub(crate) fn shared_gateway_http_client() -> Result<reqwest::Client, String> {
    SHARED_GATEWAY_HTTP_CLIENT
        .as_ref()
        .cloned()
        .map_err(ToString::to_string)
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
    fn shared_gateway_http_client_returns_ok() {
        let result = shared_gateway_http_client();
        assert!(result.is_ok());
    }

    #[test]
    fn shared_gateway_http_client_is_idempotent() {
        let a = shared_gateway_http_client().expect("first call");
        let b = shared_gateway_http_client().expect("second call");
        assert_eq!(
            format!("{a:?}"),
            format!("{b:?}"),
            "repeated calls return the same client"
        );
    }
}
