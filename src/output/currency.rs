// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

const MINOR_UNITS: &[(&str, u32)] = &[
    ("USD", 2),
    ("EUR", 2),
    ("GBP", 2),
    ("JPY", 0),
    ("KWD", 3),
    ("BHD", 3),
];

fn minor_units(currency: &str) -> usize {
    MINOR_UNITS
        .iter()
        .find(|(code, _)| *code == currency)
        .map(|(_, units)| *units as usize)
        .unwrap_or(2)
}

fn currency_symbol(currency: &str) -> Option<&'static str> {
    match currency {
        "USD" => Some("$"),
        "EUR" => Some("€"),
        "GBP" => Some("£"),
        "JPY" => Some("¥"),
        _ => None,
    }
}

pub(crate) fn format_currency(amount: f64, currency: &str) -> String {
    let currency = currency.to_uppercase();
    let decimals = minor_units(&currency);

    match (currency_symbol(&currency), decimals) {
        (Some(symbol), 0) => format!("{symbol}{}", amount.round() as i64),
        (None, 0) => format!("{} {currency}", amount.round() as i64),
        (Some(symbol), decimals) => format!("{symbol}{amount:.decimals$}"),
        (None, decimals) => format!("{amount:.decimals$} {currency}"),
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

    #[test]
    fn format_currency_usd() {
        assert_eq!(format_currency(1.5, "USD"), "$1.50");
        assert_eq!(format_currency(0.0, "USD"), "$0.00");
    }

    #[test]
    fn format_currency_eur() {
        assert_eq!(format_currency(10.456, "EUR"), "€10.46");
    }

    #[test]
    fn format_currency_gbp() {
        assert_eq!(format_currency(99.1, "GBP"), "£99.10");
    }

    #[test]
    fn format_currency_jpy_zero_decimals() {
        assert_eq!(format_currency(1500.0, "JPY"), "¥1500");
        assert_eq!(format_currency(1500.7, "JPY"), "¥1501");
    }

    #[test]
    fn format_currency_kwd_three_decimals() {
        assert_eq!(format_currency(1.2346, "KWD"), "1.235 KWD");
        assert_eq!(format_currency(3.0, "KWD"), "3.000 KWD");
    }

    #[test]
    fn format_currency_bhd_three_decimals() {
        assert_eq!(format_currency(0.5, "BHD"), "0.500 BHD");
    }

    #[test]
    fn format_currency_unknown_code() {
        assert_eq!(format_currency(42.1, "CAD"), "42.10 CAD");
    }
}
