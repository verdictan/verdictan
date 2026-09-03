// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

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
fn audio_transcription_rejects_encoded_payload_above_contract_ceiling() {
    let encoded_audio = "A".repeat(AUDIO_TRANSCRIPTION_ENCODED_MAX_BYTES + 1);
    let body = serde_json::json!({
        "model": "gpt-4o-mini-transcribe",
        "input_audio": {
            "data": encoded_audio,
            "format": "mp3"
        }
    });

    let error = validate_audio_transcription_request(&body)
        .expect_err("encoded audio above the launch ceiling must fail");

    assert_eq!(error.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(error.code, "runtime.audio.encoded_size_exceeded");
    assert_eq!(
        error.details["max_bytes"],
        AUDIO_TRANSCRIPTION_ENCODED_MAX_BYTES
    );
}

#[test]
fn audio_transcription_rejects_decoded_payload_above_contract_ceiling() {
    let raw_audio = vec![0_u8; AUDIO_TRANSCRIPTION_DECODED_MAX_BYTES + 1];
    let encoded_audio = BASE64_STANDARD.encode(raw_audio);
    assert_eq!(encoded_audio.len(), AUDIO_TRANSCRIPTION_ENCODED_MAX_BYTES);

    let body = serde_json::json!({
        "model": "gpt-4o-mini-transcribe",
        "input_audio": {
            "data": encoded_audio,
            "format": "mp3"
        }
    });

    let error = validate_audio_transcription_request(&body)
        .expect_err("decoded audio above the launch ceiling must fail");

    assert_eq!(error.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(error.code, "runtime.audio.decoded_size_exceeded");
    assert_eq!(
        error.details["max_bytes"],
        AUDIO_TRANSCRIPTION_DECODED_MAX_BYTES
    );
}
