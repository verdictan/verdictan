#!/usr/bin/env bash
# Optional wrapper for canonical or isolated target/ layout.
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <command>" >&2
  echo "example: $0 'cargo check --tests'" >&2
  exit 1
fi

readonly script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly package_root="$(cd "${script_dir}/../.." && pwd)"
readonly command="$*"

if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
  case "${CARGO_TARGET_DIR}" in
    /*) cargo_target="${CARGO_TARGET_DIR}" ;;
    *) cargo_target="${package_root}/${CARGO_TARGET_DIR}" ;;
  esac
elif [[ "${VERDICTAN_ISOLATED_CARGO_TARGET:-}" == "1" ]]; then
  isolated_suffix=""
  if [[ -n "${VERDICTAN_ISOLATED_CARGO_TARGET_SUFFIX:-}" ]]; then
    if [[ ! "${VERDICTAN_ISOLATED_CARGO_TARGET_SUFFIX}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] ||
      [[ "${VERDICTAN_ISOLATED_CARGO_TARGET_SUFFIX}" == *..* ]]; then
      echo "[host-run] VERDICTAN_ISOLATED_CARGO_TARGET_SUFFIX has invalid characters" >&2
      exit 1
    fi
    isolated_suffix=".${VERDICTAN_ISOLATED_CARGO_TARGET_SUFFIX}"
  fi
  cargo_target="${package_root}/.tmp/cargo-isolated-cli${isolated_suffix}"
else
  cargo_target="${package_root}/target"
fi

if ! mkdir -p "${cargo_target}" 2>/dev/null || ! touch "${cargo_target}/.write-test" 2>/dev/null; then
  echo "[host-run] CARGO_TARGET_DIR is not writable: ${cargo_target}" >&2
  exit 1
fi
rm -f "${cargo_target}/.write-test"

export CARGO_TARGET_DIR="$(cd "${cargo_target}" && pwd -P)"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-1}"
export CARGO_PROFILE_DEV_DEBUG="${CARGO_PROFILE_DEV_DEBUG:-0}"
export CARGO_PROFILE_TEST_DEBUG="${CARGO_PROFILE_TEST_DEBUG:-0}"
export CARGO_PROFILE_DEV_SPLIT_DEBUGINFO="${CARGO_PROFILE_DEV_SPLIT_DEBUGINFO:-off}"
export CARGO_PROFILE_TEST_SPLIT_DEBUGINFO="${CARGO_PROFILE_TEST_SPLIT_DEBUGINFO:-off}"
export COVERAGE_DIR="${COVERAGE_DIR:-${package_root}/coverage/cli}"

if [[ -z "${CARGO_BUILD_JOBS:-}" ]] && command -v nproc >/dev/null 2>&1; then
  export CARGO_BUILD_JOBS="$(nproc)"
fi

cd "${package_root}"
exec bash -c "${command}"
