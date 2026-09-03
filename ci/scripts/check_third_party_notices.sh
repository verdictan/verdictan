#!/usr/bin/env bash
# Fail when THIRD_PARTY_NOTICES.md is stale relative to Cargo.lock.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${root}"

readonly output='THIRD_PARTY_NOTICES.md'
readonly cargo_about_version='0.6.6'
tmp="$(mktemp)"
inventory_tmp="$(mktemp)"
inventory_out="$(mktemp)"
trap 'rm -f "${tmp}" "${inventory_tmp}" "${inventory_out}"' EXIT

cargo install cargo-about --version "${cargo_about_version}" --locked --quiet
cargo about generate about.hbs -o "${tmp}"

awk '/^## Dependency inventory/,/^## License texts/' "${tmp}" > "${inventory_tmp}"
awk '/^## Dependency inventory/,/^## License texts/' "${output}" > "${inventory_out}"

if ! diff -u "${inventory_out}" "${inventory_tmp}"; then
  echo "check_third_party_notices.sh: ${output} dependency inventory is stale; run bash ci/scripts/regenerate_third_party_notices.sh" >&2
  exit 1
fi

echo "check_third_party_notices.sh: ${output} matches Cargo.lock"
