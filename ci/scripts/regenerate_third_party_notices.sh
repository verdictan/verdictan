#!/usr/bin/env bash
# Regenerate THIRD_PARTY_NOTICES.md from Cargo.lock via cargo-about.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${root}"

readonly cargo_about_version='0.6.6'
readonly output='THIRD_PARTY_NOTICES.md'

cargo install cargo-about --version "${cargo_about_version}" --locked --quiet

cargo about generate about.hbs -o "${output}"

echo "regenerate_third_party_notices.sh: wrote ${output}"
