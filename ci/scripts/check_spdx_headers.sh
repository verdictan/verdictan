#!/usr/bin/env bash
# Verify SPDX BUSL-1.1 headers on all Rust sources under src/.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${root}"

required_spdx='SPDX-License-Identifier: BUSL-1.1'
required_copyright='Copyright (c) Verdictan.com'

missing=0
while IFS= read -r -d '' file; do
  head -n 5 "${file}" | grep -Fq "${required_spdx}" || {
    echo "missing SPDX header: ${file#${root}/}" >&2
    missing=1
  }
  head -n 5 "${file}" | grep -Fq "${required_copyright}" || {
    echo "missing copyright header: ${file#${root}/}" >&2
    missing=1
  }
done < <(find src -type f -name '*.rs' -print0)

if [[ "${missing}" -ne 0 ]]; then
  echo "check_spdx_headers.sh: run bash ci/scripts/apply_spdx_headers.sh" >&2
  exit 1
fi

echo "check_spdx_headers.sh: all src/**/*.rs files have SPDX headers"
