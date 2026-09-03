#!/usr/bin/env bash
# Add SPDX BUSL-1.1 headers to Rust sources under src/ (idempotent).
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${root}"

header=$'// Copyright (c) Verdictan.com\n// SPDX-License-Identifier: BUSL-1.1\n\n'

updated=0
skipped=0

while IFS= read -r -d '' file; do
  if head -n 5 "${file}" | grep -Fq 'SPDX-License-Identifier: BUSL-1.1'; then
    skipped=$((skipped + 1))
    continue
  fi

  tmp="$(mktemp)"
  printf '%s' "${header}" > "${tmp}"
  cat "${file}" >> "${tmp}"
  mv "${tmp}" "${file}"
  updated=$((updated + 1))
done < <(find src -type f -name '*.rs' -print0)

echo "apply_spdx_headers.sh: updated ${updated} file(s), skipped ${skipped} already stamped file(s)"
