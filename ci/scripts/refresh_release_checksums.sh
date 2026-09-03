#!/usr/bin/env bash
set -euo pipefail

artifacts_dir="${1:-}"
if [[ ! -d "$artifacts_dir" ]]; then
  echo "refresh_release_checksums.sh: missing directory: ${artifacts_dir}" >&2
  exit 1
fi

(
  cd "$artifacts_dir"
  find . -maxdepth 1 -type f \
    ! -name '*.sha256' \
    ! -name '*.sigstore.json' \
    ! -name 'sha256.sum' \
    ! -name 'reproducibility.json' \
    -printf '%f\n' |
    LC_ALL=C sort |
    while IFS= read -r file; do
      sha256sum "$file"
    done > sha256.sum
)

echo 'refresh_release_checksums.sh: regenerated sha256.sum.'
