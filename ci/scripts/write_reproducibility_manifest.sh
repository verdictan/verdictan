#!/usr/bin/env bash
set -euo pipefail

artifacts_dir="${1:-}"
output="${2:-${artifacts_dir}/reproducibility.json}"
if [[ ! -d "$artifacts_dir" ]]; then
  echo "write_reproducibility_manifest.sh: missing directory: ${artifacts_dir}" >&2
  exit 1
fi
if [[ ! "${SOURCE_DATE_EPOCH:-}" =~ ^[0-9]+$ ]]; then
  echo 'write_reproducibility_manifest.sh: SOURCE_DATE_EPOCH must be an integer.' >&2
  exit 1
fi

hashes="$(
  cd "$artifacts_dir"
  find . -maxdepth 1 -type f \
    ! -name '*.sigstore.json' \
    ! -name 'reproducibility.json' \
    -printf '%f\n' |
    LC_ALL=C sort |
    while IFS= read -r file; do
      jq -n --arg name "$file" --arg sha256 "$(sha256sum "$file" | awk '{print $1}')" \
        '{name: $name, sha256: $sha256}'
    done |
    jq -s .
)"

jq -n \
  --arg schemaVersion '1' \
  --arg tag "${RELEASE_TAG:?RELEASE_TAG is required}" \
  --arg commit "$(git rev-parse HEAD)" \
  --arg sourceDateEpoch "$SOURCE_DATE_EPOCH" \
  --arg rustc "$(rustc --version)" \
  --arg cargo "$(cargo --version)" \
  --arg cargoDist "$(dist --version)" \
  --argjson artifacts "$hashes" \
  '{
    schemaVersion: ($schemaVersion | tonumber),
    source: {
      tag: $tag,
      commit: $commit,
      sourceDateEpoch: ($sourceDateEpoch | tonumber)
    },
    environment: {
      timezone: "UTC",
      locale: "C",
      sourcePath: "/build/verdictan",
      rustc: $rustc,
      cargo: $cargo,
      cargoDist: $cargoDist
    },
    artifacts: $artifacts
  }' > "$output"

echo "write_reproducibility_manifest.sh: wrote ${output}."
