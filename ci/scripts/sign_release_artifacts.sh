#!/usr/bin/env bash
set -euo pipefail

artifacts_dir="${1:-artifacts}"
if [[ ! -d "$artifacts_dir" ]]; then
  echo "sign_release_artifacts.sh: missing directory: ${artifacts_dir}" >&2
  exit 1
fi
: "${COSIGN_PRIVATE_KEY:?COSIGN_PRIVATE_KEY is required}"
: "${COSIGN_PASSWORD:?COSIGN_PASSWORD is required}"

mapfile -d '' payloads < <(
  find "$artifacts_dir" -maxdepth 1 -type f ! -name '*.sigstore.json' -print0 |
    LC_ALL=C sort -z
)
if (( ${#payloads[@]} == 0 )); then
  echo 'sign_release_artifacts.sh: no release payloads were found.' >&2
  exit 1
fi

for payload in "${payloads[@]}"; do
  cosign sign-blob --yes \
    --key env://COSIGN_PRIVATE_KEY \
    --bundle "${payload}.sigstore.json" \
    "$payload"
done

echo "sign_release_artifacts.sh: signed ${#payloads[@]} release payloads."
