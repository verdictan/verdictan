#!/usr/bin/env bash
set -euo pipefail

artifacts_dir="${1:-artifacts}"
public_key="${2:-ci/release/cosign.pub}"
if [[ ! -d "$artifacts_dir" ]]; then
  echo "verify_release_signatures.sh: missing directory: ${artifacts_dir}" >&2
  exit 1
fi
if [[ ! -f "$public_key" ]]; then
  echo "verify_release_signatures.sh: missing public key: ${public_key}" >&2
  exit 1
fi

count=0
while IFS= read -r -d '' payload; do
  bundle="${payload}.sigstore.json"
  if [[ ! -f "$bundle" ]]; then
    echo "verify_release_signatures.sh: missing signature bundle: ${bundle}" >&2
    exit 1
  fi
  cosign verify-blob --key "$public_key" --bundle "$bundle" "$payload" >/dev/null
  count=$((count + 1))
done < <(find "$artifacts_dir" -maxdepth 1 -type f ! -name '*.sigstore.json' -print0 | LC_ALL=C sort -z)

if (( count == 0 )); then
  echo 'verify_release_signatures.sh: no release payloads were found.' >&2
  exit 1
fi
echo "verify_release_signatures.sh: verified ${count} signed release payloads."
