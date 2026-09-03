#!/usr/bin/env bash
# Fail before gh release create when the distrib cache handoff left artifacts/ empty
# or missing critical release assets.
set -euo pipefail

artifacts_dir="${1:-artifacts}"
manifest="${2:-dist-manifest.json}"

if [[ ! -d "$artifacts_dir" ]]; then
  echo "verify_release_artifacts.sh: missing directory: ${artifacts_dir}" >&2
  exit 1
fi

shopt -s nullglob
files=("$artifacts_dir"/*)
shopt -u nullglob

if (( ${#files[@]} == 0 )); then
  echo "verify_release_artifacts.sh: ${artifacts_dir}/ is empty." >&2
  echo "verify_release_artifacts.sh: distrib cache handoff likely failed before prepare-release." >&2
  exit 1
fi

required=(
  "reproducibility.json"
  "verdictan-cosign.pub"
  "verdictan-installer.sh"
  "verdictan-installer.ps1"
  "verdictan.rb"
)

missing=()
for name in "${required[@]}"; do
  if [[ ! -f "${artifacts_dir}/${name}" ]]; then
    missing+=("$name")
  fi
done

archive_count=0
for file in "${files[@]}"; do
  case "$(basename "$file")" in
    *.tar.gz|*.zip) archive_count=$((archive_count + 1)) ;;
  esac
done

if (( archive_count == 0 )); then
  missing+=("at least one platform archive (.tar.gz or .zip)")
fi

if (( ${#missing[@]} > 0 )); then
  echo "verify_release_artifacts.sh: missing critical release assets:" >&2
  printf '  - %s\n' "${missing[@]}" >&2
  echo "verify_release_artifacts.sh: artifacts/ contents:" >&2
  ls -la "$artifacts_dir" >&2 || true
  exit 1
fi

min_files=12
if (( ${#files[@]} < min_files )); then
  echo "verify_release_artifacts.sh: expected at least ${min_files} files in ${artifacts_dir}/, found ${#files[@]}." >&2
  ls -la "$artifacts_dir" >&2 || true
  exit 1
fi

if [[ -f "$manifest" ]] && command -v jq >/dev/null 2>&1; then
  if jq -e '.upload_files | type == "array" and length > 0' "$manifest" >/dev/null 2>&1; then
    expected_count="$(jq '.upload_files | length' "$manifest")"
    if (( ${#files[@]} < expected_count )); then
      echo "verify_release_artifacts.sh: dist-manifest.json lists ${expected_count} upload files but ${artifacts_dir}/ has ${#files[@]}." >&2
      echo "verify_release_artifacts.sh: manifest upload_files:" >&2
      jq -r '.upload_files[]' "$manifest" >&2
      exit 1
    fi
  fi
fi

echo "verify_release_artifacts.sh: verified ${#files[@]} release artifacts (${archive_count} archives)."
