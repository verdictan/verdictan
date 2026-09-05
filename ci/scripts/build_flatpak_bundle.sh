#!/usr/bin/env bash
set -euo pipefail

version="${1:-}"
artifacts_dir="${2:-}"
output_dir="${3:-flatpak-output}"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
  echo "build_flatpak_bundle.sh: invalid semantic version: ${version}" >&2
  exit 1
fi
if [[ ! -d "$artifacts_dir" ]]; then
  echo "build_flatpak_bundle.sh: missing artifacts directory: ${artifacts_dir}" >&2
  exit 1
fi
if [[ ! "${SOURCE_DATE_EPOCH:-}" =~ ^[0-9]+$ ]]; then
  echo 'build_flatpak_bundle.sh: SOURCE_DATE_EPOCH must be a Unix timestamp.' >&2
  exit 1
fi
if ! command -v flatpak >/dev/null 2>&1; then
  echo 'build_flatpak_bundle.sh: flatpak is required.' >&2
  exit 1
fi

readonly app_id='com.verdictan.Verdictan'
readonly target='x86_64-unknown-linux-gnu'
readonly flatpak_arch='x86_64'
readonly archive="verdictan-${target}.tar.gz"
readonly archive_path="${artifacts_dir}/${archive}"
readonly checksum_path="${archive_path}.sha256"
commit_timestamp="$(date -u -d "@${SOURCE_DATE_EPOCH}" '+%Y-%m-%dT%H:%M:%SZ')"
readonly commit_timestamp

if [[ ! -f "$archive_path" || ! -f "$checksum_path" ]]; then
  echo "build_flatpak_bundle.sh: ${archive} and its checksum are required." >&2
  exit 1
fi

(cd "$artifacts_dir" && sha256sum --check "${archive}.sha256")

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/verdictan-flatpak.XXXXXX")"
cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT

source_dir="${work_dir}/source"
build_dir="${work_dir}/build"
repo_dir="${work_dir}/repo"
mkdir -p "$source_dir" "$build_dir/files/bin" \
  "$build_dir/files/share/doc/verdictan" "$repo_dir" "$output_dir"
tar -xzf "$archive_path" -C "$source_dir"

mapfile -t source_roots < <(find "$source_dir" -mindepth 1 -maxdepth 1 -type d -print)
if (( ${#source_roots[@]} != 1 )); then
  echo "build_flatpak_bundle.sh: ${archive} must contain one root directory." >&2
  exit 1
fi
payload_dir="${source_roots[0]}"
for name in verdictan verdictan-update; do
  if [[ ! -x "${payload_dir}/${name}" ]]; then
    echo "build_flatpak_bundle.sh: ${archive} is missing executable ${name}." >&2
    exit 1
  fi
  install -m 0755 "${payload_dir}/${name}" "${build_dir}/files/bin/${name}"
done
for name in LICENSE LICENSE.template THIRD_PARTY_NOTICES.md; do
  if [[ ! -f "${payload_dir}/${name}" ]]; then
    echo "build_flatpak_bundle.sh: ${archive} is missing ${name}." >&2
    exit 1
  fi
  install -m 0644 "${payload_dir}/${name}" \
    "${build_dir}/files/share/doc/verdictan/${name}"
done

sed "s/@ARCH@/${flatpak_arch}/g" flatpak/metadata.in > "${build_dir}/metadata"
flatpak build-finish --no-exports "$build_dir"
flatpak build-export --arch="$flatpak_arch" \
  --timestamp="$commit_timestamp" \
  "$repo_dir" "$build_dir" stable

bundle="${output_dir}/verdictan-${version}-${flatpak_arch}.flatpak"
flatpak build-bundle --arch="$flatpak_arch" \
  --runtime-repo='https://dl.flathub.org/repo/flathub.flatpakrepo' \
  "$repo_dir" "$bundle" "$app_id" stable
(cd "$output_dir" && sha256sum "$(basename "$bundle")" > "$(basename "$bundle").sha256")

echo "build_flatpak_bundle.sh: built ${bundle}"
