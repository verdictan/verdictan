#!/usr/bin/env bash
# Normalize archive metadata so identical tagged sources produce identical payloads.
set -euo pipefail

artifacts_dir="${1:-}"
source_epoch="${2:-${SOURCE_DATE_EPOCH:-}}"

if [[ ! -d "$artifacts_dir" ]]; then
  echo "normalize_release_artifacts.sh: missing directory: ${artifacts_dir}" >&2
  exit 1
fi
if [[ ! "$source_epoch" =~ ^[0-9]+$ ]]; then
  echo 'normalize_release_artifacts.sh: SOURCE_DATE_EPOCH must be an integer.' >&2
  exit 1
fi

normalize_tar() {
  local archive="$1" name work unpack output
  name="$(basename "$archive")"
  work="$(mktemp -d)"
  unpack="${work}/unpack"
  output="${work}/${name}"
  mkdir -p "$unpack"
  tar -xzf "$archive" -C "$unpack"
  find "$unpack" -exec touch -h -d "@${source_epoch}" {} +
  tar --sort=name --format=gnu --mtime="@${source_epoch}" --clamp-mtime \
    --owner=0 --group=0 --numeric-owner -C "$unpack" -cf - . |
    gzip -n -9 > "$output"
  mv "$output" "$archive"
  rm -rf "$work"
}

normalize_zip() {
  local archive="$1" name work unpack output
  name="$(basename "$archive")"
  work="$(mktemp -d)"
  unpack="${work}/unpack"
  output="${work}/${name}"
  mkdir -p "$unpack"
  unzip -q "$archive" -d "$unpack"
  find "$unpack" -exec touch -h -d "@${source_epoch}" {} +
  (
    cd "$unpack"
    find . -type f -print | LC_ALL=C sort | zip -X -q "$output" -@
  )
  mv "$output" "$archive"
  rm -rf "$work"
}

shopt -s nullglob
for archive in "$artifacts_dir"/*.tar.gz; do
  normalize_tar "$archive"
done
for archive in "$artifacts_dir"/*.zip; do
  normalize_zip "$archive"
done

for archive in "$artifacts_dir"/*.tar.gz "$artifacts_dir"/*.zip; do
  name="$(basename "$archive")"
  (cd "$artifacts_dir" && sha256sum "$name" > "${name}.sha256")
done

echo "normalize_release_artifacts.sh: normalized release archives to ${source_epoch}."
