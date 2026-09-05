#!/usr/bin/env bash
# Build x86-64 Debian and RPM packages with the Linux repository baseline.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

target_base="${CARGO_TARGET_DIR:-target}"
target_triple='x86_64-unknown-linux-gnu'
glibc_baseline='2.17'

if [[ -x "${CARGO_HOME:-}/dist-cross-venv/bin/python3" ]]; then
  export CARGO_ZIGBUILD_PYTHON_PATH="${CARGO_HOME}/dist-cross-venv/bin/python3"
fi
for tool in cargo-auditable cargo-deb cargo-generate-rpm; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "release_extra_linux_packages.sh: ${tool} is required." >&2
    exit 1
  fi
done

cargo auditable zigbuild --locked --release \
  --target "${target_triple}.${glibc_baseline}"
release_bin="${target_base}/${target_triple}/release/verdictan"
if [[ ! -f "$release_bin" ]]; then
  echo "release_extra_linux_packages.sh: compatible release binary not found: ${release_bin}" >&2
  exit 1
fi

mkdir -p "${target_base}/release" "${root}/dist-artifacts"
install -m 0755 "$release_bin" "${target_base}/release/verdictan"

cargo deb --no-build \
  --output "${root}/dist-artifacts/verdictan-x86_64-unknown-linux-gnu.deb"
cargo generate-rpm \
  --source-date "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH is required}" \
  --output "${root}/dist-artifacts/verdictan-x86_64-unknown-linux-gnu.rpm"

incompatible_glibc="$(strings "$release_bin" |
  sed -nE 's/^GLIBC_([0-9]+)\.([0-9]+).*$/\1 \2/p' |
  awk '$1 > 2 || ($1 == 2 && $2 > 17) { print $1 "." $2; exit }')"
if [[ -n "$incompatible_glibc" ]]; then
  echo "release_extra_linux_packages.sh: package binary requires GLIBC ${incompatible_glibc}, above the 2.17 baseline." >&2
  exit 1
fi
