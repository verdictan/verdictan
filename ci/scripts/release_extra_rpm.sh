#!/usr/bin/env bash
# Build an RPM package from the release binary. x86_64 Linux only.
#
# cargo-dist reads the declared extra-artifact path as a literal, so this script
# writes a constant file name. See `dist-workspace.toml`.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${root}"

artifact="${root}/dist-artifacts/verdictan-x86_64-unknown-linux-gnu.rpm"

target_base="${CARGO_TARGET_DIR:-target}"
target_triple="${CARGO_BUILD_TARGET:-x86_64-unknown-linux-gnu}"
release_bin="${target_base}/${target_triple}/dist/verdictan"
if [[ ! -f "$release_bin" ]]; then
  release_bin="${target_base}/release/verdictan"
fi
if [[ ! -f "$release_bin" ]]; then
  echo "release_extra_rpm.sh: release binary not found" >&2
  echo "  tried ${target_base}/${target_triple}/dist/verdictan and ${target_base}/release/verdictan" >&2
  exit 1
fi

mkdir -p "${target_base}/release"
install -m 755 "$release_bin" "${target_base}/release/verdictan"

cargo install cargo-generate-rpm --version 0.12.1 --locked
mkdir -p "${root}/dist-artifacts"
cargo generate-rpm --output "$artifact"
