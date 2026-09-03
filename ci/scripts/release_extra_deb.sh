#!/usr/bin/env bash
# Build a Debian package from the release binary. x86_64 Linux only.
#
# cargo-dist reads the declared extra-artifact path as a literal, so this script
# writes a constant file name. See `dist-workspace.toml`.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${root}"

artifact="${root}/dist-artifacts/verdictan-x86_64-unknown-linux-gnu.deb"

target_base="${CARGO_TARGET_DIR:-target}"
target_triple="${CARGO_BUILD_TARGET:-x86_64-unknown-linux-gnu}"
release_bin="${target_base}/${target_triple}/dist/verdictan"
if [[ ! -f "$release_bin" ]]; then
  release_bin="${target_base}/release/verdictan"
fi
if [[ ! -f "$release_bin" ]]; then
  echo "release_extra_deb.sh: release binary not found" >&2
  echo "  tried ${target_base}/${target_triple}/dist/verdictan and ${target_base}/release/verdictan" >&2
  exit 1
fi

mkdir -p "${target_base}/release"
install -m 755 "$release_bin" "${target_base}/release/verdictan"

cargo install cargo-deb --version 3.1.0 --locked
mkdir -p "${root}/dist-artifacts"
cargo deb --no-build --output "$artifact"
