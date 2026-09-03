#!/usr/bin/env bash
# Install cargo-dist matrix build dependencies without system pip (PEP 668).
set -euo pipefail

packages_install="${PACKAGES_INSTALL:-}"
if [[ -z "$packages_install" ]]; then
  exit 0
fi

append_path() {
  local dir="$1"
  if [[ ":${PATH}:" != *":${dir}:"* ]]; then
    export PATH="${dir}:${PATH}"
  fi
  if [[ -n "${GITHUB_ENV:-}" ]]; then
    echo "PATH=${PATH}" >> "${GITHUB_ENV}"
  fi
}

ensure_cargo_on_path() {
  : "${CARGO_HOME:?CARGO_HOME must be set before installing cargo-dist build deps}"
  export PATH="${CARGO_HOME}/bin:${PATH:-}"

  if ! command -v cargo >/dev/null 2>&1 && [[ -n "${RUSTUP_HOME:-}" ]]; then
    local toolchain_cargo
    toolchain_cargo="$(find "${RUSTUP_HOME}/toolchains" -path '*/bin/cargo' -type f 2>/dev/null | head -1 || true)"
    if [[ -n "$toolchain_cargo" ]]; then
      export PATH="$(dirname "$toolchain_cargo"):${PATH}"
    fi
  fi

  if ! command -v cargo >/dev/null 2>&1; then
    echo "install_release_build_deps.sh: cargo not found in PATH" >&2
    exit 1
  fi
}

install_system_packages() {
  local packages=("$@")
  local privilege=()

  if [[ "$(id -u)" != "0" ]]; then
    if sudo --non-interactive true >/dev/null 2>&1; then
      privilege=(sudo --non-interactive)
    else
      echo "install_release_build_deps.sh: cannot install ${packages[*]} without root" >&2
      echo "install_release_build_deps.sh: the runner user has no passwordless sudo" >&2
      echo "install_release_build_deps.sh: an operator must run: sudo dnf install --assumeyes ${packages[*]}" >&2
      exit 1
    fi
  fi

  if ! command -v dnf >/dev/null 2>&1; then
    echo "install_release_build_deps.sh: dnf not found, so ${packages[*]} cannot be installed" >&2
    exit 1
  fi

  "${privilege[@]+${privilege[@]}}" dnf install --assumeyes "${packages[@]}"
}

require_tool() {
  local tool="$1"
  local source="$2"

  if command -v "$tool" >/dev/null 2>&1; then
    return 0
  fi

  echo "install_release_build_deps.sh: required tool ${tool} is not on PATH" >&2
  echo "install_release_build_deps.sh: x86_64-pc-windows-msvc builds need ${tool} from ${source}" >&2
  exit 1
}

# llvm-ar and rust-lld are multicall drivers. Under the program names llvm-lib
# and lld-link they act as the MSVC lib.exe and link.exe replacements that cc-rs
# and rustc call for x86_64-pc-windows-msvc.
install_rust_llvm_msvc_tools() {
  if ! command -v rustc >/dev/null 2>&1; then
    echo "install_release_build_deps.sh: rustc not found in PATH" >&2
    exit 1
  fi

  local rust_llvm_bin
  rust_llvm_bin="$(rustc --print target-libdir)"
  rust_llvm_bin="${rust_llvm_bin%/lib}/bin"

  if [[ ! -x "${rust_llvm_bin}/llvm-ar" ]]; then
    rustup component add llvm-tools
  fi

  local link_dir="${CARGO_HOME}/dist-msvc-tools/bin"
  mkdir -p "$link_dir"

  local tool source
  for tool in llvm-lib lld-link; do
    case "$tool" in
      llvm-lib) source="llvm-ar" ;;
      lld-link) source="rust-lld" ;;
    esac

    if [[ ! -x "${rust_llvm_bin}/${source}" ]]; then
      echo "install_release_build_deps.sh: ${source} is missing from ${rust_llvm_bin}" >&2
      echo "install_release_build_deps.sh: ${tool} is required for x86_64-pc-windows-msvc builds" >&2
      exit 1
    fi

    ln -sf "${rust_llvm_bin}/${source}" "${link_dir}/${tool}"
  done

  append_path "$link_dir"
}

# cargo-xwin supplies the Windows SDK and CRT headers and libraries. The build
# host must also supply the LLVM tools that cc-rs and rustc call directly.
install_msvc_llvm_tools() {
  if ! command -v clang-cl >/dev/null 2>&1; then
    install_system_packages clang
  fi
  require_tool clang-cl "the system clang package"

  if ! command -v llvm-lib >/dev/null 2>&1 || ! command -v lld-link >/dev/null 2>&1; then
    install_rust_llvm_msvc_tools
  fi
  require_tool llvm-lib "the Rust llvm-tools component or the system llvm package"
  require_tool lld-link "the Rust toolchain rust-lld binary or the system lld package"
}

install_zig() {
  if command -v zig >/dev/null 2>&1; then
    return 0
  fi

  # The distro package is an optional shortcut. install_system_packages exits 1
  # when the runner user has no root and no passwordless sudo, so the call runs
  # in a subshell. That keeps the privilege message visible without ending this
  # script, because the ziglang venv below is the supported install path.
  if command -v dnf >/dev/null 2>&1; then
    if dnf list --available zig 2>/dev/null | grep -q '^zig\.'; then
      if (install_system_packages zig) && command -v zig >/dev/null 2>&1; then
        return 0
      fi
      echo "install_release_build_deps.sh: the zig distro package is not installed" >&2
      echo "install_release_build_deps.sh: cargo-zigbuild uses the ziglang venv instead" >&2
    fi
  fi

  # cargo-zigbuild needs zig; install ziglang in a PEP 668-safe venv under CARGO_HOME.
  local venv_root="${CARGO_HOME}/dist-cross-venv"
  if [[ ! -x "${venv_root}/bin/python3" ]]; then
    python3 -m venv "${venv_root}"
  fi
  "${venv_root}/bin/pip" install --upgrade pip
  "${venv_root}/bin/pip" install ziglang
  append_path "${venv_root}/bin"
}

install_cargo_zigbuild() {
  ensure_cargo_on_path

  if ! command -v cargo-zigbuild >/dev/null 2>&1; then
    cargo install cargo-zigbuild --locked
  fi

  install_zig
}

install_cargo_xwin() {
  ensure_cargo_on_path

  if ! command -v cargo-xwin >/dev/null 2>&1; then
    cargo install cargo-xwin --locked
  fi

  rustup target add x86_64-pc-windows-msvc

  install_msvc_llvm_tools
}

if [[ "$packages_install" == *"cargo-zigbuild"* ]]; then
  install_cargo_zigbuild
  exit 0
fi

if [[ "$packages_install" == *"cargo-xwin"* ]]; then
  install_cargo_xwin
  exit 0
fi

echo "install_release_build_deps.sh: unsupported PACKAGES_INSTALL on Unix" >&2
echo "$packages_install" >&2
exit 1
