#!/usr/bin/env bash
# Generate a Scoop manifest from a GitHub Release.
set -euo pipefail

version="${1:?usage: generate_scoop_manifest.sh <version> <windows-x64-sha256>}"
sha256="${2:?usage: generate_scoop_manifest.sh <version> <windows-x64-sha256>}"

cat <<MANIFEST
{
  "version": "${version}",
  "description": "Verdictan AI governance gateway CLI",
  "homepage": "https://verdictan.com",
  "license": "BUSL-1.1",
  "architecture": {
    "64bit": {
      "url": "https://github.com/verdictan/verdictan/releases/download/v${version}/verdictan-x86_64-pc-windows-msvc.zip",
      "hash": "${sha256}"
    }
  },
  "bin": "verdictan.exe",
  "checkver": {
    "github": "https://github.com/verdictan/verdictan"
  },
  "autoupdate": {
    "architecture": {
      "64bit": {
        "url": "https://github.com/verdictan/verdictan/releases/download/v\$version/verdictan-x86_64-pc-windows-msvc.zip"
      }
    }
  }
}
MANIFEST
