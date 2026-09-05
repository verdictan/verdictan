#!/usr/bin/env bash
# Generate the three-file WinGet community manifest for a Verdictan release.
set -euo pipefail

version="${1:?usage: generate_winget_manifests.sh <version> <windows-x64-sha256> <release-date> <output-root>}"
sha256="${2:?usage: generate_winget_manifests.sh <version> <windows-x64-sha256> <release-date> <output-root>}"
release_date="${3:?usage: generate_winget_manifests.sh <version> <windows-x64-sha256> <release-date> <output-root>}"
output_root="${4:?usage: generate_winget_manifests.sh <version> <windows-x64-sha256> <release-date> <output-root>}"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "generate_winget_manifests.sh: invalid stable version: ${version}" >&2
  exit 1
fi
if [[ ! "$sha256" =~ ^[0-9A-Fa-f]{64}$ ]]; then
  echo 'generate_winget_manifests.sh: SHA-256 must contain 64 hexadecimal characters.' >&2
  exit 1
fi
if [[ ! "$release_date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
  echo "generate_winget_manifests.sh: invalid release date: ${release_date}" >&2
  exit 1
fi

package_id=Verdictan.Verdictan
manifest_dir="${output_root}/manifests/v/Verdictan/Verdictan/${version}"
release_url="https://github.com/verdictan/verdictan/releases/download/v${version}"
mkdir -p "$manifest_dir"
sha256="${sha256^^}"

cat > "${manifest_dir}/${package_id}.yaml" <<EOF
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.version.1.12.0.schema.json
PackageIdentifier: ${package_id}
PackageVersion: ${version}
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.12.0
EOF

cat > "${manifest_dir}/${package_id}.installer.yaml" <<EOF
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.installer.1.12.0.schema.json
PackageIdentifier: ${package_id}
PackageVersion: ${version}
InstallerType: zip
NestedInstallerType: portable
Commands:
  - verdictan
  - verdictan-update
ReleaseDate: '${release_date}'
Installers:
  - Architecture: x64
    NestedInstallerFiles:
      - RelativeFilePath: verdictan.exe
        PortableCommandAlias: verdictan
      - RelativeFilePath: verdictan-update.exe
        PortableCommandAlias: verdictan-update
    InstallerUrl: ${release_url}/verdictan-x86_64-pc-windows-msvc.zip
    InstallerSha256: ${sha256}
    UpgradeBehavior: uninstallPrevious
ManifestType: installer
ManifestVersion: 1.12.0
EOF

cat > "${manifest_dir}/${package_id}.locale.en-US.yaml" <<EOF
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.defaultLocale.1.12.0.schema.json
PackageIdentifier: ${package_id}
PackageVersion: ${version}
PackageLocale: en-US
Publisher: Verdictan
PublisherUrl: https://verdictan.com
PublisherSupportUrl: https://github.com/verdictan/verdictan/issues
PrivacyUrl: https://verdictan.com/privacy-policy
PackageName: Verdictan
PackageUrl: https://github.com/verdictan/verdictan
License: BUSL-1.1
LicenseUrl: https://github.com/verdictan/verdictan/blob/v${version}/LICENSE
Copyright: Copyright (c) Verdictan.com
ShortDescription: AI governance gateway and command-line interface
Description: Verdictan applies policy to AI model traffic, routes requests, protects provider credentials, and records decision evidence.
Moniker: verdictan
Tags:
  - ai
  - cli
  - gateway
  - governance
  - llm
ReleaseNotesUrl: https://github.com/verdictan/verdictan/releases/tag/v${version}
Documentations:
  - DocumentLabel: Verdictan documentation
    DocumentUrl: https://docs.verdictan.com
ManifestType: defaultLocale
ManifestVersion: 1.12.0
EOF

printf '%s\n' "$manifest_dir"
