#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "tmpdir"
require "yaml"

root = File.expand_path("../..", __dir__)

def assert(condition, message)
  abort "verify_distribution_manifests.rb: #{message}" unless condition
end

support = JSON.parse(File.read(File.join(root, "ci/distribution-support.json")))
assert(support.dig("snapcraft", "enabled") == true, "Snapcraft support is not enabled")
assert(support.dig("winget", "enabled") == true, "WinGet support is not enabled")
assert(support.dig("flatpak", "enabled") == true, "Flatpak support is not enabled")
assert(support.dig("flatpak", "application") == "com.verdictan.Verdictan", "unexpected Flatpak application ID")
assert(support.dig("flatpak", "architectures") == ["x86_64"], "unexpected Flatpak architectures")
assert(support.dig("flatpak", "delivery") == "github-release-bundle", "unexpected Flatpak delivery")
assert(support.dig("linux_package_repositories", "enabled") == true, "Linux package repositories are not enabled")
assert(
  support.dig("linux_package_repositories", "repository") == "verdictan/packages",
  "unexpected Linux package repository"
)
assert(
  support.dig("linux_package_repositories", "base_url") == "https://verdictan.github.io/packages",
  "unexpected Linux package repository URL"
)
assert(
  support.dig("linux_package_repositories", "signing_key_fingerprint") ==
    "FBA05B9F2E1EB214BFC52BA2FDED465F123CF517",
  "unexpected Linux package signing key"
)
assert(
  support.dig("linux_package_repositories", "apt", "architectures") == ["amd64"],
  "unexpected APT architectures"
)
assert(support.dig("linux_package_repositories", "apt", "suite") == "stable", "unexpected APT suite")
assert(support.dig("linux_package_repositories", "apt", "component") == "main", "unexpected APT component")
assert(
  support.dig("linux_package_repositories", "apt", "distributions") == %w[Ubuntu Debian],
  "unexpected APT distributions"
)
assert(
  support.dig("linux_package_repositories", "rpm", "architectures") == ["x86_64"],
  "unexpected RPM architectures"
)
assert(
  support.dig("linux_package_repositories", "rpm", "distributions") ==
    ["CentOS", "RHEL", "Fedora", "Amazon Linux 2023"],
  "unexpected RPM distributions"
)

linux_repository_builder = File.read(File.join(root, "ci/scripts/build_linux_package_repositories.sh"))
assert(linux_repository_builder.include?("apt-ftparchive"), "APT repository generation is missing")
assert(linux_repository_builder.include?("createrepo_c"), "RPM repository generation is missing")
assert(linux_repository_builder.include?("--clearsign"), "APT InRelease signing is missing")
assert(linux_repository_builder.include?("rpmsign"), "RPM package signing is missing")
assert(linux_repository_builder.include?("repomd.xml.asc"), "RPM metadata signing is missing")
assert(linux_repository_builder.include?("repo_gpgcheck=1"), "RPM metadata verification is not required")

repository_public_key = File.join(root, "packaging/repositories/verdictan-packages.asc")
assert(File.file?(repository_public_key), "Linux package repository public key is missing")
key_listing = IO.popen(
  ["gpg", "--batch", "--show-keys", "--with-colons", repository_public_key],
  err: File::NULL,
  &:read
)
key_fingerprint = key_listing.lines.find { |line| line.start_with?("fpr:") }&.split(":")&.fetch(9, nil)
assert(
  key_fingerprint == support.dig("linux_package_repositories", "signing_key_fingerprint"),
  "Linux package repository public key fingerprint mismatch"
)

snap = YAML.safe_load(File.read(File.join(root, "snap/snapcraft.yaml")))
assert(snap["name"] == "verdictan", "unexpected Snap name")
assert(snap["title"] == "Verdictan", "unexpected Snap title")
assert(snap["summary"].length <= 78, "Snap summary exceeds 78 characters")
assert(snap["description"].include?("strictly confined foreground gateway"), "Snap description is incomplete")
assert(snap["license"] == "BUSL-1.1", "unexpected Snap license")
assert(snap["type"] == "app", "unexpected Snap type")
assert(snap["website"] == "https://verdictan.com", "unexpected Snap website")
assert(snap["source-code"] == "https://github.com/verdictan/verdictan", "unexpected Snap source URL")
assert(snap["issues"] == "https://github.com/verdictan/verdictan/issues", "unexpected Snap issues URL")
assert(snap["base"] == "core24", "unexpected Snap base")
assert(snap["grade"] == "stable", "Snap is not stable")
assert(snap["confinement"] == "strict", "Snap must use strict confinement")
assert(snap["compression"] == "xz", "Snap compression must be explicit")
assert(snap.fetch("platforms").keys.sort == %w[amd64 arm64], "Snap platforms must be amd64 and arm64")
assert(snap.dig("apps", "verdictan", "command") == "bin/verdictan", "Snap CLI command is missing")
assert(
  snap.dig("apps", "verdictan", "plugs").sort == %w[home network network-bind removable-media],
  "Snap CLI interfaces do not match the strict-confinement contract"
)
assert(!snap.fetch("apps").key?("verdictan-update"), "Snap must use snap refresh instead of the self-updater")

icon_path = File.join(root, snap.fetch("icon"))
assert(File.file?(icon_path), "Snap icon is missing")
assert(File.size(icon_path) < 256 * 1024, "Snap icon exceeds 256 KB")
icon = File.read(icon_path)
assert(icon.include?('width="256"') && icon.include?('height="256"'), "Snap icon must be 256x256")
assert(icon.include?('viewBox="0 0 24 24"'), "Snap icon viewBox is missing")

flatpak_metadata = File.read(File.join(root, "flatpak/metadata.in"))
assert(flatpak_metadata.include?("name=com.verdictan.Verdictan"), "Flatpak application ID is missing")
assert(flatpak_metadata.include?("runtime=org.freedesktop.Platform/@ARCH@/25.08"), "Flatpak runtime is missing")
assert(flatpak_metadata.include?("command=verdictan"), "Flatpak command is missing")
assert(flatpak_metadata.include?("shared=network;"), "Flatpak network access is missing")
assert(flatpak_metadata.include?("filesystems=host;"), "Flatpak host filesystem access is missing")

Dir.mktmpdir("verdictan-winget-") do |directory|
  generator = File.join(root, "ci/scripts/generate_winget_manifests.sh")
  ok = system(generator, "1.2.3", "a" * 64, "2026-09-05", directory, out: File::NULL)
  assert(ok, "WinGet generator failed")

  manifest_dir = File.join(directory, "manifests/v/Verdictan/Verdictan/1.2.3")
  files = Dir.children(manifest_dir).sort
  expected = [
    "Verdictan.Verdictan.installer.yaml",
    "Verdictan.Verdictan.locale.en-US.yaml",
    "Verdictan.Verdictan.yaml"
  ]
  assert(files == expected, "WinGet manifest set is incomplete")

  manifests = files.to_h do |file|
    [file, YAML.safe_load(File.read(File.join(manifest_dir, file)))]
  end
  manifests.each_value do |manifest|
    assert(manifest["PackageIdentifier"] == "Verdictan.Verdictan", "WinGet package identifier mismatch")
    assert(manifest["PackageVersion"] == "1.2.3", "WinGet package version mismatch")
    assert(manifest["ManifestVersion"] == "1.12.0", "WinGet schema version mismatch")
  end

  installer = manifests.fetch("Verdictan.Verdictan.installer.yaml")
  assert(installer["InstallerType"] == "zip", "WinGet installer must use the release ZIP")
  assert(installer["NestedInstallerType"] == "portable", "WinGet nested installer must be portable")
  aliases = installer.fetch("Installers").first.fetch("NestedInstallerFiles").map { |entry| entry["PortableCommandAlias"] }
  assert(aliases == %w[verdictan verdictan-update], "WinGet command aliases mismatch")
  assert(installer.fetch("Installers").first.fetch("InstallerSha256") == "A" * 64, "WinGet checksum mismatch")
end

puts "verify_distribution_manifests.rb: distribution manifests passed"
