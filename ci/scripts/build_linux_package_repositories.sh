#!/usr/bin/env bash
set -euo pipefail

version="${1:?usage: build_linux_package_repositories.sh <version> <deb> <rpm> <repository-root> <private-key> [base-url]}"
deb_source="${2:?usage: build_linux_package_repositories.sh <version> <deb> <rpm> <repository-root> <private-key> [base-url]}"
rpm_source="${3:?usage: build_linux_package_repositories.sh <version> <deb> <rpm> <repository-root> <private-key> [base-url]}"
repository_root="${4:?usage: build_linux_package_repositories.sh <version> <deb> <rpm> <repository-root> <private-key> [base-url]}"
private_key="${5:?usage: build_linux_package_repositories.sh <version> <deb> <rpm> <repository-root> <private-key> [base-url]}"
base_url="${6:-https://verdictan.github.io/packages}"
expected_fingerprint="${VERDICTAN_PACKAGE_REPOSITORY_GPG_FINGERPRINT:-FBA05B9F2E1EB214BFC52BA2FDED465F123CF517}"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.+][0-9A-Za-z.-]+)?$ ]]; then
  echo "build_linux_package_repositories.sh: invalid semantic version: ${version}" >&2
  exit 1
fi
if [[ ! "$base_url" =~ ^https://[^/]+(/[^/]+)*$ ]]; then
  echo "build_linux_package_repositories.sh: invalid HTTPS base URL: ${base_url}" >&2
  exit 1
fi
for source_file in "$deb_source" "$rpm_source" "$private_key"; do
  if [[ ! -f "$source_file" ]]; then
    echo "build_linux_package_repositories.sh: missing input file: ${source_file}" >&2
    exit 1
  fi
done
for tool in apt-ftparchive createrepo_c dpkg-deb gpg gpgv gzip rpm rpmkeys rpmsign sha256sum; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "build_linux_package_repositories.sh: ${tool} is required." >&2
    exit 1
  fi
done

source_date_epoch="${SOURCE_DATE_EPOCH:-$(date +%s)}"
if [[ ! "$source_date_epoch" =~ ^[0-9]+$ ]]; then
  echo 'build_linux_package_repositories.sh: SOURCE_DATE_EPOCH must be a Unix timestamp.' >&2
  exit 1
fi

deb_name="$(dpkg-deb --field "$deb_source" Package)"
deb_version="$(dpkg-deb --field "$deb_source" Version)"
deb_architecture="$(dpkg-deb --field "$deb_source" Architecture)"
if [[ "$deb_name" != verdictan || "$deb_version" != "${version}-1" || "$deb_architecture" != amd64 ]]; then
  echo "build_linux_package_repositories.sh: unexpected Debian metadata: ${deb_name} ${deb_version} ${deb_architecture}" >&2
  exit 1
fi

rpm_name="$(rpm -qp --queryformat '%{NAME}' "$rpm_source")"
rpm_version="$(rpm -qp --queryformat '%{VERSION}' "$rpm_source")"
rpm_release="$(rpm -qp --queryformat '%{RELEASE}' "$rpm_source")"
rpm_architecture="$(rpm -qp --queryformat '%{ARCH}' "$rpm_source")"
if [[ "$rpm_name" != verdictan-gateway || "$rpm_version" != "$version" || "$rpm_release" != 1 || "$rpm_architecture" != x86_64 ]]; then
  echo "build_linux_package_repositories.sh: unexpected RPM metadata: ${rpm_name} ${rpm_version}-${rpm_release} ${rpm_architecture}" >&2
  exit 1
fi

mkdir -p "$repository_root/releases"
release_marker="$repository_root/releases/${version}.sha256"
marker_candidate="$(mktemp)"
signing_home="$(mktemp -d)"
verification_home="$(mktemp -d)"
cleanup() {
  rm -f "$marker_candidate"
  rm -rf "$signing_home" "$verification_home"
}
trap cleanup EXIT

{
  sha256sum "$deb_source" | sed "s#  .*#  verdictan-x86_64-unknown-linux-gnu.deb#"
  sha256sum "$rpm_source" | sed "s#  .*#  verdictan-x86_64-unknown-linux-gnu.rpm#"
} > "$marker_candidate"
if [[ -f "$release_marker" ]]; then
  if cmp --silent "$marker_candidate" "$release_marker"; then
    echo "build_linux_package_repositories.sh: Verdictan ${version} is already indexed."
    exit 0
  fi
  echo "build_linux_package_repositories.sh: release ${version} already has different package inputs." >&2
  exit 1
fi

chmod 0700 "$signing_home" "$verification_home"
gpg --homedir "$signing_home" --batch --import "$private_key" >/dev/null 2>&1
mapfile -t signing_fingerprints < <(
  gpg --homedir "$signing_home" --batch --with-colons --list-secret-keys |
    awk -F: '$1 == "fpr" { print $10; exit }'
)
if [[ "${#signing_fingerprints[@]}" -ne 1 || ! "${signing_fingerprints[0]}" =~ ^[0-9A-F]{40}$ ]]; then
  echo 'build_linux_package_repositories.sh: the private key must contain one usable OpenPGP signing key.' >&2
  exit 1
fi
fingerprint="${signing_fingerprints[0]}"
if [[ "$fingerprint" != "$expected_fingerprint" ]]; then
  echo "build_linux_package_repositories.sh: signing key fingerprint ${fingerprint} does not match ${expected_fingerprint}." >&2
  exit 1
fi

mkdir -p \
  "$repository_root/apt/pool/main/v/verdictan" \
  "$repository_root/apt/dists/stable/main/binary-amd64" \
  "$repository_root/rpm/x86_64" \
  "$repository_root/keys"

deb_destination="$repository_root/apt/pool/main/v/verdictan/verdictan_${deb_version}_${deb_architecture}.deb"
rpm_destination="$repository_root/rpm/x86_64/${rpm_name}-${rpm_version}-${rpm_release}.${rpm_architecture}.rpm"
cp "$deb_source" "$deb_destination"
cp "$rpm_source" "$rpm_destination"

GNUPGHOME="$signing_home" rpmsign \
  --define "_gpg_name ${fingerprint}" \
  --define "_gpg_path ${signing_home}" \
  --define '__gpg /usr/bin/gpg' \
  --define '_gpg_digest_algo sha256' \
  --addsign "$rpm_destination"

packages_file="$repository_root/apt/dists/stable/main/binary-amd64/Packages"
(
  cd "$repository_root/apt"
  apt-ftparchive packages pool/main
) > "${packages_file}.tmp"
mv "${packages_file}.tmp" "$packages_file"
gzip --no-name --best --stdout "$packages_file" > "${packages_file}.gz.tmp"
mv "${packages_file}.gz.tmp" "${packages_file}.gz"

release_date="$(date --utc --date="@${source_date_epoch}" --rfc-email)"
release_file="$repository_root/apt/dists/stable/Release"
(
  cd "$repository_root/apt"
  apt-ftparchive \
    -o "APT::FTPArchive::Release::Origin=Verdictan" \
    -o "APT::FTPArchive::Release::Label=Verdictan" \
    -o "APT::FTPArchive::Release::Suite=stable" \
    -o "APT::FTPArchive::Release::Codename=stable" \
    -o "APT::FTPArchive::Release::Architectures=amd64" \
    -o "APT::FTPArchive::Release::Components=main" \
    -o "APT::FTPArchive::Release::Description=Verdictan stable package repository" \
    -o "APT::FTPArchive::Release::Acquire-By-Hash=yes" \
    -o "APT::FTPArchive::Release::Date=${release_date}" \
    release dists/stable
) > "${release_file}.tmp"
mv "${release_file}.tmp" "$release_file"
gpg --homedir "$signing_home" --batch --yes --digest-algo SHA256 \
  --local-user "$fingerprint" --clearsign \
  --output "$repository_root/apt/dists/stable/InRelease" "$release_file"
gpg --homedir "$signing_home" --batch --yes --digest-algo SHA256 \
  --local-user "$fingerprint" --detach-sign \
  --output "$repository_root/apt/dists/stable/Release.gpg" "$release_file"

createrepo_c --update --database --checksum sha256 \
  --revision "$source_date_epoch" --set-timestamp-to-revision \
  "$repository_root/rpm/x86_64"
gpg --homedir "$signing_home" --batch --yes --armor --digest-algo SHA256 \
  --local-user "$fingerprint" --detach-sign \
  --output "$repository_root/rpm/x86_64/repodata/repomd.xml.asc" \
  "$repository_root/rpm/x86_64/repodata/repomd.xml"

public_key="$repository_root/keys/verdictan-packages.asc"
gpg --homedir "$signing_home" --batch --yes --armor \
  --output "$public_key" --export "$fingerprint"
printf '%s\n' "$fingerprint" > "$repository_root/keys/verdictan-packages.fingerprint"

cat > "$repository_root/apt/verdictan.list" <<EOF
deb [arch=amd64 signed-by=/usr/share/keyrings/verdictan-packages.gpg] ${base_url}/apt stable main
EOF
cat > "$repository_root/rpm/verdictan.repo" <<EOF
[verdictan]
name=Verdictan stable packages
baseurl=${base_url}/rpm/\$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=${base_url}/keys/verdictan-packages.asc
EOF
cat > "$repository_root/index.html" <<EOF
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Verdictan package repositories</title></head>
<body>
<h1>Verdictan package repositories</h1>
<p>Use the signed APT repository for Debian and Ubuntu.</p>
<p>Use the signed RPM repository for CentOS, RHEL, Fedora, and Amazon Linux 2023.</p>
<p><a href="https://docs.verdictan.com/docs/install-gateway">Installation instructions</a></p>
</body>
</html>
EOF
touch "$repository_root/.nojekyll"
cp "$marker_candidate" "$release_marker"

gpg --dearmor --yes --output "$verification_home/verdictan-packages.gpg" "$public_key"
gpgv --keyring "$verification_home/verdictan-packages.gpg" \
  "$repository_root/apt/dists/stable/InRelease" >/dev/null
gpgv --keyring "$verification_home/verdictan-packages.gpg" \
  "$repository_root/apt/dists/stable/Release.gpg" "$release_file" >/dev/null
gpgv --keyring "$verification_home/verdictan-packages.gpg" \
  "$repository_root/rpm/x86_64/repodata/repomd.xml.asc" \
  "$repository_root/rpm/x86_64/repodata/repomd.xml" >/dev/null
mkdir -p "$verification_home/rpmdb"
rpmkeys --dbpath "$verification_home/rpmdb" --import "$public_key"
rpmkeys --dbpath "$verification_home/rpmdb" --checksig "$rpm_destination" |
  grep -F 'digests signatures OK' >/dev/null

find "$repository_root" -type f -exec chmod 0644 {} +
echo "build_linux_package_repositories.sh: indexed Verdictan ${version} with key ${fingerprint}."
