#!/usr/bin/env bash
# Stamp LICENSE from LICENSE.template for a release tag.
# Computes the Change Date as four calendar years after the tag date per
# docs/license-faq.md and DECISION-001.
set -euo pipefail

readonly root="$(cd "$(dirname "$0")/../.." && pwd)"
readonly template="${root}/LICENSE.template"
readonly output="${root}/LICENSE"
readonly licensor="${VERDICTAN_LICENSOR_NAME:-Verdictan.com}"

tag="${VERDICTAN_RELEASE_TAG:-}"
if [[ -z "${tag}" && -n "${GITHUB_REF_NAME:-}" ]]; then
  tag="${GITHUB_REF_NAME}"
fi
if [[ -z "${tag}" ]]; then
  echo "stamp_license_for_release.sh: VERDICTAN_RELEASE_TAG or GITHUB_REF_NAME is required" >&2
  exit 1
fi

version="${tag#v}"
if [[ -z "${version}" ]]; then
  echo "stamp_license_for_release.sh: could not parse version from tag '${tag}'" >&2
  exit 1
fi

if [[ ! -f "${template}" ]]; then
  echo "stamp_license_for_release.sh: missing ${template}" >&2
  exit 1
fi

tag_ref="refs/tags/${tag}"
if git rev-parse "${tag_ref}" >/dev/null 2>&1; then
  tag_iso="$(git log -1 --format=%cI "${tag_ref}")"
else
  tag_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "stamp_license_for_release.sh: tag ${tag_ref} not found locally; using build UTC time ${tag_iso}" >&2
fi

tag_date="${tag_iso%%T*}"

add_years_to_date() {
  local base_date="$1"
  local years="$2"
  if date --version >/dev/null 2>&1; then
    date -d "${base_date} + ${years} years" +%Y-%m-%d
  else
    date -j -v+"${years}"y -f "%Y-%m-%d" "${base_date}" +%Y-%m-%d
  fi
}
change_date="$(add_years_to_date "${tag_date}" 4)"

if [[ "${licensor}" == *"<<"* ]]; then
  echo "stamp_license_for_release.sh: licensor still contains placeholder token" >&2
  exit 1
fi

sed \
  -e "s/<<REGISTERED-LICENSOR-NAME>>/${licensor}/g" \
  -e "s/<<VERSION>>/${version}/g" \
  -e "s/<<CHANGE-DATE>>/${change_date}/g" \
  "${template}" >"${output}"

if grep -q '<<' "${output}"; then
  echo "stamp_license_for_release.sh: unstamped tokens remain in LICENSE" >&2
  grep '<<' "${output}" >&2 || true
  exit 1
fi

echo "stamp_license_for_release.sh: stamped LICENSE for version ${version}, Change Date ${change_date}"
